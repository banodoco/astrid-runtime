"""Shared Darwin custody control flow and separately marked native proof.

Unmarked tests use explicit native API doubles. They prove ordering/refusal and
resource ownership, never a Mach operation or native macOS qualification.
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from astrid_runtime import custody_broker as custody
from runtime_protocol import darwin_process_binding as darwin
from runtime_protocol import platform, process_binding as binding
from runtime_protocol.local_execution_supervisor import RetainedProcess


IDENTITY = {"pid": 73, "uid": 501, "birth_id": "birth-73", "parent_pid": 59}
PARENT = {"pid": 59, "uid": 501, "birth_id": "birth-59"}


def token(version=1, pid=73):
    return {"pid": pid, "uid": 501, "pidversion": version,
            "sha256": f"sha256:portable-{pid}-{version}",
            "words": [0, 501, 0, 0, 0, pid, 0, version]}


@pytest.mark.parametrize("hook,args,kwargs", [
    ("token", (73,), {}), ("details", ([1] * 8,), {}),
    ("peer_token", (object(),), {}), ("retain_peer", (object(),), {}),
    ("retain_child", (object(),), {"reap_guard": threading.RLock()}),
    ("signal", ([1] * 8, platform.TERM), {"authority": object()}),
    ("resume_once", (object(),), {}),
])
def test_dispatch_normalizes_only_named_darwin_failures(monkeypatch, hook, args, kwargs):
    failure = darwin.DarwinBindingError("native refusal")

    def refused(*args, **kwargs):
        raise failure

    provider = SimpleNamespace(DarwinBindingError=darwin.DarwinBindingError, **{hook: refused})
    monkeypatch.setattr(binding, "_platform", lambda: "darwin")
    monkeypatch.setattr(binding, "_native_backend", lambda: provider)
    with pytest.raises(binding.ProcessBindingError) as caught:
        getattr(binding, hook)(*args, **kwargs)
    assert caught.value.__cause__ is failure
    failure = RuntimeError("unrelated implementation failure")
    with pytest.raises(RuntimeError) as caught:
        getattr(binding, hook)(*args, **kwargs)
    assert caught.value is failure


@pytest.mark.parametrize("kind,stage,result,acquired,narrow", [
    (darwin.TaskNameUnavailable, "task_name_for_pid", 5, False, True),
    (darwin.TaskNameUnavailable, "task_name_for_pid", 0, False, False),
    (darwin.TaskNameUnavailable, "task_name_for_pid", 5, True, False),
    (darwin.NativeTokenCaptureError, "task_name_for_pid", 0, False, False),
    (darwin.NativeTokenCaptureError, "task_info", 5, True, False),
    (darwin.NativeTokenCaptureError, "mach_port_deallocate", 5, True, False),
])
def test_only_no_acquired_port_denial_keeps_observation_exception(
        monkeypatch, kind, stage, result, acquired, narrow):
    failure = kind("capture refused", substage=stage, kern_return=result, port_acquired=acquired)

    def refused(pid):
        raise failure

    monkeypatch.setattr(binding, "_platform", lambda: "darwin")
    monkeypatch.setattr(binding, "_native_backend", lambda: SimpleNamespace(
        DarwinBindingError=darwin.DarwinBindingError, token=refused))
    with pytest.raises(custody.CustodyError) as caught:
        custody.current_process_audit_token(73)
    assert isinstance(caught.value, custody._TaskNameUnavailable) is narrow
    assert caught.value.__cause__.__cause__ is failure


@pytest.mark.parametrize("method", ["verify", "refresh_after_exec", "close"])
def test_retained_method_errors_keep_the_native_cause(monkeypatch, method):
    monkeypatch.setattr(binding, "_platform", lambda: "darwin")
    failure = darwin.DarwinBindingError("retained reference refused")

    def refused(*args):
        raise failure

    reference = SimpleNamespace(**{method: refused})
    with pytest.raises(custody.CustodyError) as caught:
        custody._retained_call(reference, method)
    assert caught.value.__cause__ is failure
    failure = RuntimeError("not a native binding error")
    with pytest.raises(RuntimeError) as caught:
        custody._retained_call(reference, method)
    assert caught.value is failure


class PeerDouble(darwin.PeerHandle):
    """A Python control-flow double; no Mach right is created."""

    def __init__(self, fixture, kind="peer"):
        self.fixture, self.kind = fixture, kind
        self.version = fixture.version
        self._closed, self.close_count = False, 0

    @property
    def identity(self):
        return dict(IDENTITY)

    @property
    def token(self):
        return token(self.version)

    def verify(self, expected=None):
        if self._closed or self.fixture.failure == "exit":
            raise darwin.DarwinBindingError("retained reference closed or exited")
        if self.version != self.fixture.version:
            raise darwin.DarwinBindingError("task token rotated without explicit refresh")
        if expected is not None and any(expected.get(k) != IDENTITY[k] for k in ("pid", "uid", "birth_id")):
            raise darwin.DarwinBindingError("retained incarnation mismatch")
        return self.token

    def close(self):
        if not self._closed:
            self.close_count += 1
            self._closed = True
            self.fixture.events.append((self.kind + "-closed",))
            if self.fixture.failure == self.kind + "-close":
                raise darwin.DarwinBindingError("native right release failed")


class ChildDouble(PeerDouble, darwin.OwnedChildHandle):
    def __init__(self, fixture, child, guard):
        super().__init__(fixture, "child")
        self.original, self.guard = child, guard
        self._resume_consumed = False

    def refresh_after_exec(self):
        with self.guard:
            assert self.original is self.fixture.child
            assert self.guard is self.fixture.guard
            assert self.guard._is_owned()
            self.fixture.events.append(("refresh", self.original, self.guard))
            if self.fixture.failure == "refresh" or self.original.returncode is not None:
                raise darwin.DarwinBindingError("original child refresh refused")
            self.version = self.fixture.version
            if self.fixture.failure == "refresh-mismatch":
                self.version += 1
            return self.token


class Channel:
    def __init__(self, fixture, pid=73):
        self.fixture, self.pid = fixture, pid
        self.closed = False
        self.sent = []
        frame = {"version": 1, "command": "register_pre_exec", "run_id": "run",
                 "role": "host", "pid": pid, "ppid": 59, "argv_digest": "argv"}
        self.data = custody._canonical(frame) + b"\n"

    def settimeout(self, timeout):
        assert timeout > 0

    def recv(self, size):
        value, self.data = self.data[:size], self.data[size:]
        return value

    def sendall(self, value):
        self.fixture.events.append(("ack",))
        self.sent.append(value)
        self.fixture.version = 2
        self.fixture.stopped = True

    def close(self):
        self.closed = True


@pytest.fixture
def joined(monkeypatch, tmp_path):
    f = SimpleNamespace(version=1, stopped=False, events=[], failure=None,
                        child=SimpleNamespace(pid=73, returncode=None), guard=threading.RLock(),
                        captures=[], peer=None, target=None, signals=[])
    channel = f.channel = Channel(f)
    pending = f.pending = [channel]

    def accept():
        if not pending:
            raise TimeoutError("fixture has no further connection")
        return pending.pop(0), None

    def retain_peer(connection, *, expected=None):
        f.captures.append(("peer", connection))
        if f.failure == "peer-capture":
            raise darwin.TaskNameUnavailable("peer acquisition refused", substage="task_name_for_pid",
                                             kern_return=5, port_acquired=False)
        f.peer = PeerDouble(f)
        return f.peer

    def retain_child(child, *, reap_guard, expected=None):
        f.captures.append(("child", child, reap_guard))
        assert child is f.child and reap_guard is f.guard
        if f.failure == "child-capture":
            raise darwin.NativeTokenCaptureError("child acquisition refused", substage="task_info",
                                                kern_return=5, port_acquired=True)
        with reap_guard:
            f.target = ChildDouble(f, child, reap_guard)
            return f.target

    def resume_once(authority):
        assert authority is f.target and f.stopped
        assert f.broker.registration["suspended_release"] == "intent"
        assert ("persist", "suspended_release_intent") in f.events
        if authority._resume_consumed:
            raise darwin.DarwinBindingError("release already consumed")
        authority._resume_consumed = True
        f.events.append(("resume",))
        if f.failure == "resume":
            raise darwin.DarwinBindingError("native resume failed")
        f.stopped = False

    def signal(words, signum, *, authority=None):
        if authority is not f.target:
            raise darwin.DarwinBindingError("wrong retained target")
        if list(words) != authority.verify()["words"]:
            raise darwin.DarwinBindingError("token differs from retained target")
        f.signals.append(signum)

    def details(words):
        value = token(words[7], words[5])
        return {k: value[k] for k in ("pid", "uid", "pidversion", "sha256")}

    def forbidden(*args, **kwargs):
        pytest.fail("a PID/token observation cannot replace retained custody")

    provider = SimpleNamespace(DarwinBindingError=darwin.DarwinBindingError,
        retain_peer=retain_peer, retain_child=retain_child, resume_once=resume_once,
        signal=signal, token=forbidden, details=details,
        peer_token=lambda channel: token(f.version, channel.pid))
    monkeypatch.setattr(binding, "_platform", lambda: "darwin")
    monkeypatch.setattr(binding, "LINUX", False)
    monkeypatch.setattr(binding, "_native_backend", lambda: provider)
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(custody, "default_process_identity", lambda pid: dict(IDENTITY))
    monkeypatch.setattr(platform, "current_user", lambda: 501)
    broker = f.broker = object.__new__(custody.RoleBoundCustodyBroker)
    root = tmp_path / "socket"
    root.mkdir()

    def persist(event):
        f.events.append(("persist", event))
        if f.failure == event:
            raise OSError("durable checkpoint refused")

    broker.__dict__.update(
        listener=SimpleNamespace(accept=accept, settimeout=lambda timeout: None,
                                 close=lambda: f.events.append(("listener-closed",))),
        timeout=.1, error=None, state="accepting", sequence=0, run_id="run", role="host",
        launch_parent=SimpleNamespace(verify=lambda: dict(PARENT)),
        identity_provider=lambda pid: dict(IDENTITY), registration=None, ack=None,
        cleanup_actor=SimpleNamespace(close=lambda: f.events.append(("actor-closed",))),
        custody_generation=1, role_authority=SimpleNamespace(
            bind_pending=lambda **kw: f.events.append(("pending-bound",)),
            bind_target=lambda **kw: f.events.append(("target-bound",))),
        chain_head="chain", authority_journal=None, _persist=persist,
        _ready=threading.Event(), socket_path=root / "s", socket_root=root,
        _release_authority_scope=lambda: f.events.append(("scope-released",)),
        _retain_post_exec_connection=False, _post_exec_connection=None,
        _post_exec_authority_validated=False, _native_peer=None, _close_native_peer=None,
        _original_child=None, _original_child_reap_guard=None,
        _original_child_lock=threading.Lock(), _original_child_ready=threading.Event(),
    )
    broker.bind_original_child(f.child, reap_guard=f.guard)
    yield f
    broker.close()


def test_original_child_is_retained_before_ack_and_release_intent_precedes_resume(joined):
    f = joined
    f.broker._serve()
    assert f.broker.error is None and f.broker.state == "sealed"
    assert f.captures == [("peer", f.channel), ("child", f.child, f.guard)]
    assert f.peer.close_count == 1 and not f.target._closed
    assert f.channel.closed and len(f.channel.sent) == 1
    ordered = [("peer-closed",), ("ack",), ("refresh", f.child, f.guard), ("target-bound",),
               ("persist", "suspended_release_intent"), ("resume",),
               ("persist", "suspended_release_completed"), ("persist", "admission_sealed")]
    assert [f.events.index(value) for value in ordered] == sorted(f.events.index(value) for value in ordered)
    assert f.broker.registration["suspended_release"] == "completed"
    f.version = 3  # Explicit final-ready exec refresh of the same owned child.
    f.broker.bind_ready_token(expected_pid=73, expected_identity=IDENTITY)
    assert f.broker.registration["audit_token_pidversion"] == 3
    assert f.broker.state == "ready-bound"
    f.broker._signal_registered(token(3)["words"], platform.TERM)
    assert f.signals == [platform.TERM]
    assert len(f.captures) == 2  # No token/PID recapture.
    f.broker.close()
    f.broker.close()
    assert f.target.close_count == 1


def test_missing_original_child_never_acknowledges_or_resumes(joined):
    f = joined
    f.broker._original_child_ready.clear()
    f.broker._serve()
    assert isinstance(f.broker.error, custody._NativeReferenceFailure)
    assert "original child" in str(f.broker.error)
    assert not f.captures and not f.channel.sent and not f.signals
    assert f.channel.closed and f.broker._ready.is_set()


def test_stray_peer_cannot_replace_the_original_child(joined):
    f = joined
    stray = Channel(f, pid=74)
    f.pending.insert(0, stray)
    f.broker._serve()
    assert f.broker.error is None and f.broker.state == "sealed"
    assert stray.closed and not stray.sent
    assert f.captures == [("peer", f.channel), ("child", f.child, f.guard)]


@pytest.mark.parametrize("failure", ["peer-capture", "child-capture", "peer-close", "refresh", "refresh-mismatch"])
def test_native_capture_refresh_or_release_failure_is_fatal_and_closes(joined, failure):
    f = joined
    f.failure = failure
    f.broker._serve()
    assert isinstance(f.broker.error, custody.CustodyError)
    assert f.broker.state != "sealed" and not f.broker._post_exec_authority_validated
    assert ("resume",) not in f.events and not f.signals
    assert f.channel.closed and ("scope-released",) in f.events and ("listener-closed",) in f.events
    if f.peer is not None:
        assert f.peer.close_count == 1
    if f.target is not None:
        assert f.target.close_count == 1


@pytest.mark.parametrize("failure", ["suspended_release_intent", "resume", "suspended_release_completed", "admission_sealed"])
def test_release_failure_never_retries_and_keeps_validated_target_for_cleanup(joined, failure):
    f = joined
    f.failure = failure
    f.broker._serve()
    assert f.broker.error is not None and f.broker._post_exec_authority_validated
    assert not f.target._closed and f.channel.closed
    assert f.events.count(("resume",)) == (0 if failure == "suspended_release_intent" else 1)
    with pytest.raises(custody.CustodyError, match="consumed"):
        f.broker._resume_registered_once()
    f.broker._signal_registered(token(2)["words"], platform.KILL)
    assert f.signals == [platform.KILL]


@pytest.mark.parametrize("refusal", ["closed", "exit", "words", "no-target", "peer-as-target", "signal-zero"])
def test_registered_darwin_signal_requires_live_original_target(joined, refusal):
    f = joined
    f.broker._serve()
    assert f.broker.error is None
    words, signum = token(2)["words"], platform.TERM
    if refusal == "closed":
        f.broker.close()
    elif refusal == "exit":
        f.failure = "exit"
    elif refusal == "words":
        words = token(1)["words"]
    elif refusal == "no-target":
        f.broker._native_peer = None
    elif refusal == "peer-as-target":
        f.broker._native_peer = PeerDouble(f)
    else:
        signum = 0
    with pytest.raises(custody.CustodyError):
        f.broker._signal_registered(words, signum)
    assert not f.signals and len(f.captures) == 2


@pytest.mark.parametrize("origin", ["peer", "child"])
def test_darwin_actor_retains_original_reference_and_closes(joined, origin):
    f = joined
    if origin == "peer":
        actor = custody.AuthenticatedCleanupActor.private_peer(f.channel)
        native = f.peer
    else:
        actor = custody.AuthenticatedCleanupActor.retained_child(f.child, reap_guard=f.guard)
        native = f.target
    assert actor.verify()["birth_id"] == IDENTITY["birth_id"]
    actor.close()
    actor.close()
    assert native.close_count == 1
    with pytest.raises(custody.CustodyError, match="stage=verify.token"):
        actor.verify()


def test_peer_rotation_is_not_an_actor_refresh(joined):
    f = joined
    actor = custody.AuthenticatedCleanupActor.private_peer(f.channel)
    try:
        f.version = 2
        with pytest.raises(custody.CustodyError, match="stage=verify.token"):
            actor.verify()
        assert not any(event[0] == "refresh" for event in f.events)
        assert f.target is None
    finally:
        actor.close()


def test_darwin_journal_without_native_reference_cannot_signal(joined, tmp_path, monkeypatch):
    f = joined
    monkeypatch.setattr(platform, "current_user", os.getuid)
    instance = custody.NativeProcessCustody(tmp_path, IDENTITY)
    record = {"version": custody.NATIVE_CAPABILITY_VERSION, "role": "runtime_owner",
              "target": {k: IDENTITY[k] for k in ("pid", "uid", "birth_id")},
              "controller": dict(IDENTITY), "state": "owned", "audit_token_words": token()["words"]}
    custody._atomic_owner_json(instance.path, record)
    before = instance.path.read_bytes()
    with pytest.raises(custody.CustodyError, match="retained original"):
        instance.signal(platform.TERM)
    assert instance.path.read_bytes() == before and not f.signals


def test_darwin_journal_token_mismatch_does_not_change_controller_or_signal(joined, tmp_path, monkeypatch):
    f = joined
    f.broker._serve()
    assert f.broker.error is None
    monkeypatch.setattr(platform, "current_user", os.getuid)
    instance = custody.NativeProcessCustody(tmp_path, IDENTITY, authority=f.target)
    record = {"version": custody.NATIVE_CAPABILITY_VERSION, "role": "runtime_owner",
              "target": {k: IDENTITY[k] for k in ("pid", "uid", "birth_id")},
              "controller": dict(IDENTITY), "state": "released", "audit_token_words": token(1)["words"]}
    custody._atomic_owner_json(instance.path, record)
    before = instance.path.read_bytes()
    with pytest.raises(custody.CustodyError, match="token differs"):
        instance.signal(platform.TERM)
    assert instance.path.read_bytes() == before and not f.signals


def test_original_child_handoff_cannot_be_replaced(joined):
    f = joined
    with pytest.raises(custody.CustodyError, match="already closed"):
        f.broker.bind_original_child(SimpleNamespace(pid=74), reap_guard=f.guard)
    assert f.broker._original_child is f.child
    assert not f.channel.sent and not f.captures


def test_runtime_owner_wait_uses_the_retained_guard():
    from astrid_runtime.runtime_boundary import _poll_runtime_child
    child = SimpleNamespace(returncode=None)
    retained = RetainedProcess(child)
    child._runtime_retained_process = retained
    entered, finished = threading.Event(), threading.Event()
    failures = []

    def poll():
        assert retained.guard._is_owned()
        return None

    child.poll = poll

    def waiter():
        entered.set()
        try:
            assert _poll_runtime_child(child) is None
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    with retained.guard:
        thread = threading.Thread(target=waiter)
        thread.start()
        assert entered.wait(1)
        assert not finished.wait(.03)
    thread.join(timeout=1)
    assert not thread.is_alive() and finished.is_set() and not failures


@pytest.mark.parametrize("failure_at", [None, "actor", "broker"])
@pytest.mark.parametrize("primary_failure", [False, True])
def test_runtime_owner_closes_both_references_after_owned_exit_and_preserves_failure(
        monkeypatch, failure_at, primary_failure):
    from astrid_runtime import runtime_boundary as boundary
    monkeypatch.setattr(boundary, "sys", SimpleNamespace(platform="darwin", exc_info=sys.exc_info))
    closed = []

    def close(name):
        closed.append(name)
        if name == failure_at:
            raise custody.CustodyError(name + " native release failed")

    child = SimpleNamespace(_runtime_boundary_sole_reaper=True,
        _runtime_retained_process=SimpleNamespace(exit_code=0, poll=lambda: 0, close=lambda: close("actor")),
        _runtime_custody_broker=SimpleNamespace(close=lambda: close("broker")))

    def terminate():
        if failure_at is None:
            boundary.LocalRuntimeBoundary._terminate(child)
        else:
            expected = ValueError if primary_failure else boundary.BootstrapError
            with pytest.raises(expected) as caught:
                boundary.LocalRuntimeBoundary._terminate(child)
            assert isinstance(child._runtime_cleanup_error, boundary.BootstrapError)
            if primary_failure:
                assert caught.value is original
                assert caught.value.__cause__ is child._runtime_cleanup_error
            else:
                assert caught.value is child._runtime_cleanup_error

    if primary_failure:
        try:
            raise ValueError("original startup failure")
        except ValueError as original:
            terminate()
    else:
        terminate()
    assert closed == ["actor", "broker"]


@pytest.mark.darwin_native
def test_native_broker_retains_original_child_through_suspended_exec_ready_signal_and_close(tmp_path):
    assert sys.platform == "darwin", "requires a real macOS native venue"
    broker = custody.RoleBoundCustodyBroker(role="host", identity_provider=custody.default_process_identity,
        ledger_root=tmp_path / "admission", timeout=5, retain_post_exec_connection=True)
    child = retained = native = None
    try:
        target = [sys.executable, "-c", "import sys; print('ready',flush=True); sys.stdin.readline()"]
        environment = {**os.environ, **broker.child_environment(target, start_new_session=True)}
        child = subprocess.Popen(custody.custody_wrapper_argv(sys.executable), env=environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=False)
        retained = RetainedProcess(child)
        broker.bind_original_child(child, reap_guard=retained.guard)
        broker.wait_until_sealed()
        native = broker._native_peer
        assert isinstance(native, darwin.OwnedChildHandle)
        assert native._child is child and native._reap_guard is retained.guard
        assert broker.registration["suspended_release"] == "completed"
        assert select.select([child.stdout], [], [], 5)[0], "released target did not become ready"
        assert child.stdout.readline() == b"ready\n"
        retained.bind_actor()
        identity = retained.verify()
        broker.bind_ready_token(expected_pid=child.pid, expected_identity=identity)
        events = [json.loads(line)["event"] for line in broker.journal_path.read_text().splitlines()]
        assert events.index("suspended_release_intent") < events.index("suspended_release_completed")
        assert events.index("suspended_release_completed") < events.index("admission_sealed")
        with pytest.raises(custody.CustodyError, match="consumed"):
            broker._resume_registered_once()
        broker.signal(platform.TERM, expected_pid=child.pid)
        assert retained.wait(5) == -int(platform.TERM)
        retained.close()
        broker.close()
        assert native._closed and native._native.port == 0
        assert broker._post_exec_connection is None
    finally:
        try:
            if child is not None:
                # Fixture cleanup is limited to this original disposable child.
                with retained.guard:
                    if retained.poll() is None:
                        child.kill()
                retained.wait(5)
        finally:
            try:
                if retained is not None:
                    retained.close()
            finally:
                try:
                    broker.close()
                finally:
                    if child is not None:
                        for stream in (child.stdin, child.stdout, child.stderr):
                            stream.close()
