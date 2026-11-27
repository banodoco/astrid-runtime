"""Portable retained-provider joins; these are not native Windows proof."""
from __future__ import annotations

import threading
from types import SimpleNamespace
import weakref

import pytest

from astrid_runtime import custody_broker as custody
from runtime_protocol import platform, process_binding as binding
from runtime_protocol.errors import ConflictError


IDENTITY = {"pid": 73, "uid": 501, "birth_id": "creation-73", "parent_pid": 59}
PARENT = {"pid": 59, "uid": 501, "birth_id": "creation-59"}
TOKEN = {"pid": 73, "uid": 501, "pidversion": 7,
         "sha256": "sha256:retained-test-token", "words": [7] * 8}


class WindowsBindingError(ConflictError):
    """Match the independently owned Windows provider's exception ABI."""


class RetainedAuthority:
    def __init__(self):
        self.closed = False
        self.close_count = 0
        self.failure = None
        self.verify_calls = []
        self.signals = []

    def verify(self, expected=None):
        self.verify_calls.append(None if expected is None else dict(expected))
        if self.closed:
            raise WindowsBindingError("retained native authority is closed")
        if self.failure is not None:
            raise WindowsBindingError(self.failure)
        if expected is not None and any(expected.get(key) != IDENTITY[key]
                                        for key in ("pid", "uid", "birth_id")):
            raise WindowsBindingError("retained native incarnation differs")
        return {**TOKEN, "words": list(TOKEN["words"])}

    def signal(self, signum):
        self.verify()
        self.signals.append(signum)

    def close(self):
        self.close_count += 1
        self.closed = True


@pytest.fixture
def windows_provider(monkeypatch):
    authority = RetainedAuthority()
    captures = []

    def retain_peer(channel, *, expected=None):
        captures.append(("peer", channel, expected))
        # The backend owns adoption and duplication. This join consumes only
        # the returned reference, never the peer PID or a token dictionary.
        assert channel.adopted_reference is not None
        authority.verify(expected)
        return authority

    def retain_child(child, *, reap_guard, expected=None):
        captures.append(("child", child, reap_guard, expected))
        authority.verify(expected)
        return authority

    def send(words, signum, *, authority=None):
        if not isinstance(authority, RetainedAuthority):
            raise WindowsBindingError("signal requires retained native authority")
        if list(words) != TOKEN["words"]:
            raise WindowsBindingError("signal token differs from native authority")
        authority.signal(signum)

    def observation(*args, **kwargs):
        pytest.fail("an observation or PID reopen cannot replace retained authority")

    native = SimpleNamespace(WindowsBindingError=WindowsBindingError,
                             retain_peer=retain_peer, retain_child=retain_child, signal=send)
    monkeypatch.setattr(binding, "_platform", lambda: "win32")
    monkeypatch.setattr(binding, "_native_backend", lambda: native)
    monkeypatch.setattr(binding, "token", observation)
    monkeypatch.setattr(binding, "peer_token", observation)
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(custody, "default_process_identity", lambda pid: dict(IDENTITY))
    monkeypatch.setattr(platform, "current_user", lambda: IDENTITY["uid"])
    return SimpleNamespace(authority=authority, native=native, captures=captures)


@pytest.mark.parametrize("origin", ["peer", "child"])
def test_windows_cleanup_actor_retains_original_reference_and_closes_once(windows_provider, origin):
    provider = windows_provider
    source = SimpleNamespace(adopted_reference=object())
    guard = threading.RLock()
    if origin == "peer":
        actor = custody.AuthenticatedCleanupActor.private_peer(source)
        assert provider.captures == [("peer", source, None)]
    else:
        actor = custody.AuthenticatedCleanupActor.retained_child(source, reap_guard=guard)
        assert provider.captures == [("child", source, guard, None)]
    try:
        assert actor.verify()["birth_id"] == IDENTITY["birth_id"]
        assert any(item is not None and item["birth_id"] == IDENTITY["birth_id"]
                   for item in provider.authority.verify_calls)
    finally:
        actor.close()
        actor.close()
    assert provider.authority.close_count == 1
    with pytest.raises(custody.CustodyError, match="stage=verify.token"):
        actor.verify()


def test_windows_actor_refuses_independently_observed_birth_mismatch_and_closes(windows_provider):
    source = SimpleNamespace(adopted_reference=object())
    with pytest.raises(custody.CustodyError, match="incarnation differs"):
        custody.AuthenticatedCleanupActor.private_peer(
            source, identity_provider=lambda pid: {**IDENTITY, "birth_id": "replacement"})
    assert windows_provider.authority.close_count == 1


@pytest.mark.parametrize("origin", ["peer", "child"])
def test_windows_actor_capture_refusal_is_custody_error(windows_provider, origin):
    windows_provider.authority.failure = "native adoption refused"
    with pytest.raises(custody.CustodyError, match="native adoption refused"):
        if origin == "peer":
            custody.AuthenticatedCleanupActor.private_peer(SimpleNamespace(adopted_reference=object()))
        else:
            custody.AuthenticatedCleanupActor.retained_child(object(), reap_guard=threading.RLock())


class Channel:
    def __init__(self, frame):
        self.data = custody._canonical(frame) + b"\n"
        self.adopted_reference = object()
        self.closed = False
        self.sent = []

    def settimeout(self, timeout):
        assert timeout > 0

    def recv(self, size):
        data, self.data = self.data[:size], self.data[size:]
        return data

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True
        self.adopted_reference = None


@pytest.fixture
def broker_join(windows_provider, tmp_path):
    broker = object.__new__(custody.RoleBoundCustodyBroker)
    frame = {"version": custody.PROTOCOL_VERSION, "command": "register_pre_exec",
             "run_id": "run", "role": "relay", "pid": IDENTITY["pid"],
             "ppid": PARENT["pid"], "argv_digest": "argv-digest"}
    channel = Channel(frame)
    events = []

    def accept_child(parent, *, deadline):
        assert parent == PARENT and deadline > 0
        return channel, None

    listener = SimpleNamespace(accept_child=accept_child, close=lambda: events.append("listener-closed"))
    root = tmp_path / "socket"
    root.mkdir()
    broker.__dict__.update(
        listener=listener, timeout=1, error=None, state="accepting", sequence=0,
        run_id="run", role="relay", launch_parent=SimpleNamespace(verify=lambda: dict(PARENT)),
        identity_provider=lambda pid: dict(IDENTITY), registration=None, ack=None,
        cleanup_actor=SimpleNamespace(close=lambda: events.append("actor-closed")), custody_generation=1,
        role_authority=SimpleNamespace(bind_pending=lambda **kw: events.append("pending-bound"),
                                       bind_target=lambda **kw: events.append("target-bound")),
        chain_head="chain", authority_journal=None, _persist=events.append,
        _ready=threading.Event(), socket_path=root / "s", socket_root=root,
        _release_authority_scope=lambda: events.append("scope-released"),
        _retain_post_exec_connection=False, _post_exec_connection=None,
        _post_exec_authority_validated=False, _native_peer=None, _close_native_peer=None,
    )
    yield SimpleNamespace(broker=broker, channel=channel, events=events,
                          provider=windows_provider, frame=frame)
    broker.close()


def test_windows_broker_keeps_authority_after_channel_close_through_ready_and_signal(broker_join, monkeypatch):
    join = broker_join
    broker, authority = join.broker, join.provider.authority
    broker._serve()
    assert broker.error is None and broker.state == "sealed"
    assert broker._ready.is_set() and join.channel.closed
    assert join.channel.adopted_reference is None
    assert join.provider.captures == [("peer", join.channel, None)]
    assert not authority.closed
    assert broker.registration["identity"] == IDENTITY
    assert "scope-released" in join.events and "listener-closed" in join.events
    monkeypatch.setattr(binding, "details", lambda words: {key: TOKEN[key] for key in TOKEN if key != "words"})
    broker.bind_ready_token(expected_pid=IDENTITY["pid"], expected_identity=IDENTITY)
    assert broker.state == "ready-bound"
    broker._signal_registered(TOKEN["words"], platform.TERM)
    assert authority.signals == [platform.TERM] and not authority.closed
    broker.close()
    assert authority.close_count == 1
    with pytest.raises(custody.CustodyError, match="closed"):
        broker._signal_registered(TOKEN["words"], platform.KILL)
    assert authority.signals == [platform.TERM]


@pytest.mark.parametrize("failure", ["capture", "frame", "birth", "exit"])
def test_windows_broker_failed_admission_closes_all_acquired_resources(broker_join, failure):
    join = broker_join
    if failure == "capture":
        join.provider.authority.failure = "native adoption refused"
    elif failure == "frame":
        join.channel.data = custody._canonical({**join.frame, "pid": IDENTITY["pid"] + 1}) + b"\n"
    elif failure == "birth":
        join.broker.identity_provider = lambda pid: {**IDENTITY, "birth_id": "replacement"}
    else:
        # Exit after frame validation and before post-exec binding.
        def persist(event):
            join.events.append(event)
            if event == "registration_ack_checkpoint":
                join.provider.authority.failure = "retained peer exited"
        join.broker._persist = persist
    join.broker._serve()
    assert join.broker.error is not None and join.broker.state != "sealed"
    assert join.broker._ready.is_set() and join.channel.closed
    assert "listener-closed" in join.events and "scope-released" in join.events
    assert not join.broker._post_exec_authority_validated
    assert join.provider.authority.close_count == (0 if failure == "capture" else 1)
    assert join.provider.authority.signals == []


def test_windows_validated_authority_survives_late_seal_failure_for_cleanup(broker_join):
    join = broker_join

    def persist(event):
        if event == "registration_post_exec":
            raise OSError("seal persistence failed")
        join.events.append(event)

    join.broker._persist = persist
    join.broker._serve()
    assert isinstance(join.broker.error, OSError)
    assert join.broker._post_exec_authority_validated
    assert not join.provider.authority.closed
    join.broker._signal_registered(TOKEN["words"], platform.TERM)
    assert join.provider.authority.signals == [platform.TERM]
    join.broker.close()
    assert join.provider.authority.close_count == 1


def test_windows_admission_native_close_error_does_not_strand_transport(broker_join):
    join = broker_join
    join.channel.data = custody._canonical({**join.frame, "pid": IDENTITY["pid"] + 1}) + b"\n"

    def fail_close():
        raise WindowsBindingError("native close failed")

    join.provider.authority.close = fail_close
    join.broker._serve()
    assert isinstance(join.broker.error, custody.CustodyError)
    assert "kernel identity differs" in str(join.broker.error)
    assert join.broker._ready.is_set() and join.channel.closed
    assert "listener-closed" in join.events and "scope-released" in join.events


@pytest.mark.parametrize("refusal", ["exited", "replaced", "wrong-words", "denied-signal"])
def test_windows_registered_signal_refuses_without_reacquiring_authority(broker_join, refusal):
    join = broker_join
    join.broker._serve()
    assert join.broker.error is None
    words, signum = TOKEN["words"], platform.TERM
    if refusal in ("exited", "replaced"):
        join.provider.authority.failure = f"retained peer {refusal}"
    elif refusal == "wrong-words":
        words = [8] * 8
    else:
        signum = 0
    with pytest.raises(custody.CustodyError):
        join.broker._signal_registered(words, signum)
    assert join.provider.authority.signals == []
    assert not join.provider.authority.closed


@pytest.mark.parametrize("selected", ["linux", "windows"])
def test_registered_token_observations_cannot_bind_ready_or_signal(broker_join, monkeypatch, selected):
    broker = broker_join.broker
    monkeypatch.setattr(binding, "backend", lambda: selected)
    broker.state = "sealed"
    broker.registration = {"identity": dict(IDENTITY), "audit_token_words": list(TOKEN["words"])}
    with pytest.raises(custody.CustodyError, match="no retained native authority"):
        broker.bind_ready_token(expected_pid=IDENTITY["pid"], expected_identity=IDENTITY)
    with pytest.raises(custody.CustodyError, match="no retained native authority"):
        broker._signal_registered(TOKEN["words"], platform.TERM)
    assert broker_join.provider.captures == []


@pytest.mark.parametrize("resource", ["channel", "native"])
def test_broker_close_releases_remaining_owners_after_close_error(broker_join, resource):
    broker = broker_join.broker
    events = broker_join.events

    def fail_close():
        raise OSError("close failed")

    native_close = fail_close if resource == "native" else lambda: events.append("native-closed")
    broker._close_native_peer = weakref.finalize(broker, native_close)
    if resource == "channel":
        broker._post_exec_connection = SimpleNamespace(close=fail_close)
    with pytest.raises(OSError, match="close failed"):
        broker.close()
    assert "actor-closed" in events
    if resource == "channel":
        assert "native-closed" in events
    assert broker._post_exec_connection is None


def test_darwin_actor_keeps_separate_exec_contract(monkeypatch):
    monkeypatch.setattr(binding, "backend", lambda: "darwin")
    monkeypatch.setattr(binding, "retain_peer", lambda *a, **kw: pytest.fail("Darwin join was not authorized"))
    monkeypatch.setattr(custody, "_peer_token", lambda channel: dict(TOKEN))
    with custody.AuthenticatedCleanupActor.private_peer(object(), identity_provider=lambda pid: dict(IDENTITY)) as actor:
        assert actor.verify()["birth_id"] == IDENTITY["birth_id"]
