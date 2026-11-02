from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tests.lanes import requires_linux_tree_custody, requires_posix_file_modes_native_custody

from astrid_runtime import custody_broker as custody
from runtime_protocol import platform


@pytest.fixture

def processes():
    if sys.platform != "linux":
        yield None  # portable tests do not use this fixture; yield so the setup completes
        return
    children = []

    def spawn(*, catch_term=False):
        code = (
            "import signal, sys\n"
            + ("signal.signal(signal.SIGTERM, lambda *_: print('TERM', flush=True))\n" if catch_term else "")
            + "print('READY', flush=True)\nwhile True: signal.pause()\n"
        )
        child = subprocess.Popen([sys.executable, "-u", "-c", code], stdout=subprocess.PIPE, text=True)
        children.append(child)
        assert child.stdout.readline().strip() == "READY"
        identity = custody.default_process_identity(child.pid)
        assert identity is not None
        return child, {key: identity[key] for key in ("pid", "uid", "birth_id")}

    yield spawn
    for child in children:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()

def _assert_running(child):
    # Give a mistakenly delivered terminating signal time to take effect.
    with pytest.raises(subprocess.TimeoutExpired):
        child.wait(timeout=0.1)

def _linux_identities(processes, *, catch_term=False):
    owner = custody.default_process_identity(os.getpid())
    assert owner is not None
    child, target = processes(catch_term=catch_term)
    return owner, child, target

def _linux_test_native_custody_publish_release_and_adopted_signal_use_guard(tmp_path, processes):
    owner_identity, child, target = _linux_identities(processes, catch_term=True)
    original = custody.NativeProcessCustody(tmp_path, target)
    original.publish()
    stored = json.loads(original.path.read_text())
    assert stored["state"] == "owned"
    assert stored["controller"] == owner_identity
    assert stored["target"] == target

    guarded = []
    def validate_inside_lock():
        with pytest.raises(BlockingIOError):
            with platform.file_lock(original.lock, blocking=False):
                pytest.fail("native custody guard was not held during validation")
        guarded.append(True)
    original.signal(platform.TERM, validate=validate_inside_lock)
    assert guarded == [True]
    assert select.select([child.stdout], [], [], 5)[0], "child did not receive TERM"
    assert child.stdout.readline().strip() == "TERM"
    assert child.poll() is None

    assert original.release() == {"state": "released"}
    assert json.loads(original.path.read_text())["state"] == "released"
    # A fresh operator object adopts the released record and delivers through
    # the identity-pinning platform boundary.
    adopted = custody.NativeProcessCustody(tmp_path, target)
    adopted.signal(platform.KILL)
    assert child.wait(timeout=5) == -platform.KILL

def _linux_test_native_custody_rejects_wrong_target_or_version(tmp_path, monkeypatch, processes, mutation, match):
    _owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    value = json.loads(instance.path.read_text())
    if mutation == "target":
        value["target"] = {**target, "birth_id": "replacement-birth"}
    else:
        value["version"] = "other"
    custody._atomic_owner_json(instance.path, value)
    with pytest.raises(custody.CustodyError, match=match):
        instance._read()

def _linux_test_native_custody_rejects_another_live_controller_while_owned(tmp_path, monkeypatch, processes):
    old_child, old = processes()
    _owner, child, target = _linux_identities(processes)
    class OsProxy:
        current_pid = old["pid"]
        def __getattr__(self, name): return getattr(os, name)
        def getpid(self): return self.current_pid
    os_proxy = OsProxy()
    monkeypatch.setattr(custody, "os", os_proxy)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    os_proxy.current_pid = os.getpid()
    with pytest.raises(custody.CustodyError, match="another controller"):
        instance.release()
    with pytest.raises(custody.CustodyError, match="another live controller"):
        instance.signal(platform.TERM)
    _assert_running(old_child)
    _assert_running(child)

def _linux_test_native_custody_recovers_when_prior_controller_is_proven_absent(tmp_path, monkeypatch, processes):
    old_child, old = processes()
    current, child, target = _linux_identities(processes)
    class OsProxy:
        current_pid = old["pid"]
        def __getattr__(self, name): return getattr(os, name)
        def getpid(self): return self.current_pid
    os_proxy = OsProxy()
    monkeypatch.setattr(custody, "os", os_proxy)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    os_proxy.current_pid = os.getpid()
    old_child.terminate()
    assert old_child.wait(timeout=5) == -platform.TERM
    # The old controller PID is absent; the signal operation durably adopts
    # the active record before delivering through the platform boundary.
    instance.signal(platform.TERM)
    record = json.loads(instance.path.read_text())
    assert record["state"] == "owned"
    assert record["controller"] == current
    assert child.wait(timeout=5) == -platform.TERM

def _linux_test_native_custody_rejects_unsafe_owner_file(tmp_path, monkeypatch, processes):
    _owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    instance.path.chmod(0o644)
    with pytest.raises(custody.CustodyError, match="owner-only"):
        instance._read()

def _linux_test_native_custody_wraps_platform_identity_drift_without_signaling(tmp_path, monkeypatch, processes):
    _owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    failures = []
    def reject_drift(words, signum):
        failures.append((words, signum))
        raise OSError("process incarnation changed")
    expected_words = custody.linux_process_binding.token(target["pid"])["words"]
    monkeypatch.setattr(custody, "signal_audit_token", reject_drift)
    with pytest.raises(custody.CustodyError, match="process incarnation changed"):
        instance.signal(platform.TERM)
    assert failures == [(expected_words, platform.TERM)]
    _assert_running(child)

def _linux_test_native_custody_preserves_controller_after_metadata_changes(tmp_path, monkeypatch, processes, operation, field):
    owner, child, target = _linux_identities(processes)
    owner.update(parent_pid=100, process_group=200, session_id=300)
    real_identity = custody.default_process_identity
    monkeypatch.setattr(custody, "default_process_identity", lambda pid: dict(owner) if pid == os.getpid() else real_identity(pid))
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    pinned = json.loads(instance.path.read_text())["controller"]
    owner[field] += 1
    if operation == "release":
        assert instance.release() == {"state": "released"}
        _assert_running(child)
    else:
        instance.signal(platform.TERM)
        assert child.wait(timeout=5) == -platform.TERM
    assert {key: owner[key] for key in target} == {key: pinned[key] for key in target}

def _linux_test_native_custody_rejects_each_different_live_controller_incarnation(tmp_path, monkeypatch, processes, field):
    owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    other = {**owner, field: "other-birth" if field == "birth_id" else owner[field] + 1}
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: other)
    with pytest.raises(custody.CustodyError, match="another controller"):
        instance.release()
    # Independently observing the persisted controller still proves it is live.
    observations = iter([other, owner])
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: next(observations))
    before = instance.path.read_bytes()
    with pytest.raises(custody.CustodyError, match="another live controller"):
        instance.signal(platform.TERM, validate=lambda: pytest.fail("validated without controller custody"))
    assert instance.path.read_bytes() == before
    _assert_running(child)

def _linux_test_native_custody_rejects_unavailable_or_malformed_actor(tmp_path, monkeypatch, processes, actor):
    _owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    before = instance.path.read_bytes()
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: actor)
    for operation in (instance.release, lambda: instance.signal(platform.TERM), instance.publish):
        with pytest.raises(custody.CustodyError, match="actor.*unavailable|actor.*malformed"):
            operation()
        assert instance.path.read_bytes() == before
        _assert_running(child)

def _linux_test_native_custody_rejects_missing_or_malformed_persisted_controller(tmp_path, monkeypatch, processes, controller):
    _owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    record = json.loads(instance.path.read_text())
    record["controller"] = controller
    custody._atomic_owner_json(instance.path, record)
    before = instance.path.read_bytes()
    for operation in (instance.release, lambda: instance.signal(platform.TERM)):
        with pytest.raises(custody.CustodyError):
            operation()
        assert instance.path.read_bytes() == before
        _assert_running(child)

def _linux_test_native_custody_unknown_prior_controller_observation_does_not_adopt(tmp_path, monkeypatch, processes):
    owner, child, target = _linux_identities(processes)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    actor = {**owner, "pid": owner["pid"] + 1}
    for observation in ({}, {"pid": owner["pid"]}):
        observations = iter([actor, observation])
        monkeypatch.setattr(custody, "default_process_identity", lambda _pid: next(observations))
        before = instance.path.read_bytes()
        with pytest.raises(custody.CustodyError):
            instance.signal(platform.TERM)
        assert instance.path.read_bytes() == before
        _assert_running(child)

def _linux_test_native_custody_real_reparented_controller_signals_and_releases(tmp_path):
    # The controller subprocess reads Runtime support's setting, as an install would.
    if platform.process_control() == "sandbox":
        from runtime_protocol import process_control
        process_control.write_setting(tmp_path, "sandbox")
    # Subreaper state belongs only to this isolated subprocess, never pytest.
    completed = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; import sys; "
         "from tests.test_native_custody import _linux_reparent_custody_proof; "
         "_linux_reparent_custody_proof(Path(sys.argv[1]))", str(tmp_path)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    proof = json.loads(completed.stdout)
    assert proof["before"]["parent_pid"] != proof["after"]["parent_pid"]
    for field in ("pid", "uid", "birth_id", "process_group", "session_id"):
        assert proof["before"][field] == proof["after"][field]
    assert proof["target_exit"] == -platform.TERM
    assert proof["state"] == "released"
    assert proof["all_owned_children_reaped"] is True

def _linux_reparent_custody_proof(root):
    import ctypes
    import signal
    import time

    library = ctypes.CDLL(None, use_errno=True)
    assert library.prctl(36, 1, 0, 0, 0) == 0, ctypes.get_errno()  # PR_SET_CHILD_SUBREAPER
    ready, result = root / "ready.json", root / "result.json"
    read_fd, write_fd = os.pipe()
    intermediate = os.fork()
    if intermediate == 0:
        os.close(read_fd)
        controller = os.fork()
        if controller == 0:
            target = None
            outcome = {}
            try:
                before = custody.default_process_identity(os.getpid())
                target = subprocess.Popen([sys.executable, "-c", "import signal; signal.pause()"])
                identity = custody.default_process_identity(target.pid)
                instance = custody.NativeProcessCustody(root, identity)
                instance.publish()
                ready.write_text(json.dumps({"controller": os.getpid(), "target": target.pid}))
                os.write(write_fd, ready.read_bytes())
                os.close(write_fd)
                deadline = time.monotonic() + 5
                while os.getppid() == before["parent_pid"] and time.monotonic() < deadline:
                    time.sleep(0.01)
                after = custody.default_process_identity(os.getpid())
                assert before["parent_pid"] != after["parent_pid"], "controller did not reparent"
                instance.signal(platform.TERM)
                target_exit = target.wait(timeout=3)
                instance.release()
                outcome = {"before": before, "after": after, "target_exit": target_exit,
                           "state": json.loads(instance.path.read_text())["state"]}
            except BaseException as exc:
                outcome = {"error": repr(exc)}
            finally:
                if target is not None:
                    if target.poll() is None:
                        target.kill()
                    target.wait()
                result.write_text(json.dumps(outcome))
            os._exit(1 if "error" in outcome else 0)
        os.close(write_fd)
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os._exit(0 if ready.exists() else 1)
    os.close(write_fd)
    def expired(_signum, _frame):
        raise TimeoutError("reparent proof deadline expired")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(10)
    try:
        children = json.loads(os.read(read_fd, 4096))
        assert os.waitstatus_to_exitcode(os.waitpid(intermediate, 0)[1]) == 0
        status = os.waitpid(children["controller"], 0)[1]
        proof = json.loads(result.read_text())
        assert os.waitstatus_to_exitcode(status) == 0, proof
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            proof["all_owned_children_reaped"] = True
        else:
            raise AssertionError("owned children remain unreaped")
        assert not Path(f"/proc/{children['target']}").exists()
        print(json.dumps(proof))
    finally:
        signal.alarm(0)
        os.close(read_fd)
        # Kill and reap only this isolated subreaper's children, including any
        # descendants adopted after an assertion or deadline failure.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            child_pids = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
            for pid in child_pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("failed to reap all owned children")

def _portable_identities(monkeypatch):
    owner = {"pid": os.getpid(), "uid": platform.current_user(), "birth_id": "controller-birth"}
    target = {"pid": 44121, "uid": platform.current_user(), "birth_id": "target-birth"}
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: dict(owner))
    # Exercise the native pidfd/OpenProcess branch without entering Darwin's
    # audit-token lane. The signal itself remains a mocked platform call.
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="linux"))
    return owner, target

def _portable_test_native_custody_publish_release_and_adopted_signal_use_guard(tmp_path, monkeypatch):
    owner_identity, target = _portable_identities(monkeypatch)
    delivered = []
    monkeypatch.setattr(platform, "signal_process", lambda identity, signum: delivered.append((dict(identity), signum)))
    original = custody.NativeProcessCustody(tmp_path, target)
    original.publish()
    stored = json.loads(original.path.read_text())
    assert stored["state"] == "owned"
    assert stored["controller"] == owner_identity
    assert stored["target"] == target

    guarded = []
    def validate_inside_lock():
        with pytest.raises(BlockingIOError):
            with platform.file_lock(original.lock, blocking=False):
                pytest.fail("native custody guard was not held during validation")
        guarded.append(True)
    original.signal(platform.TERM, validate=validate_inside_lock)
    assert guarded == [True]
    assert delivered == [(target, platform.TERM)]

    assert original.release() == {"state": "released"}
    assert json.loads(original.path.read_text())["state"] == "released"
    # A fresh operator object adopts the released record and delivers through
    # the identity-pinning platform boundary.
    adopted = custody.NativeProcessCustody(tmp_path, target)
    adopted.signal(platform.KILL)
    assert delivered == [(target, platform.TERM), (target, platform.KILL)]

def _portable_test_native_custody_rejects_wrong_target_or_version(tmp_path, monkeypatch, mutation, match):
    _owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    value = json.loads(instance.path.read_text())
    if mutation == "target":
        value["target"] = {**target, "birth_id": "replacement-birth"}
    else:
        value["version"] = "other"
    custody._atomic_owner_json(instance.path, value)
    with pytest.raises(custody.CustodyError, match=match):
        instance._read()

def _portable_test_native_custody_rejects_another_live_controller_while_owned(tmp_path, monkeypatch):
    old = {"pid": 41001, "uid": platform.current_user(), "birth_id": "old-controller"}
    other = {"pid": 41002, "uid": platform.current_user(), "birth_id": "other-controller"}
    target = {"pid": 44121, "uid": platform.current_user(), "birth_id": "target-birth"}
    identities = {old["pid"]: old, other["pid"]: other}
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(custody, "default_process_identity", lambda pid: identities.get(pid))
    class OsProxy:
        current_pid = old["pid"]
        def __getattr__(self, name): return getattr(os, name)
        def getpid(self): return self.current_pid
    os_proxy = OsProxy()
    monkeypatch.setattr(custody, "os", os_proxy)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    os_proxy.current_pid = other["pid"]
    with pytest.raises(custody.CustodyError, match="another controller"):
        instance.release()
    with pytest.raises(custody.CustodyError, match="another live controller"):
        instance.signal(platform.TERM)

def _portable_test_native_custody_recovers_when_prior_controller_is_proven_absent(tmp_path, monkeypatch):
    old = {"pid": 41011, "uid": platform.current_user(), "birth_id": "dead-controller"}
    current = {"pid": 41012, "uid": platform.current_user(), "birth_id": "current-controller"}
    target = {"pid": 44122, "uid": platform.current_user(), "birth_id": "target-birth"}
    identities = {old["pid"]: old, current["pid"]: current}
    monkeypatch.setattr(custody, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(custody, "default_process_identity", lambda pid: identities.get(pid))
    class OsProxy:
        current_pid = old["pid"]
        def __getattr__(self, name): return getattr(os, name)
        def getpid(self): return self.current_pid
    os_proxy = OsProxy()
    monkeypatch.setattr(custody, "os", os_proxy)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    os_proxy.current_pid = current["pid"]
    # The old controller PID is absent; the signal operation durably adopts
    # the active record before delivering through the platform boundary.
    identities.pop(old["pid"])
    delivered = []
    monkeypatch.setattr(platform, "signal_process", lambda identity, signum: delivered.append((dict(identity), signum)))
    instance.signal(platform.TERM)
    record = json.loads(instance.path.read_text())
    assert record["state"] == "owned"
    assert record["controller"] == current
    assert delivered == [(target, platform.TERM)]

def _portable_test_native_custody_rejects_unsafe_owner_file(tmp_path, monkeypatch):
    _owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    instance.path.chmod(0o644)
    with pytest.raises(custody.CustodyError, match="owner-only"):
        instance._read()

def _portable_test_native_custody_wraps_platform_identity_drift_without_signaling(tmp_path, monkeypatch):
    _owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    failures = []
    def reject_drift(identity, signum):
        failures.append((identity, signum))
        raise OSError("process incarnation changed")
    monkeypatch.setattr(platform, "signal_process", reject_drift)
    with pytest.raises(custody.CustodyError, match="process incarnation changed"):
        instance.signal(platform.TERM)
    assert failures == [(target, platform.TERM)]

def _portable_test_native_custody_preserves_controller_after_metadata_changes(tmp_path, monkeypatch, operation, field):
    owner, target = _portable_identities(monkeypatch)
    owner.update(parent_pid=100, process_group=200, session_id=300)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    pinned = json.loads(instance.path.read_text())["controller"]
    owner[field] += 1
    delivered = []
    monkeypatch.setattr(platform, "signal_process", lambda *args: delivered.append(args))
    if operation == "release":
        assert instance.release() == {"state": "released"}
        assert delivered == []
    else:
        instance.signal(platform.TERM)
        assert delivered == [(target, platform.TERM)]
    assert {key: owner[key] for key in target} == {key: pinned[key] for key in target}

def _portable_test_native_custody_rejects_each_different_live_controller_incarnation(tmp_path, monkeypatch, field):
    owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    other = {**owner, field: "other-birth" if field == "birth_id" else owner[field] + 1}
    monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("delivered without controller custody"))
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: other)
    with pytest.raises(custody.CustodyError, match="another controller"):
        instance.release()
    # Independently observing the persisted controller still proves it is live.
    observations = iter([other, owner])
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: next(observations))
    before = instance.path.read_bytes()
    with pytest.raises(custody.CustodyError, match="another live controller"):
        instance.signal(platform.TERM, validate=lambda: pytest.fail("validated without controller custody"))
    assert instance.path.read_bytes() == before

def _portable_test_native_custody_rejects_unavailable_or_malformed_actor(tmp_path, monkeypatch, actor):
    _owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    before = instance.path.read_bytes()
    monkeypatch.setattr(custody, "default_process_identity", lambda _pid: actor)
    monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("delivered for an unknown actor"))
    for operation in (instance.release, lambda: instance.signal(platform.TERM), instance.publish):
        with pytest.raises(custody.CustodyError, match="actor.*unavailable|actor.*malformed"):
            operation()
        assert instance.path.read_bytes() == before

def _portable_test_native_custody_rejects_missing_or_malformed_persisted_controller(tmp_path, monkeypatch, controller):
    _owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    record = json.loads(instance.path.read_text())
    record["controller"] = controller
    custody._atomic_owner_json(instance.path, record)
    before = instance.path.read_bytes()
    monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("delivered without known controller"))
    for operation in (instance.release, lambda: instance.signal(platform.TERM)):
        with pytest.raises(custody.CustodyError):
            operation()
        assert instance.path.read_bytes() == before

def _portable_test_native_custody_unknown_prior_controller_observation_does_not_adopt(tmp_path, monkeypatch):
    owner, target = _portable_identities(monkeypatch)
    instance = custody.NativeProcessCustody(tmp_path, target)
    instance.publish()
    actor = {**owner, "pid": owner["pid"] + 1}
    for observation in ({}, {"pid": owner["pid"]}):
        observations = iter([actor, observation])
        monkeypatch.setattr(custody, "default_process_identity", lambda _pid: next(observations))
        before = instance.path.read_bytes()
        monkeypatch.setattr(platform, "signal_process", lambda *args: pytest.fail("delivered for unknown prior controller"))
        with pytest.raises(custody.CustodyError):
            instance.signal(platform.TERM)
        assert instance.path.read_bytes() == before

def _portable_test_native_custody_real_reparented_controller_signals_and_releases(tmp_path):
    # The controller subprocess reads Runtime support's setting, as an install would.
    if platform.process_control() == "sandbox":
        from runtime_protocol import process_control
        process_control.write_setting(tmp_path, "sandbox")
    # Subreaper state belongs only to this isolated subprocess, never pytest.
    completed = subprocess.run(
        [sys.executable, "-c", "from pathlib import Path; import sys; "
         "from tests.test_native_custody import _linux_reparent_custody_proof; "
         "_linux_reparent_custody_proof(Path(sys.argv[1]))", str(tmp_path)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    proof = json.loads(completed.stdout)
    assert proof["before"]["parent_pid"] != proof["after"]["parent_pid"]
    for field in ("pid", "uid", "birth_id", "process_group", "session_id"):
        assert proof["before"][field] == proof["after"][field]
    assert proof["target_exit"] == -platform.TERM
    assert proof["state"] == "released"
    assert proof["all_owned_children_reaped"] is True

def _linux_reparent_custody_proof(root):
    import ctypes
    import signal
    import time

    library = ctypes.CDLL(None, use_errno=True)
    assert library.prctl(36, 1, 0, 0, 0) == 0, ctypes.get_errno()  # PR_SET_CHILD_SUBREAPER
    ready, result = root / "ready.json", root / "result.json"
    read_fd, write_fd = os.pipe()
    intermediate = os.fork()
    if intermediate == 0:
        os.close(read_fd)
        controller = os.fork()
        if controller == 0:
            target = None
            outcome = {}
            try:
                before = custody.default_process_identity(os.getpid())
                target = subprocess.Popen([sys.executable, "-c", "import signal; signal.pause()"])
                identity = custody.default_process_identity(target.pid)
                instance = custody.NativeProcessCustody(root, identity)
                instance.publish()
                ready.write_text(json.dumps({"controller": os.getpid(), "target": target.pid}))
                os.write(write_fd, ready.read_bytes())
                os.close(write_fd)
                deadline = time.monotonic() + 5
                while os.getppid() == before["parent_pid"] and time.monotonic() < deadline:
                    time.sleep(0.01)
                after = custody.default_process_identity(os.getpid())
                assert before["parent_pid"] != after["parent_pid"], "controller did not reparent"
                instance.signal(platform.TERM)
                target_exit = target.wait(timeout=3)
                instance.release()
                outcome = {"before": before, "after": after, "target_exit": target_exit,
                           "state": json.loads(instance.path.read_text())["state"]}
            except BaseException as exc:
                outcome = {"error": repr(exc)}
            finally:
                if target is not None:
                    if target.poll() is None:
                        target.kill()
                    target.wait()
                result.write_text(json.dumps(outcome))
            os._exit(1 if "error" in outcome else 0)
        os.close(write_fd)
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        os._exit(0 if ready.exists() else 1)
    os.close(write_fd)
    def expired(_signum, _frame):
        raise TimeoutError("reparent proof deadline expired")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(10)
    try:
        children = json.loads(os.read(read_fd, 4096))
        assert os.waitstatus_to_exitcode(os.waitpid(intermediate, 0)[1]) == 0
        status = os.waitpid(children["controller"], 0)[1]
        proof = json.loads(result.read_text())
        assert os.waitstatus_to_exitcode(status) == 0, proof
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            proof["all_owned_children_reaped"] = True
        else:
            raise AssertionError("owned children remain unreaped")
        assert not Path(f"/proc/{children['target']}").exists()
        print(json.dumps(proof))
    finally:
        signal.alarm(0)
        os.close(read_fd)
        # Kill and reap only this isolated subreaper's children, including any
        # descendants adopted after an assertion or deadline failure.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            child_pids = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
            for pid in child_pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("failed to reap all owned children")

def test_native_custody_publish_release_and_adopted_signal_use_guard(tmp_path, processes, monkeypatch):
    if sys.platform == "linux":
        return _linux_test_native_custody_publish_release_and_adopted_signal_use_guard(tmp_path, processes)
    return _portable_test_native_custody_publish_release_and_adopted_signal_use_guard(tmp_path, monkeypatch)


@pytest.mark.parametrize('mutation,match', [('target', 'differs from the selected owner'), ('version', 'differs from the selected owner')])

def test_native_custody_rejects_wrong_target_or_version(tmp_path, monkeypatch, processes, mutation, match):
    if sys.platform == "linux":
        return _linux_test_native_custody_rejects_wrong_target_or_version(tmp_path, monkeypatch, processes, mutation, match)
    return _portable_test_native_custody_rejects_wrong_target_or_version(tmp_path, monkeypatch, mutation, match)


def test_native_custody_rejects_another_live_controller_while_owned(tmp_path, monkeypatch, processes):
    if sys.platform == "linux":
        return _linux_test_native_custody_rejects_another_live_controller_while_owned(tmp_path, monkeypatch, processes)
    return _portable_test_native_custody_rejects_another_live_controller_while_owned(tmp_path, monkeypatch)


def test_native_custody_recovers_when_prior_controller_is_proven_absent(tmp_path, monkeypatch, processes):
    if sys.platform == "linux":
        return _linux_test_native_custody_recovers_when_prior_controller_is_proven_absent(tmp_path, monkeypatch, processes)
    return _portable_test_native_custody_recovers_when_prior_controller_is_proven_absent(tmp_path, monkeypatch)


@requires_posix_file_modes_native_custody

def test_native_custody_rejects_unsafe_owner_file(tmp_path, monkeypatch, processes):
    if sys.platform == "linux":
        return _linux_test_native_custody_rejects_unsafe_owner_file(tmp_path, monkeypatch, processes)
    return _portable_test_native_custody_rejects_unsafe_owner_file(tmp_path, monkeypatch)


def test_native_custody_wraps_platform_identity_drift_without_signaling(tmp_path, monkeypatch, processes):
    if sys.platform == "linux":
        return _linux_test_native_custody_wraps_platform_identity_drift_without_signaling(tmp_path, monkeypatch, processes)
    return _portable_test_native_custody_wraps_platform_identity_drift_without_signaling(tmp_path, monkeypatch)


@pytest.mark.parametrize('operation', ['release', 'signal'])
@pytest.mark.parametrize('field', ['parent_pid', 'process_group', 'session_id'])

def test_native_custody_preserves_controller_after_metadata_changes(tmp_path, monkeypatch, processes, operation, field):
    if sys.platform == "linux":
        return _linux_test_native_custody_preserves_controller_after_metadata_changes(tmp_path, monkeypatch, processes, operation, field)
    return _portable_test_native_custody_preserves_controller_after_metadata_changes(tmp_path, monkeypatch, operation, field)


@pytest.mark.parametrize('field', ['pid', 'uid', 'birth_id'])

def test_native_custody_rejects_each_different_live_controller_incarnation(tmp_path, monkeypatch, processes, field):
    if sys.platform == "linux":
        return _linux_test_native_custody_rejects_each_different_live_controller_incarnation(tmp_path, monkeypatch, processes, field)
    return _portable_test_native_custody_rejects_each_different_live_controller_incarnation(tmp_path, monkeypatch, field)


@pytest.mark.parametrize('actor', [None, {}, [], {'pid': True, 'uid': 0, 'birth_id': 'birth'}, {'pid': 0, 'uid': 0, 'birth_id': 'birth'}, {'pid': 1, 'uid': False, 'birth_id': 'birth'}, {'pid': 1, 'uid': -1, 'birth_id': 'birth'}, {'pid': 1, 'uid': 0, 'birth_id': ''}, {'pid': 1, 'uid': 0, 'birth_id': None}])

def test_native_custody_rejects_unavailable_or_malformed_actor(tmp_path, monkeypatch, processes, actor):
    if sys.platform == "linux":
        return _linux_test_native_custody_rejects_unavailable_or_malformed_actor(tmp_path, monkeypatch, processes, actor)
    return _portable_test_native_custody_rejects_unavailable_or_malformed_actor(tmp_path, monkeypatch, actor)


@pytest.mark.parametrize('controller', [None, {}, [], {'pid': 'unknown'}])

def test_native_custody_rejects_missing_or_malformed_persisted_controller(tmp_path, monkeypatch, processes, controller):
    if sys.platform == "linux":
        return _linux_test_native_custody_rejects_missing_or_malformed_persisted_controller(tmp_path, monkeypatch, processes, controller)
    return _portable_test_native_custody_rejects_missing_or_malformed_persisted_controller(tmp_path, monkeypatch, controller)


def test_native_custody_unknown_prior_controller_observation_does_not_adopt(tmp_path, monkeypatch, processes):
    if sys.platform == "linux":
        return _linux_test_native_custody_unknown_prior_controller_observation_does_not_adopt(tmp_path, monkeypatch, processes)
    return _portable_test_native_custody_unknown_prior_controller_observation_does_not_adopt(tmp_path, monkeypatch)


@requires_linux_tree_custody

def test_native_custody_real_reparented_controller_signals_and_releases(tmp_path):
    if sys.platform == "linux":
        return _linux_test_native_custody_real_reparented_controller_signals_and_releases(tmp_path)
    return _portable_test_native_custody_real_reparented_controller_signals_and_releases(tmp_path)
