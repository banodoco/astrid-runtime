"""Linux process-binding provider: exact identity, refusal before signal, real process."""
from __future__ import annotations

import errno
import os
import subprocess
import sys
import time

import pytest

from runtime_protocol import linux_process_binding as lpb
from runtime_protocol import platform

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux provider")


def _sleeper():
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def test_token_round_trips_for_a_live_child_and_refuses_forged_fields():
    child = _sleeper()
    try:
        token = lpb.token(child.pid)
        words = token["words"]
        assert lpb.details(words)["pid"] == child.pid
        assert lpb.details(words)["sha256"] == token["sha256"]
        # Forged start ticks for the same pid: refused as reused.
        forged_ticks = list(words); forged_ticks[4] ^= 1
        with pytest.raises(lpb.LinuxBindingError):
            lpb._matches(forged_ticks)
        # Forged uid for the same pid: refused.
        forged_uid = list(words); forged_uid[2] ^= 1
        with pytest.raises(lpb.LinuxBindingError):
            lpb._matches(forged_uid)
        # Forged pid: names a different process, whose identity cannot match these ticks.
        time.sleep(0.05)  # start ticks are ~10 ms; separate them so the test is deterministic
        other = _sleeper()
        try:
            forged_pid = list(words); forged_pid[1] = other.pid
            with pytest.raises(lpb.LinuxBindingError):
                lpb._matches(forged_pid)
        finally:
            other.kill(); other.wait()
    finally:
        child.kill(); child.wait()


def test_signal_reaches_the_same_process_and_refusal_signals_nothing():
    child = _sleeper()
    try:
        words = lpb.token(child.pid)["words"]
        forged = list(words); forged[4] ^= 1
        with pytest.raises(lpb.LinuxBindingError):
            lpb.signal(forged, platform.TERM)
        assert child.poll() is None  # refusal delivered no signal
        lpb.signal(words, platform.TERM)
        assert child.wait(timeout=10) == -platform.TERM
    finally:
        if child.poll() is None:
            child.kill(); child.wait()


def test_exited_child_is_refused_without_signal():
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    with pytest.raises(lpb.LinuxBindingError):
        lpb.token(child.pid)


def test_namespace_zero_or_missing_is_refused():
    with pytest.raises(lpb.LinuxBindingError):
        lpb._parse_birth("proc-start-ticks:123")
    with pytest.raises(lpb.LinuxBindingError):
        lpb.details([lpb.TOKEN_TAG, os.getpid(), 0, 0, 1, 0, 0, 0])


def test_exited_unreaped_child_is_refused_before_binding_and_never_signalled():
    """Spawn-to-seal window: the child exits but is not reaped; binding must refuse it."""
    import threading
    from astrid_runtime import custody_broker

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and platform.process_identity(child.pid) is not None:
        time.sleep(0.01)  # zombie is reported as absent; wait until it has exited
    with pytest.raises(custody_broker.CustodyError):
        custody_broker.AuthenticatedCleanupActor.retained_child(child, reap_guard=threading.RLock())
    assert child.returncode is None  # never reaped by the refusal path
    child.wait()  # now reap it ourselves; nothing was signalled by the broker


def test_real_host_broker_constructs_on_linux_and_custody_branches_stay_in_one_module(tmp_path):
    from astrid_runtime import custody_broker
    from runtime_protocol import platform as rp

    scope = tmp_path / "scope"
    scope.mkdir()
    platform.owner_only(scope)
    broker = custody_broker.RoleBoundCustodyBroker(
        role="host", identity_provider=rp.process_identity,
        ledger_root=scope / "host-admission", authority_scope_root=scope,
        authority_journal=scope / "admissions.jsonl", owner_epoch="epoch", timeout=5,
    )
    assert broker.role == "host"
    # Allow-list guard: custody_broker gained no sys.platform branch; the Linux
    # branches go through process_binding.LINUX. Base had 26; this head has 25.
    from pathlib import Path
    source = Path(custody_broker.__file__).read_text(encoding="utf-8")
    assert source.count("sys.platform") <= 25


def test_missing_or_denied_boot_id_fails_closed_for_token_and_signal(monkeypatch):
    child = _sleeper()
    try:
        words = lpb.token(child.pid)["words"]
        real_identity = platform.process_identity

        def without_boot(pid, **kwargs):
            identity = real_identity(pid, **kwargs)
            if identity is not None:
                identity = dict(identity)
                identity["birth_id"] = identity["birth_id"].split(";boot:")[0] + ";pidns:" + identity["birth_id"].split(";pidns:")[1]
            return identity

        monkeypatch.setattr(platform, "process_identity", without_boot)
        with pytest.raises(lpb.LinuxBindingError, match="boot_id"):
            lpb.token(child.pid)
        with pytest.raises(lpb.LinuxBindingError, match="boot_id"):
            lpb.signal(words, platform.TERM)
        assert child.poll() is None  # refusal delivered no signal
    finally:
        child.kill(); child.wait()


def test_hidepid_without_pid_namespace_fails_closed(monkeypatch):
    child = _sleeper()
    try:
        real_identity = platform.process_identity

        def without_namespace(pid, **kwargs):
            identity = real_identity(pid, **kwargs)
            if identity is not None:
                identity = dict(identity)
                identity["birth_id"] = identity["birth_id"].split(";pidns:")[0]
            return identity

        monkeypatch.setattr(platform, "process_identity", without_namespace)
        with pytest.raises(lpb.LinuxBindingError):
            lpb.token(child.pid)
    finally:
        child.kill(); child.wait()


def test_pidfd_probe_failure_refuses_admission_and_never_uses_bare_pid_fallback(monkeypatch):
    from runtime_protocol import process_binding

    def enosys(*_args, **_kwargs):
        raise OSError(errno.ENOSYS, "pidfd unsupported")

    monkeypatch.setattr(platform, "pidfd_open", enosys)
    monkeypatch.setattr(platform, "_signal_checked_pid", lambda *a, **k: pytest.fail("bare-pid fallback reached"), raising=False)
    assert lpb.pidfd_available() is False
    assert process_binding.supported() is False
    child = _sleeper()
    try:
        words = None
        # Build a token before the probe failure: the signal path must still refuse.
        monkeypatch.undo()
        words = lpb.token(child.pid)["words"]
        monkeypatch.setattr(platform, "pidfd_open", enosys)
        monkeypatch.setattr(platform, "_signal_checked_pid", lambda *a, **k: pytest.fail("bare-pid fallback reached"), raising=False)
        with pytest.raises(OSError):
            lpb.signal(words, platform.TERM)
        assert child.poll() is None
    finally:
        child.kill(); child.wait()


def test_pidfd_probe_succeeds_on_this_kernel():
    from runtime_protocol import process_binding
    assert lpb.pidfd_available() is True
    assert process_binding.supported() is True


def test_real_linux_broker_admits_wrapper_seals_binds_and_signals_child(tmp_path):
    """N2: real broker, real wrapper exec, nothing mocked: seal, bind, TERM ends the child."""
    import json
    import os
    import signal as _signal
    import threading
    from astrid_runtime import custody_broker as custody

    scope = tmp_path / "scope"
    platform.private_directory(scope)
    broker = custody.RoleBoundCustodyBroker(role="host", identity_provider=custody.default_process_identity,
        ledger_root=scope / "admission", authority_scope_root=scope,
        authority_journal=scope / "admissions.jsonl", owner_epoch="owner", timeout=15)
    target = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]
    environment = {**os.environ, **broker.child_environment(target, start_new_session=True)}
    process = None
    try:
        # Production wrapper argv, exactly; the test interpreter is a task-local venv with this lane installed,
        # so the -I wrapper resolves this checkout.
        wrapper = custody.custody_wrapper_argv(sys.executable)
        process = platform.spawn_tree(wrapper, env=environment, start_new_session=False, close_fds=True)
        broker.wait_until_sealed()
        actor = custody.AuthenticatedCleanupActor.retained_child(process, reap_guard=threading.RLock())
        assert actor.verify()["pid"] == process.pid
        assert broker.role_authority.reference()["target"] == actor.verify()
        broker.signal(int(_signal.SIGTERM), expected_pid=process.pid)
        assert process.wait(timeout=15) in (-int(_signal.SIGTERM), 128 + int(_signal.SIGTERM))
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        else:
            if process is None:
                broker.abort_before_spawn()
