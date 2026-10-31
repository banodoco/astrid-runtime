"""Process control: strict (default) vs sandbox, the setting, fallbacks and probe."""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from astrid_runtime.bootstrap import BootstrapConfig, SourceProfile
from astrid_runtime.paths import RuntimePaths
from runtime_protocol import platform, process_control
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import RealmStore
from tests.lanes import requires_linux_tree_custody as linux_only


@pytest.fixture
def mode(monkeypatch):
    """Set this process's mode for one test, then restore it."""
    monkeypatch.setattr(platform, "_process_control", None)
    monkeypatch.setattr(platform, "_fallbacks_noted", set())

    def set_mode(value):
        monkeypatch.setattr(platform, "_process_control", value)
    return set_mode


def _no_pidfd(monkeypatch):
    def enosys(*_args, **_kwargs):
        raise OSError(errno.ENOSYS, "pidfd_open: Function not implemented")
    monkeypatch.setattr(platform, "pidfd_open", enosys)


def _no_killpg(monkeypatch):
    def eperm(*_args, **_kwargs):
        raise PermissionError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(platform.os, "killpg", eperm)


# --- the setting ---------------------------------------------------------------

def test_missing_setting_is_strict(tmp_path):
    assert process_control.read_setting(tmp_path) == "strict"


@pytest.mark.parametrize("value", ["strict", "sandbox"])
def test_setting_round_trips(tmp_path, value):
    process_control.write_setting(tmp_path, value)
    assert process_control.read_setting(tmp_path) == value
    assert json.loads((tmp_path / "process-control.json").read_text()) == {"format_version": 1, "process_control": value}


@pytest.mark.parametrize("payload", [
    "not json",
    json.dumps({"format_version": 1, "process_control": "relaxed"}),
    json.dumps({"format_version": 2, "process_control": "sandbox"}),
    json.dumps({"format_version": 1, "process_control": "sandbox", "extra": True}),
    json.dumps(["sandbox"]),
])
def test_invalid_setting_refuses_startup(tmp_path, payload):
    (tmp_path / "process-control.json").write_text(payload)
    with pytest.raises(ConflictError, match="refuse startup"):
        process_control.read_setting(tmp_path)


@linux_only
def test_symlinked_or_non_regular_setting_refuses_startup(tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"format_version": 1, "process_control": "sandbox"}))
    (tmp_path / "process-control.json").symlink_to(target)
    with pytest.raises(ConflictError, match="not a regular file"):
        process_control.read_setting(tmp_path)
    (tmp_path / "process-control.json").unlink()
    (tmp_path / "process-control.json").mkdir()
    with pytest.raises(ConflictError, match="not a regular file"):
        process_control.read_setting(tmp_path)


def test_write_rejects_unknown_modes(tmp_path):
    with pytest.raises(ValueError):
        process_control.write_setting(tmp_path, "off")


def test_mode_is_fixed_once_per_process(mode):
    platform.configure_process_control("sandbox")
    platform.configure_process_control("sandbox")
    assert platform.process_control() == "sandbox"
    with pytest.raises(RuntimeError, match="refusing to change"):
        platform.configure_process_control("strict")
    with pytest.raises(ValueError):
        platform.configure_process_control("off")


def test_unconfigured_process_is_strict(mode):
    assert platform.process_control() == "strict"


def test_workspace_create_and_rerun_write_the_setting(tmp_path):
    from astrid_runtime.workspace import configure_workspace

    paths = RuntimePaths.sandbox(tmp_path)
    profile = SourceProfile("astrid", "/runtime", "/source")

    class Boundary:
        def create(self, **kwargs):
            RealmStore.initialize(kwargs["realm_root"], realm_id=kwargs["realm_id"],
                                  display_name=kwargs["display_name"]).close()
            return {"state": "created", "realm_id": kwargs["realm_id"], "root": str(kwargs["realm_root"])}

        def inspect(self, **kwargs):
            return RealmStore.inspect_realm(kwargs["realm_root"])

    root = paths.realms_dir / "pc-realm"
    created = configure_workspace(paths, Boundary(), BootstrapConfig(source_profile=profile), mode="create",
                                  realm_root=root, realm_id="pc-realm", process_control="sandbox")
    assert created["process_control"] == "sandbox"
    assert process_control.read_setting(paths.runtime_support) == "sandbox"
    assert paths.process_control_path == paths.runtime_support / "process-control.json"
    # Re-running the installer without --sandbox switches it back, even though the selection is unchanged.
    rerun = configure_workspace(paths, Boundary(), BootstrapConfig(source_profile=profile), mode="attach",
                                realm_root=root, realm_id="pc-realm", process_control="strict")
    assert (rerun["status"], rerun["process_control"]) == ("unchanged", "strict")
    # Omitting the option keeps whatever is set.
    kept = configure_workspace(paths, Boundary(), BootstrapConfig(source_profile=profile), mode="attach",
                               realm_root=root, realm_id="pc-realm")
    assert kept["process_control"] == "strict"


def test_cli_accepts_process_control_on_create_and_attach():
    from astrid_runtime.cli import parser

    args = parser().parse_args(["workspace", "create", "--realm-root", "/r", "--process-control", "sandbox"])
    assert args.process_control == "sandbox"
    args = parser().parse_args(["workspace", "attach", "--realm-root", "/r", "--realm-id", "x"])
    assert args.process_control is None
    with pytest.raises(SystemExit):
        parser().parse_args(["workspace", "create", "--realm-root", "/r", "--process-control", "off"])


# --- signal_process fallback -------------------------------------------------

@pytest.fixture
def child():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        yield process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


@linux_only
def test_strict_mode_never_signals_a_bare_pid(mode, monkeypatch, child):
    _no_pidfd(monkeypatch)
    identity = platform.process_identity(child.pid)
    with monkeypatch.context() as scoped:
        scoped.setattr(platform.os, "kill", lambda *_a: pytest.fail("strict mode signalled a bare PID"))
        with pytest.raises(OSError) as raised:
            platform.signal_process(identity, signal.SIGTERM)
    assert raised.value.errno == errno.ENOSYS


@linux_only
def test_sandbox_mode_signals_by_pid_after_a_start_time_check(mode, monkeypatch, child, capsys):
    mode("sandbox")
    _no_pidfd(monkeypatch)
    platform.signal_process(platform.process_identity(child.pid), signal.SIGTERM)
    assert child.wait(timeout=10) == -signal.SIGTERM
    assert "signalling by PID after a /proc start-time check" in capsys.readouterr().err


@linux_only
def test_sandbox_mode_refuses_a_changed_incarnation(mode, monkeypatch, child):
    mode("sandbox")
    _no_pidfd(monkeypatch)
    stale = dict(platform.process_identity(child.pid), birth_id="proc-start-ticks:1")
    with monkeypatch.context() as scoped:
        scoped.setattr(platform.os, "kill", lambda *_a: pytest.fail("signalled a changed incarnation"))
        with pytest.raises(OSError, match="incarnation changed"):
            platform.signal_process(stale, signal.SIGTERM)


@linux_only
def test_sandbox_mode_only_relaxes_enosys(mode, monkeypatch, child):
    mode("sandbox")

    def eperm(*_a, **_k):
        raise PermissionError(errno.EPERM, "denied")
    monkeypatch.setattr(platform, "pidfd_open", eperm)
    identity = platform.process_identity(child.pid)
    with monkeypatch.context() as scoped:
        scoped.setattr(platform.os, "kill", lambda *_a: pytest.fail("fell back on EPERM"))
        with pytest.raises(PermissionError):
            platform.signal_process(identity, signal.SIGTERM)


# --- process-group walk ------------------------------------------------------

def _group_with_children(count=2):
    script = "; ".join(["import subprocess, sys, time"]
                       + [f"subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])" for _ in range(count)]
                       + ["print('ready', flush=True)", "time.sleep(60)"])
    process = platform.spawn_tree([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    assert process.stdout.readline().strip() == "ready"
    return process


def _members(pgid):
    return {m["pid"] for m in platform._linux_group_members(pgid)}


@linux_only
def test_strict_mode_keeps_killpg_failures(mode, monkeypatch):
    process = _group_with_children()
    try:
        with monkeypatch.context() as scoped:
            _no_killpg(scoped)
            with pytest.raises(PermissionError):
                platform.signal_tree(process, signal.SIGTERM)
    finally:
        # Under a real seccomp profile strict cleanup is denied too; clean up in sandbox mode.
        mode("sandbox")
        platform.stop_tree(process, grace=2)


@linux_only
def test_sandbox_mode_walks_the_group_leader_last(mode, monkeypatch):
    mode("sandbox")
    process = _group_with_children()
    pgid = process.pid
    try:
        members = _members(pgid)
        assert process.pid in members and len(members) == 3
        order = []
        real_kill = os.kill
        with monkeypatch.context() as scoped:
            _no_pidfd(scoped)
            _no_killpg(scoped)
            scoped.setattr(platform.os, "kill", lambda pid, sig: (order.append(pid), real_kill(pid, sig)))
            platform.signal_tree(process, signal.SIGKILL)
        assert order[-1] == process.pid and set(order) == members
        assert process.wait(timeout=10) == -signal.SIGKILL
        deadline = time.monotonic() + 10
        while _members(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _members(pgid)
    finally:
        if process.poll() is None:
            platform.stop_tree(process, grace=2)


@linux_only
def test_sandbox_stop_tree_stops_the_whole_group(mode, monkeypatch):
    mode("sandbox")
    process = _group_with_children(3)
    pgid = process.pid
    with monkeypatch.context() as scoped:
        _no_pidfd(scoped)
        _no_killpg(scoped)
        platform.stop_tree(process, grace=2)
    deadline = time.monotonic() + 10
    while _members(pgid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _members(pgid)


@linux_only
def test_group_walk_refuses_our_own_group(mode):
    mode("sandbox")
    with pytest.raises(PermissionError):
        platform.signal_observed_group(os.getpgrp(), 0)


@linux_only
@pytest.mark.needs_real_pidfd
def test_strict_group_recovery_signals_members_without_a_sandbox_note(mode, capsys):
    mode("strict")
    process = _group_with_children()
    pgid = process.pid
    try:
        platform.signal_observed_group(pgid, signal.SIGKILL)
        assert process.wait(timeout=10) == -signal.SIGKILL
        deadline = time.monotonic() + 10
        while _members(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _members(pgid)
        assert "sandbox process control" not in capsys.readouterr().err
    finally:
        if process.poll() is None:
            platform.stop_tree(process, grace=2)


# --- probe -------------------------------------------------------------------

@linux_only
def test_probe_in_a_seccomp_like_environment(mode, monkeypatch):
    _no_pidfd(monkeypatch)
    _no_killpg(monkeypatch)
    strict = platform.process_control_probe()
    assert (strict["ok"], strict["signalling"], strict["group_signalling"]) == (False, "unavailable", "unavailable")
    assert "--sandbox" in strict["reason"]
    sandbox = platform.process_control_probe(mode="sandbox")
    assert sandbox["ok"] is True
    assert (sandbox["signalling"], sandbox["group_signalling"]) == ("pid-with-start-time-check", "member-walk")
    assert (sandbox["pidfd"], sandbox["process_group_kill"]) == ("enosys", "denied")


def test_probe_reports_this_environment(mode):
    report = platform.process_control_probe()
    assert report["process_control"] == "strict"
    if sys.platform != "linux":
        assert report["ok"] is True
        assert "note" in platform.process_control_probe(mode="sandbox")
    elif report["pidfd"] == "available" and report["process_group_kill"] == "allowed":
        assert (report["ok"], report["signalling"], report["group_signalling"]) == (True, "pidfd", "killpg")


def test_doctor_reports_mode_and_probe(tmp_path):
    from astrid_runtime.bootstrap import doctor

    paths = RuntimePaths.sandbox(tmp_path)
    paths.ensure_support_dirs()
    process_control.write_setting(paths.runtime_support, "sandbox")
    report = doctor(paths)
    assert report["process_control"] == "sandbox"
    assert report["process_signalling"]["process_control"] == "sandbox"
    (paths.process_control_path).write_text("{}")
    broken = doctor(paths)
    assert broken["healthy"] is False and any("process-control.json" in issue for issue in broken["issues"])


@linux_only
def test_probe_uses_live_child_group_when_inherited_group_is_unreachable(mode, monkeypatch):
    original = os.killpg
    observed = []
    inherited = os.getpgrp()

    def namespace_killpg(pgid, signum):
        if pgid == inherited:
            raise ProcessLookupError(errno.ESRCH, "group outside PID namespace")
        assert signum == 0
        assert platform.process_identity(pgid) is not None
        assert os.getpgid(pgid) == pgid
        observed.append(pgid)
        return original(pgid, signum)

    monkeypatch.setattr(platform.os, "killpg", namespace_killpg)
    report = platform.process_control_probe()
    assert report["process_group_kill"] == "allowed"
    assert report["ok"] is (report["pidfd"] == "available")
    assert observed and all(platform.process_identity(pid) is None for pid in observed)


@linux_only
@pytest.mark.parametrize("error", [errno.EPERM, errno.ESRCH])
def test_probe_reaps_child_on_group_check_failure(mode, monkeypatch, error):
    observed = []

    def failed_check(pgid, signum):
        observed.append(pgid)
        raise OSError(error, "group check failed")

    monkeypatch.setattr(platform.os, "killpg", failed_check)
    report = platform.process_control_probe()
    assert report["ok"] is False
    assert report["process_group_kill"] == ("denied" if error == errno.EPERM else "error:ESRCH")
    if error == errno.ESRCH:
        assert "PID namespaces" in report["reason"]
        assert "--sandbox" not in report["reason"]
    assert observed and all(platform.process_identity(pid) is None for pid in observed)


@linux_only
def test_probe_child_creation_failure_is_actionable_and_not_a_sandbox_fallback(mode, monkeypatch):
    def denied(*_args, **_kwargs):
        raise PermissionError(errno.EACCES, "cannot create child")

    monkeypatch.setattr(platform.subprocess, "Popen", denied)
    report = platform.process_control_probe(mode="sandbox")
    assert report["ok"] is False
    assert report["process_group_kill"] == "probe-error:EACCES"
    assert "create and signal" in report["reason"]
