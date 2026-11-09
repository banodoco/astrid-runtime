"""Status polls must not launch the update helper while nothing changes (UR-R2.4).

Status is read every few seconds. Starting a helper (and, on Windows, PowerShell) on each
read is a cost with no state change behind it, so repeated polls reuse the last answer.
"""
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest

from astrid_runtime import update

ALL_ACTIONS = sorted(update._SELF_UPDATE_ACTIONS | {"availability"})


def _admission(monkeypatch, tmp_path, platform):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(update.sys, "platform", platform)
    program = tmp_path / "program"
    program.mkdir()
    (program / "install.json").write_text('{"owner": "installer"}', encoding="utf-8")
    record = update._install_record_path(home)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text('{"program_root": "%s"}' % program, encoding="utf-8")
    admission = update.UpdateAdmission(SimpleNamespace())
    admission._selection = lambda **_kwargs: (None, {}, Path("/python"), Path("/agent"), Path("/runtime"), 1)
    launches = []

    def run(argv, **_kwargs):
        launches.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, stdout='{"available": true, "actions": %s}'
                                           % ALL_ACTIONS.__repr__().replace("'", '"'), stderr="")

    monkeypatch.setattr(update.subprocess, "run", run)
    return admission, launches


@pytest.mark.parametrize("platform", ["darwin", "win32", "linux"])
def test_repeated_status_polls_without_state_change_launch_no_helper(tmp_path, monkeypatch, platform):
    admission, launches = _admission(monkeypatch, tmp_path, platform)
    first = admission.status()
    assert first["available"] is True
    after_first = len(launches)
    for _ in range(20):
        assert admission.status()["available"] is True
    assert len(launches) == after_first, "status polls launched a helper without a state change"


def test_install_state_change_refreshes_the_answer(tmp_path, monkeypatch):
    admission, launches = _admission(monkeypatch, tmp_path, "darwin")
    admission.status()
    marker = tmp_path / "program" / "install.json"
    marker.write_text('{"owner": "installer", "changed": true}', encoding="utf-8")
    admission.status()
    assert len(launches) == 2


def test_unresolved_job_is_observed_at_most_every_thirty_seconds(tmp_path, monkeypatch):
    admission, launches = _admission(monkeypatch, tmp_path, "win32")
    marker = tmp_path / "program" / "install.json"
    marker.write_text('{"owner": "installer", "update_job": {"operation_id": "x", "state": "active"}}', encoding="utf-8")
    clock = [1000.0]
    monkeypatch.setattr(update.time, "monotonic", lambda: clock[0])
    admission.status()
    clock[0] += 29.0
    for _ in range(10):
        admission.status()
    assert len(launches) == 1
    clock[0] += 2.0
    admission.status()
    assert len(launches) == 2


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_failed_probe_is_not_cached_and_clears_on_the_next_poll(tmp_path, monkeypatch, platform):
    admission, launches = _admission(monkeypatch, tmp_path, platform)
    healthy = subprocess.CompletedProcess([], 0, stdout='{"available": true, "actions": %s}'
                                          % ALL_ACTIONS.__repr__().replace("'", '"'), stderr="")
    attempts = []

    def run(argv, **_kwargs):
        attempts.append(argv[0])
        if len(attempts) == 1:
            raise OSError("helper could not start")
        return healthy

    monkeypatch.setattr(update.subprocess, "run", run)
    first = admission.status()
    assert first["available"] is False
    second = admission.status()
    assert second["available"] is True and second["self_update"] is True
    assert len(attempts) == 2


def test_settled_job_uses_the_long_refresh(tmp_path, monkeypatch):
    admission, launches = _admission(monkeypatch, tmp_path, "darwin")
    marker = tmp_path / "program" / "install.json"
    marker.write_text('{"owner": "installer", "update_job": {"operation_id": "x", "state": "succeeded"}}',
                      encoding="utf-8")
    clock = [1000.0]
    monkeypatch.setattr(update.time, "monotonic", lambda: clock[0])
    admission.status()
    clock[0] += 60.0
    admission.status()
    assert len(launches) == 1, "a settled job must not be re-observed every 30 seconds"
    clock[0] += 241.0
    admission.status()
    assert len(launches) == 2


WINDOWS_REFUSAL = ("Upgrading from an earlier Windows version isn't supported yet. "
                   "Your data was kept; reinstall to get the new version.")


def _windows_unsupported_reply(kind):
    import json
    if kind == "availability":
        return 0, json.dumps({"available": False, "reason": "windows-upgrade-unsupported", "actions": ALL_ACTIONS})
    return 1, json.dumps({"reason": "windows-upgrade-unsupported", "message": WINDOWS_REFUSAL})


@pytest.mark.parametrize("kind", ["availability", "refusal"])
def test_status_reports_windows_upgrade_unsupported_from_the_helper(tmp_path, monkeypatch, kind):
    """The App shows a line with no retry command only when status.reason says so (Plan 29 R11 card 4)."""
    admission, launches = _admission(monkeypatch, tmp_path, "win32")
    code, stdout = _windows_unsupported_reply(kind)

    def run(argv, **_kwargs):
        launches.append(argv[0])
        return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr="")

    monkeypatch.setattr(update.subprocess, "run", run)
    status = admission.status()
    assert status["available"] is False
    assert status["reason"] == "windows-upgrade-unsupported"
    for _ in range(20):
        assert admission.status()["reason"] == "windows-upgrade-unsupported"
    assert len(launches) == 1, "a steady windows-upgrade-unsupported answer must not start a helper per poll"


def test_explicit_update_keeps_the_windows_upgrade_unsupported_reason(monkeypatch):
    admission = update.UpdateAdmission(SimpleNamespace())
    code, stdout = _windows_unsupported_reply("refusal")
    monkeypatch.setattr(update.subprocess, "run",
                        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=""))
    with pytest.raises(update.UpdateRefusal) as refusal:
        admission._helper(Path("/python"), Path("/agent"), Path("/runtime"), {"action": "launch"})
    assert refusal.value.details["reason"] == "windows-upgrade-unsupported"
