"""Status polls must not launch the update helper while nothing changes (UR-R2.4).

Status is read every few seconds. Starting a helper (and, on Windows, PowerShell) on each
read is a cost with no state change behind it, so repeated polls reuse the last answer.
"""
from pathlib import Path
from types import SimpleNamespace
import json
import subprocess

import pytest

from astrid_runtime import update

ALL_ACTIONS = sorted(update._SELF_UPDATE_ACTIONS | {"availability"})


def _no_pointer_admission(monkeypatch, tmp_path, platform, *, login_task, choices=None):
    """Status through the real _selection for an install with no program/current pointer.

    Nothing in the selection is stubbed except identity normalization. The Windows
    sign-in task query (PowerShell) and the helper are fakes that record their launches.
    """
    home, data, realm = tmp_path / "home", tmp_path / "data", tmp_path / "realm"
    agent, runtime, program = tmp_path / "agent", tmp_path / "runtime", tmp_path / "program"
    for folder in (home, data, realm, agent, runtime, program):
        folder.mkdir()
    monkeypatch.setattr(update.Path, "home", classmethod(lambda _cls: home))
    monkeypatch.setattr(update.sys, "platform", platform)
    monkeypatch.setattr(update, "normalize_startup_identity", lambda _value: {"release": 0, "managed_by": None})
    (program / "install.json").write_text(
        json.dumps({"owner": update.INSTALL_RECORD_OWNER, "data_root": str(data)}), encoding="utf-8")
    record = update._install_record_path(home)
    record.parent.mkdir(parents=True, exist_ok=True)
    selected = {
        "owner": update.INSTALL_RECORD_OWNER, "program_root": str(program), "data_root": str(data),
        "realm_root": str(realm), "realm_id": "realm-1"}
    if choices is not None:
        selected["choices"] = choices
    record.write_text(json.dumps(selected), encoding="utf-8")
    daemon = SimpleNamespace(
        startup_identity={}, startup_identity_instance_id=1, instance_id=1, root=realm,
        support_root=data / "runtime", service=SimpleNamespace(realm={"id": "realm-1"}),
        _identity_agent_checkout=str(agent), _identity_runtime_checkout=str(runtime))
    admission = update.UpdateAdmission(daemon)
    launches, queries = [], []

    def run(argv, **_kwargs):
        if str(argv[0]).endswith("powershell.exe"):
            queries.append(argv[0])
            return subprocess.CompletedProcess(argv, 0, stdout="ASTRID_TASK_COUNT=%d\n" % int(login_task), stderr="")
        launches.append(argv[0])
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(
            {"available": False, "reason": "windows-upgrade-unsupported", "actions": ALL_ACTIONS}), stderr="")

    monkeypatch.setattr(update.subprocess, "run", run)
    return admission, launches, queries


def test_win32_r0_no_current_pointer_with_login_task_reports_windows_upgrade_unsupported_once(tmp_path, monkeypatch):
    """Windows R0 with no program/current pointer and the sign-in task: the helper answers, once (Plan 29 card 4)."""
    admission, launches, queries = _no_pointer_admission(monkeypatch, tmp_path, "win32", login_task=True)
    for _ in range(20):
        status = admission.status()
        assert status["available"] is False
        assert status["reason"] == "windows-upgrade-unsupported"
    assert len(launches) == 1, "the helper must be launched once across steady polls"
    assert len(queries) == 1, "the sign-in task query must not run on every poll"


def test_win32_no_current_pointer_without_login_task_stays_needs_repair(tmp_path, monkeypatch):
    admission, launches, queries = _no_pointer_admission(monkeypatch, tmp_path, "win32", login_task=False)
    for _ in range(20):
        assert admission.status()["reason"] == "needs-repair"
    assert launches == []
    assert len(queries) <= 1, "the negative sign-in task answer must be reused, not queried per poll"


def test_win32_no_current_pointer_with_pending_journal_stays_needs_repair(tmp_path, monkeypatch):
    admission, launches, _queries = _no_pointer_admission(monkeypatch, tmp_path, "win32", login_task=True)
    (tmp_path / "program" / "update-transaction.json").write_text('{"step": "switched"}', encoding="utf-8")
    assert admission.status()["reason"] == "needs-repair"
    assert launches == []


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_non_windows_no_current_pointer_stays_needs_repair(tmp_path, monkeypatch, platform):
    admission, launches, queries = _no_pointer_admission(monkeypatch, tmp_path, platform, login_task=True)
    for _ in range(3):
        assert admission.status()["reason"] == "needs-repair"
    assert launches == [] and queries == []


def test_status_refuses_saved_autostart_off_choice_before_the_windows_handoff(tmp_path, monkeypatch):
    """choices.autostart false refuses status with autostart-off, ahead of the R0 handoff (Plan 29 R12)."""
    admission, launches, queries = _no_pointer_admission(
        monkeypatch, tmp_path, "win32", login_task=True, choices={"autostart": False})
    for _ in range(3):
        assert admission.status()["reason"] == "autostart-off"
    assert launches == [] and queries == []


@pytest.mark.parametrize("value", ["off", 0, None], ids=["string-off", "zero", "null"])
def test_status_reports_needs_repair_for_a_non_boolean_autostart_choice(tmp_path, monkeypatch, value):
    """The Agent's validator accepts only booleans. A malformed saved value is needs-repair, never a silent on."""
    admission, launches, _queries = _no_pointer_admission(
        monkeypatch, tmp_path, "win32", login_task=True, choices={"autostart": value})
    for _ in range(3):
        assert admission.status()["reason"] == "needs-repair"
    assert launches == []


@pytest.mark.parametrize("choices", [None, {"autostart": True}], ids=["absent", "on"])
def test_status_does_not_refuse_an_absent_or_on_autostart_choice(tmp_path, monkeypatch, choices):
    """With the guard passed, the Windows R0 handoff answers as before (Plan 29 R12)."""
    admission, launches, _queries = _no_pointer_admission(
        monkeypatch, tmp_path, "win32", login_task=True, choices=choices)
    assert admission.status()["reason"] == "windows-upgrade-unsupported"
    assert len(launches) == 1


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


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_interrupted_terminal_update_with_autostart_off_reads_recovery_needed_and_busy(tmp_path, monkeypatch, platform):
    """R13b: recovery-needed never carries a policy reason. The App keys recovery copy off the state.

    A user with autostart off updates from a terminal; an interrupted install-line update leaves a
    non-terminal journal and no app job. Status says recovery-needed with reason busy, the same
    normalization POST applies to a recovery refusal (runtime_protocol/server.py), not autostart-off.
    """
    admission, launches, _queries = _no_pointer_admission(
        monkeypatch, tmp_path, platform, login_task=True, choices={"autostart": False})
    (tmp_path / "program" / "update-transaction.json").write_text(json.dumps({"step": "switched"}), encoding="utf-8")
    status = admission.status()
    assert status["state"] == "recovery-needed"
    assert status["reason"] == "busy"
    assert launches == []


_POLICY_REASONS = ["autostart-off", "unsupported-service-manager", "windows-upgrade-unsupported",
                   "managed-elsewhere", "source"]


def _pending_journal_install(tmp_path, monkeypatch):
    home, root, data = tmp_path / "home", tmp_path / "program", tmp_path / "data"
    for folder in (home, root, data):
        folder.mkdir()
    record = update._install_record_path(home)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"owner": update.INSTALL_RECORD_OWNER, "program_root": str(root),
                                  "data_root": str(data)}), encoding="utf-8")
    (root / "install.json").write_text(json.dumps({"owner": update.INSTALL_RECORD_OWNER, "data_root": str(data)}),
                                       encoding="utf-8")
    (root / "update-transaction.json").write_text(json.dumps({"step": "stopping"}), encoding="utf-8")
    return home


@pytest.mark.parametrize("reason", _POLICY_REASONS)
def test_recovery_needed_status_reads_busy_in_place_of_a_policy_reason(tmp_path, monkeypatch, reason):
    home = _pending_journal_install(tmp_path, monkeypatch)
    status = update.read_update_status(home, available=False, reason=reason)
    assert status["state"] == "recovery-needed"
    assert status["reason"] == "busy"


@pytest.mark.parametrize("reason", ["busy", None])
def test_recovery_needed_status_keeps_busy_and_needs_repair(tmp_path, monkeypatch, reason):
    home = _pending_journal_install(tmp_path, monkeypatch)
    status = update.read_update_status(home, available=False, reason=reason)
    assert status["state"] == "recovery-needed"
    assert status["reason"] == ("busy" if reason == "busy" else "needs-repair")


@pytest.mark.parametrize("reason", _POLICY_REASONS)
def test_a_policy_reason_is_kept_when_no_recovery_is_needed(tmp_path, monkeypatch, reason):
    home = tmp_path / "home"
    home.mkdir()
    status = update.read_update_status(home, available=False, reason=reason)
    assert status["state"] == "none"
    assert status["reason"] == reason
