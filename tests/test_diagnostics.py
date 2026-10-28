import json
from pathlib import Path, PureWindowsPath
import sys
from types import SimpleNamespace

import pytest

from astrid_runtime import cli
from astrid_runtime.diagnostics import diagnostics_report, redact
from astrid_runtime.paths import RuntimePaths, _install_record_path
from runtime_protocol import platform


SECRETS = [
    "Authorization: Bearer bearer-secret-123",
    '"authorization": "Bearer json-auth-secret"',
    "Cookie: session=cookie-secret",
    "Set-Cookie: sid=set-cookie-secret",
    '"cookie": "sid=json-cookie-secret"',
    "api_key=api-secret-123",
    "OPENROUTER_API_KEY=sk-or-v1-openroutersecret",
    '"openrouter_api_key": "sk-or-v1-jsonsecret"',
    "token: token-secret-123",
    "password='password-secret'",
    "credential: credential-secret",
    "sk-ant-api03-abcdefghijklmnop",
]


@pytest.mark.parametrize("secret", SECRETS)
def test_secret_shapes_are_redacted_from_logs_and_report(tmp_path, secret):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    log_path = platform.log_dir(paths.home) / "runtime.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_bytes(("prefix\r\n" + secret + "\r\n").encode())
    platform.owner_only(log_path)
    report = diagnostics_report(paths, {"healthy": True, "state": "healthy"})
    assert "[REDACTED]" in report
    assert secret.split("=", 1)[-1].strip("'\"") not in report


def test_report_includes_identity_update_runtime_and_disk_details(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    record_path = _install_record_path(paths.home)
    record_path.parent.mkdir(parents=True)
    record_path.write_text(json.dumps({"owner": "haus.astrid.runtime", "program_root": str(tmp_path / "program"), "managed_by": "source", "identity": {"release": 8, "managed_by": "source"}}))
    program = tmp_path / "program"
    (program / "versions" / "v1").mkdir(parents=True)
    (program / "versions" / "v1" / "copy.bin").write_bytes(b"12345")
    (program / "install-manifest.json").write_text(json.dumps({"release": 8, "agent": {"sha": "build-sha"}}))
    (program / "logs").mkdir()
    (program / "logs" / "launcher.log").write_text("launcher output")
    record_path.parent.mkdir(parents=True, exist_ok=True)
    platform.owner_only(program / "logs", directory=True)
    platform.owner_only(program / "logs" / "launcher.log")
    (program / "update-transaction.json").write_text(json.dumps({"result": "rolled_back", "log": str(program / "update.log")}))
    (program / "update.log").write_text("installer output")
    platform.owner_only(program, directory=True)
    platform.owner_only(program / "update-transaction.json")
    platform.owner_only(program / "update.log")
    runtime_log = platform.log_dir(paths.home) / "runtime.log"
    runtime_log.parent.mkdir(parents=True, exist_ok=True)
    runtime_log.write_text("runtime output")
    platform.owner_only(runtime_log.parent, directory=True)
    platform.owner_only(runtime_log)
    report = diagnostics_report(paths, {"healthy": True, "state": "healthy"})
    assert "App build:" not in report
    assert "App release:" not in report
    assert "build-sha" not in report
    assert "Install identity: managed_by=source; release=8" in report
    assert "Runtime support state: healthy (healthy=True)" in report
    assert "Last update result: rolled_back" in report
    assert "installer output" in report and "launcher output" in report
    assert "Retained back-end copies: 5 bytes" in report


def test_source_checkout_includes_owner_only_launcher_log(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    root = tmp_path / "program"
    record_path = _install_record_path(paths.home)
    record_path.parent.mkdir(parents=True)
    record_path.write_text(json.dumps({"owner": "haus.astrid.runtime", "program_root": str(root), "identity": {"managed_by": "source"}}))
    launcher = root / "logs" / "launcher.log"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("source launcher output")
    platform.owner_only(launcher.parent, directory=True)
    platform.owner_only(launcher)
    report = diagnostics_report(paths, {"healthy": True})
    assert "Launcher log:\nsource launcher output" in report


def test_diagnostics_uses_shared_update_job_result_and_program_root_log(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    record_path = _install_record_path(paths.home)
    record_path.parent.mkdir(parents=True)
    root = tmp_path / "managed-program"
    data_root = tmp_path / "managed-data"
    record_path.write_text(json.dumps({"owner": "haus.astrid.runtime", "program_root": str(root), "data_root": str(data_root)}))
    log = root / "logs" / "accepted-update.log"
    log.parent.mkdir(parents=True)
    log.write_text("worker output")
    platform.owner_only(log.parent, directory=True)
    platform.owner_only(log)
    (root / "install.json").write_text(json.dumps({"owner": "haus.astrid.runtime", "data_root": str(data_root), "update_job": {
        "operation_id": "55555555555555555555555555555555", "state": "updated", "result": "Updated to release 9.",
        "log_path": str(log),
    }}))
    platform.owner_only(root / "install.json")
    report = diagnostics_report(paths, {"healthy": True})
    assert "Last update result: Updated to release 9." in report
    assert "Installer transaction log:\nworker output" in report
    assert f"Update log: {log}" in report


def test_redaction_covers_home_as_native_and_windows_path(tmp_path):
    home = tmp_path / "profile" / "owner"
    value = f"{home} and {PureWindowsPath(str(home))}"
    assert redact(value, home).count("~") == 2


def test_runtime_log_stat_failure_is_reported_without_aborting(tmp_path, monkeypatch):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    target = platform.log_dir(paths.home) / "runtime.log"
    original_stat = Path.stat
    def patched_stat(path, *args, **kwargs):
        if path == target:
            raise PermissionError("patched stat denial")
        return original_stat(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", patched_stat)
    assert "Runtime log tail (runtime.log):\n(not available)" in diagnostics_report(paths, {"healthy": True})


def test_report_does_not_read_non_owner_only_logs(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    target = platform.log_dir(paths.home) / "runtime.log"
    target.parent.mkdir(parents=True)
    target.write_text("private secret data")
    target.chmod(0o644)
    report = diagnostics_report(paths, {"healthy": True})
    assert "private secret data" not in report
    assert "log permissions are not owner-only" in report


def test_missing_home_and_fake_winreg_use_injected_platform_helpers(tmp_path, monkeypatch):
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(HKEY_CURRENT_USER=1))
    monkeypatch.setattr(platform.sys, "platform", "win32")
    paths = RuntimePaths.current(tmp_path / "profile")
    assert paths.home == tmp_path / "profile"
    assert paths.app_support == tmp_path / "profile/AppData/Local/Astrid Runtime"


def test_doctor_text_default_and_json_compatibility(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_paths", lambda _args: RuntimePaths.sandbox(tmp_path))
    monkeypatch.setattr(cli, "doctor", lambda *_args: {"healthy": True, "state": "healthy"})
    assert cli.main(["doctor"]) == 0
    assert "Astrid diagnostics" in capsys.readouterr().out
    assert cli.main(["doctor", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"healthy": True, "state": "healthy"}


def test_real_doctor_issues_are_shown_and_json_unchanged(tmp_path, monkeypatch, capsys):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    monkeypatch.setattr(cli, "_paths", lambda _args: paths)
    assert cli.main(["doctor"]) == 1
    text = capsys.readouterr().out
    assert "Runtime support state: unhealthy (healthy=False)" in text
    assert "catalog_missing" in text
    assert cli.main(["doctor", "--json"]) == 1
    assert "catalog_missing" in json.loads(capsys.readouterr().out)["issues"]


def test_old_journal_uses_default_install_log_and_step(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    root = tmp_path / "program"
    root.mkdir()
    record = _install_record_path(paths.home)
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"owner": "haus.astrid.runtime", "program_root": str(root)}))
    (root / "update-transaction.json").write_text(json.dumps({"step": "complete"}))
    log = platform.log_dir(paths.home) / "install.log"
    log.parent.mkdir(parents=True)
    log.write_text("legacy installer output")
    platform.owner_only(log)
    report = diagnostics_report(paths, {"healthy": True})
    assert "Last update result: complete" in report
    assert "legacy installer output" in report


def test_direct_journal_wins_over_old_job_and_rejects_public_log(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    root = tmp_path / "program"
    root.mkdir()
    data = str(tmp_path / "data")
    record = _install_record_path(paths.home)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"owner": "haus.astrid.runtime", "program_root": str(root), "data_root": data}))
    old_log = root / "old.log"
    old_log.write_text("old job output")
    platform.owner_only(old_log)
    (root / "install.json").write_text(json.dumps({"owner": "haus.astrid.runtime", "data_root": data, "update_job": {"operation_id": "a" * 32, "state": "updated", "result": "old job", "log_path": str(old_log)}}))
    log = root / "current.log"
    log.write_text("private installer output")
    log.chmod(0o644)
    (root / "update-transaction.json").write_text(json.dumps({"step": "rolled_back", "log_path": str(log)}))
    platform.owner_only(record)
    platform.owner_only(root / "install.json")
    platform.owner_only(root / "update-transaction.json")
    report = diagnostics_report(paths, {"healthy": False, "issues": ["bad token=issue-secret"]})
    assert "Last update result: rolled_back" in report
    assert "old job output" not in report and "private installer output" not in report
    assert "log permissions are not owner-only" in report
    assert "issue-secret" not in report


def test_unreadable_current_job_log_does_not_fall_back_to_prior_log(tmp_path):
    paths = RuntimePaths.sandbox(tmp_path / "home")
    root = tmp_path / "program"
    root.mkdir()
    data = str(tmp_path / "data")
    record = _install_record_path(paths.home)
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"owner": "haus.astrid.runtime", "program_root": str(root), "data_root": data}))
    old_log = root / "old.log"
    old_log.write_text("previous output")
    platform.owner_only(old_log)
    public_log = root / "job.log"
    public_log.write_text("current output")
    public_log.chmod(0o644)
    (root / "install.json").write_text(json.dumps({"owner": "haus.astrid.runtime", "data_root": data,
        "update_job": {"operation_id": "a" * 32, "state": "failed", "result": "failed",
                       "prior_transaction_id": "previous", "log_path": str(public_log)}}))
    (root / "update-transaction.json").write_text(json.dumps({"operation_id": "previous", "step": "complete", "log_path": str(old_log)}))
    report = diagnostics_report(paths, {"healthy": True})
    assert "Last update result: failed" in report
    assert "Update log: (not available)" in report
    assert "previous output" not in report and "current output" not in report
