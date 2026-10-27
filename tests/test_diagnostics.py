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
    (record_path.parent / "update-transaction.json").write_text(json.dumps({"result": "rolled_back", "log": str(record_path.parent / "update.log")}))
    (record_path.parent / "update.log").write_text("installer output")
    platform.owner_only(record_path.parent, directory=True)
    platform.owner_only(record_path.parent / "update-transaction.json")
    platform.owner_only(record_path.parent / "update.log")
    runtime_log = platform.log_dir(paths.home) / "runtime.log"
    runtime_log.parent.mkdir(parents=True, exist_ok=True)
    runtime_log.write_text("runtime output")
    platform.owner_only(runtime_log.parent, directory=True)
    platform.owner_only(runtime_log)
    report = diagnostics_report(paths, {"healthy": True, "state": "healthy"})
    assert "App build:" not in report
    assert "App release:" not in report
    assert "build-sha" not in report
    assert "B1 identity: managed_by=source; release=8" in report
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
