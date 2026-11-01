"""Detached Runtime startup must retain the interpreter's PID on Windows."""

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import venv

import pytest

from astrid_runtime.bootstrap import BootstrapError, SourceProfile
from astrid_runtime import runtime_boundary
from runtime_protocol import windows_handoff
from tests.lanes import requires_windows_runtime_venv


@pytest.mark.parametrize("selected_venv", [True, False])
def test_windows_daemon_launch_preserves_selected_python(tmp_path, monkeypatch, selected_venv):
    base = tmp_path / "base"
    base.mkdir()
    executable = base / "python.exe"
    executable.touch()
    selected = executable
    if selected_venv:
        root = tmp_path / "selected"
        (root / "Scripts").mkdir(parents=True)
        selected = root / "Scripts" / "python.exe"
        selected.touch()
        (root / "pyvenv.cfg").write_text(f"home = {base}\n", encoding="utf-8")
    monkeypatch.setattr(runtime_boundary, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(windows_handoff, "sys", SimpleNamespace(executable="other-python"))
    monkeypatch.setenv("__PYVENV_LAUNCHER__", "stale-python")
    monkeypatch.setenv("ASTRID_RUNTIME_DOOR_PORT", "17341")
    child = SimpleNamespace()
    calls = []
    monkeypatch.setattr(runtime_boundary.platform, "spawn_tree", lambda argv, **kwargs: (
        calls.append((argv, kwargs)) or child
    ))

    boundary = runtime_boundary.LocalRuntimeBoundary()
    process, broker = boundary._spawn_runtime(
        [str(selected), "-X", "utf8", "-m", "runtime_protocol", "start"],
        support_root=tmp_path, stdout=subprocess.DEVNULL,
    )

    argv, options = calls[0]
    assert argv == [str(executable), "-X", "utf8", "-m", "runtime_protocol", "start"]
    assert options["env"].get("__PYVENV_LAUNCHER__") == (str(selected) if selected_venv else None)
    assert options["env"]["ASTRID_RUNTIME_DOOR_PORT"] == "17341"
    assert os.environ["__PYVENV_LAUNCHER__"] == "stale-python"
    assert options["detached"] is True and options["close_fds"] is True
    assert process is child and boundary._process is child and broker is None


@pytest.mark.parametrize("selected_venv", [True, False])
def test_windows_realm_creation_preserves_selected_python(tmp_path, monkeypatch, selected_venv):
    base = tmp_path / "base"
    base.mkdir()
    executable = base / "python.exe"
    executable.touch()
    environment = tmp_path / "direct"
    (environment / "Scripts").mkdir(parents=True)
    selected = environment / "Scripts" / "python.exe"
    selected.touch()
    selected.chmod(0o755)
    if selected_venv:
        environment = tmp_path / "selected"
        (environment / "Scripts").mkdir(parents=True)
        selected = environment / "Scripts" / "python.exe"
        selected.touch()
        selected.chmod(0o755)
        (environment / "pyvenv.cfg").write_text(f"home = {base}\n", encoding="utf-8")
    monkeypatch.setattr(runtime_boundary, "sys", SimpleNamespace(platform="win32", executable="other-python"))
    monkeypatch.setattr(windows_handoff, "sys", SimpleNamespace(executable="other-python"))
    monkeypatch.setattr(runtime_boundary.platform, "venv_python", lambda root: root / "Scripts" / "python.exe")
    monkeypatch.setenv("__PYVENV_LAUNCHER__", "stale-python")
    calls = []
    monkeypatch.setattr(runtime_boundary.subprocess, "run", lambda argv, **kwargs: (
        calls.append((argv, kwargs)) or SimpleNamespace(stdout='{"realm_id":"realm"}', returncode=0)
    ))

    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path),
                            runtime_environment=str(environment))
    created = runtime_boundary.LocalRuntimeBoundary().create(
        realm_id="realm", realm_root=tmp_path / "new-realm",
        display_name="Astrid Workspace", source_profile=profile,
    )

    argv, options = calls[0]
    assert created == {"realm_id": "realm"}
    expected = executable if selected_venv else selected
    assert argv[:5] == [str(expected), "-X", "utf8", "-m", "runtime_protocol"]
    assert options["env"].get("__PYVENV_LAUNCHER__") == (str(selected) if selected_venv else None)
    assert os.environ["__PYVENV_LAUNCHER__"] == "stale-python"


def test_windows_realm_creation_preserves_non_json_child_diagnostic(tmp_path, monkeypatch):
    environment = tmp_path / "selected"
    (environment / "Scripts").mkdir(parents=True)
    selected = environment / "Scripts" / "python.exe"
    selected.touch()
    selected.chmod(0o755)
    monkeypatch.setattr(runtime_boundary, "sys", SimpleNamespace(platform="win32", executable="other-python"))
    monkeypatch.setattr(windows_handoff, "sys", SimpleNamespace(executable="other-python"))
    monkeypatch.setattr(runtime_boundary.platform, "venv_python", lambda root: root / "Scripts" / "python.exe")
    monkeypatch.setattr(
        runtime_boundary.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="child startup diagnostic", returncode=0),
    )
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path),
                            runtime_environment=str(environment))

    with pytest.raises(BootstrapError, match="'child startup diagnostic'"):
        runtime_boundary.LocalRuntimeBoundary().create(
            realm_id="realm", realm_root=tmp_path / "new-realm",
            display_name="Astrid Workspace", source_profile=profile,
        )


@pytest.mark.integration
@requires_windows_runtime_venv
def test_windows_update_backup_up_uses_the_actual_venv_interpreter(tmp_path, monkeypatch):
    for name, suffix in {
        "HOME": "home", "USERPROFILE": "home", "LOCALAPPDATA": "local",
        "APPDATA": "roaming", "XDG_STATE_HOME": "state",
    }.items():
        folder = tmp_path / suffix
        folder.mkdir(exist_ok=True)
        monkeypatch.setenv(name, str(folder))
    monkeypatch.setenv("ASTRID_RUNTIME_DOOR_PORT", "17341")
    environment = tmp_path / "selected venv"
    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(environment)
    python = environment / "Scripts" / "python.exe"
    probe = subprocess.Popen(
        [str(python), "-c", "import os; print(os.getpid())"], stdout=subprocess.PIPE, text=True,
    )
    output, _ = probe.communicate()
    assert probe.returncode == 0
    assert int(output) != probe.pid
    print(f"Uncorrected venv launcher PID {probe.pid}; interpreter PID {output.strip()}")

    boundary = runtime_boundary.LocalRuntimeBoundary()
    child, _ = boundary._spawn_runtime(
        [str(python), "-c", "import json,os,sys; from runtime_protocol import platform; "
         "print(json.dumps({'pid':os.getpid(),'prefix':sys.prefix,'executable':sys.executable,"
         "'job':bool(platform._inherited_job_handle)}))"],
        support_root=tmp_path, stdout=subprocess.PIPE,
    )
    try:
        output, _ = child.communicate()
        assert child.returncode == 0, output
        report = json.loads(output)
        assert report["pid"] == child.pid
        assert Path(report["prefix"]) == environment
        assert Path(report["executable"]) == python
        assert report["job"] is True
    finally:
        if child.poll() is None:
            boundary.stop()
        child._runtime_job.close()

    checkout = Path(__file__).resolve().parents[1]
    manifest = tmp_path / "source-profile.json"
    manifest.write_text(json.dumps({
        "profile": "astrid", "runtime_checkout": str(checkout),
        "source_checkout": str(checkout), "runtime_environment": str(environment),
    }), encoding="utf-8")
    data = tmp_path / "support"

    def command(*args, profile=True):
        result = subprocess.run(
            [str(python), "-X", "utf8", "-I", "-m", "astrid_runtime", *args,
             "--data-root", str(data), "--json",
             *(["--source-manifest", str(manifest)] if profile else [])],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        assert result.returncode == 0, result.stdout
        value = json.loads(result.stdout)
        assert value.get("ok") is not False, value
        return value

    command("workspace", "create", "--realm-root", str(data / "runtime/realms/update"), "--realm-id", "update")
    try:
        command("up", "--hosted-origin", "off")
        discovery = json.loads((data / "runtime/discovery.json").read_text(encoding="utf-8"))
        assert not discovery.get("door_endpoint")
        command("backup", "--destination", str(tmp_path / "backup"), profile=False)
        print(f"Neutral update daemon ready at PID {discovery['pid']}; authenticated backup succeeded")
    finally:
        command("down")
