"""Installed-runtime lifecycle checks shared by Linux, macOS, and Windows CI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import sysconfig
import time
import urllib.error
import urllib.request

import pytest

from runtime_protocol import platform


HOSTED_ORIGIN = "https://hosted.test"
ROOT = Path(__file__).resolve().parents[1]


def _python(environment: Path) -> Path:
    scripts = "Scripts" if os.name == "nt" else "bin"
    executable = "python.exe" if os.name == "nt" else "python"
    return environment / scripts / executable


def _environment(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["ASTRID_RUNTIME_HOME"] = str(home)
    env["ASTRID_RUNTIME_DATA_ROOT"] = str(tmp_path / "support")
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["LOCALAPPDATA"] = str(tmp_path / "local-app-data")
    env["XDG_STATE_HOME"] = str(tmp_path / "state")
    return env


def _manifest(tmp_path: Path) -> Path:
    path = tmp_path / "source-profile.json"
    path.write_text(json.dumps({
        "profile": "astrid",
        "runtime_checkout": str(ROOT),
        "source_checkout": str(ROOT),
    }), encoding="utf-8")
    return path


def _command(environment: Path, manifest: Path, *args: str) -> list[str]:
    return [
        str(_python(environment)), "-m", "astrid_runtime.cli", *args,
        "--profile", "astrid", "--data-root", str(manifest.parent / "support"),
        "--source-manifest", str(manifest), "--hosted-origin", HOSTED_ORIGIN,
        "--json",
    ]


def _prepare_workspace(environment: Path, manifest: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(
            environment, manifest, "workspace", "create",
            "--realm-root", str(manifest.parent / "support" / "runtime" / "realms" / "test-realm"),
            "--realm-id", "portable-test",
        ),
        capture_output=True, text=True, timeout=60, env=env,
    )


def test_workspace_setup_uses_installed_cli_and_explicit_realm_without_starting_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    environment = tmp_path / "venv"
    manifest = _manifest(tmp_path)
    env = _environment(tmp_path)
    calls = []

    def capture(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    monkeypatch.setattr(subprocess, "run", capture)
    assert _prepare_workspace(environment, manifest, env).returncode == 0
    argv, kwargs = calls[0]
    assert argv[:4] == [str(_python(environment)), "-m", "astrid_runtime.cli", "workspace"]
    assert argv[4] == "create"
    assert argv[argv.index("--realm-root") + 1] == str(
        tmp_path / "support" / "runtime" / "realms" / "test-realm"
    )
    assert argv[argv.index("--realm-id") + 1] == "portable-test"
    assert kwargs["env"] is env
    assert "run" not in argv and "up" not in argv


def _json_output(result: subprocess.CompletedProcess[str]) -> dict:
    assert result.stdout.strip(), f"Runtime emitted no JSON (exit {result.returncode}): {result.stderr}"
    return json.loads(result.stdout)


def _door_json(endpoint: str, path: str) -> dict:
    request = urllib.request.Request(
        endpoint + path,
        headers={"Host": endpoint.split("//", 1)[1], "Origin": HOSTED_ORIGIN},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_for_discovery(path: Path, process: subprocess.Popen, timeout: float = 60) -> dict:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"foreground Runtime exited {process.returncode}: {process.stdout.read()}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("door_endpoint"):
                return value
        except (OSError, ValueError) as exc:
            last_error = exc
        time.sleep(0.1)
    raise AssertionError(f"Runtime did not publish door discovery: {last_error}")


def _stop_foreground(process: subprocess.Popen) -> None:
    try:
        if process.poll() is None:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                platform.stop_tree(process, grace=2)
                process.wait(timeout=10)
    finally:
        job = getattr(process, "_runtime_job", None)
        if job is not None:
            job.close()


def _expected_log_path(env: dict[str, str]) -> Path:
    if sys.platform == "darwin":
        return Path(env["HOME"]) / "Library" / "Logs" / "Astrid Runtime" / "runtime.log"
    if sys.platform == "win32":
        return Path(env["LOCALAPPDATA"]) / "Astrid Runtime" / "logs" / "runtime.log"
    return Path(env["XDG_STATE_HOME"]) / "astrid-runtime" / "logs" / "runtime.log"


def _cleanup_discovered_owner(environment: Path, manifest: Path, env: dict[str, str], discovery: dict) -> None:
    cleanup = _down(environment, manifest, env)
    if cleanup.returncode == 0:
        return
    expected = {
        "pid": int(discovery["pid"]),
        "uid": platform.current_user(),
        "birth_id": str(discovery["process_birth_id"]),
    }
    observed = platform.process_identity(expected["pid"])
    if observed is None:
        return
    if any(observed.get(key) != value for key, value in expected.items()):
        raise AssertionError(
            "down failed and the discovered Runtime identity no longer matches; "
            f"refusing fallback signal: {cleanup.stderr}{cleanup.stdout}"
        )
    platform.signal_process(expected, platform.TERM)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        current = platform.process_identity(expected["pid"])
        if current is None or current.get("birth_id") != expected["birth_id"]:
            return
        time.sleep(0.1)
    raise AssertionError("identity-pinned fallback stop did not terminate the discovered Runtime")


def _down(environment: Path, manifest: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(environment, manifest, "down"), capture_output=True, text=True,
        timeout=45, env=env,
    )


@pytest.mark.integration
def test_installed_foreground_runtime_owns_discovery_door_and_stops_cleanly(
    tmp_path: Path, stage1_runtime_environment: Path,
):
    manifest = _manifest(tmp_path)
    env = _environment(tmp_path)
    created = _prepare_workspace(stage1_runtime_environment, manifest, env)
    assert created.returncode == 0, created.stderr + created.stdout
    process = platform.spawn_tree(
        _command(stage1_runtime_environment, manifest, "run", "--door-port", "0"),
        cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    discovery_path = tmp_path / "support" / "runtime" / "discovery.json"
    try:
        discovery = _wait_for_discovery(discovery_path, process)
        assert discovery["pid"] == process.pid
        assert discovery["active_realm"]
        assert discovery["runtime_instance_id"]
        endpoint = discovery["door_endpoint"]
        deadline = time.monotonic() + 30
        last_error = None
        while time.monotonic() < deadline:
            try:
                health = _door_json(endpoint, "/api/runtime/v1/health")
                realm = _door_json(endpoint, "/api/runtime/v1/realm")
                break
            except (OSError, urllib.error.URLError, ValueError) as exc:
                last_error = exc
                time.sleep(0.1)
        else:
            raise AssertionError(f"foreground browser door did not become ready: {last_error}")
        assert health["status"] == "ok"
        assert health["runtime_instance_id"] == discovery["runtime_instance_id"]
        assert realm["realm_id"] == discovery["active_realm"]
        # The door can answer before run reports ready; stop only once run has
        # logged its own readiness, so this exercises stopping a running Runtime.
        log_path = _expected_log_path(env)
        deadline = time.monotonic() + 30
        while "door_endpoint" not in (log_path.read_text(encoding="utf-8") if log_path.is_file() else ""):
            assert time.monotonic() < deadline, "run did not report ready"
            time.sleep(0.1)
    finally:
        _stop_foreground(process)
    assert process.returncode == 0
    assert log_path.is_file()
    assert "door_endpoint" in log_path.read_text(encoding="utf-8")


@pytest.mark.integration
def test_installed_foreground_use_down_then_up_again(
    tmp_path: Path, stage1_runtime_environment: Path,
):
    manifest = _manifest(tmp_path)
    env = _environment(tmp_path)
    # The offline Runtime wheel fixture contains no optional Agent dependencies.
    # Supply the test interpreter's dependencies without changing that venv.
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (env.get("PYTHONPATH"), sysconfig.get_path("purelib"))))
    created = _prepare_workspace(stage1_runtime_environment, manifest, env)
    assert created.returncode == 0, created.stderr + created.stdout
    discovery_path = tmp_path / "support" / "runtime" / "discovery.json"
    for _ in range(2):
        process = platform.spawn_tree(
            _command(stage1_runtime_environment, manifest, "run", "--door-port", "0"),
            cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        try:
            discovery = _wait_for_discovery(discovery_path, process)
            deadline = time.monotonic() + 30
            while True:
                try:
                    assert _door_json(discovery["door_endpoint"], "/api/runtime/v1/realm")["realm_id"] == discovery["active_realm"]
                    break
                except (OSError, urllib.error.URLError):
                    assert time.monotonic() < deadline
                    time.sleep(0.1)
            stopped = _down(stage1_runtime_environment, manifest, env)
            assert stopped.returncode == 0, stopped.stderr + stopped.stdout
            assert _json_output(stopped)["status"] == "stopped"
            assert process.wait(timeout=30) == 0
        finally:
            if process.poll() is None:
                _stop_foreground(process)
    up = subprocess.run(
        _command(stage1_runtime_environment, manifest, "up", "--wait", "--door-port", "0"),
        capture_output=True, text=True, timeout=90, env=env,
    )
    try:
        assert up.returncode == 0, up.stderr + up.stdout
        discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
        assert _door_json(discovery["door_endpoint"], "/api/runtime/v1/realm")["realm_id"] == discovery["active_realm"]
    finally:
        if discovery_path.exists():
            _cleanup_discovered_owner(stage1_runtime_environment, manifest, env, json.loads(discovery_path.read_text(encoding="utf-8")))


@pytest.mark.integration
def test_installed_up_wait_and_down_stop_the_exact_discovered_owner(
    tmp_path: Path, stage1_runtime_environment: Path,
):
    manifest = _manifest(tmp_path)
    env = _environment(tmp_path)
    created = _prepare_workspace(stage1_runtime_environment, manifest, env)
    assert created.returncode == 0, created.stderr + created.stdout
    up = subprocess.run(
        _command(stage1_runtime_environment, manifest, "up", "--wait", "--door-port", "0"),
        capture_output=True, text=True, timeout=90, env=env,
    )
    discovery_path = tmp_path / "support" / "runtime" / "discovery.json"
    discovery = None
    try:
        assert up.returncode == 0, up.stderr + up.stdout
        ready = _json_output(up)
        discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
        assert ready["realm_id"] == discovery["active_realm"]
        assert ready["door_endpoint"] == discovery["door_endpoint"]
        assert _door_json(discovery["door_endpoint"], "/api/runtime/v1/health")["status"] == "ok"
        assert _door_json(discovery["door_endpoint"], "/api/runtime/v1/realm")["realm_id"] == discovery["active_realm"]
        down = subprocess.run(
            _command(stage1_runtime_environment, manifest, "down"),
            capture_output=True, text=True, timeout=60, env=env,
        )
        assert down.returncode == 0, down.stderr + down.stdout
        stopped = _json_output(down)
        assert stopped["status"] == "stopped"
        assert stopped["realm_id"] == discovery["active_realm"]
        deadline = time.monotonic() + 10
        while discovery_path.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not discovery_path.exists()
    finally:
        if discovery_path.exists():
            if discovery is None:
                discovery = json.loads(discovery_path.read_text(encoding="utf-8"))
            _cleanup_discovered_owner(stage1_runtime_environment, manifest, env, discovery)


@pytest.mark.integration
def test_installed_up_reports_occupied_browser_door_without_claiming_owner(
    tmp_path: Path, stage1_runtime_environment: Path,
):
    manifest = _manifest(tmp_path)
    env = _environment(tmp_path)
    created = _prepare_workspace(stage1_runtime_environment, manifest, env)
    assert created.returncode == 0, created.stderr + created.stdout
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        result = subprocess.run(
            _command(stage1_runtime_environment, manifest, "up", "--wait", "--door-port", str(port)),
            capture_output=True, text=True, timeout=90, env=env,
        )
        assert result.returncode != 0
        payload = _json_output(result)
        assert payload.get("ok") is False
        reason = payload.get("error", "").lower()
        assert str(port) in reason
        assert "already in use" in reason or "already served" in reason
    discovery_path = tmp_path / "support" / "runtime" / "discovery.json"
    assert not discovery_path.exists(), "failed startup left a claimed runtime discovery"
