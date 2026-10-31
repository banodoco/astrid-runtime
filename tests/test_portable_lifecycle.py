"""Installed-runtime lifecycle checks shared by Linux, macOS, and Windows CI."""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from runtime_protocol import platform
from tests.door_helpers import HOSTED, create_realm, door_call
from astrid_runtime import update


HOSTED_ORIGIN = "https://hosted.test"
ROOT = Path(__file__).resolve().parents[1]
_CHILD_OUTPUT_LIMIT = 4096
_PHASE_EVENT_LIMIT = 16
_PRE_TIMEOUT_STACK_DELAY_SECONDS = 15


def _redacted_tail(value: str | bytes | None) -> str:
    """Keep readiness-failure output small without exposing credential values."""
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    value = value or ""
    tail = value[-_CHILD_OUTPUT_LIMIT:]
    tail = re.sub(
        r'(?i)(["\']?(?:token|authorization|credential|secret|password)["\']?\s*[:=]\s*)'
        r'(?:["\'][^"\']*["\']|\S+)',
        r"\1<redacted>",
        tail,
    )
    tail = re.sub(r"(?i)\b(bearer\s+)[-A-Za-z0-9._~+/]{8,}", r"\1<redacted>", tail)
    return re.sub(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,})\b",
        "<redacted>",
        tail,
    )


def _bounded_file_tail(path: Path | None) -> str:
    """Read only a redacted tail, so timeout evidence never expands with child output."""
    if path is None:
        return ""
    try:
        with path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - _CHILD_OUTPUT_LIMIT))
            return _redacted_tail(source.read())
    except OSError as exc:
        return f"<unavailable: {type(exc).__name__}>"


def _readiness_failure(
    process: subprocess.Popen[str], *, started_monotonic: float, started_unix: float, polls: int,
    phase_path: Path | None = None, stack_path: Path | None = None,
    spawn_started_monotonic: float | None = None, spawn_started_unix: float | None = None,
    spawned_monotonic: float | None = None, spawned_unix: float | None = None,
) -> str:
    """Return bounded child state after an early exit or readiness timeout."""
    observed_monotonic = time.monotonic()
    observed_unix = time.time()
    exit_before_capture = process.poll()
    phase_events = _bounded_file_tail(phase_path)
    pre_timeout_stack = _bounded_file_tail(stack_path)
    if exit_before_capture is None:
        process.kill()
    try:
        stdout, stderr = process.communicate(timeout=5)
        drain = "completed"
    except subprocess.TimeoutExpired as first_timeout:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        try:
            stdout, stderr = process.communicate(timeout=5)
            drain = "completed after forced child kill"
        except subprocess.TimeoutExpired as second_timeout:
            stdout, stderr = second_timeout.output or first_timeout.output, (
                second_timeout.stderr or first_timeout.stderr
            )
            drain = "timed out after bounded 5s + 5s drain"
    details = {
        "child_exit_after_capture": process.returncode,
        "child_exit_before_capture": exit_before_capture,
        "child_output_drain": drain,
        "child_pid": process.pid,
        "child_spawn_started_monotonic": spawn_started_monotonic,
        "child_spawn_started_unix": spawn_started_unix,
        "child_spawned_monotonic": spawned_monotonic,
        "child_spawned_unix": spawned_unix,
        "child_stderr_tail": _redacted_tail(stderr),
        "child_stdout_tail": _redacted_tail(stdout),
        "pre_timeout_python_stack_tail": pre_timeout_stack,
        "readiness_phase_events_tail": phase_events,
        "readiness_elapsed_seconds": round(observed_monotonic - started_monotonic, 3),
        "readiness_observed_monotonic": observed_monotonic,
        "readiness_observed_unix": observed_unix,
        "readiness_polls": polls,
        "readiness_started_monotonic": started_monotonic,
        "readiness_started_unix": started_unix,
    }
    return f"RuntimeDaemon child did not publish readiness: {json.dumps(details, sort_keys=True)}"


def test_readiness_failure_reports_live_child_state(tmp_path: Path):
    started = tmp_path / "child-started"
    phase_path = tmp_path / "phases.json"
    phase_path.write_text(
        json.dumps([{"sequence": 1, "phase": "child_entry", "monotonic_ns": 1, "time_utc": "x"}]),
        encoding="utf-8",
    )
    stack_path = tmp_path / "stack.txt"
    stack_path.write_text("Bearer value-for-stack\nghp_0123456789abcdefghijklmnop\n", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import pathlib, sys, time; print('token=not-for-output', flush=True); "
            "pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(60)",
            str(started),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 5
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()
    diagnostics = _readiness_failure(
        process,
        started_monotonic=time.monotonic(),
        started_unix=time.time(),
        polls=400,
        phase_path=phase_path,
        stack_path=stack_path,
        spawn_started_monotonic=0.5,
        spawn_started_unix=1.5,
        spawned_monotonic=1.0,
        spawned_unix=2.0,
    )
    assert '"child_exit_before_capture": null' in diagnostics
    assert '"child_exit_after_capture":' in diagnostics
    assert '"child_stdout_tail": "token=<redacted>\\n"' in diagnostics
    assert '"child_spawned_monotonic": 1.0' in diagnostics
    assert "child_entry" in diagnostics
    assert "Bearer <redacted>" in diagnostics
    assert "ghp_0123456789abcdefghijklmnop" not in diagnostics
    assert "not-for-output" not in diagnostics


def test_pre_timeout_python_stack_snapshot_is_bounded(tmp_path: Path):
    stack_path = tmp_path / "stack.txt"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import faulthandler, pathlib, sys, time; "
            "output=pathlib.Path(sys.argv[1]).open('w', encoding='utf-8'); "
            "faulthandler.dump_traceback_later(0.01, file=output); time.sleep(0.1); output.close()",
            str(stack_path),
        ],
        capture_output=True,
        text=True,
        timeout=2,
    )
    assert result.returncode == 0, result.stderr
    snapshot = _bounded_file_tail(stack_path)
    assert snapshot
    assert len(snapshot) <= _CHILD_OUTPUT_LIMIT


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


@pytest.mark.integration
def test_real_post_worker_finishes_after_runtime_daemon_process_is_killed(tmp_path: Path, monkeypatch):
    """Real authenticated door POST and Agent run_job; OS-manager survival is not claimed."""
    home = tmp_path / "home"
    home.mkdir()
    data_home = home / "share"
    env = _environment(tmp_path)
    env["XDG_DATA_HOME"] = str(data_home)
    env["PYTHONPATH"] = f"{ROOT}:{ROOT.parent / 'astrid-agent'}"
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    realm = tmp_path / "realm"
    create_realm(realm)
    program = tmp_path / "program with spaces"
    data = tmp_path / "data with spaces"
    version = program / "versions" / "old"
    agent_root = ROOT.parent / "astrid-agent"
    ready, trigger, worker_result = (tmp_path / "daemon.json", tmp_path / "worker.start",
                                     tmp_path / "worker.json")
    phase_path = tmp_path / "readiness-phases.json"
    stack_path = tmp_path / "readiness-stack.txt"
    worker_pid = tmp_path / "worker.pid"
    worker_script = tmp_path / "update-worker.py"
    worker_script.write_text(f"""\
import json, pathlib, sys, time
sys.path[:0] = [{str(agent_root)!r}, {str(ROOT)!r}]
from astrid.installer import update_job as jobs
trigger = pathlib.Path(sys.argv[3])
deadline = time.monotonic() + 20
while not trigger.exists() and time.monotonic() < deadline:
    time.sleep(0.02)
if not trigger.exists():
    raise SystemExit("Runtime handoff trigger was not received")
result = jobs.run_job(pathlib.Path(sys.argv[1]), sys.argv[2])
pathlib.Path(sys.argv[4]).write_text(json.dumps(result))
""", encoding="utf-8")
    child = f"""\
import contextlib, faulthandler, hashlib, json, os, pathlib, secrets, subprocess, sys, time
from types import SimpleNamespace
phase_path=pathlib.Path({str(phase_path)!r}); stack_path=pathlib.Path({str(stack_path)!r})
phases=[]
def phase(name):
    timestamp_ns=time.time_ns(); seconds,nanos=divmod(timestamp_ns,1_000_000_000)
    phases.append({{'sequence':len(phases)+1,'phase':name,'monotonic_ns':time.monotonic_ns(),'time_utc':time.strftime('%Y-%m-%dT%H:%M:%S',time.gmtime(seconds))+f'.{{nanos:09d}}Z'}})
    pending=phase_path.with_name(phase_path.name+'.tmp')
    pending.write_text(json.dumps(phases[-{_PHASE_EVENT_LIMIT}:]),encoding='utf-8')
    os.replace(pending,phase_path)
phase('child_entry')
stack_output=stack_path.open('w',encoding='utf-8')
faulthandler.dump_traceback_later({_PRE_TIMEOUT_STACK_DELAY_SECONDS},repeat=False,file=stack_output)
phase('runtime_import_begin')
sys.path[:0] = [{str(ROOT)!r}, {str(agent_root)!r}]
from astrid_runtime import update
from astrid.installer.service import install_selection
from runtime_protocol import platform
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig, PRODUCT_SCOPES
phase('runtime_import_complete')
home=pathlib.Path(os.environ['HOME']); program=pathlib.Path({str(program)!r}); data=pathlib.Path({str(data)!r})
version=pathlib.Path({str(version)!r}); realm=pathlib.Path({str(realm)!r})
version.mkdir(parents=True); (program/'logs').mkdir(); data.mkdir(parents=True)
agent=version/'agent'; runtime=version/'runtime'; agent.mkdir(); runtime.mkdir()
python=version/'python'; python.write_text('')
profile=version/'profile.json'; profile.write_text(json.dumps({{'profile':'astrid','source_checkout':str(agent),'runtime_checkout':str(runtime)}}))
old={{'root':str(version),'python':str(python),'profile':str(profile),'identity':{{'release':4,'managed_by':None}},'env':{{'ASTRID_INSTALL_RELEASE':'4','ASTRID_INSTALL_MANAGED_BY':''}}}}
(version/'version.json').write_text(json.dumps(old)); (program/'current').write_text('old\\n')
selection=install_selection(home, sys.platform); selection.parent.mkdir(parents=True,exist_ok=True)
selected={{'owner':'haus.astrid.runtime','program_root':str(program),'data_root':str(data),'realm_root':str(realm),'realm_id':'test-realm'}}
selection.write_text(json.dumps(selected)); marker=program/'install.json'; marker.write_text(json.dumps({{'owner':'haus.astrid.runtime','data_root':str(data)}}))
snapshots={{path:path.read_bytes() for path in (selection,program/'current',version/'version.json',profile,marker)}}
fake=SimpleNamespace(root=realm,instance_id='old-instance',startup_identity={{'release':4,'managed_by':None}},startup_identity_instance_id='old-instance',support_root=data/'runtime',service=SimpleNamespace(realm={{'id':'test-realm'}}),_identity_agent_checkout=agent,_identity_runtime_checkout=runtime)
admission=update.UpdateAdmission(fake)
admission._selection=lambda *, allow_pending=False:(selection,snapshots,python,agent,runtime,4)
admission._installer_idle=lambda _path: contextlib.nullcontext()
update.assert_interruption_safe=lambda _root:None
def helper(_python,_agent,_runtime,payload,**kwargs):
    if payload.get('action')=='accept':
        op=payload['operation_id']; job={{'format':'astrid-update-job/v1','operation_id':op,'state':'accepted','job_name':payload['job_name'],'program_root':str(program),'data_root':str(data),'log_path':payload['log_path'],'old_instance_id':payload['old_instance_id'],'old_identity':payload['old_identity'],'old_version':payload['old_version'],'target_release':payload['metadata']['release'],'metadata':payload['metadata'],'message':'Update accepted.'}}
        marker_value=json.loads(marker.read_text()); marker_value['update_job']=job; marker.write_text(json.dumps(marker_value)); return job
    directory=pathlib.Path(payload['directory']); directory.mkdir(exist_ok=True)
    manifest=directory/'manifest'; bootstrap=directory/'bootstrap'; manifest.write_text('{{"release":5}}'); bootstrap.write_text('bootstrap')
    platform.owner_only(manifest); platform.owner_only(bootstrap)
    return {{'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'bootstrap_sha256':hashlib.sha256(bootstrap.read_bytes()).hexdigest(),'release':5}}
admission._helper=helper
trigger=pathlib.Path({str(trigger)!r}); result_path=pathlib.Path({str(worker_result)!r}); worker_pid=pathlib.Path({str(worker_pid)!r})
def launch(job):
    op=job['operation_id']
    worker=subprocess.Popen([sys.executable,{str(worker_script)!r},str(program),op,{str(trigger)!r},{str(worker_result)!r}],cwd={str(ROOT)!r},env=os.environ.copy(),start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    worker_pid.write_text(str(worker.pid))
    return {{'state':'launching','launch_status':'acknowledged'}}
admission.launcher=launch
door_credential=pathlib.Path({str(tmp_path/'door.json')!r})
phase('runtime_daemon_construction_begin')
daemon=RuntimeDaemon(realm,support_root=data/'runtime',door=DoorConfig(origin={HOSTED!r},credential_file=door_credential,port=0))
phase('runtime_daemon_constructed')
phase('runtime_daemon_start_begin')
daemon=daemon.start()
phase('runtime_daemon_started')
daemon.update_admission=admission
fake.instance_id=daemon.instance_id; fake.startup_identity_instance_id=daemon.instance_id
discovery=data/'runtime'/'discovery.json'
phase('product_discovery_read_begin')
published=json.loads(discovery.read_text()); assert published['runtime_instance_id']==daemon.instance_id
phase('product_discovery_published')
phase('fixture_discovery_rewrite_begin')
discovery.parent.mkdir(parents=True,exist_ok=True); discovery.write_text(json.dumps({{'runtime_instance_id':daemon.instance_id,'endpoint':daemon.endpoint,'door_endpoint':daemon.endpoint}}))
phase('fixture_discovery_rewritten')
phase('door_credential_setup_begin')
token,_=daemon.credentials.provision('astrid-door-product',list(PRODUCT_SCOPES))
platform.private_directory(door_credential.parent); door_credential.write_text(json.dumps({{'version':1,'scope':'astrid','actor_id':'astrid-door-product','token':token}})); platform.owner_only(door_credential)
phase('door_credential_setup_complete')
phase('fixture_marker_write_begin')
pathlib.Path({str(ready)!r}).write_text(json.dumps({{'port':daemon.door_httpd.server_port}}))
phase('fixture_marker_written')
while True: time.sleep(1)
"""
    spawn_started_monotonic = time.monotonic()
    spawn_started_unix = time.time()
    runtime_process = subprocess.Popen([sys.executable, "-c", child], cwd=ROOT, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    spawned_monotonic = time.monotonic()
    spawned_unix = time.time()
    worker_result_payload = None
    try:
        readiness_started_monotonic = time.monotonic()
        readiness_started_unix = time.time()
        deadline = time.monotonic() + 20
        readiness_polls = 0
        while not ready.exists() and time.monotonic() < deadline:
            readiness_polls += 1
            if runtime_process.poll() is not None:
                raise AssertionError(_readiness_failure(
                    runtime_process, started_monotonic=readiness_started_monotonic,
                    started_unix=readiness_started_unix, polls=readiness_polls,
                    phase_path=phase_path, stack_path=stack_path,
                    spawn_started_monotonic=spawn_started_monotonic,
                    spawn_started_unix=spawn_started_unix,
                    spawned_monotonic=spawned_monotonic, spawned_unix=spawned_unix,
                ))
            time.sleep(0.05)
        if not ready.exists():
            raise AssertionError(_readiness_failure(
                runtime_process, started_monotonic=readiness_started_monotonic,
                started_unix=readiness_started_unix, polls=readiness_polls,
                phase_path=phase_path, stack_path=stack_path,
                spawn_started_monotonic=spawn_started_monotonic,
                spawn_started_unix=spawn_started_unix,
                spawned_monotonic=spawned_monotonic, spawned_unix=spawned_unix,
            ))
        port = json.loads(ready.read_text(encoding="utf-8"))["port"]
        response = door_call(port, "/api/runtime/v1/update", "POST", body=b"")
        assert response.status == 202, response.body
        accepted_response = json.loads(response.body)
        assert accepted_response["accepted"] is True
        runtime_process.kill()
        runtime_process.wait(timeout=10)
        trigger.touch()
        deadline = time.monotonic() + 20
        while not worker_result.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        worker_result_payload = json.loads(worker_result.read_text(encoding="utf-8"))
        assert worker_result_payload["state"] == "failed"
        assert worker_result_payload["operation_id"] == accepted_response["operation_id"]
        status = update.read_update_status(home, available=True)
        assert status["state"] == "terminal"
        assert status["outcome"] == "failed"
        assert status["result"].startswith("Failed:")
        assert status["operation_id"] == worker_result_payload["operation_id"]
    finally:
        trigger.touch(exist_ok=True)
        if runtime_process.poll() is None:
            runtime_process.kill()
            runtime_process.wait(timeout=10)
        if worker_pid.exists() and not worker_result.exists():
            with contextlib.suppress(OSError, ValueError):
                os.kill(int(worker_pid.read_text()), signal.SIGTERM)


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
