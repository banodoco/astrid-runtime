"""Runtime start attempts describe launcher continuity across independent operations."""
from contextlib import contextmanager, nullcontext
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

from astrid_runtime import workspace
from astrid_runtime.bootstrap import BootstrapConfig, SourceProfile
from astrid_runtime.paths import RuntimePaths
from runtime_protocol.startup_operation import read_operation
from runtime_protocol.store import RealmStore


REALM_ID = "launch-attempt-realm"


@pytest.fixture
def selection(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTRID_INSTALL_RELEASE", "42")
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "pinokio")
    paths = RuntimePaths.current(tmp_path / "home", data_root=tmp_path / "data")
    paths.ensure_support_dirs()
    root = paths.realms_dir / REALM_ID
    RealmStore.initialize(root, realm_id=REALM_ID).close()
    paths.catalog_path.write_text(json.dumps({
        "version": 1, "selected_realm_id": REALM_ID, "source_profiles": {},
        "realms": [{"realm_id": REALM_ID, "data_root": str(root), "display_name": "Start attempt"}],
    }))
    installed_root = str(Path(sys.prefix).resolve())
    source = SourceProfile("astrid", installed_root, installed_root, runtime_environment=installed_root)
    manifest = tmp_path / "source.json"
    manifest.write_text(json.dumps(source.as_dict()))
    return paths, root, BootstrapConfig(source_manifest=manifest)


def _runtime_args(selection):
    paths, _, config = selection
    return ["--home", str(paths.home), "--data-root", str(paths.app_support),
            "--source-manifest", str(config.source_manifest), "--json"]


def _observe(selection):
    result = subprocess.run(
        [sys.executable, "-m", "astrid_runtime", "startup-status", *_runtime_args(selection)],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode in (0, 1), result.stderr
    return json.loads(result.stdout)


@contextmanager
def _process_waiting_after(script, args, receipt):
    """Hold a process at a real entry-point boundary until the test releases it."""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(receipt), *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not receipt.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if not receipt.exists():
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            pytest.fail(f"local producer did not reach its barrier: {stdout} {stderr}")
        yield process
    finally:
        if process.poll() is None:
            try:
                process.communicate("\n", timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


_INSPECT = """
import pathlib, sys
from astrid_runtime.cli import main
assert main(["workspace", "inspect", "--startup-operation", *sys.argv[2:]]) == 0
pathlib.Path(sys.argv[1]).touch()
sys.stdin.readline()
"""

_INSPECT_RECEIPT = """
import contextlib, io, json, pathlib, sys
from astrid_runtime.cli import main
output = io.StringIO()
with contextlib.redirect_stdout(output):
    returncode = main(["workspace", "inspect", "--startup-operation", *sys.argv[2:]])
pathlib.Path(sys.argv[1]).write_text(json.dumps({"returncode": returncode, "stdout": output.getvalue()}))
sys.stdin.readline()
"""


def _begin(selection, **kwargs):
    paths, _, config = selection
    # A predecessor has no launcher reservation. Still drive the same real
    # inspection, observer and process exit so the behavioral assertion is red.
    begin = getattr(workspace, "begin_startup_attempt", None)
    return nullcontext() if begin is None else begin(paths, config=config, **kwargs)


def test_observers_reattach_to_launcher_arcs_across_offline_verifier_exit(selection, tmp_path):
    paths, _, _ = selection
    with _begin(selection) as attempt:
        with _process_waiting_after(_INSPECT, _runtime_args(selection), tmp_path / "inspected") as verifier:
            offline = read_operation(paths.runtime_support)
            assert offline.owner_pid == verifier.pid
            assert offline.state == "ended"
            if attempt is not None:
                attempt.starting_service()
            before_exit = _observe(selection)
        assert verifier.returncode == 0
        assert read_operation(paths.runtime_support) is None
        after_exit = _observe(selection)
        assert before_exit["state"] == after_exit["state"] == "starting_service"
        assert before_exit == after_exit == {"state": "starting_service", "attempt_id": attempt.attempt_id}
        assert not paths.discovery_path.exists()
        assert not paths.instance_lock_path.exists()


def test_coordinated_inspection_observes_live_starting_service_without_scanning(selection, tmp_path):
    paths, _, _ = selection
    receipt = tmp_path / "live-inspection.json"
    with _begin(selection) as attempt:
        attempt.starting_service()
        expected = {
            "ok": False,
            "state": "starting_service",
            "startup_attempt": {"attempt_id": attempt.attempt_id, "state": "starting_service"},
        }
        with _process_waiting_after(_INSPECT_RECEIPT, _runtime_args(selection), receipt) as observer:
            operation = read_operation(paths.runtime_support)
            assert operation is None, (
                "coordinated observation started an offline verifier during the launcher gap: "
                f"{None if operation is None else operation.as_observation()}"
            )
            envelope = json.loads(receipt.read_text())
            assert envelope["returncode"] == 1
            assert json.loads(envelope["stdout"]) == expected
        assert observer.returncode == 0
        assert not paths.discovery_path.exists()
        assert not paths.instance_lock_path.exists()


def test_coordinated_inspection_preserves_exact_abandoned_starting_service_attempt(selection, tmp_path):
    paths, _, _ = selection
    with _process_waiting_after(_ABANDON, _runtime_args(selection), tmp_path / "abandoned-inspection") as launcher:
        live = _observe(selection)
    assert launcher.returncode == 0
    receipt = tmp_path / "abandoned-inspection-result.json"
    with _process_waiting_after(_INSPECT_RECEIPT, _runtime_args(selection), receipt) as observer:
        operation = read_operation(paths.runtime_support)
        assert operation is None, (
            "coordinated observation retried the abandoned offline verifier: "
            f"{None if operation is None else operation.as_observation()}"
        )
        envelope = json.loads(receipt.read_text())
        assert envelope["returncode"] == 1
        assert json.loads(envelope["stdout"]) == {
            "ok": False,
            "state": "startup_attempt_failed",
            "startup_attempt": {"attempt_id": live["attempt_id"], "state": "failed"},
        }
    assert observer.returncode == 0
    assert _observe(selection) == {"state": "failed", "attempt_id": live["attempt_id"]}
    assert not paths.discovery_path.exists()
    assert not paths.instance_lock_path.exists()


_ABANDON = """
from contextlib import nullcontext
import os, pathlib, sys
from astrid_runtime import workspace
from astrid_runtime.cli import _config, _paths, parser
args = parser().parse_args(["startup-status", *sys.argv[2:]])
paths = _paths(args)
begin = getattr(workspace, "begin_startup_attempt", None)
with (nullcontext() if begin is None else begin(paths, config=_config(args, paths))) as attempt:
    if attempt is not None:
        attempt.starting_service()
    pathlib.Path(sys.argv[1]).touch()
    sys.stdin.readline()
    os._exit(0)
"""


def test_launcher_exit_without_native_operation_is_terminal(selection, tmp_path):
    with _process_waiting_after(_ABANDON, _runtime_args(selection), tmp_path / "attempted") as launcher:
        live = _observe(selection)
    assert launcher.returncode == 0
    terminal = _observe(selection)
    assert terminal["state"] == "failed"
    assert live["state"] == "starting_service"
    assert terminal["attempt_id"] == live["attempt_id"]
    assert _observe(selection) == terminal


def test_live_launcher_blocks_competing_native_bootstrap(selection, tmp_path):
    from astrid_runtime.bootstrap import BootstrapError, bootstrap
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary

    paths, _, config = selection
    with _process_waiting_after(_ABANDON, _runtime_args(selection), tmp_path / "live"):
        live = _observe(selection)
        with pytest.raises(BootstrapError) as refused:
            bootstrap(paths, LocalRuntimeBoundary(), config)
        assert refused.value.details == {"code": "startup_pending", **live}
        assert _observe(selection) == live
        assert not paths.discovery_path.exists()
        assert not paths.instance_lock_path.exists()


def test_a_failed_predecessor_authorizes_only_one_native_retry(selection, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from astrid_runtime.bootstrap import BootstrapError, bootstrap
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary

    paths, _, config = selection
    with _process_waiting_after(_ABANDON, _runtime_args(selection), tmp_path / "retry"):
        predecessor = _observe(selection)["attempt_id"]
    with pytest.raises(BootstrapError) as refused:
        bootstrap(paths, LocalRuntimeBoundary(), config)
    assert refused.value.details == {"code": "startup_attempt_failed", "state": "failed", "attempt_id": predecessor}

    launches = []

    class AdmissionRefuses(LocalRuntimeBoundary):
        def start(self, **_kwargs):
            launches.append(workspace.startup_status(paths, config=config)["attempt_id"])
            raise BootstrapError("independent native admission refused")

    contenders = Barrier(2)

    def retry():
        contenders.wait(timeout=10)
        with pytest.raises(BootstrapError) as result:
            bootstrap(paths, AdmissionRefuses(), config, retry_attempt_id=predecessor)
        return str(result.value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(pool.map(lambda _index: retry(), range(2)))
    assert receipts.count("independent native admission refused") == 1
    assert len(launches) == 1 and launches[0] != predecessor
    assert workspace.startup_status(paths, config=config) == {"state": "failed", "attempt_id": launches[0]}
    assert not paths.discovery_path.exists()
    with pytest.raises(BootstrapError, match="no longer available to retry"):
        bootstrap(paths, AdmissionRefuses(), config, retry_attempt_id=predecessor)
    assert len(launches) == 1
    # An orderly admission refusal still allows the ordinary authorized launch.
    with pytest.raises(BootstrapError, match="independent native admission refused"):
        bootstrap(paths, AdmissionRefuses(), config)
    assert len(launches) == 2 and len(set(launches)) == 2


def test_unknown_launcher_birth_is_unavailable_and_recycled_pid_is_terminal(selection, tmp_path, monkeypatch, capsys):
    import os

    from astrid_runtime.bootstrap import BootstrapError, bootstrap
    from astrid_runtime.cli import main
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
    from runtime_protocol import startup_attempt

    paths, _, config = selection
    with _process_waiting_after(_ABANDON, _runtime_args(selection), tmp_path / "identity") as launcher:
        live = _observe(selection)
        birth_of = startup_attempt._process_birth

        def unknown(pid):
            if pid == launcher.pid:
                raise PermissionError("kernel identity unavailable")
            return birth_of(pid)

        monkeypatch.setattr(startup_attempt, "_process_birth", unknown)
        assert main(["startup-status", *_runtime_args(selection)]) == 1
        assert json.loads(capsys.readouterr().out) == {"state": "unavailable"}
        with pytest.raises(BootstrapError, match="launcher ownership could not be verified"):
            bootstrap(paths, LocalRuntimeBoundary(), config, retry_attempt_id=live["attempt_id"])
        assert not paths.discovery_path.exists()

        # Present an actual different birth in the same process namespace at
        # the recorded PID, as a kernel PID reuse would.
        monkeypatch.setattr(startup_attempt, "_process_birth",
                            lambda pid: birth_of(os.getpid() if pid == launcher.pid else pid))
        assert workspace.startup_status(paths, config=config) == {"state": "failed", "attempt_id": live["attempt_id"]}
        assert launcher.poll() is None


def test_replaced_support_realm_generation_or_unsafe_record_cannot_observe_the_gap(selection, tmp_path, monkeypatch):
    from runtime_protocol import platform, startup_attempt

    paths, root, config = selection
    with _begin(selection) as attempt:
        assert _observe(selection) == {"state": "inspecting_workspace", "attempt_id": attempt.attempt_id}
        attempt.starting_service()
        expected = {"state": "starting_service", "attempt_id": attempt.attempt_id}
        record = paths.runtime_support / startup_attempt.RECORD_NAME
        before = record.read_bytes()
        assert platform.is_owner_only(record, directory=False)
        assert _observe(selection) == expected
        with monkeypatch.context() as changed:
            changed.setenv("ASTRID_INSTALL_RELEASE", "43")
            assert _observe(selection) == {"state": "unavailable"}
        other = RuntimePaths.current(paths.home, data_root=tmp_path / "other-data")
        other.ensure_support_dirs()
        other.catalog_path.write_bytes(paths.catalog_path.read_bytes())
        copied = other.runtime_support / startup_attempt.RECORD_NAME
        copied.write_bytes(before)
        platform.owner_only(copied)
        assert _observe((other, root, config)) == {"state": "unavailable"}
        displaced = root.with_name("original-realm")
        root.rename(displaced)
        root.mkdir()
        try:
            assert _observe(selection) == {"state": "unavailable"}
        finally:
            root.rmdir()
            displaced.rename(root)
        assert _observe(selection) == expected
        assert record.read_bytes() == before

    # This is the same exact path and selection. A private but unbounded
    # receipt must be refused without being changed by the observer.
    record.write_bytes(b"x" * (startup_attempt.MAX_RECORD_BYTES + 1))
    assert _observe(selection) == {"state": "unavailable"}
    assert record.stat().st_size == startup_attempt.MAX_RECORD_BYTES + 1


_NATIVE_OWNER = """
import pathlib, sys
pathlib.Path(sys.argv[1]).touch()
sys.stdin.readline()
"""

_ASSIGN_AND_ABANDON = """
import os, pathlib, sys
from astrid_runtime.bootstrap import _bootstrap_mutex
from astrid_runtime.cli import _config, _paths, parser
from astrid_runtime.workspace import _startup_selection, begin_startup_attempt
from runtime_protocol.startup_operation import StartupOperation
args = parser().parse_args(["startup-status", *sys.argv[3:]])
paths = _paths(args)
config = _config(args, paths)
with begin_startup_attempt(paths, config=config) as attempt:
    attempt.starting_service()
    with _bootstrap_mutex(paths):
        scope = _startup_selection(paths, None, None, config)[3]
        StartupOperation.assign(paths.runtime_support, scope, pid=int(sys.argv[2]))
    pathlib.Path(sys.argv[1]).touch()
    sys.stdin.readline()
    os._exit(0)
"""


def test_independently_owned_native_operation_wins_after_launcher_exit(selection, tmp_path, monkeypatch):
    from astrid_runtime.bootstrap import BootstrapError, bootstrap
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
    from runtime_protocol import startup_operation

    paths, _, config = selection
    with _process_waiting_after(_NATIVE_OWNER, [], tmp_path / "native-alive") as native:
        with _process_waiting_after(
            _ASSIGN_AND_ABANDON, [str(native.pid), *_runtime_args(selection)], tmp_path / "assigned",
        ) as launcher:
            active = read_operation(paths.runtime_support)
            assert active.owner_pid == native.pid != launcher.pid
            assert _observe(selection) == active.as_observation()
        assert launcher.returncode == 0
        assert _observe(selection) == active.as_observation()
        assert not paths.discovery_path.exists()
        assert native.poll() is None
        with monkeypatch.context() as elapsed:
            elapsed.setattr(startup_operation.time, "monotonic_ns",
                            lambda: active.updated_ns + (startup_operation.MAX_AGE_SECONDS + 1) * 10**9)
            assert workspace.startup_status(paths, config=config) == {"state": "unavailable"}
            with pytest.raises(BootstrapError, match="already owns this installation"):
                bootstrap(paths, LocalRuntimeBoundary(), config)
    terminal = _observe(selection)
    assert terminal["state"] == "failed"
    assert terminal["attempt_id"] != active.operation_id


def test_native_operation_published_after_first_read_supersedes_launcher_receipt(
    selection, tmp_path, monkeypatch,
):
    """A fresh exact native operation wins a launcher record read after exit."""
    from threading import Event, Lock, Thread

    paths, _, config = selection
    first_read = Event()
    resume_observer = Event()
    read_lock = Lock()
    read_count = 0
    outcomes = {}
    original_pending = workspace._pending_inspection

    def pause_after_initial_empty_read(paths_arg, scope):
        nonlocal read_count
        result = original_pending(paths_arg, scope)
        with read_lock:
            initial = read_count == 0
            read_count += 1
        if initial:
            assert result is None
            first_read.set()
            if not resume_observer.wait(timeout=10):
                raise TimeoutError("observer test did not resume the pending read")
            return result
        return result

    monkeypatch.setattr(workspace, "_pending_inspection", pause_after_initial_empty_read)

    class NoScanBoundary:
        def inspect_startup(self, *, realm_root):
            raise AssertionError("observer must not run a second offline verifier")

    def observe():
        try:
            outcomes["result"] = workspace.inspect_workspace(
                paths, NoScanBoundary(), startup_operation=True, config=config,
            )
        except BaseException as exc:
            outcomes["error"] = exc

    with _process_waiting_after(_NATIVE_OWNER, [], tmp_path / "native-owner") as native:
        observer = Thread(target=observe, name="startup-gap-observer")
        observer.start()
        try:
            assert first_read.wait(timeout=5), "observer did not capture its initial empty read"
            with _process_waiting_after(
                _ASSIGN_AND_ABANDON,
                [str(native.pid), *_runtime_args(selection)],
                tmp_path / "assigned-then-abandoned",
            ) as launcher:
                from runtime_protocol import startup_attempt

                active = read_operation(paths.runtime_support)
                assert active.owner_pid == native.pid != launcher.pid
                assert active.state == "pending"
                observed_launcher = startup_attempt.read_attempt(paths.runtime_support.resolve())
                launcher_live = observed_launcher.as_observation()
                assert launcher_live["state"] == "starting_service"
            assert launcher.returncode == 0
            from runtime_protocol import startup_attempt

            terminal_attempt = startup_attempt.read_attempt(paths.runtime_support.resolve()).as_observation()
            assert terminal_attempt == {
                "state": "failed", "attempt_id": launcher_live["attempt_id"],
            }
            resume_observer.set()
            observer.join(timeout=10)
            assert not observer.is_alive(), "observer exceeded its bounded join"
        finally:
            resume_observer.set()
            observer.join(timeout=10)

        assert "error" not in outcomes, outcomes.get("error")
        assert outcomes.get("result") == {
            "ok": False,
            "state": "startup_pending",
            "startup_operation": active.as_observation(),
        }
        assert read_operation(paths.runtime_support).operation_id == active.operation_id
        assert not paths.discovery_path.exists()
        assert not paths.instance_lock_path.exists()


_MANAGED_NATIVE = """
import json, pathlib, signal, sys, threading, time
from astrid_runtime import cli
from runtime_protocol.startup_operation import current_verification
from runtime_protocol.store import RealmStore
receipt, resume = map(pathlib.Path, sys.argv[1:3])
args = sys.argv[3:]
original = RealmStore.inspect_realm
original_emit = cli._emit_ready

def emit_ready(result, **kwargs):
    original_emit(result, **kwargs)
    receipt.with_suffix(".ready").touch()

cli._emit_ready = emit_ready

def inspect(root, **kwargs):
    report = original(root, **kwargs)
    status = current_verification(pathlib.Path(root)).snapshot()
    checked = {
        "allow_active_marker": kwargs.get("allow_active_marker"),
        "operation_id": status.operation_id,
        "ok": report["ok"],
        "realm": report["checks"]["realm_identity"]["realm_id"],
    }
    pending = receipt.with_suffix(".pending")
    pending.write_text(json.dumps(checked))
    pending.replace(receipt)
    deadline = time.monotonic() + 20
    while not resume.exists() and time.monotonic() < deadline:
        time.sleep(.02)
    assert resume.exists()
    return report

RealmStore.inspect_realm = staticmethod(inspect)

def stop_on_stdin():
    sys.stdin.readline()
    signal.raise_signal(signal.SIGINT)

threading.Thread(target=stop_on_stdin, daemon=True).start()
expected = {"data_root": args[args.index("--data-root") + 1],
            "profile": args[args.index("--source-manifest") + 1]}
sys.exit(cli.main(["run", *args], managed_launch=expected))
"""


@pytest.mark.integration
def test_existing_managed_service_entry_runs_independent_admission(selection, tmp_path, monkeypatch, astrid_importable):
    import os

    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary

    paths, _, config = selection
    paths.home.mkdir()
    for variable in ("ASTRID_RUNTIME_HOME", "HOME", "USERPROFILE", "XDG_STATE_HOME", "XDG_DATA_HOME", "LOCALAPPDATA"):
        monkeypatch.setenv(variable, str(paths.home))
    runtime_root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(map(str, (runtime_root, runtime_root / "packages" / "python", astrid_importable))))
    version_source = tmp_path / "versions" / "42" / "agent"
    version_source.mkdir(parents=True)
    profile = json.loads(config.source_manifest.read_text())
    profile["source_checkout"] = str(version_source)
    config.source_manifest.write_text(json.dumps(profile))
    run_args = ["--data-root", str(paths.app_support), "--source-manifest", str(config.source_manifest),
                "--hosted-origin", "off", "--json"]
    receipt = tmp_path / "native-verified"
    resume = tmp_path / "publish-service"
    with _begin(selection) as attempt:
        with _process_waiting_after(_INSPECT, _runtime_args(selection), tmp_path / "offline-verified") as verifier:
            offline = read_operation(paths.runtime_support)
            assert offline.owner_pid == verifier.pid
            assert offline.state == "ended"
            attempt.starting_service()
        attempt_file = paths.runtime_support / "startup-attempt.json"
        gap_bytes = attempt_file.read_bytes()
        unapproved = subprocess.run(
            [sys.executable, "-m", "astrid_runtime", "run", *run_args],
            capture_output=True, text=True, timeout=20,
        )
        assert unapproved.returncode == 1
        assert "Managed Astrid must be started by its installation service" in unapproved.stdout
        assert _observe(selection) == {"state": "starting_service", "attempt_id": attempt.attempt_id}

        with _process_waiting_after(_MANAGED_NATIVE, [str(resume), *run_args], receipt) as service:
            try:
                native = read_operation(paths.runtime_support)
                assert native.owner_pid == service.pid != offline.owner_pid
                assert native.operation_id != offline.operation_id
                assert json.loads(receipt.read_text()) == {
                    "allow_active_marker": False, "operation_id": native.operation_id,
                    "ok": True, "realm": REALM_ID,
                }
                assert _observe(selection) == native.as_observation()
                assert not paths.discovery_path.exists()
                assert not paths.instance_lock_path.exists()
                assert not any(row.get("readiness") == "ready" for row in json.loads(paths.catalog_path.read_text())["realms"])
                assert attempt_file.read_bytes() == gap_bytes
            finally:
                resume.touch()
            deadline = time.monotonic() + 20
            boundary = LocalRuntimeBoundary()
            while time.monotonic() < deadline and service.poll() is None:
                discovery = boundary._read_discovery(paths.runtime_support)
                if (receipt.with_suffix(".ready").exists() and discovery.get("pid") == service.pid
                        and boundary._http_health(discovery.get("endpoint", ""))):
                    break
                time.sleep(.02)
            else:
                pytest.fail("Managed Runtime did not complete independently verified native startup.")
            assert attempt_file.read_bytes() == gap_bytes
        assert service.returncode == 0


def test_source_edit_cannot_observe_the_previous_generation(selection, tmp_path, monkeypatch):
    from tests.test_real_bootstrap import _git_checkout

    _, _, config = selection
    runtime_source, product_source = tmp_path / "runtime-source", tmp_path / "product-source"
    _git_checkout(runtime_source)
    _git_checkout(product_source)
    profile = json.loads(config.source_manifest.read_text())
    profile.update(runtime_checkout=str(runtime_source), source_checkout=str(product_source))
    config.source_manifest.write_text(json.dumps(profile))
    monkeypatch.delenv("ASTRID_INSTALL_RELEASE")
    monkeypatch.delenv("ASTRID_INSTALL_MANAGED_BY")
    with _begin(selection) as attempt:
        attempt.starting_service()
        assert _observe(selection) == {"state": "starting_service", "attempt_id": attempt.attempt_id}
        tracked = product_source / "tracked.txt"
        tracked.write_text("different source generation", encoding="utf-8")
        assert _observe(selection) == {"state": "unavailable"}


@pytest.mark.integration
def test_restart_of_verified_incumbent_does_not_stop_at_an_older_abandoned_attempt(
    selection, tmp_path, monkeypatch, astrid_importable, owned_process_groups,
):
    import os

    from astrid_runtime.bootstrap import bootstrap, restart
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary

    paths, _, config = selection
    paths.home.mkdir()
    for variable in ("ASTRID_RUNTIME_HOME", "HOME", "USERPROFILE", "XDG_STATE_HOME", "XDG_DATA_HOME", "LOCALAPPDATA"):
        monkeypatch.setenv(variable, str(paths.home))
    monkeypatch.setenv("ASTRID_INSTALL_MANAGED_BY", "")
    runtime_root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(map(str, (runtime_root, runtime_root / "packages" / "python", astrid_importable))))

    boundary = LocalRuntimeBoundary()
    owned_process_groups.add_cleanup(boundary.stop)
    first = bootstrap(paths, boundary, config)
    assert first.ready
    with _process_waiting_after(_ABANDON, _runtime_args(selection), tmp_path / "orphaned"):
        abandoned = _observe(selection)["attempt_id"]
    assert _observe(selection) == {"state": "failed", "attempt_id": abandoned}
    replacement = restart(paths, boundary, config)
    assert replacement.ready
    assert replacement.runtime_instance_id != first.runtime_instance_id
    assert boundary._http_health(replacement.endpoint)
