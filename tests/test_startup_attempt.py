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
