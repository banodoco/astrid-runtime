"""Regression coverage for valid Runtime admission that grows past 120 seconds.

These tests model elapsed work deterministically: there is no wall-clock wait,
and realms remain unchanged and healthy throughout verification.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid
from contextlib import redirect_stderr, redirect_stdout

from astrid_runtime import runtime_boundary
from astrid_runtime.bootstrap import BootstrapConfig, BootstrapError, SourceProfile
from astrid_runtime.paths import RuntimePaths
from astrid_runtime.runtime_boundary import ADMISSION_TIMEOUT_ENV, LocalRuntimeBoundary
from astrid_runtime.workspace import inspect_workspace
from runtime_protocol import platform, store as store_module
from runtime_protocol.store import RealmStore


def test_native_startup_keeps_exact_live_child_until_growing_admission_finishes(tmp_path, monkeypatch):
    """An owned verifier still working past the old limit must not be killed."""
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "120")
    boundary = LocalRuntimeBoundary()
    realm_root = tmp_path / "realm"
    RealmStore.initialize(realm_root, realm_id="slow-cold-realm").close()
    assert RealmStore.inspect_realm(realm_root, timeout_seconds=120)["ok"] is True
    process = SimpleNamespace(pid=os.getpid(), terminated=False, poll=lambda: None)
    # This exact child's Runtime admission is still progressing. The next
    # candidate validation can bind this evidence to its startup operation.
    process.startup_operation = {
        "pid": process.pid,
        "phase": "integrity",
        "stage": "final_integrity_walk",
        "completed_units": 7,
        "total_units": 8,
    }
    support = tmp_path / "support"
    platform.private_directory(support)
    if importlib.util.find_spec("runtime_protocol.startup_operation") is not None:
        from runtime_protocol.startup_operation import OperationScope, StartupOperation

        scope = OperationScope.from_selection("slow-cold-realm", realm_root, "0" * 64)
        boundary._startup_operation = StartupOperation.assign(
            support, scope, operation_id=uuid.uuid4().hex, pid=process.pid,
        )
    now = [0.0]
    monkeypatch.setattr(runtime_boundary.time, "monotonic", lambda: now[0])

    def advance(seconds):
        now[0] += seconds

    def healthy_after_admission(endpoint):
        # Cold integrity has validly grown to 126 seconds, then publishes its
        # own endpoint. No health response is available while it is pending.
        return endpoint == f"http://127.0.0.1:{process.pid}" and now[0] >= 126.0

    def candidate_discovery(_root):
        if now[0] >= 126.0:
            return {"pid": process.pid, "endpoint": f"http://127.0.0.1:{process.pid}"}
        return {}

    monkeypatch.setattr(boundary, "_read_discovery", candidate_discovery)
    monkeypatch.setattr(boundary, "_http_health", healthy_after_admission)
    monkeypatch.setattr(boundary, "_terminate", lambda child: setattr(child, "terminated", True))
    monkeypatch.setattr(runtime_boundary.time, "sleep", lambda _seconds: advance(30.0))
    endpoint = boundary._wait_endpoint(support, process)

    # Desired regression oracle: successful admission after 120 seconds must
    # leave its exact child alive and become ready only after verification.
    assert endpoint == f"http://127.0.0.1:{process.pid}"
    assert not process.terminated
    assert now[0] >= 126.0


def test_managed_workspace_inspection_accepts_healthy_cold_admission_past_120s(tmp_path, monkeypatch):
    """Managed attach inspection must not turn valid slow integrity into refusal."""
    from astrid_runtime import runtime_boundary as boundary_module
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "120")
    root = tmp_path / "realm"
    RealmStore.initialize(root, realm_id="slow-cold-realm").close()
    original_inspect = RealmStore.inspect_realm
    cold_report = original_inspect(root, timeout_seconds=120)
    assert cold_report["ok"] is True
    paths = RuntimePaths.current(data_root=tmp_path / "support")
    paths.ensure_support_dirs()
    clock = [0.0]
    monkeypatch.setattr(store_module.time, "monotonic", lambda: clock.__setitem__(0, clock[0] + 30.0) or clock[0])
    reports = []

    # LocalRuntimeBoundary.inspect invokes the installed Runtime CLI through a
    # subprocess. Route that exact public entry point in-process to advance
    # monotonic time without sleeps or changes to the realm bytes.
    from runtime_protocol import cli as runtime_cli

    def run(argv, **kwargs):
        command_start = argv.index("doctor")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            returncode = runtime_cli.main(argv[command_start:])
        output = stdout.getvalue().strip()
        if output:
            reports.append(json.loads(output))
        return SimpleNamespace(stdout=output, stderr=stderr.getvalue(), returncode=returncode)

    monkeypatch.setattr(boundary_module.subprocess, "run", run)
    # The configured managed path falls through to Runtime's read-only doctor
    # when there is no verified live owner.
    paths.catalog_path.write_text(json.dumps({
        "version": 1,
        "selected_realm_id": "slow-cold-realm",
        "source_profiles": {},
        "realms": [{"realm_id": "slow-cold-realm", "data_root": str(root), "display_name": "Cold realm"}],
    }))
    boundary = LocalRuntimeBoundary()
    boundary.is_pid_alive = lambda _pid: False
    # The root is unchanged and healthy; a managed inspection needs a growing
    # operation budget to finish rather than reporting a timeout/refusal.
    source_root = Path(sys.prefix).resolve()
    config = BootstrapConfig(source_profile=SourceProfile(
        "astrid", str(source_root), str(source_root), runtime_environment=str(source_root),
    ))
    try:
        if "startup_operation" in inspect_workspace.__code__.co_varnames:
            result = inspect_workspace(paths, boundary, startup_operation=True, config=config)
        else:
            # Baseline compatibility adapter: keep the exact pre-feature call
            # shape so its real timeout/refusal remains the behavioral red.
            result = inspect_workspace(paths, boundary)
    except BootstrapError:
        # Preserve the actual Runtime report for a behavioral assertion below;
        # this should only be reached when the legacy budget refuses admission.
        result = {"ok": False, "inspection": reports[-1]}
    assert result["ok"] is True, result.get("inspection", {}).get("checks", {}).get("sqlite_integrity")
    assert result["inspection"]["checks"]["realm_identity"]["ok"] is True
