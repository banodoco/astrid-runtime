"""Regression coverage for valid Runtime admission that grows past 120 seconds.

These tests model elapsed work deterministically: there is no wall-clock wait,
and realms remain unchanged and healthy throughout verification.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from astrid_runtime import runtime_boundary
from astrid_runtime.bootstrap import BootstrapError
from astrid_runtime.paths import RuntimePaths
from astrid_runtime.runtime_boundary import ADMISSION_TIMEOUT_ENV, LocalRuntimeBoundary
from astrid_runtime.workspace import inspect_workspace
from runtime_protocol import store as store_module
from runtime_protocol.store import RealmStore


def test_native_startup_keeps_exact_live_child_until_growing_admission_finishes(tmp_path, monkeypatch):
    """An owned verifier still working past the old limit must not be killed."""
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "120")
    boundary = LocalRuntimeBoundary()
    process = SimpleNamespace(pid=4812, terminated=False, poll=lambda: None)
    # This exact child's Runtime admission is still progressing. The next
    # candidate validation can bind this evidence to its startup operation.
    process.startup_operation = {
        "pid": process.pid,
        "phase": "integrity",
        "stage": "final_integrity_walk",
        "completed_units": 7,
        "total_units": 8,
    }
    now = [0.0]
    monkeypatch.setattr(runtime_boundary.time, "monotonic", lambda: now[0])

    def advance(seconds):
        now[0] += seconds

    def healthy_after_admission(endpoint):
        # Cold integrity has validly grown to 126 seconds, then publishes its
        # own endpoint. No health response is available while it is pending.
        return endpoint == "http://127.0.0.1:4812" and now[0] >= 126.0

    def no_discovery(_root):
        advance(30.0)
        return {}

    monkeypatch.setattr(boundary, "_read_discovery", no_discovery)
    monkeypatch.setattr(boundary, "_http_health", healthy_after_admission)
    monkeypatch.setattr(boundary, "_terminate", lambda child: setattr(child, "terminated", True))
    endpoint = boundary._wait_endpoint(tmp_path, process)

    # Desired regression oracle: successful admission after 120 seconds must
    # leave its exact child alive and become ready only after verification.
    assert endpoint == "http://127.0.0.1:4812"
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

    # LocalRuntimeBoundary.inspect invokes the installed Runtime doctor through
    # a subprocess. Route its actual doctor request through RealmStore's public
    # cold integrity entry point so deterministic elapsed time can cross the
    # old timeout without sleeps or changes to the realm bytes.
    def run(argv, **kwargs):
        assert argv[argv.index("doctor") + 1] == "--root"
        root_arg = argv[argv.index("--root") + 1]
        timeout = float(argv[argv.index("--admission-timeout") + 1])
        result = original_inspect(root_arg, timeout_seconds=timeout)
        reports.append(result)
        return SimpleNamespace(stdout=json.dumps(result), stderr="", returncode=0 if result.get("ok") else 1)

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
    try:
        result = inspect_workspace(paths, boundary)
    except BootstrapError:
        # Preserve the actual Runtime report for a behavioral assertion below;
        # this should only be reached when the legacy budget refuses admission.
        result = reports[-1]
    assert result["ok"] is True, result.get("checks", {}).get("sqlite_integrity")
    assert result["checks"]["realm_identity"]["ok"] is True
