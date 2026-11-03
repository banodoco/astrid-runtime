"""L1: stale publication cleanup against R0's owner-for-life lock model.

R0 6d53a190: store.py RealmStore/_acquire_owner and daemon.py start
publish the marker/discovery after acquiring the shared owner.lock.
"""
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

bootstrap = importlib.import_module("astrid_runtime.bootstrap")
import test_bootstrap


@pytest.fixture
def stale(monkeypatch):
    case = test_bootstrap.BootstrapTests()
    case.setUp()
    try:
        root = case._configure()
        marker = {"pid": 12345, "process_birth_id": "proc-start-ticks:123",
                  "runtime_instance_id": "r0-instance", "realm_id": "configured-realm",
                  "realm_root": str(root)}
        discovery = {"version": 1, "endpoint": "http://127.0.0.1:43100",
                     "pid": marker["pid"], "process_birth_id": marker["process_birth_id"],
                     "runtime_instance_id": marker["runtime_instance_id"],
                     "active_realm": marker["realm_id"], "realm_root": str(root),
                     "protocol_version": "workspace.v1", "schema_version": "workspace-schema-v1",
                     "coordinator_epoch": marker["runtime_instance_id"], "credential_file": "credential"}
        case.paths.instance_lock_path.write_text(json.dumps(marker))
        case.paths.discovery_path.write_text(json.dumps(discovery))
        # Isolate the final lock from the earlier PID and lock observations.
        monkeypatch.setattr(bootstrap, "_owner_may_be_alive", lambda *_: False)
        yield case, root
    finally:
        case.tearDown()
        case.doCleanups()


COMPETING_OWNER = r'''
import os, sys
from pathlib import Path
from runtime_protocol import platform
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    try:
        platform.lock_file(fd, blocking=False)
    except BlockingIOError:
        sys.exit(73)
    for name in sys.argv[2:]:
        Path(name).write_text('{"replacement": true}')
    platform.unlock_file(fd)
finally:
    os.close(fd)
'''


@pytest.mark.parametrize("removal", [1, 2])
def test_competing_owner_cannot_publish_during_final_removals(stale, monkeypatch, removal):
    case, root = stale
    original_remove = bootstrap.remove_file
    calls = []
    results = []
    def remove_at_boundary(path):
        calls.append(path)
        if len(calls) == removal:
            result = subprocess.run([sys.executable, "-c", COMPETING_OWNER, str(root / "owner.lock"),
                                     str(case.paths.discovery_path), str(case.paths.instance_lock_path)],
                                    capture_output=True, text=True, timeout=20)
            results.append(result)
        original_remove(path)
    monkeypatch.setattr(bootstrap, "remove_file", remove_at_boundary)
    assert bootstrap._reclaim_stale_owner_locked(case.paths, case.boundary)
    assert len(calls) == 2 and len(results) == 1
    assert results[0].returncode == 73, (results[0].returncode, results[0].stderr)
    assert not case.paths.discovery_path.exists()
    assert not case.paths.instance_lock_path.exists()


@pytest.mark.parametrize("changed", ["discovery_path", "instance_lock_path"])
def test_changed_publication_refuses_without_removing_either(stale, monkeypatch, changed):
    case, _root = stale
    select = bootstrap._selected_stop_realm
    other = case.paths.instance_lock_path if changed == "discovery_path" else case.paths.discovery_path
    other_before = other.read_bytes()
    def replace_before_final_check(paths):
        selection = select(paths)
        path = getattr(paths, changed)
        record = json.loads(path.read_text())
        record["runtime_instance_id"] = "replacement"
        path.write_text(json.dumps(record))
        return selection
    monkeypatch.setattr(bootstrap, "_selected_stop_realm", replace_before_final_check)
    with pytest.raises(bootstrap.BootstrapError, match="owner changed"):
        bootstrap._reclaim_stale_owner_locked(case.paths, case.boundary)
    assert case.paths.discovery_path.exists() and case.paths.instance_lock_path.exists()
    assert json.loads(getattr(case.paths, changed).read_text())["runtime_instance_id"] == "replacement"
    assert other.read_bytes() == other_before


@pytest.mark.parametrize("state", ["busy", "unobservable"])
def test_final_lock_refusal_preserves_both_publications(stale, monkeypatch, state):
    case, root = stale
    paths = (case.paths.discovery_path, case.paths.instance_lock_path)
    before = [path.read_bytes() for path in paths]
    fd = None
    if state == "busy":
        fd = os.open(root / "owner.lock", os.O_RDONLY)
        bootstrap.runtime_platform.lock_file(fd, blocking=False)
    else:
        def denied(*args, **kwargs):
            raise PermissionError("owner lock unobservable")
        monkeypatch.setattr(bootstrap.runtime_platform, "lock_file", denied)
    try:
        if state == "busy":
            assert not bootstrap._reclaim_stale_owner_locked(case.paths, case.boundary)
        else:
            with pytest.raises(bootstrap.BootstrapError):
                bootstrap._reclaim_stale_owner_locked(case.paths, case.boundary)
        assert [path.read_bytes() for path in paths] == before
    finally:
        if fd is not None:
            bootstrap.runtime_platform.unlock_file(fd)
            os.close(fd)
