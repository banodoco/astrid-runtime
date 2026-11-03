"""Native C5 owner-lock and crash-recovery witnesses using the actual R0 tree."""
import json
import os
from pathlib import Path
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import OwnerBusyError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol import upgrade
from runtime_protocol import platform
from astrid_runtime import operator_upgrade as operator
from test_timeline_commit_port import PreparedProvider

R0 = "6d53a19070faf63fc15ae1f81417722edc2c8a5f"

R0_OWNER = r'''
import json, sys
from pathlib import Path
from runtime_protocol.store import RealmStore
from runtime_protocol.daemon import RuntimeDaemon
root = Path(sys.argv[1])
RealmStore.initialize(root, realm_id="r0-realm").close()
daemon = RuntimeDaemon(root, support_root=root.parent / "r0-support").start()
service = daemon.service
facts = {"epoch": service.health()["runtime_epoch"]}
if sys.argv[2] == "render":
    service.register_executor({"executor_id": "worker", "capabilities": ["render.basic"]}, idempotency_key="worker")
    task = service.create_task({"capability_id": "render.basic", "spec": {}, "idempotency_key": "render"})
    attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.basic"], "runtime_epoch": facts["epoch"]}, idempotency_key="claim")
    facts.update(task_id=task["task"]["id"], run_id=task["run"]["id"], attempt_id=attempt["attempt_id"])
print(json.dumps(facts), flush=True)
sys.stdin.readline()
daemon.stop()
'''


def r0_owner(root, render=False):
    source = os.environ.get("ASTRID_R0_SOURCE")
    if not source:
        pytest.skip("ASTRID_R0_SOURCE must name the authentic R0 checkout")
    source = Path(source).resolve()
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() == R0
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip()
    env = {**os.environ, "PYTHONPATH": str(source), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.Popen([sys.executable, "-B", "-c", R0_OWNER, str(root), "render" if render else "idle"],
                            cwd=source, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    if not line:
        error = proc.stderr.read()
        proc.wait(timeout=20)
        pytest.fail(f"R0 owner failed: {error}")
    return proc, json.loads(line)


def migrate(root):
    identity = upgrade.inspect_realm_schema(root)
    upgrade.migrate_canonical_to_current(root, confirmation=f"MIGRATE CANONICAL {identity['realm_id']}")


@pytest.mark.parametrize("publication", ["absent", "stale", "malformed"])
def test_operator_stopped_requires_actual_free_lock_not_publication_hints(tmp_path, publication):
    root = tmp_path / "realm"
    root.mkdir()
    lock = root / "owner.lock"
    lock.write_bytes(b"original")
    paths = SimpleNamespace(discovery_path=tmp_path / "discovery.json", instance_lock_path=tmp_path / "instance.lock")
    if publication != "absent":
        paths.discovery_path.write_text('{"pid": 999999, "process_birth_id": "stale"}' if publication == "stale" else 'not json')
        paths.instance_lock_path.write_text('{"pid": 1, "process_birth_id": "unrelated"}')
    before = {p: p.read_bytes() for p in (paths.discovery_path, paths.instance_lock_path) if p.exists()}
    lock_before = lock.stat()
    boundary = SimpleNamespace()  # No PID, birth or endpoint observation is permitted.
    operator._stop_selected(paths, boundary, "selected", root, None)
    assert {p: p.read_bytes() for p in before} == before
    assert (lock.stat().st_size, lock.stat().st_mtime_ns) == (lock_before.st_size, lock_before.st_mtime_ns)

    fd = os.open(lock, os.O_RDONLY)
    platform.lock_file(fd, blocking=False)
    try:
        with pytest.raises(operator.BootstrapError):
            operator._stop_selected(paths, boundary, "selected", root, None)
        assert {p: p.read_bytes() for p in before} == before
    finally:
        platform.unlock_file(fd)
        os.close(fd)


@pytest.mark.parametrize("state", ["missing", "symlink", "directory", "unobservable"])
def test_operator_stopped_refuses_unobservable_or_invalid_selected_lock(tmp_path, monkeypatch, state):
    root = tmp_path / "realm"
    root.mkdir()
    lock = root / "owner.lock"
    if state == "symlink":
        target = tmp_path / "target"
        target.write_text("unchanged")
        try:
            lock.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation unavailable")
    elif state == "directory":
        lock.mkdir()
    elif state == "unobservable":
        lock.write_text("unchanged")
        def denied(*_args, **_kwargs):
            raise PermissionError("unobservable")
        monkeypatch.setattr(platform, "lock_file", denied)
    paths = SimpleNamespace(discovery_path=tmp_path / "discovery", instance_lock_path=tmp_path / "marker")
    with pytest.raises(operator.BootstrapError):
        operator._stop_selected(paths, SimpleNamespace(), "selected", root, None)
    assert not paths.discovery_path.exists() and not paths.instance_lock_path.exists()
    if state == "unobservable":
        assert lock.stat().st_size == len("unchanged")


def test_operator_real_r0_lock_blocks_missing_publications_then_admits_stopped(tmp_path):
    root = tmp_path / "realm"
    proc, _facts = r0_owner(root)
    paths = SimpleNamespace(discovery_path=tmp_path / "unpublished", instance_lock_path=tmp_path / "missing-marker")
    try:
        with pytest.raises(operator.OperatorUpgradeError, match="identity is incomplete"):
            operator._stop_selected(paths, SimpleNamespace(), "r0-realm", root, None)
        proc.stdin.write("stop\n")
        proc.stdin.flush()
        assert proc.wait(timeout=30) == 0
        operator._stop_selected(paths, SimpleNamespace(), "r0-realm", root, None)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_operator_busy_authenticated_owner_is_stopped_before_cleanup(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    root.mkdir()
    lock = root / "owner.lock"
    lock.write_bytes(b"")
    paths = SimpleNamespace(discovery_path=tmp_path / "discovery", instance_lock_path=tmp_path / "marker", runtime_support=tmp_path)
    owner = {"pid": 123, "runtime_instance_id": "old", "process_birth_id": "birth", "endpoint": "endpoint", "active_realm": "selected", "realm_root": str(root)}
    paths.discovery_path.write_text(json.dumps(owner))
    paths.instance_lock_path.write_text(json.dumps({**owner, "realm_id": "selected"}))
    fd = os.open(lock, os.O_RDONLY)
    platform.lock_file(fd, blocking=False)
    held = [True]
    calls = []
    def stop(**_kwargs):
        calls.append("stop")
        platform.unlock_file(fd)
        held[0] = False
    boundary = SimpleNamespace(validate_owner=lambda **_kwargs: True,
        endpoint_metadata=lambda **_kwargs: {"runtime_instance_id": "old", "realm_id": "selected"},
        prepare_restart=lambda **_kwargs: calls.append("prepare"), stop_owner=stop)
    config = SimpleNamespace(resolve_source_profile=lambda _paths: None)
    monkeypatch.setattr(operator, "interruption_fence", lambda *_: nullcontext())
    try:
        operator._stop_selected(paths, boundary, "selected", root, config)
        assert calls == ["prepare", "stop"]
        assert not paths.discovery_path.exists() and not paths.instance_lock_path.exists()
    finally:
        if held[0]:
            platform.unlock_file(fd)
        os.close(fd)


@pytest.mark.parametrize("change", ["discovery", "marker", "busy", "unobservable", "remove1", "remove2"])
def test_operator_stop_holds_lock_and_preserves_changed_publications(tmp_path, monkeypatch, change):
    root = tmp_path / "realm"
    root.mkdir()
    lock = root / "owner.lock"
    lock.write_bytes(b"lock")
    paths = SimpleNamespace(discovery_path=tmp_path / "discovery", instance_lock_path=tmp_path / "marker", runtime_support=tmp_path)
    owner = {"pid": 123, "runtime_instance_id": "old", "process_birth_id": "birth", "endpoint": "endpoint"}
    marker = {"pid": 123, "runtime_instance_id": "old"}
    paths.discovery_path.write_text(json.dumps(owner))
    paths.instance_lock_path.write_text(json.dumps(marker))
    monkeypatch.setattr(operator, "_owner_record", lambda *_: owner)
    monkeypatch.setattr(operator, "_lock_matches", lambda *_: True)
    monkeypatch.setattr(operator, "interruption_fence", lambda *_: nullcontext())
    held = []
    def stop(**_kwargs):
        if change in ("discovery", "marker"):
            path = paths.discovery_path if change == "discovery" else paths.instance_lock_path
            path.write_text('{"replacement": true}')
        elif change == "busy":
            fd = os.open(lock, os.O_RDONLY)
            platform.lock_file(fd, blocking=False)
            held.append(fd)
        elif change == "unobservable":
            monkeypatch.setattr(platform, "lock_file", lambda *_a, **_k: (_ for _ in ()).throw(PermissionError()))
    boundary = SimpleNamespace(prepare_restart=lambda **_kwargs: None, stop_owner=stop)
    config = SimpleNamespace(resolve_source_profile=lambda _paths: None)
    original_remove = operator.remove_file
    calls = []
    def remove(path):
        calls.append(path)
        if len(calls) == (1 if change == "remove1" else 2):
            from test_marker_cleanup_race import COMPETING_OWNER
            result = subprocess.run([sys.executable, "-c", COMPETING_OWNER, str(lock), str(paths.discovery_path), str(paths.instance_lock_path)], capture_output=True, text=True, timeout=20)
            assert result.returncode == 73, result.stderr
        original_remove(path)
    monkeypatch.setattr(operator, "remove_file", remove)
    try:
        if change in ("remove1", "remove2"):
            operator._stop_selected(paths, boundary, "selected", root, config)
            assert len(calls) == 2
        else:
            with pytest.raises(operator.BootstrapError):
                operator._stop_selected(paths, boundary, "selected", root, config)
            assert paths.discovery_path.exists() and paths.instance_lock_path.exists()
            if change in ("discovery", "marker"):
                changed_path = paths.discovery_path if change == "discovery" else paths.instance_lock_path
                assert json.loads(changed_path.read_text()) == {"replacement": True}
    finally:
        for fd in held:
            platform.unlock_file(fd)
            os.close(fd)


def test_authentic_r0_owner_busy_then_r1_starts(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    proc, _facts = r0_owner(root)
    try:
        owner_lock = root / "owner.lock"
        before = owner_lock.stat()
        with pytest.raises(OwnerBusyError):
            RuntimeDaemon(root, support_root=tmp_path / "r1-support").start()
        assert proc.poll() is None
        after = owner_lock.stat()
        assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
        proc.stdin.write("stop\n")
        proc.stdin.flush()
        assert proc.wait(timeout=30) == 0
        migrate(root)
        # Existing test provider exercises R1's required migration readiness gate.
        monkeypatch.setattr(RuntimeDaemon, "_load_installed_timeline_commit_provider", lambda self: PreparedProvider())
        daemon = RuntimeDaemon(root, support_root=tmp_path / "r1-support").start()
        service = daemon.service
        try:
            assert service.health()["runtime_epoch"] > 0
        finally:
            daemon.stop()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)


def test_authentic_r0_interrupted_render_reconciles_on_r1_start(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    proc, facts = r0_owner(root, render=True)
    try:
        assert facts["attempt_id"] and facts["task_id"]
        with pytest.raises(OwnerBusyError):
            RuntimeDaemon(root, support_root=tmp_path / "r1-support").start()
        proc.kill()
        proc.wait(timeout=30)
        migrate(root)
        # Existing test provider exercises R1's required migration readiness gate.
        monkeypatch.setattr(RuntimeDaemon, "_load_installed_timeline_commit_provider", lambda self: PreparedProvider())
        daemon = RuntimeDaemon(root, support_root=tmp_path / "r1-support").start()
        service = daemon.service
        try:
            assert service.health()["runtime_epoch"] > facts["epoch"]
            task = service.task(facts["task_id"])["task"]
            assert task["status"] == "queued"
            events = [event for event in service.events(facts["run_id"]) if event["kind"] == "task.runtime_recovered"]
            assert events and events[-1]["payload"]["attempt_id"] == facts["attempt_id"]
            assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (facts["attempt_id"],)).fetchone()[0] == 1
        finally:
            daemon.stop()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=30)
