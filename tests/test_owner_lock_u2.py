"""Native C5 owner-lock and crash-recovery witnesses using the actual R0 tree."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime_protocol.errors import OwnerBusyError
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol import upgrade
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


def test_authentic_r0_owner_busy_then_r1_starts(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    proc, _facts = r0_owner(root)
    try:
        before = (root / "owner.lock").read_bytes()
        with pytest.raises(OwnerBusyError):
            RuntimeDaemon(root, support_root=tmp_path / "r1-support").start()
        assert proc.poll() is None
        assert (root / "owner.lock").read_bytes() == before
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
