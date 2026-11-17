"""LS-7: the ordinary three-step lifecycle wakes readers without polling."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import os
import threading

import pytest

from http_helpers import Api
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import AuthorizationError, InvalidRequestError, LeaseError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


@pytest.fixture
def service(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    value = RuntimeService(tmp_path / "realm")
    value.register_executor({"executor_id": "worker", "capabilities": ["test.wait"]}, idempotency_key="register")
    yield value
    value.close()


def claim_body(service):
    return {"executor_id": "worker", "capability_ids": ["test.wait"], "runtime_epoch": service._runtime_state["runtime_epoch"]}


def create(service, key="job"):
    return service.create_task({"capability_id": "test.wait", "idempotency_key": key})["task"]["id"]


def entered_wait(service, monkeypatch):
    entered = threading.Event()
    condition = service._changes().condition
    original = condition.wait
    def wait(seconds):
        entered.set()
        return original(seconds)
    monkeypatch.setattr(condition, "wait", wait)
    return entered


def test_empty_work_wait_is_read_only(service):
    statements = []
    service.store.conn.set_trace_callback(statements.append)
    result = service.wait_for_work({**claim_body(service), "timeout_seconds": 0})
    assert result["available"] is False
    assert result["reason"] == "timeout"
    assert not any(s.startswith(("BEGIN", "INSERT", "UPDATE", "DELETE", "COMMIT")) for s in statements)


def test_admission_and_result_wake_with_three_commits(service, monkeypatch):
    entered = entered_wait(service, monkeypatch)
    statements = []
    service.store.conn.set_trace_callback(statements.append)
    with ThreadPoolExecutor() as pool:
        work = pool.submit(service.wait_for_work, {**claim_body(service), "timeout_seconds": 2})
        assert entered.wait(1)
        task_id = create(service)
        assert work.result(2)["available"] is True
        claim = service.claim_next(claim_body(service), idempotency_key="claim")
        first = service.wait_for_task(task_id)
        entered.clear()
        result = pool.submit(service.wait_for_task, task_id, {"cursor": first["cursor"], "timeout_seconds": 2})
        assert entered.wait(1)
        payload = b"small durable output"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        output = {"digest": digest, "data_base64": base64.b64encode(payload).decode(), "size": len(payload),
                  "media_type": "application/octet-stream", "kind": "object", "name": "result"}
        # Warm fixture: installation/private staging directories already exist.
        service.store.attempt_staging_dir(claim["attempt_id"])
        syncs = []
        real_fsync = os.fsync
        def fsync(fd):
            syncs.append(fd)
            return real_fsync(fd)
        monkeypatch.setattr(os, "fsync", fsync)
        service.settle_attempt(claim["attempt_id"], {
            "lease_id": claim["lease_id"], "fence": claim["fence"], "runtime_epoch": claim["runtime_epoch"], "outputs": [output],
            "progress": {"phase": "complete", "percent": 100},
        }, idempotency_key="settle")
        settled = result.result(2)
    assert settled["task"]["state"] == "succeeded"
    assert settled["task"]["result"]["outputs"][0]["digest"] == digest
    assert service.cas.read(digest.removeprefix("sha256:")) == payload
    assert len(settled["managed_outputs"]["items"]) == 1
    assert settled["task"]["progress"] == {"phase": "complete", "percent": 100}
    assert sum(s == "COMMIT" for s in statements) == 3
    assert service.store.conn.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert len(syncs) == 9


def test_wait_rechecks_capacity_and_wakes_after_settlement(service, monkeypatch):
    first = create(service)
    claim = service.claim_next(claim_body(service), idempotency_key="claim-first")
    second = create(service, "second")
    assert service.wait_for_work({**claim_body(service), "timeout_seconds": 0})["available"] is False
    entered = entered_wait(service, monkeypatch)
    with ThreadPoolExecutor() as pool:
        work = pool.submit(service.wait_for_work, {**claim_body(service), "timeout_seconds": 2})
        assert entered.wait(1)
        service.settle_attempt(claim["attempt_id"], {
            "lease_id": claim["lease_id"], "fence": claim["fence"], "runtime_epoch": claim["runtime_epoch"], "outputs": [],
        }, idempotency_key="settle-first")
        assert work.result(2)["available"] is True
    next_claim = service.claim_next(claim_body(service), idempotency_key="claim-second")
    assert next_claim["task_id"] == second != first


def test_work_hint_avoids_an_ineligible_capability_without_claim_writes(service):
    service.register_executor({"executor_id": "worker", "capabilities": ["test.wait", "test.ready"],
                               "runtime_epoch": service._runtime_state["runtime_epoch"]}, idempotency_key="more-caps")
    blocked = create(service)
    ready = service.create_task({"capability_id": "test.ready", "idempotency_key": "ready"})["task"]["id"]
    with service.store._mutex, service.store._transaction():
        service.store.conn.execute("UPDATE tasks SET waiting_reason='provider_state_unknown' WHERE id=?", (blocked,))
    statements = []
    service.store.conn.set_trace_callback(statements.append)
    observed = service.wait_for_work({**claim_body(service), "capability_ids": ["test.wait", "test.ready"], "timeout_seconds": 0})
    assert observed["available"] is True and observed["capability_ids"] == ["test.ready"]
    assert not any(s.startswith(("BEGIN", "INSERT", "UPDATE", "DELETE", "COMMIT")) for s in statements)
    claim = service.claim_next({**claim_body(service), "capability_ids": observed["capability_ids"]}, idempotency_key="hint-claim")
    assert claim["task_id"] == ready


def test_final_progress_is_validated_and_duplicate_settlement_is_exact(service):
    from runtime_protocol.errors import ValidationError, ConflictError
    task_id = create(service)
    claim = service.claim_next(claim_body(service), idempotency_key="claim")
    body = {k: claim[k] for k in ("lease_id", "fence", "runtime_epoch")}
    body.update(outputs=[], progress={"percent": 101})
    with pytest.raises(ValidationError):
        service.settle_attempt(claim["attempt_id"], body, idempotency_key="settle")
    assert service.store.get_task(task_id)["task"]["status"] == "running"
    body["progress"] = {"phase": "complete", "percent": 100}
    first = service.settle_attempt(claim["attempt_id"], body, idempotency_key="settle")
    assert service.settle_attempt(claim["attempt_id"], body, idempotency_key="settle") == first
    assert service.store.conn.execute("SELECT COUNT(*) FROM events WHERE task_id=? AND kind='task.progress'", (task_id,)).fetchone()[0] == 1
    with pytest.raises(ConflictError):
        service.settle_attempt(claim["attempt_id"], {**body, "progress": {"percent": 50}}, idempotency_key="settle")


def test_rollback_cannot_return_terminal_result(service, monkeypatch):
    task_id = create(service)
    first = service.wait_for_task(task_id)
    entered = entered_wait(service, monkeypatch)
    with ThreadPoolExecutor() as pool:
        result = pool.submit(service.wait_for_task, task_id, {"cursor": first["cursor"], "timeout_seconds": .15})
        assert entered.wait(1)
        with pytest.raises(RuntimeError), service.store._mutex, service.store._transaction():
            service.store.conn.execute("UPDATE tasks SET status='completed' WHERE id=?", (task_id,))
            raise RuntimeError("rollback")
        value = result.result(2)
    assert value["reason"] == "timeout"
    assert value["task"]["state"] == "queued"


def test_lease_deadline_wakes_without_requeue_or_poll(service):
    task_id = create(service)
    claim = service.claim_next(claim_body(service), idempotency_key="claim")
    expiry = (datetime.now(timezone.utc) + timedelta(milliseconds=80)).isoformat()
    with service.store._mutex, service.store._transaction():
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expiry, task_id))
    initial = service.wait_for_task(task_id)
    value = service.wait_for_task(task_id, {"cursor": initial["cursor"], "timeout_seconds": 1})
    assert value["reason"] == "changed" and value["lease_expired"] is True
    assert value["task"]["state"] == "running"
    assert value["task"]["attempt_id"] == claim["attempt_id"]


def test_work_wait_keeps_actor_and_epoch_fences(service):
    with pytest.raises(AuthorizationError):
        service.wait_for_work({**claim_body(service), "timeout_seconds": 0}, identity={"actor": "someone-else", "scopes": ["worker:execute"]})
    with pytest.raises(LeaseError):
        service.wait_for_work({**claim_body(service), "runtime_epoch": 999, "timeout_seconds": 0})


def test_task_cursor_is_scoped_and_shutdown_wakes(service, monkeypatch):
    task_id = create(service)
    first = service.wait_for_task(task_id)
    with pytest.raises(InvalidRequestError):
        service.wait_for_task(create(service, "other"), {"cursor": first["cursor"]})
    entered = entered_wait(service, monkeypatch)
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(service.wait_for_task, task_id, {"cursor": first["cursor"], "timeout_seconds": 2})
        assert entered.wait(1)
        service.close_task_waits()
        assert pending.result(1)["reason"] == "shutdown"


def test_http_wait_releases_dispatch_lock_and_checks_scopes(tmp_path, monkeypatch):
    RealmStore.initialize(tmp_path / "realm").close()
    daemon = RuntimeDaemon(tmp_path / "realm", support_root=tmp_path / "support").start()
    try:
        api = Api(daemon.endpoint, daemon.token)
        api.register_executor("worker", ["test.wait"])
        body = {"executor_id": "worker", "capability_ids": ["test.wait"], "runtime_epoch": api.health()["runtime_epoch"], "timeout_seconds": 2}
        token, _ = daemon.credentials.provision("reader", ["tasks:read"])
        reader = Api(daemon.endpoint, token)
        with pytest.raises(RuntimeError) as denied:
            reader.request("POST", "/v1/tasks/wait-for-work", body)
        assert denied.value.status == 401
        entered = entered_wait(daemon.service, monkeypatch)
        with ThreadPoolExecutor() as pool:
            work = pool.submit(api.request, "POST", "/v1/tasks/wait-for-work", body)
            assert entered.wait(1)
            task = api.create_task("test.wait", {}, idempotency_key="http-create")
            assert work.result(2)["available"] is True
        snapshot = reader.request("POST", f"/v1/tasks/{task['task_id']}/wait", {"timeout_seconds": 0})
        assert snapshot["task"]["task_id"] == task["task_id"]
    finally:
        daemon.stop()
