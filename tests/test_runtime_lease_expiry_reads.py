"""Ordinary lease expiry fences publication without proving executor stop.

Reads, polls and competing claims retain the exact execution custody until
the owner explicitly cedes it or Runtime has other reconciliation authority.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import LeaseError
from runtime_protocol.lifecycle import _interruption_report
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _digest(name):
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    svc = RuntimeService(root)
    try:
        yield svc
    finally:
        svc.close()


def _claimed_task(service):
    service.register_capability({"capability_id": "render.gpu", "definition_digest": _digest("render.gpu-v1"),
                                 "required_resource_keys": ["gpu"]})
    service.register_executor({"executor_id": "worker", "capabilities": ["render.gpu"], "resource_keys": ["gpu"], "max_concurrency": 1,
                               "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="reg")
    task_id = service.create_task({"capability_id": "render.gpu", "capability_digest": _digest("render.gpu-v1"),
                                   "input_object_ids": [], "spec": {}, "idempotency_key": "t1"})["task"]["id"]
    attempt = service.claim_next({"executor_id": "worker", "capability_ids": ["render.gpu"],
                                  "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-1")
    assert service.task(task_id)["task"]["status"] == "running"
    return task_id, attempt


def _expire(service, task_id, attempt):
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="milliseconds")
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (past, task_id))
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (past, attempt["attempt_id"]))
    service.store.conn.execute("UPDATE reservations SET lease_expires_at=? WHERE task_id=? AND released_at IS NULL", (past, task_id))
    service.store.conn.commit()


def _kinds(service, task_id):
    return [e["kind"] for e in service.store.list_events(service.store.get_task(task_id)["run"]["id"]) if e["task_id"] == task_id]


def _custody(service, task_id, attempt):
    return {
        "task": dict(service.store.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()),
        "attempt": dict(service.store.conn.execute("SELECT * FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()),
        "reservations": [dict(row) for row in service.store.conn.execute(
            "SELECT * FROM reservations WHERE task_id=? ORDER BY resource_key", (task_id,))],
    }


def _assert_retained(service, task_id, attempt, custody):
    assert _custody(service, task_id, attempt) == custody
    assert custody["task"]["status"] == "running"
    assert custody["task"]["attempt_id"] == attempt["attempt_id"]
    assert custody["attempt"]["settled"] == 0
    assert len(custody["reservations"]) == 1
    assert custody["reservations"][0]["released_at"] is None
    report = _interruption_report(service.store.conn)
    assert report["safe"] is False
    assert {row["blocker_kind"] for row in report["blockers"] if row["task_id"] == task_id} == {
        "running_task", "unsettled_attempt", "unreleased_reservation",
    }
    assert report["unreconciled_attempts"][0]["lease_expired"] is True
    assert report["unreleased_reservations"][0]["lease_expired"] is True
    assert "task.lease_expired" not in _kinds(service, task_id)


@pytest.mark.parametrize("entry_point", ["task", "project_tasks", "project_runs", "poll"])
def test_reads_and_poll_retain_expired_executor_custody(service, entry_point):
    task_id, attempt = _claimed_task(service)
    run = service.store.get_task(task_id)["run"]
    project = service.create_project({"name": "p"}, idempotency_key="proj")["id"]
    service.store.conn.execute("UPDATE runs SET project_id=? WHERE id=?", (project, run["id"]))
    service.store.conn.commit()
    _expire(service, task_id, attempt)
    custody = _custody(service, task_id, attempt)
    if entry_point == "task":
        resource = service._task_resource(service.task(task_id))
        assert resource["state"] == "running"
        assert resource["lease_expires_at"] == custody["task"]["lease_expires_at"]
    elif entry_point == "project_tasks":
        items = service.list_project_tasks(project)["items"]
        assert [item["state"] for item in items if item["task_id"] == task_id] == ["running"]
    elif entry_point == "project_runs":
        assert service.list_project_runs(project)["items"][0]["status"] == "running"
    else:
        service.reap_task_lifetimes()
    _assert_retained(service, task_id, attempt, custody)


def test_repeated_reads_polls_and_claim_cannot_reclaim_expired_executor(service):
    task_id, attempt = _claimed_task(service)
    _expire(service, task_id, attempt)
    custody = _custody(service, task_id, attempt)
    for _ in range(2):
        service.task(task_id)
        service.reap_task_lifetimes()
    reclaimed = service.claim_next({"executor_id": "worker", "capability_ids": ["render.gpu"],
                                    "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-2")
    assert reclaimed is None
    _assert_retained(service, task_id, attempt, custody)


def test_expired_owner_can_cede_exact_custody_before_retry_and_successor(service):
    task_id, attempt = _claimed_task(service)
    _expire(service, task_id, attempt)
    lease = {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}
    service.fail_attempt(attempt["attempt_id"], {**lease, "error": {"code": "lease_lost"}},
                         idempotency_key="cede-expired-owner")
    failed = service.store.get_task(task_id)
    assert failed["task"]["status"] == "failed"
    assert failed["task"]["result"]["error"]["code"] == "lease_lost"
    assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM reservations WHERE task_id=? AND released_at IS NULL", (task_id,)).fetchone()[0] == 0
    assert _interruption_report(service.store.conn)["safe"] is True

    service.retry_task(task_id, {}, idempotency_key="retry-after-cede")
    successor = service.claim_next({"executor_id": "worker", "capability_ids": ["render.gpu"],
                                    "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-after-cede")
    assert successor["task_id"] == task_id
    assert successor["attempt_id"] != attempt["attempt_id"]
    assert successor["fence"] > attempt["fence"]
    successor_custody = _custody(service, task_id, successor)
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], {**lease, "outputs": []}, idempotency_key="stale-settle")
    assert _custody(service, task_id, successor) == successor_custody


def test_unexpired_lease_is_untouched_by_reads(service):
    task_id, _ = _claimed_task(service)
    assert service._task_resource(service.task(task_id))["state"] == "running"
    assert "task.lease_expired" not in _kinds(service, task_id)
