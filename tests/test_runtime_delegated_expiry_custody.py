"""An expired delegate owner retains custody until its explicit stop report."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.lifecycle import inspect_interruption_state
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


PARENT = "test.expiry.parent"
CHILD = "test.expiry.child"
# Ordinary authenticated worker authority, with no asserted placement or
# externally verified execution binding.
IDENTITY = {"actor": "worker", "scopes": ["worker:execute"]}


def _digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def runtime(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    for capability in (PARENT, CHILD):
        service.register_capability({
            "capability_id": capability, "definition_digest": _digest(capability),
        })
    service.register_executor({
        "executor_id": "worker", "capabilities": [PARENT, CHILD],
        "max_concurrency": 8, "resource_keys": ["cpu"],
        "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key="register", identity=IDENTITY)
    project = service.create_project({"name": "Delegated expiry"})["id"]
    try:
        yield service, project, root
    finally:
        service.close()


def _claim(service, capability, key):
    return service.claim_next({
        "executor_id": "worker", "capability_ids": [capability],
        "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key=key, identity=IDENTITY)


def _lease(attempt):
    return {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}


def _parent(runtime, *, cpu=False):
    service, project, _ = runtime
    service.register_capability({
        "capability_id": PARENT, "definition_digest": _digest(PARENT),
        "required_resource_keys": ["cpu"] if cpu else [],
    })
    service.create_task({
        "project": project, "capability_id": PARENT,
        "capability_digest": _digest(PARENT), "input_object_ids": [], "spec": {},
        "child_delegation": {
            "capabilities": [{"capability_id": CHILD, "capability_digest": _digest(CHILD)}],
            "targets": [{"kind": "default"}], "input_object_ids": [],
        }, "idempotency_key": "parent",
    }, enforce_readiness=True)
    attempt = _claim(service, PARENT, "claim-parent")
    assert attempt is not None
    assert service.store.execution_binding(attempt["task_id"]) is None
    return attempt


def _authority(service, attempt):
    return service.issue_child_authority(
        attempt["attempt_id"], _lease(attempt), identity=IDENTITY,
    )


def _admit(service, receipt, key):
    return service.admit_delegated_child({
        "authority": receipt["authority"], "task": {
            "capability_id": CHILD, "capability_digest": _digest(CHILD),
            "input_object_ids": [], "spec": {},
        },
    }, idempotency_key=key, identity=IDENTITY)


def _expire(service, attempt):
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="milliseconds")
    service.store.conn.execute(
        "UPDATE tasks SET lease_expires_at=? WHERE id=?", (past, attempt["task_id"]),
    )
    service.store.conn.execute(
        "UPDATE attempts SET lease_expires_at=? WHERE id=?", (past, attempt["attempt_id"]),
    )
    service.store.conn.commit()
    return past


def _attempt(service, attempt):
    return service.store.conn.execute(
        "SELECT * FROM attempts WHERE id=?", (attempt["attempt_id"],),
    ).fetchone()


def _assert_custody(runtime, attempt, expired_at, *, cpu):
    service, _, root = runtime
    task = service.task(attempt["task_id"])["task"]
    assert task["status"] == "running"
    assert task["attempt_id"] == attempt["attempt_id"]
    assert task["lease_token"] == attempt["lease_id"]
    assert task["lease_fence"] == attempt["fence"]
    assert task["executor_id"] == "worker"
    assert task["runtime_epoch"] == attempt["runtime_epoch"]
    assert task["lease_expires_at"] == expired_at
    stored = _attempt(service, attempt)
    assert not stored["settled"]
    assert (stored["lease_id"], stored["fence"], stored["lease_expires_at"]) == (
        attempt["lease_id"], attempt["fence"], expired_at,
    )
    assert service.store.execution_binding(attempt["task_id"]) is None
    report = inspect_interruption_state(root)
    assert report["safe"] is False
    blockers = [row for row in report["blockers"] if row["task_id"] == attempt["task_id"]]
    expected = {"running_task", "unsettled_attempt"}
    if cpu:
        expected.add("unreleased_reservation")
    assert {row["blocker_kind"] for row in blockers} == expected
    unsettled = next(row for row in blockers if row["blocker_kind"] == "unsettled_attempt")
    assert unsettled["attempt_id"] == attempt["attempt_id"]
    assert unsettled["lease_id"] == attempt["lease_id"]
    assert unsettled["lease_expired"] is True


def _assert_expiry_requires_owner_stop(runtime, attempt, expired_at, *, cpu=False):
    service, _, root = runtime
    for index in range(2):
        _assert_custody(runtime, attempt, expired_at, cpu=cpu)
        assert _claim(service, PARENT, f"no-claim-before-stop-{index}") is None
    with pytest.raises(LeaseError):
        service.heartbeat_attempt(attempt["attempt_id"], _lease(attempt),
            idempotency_key="expired-ordinary-heartbeat", identity=IDENTITY)
    with pytest.raises(LeaseError):
        service.settle_attempt(attempt["attempt_id"], {**_lease(attempt), "outputs": []},
            idempotency_key="expired-ordinary-settle", identity=IDENTITY)
    stopped = service.fail_attempt(attempt["attempt_id"], {
        **_lease(attempt), "error": {"code": "owner_stopped"},
    }, idempotency_key="ordinary-owner-stop", identity=IDENTITY)
    assert stopped["data"]["state"] == "failed"
    assert _attempt(service, attempt)["settled"] == 1
    assert inspect_interruption_state(root)["safe"] is True
    service.retry_task(attempt["task_id"], idempotency_key="retry-stopped-ordinary-owner")


@pytest.mark.parametrize("child_state,cpu", [
    ("queued", False), ("running", False), ("cancelled", False),
    ("completed", False), ("running", True),
])
def test_expired_delegating_owner_retains_custody_until_explicit_failure(runtime, child_state, cpu):
    service, project, root = runtime
    parent = _parent(runtime, cpu=cpu)
    receipt = _authority(service, parent)
    child = _admit(service, receipt, "child")
    child_attempt = None
    if child_state in {"running", "completed"}:
        child_attempt = _claim(service, CHILD, "claim-child")
        assert child_attempt is not None
    if child_state == "completed":
        service.settle_attempt(child_attempt["attempt_id"], {
            **_lease(child_attempt), "outputs": [],
        }, idempotency_key="complete-child", identity=IDENTITY)
    elif child_state == "cancelled":
        service.cancel_task_canonical(child["task"]["id"], idempotency_key="cancel-child")

    expired_at = _expire(service, parent)
    # Each read/claim path may contain the children. Their resulting terminal
    # state must not be mistaken for the parent's explicit stop report.
    for index in range(2):
        _assert_custody(runtime, parent, expired_at, cpu=cpu)
        tasks = service.list_project_tasks(project)["items"]
        assert next(row for row in tasks if row["task_id"] == parent["task_id"])["state"] == "running"
        runs = service.list_project_runs(project)["items"]
        assert next(row for row in runs if row["id"] == parent["run_id"])["status"] == "running"
        assert _claim(service, PARENT, f"expired-parent-claim-{index}") is None
        assert _claim(service, CHILD, f"expired-child-claim-{index}") is None
        _assert_custody(runtime, parent, expired_at, cpu=cpu)
    expected_child = "completed" if child_state == "completed" else "cancelled"
    assert service.task(child["task"]["id"])["task"]["status"] == expected_child

    with pytest.raises(ConflictError, match="not retryable"):
        service.retry_task(parent["task_id"], idempotency_key="premature-retry")
    with pytest.raises(LeaseError):
        service.heartbeat_attempt(parent["attempt_id"], _lease(parent), idempotency_key="late-heartbeat", identity=IDENTITY)
    with pytest.raises(LeaseError):
        service.settle_attempt(parent["attempt_id"], {**_lease(parent), "outputs": []}, idempotency_key="late-settle", identity=IDENTITY)
    with pytest.raises(LeaseError):
        _authority(service, parent)
    with pytest.raises(LeaseError):
        _admit(service, receipt, "late-child")
    if child_attempt is not None:
        with pytest.raises(LeaseError):
            service.settle_attempt(child_attempt["attempt_id"], {**_lease(child_attempt), "outputs": []}, idempotency_key="late-child-settle", identity=IDENTITY)
    with pytest.raises(LeaseError):
        service.fail_attempt(parent["attempt_id"], {
            **_lease(parent), "fence": parent["fence"] + 1, "error": {"code": "owner_stopped"},
        }, idempotency_key="wrong-fence-failure", identity=IDENTITY)
    _assert_custody(runtime, parent, expired_at, cpu=cpu)

    stop = {**_lease(parent), "error": {"code": "owner_stopped"}}
    failed = service.fail_attempt(parent["attempt_id"], stop, idempotency_key="owner-stop", identity=IDENTITY)
    assert failed["data"]["state"] == "failed"
    assert service.fail_attempt(parent["attempt_id"], stop, idempotency_key="owner-stop", identity=IDENTITY) == failed
    assert _attempt(service, parent)["settled"] == 1
    assert inspect_interruption_state(root)["safe"] is True
    service.retry_task(parent["task_id"], idempotency_key="retry-after-stop")
    retried = _claim(service, PARENT, "claim-after-stop")
    assert retried["task_id"] == parent["task_id"]
    assert retried["attempt_id"] != parent["attempt_id"]
    assert retried["lease_id"] != parent["lease_id"]
    assert retried["fence"] > parent["fence"]
    with pytest.raises(LeaseError):
        service.fail_attempt(parent["attempt_id"], stop, idempotency_key="stale-owner-stop", identity=IDENTITY)
    with pytest.raises(LeaseError):
        _admit(service, receipt, "old-authority-after-retry")

    # Historical lineage cannot confer current delegation authority. Ordinary
    # expiry also retains exact custody until an explicit owner stop report.
    assert not service.store.delegated_children(retried["task_id"], retried["attempt_id"])
    assert len(service.store.delegated_children(parent["task_id"], parent["attempt_id"])) == 1
    retried_expiry = _expire(service, retried)
    _assert_expiry_requires_owner_stop(runtime, retried, retried_expiry, cpu=cpu)
    reclaimed = _claim(service, PARENT, "reclaim-undelegated-retry")
    assert reclaimed["task_id"] == parent["task_id"]
    assert reclaimed["attempt_id"] != retried["attempt_id"]
    assert reclaimed["lease_id"] != retried["lease_id"]
    assert reclaimed["fence"] > retried["fence"]


@pytest.mark.parametrize("issued_authority", [False, True])
def test_policy_without_an_accepted_child_retains_custody_until_owner_stop(runtime, issued_authority):
    service, _, _ = runtime
    parent = _parent(runtime)
    if issued_authority:
        _authority(service, parent)
    assert not service.store.delegated_children(parent["task_id"], parent["attempt_id"])
    expired_at = _expire(service, parent)
    _assert_expiry_requires_owner_stop(runtime, parent, expired_at)
    reclaimed = _claim(service, PARENT, "claim-after-ordinary-expiry")
    assert reclaimed["task_id"] == parent["task_id"]
    assert reclaimed["attempt_id"] != parent["attempt_id"]
    assert reclaimed["lease_id"] != parent["lease_id"]
    assert reclaimed["fence"] > parent["fence"]
