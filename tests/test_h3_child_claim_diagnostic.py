"""Bounded diagnosis of a prepared child skipped by Runtime claim selection."""
from __future__ import annotations

import json

from tests.test_child_target_preservation import DEFAULT, admit_resource, child_case
from tests.test_runtime_child_delegation import CHILD, IDENTITY, digest, lease, runtime


def _count_attempts(service, task_id):
    return service.store.conn.execute(
        "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)
    ).fetchone()[0]


def _progress_events(service, task_id):
    rows = service.store.conn.execute(
        "SELECT payload_json FROM events WHERE task_id=? AND kind='task.progress' ORDER BY id",
        (task_id,),
    ).fetchall()
    return [json.loads(row["payload_json"]) for row in rows]


def test_h3_child_claim_diagnostic(runtime, monkeypatch, capsys):
    service, _ = runtime
    service.register_capability({
        "capability_id": CHILD,
        "definition_digest": digest(CHILD),
        "required_resource_keys": ["cpu"],
    })
    epoch = service.health()["runtime_epoch"]
    service.register_executor({
        "executor_id": "worker",
        "capabilities": ["test.d18.parent", CHILD],
        "max_concurrency": 2,
        "resource_keys": ["cpu"],
        "readiness": "ready",
        "runtime_epoch": epoch,
    }, idempotency_key="h3-diagnostic-executor")

    parent_attempt, receipt, child_spec, _ = child_case(
        runtime, targeted=False, target=DEFAULT,
    )
    child = admit_resource(service, receipt, child_spec)
    child_id = child["task_id"]
    parent_task_id = parent_attempt["task_id"]

    executor = service.store.conn.execute(
        "SELECT * FROM executors WHERE id='worker'"
    ).fetchone()
    advertised = service.store._executor_capability(executor, CHILD)
    capability_row = service.store.conn.execute(
        "SELECT status, required_resource_keys_json FROM capabilities WHERE id=?",
        (CHILD,),
    ).fetchone()
    candidate = service.store.conn.execute(
        "SELECT status, attempt, waiting_reason FROM tasks WHERE id=?", (child_id,)
    ).fetchone()
    binding = service.store.execution_binding(child_id)
    occupancy_before = service.store.conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE executor_id='worker' AND status='running'"
    ).fetchone()[0]
    reservations_before = [row[0] for row in service.store.conn.execute(
        "SELECT resource_key FROM reservations "
        "WHERE executor_id='worker' AND released_at IS NULL ORDER BY resource_key"
    ).fetchall()]
    parent_required_resources = service.store._required_resource_keys("test.d18.parent")
    child_required_resources = service.store._required_resource_keys(CHILD)

    store_claim_calls = []
    original_claim_task = service.store._claim_task

    def observe_store_claim(*args, **kwargs):
        store_claim_calls.append({"task_id": args[0] if args else kwargs.get("task_id")})
        return original_claim_task(*args, **kwargs)

    monkeypatch.setattr(service.store, "_claim_task", observe_store_claim)
    no_selector_result = service.claim_next({
        "executor_id": "worker",
        "capability_ids": [CHILD],
        "runtime_epoch": epoch,
    }, idempotency_key="h3-diagnostic-no-selector", identity=IDENTITY)
    assert no_selector_result is None
    assert store_claim_calls == []
    after_no_claim = service.store.conn.execute(
        "SELECT status, attempt, waiting_reason FROM tasks WHERE id=?", (child_id,)
    ).fetchone()
    assert after_no_claim["status"] == "queued"
    assert after_no_claim["attempt"] == 0
    assert after_no_claim["waiting_reason"] is None
    assert _count_attempts(service, child_id) == 0
    assert executor["readiness"] == "ready"
    assert advertised["capability_id"] == CHILD
    assert capability_row["status"] == "ready"
    assert occupancy_before == 1
    assert executor["max_concurrency"] - occupancy_before == 1
    assert parent_required_resources == []
    assert child_required_resources == ["cpu"]
    assert "cpu" in json.loads(executor["resource_keys_json"])
    assert reservations_before == []

    parent_progress_before = _progress_events(service, parent_task_id)
    heartbeat_no_progress = service.heartbeat_attempt(
        parent_attempt["attempt_id"],
        {**lease(parent_attempt), "lease_seconds": 30},
        idempotency_key="h3-diagnostic-parent-heartbeat-no-progress",
        identity=IDENTITY,
    )
    assert heartbeat_no_progress["data"]["task_id"] == parent_task_id
    assert _progress_events(service, parent_task_id) == parent_progress_before

    progress = {"phase": "waiting_for_child", "percent": 0}
    heartbeat_with_progress = service.heartbeat_attempt(
        parent_attempt["attempt_id"],
        {**lease(parent_attempt), "lease_seconds": 30, "progress": progress},
        idempotency_key="h3-diagnostic-parent-heartbeat-progress-1",
        identity=IDENTITY,
    )
    heartbeat_same_progress = service.heartbeat_attempt(
        parent_attempt["attempt_id"],
        {**lease(parent_attempt), "lease_seconds": 30, "progress": progress},
        idempotency_key="h3-diagnostic-parent-heartbeat-progress-2",
        identity=IDENTITY,
    )
    assert heartbeat_with_progress["data"]["task_id"] == parent_task_id
    assert heartbeat_same_progress["data"]["task_id"] == parent_task_id
    assert _progress_events(service, parent_task_id) == [progress, progress]

    exact_selector_result = service.claim_next({
        "executor_id": "worker",
        "capability_ids": [CHILD],
        "runtime_epoch": epoch,
        "target": DEFAULT,
    }, idempotency_key="h3-diagnostic-exact-selector", identity=IDENTITY)
    assert exact_selector_result["task_id"] == child_id
    assert len(store_claim_calls) == 1
    assert store_claim_calls[0]["task_id"] == child_id
    assert service.store.conn.execute(
        "SELECT status FROM tasks WHERE id=?", (child_id,)
    ).fetchone()[0] == "running"
    assert _count_attempts(service, child_id) == 1

    diagnostic = {
        "candidate": {
            "task_role": "admitted_delegated_child",
            "capability": CHILD,
            "status_before_claim": candidate["status"],
            "attempt_before_claim": candidate["attempt"],
            "waiting_reason_before_claim": candidate["waiting_reason"],
            "resolved_target_kind": binding["resolved_target"]["kind"],
        },
        "executor": {
            "readiness": executor["readiness"],
            "advertises_capability": advertised["capability_id"] == CHILD,
            "capability_registry_status": capability_row["status"],
            "capability_registry_required_resource_keys": json.loads(
                capability_row["required_resource_keys_json"]
            ),
            "max_concurrency": executor["max_concurrency"],
            "resource_keys": json.loads(executor["resource_keys_json"]),
        },
        "no_selector_decision": {
            "requested_target": None,
            "candidate_target_kind": binding["resolved_target"]["kind"],
            "claim_next_result": "no_claim",
            "filtered_before_store_preflight": True,
            "store_preflight_invocations": 0,
            "task_waiting_reason_after_no_claim": after_no_claim["waiting_reason"],
            "attempt_rows_after_no_claim": 0,
        },
        "occupancy_and_resources_before_claim": {
            "running_tasks": occupancy_before,
            "spare_concurrency_slots": executor["max_concurrency"] - occupancy_before,
            "parent_required_resource_keys": parent_required_resources,
            "child_required_resource_keys": child_required_resources,
            "executor_resource_keys": json.loads(executor["resource_keys_json"]),
            "active_reservations": reservations_before,
        },
        "exact_selector_control": {
            "requested_target_kind": DEFAULT["kind"],
            "claim_next_result": "claimed",
            "store_preflight_invocations": len(store_claim_calls),
            "task_status": "running",
            "attempt_rows": 1,
        },
        "parent_heartbeat_progress": {
            "no_progress_heartbeat_renewed_lease": bool(
                heartbeat_no_progress["data"]["lease_expires_at"]
            ),
            "progress_events_before": len(parent_progress_before),
            "progress_events_after_no_progress_heartbeat": len(parent_progress_before),
            "submitted_progress": progress,
            "same_progress_submissions_recorded": len(_progress_events(service, parent_task_id)),
            "runtime_renewal_depends_on_progress": False,
        },
    }
    serialized = json.dumps(diagnostic, sort_keys=True)
    with capsys.disabled():
        print("H3_CHILD_CLAIM_DIAGNOSTIC=" + serialized)
    emitted = json.loads(serialized)
    assert emitted == diagnostic
    assert emitted["no_selector_decision"]["filtered_before_store_preflight"] is True
    assert emitted["exact_selector_control"]["store_preflight_invocations"] == 1
