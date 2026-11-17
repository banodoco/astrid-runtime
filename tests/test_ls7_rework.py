"""Lead rework probes: durable descriptors, interchangeable hosts and wakes."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy

import pytest

from runtime_protocol.errors import LeaseError
from runtime_protocol.service import RuntimeService
from test_ls7_task_waits import entered_wait
from test_ls7_thin_resolution import DIGEST, claim, descriptor, registration, request, service


def work_body(service, executor_id="scalar-host"):
    return {"executor_id": executor_id, "capability_ids": ["ls7.scalar"],
            "runtime_epoch": service._runtime_state["runtime_epoch"]}


@pytest.mark.parametrize("previous_state", ["queued", "running"])
def test_frozen_thin_task_is_claimable_after_runtime_restart(service, previous_state):
    admitted = service.create_task(request())
    task_id = admitted["task"]["id"]
    frozen_spec = copy.deepcopy(admitted["task"]["spec"])
    previous_claim = claim(service) if previous_state == "running" else None
    previous_epoch = service._runtime_state["runtime_epoch"]
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        assert restarted._runtime_state["runtime_epoch"] > previous_epoch
        assert restarted.store.get_task(task_id)["task"]["status"] == "queued"
        restarted.register_executor(registration(restarted), idempotency_key="register-after-restart")
        assert restarted.wait_for_work({**work_body(restarted), "timeout_seconds": 0})["available"] is True
        claimed = claim(restarted, "claim-after-restart")
        assert claimed["task_id"] == task_id and claimed["runtime_epoch"] > previous_epoch
        assert restarted.store.get_task(task_id)["task"]["spec"] == frozen_spec
        assert restarted.create_task(request()) == admitted
        if previous_claim is not None:
            with pytest.raises(LeaseError):
                restarted.settle_attempt(previous_claim["attempt_id"], {
                    key: previous_claim[key] for key in ("lease_id", "fence", "runtime_epoch")
                } | {"outputs": []}, idempotency_key="stale-settlement")
            assert claimed["attempt_id"] != previous_claim["attempt_id"]
            assert claimed["fence"] > previous_claim["fence"]
    finally:
        restarted.close()


@pytest.mark.parametrize("first_host_ready", [True, False])
def test_identical_descriptor_can_execute_on_either_host(service, first_host_ready):
    second = {**registration(service), "executor_id": "second-host"}
    service.register_executor(second, idempotency_key="register-second")
    admitted = service.create_task(request())
    if not first_host_ready:
        service.register_executor({**registration(service), "readiness": "not_ready"},
                                  idempotency_key="first-host-unavailable")
    body = work_body(service, "second-host")
    assert service.wait_for_work({**body, "timeout_seconds": 0})["available"] is True
    claimed = service.claim_next(body, idempotency_key="second-host-claim")
    assert claimed["task_id"] == admitted["task"]["id"]
    assert service.store.get_task(claimed["task_id"])["task"]["executor_id"] == "second-host"
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 1


@pytest.mark.parametrize("change", ["descriptor", "source", "settings"])
def test_truly_stale_descriptor_finishes_with_a_durable_typed_refusal(service, change):
    admitted = service.create_task(request())
    task_id = admitted["task"]["id"]
    updated = descriptor()
    if change == "descriptor":
        updated["inputs"][1]["default"] = 1024
    elif change == "source":
        updated.update(source_digest="source-v2", source_epoch="epoch-v2")
    else:
        updated["settings_digest"] = "settings-v2"
    service.register_executor({**registration(service, updated),
        "source_digest": updated["source_digest"], "source_epoch": updated["source_epoch"]},
        idempotency_key="replace-descriptor")
    statements = []
    service.store.conn.set_trace_callback(statements.append)
    # A stale queued command needs one ordinary atomic refusal, not a write
    # from this read-only wait or a claimable worker lease.
    assert service.wait_for_work({**work_body(service), "timeout_seconds": 0})["available"] is True
    assert not any(s.startswith(("BEGIN", "INSERT", "UPDATE", "DELETE", "COMMIT")) for s in statements)
    refused = claim(service)
    assert refused["waiting_reason"] == "resolution_descriptor_stale"
    assert refused["task"]["state"] == "failed"
    task = service.store.get_task(task_id)["task"]
    assert task["status"] == "failed" and task["waiting_reason"] is None
    assert task["result"]["error"]["code"] == "resolution_descriptor_stale"
    assert task["spec"] == admitted["task"]["spec"]
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM events WHERE task_id=? AND kind='task.failed'", (task_id,)).fetchone()[0] == 1
    assert claim(service) == refused, "lost refusal ACK must replay without another failure event"
    assert service.wait_for_work({**work_body(service), "timeout_seconds": 0})["available"] is False


def test_different_descriptor_does_not_refuse_another_hosts_frozen_task(service):
    admitted = service.create_task(request())
    service.register_executor({**registration(service, descriptor(settings_digest="other-settings")),
                               "executor_id": "second-host"}, idempotency_key="register-other")
    body = work_body(service, "second-host")
    assert service.wait_for_work({**body, "timeout_seconds": 0})["available"] is False
    assert service.claim_next(body, idempotency_key="other-host-claim") is None
    assert service.store.get_task(admitted["task"]["id"])["task"]["status"] == "queued"
    assert claim(service)["task_id"] == admitted["task"]["id"]


def test_capability_endpoint_commit_wakes_work_waiter(service, monkeypatch):
    service.create_task(request())
    capability = {"capability_id": "ls7.scalar", "definition_digest": DIGEST}
    service.register_capability({**capability, "status": "unavailable"})
    entered = entered_wait(service, monkeypatch)
    with ThreadPoolExecutor() as pool:
        pending = pool.submit(service.wait_for_work, {**work_body(service), "timeout_seconds": 2})
        assert entered.wait(1)
        service.register_capability({**capability, "status": "ready"})
        assert pending.result(1)["available"] is True, "capability commit did not wake its waiter"
