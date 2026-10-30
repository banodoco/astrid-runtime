"""Deterministic fixtures; every realm/CAS here is pytest-owned temporary data."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, ValidationError
from runtime_protocol import service as service_module
from runtime_protocol.service import CHILD_LIMITS, CHILD_LIMIT_CEILINGS, OBJECT_MAX_BYTES, RuntimeService
from runtime_protocol.store import RealmStore


PARENT = "test.d18.parent"
CHILD = "test.d18.child"
OTHER = "test.d18.other"
TARGET = {"kind": "machine", "id": "fixture-machine"}


def digest(data):
    return "sha256:" + hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


IDENTITY = {"actor": "worker", "scopes": ["worker:execute"], "execution_binding": {
    "actual": TARGET, "executor_incarnation": "worker/fixture",
    "verification": {"method": "credential_claim", "verified": True, "evidence_digest": digest("placement")},
}}


@pytest.fixture
def runtime(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    for cap in (PARENT, CHILD, OTHER):
        service.register_capability({"capability_id": cap, "definition_digest": digest(cap)})
    service.register_executor({"executor_id": "worker", "capabilities": [PARENT, CHILD, OTHER], "max_concurrency": 64}, idempotency_key="register")
    project = service.create_project({"slug": "d18", "name": "D18 fixture"})["id"]
    try:
        yield service, project
    finally:
        service.close()


def load_task_spec(service, task_id):
    """Read a task spec through its content-addressed reference (tasks.spec_digest -> task_specs)."""
    row = service.store.conn.execute("SELECT spec_digest FROM tasks WHERE id=?", (task_id,)).fetchone()
    return service.store._load_spec(row["spec_digest"])


def store_task_spec(service, task_id, spec):
    """Publish an edited spec as a task_specs body and repoint the task at it."""
    spec_digest_value = service.store._store_spec(spec)
    service.store.conn.execute("UPDATE tasks SET spec_digest=? WHERE id=?", (spec_digest_value, task_id))


def claim(service, cap, key):
    body = {"executor_id": "worker", "capability_ids": [cap], "runtime_epoch": service.health()["runtime_epoch"]}
    row = service.store.conn.execute("SELECT id FROM tasks WHERE capability=? AND status='queued' ORDER BY rowid LIMIT 1", (cap,)).fetchone()
    if row is not None:
        target = service.store.effective_execution_target(row["id"])
        if target is not None:
            body["target"] = target
    return service.claim_next(body, idempotency_key=key, identity=IDENTITY)


def lease(attempt):
    return {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}


def parent(runtime, *, limits=None, targeted=False, key="parent"):
    service, project = runtime
    policy = {"capabilities": [{"capability_id": cap, "capability_digest": digest(cap)} for cap in (CHILD, OTHER)], "targets": [{"kind": "default"}, TARGET], "input_object_ids": []}
    if limits is not None:
        policy["limits"] = limits
    body = {"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT), "input_object_ids": [], "spec": {}, "child_delegation": policy, "idempotency_key": key}
    if targeted:
        body["execution_request"] = {"schema_version": 1, "target": TARGET, "inputs": []}
    service.create_task(body, enforce_readiness=True)
    return claim(service, PARENT, "claim-" + key)


def upload(service, attempt, data=b"new-parent-frame", name="frame"):
    descriptor = {"name": name, "output_port": name, "filename": name + ".bin", "object_id": digest(data), "size": len(data), "media_type": "application/octet-stream"}
    binding = {"project_id": attempt["project_id"], "run_id": attempt["run_id"], "task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"], "executor_id": "worker", **lease(attempt), "output_key": name, "output_port": name, "filename": descriptor["filename"], "digest": digest(data), "size": len(data), "media_type": descriptor["media_type"]}
    service.ingest_object(data, original_name=descriptor["filename"], idempotency_key=service._generic_output_idempotency_key(binding), identity=IDENTITY, upload_binding=binding)
    return descriptor


def authority(service, attempt, *, refs=None, key="child", cap=CHILD):
    body = lease(attempt)
    if refs is not None:
        body.update(child={"child_id": key, "capability_id": cap, "capability_digest": digest(cap)}, derived_inputs=refs)
    return service.issue_child_authority(attempt["attempt_id"], body, identity=IDENTITY)


def admit(service, receipt, *, refs=None, key="child", cap=CHILD, params=None):
    task = {"capability_id": cap, "capability_digest": digest(cap), "input_object_ids": [], "spec": {"params": params or {"query": "fixture://video"}}}
    if refs is not None:
        task["input_object_ids"] = [ref["object_id"] for ref in refs]
        task["execution_request"] = {"schema_version": 1, "target": {"kind": "default"}, "inputs": [{"name": ref["name"], "object_id": ref["object_id"], "filename": ref["filename"], "digest": ref["object_id"]} for ref in refs]}
    return service.admit_delegated_child({"authority": receipt["authority"], "task": task}, idempotency_key=key, identity=IDENTITY)


def settle(service, attempt, key, outputs=None):
    return service.settle_attempt(attempt["attempt_id"], {**lease(attempt), "outputs": outputs or []}, idempotency_key=key, identity=IDENTITY)


def test_live_derived_registration_exact_admission_and_verified_success(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    assert authority(service, attempt, refs=[ref]) == receipt
    child = admit(service, receipt, refs=[ref])
    assert admit(service, receipt, refs=[ref]) == child
    assert child["task"]["spec"]["delegated_inputs"][0]["association_id"] == receipt["derived_inputs"][0]["association_id"]
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, attempt, "early-parent")
    child_attempt = claim(service, CHILD, "claim-child")
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, attempt, "running-parent")
    payload = b"verified-child-result"
    settle(service, child_attempt, "settle-child", [{"name": "result", "digest": digest(payload), "data_base64": base64.b64encode(payload).decode()}])
    settle(service, attempt, "settle-parent")
    assert service.task(attempt["task_id"])["task"]["status"] == "completed"
    assert len(service.store.delegated_children(attempt["task_id"], attempt["attempt_id"])) == 1
    with pytest.raises(LeaseError):
        admit(service, receipt, refs=[ref], key="after-parent")


def test_scalar_no_object_call_progress_and_same_target(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    assert child["task"]["execution_request"]["target"] == TARGET
    child_attempt = claim(service, CHILD, "claim-scalar")
    progress = service.heartbeat_attempt(child_attempt["attempt_id"], {**lease(child_attempt), "progress": {"percent": 50}}, idempotency_key="scalar-progress", identity=IDENTITY)
    assert progress["data"]["task_id"] == child["task"]["id"]
    settle(service, child_attempt, "scalar-success")
    settle(service, attempt, "scalar-parent-success")


@pytest.mark.parametrize("field", ["fence", "runtime_epoch", "lease_id"])
def test_stale_attempt_registration_rejected(runtime, field):
    service, _ = runtime
    attempt = parent(runtime)
    body = {**lease(attempt), "child": {"child_id": "child", "capability_id": CHILD, "capability_digest": digest(CHILD)}, "derived_inputs": [upload(service, attempt)]}
    body[field] = "foreign" if field == "lease_id" else body[field] + 1
    with pytest.raises((LeaseError, ConflictError)):
        service.issue_child_authority(attempt["attempt_id"], body, identity=IDENTITY)
    assert not service.managed_outputs(attempt["task_id"])


def test_foreign_worker_project_and_unregistered_object_rejected(runtime):
    service, project = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    foreign = copy.deepcopy(IDENTITY)
    foreign["actor"] = "foreign-worker"
    with pytest.raises(AuthorizationError):
        service.issue_child_authority(attempt["attempt_id"], lease(attempt), identity=foreign)
    receipt = authority(service, attempt, refs=[ref])
    with pytest.raises(AuthorizationError):
        service.admit_delegated_child({"authority": receipt["authority"], "task": {"capability_id": CHILD, "capability_digest": digest(CHILD)}}, idempotency_key="child", identity=foreign)
    service.store.conn.execute("UPDATE runs SET project_id=NULL WHERE id=?", (attempt["run_id"],))
    with pytest.raises(AuthorizationError):
        admit(service, receipt, refs=[ref])
    service.store.conn.execute("UPDATE runs SET project_id=? WHERE id=?", (project, attempt["run_id"]))
    raw = b"unbound-upload"
    service.ingest_object(raw, original_name="raw.bin", idempotency_key="unbound")
    with pytest.raises(AuthorizationError, match="authenticated upload receipt"):
        authority(service, attempt, refs=[{"name": "raw", "output_port": "raw", "filename": "raw.bin", "object_id": digest(raw), "size": len(raw), "media_type": "application/octet-stream"}])
    with pytest.raises(AuthorizationError):
        admit(service, authority(service, attempt), refs=[ref])


@pytest.mark.parametrize("change", ["capability", "digest", "child_id", "filename", "bytes", "association", "metadata", "project_association", "registry"])
def test_wrong_child_receipt_or_changed_object_rejected(runtime, change):
    service, project = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    if change == "bytes":
        service.cas.path_for(ref["object_id"][7:]).write_bytes(b"corrupt-object!!")
    elif change == "association":
        service.store.conn.execute("UPDATE managed_output_associations SET role='output' WHERE association_id=?", (receipt["derived_inputs"][0]["association_id"],))
    elif change == "metadata":
        service.store.conn.execute("UPDATE objects SET media_type='image/png' WHERE digest=?", (ref["object_id"][7:],))
    elif change == "project_association":
        service.store.conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=?", (project, ref["object_id"][7:]))
    elif change == "registry":
        spec = load_task_spec(service, attempt["task_id"])
        spec["derived_input_registry"] = {}
        store_task_spec(service, attempt["task_id"], spec)
    elif change == "filename":
        ref["filename"] = "changed.bin"
    elif change == "digest":
        payload = service._decode_child_authority(receipt["authority"])
        payload["child"]["capability_digest"] = digest("wrong")
        # Unsigned mutation cannot turn a predicted identity into authority.
        encoded, signature = receipt["authority"].split(".")
        receipt["authority"] = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "." + signature
    with pytest.raises((AuthorizationError, ConflictError)):
        admit(service, receipt, refs=[ref], cap=OTHER if change == "capability" else CHILD, key="replayed-other-id" if change == "child_id" else "child")


def test_replay_cannot_change_child_and_limits_are_atomic(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 1, "max_derived_objects": 1, "max_derived_bytes": 20, "max_child_inputs": 1})
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    admit(service, receipt, refs=[ref])
    with pytest.raises(ConflictError):
        admit(service, receipt, refs=[ref], params={"changed": True})
    with pytest.raises(ValidationError, match="child count"):
        admit(service, authority(service, attempt), key="second")
    second = upload(service, attempt, b"second", "second")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[second], key="second")
    with pytest.raises(ValidationError, match="child input count"):
        authority(service, attempt, refs=[ref, second], key="second")
    assert len(service.managed_outputs(attempt["task_id"])) == 1


def test_derived_byte_budget_rejects_before_registration(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_derived_bytes": 3})
    ref = upload(service, attempt, b"four")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[ref])
    assert not service.managed_outputs(attempt["task_id"])


@pytest.mark.parametrize("end", ["cancel", "failure", "lease", "authority", "epoch"])
def test_parent_end_contains_queued_and_running_children_and_fences_admission(runtime, end):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    running = admit(service, receipt, key="running")
    child_attempt = claim(service, CHILD, "claim-running")
    queued = admit(service, receipt, key="queued")
    if end == "cancel":
        service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="cancel-parent")
    elif end == "failure":
        service.fail_attempt(attempt["attempt_id"], {**lease(attempt), "error": {"code": "fixture_failure"}}, idempotency_key="fail-parent", identity=IDENTITY)
    elif end == "lease":
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, attempt["task_id"]))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
        with service.store._transaction():
            service.store._reap_expired_leases()
    elif end == "authority":
        # Deterministic fixture for the existing owner revocation endpoint.
        service.store._append_event(attempt["run_id"], attempt["task_id"], "task.remote_activation_qualified", {"activation_id": "fixture-activation"})
        service.revoke_remote_activation(attempt["task_id"], "fixture-activation", identity={"actor": "owner", "scopes": ["admin"]})
    else:
        service.store.begin_runtime_session("fixture-next-boot")
    for child in (running, queued):
        assert service.task(child["task"]["id"])["task"]["status"] == "cancelled"
    with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
        admit(service, receipt, key="late")
    with pytest.raises(LeaseError):
        settle(service, child_attempt, "late-child-settle")


def test_external_descendant_termination_stays_unknown(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    claim(service, CHILD, "claim-external")
    service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="cancel-external-parent")
    child_value = service.task(child["task"]["id"])["task"]
    assert child_value["status"] == "cancel_requested"
    assert child_value["waiting_reason"] == "provider_state_unknown"
    events = service.events(child["run"]["id"])
    cancellation = next(e for e in events if e["kind"] == "task.cancel_requested")
    assert cancellation["payload"]["remote_stop_confirmed"] is False
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, child_value["id"]))
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, child_value["attempt_id"]))
    with service.store._transaction():
        service.store._reap_expired_leases()
    assert service.task(child_value["id"])["task"]["status"] == "cancel_requested"
    service.store.begin_runtime_session("external-next-boot")
    assert service.task(child_value["id"])["task"]["status"] == "cancel_requested"
    assert service.task(child_value["id"])["task"]["waiting_reason"] == "provider_state_unknown"
    assert not service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (child_value["attempt_id"],)).fetchone()[0]


@pytest.mark.parametrize("corruption", ["bytes", "lifecycle", "association", "failed_child"])
def test_parent_success_requires_managed_verified_child_outputs(runtime, corruption):
    service, _ = runtime
    attempt = parent(runtime)
    child = admit(service, authority(service, attempt))
    child_attempt = claim(service, CHILD, "claim-child")
    if corruption == "failed_child":
        service.fail_attempt(child_attempt["attempt_id"], {**lease(child_attempt), "error": {"code": "failed"}}, idempotency_key="fail-child", identity=IDENTITY)
    else:
        payload = b"child-output"
        settle(service, child_attempt, "child-success", [{"digest": digest(payload), "data_base64": base64.b64encode(payload).decode()}])
        association = service.managed_outputs(child["task"]["id"])[0]
        if corruption == "bytes":
            service.cas.path_for(digest(payload)[7:]).write_bytes(b"bad-output!!")
        elif corruption == "lifecycle":
            service.store.conn.execute("UPDATE managed_output_lifecycle SET state='reclaimed' WHERE association_id=?", (association["association_id"],))
        else:
            service.store.conn.execute("DELETE FROM managed_output_lifecycle WHERE association_id=?", (association["association_id"],))
    with pytest.raises(ConflictError):
        settle(service, attempt, "parent-success")
    assert service.task(attempt["task_id"])["task"]["status"] == "running"


def test_bounded_parallel_admission_and_same_key_replay(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 2})
    receipt = authority(service, attempt)
    def one(key):
        try:
            return admit(service, receipt, key=key)["task"]["id"]
        except ValidationError:
            return "limit"
    with ThreadPoolExecutor(max_workers=3) as pool:
        values = list(pool.map(one, ["first", "second", "third"]))
    assert values.count("limit") == 1
    assert len(service.store.delegated_children(attempt["task_id"], attempt["attempt_id"])) == 2


def test_policy_limits_cannot_expand_runtime_ceiling(runtime):
    for key, ceiling in CHILD_LIMIT_CEILINGS.items():
        with pytest.raises(ValidationError):
            parent(runtime, limits={key: ceiling + 1}, key=key)


@pytest.mark.parametrize("key,ceiling", list(CHILD_LIMIT_CEILINGS.items()))
def test_every_limit_ceiling_is_accepted_and_next_integer_rejected(key, ceiling):
    base = {"capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}], "targets": [{"kind": "default"}], "input_object_ids": []}
    for value in (ceiling - 1, ceiling):
        policy = RuntimeService._child_policy({**base, "limits": {key: value}})
        assert policy["limits"][key] == value
        assert set(policy["limits"]) == set(CHILD_LIMITS)
    for value in (ceiling + 1, 0, -1, True, 1.5, "1"):
        with pytest.raises(ValidationError):
            RuntimeService._child_policy({**base, "limits": {key: value}})


def test_effective_defaults_are_frozen_at_admission(runtime, monkeypatch):
    service, _ = runtime
    attempt = parent(runtime)
    stored = service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]["limits"]
    assert stored == CHILD_LIMITS
    monkeypatch.setattr(service_module, "CHILD_LIMITS", {key: 1 for key in CHILD_LIMITS})
    receipt = authority(service, attempt)
    admit(service, receipt, key="first")
    admit(service, receipt, key="second")
    assert service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]["limits"] == stored


def test_explicit_expanded_envelope_and_lifetime_active_accounting(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 500, "max_active_children": 1, "max_derived_objects": 512, "max_derived_bytes": 1024 ** 3})
    policy = service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]["limits"]
    assert policy["max_children"] == 500
    assert policy["max_derived_bytes"] == 1024 ** 3
    receipt = authority(service, attempt)
    first = admit(service, receipt, key="first")
    assert admit(service, receipt, key="first") == first
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"]) == {"lifetime": 1, "active": 1, "replay": False}
    with pytest.raises(ValidationError, match="active child"):
        admit(service, receipt, key="second")
    first_attempt = claim(service, CHILD, "claim-first")
    settle(service, first_attempt, "first-done")
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 0
    admit(service, receipt, key="second")
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["lifetime"] == 2
    with pytest.raises(ValidationError, match="active child"):
        service.retry_task(first["task"]["id"], {}, idempotency_key="retry-first")


@pytest.mark.parametrize("state", ["queued", "running", "cancel_requested", "provider_state_unknown"])
def test_all_outstanding_child_states_hold_active_capacity(runtime, state):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 3, "max_active_children": 1}, targeted=state in {"cancel_requested", "provider_state_unknown"})
    receipt = authority(service, attempt)
    child = admit(service, receipt, key="first")
    child_attempt = None
    if state != "queued":
        child_attempt = claim(service, CHILD, "claim-first")
    if state == "cancel_requested":
        service.cancel_task_canonical(child["task"]["id"], {}, idempotency_key="cancel-first")
    if state == "provider_state_unknown":
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, child_attempt["task_id"]))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, child_attempt["attempt_id"]))
        with service.store._transaction():
            service.store._reap_expired_leases()
        assert service.task(child_attempt["task_id"])["task"]["waiting_reason"] == "provider_state_unknown"
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 1
    assert admit(service, receipt, key="first")["task"]["id"] == child["task"]["id"]
    with pytest.raises(ValidationError, match="active child"):
        admit(service, receipt, key="second")


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
def test_terminal_release_preserves_lifetime_and_retry_reuses_identity(runtime, terminal):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_children": 1, "max_active_children": 1})
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    if terminal == "cancelled":
        service.cancel_task_canonical(child["task"]["id"], {}, idempotency_key="cancel-child")
    else:
        child_attempt = claim(service, CHILD, "claim-child")
        if terminal == "completed":
            settle(service, child_attempt, "done-child")
        else:
            service.fail_attempt(child_attempt["attempt_id"], {**lease(child_attempt), "error": {"code": "fixture"}}, idempotency_key="failed-child", identity=IDENTITY)
    accounting = service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])
    assert accounting["lifetime"] == 1 and accounting["active"] == 0
    with pytest.raises(ValidationError, match="parent child count"):
        admit(service, receipt, key="new-child")
    service.retry_task(child["task"]["id"], {}, idempotency_key="retry-child")
    accounting = service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])
    assert accounting["lifetime"] == 1 and accounting["active"] == 1


def test_distinct_object_union_and_scaled_exact_byte_boundary(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_derived_objects": 2, "max_derived_bytes": 5})
    first = upload(service, attempt, b"12", "first")
    second = upload(service, attempt, b"345", "second")
    one = authority(service, attempt, refs=[first], key="one")
    assert authority(service, attempt, refs=[first], key="one") == one
    authority(service, attempt, refs=[first, second], key="two")
    registry = service.task(attempt["task_id"])["task"]["spec"]["derived_input_registry"]
    assert len(registry) == 2 and sum(ref["size"] for ref in registry.values()) == 5
    third = upload(service, attempt, b"6", "third")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[third], key="three")
    assert service.task(attempt["task_id"])["task"]["spec"]["derived_input_registry"] == registry


def test_scaled_byte_overage_with_object_capacity_remaining(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_derived_objects": 3, "max_derived_bytes": 5})
    first = upload(service, attempt, b"12345", "first")
    authority(service, attempt, refs=[first])
    second = upload(service, attempt, b"6", "second")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[second], key="second")
    assert len(service.managed_outputs(attempt["task_id"])) == 1


def test_per_child_derived_bytes_and_individual_object_boundary(runtime, monkeypatch):
    service, _ = runtime
    attempt = parent(runtime, limits={"max_child_bytes": 4, "max_derived_bytes": 10})
    first = upload(service, attempt, b"12", "first")
    second = upload(service, attempt, b"345", "second")
    authority(service, attempt, refs=[first], key="first")
    authority(service, attempt, refs=[second], key="second")
    with pytest.raises(ValidationError, match="child input byte"):
        authority(service, attempt, refs=[first, second], key="both")
    too_big = {**first, "size": OBJECT_MAX_BYTES + 1}
    with pytest.raises(ValidationError, match="identity or size"):
        authority(service, attempt, refs=[too_big], key="oversized")
    # Scale the already-established 64 MiB per-object gate to real tiny bytes.
    monkeypatch.setattr(service_module, "OBJECT_MAX_BYTES", 4)
    boundary = upload(service, attempt, b"1234", "boundary")
    assert boundary["size"] == 4
    authority(service, attempt, refs=[boundary], key="exact-child-byte-boundary")
    with pytest.raises(ValidationError):
        upload(service, attempt, b"12345", "over-boundary")


def test_direct_wrong_capability_digest_and_scalar_omitted_objects(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    task = {"capability_id": CHILD, "capability_digest": digest("wrong"), "spec": {"params": {"query": "fixture://video"}}}
    with pytest.raises(AuthorizationError, match="capability"):
        service.admit_delegated_child({"authority": receipt["authority"], "task": task}, idempotency_key="child", identity=IDENTITY)
    task["capability_digest"] = digest(CHILD)
    child = service.admit_delegated_child({"authority": receipt["authority"], "task": task}, idempotency_key="child", identity=IDENTITY)
    assert child["task"]["spec"]["input_object_ids"] == []


def test_four_by_four_runtime_fanout_has_33_overlapping_required_children(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    refs = [upload(service, attempt, f"frame-{index}".encode(), f"frame-{index}") for index in range(17)]
    accepted = []
    for index in range(33):
        cap = CHILD if index < 17 else OTHER
        key = "fanout-" + str(index)
        ref = refs[index if index < 17 else index - 16]
        accepted.append(admit(service, authority(service, attempt, refs=[ref], key=key, cap=cap), refs=[ref], key=key, cap=cap))
    attempts = [claim(service, CHILD if index < 17 else OTHER, "claim-fanout-" + str(index)) for index in range(33)]
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 33
    assert all(value["task"]["execution_request"]["target"] == TARGET for value in accepted)
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, attempt, "fanout-early")
    service.heartbeat_attempt(attempts[0]["attempt_id"], {**lease(attempts[0]), "progress": {"percent": 50}}, idempotency_key="fanout-progress", identity=IDENTITY)
    for index, child_attempt in enumerate(attempts):
        settle(service, child_attempt, "fanout-done-" + str(index))
    settle(service, attempt, "fanout-parent-done")


def test_maximum_child_and_registry_accounting_enforces_admission_limits(runtime):
    service, _ = runtime
    attempt = parent(runtime, limits=CHILD_LIMIT_CEILINGS)
    ref = upload(service, attempt, b"x", "selected")
    receipt = authority(service, attempt, refs=[ref], key="selected-child")
    spec = load_task_spec(service, attempt["task_id"])
    # Populate bounded metadata in the temporary fixture, without allocating GiB
    # or treating synthetic references as authenticated objects. Only `ref` is used.
    for index in range(1023):
        object_id = digest("metadata-" + str(index))
        spec["derived_input_registry"][object_id] = {**ref, "object_id": object_id, "parent_attempt_id": attempt["attempt_id"], "association_id": "fixture-association-" + str(index)}
    store_task_spec(service, attempt["task_id"], spec)
    selected = admit(service, receipt, refs=[ref], key="selected-child")
    selected_row = service.store.conn.execute("SELECT * FROM tasks WHERE id=?", (selected["task"]["id"],)).fetchone()
    run_row = service.store.conn.execute("SELECT * FROM runs WHERE id=?", (selected_row["run_id"],)).fetchone()
    task_columns = list(selected_row.keys())
    run_columns = list(run_row.keys())
    with service.store._transaction():
        for index in range(4095):
            task = dict(selected_row)
            run = dict(run_row)
            run["id"] = "metadata-run-" + str(index)
            run["idempotency_key"] = "metadata-child-" + str(index)
            task.update(id="metadata-task-" + str(index), run_id=run["id"], status="queued" if index < 63 else "completed", result_json='{"outputs": []}')
            service.store.conn.execute(f"INSERT INTO runs({','.join(run_columns)}) VALUES ({','.join('?' for _ in run_columns)})", [run[key] for key in run_columns])
            service.store.conn.execute(f"INSERT INTO tasks({','.join(task_columns)}) VALUES ({','.join('?' for _ in task_columns)})", [task[key] for key in task_columns])
            if index == 62:
                assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["active"] == 64
                with pytest.raises(ValidationError, match="active child"):
                    admit(service, authority(service, attempt), key="over-active")
    replays = [admit(service, receipt, refs=[ref], key="selected-child") for _ in range(10)]
    assert len(replays) == 10
    assert all(replay["task"]["id"] == selected["task"]["id"] for replay in replays)
    assert service.store.delegated_child_accounting(attempt["task_id"], attempt["attempt_id"])["lifetime"] == 4096
    with pytest.raises(ValidationError, match="parent child count"):
        admit(service, authority(service, attempt), key="over-lifetime")
    extra = upload(service, attempt, b"extra", "extra")
    with pytest.raises(ValidationError, match="count or byte"):
        authority(service, attempt, refs=[extra], key="over-registry")


def test_parent_success_racing_child_admission_has_one_fenced_outcome(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    barrier = threading.Barrier(2)
    def admit_child():
        barrier.wait()
        try:
            admit(service, receipt)
            return "accepted"
        except LeaseError:
            return "fenced"
    def settle_parent():
        barrier.wait()
        try:
            settle(service, attempt, "race-success")
            return "completed"
        except ConflictError:
            return "child-active"
    with ThreadPoolExecutor(max_workers=2) as pool:
        child_future = pool.submit(admit_child)
        parent_future = pool.submit(settle_parent)
        outcome = (child_future.result(), parent_future.result())
    assert outcome in {("accepted", "child-active"), ("fenced", "completed")}
    if outcome[0] == "accepted":
        assert service.task(attempt["task_id"])["task"]["status"] == "running"
    else:
        assert not service.store.delegated_children(attempt["task_id"], attempt["attempt_id"])


def test_parent_cancellation_racing_admission_contains_any_accepted_child(runtime):
    service, _ = runtime
    attempt = parent(runtime)
    receipt = authority(service, attempt)
    barrier = threading.Barrier(2)
    def admit_child():
        barrier.wait()
        try:
            return admit(service, receipt)["task"]["id"]
        except LeaseError:
            return None
    def cancel_parent():
        barrier.wait()
        service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="race-cancel")
    with ThreadPoolExecutor(max_workers=2) as pool:
        child_future = pool.submit(admit_child)
        parent_future = pool.submit(cancel_parent)
        child_id = child_future.result()
        parent_future.result()
    assert service.task(attempt["task_id"])["task"]["status"] == "cancelled"
    if child_id is not None:
        assert service.task(child_id)["task"]["status"] == "cancelled"
    with pytest.raises(LeaseError):
        admit(service, receipt, key="late-race")


def test_external_parent_run_cancellation_contains_delegated_children(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    receipt = authority(service, attempt)
    child = admit(service, receipt)
    claim(service, CHILD, "claim-run-child")
    service.cancel_run(attempt["run_id"], {}, idempotency_key="parent-run-cancel")
    assert service.task(attempt["task_id"])["task"]["status"] == "cancel_requested"
    assert service.task(child["task"]["id"])["task"]["status"] == "cancel_requested"
    with pytest.raises(LeaseError):
        admit(service, receipt, key="after-run-cancel")

# Producing-child snapshots use the actual Human Review ID,
# with deterministic local capability bytes and two independent worker actors.
HUMAN_REVIEW = "editorial.human_review"
REVIEWER_IDENTITY = {**copy.deepcopy(IDENTITY), "actor": "reviewer"}


def snapshot_parent(runtime, *, permitted=True, limits=None):
    service, project = runtime
    service.register_capability({"capability_id": HUMAN_REVIEW, "definition_digest": digest(HUMAN_REVIEW)})
    service.register_executor({"executor_id": "reviewer", "capabilities": [HUMAN_REVIEW], "max_concurrency": 4}, idempotency_key="register-reviewer")
    policy = {"capabilities": [{"capability_id": HUMAN_REVIEW, "capability_digest": digest(HUMAN_REVIEW)}],
              "targets": [{"kind": "default"}], "input_object_ids": []}
    if permitted:
        policy["recoverable_outputs"] = [{**policy["capabilities"][0], "output_ports": ["state_result"]}]
    if limits is not None:
        policy["limits"] = limits
    service.create_task({"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
        "input_object_ids": [], "spec": {}, "child_delegation": policy, "idempotency_key": "snapshot-parent"}, enforce_readiness=True)
    return claim(service, PARENT, "claim-snapshot-parent")


def snapshot_child(service, parent_attempt, key="review"):
    task = admit(service, authority(service, parent_attempt), cap=HUMAN_REVIEW, key=key)
    attempt = service.claim_next({"executor_id": "reviewer", "capability_ids": [HUMAN_REVIEW],
        "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-" + key, identity=REVIEWER_IDENTITY)
    assert attempt["task_id"] == task["task"]["id"]
    return attempt


def snapshot_upload(service, attempt, data=b'{"draft":1}', *, name="draft", port="state_result"):
    output = {"name": name, "output_port": port, "filename": name + ".json", "object_id": digest(data),
              "size": len(data), "media_type": "application/json"}
    binding = {"project_id": attempt["project_id"], "run_id": attempt["run_id"], "task_id": attempt["task_id"],
        "attempt_id": attempt["attempt_id"], "executor_id": "reviewer", **lease(attempt), "output_key": name,
        "output_port": port, "filename": output["filename"], "digest": output["object_id"], "size": len(data),
        "media_type": output["media_type"]}
    service.ingest_object(data, media_type=output["media_type"], original_name=output["filename"],
        idempotency_key=service._generic_output_idempotency_key(binding), identity=REVIEWER_IDENTITY, upload_binding=binding)
    return output


def publish_snapshot(service, attempt, output, revision=1, key="save-1", **kwargs):
    return service.publish_recoverable_snapshot(attempt["attempt_id"], {**lease(attempt), "revision": revision, "output": output},
        idempotency_key=key, identity=kwargs.get("identity", REVIEWER_IDENTITY))


def test_snapshot_grant_omission_denies_and_admission_freezes_defaults(runtime, monkeypatch):
    service, _ = runtime
    p = snapshot_parent(runtime, permitted=False)
    child = snapshot_child(service, p)
    assert "delegated_recoverable_outputs" not in child["spec"]
    with pytest.raises(AuthorizationError, match="grant"):
        publish_snapshot(service, child, snapshot_upload(service, child))


def test_snapshot_grant_is_parent_bound_and_runtime_owned(runtime, monkeypatch):
    service, _ = runtime
    p = snapshot_parent(runtime)
    policy = service.task(p["task_id"])["task"]["spec"]["child_delegation"]
    for grant in ([{**policy["recoverable_outputs"][0], "output_ports": ["*"]}],
                  [policy["recoverable_outputs"][0]] * 2,
                  [{**policy["recoverable_outputs"][0], "capability_id": CHILD}],
                  [{**policy["recoverable_outputs"][0], "capability_digest": digest("wrong")}],
                  [{**policy["recoverable_outputs"][0], "limits": {}}]):
        with pytest.raises(ValidationError):
            service._child_policy({**policy, "recoverable_outputs": grant})
    receipt = authority(service, p)
    for spec in ({"delegated_recoverable_outputs": {}}, {"delegated_parent": {}}):
        with pytest.raises(ValidationError, match="Runtime admission"):
            service.admit_delegated_child(
                {"authority": receipt["authority"], "task": {"capability_id": HUMAN_REVIEW,
                    "capability_digest": digest(HUMAN_REVIEW), "spec": spec}}, idempotency_key="forge", identity=IDENTITY)
    child = snapshot_child(service, p)
    frozen = child["spec"]["delegated_recoverable_outputs"]
    assert frozen["capability_id"] == HUMAN_REVIEW and frozen["output_ports"] == ["state_result"]
    assert frozen["policy_digest"] == child["spec"]["delegated_parent"]["policy_digest"]
    assert frozen["parent_attempt_id"] == p["attempt_id"]
    assert frozen["limits"] == {k: CHILD_LIMITS[k] for k in ("max_recoverable_snapshots", "max_recoverable_bytes", "max_snapshot_bytes")}
    monkeypatch.setitem(CHILD_LIMITS, "max_snapshot_bytes", 1)
    publish_snapshot(service, child, snapshot_upload(service, child))


@pytest.mark.parametrize("limit", ["max_recoverable_snapshots", "max_recoverable_bytes", "max_snapshot_bytes"])
def test_snapshot_policy_hard_ceilings_inclusive(runtime, limit):
    service, _ = runtime
    p = snapshot_parent(runtime)
    policy = service.task(p["task_id"])["task"]["spec"]["child_delegation"]
    assert service._child_policy({**policy, "limits": {limit: CHILD_LIMIT_CEILINGS[limit]}})["limits"][limit] == CHILD_LIMIT_CEILINGS[limit]
    for bad in (0, True, CHILD_LIMIT_CEILINGS[limit] + 1):
        with pytest.raises(ValidationError, match="finite Runtime"):
            service._child_policy({**policy, "limits": {limit: bad}})


def test_snapshot_own_worker_replay_revision_conflict_and_settlement_separation(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    saved = publish_snapshot(service, child, output)
    assert saved["data"]["role"] == "recoverable_snapshot"
    assert saved["data"]["provenance"]["executor_id"] == "reviewer"
    assert p["spec"].get("delegated_parent") is None
    assert publish_snapshot(service, child, output) == saved
    assert publish_snapshot(service, child, output, key="lost-response-new-key") == saved
    with pytest.raises(ConflictError):
        publish_snapshot(service, child, output, revision=2, key="lost-response-new-key")
    assert len(service.managed_outputs(child["task_id"])) == 1
    changed = snapshot_upload(service, child, b'{"draft":2}')
    with pytest.raises(ConflictError):
        publish_snapshot(service, child, changed)
    with pytest.raises(ConflictError):
        publish_snapshot(service, child, changed, key="changed-revision")
    publish_snapshot(service, child, changed, revision=3, key="save-3")
    with pytest.raises(ConflictError, match="stale"):
        publish_snapshot(service, child, output, revision=2, key="save-2")
    assert service.task(child["task_id"])["task"]["status"] == "running"
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, p, "draft-is-not-success")
    with pytest.raises(ValidationError, match="Runtime-reserved"):
        service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": [{"digest": output["object_id"], "role": "recoverable_snapshot"}]}, idempotency_key="forge-role", identity=REVIEWER_IDENTITY)
    final_data = b'{"submitted":true}'
    service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": [{"name": "state_result", "output_port": "state_result",
        "digest": digest(final_data), "data_base64": base64.b64encode(final_data).decode()}]}, idempotency_key="review-submit", identity=REVIEWER_IDENTITY)
    task = service.task(child["task_id"])["task"]
    assert len(task["result"]["outputs"]) == 1
    assert task["result"]["outputs"][0]["digest"] == digest(final_data)
    assert len(service.managed_outputs(child["task_id"])) == 3
    settle(service, p, "parent-with-final")
    assert service.task(p["task_id"])["task"]["status"] == "completed"


@pytest.mark.parametrize("change", ["identity", "no_identity", "fence", "lease_id", "runtime_epoch", "attempt", "no_receipt",
    "foreign_receipt", "digest", "unprefixed_digest", "size", "media_type", "filename", "object_metadata", "project", "port", "capability", "grant", "parent_policy", "corrupt", "missing", "malformed"])
def test_snapshot_authentication_upload_and_custody_rejections(runtime, change):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    body = {**lease(child), "revision": 1, "output": output}
    attempt_id = child["attempt_id"]
    identity = REVIEWER_IDENTITY
    if change in ("identity", "no_identity"):
        identity = IDENTITY if change == "identity" else None
    elif change in ("fence", "lease_id", "runtime_epoch"):
        body[change] = "foreign" if change == "lease_id" else body[change] + 1
    elif change == "attempt":
        attempt_id = p["attempt_id"]
    elif change == "no_receipt":
        service.store.conn.execute("DELETE FROM command_idempotency WHERE command_kind='object.ingest'")
    elif change == "foreign_receipt":
        sibling = snapshot_child(service, p, key="sibling")
        body["output"] = snapshot_upload(service, sibling, b"foreign")
    elif change == "digest":
        output["object_id"] = digest("unuploaded")
    elif change == "unprefixed_digest":
        output["object_id"] = output["object_id"][7:]
    elif change == "filename":
        output["filename"] = "wrong.json"
    elif change == "object_metadata":
        service.store.conn.execute("UPDATE objects SET media_type='image/png' WHERE digest=?", (output["object_id"][7:],))
    elif change in ("size", "media_type", "port"):
        output["size" if change == "size" else "media_type" if change == "media_type" else "output_port"] = len(b'{"draft":1}') + 1 if change == "size" else "image/png" if change == "media_type" else "other"
    elif change == "project":
        service.store.conn.execute("UPDATE runs SET project_id=NULL WHERE id=?", (child["run_id"],))
    elif change in ("capability", "grant"):
        spec = load_task_spec(service, child["task_id"])
        if change == "capability":
            spec["capability_digest"] = digest("changed")
        else:
            spec["delegated_recoverable_outputs"]["output_ports"] = ["other"]
        store_task_spec(service, child["task_id"], spec)
    elif change == "parent_policy":
        spec = load_task_spec(service, p["task_id"])
        spec["child_delegation"]["limits"]["max_snapshot_bytes"] = 2
        store_task_spec(service, p["task_id"], spec)
    elif change in ("corrupt", "missing"):
        path = service.cas.path_for(output["object_id"][7:])
        path.write_bytes(b"corrupt!!!") if change == "corrupt" else path.unlink()
    elif change == "malformed":
        output["unexpected"] = True
    with pytest.raises((AuthorizationError, LeaseError, ConflictError, ValidationError)):
        service.publish_recoverable_snapshot(attempt_id, body, idempotency_key="bad-save", identity=identity)
    assert not service.managed_outputs(child["task_id"])
    assert not service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE command_kind='attempt.recoverable_snapshot.publish'").fetchone()


@pytest.mark.parametrize("bound", ["count", "aggregate_bytes", "object_bytes"])
def test_snapshot_quota_inclusive_edges_and_replay_no_double_charge(runtime, bound):
    service, _ = runtime
    limits = {"max_recoverable_snapshots": 2 if bound == "count" else 10,
              "max_recoverable_bytes": 4 if bound == "aggregate_bytes" else 100,
              "max_snapshot_bytes": 2 if bound == "object_bytes" else 100}
    p = snapshot_parent(runtime, limits=limits)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child, b"12")
    saved = publish_snapshot(service, child, output)
    assert publish_snapshot(service, child, output) == saved
    publish_snapshot(service, child, output, revision=2, key="save-2")
    extra = snapshot_upload(service, child, b"123" if bound == "object_bytes" else b"1", name="extra")
    with pytest.raises(ValidationError, match="count or byte"):
        publish_snapshot(service, child, extra, revision=3, key="overflow")
    assert len(service.managed_outputs(child["task_id"])) == 2
    assert len(service.store.recoverable_snapshots(parent_attempt_id=p["attempt_id"])) == 2


def test_snapshot_quota_shared_by_children_and_cancel_does_not_refund(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime, limits={"max_recoverable_snapshots": 1})
    child = snapshot_child(service, p)
    saved = publish_snapshot(service, child, snapshot_upload(service, child))
    service.cancel_task_canonical(child["task_id"], {}, idempotency_key="cancel-review")
    sibling = snapshot_child(service, p, "retry-child")
    with pytest.raises(ValidationError, match="count or byte"):
        publish_snapshot(service, sibling, snapshot_upload(service, sibling), key="sibling-save")
    assert service.managed_output(saved["data"]["association_id"]) == saved["data"]
    with pytest.raises(ConflictError, match="every accepted child"):
        settle(service, p, "cancelled-draft-is-not-success")


@pytest.mark.parametrize("closure", ["child_cancel", "parent_cancel", "child_lease", "parent_lease", "restart"])
def test_snapshot_closure_preserves_acknowledged_receipt_and_exact_bytes(runtime, closure):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    data = b'{"partial":"acknowledged"}'
    output = snapshot_upload(service, child, data)
    saved = publish_snapshot(service, child, output)
    # Upload a proposed later revision while live; closure must still deny it.
    later = snapshot_upload(service, child, b'{"partial":"unacknowledged"}', name="later")
    if closure.endswith("cancel"):
        closing = child if closure.startswith("child") else p
        service.cancel_task_canonical(closing["task_id"], {}, idempotency_key="close")
    elif closure.endswith("lease"):
        closing = child if closure.startswith("child") else p
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with service.store._mutex, service.store._transaction():
            service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, closing["task_id"]))
            service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, closing["attempt_id"]))
            service.store._reap_expired_leases()
    else:
        root = service.store.root
        service.close()
        service = RuntimeService(root)
    try:
        assert publish_snapshot(service, child, output) == saved
        assert publish_snapshot(service, child, output, key="recover-receipt") == saved
        with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
            publish_snapshot(service, child, later, revision=2, key="after-close")
        items = service.managed_output_page(child["task_id"])["items"]
        assert [a["association_id"] for a in items] == [saved["data"]["association_id"]]
        recovered = service.managed_output(saved["data"]["association_id"])
        row, raw = service.object(recovered["object_id"])
        assert raw == data and digest(raw) == recovered["object_id"] and row["size"] == len(data)
        assert recovered["lifecycle"]["state"] == "available"
        assert service.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (child["project_id"], output["object_id"][7:])).fetchone()
        assert service.task(child["task_id"])["task"]["status"] != "completed"
    finally:
        if closure == "restart":
            service.close()


@pytest.mark.parametrize("closure", ["child_cancel", "parent_cancel", "child_lease", "parent_lease"])
@pytest.mark.parametrize("order", ["publish_first", "close_first", "concurrent"])
def test_snapshot_publication_and_authority_closure_serialize(runtime, closure, order):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    barrier = threading.Barrier(2) if order == "concurrent" else None
    def publish():
        if barrier:
            barrier.wait()
        try:
            return publish_snapshot(service, child, output)
        except (LeaseError, AuthorizationError, ConflictError):
            return None
    def close():
        if barrier:
            barrier.wait()
        closing = child if closure.startswith("child") else p
        if closure.endswith("cancel"):
            service.cancel_task_canonical(closing["task_id"], {}, idempotency_key="race-close")
        else:
            with service.store._mutex, service.store._transaction():
                expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, closing["task_id"]))
                service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, closing["attempt_id"]))
                service.store._reap_expired_leases()
    if order == "concurrent":
        with ThreadPoolExecutor(max_workers=2) as pool:
            published = pool.submit(publish)
            closed = pool.submit(close)
            saved = published.result()
            closed.result()
    elif order == "publish_first":
        saved = publish()
        assert saved is not None
        close()
    else:
        close()
        saved = publish()
        assert saved is None
    items = service.managed_outputs(child["task_id"])
    assert len(items) == int(saved is not None)
    if saved is not None:
        assert publish_snapshot(service, child, output) == saved
    with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
        publish_snapshot(service, child, output, revision=2, key="closed-revision")


def test_snapshot_transaction_failure_rolls_back_custody_event_quota_and_receipt(runtime, monkeypatch):
    service, project = runtime
    p = snapshot_parent(runtime, limits={"max_recoverable_snapshots": 1})
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    before = service.events(child["run_id"])
    original = service._command_record
    def fail_commit(kind, *args, **kwargs):
        if kind == "attempt.recoverable_snapshot.publish":
            raise ConflictError("injected receipt failure")
        return original(kind, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(service, "_command_record", fail_commit)
        with pytest.raises(ConflictError, match="injected"):
            publish_snapshot(service, child, output)
    assert service.managed_outputs(child["task_id"]) == []
    assert service.store.recoverable_snapshots(parent_attempt_id=p["attempt_id"]) == []
    assert service.events(child["run_id"]) == before
    assert not service.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project, output["object_id"][7:])).fetchone()
    assert not service.store.conn.execute("SELECT 1 FROM command_idempotency WHERE command_kind='attempt.recoverable_snapshot.publish'").fetchone()
    publish_snapshot(service, child, output)


def test_snapshot_cannot_replace_missing_final_managed_association(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child)
    saved = publish_snapshot(service, child, output)
    service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": [{"name": output["name"],
        "filename": output["filename"], "output_port": "state_result", "digest": output["object_id"],
        "size": output["size"], "media_type": output["media_type"]}]}, idempotency_key="final-same-bytes", identity=REVIEWER_IDENTITY)
    service.store.conn.execute("DELETE FROM managed_output_lifecycle WHERE association_id IN (SELECT association_id FROM managed_output_associations WHERE task_id=? AND role!='recoverable_snapshot')", (child["task_id"],))
    service.store.conn.execute("DELETE FROM managed_output_associations WHERE task_id=? AND role!='recoverable_snapshot'", (child["task_id"],))
    assert service.managed_outputs(child["task_id"])[0]["association_id"] == saved["data"]["association_id"]
    with pytest.raises(ConflictError, match="verified durable"):
        settle(service, p, "snapshots-cannot-cover-final")


def test_snapshot_same_task_retry_shares_parent_quota(runtime):
    service, _ = runtime
    p = snapshot_parent(runtime, limits={"max_recoverable_snapshots": 1})
    child = snapshot_child(service, p)
    publish_snapshot(service, child, snapshot_upload(service, child))
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with service.store._mutex, service.store._transaction():
        service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, child["task_id"]))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, child["attempt_id"]))
        service.store._reap_expired_leases()
    retry = service.claim_next({"executor_id": "reviewer", "capability_ids": [HUMAN_REVIEW],
        "runtime_epoch": service.health()["runtime_epoch"]}, idempotency_key="claim-review-retry", identity=REVIEWER_IDENTITY)
    assert retry["task_id"] == child["task_id"] and retry["attempt_id"] != child["attempt_id"]
    with pytest.raises(ValidationError, match="count or byte"):
        publish_snapshot(service, retry, snapshot_upload(service, retry), key="attempt-retry-save")


def test_snapshot_restart_fresh_authorized_generated_reads_return_exact_bytes(runtime, tmp_path):
    import sys
    from pathlib import Path
    from types import SimpleNamespace
    from runtime_protocol.auth import CredentialStore
    from runtime_protocol.server import RuntimeHandler
    sys.path.insert(0, str(Path(__file__).parents[1] / "packages/python"))
    from astrid_runtime_client import WorkspaceClient

    service, _ = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    payload = b'{"last_acknowledged":true}'
    saved = publish_snapshot(service, child, snapshot_upload(service, child, payload))
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    try:
        credentials = CredentialStore(tmp_path / "fresh-reader-credentials")
        token, _ = credentials.provision("fresh-reader", ["tasks:read", "objects:read"])
        no_scopes, _ = credentials.provision("unauthorized-reader", [])
        def transport(method, path, headers, body):
            handler = object.__new__(RuntimeHandler)
            handler.server = SimpleNamespace(runtime=restarted, credentials=credentials)
            handler.command = method
            handler.path = path
            handler.headers = headers
            captured = {"status": None, "headers": {}, "body": bytearray()}
            handler.send_response = lambda status: captured.update(status=status)
            handler.send_header = lambda key, value: captured["headers"].__setitem__(key, value)
            handler.end_headers = lambda: None
            handler.wfile = SimpleNamespace(write=lambda value: captured["body"].extend(value))
            handler._send = lambda status, value=None, *, headers=None, body=None: (
                status, headers or {}, body if body is not None else json.dumps(value).encode())
            response = handler._route()
            if response is not None:
                return response
            return captured["status"], captured["headers"], bytes(captured["body"])
        reader = WorkspaceClient("http://runtime", token, transport=transport)
        items, cursor = reader.list_managed_outputs(child["task_id"])
        assert cursor is None and len(items) == 1
        recovered = reader.get_managed_output(saved["data"]["association_id"])
        assert items[0].association_id == recovered.association_id
        raw = reader.get_object(recovered.object_id)
        assert raw.data == payload and digest(raw.data) == recovered.object_id
        assert recovered.size == len(payload) and recovered.role == "recoverable_snapshot"
        forbidden = WorkspaceClient("http://runtime", no_scopes, transport=transport)
        for read in (lambda: forbidden.list_managed_outputs(child["task_id"]),
                     lambda: forbidden.get_managed_output(recovered.association_id),
                     lambda: forbidden.get_object(recovered.object_id)):
            with pytest.raises(AuthorizationError):
                read()
    finally:
        restarted.close()


def test_snapshot_is_not_a_settled_stage_output_even_after_submit(runtime):
    service, project = runtime
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    saved = publish_snapshot(service, child, snapshot_upload(service, child))
    service.settle_attempt(child["attempt_id"], {**lease(child), "outputs": []}, idempotency_key="review-done", identity=REVIEWER_IDENTITY)
    declared = [{"name": "state", "producer_stage": "review", "output_port": "state_result"}]
    supplied = [{"name": "state", "producer_task_id": child["task_id"], "association_id": saved["data"]["association_id"], "output_port": "state_result"}]
    siblings = {"review": {"id": child["task_id"], "attempt_id": child["attempt_id"], "status": "completed"}}
    with pytest.raises(AuthorizationError, match="declared live lineage"):
        service._resolve_delegated_stage_inputs(declared, supplied, siblings=siblings, project=project,
            lineage=child["spec"]["delegated_parent"])


# Discovery selects one historical tuple; execution authority is unchanged.
def discovery_parent_body(runtime):
    service, project = runtime
    selected = parent(runtime, key="discovery-selected")
    settle(service, selected, "discovery-selected-success")
    grant = {"project_id": project, "run_id": selected["run_id"], "task_id": selected["task_id"],
             "attempt_id": selected["attempt_id"], "capability_id": PARENT, "capability_digest": digest(PARENT),
             "limits": dict(service_module.DISCOVERY_GRANT_CEILINGS)}
    policy = {"capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}],
              "targets": [{"kind": "default"}], "input_object_ids": [], "discovery_grant": grant}
    return {"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
            "input_object_ids": [], "spec": {}, "child_delegation": policy, "idempotency_key": "discovery-parent"}


def test_discovery_grant_persists_exact_historical_tuple_and_preserves_receipts(runtime):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    expected = copy.deepcopy(body["child_delegation"]["discovery_grant"])
    service.create_task(body, enforce_readiness=True)
    attempt = claim(service, PARENT, "claim-discovery-parent")
    persisted = service.task(attempt["task_id"])["task"]["spec"]["child_delegation"]
    assert persisted["discovery_grant"] == expected
    assert persisted["limits"] == CHILD_LIMITS
    assert attempt["spec"]["child_delegation"]["discovery_grant"] == expected
    assert expected["attempt_id"] != attempt["attempt_id"]
    assert service._decode_child_authority(authority(service, attempt)["authority"])["policy_digest"] == digest(
        service_module.canonical_json(persisted)).removeprefix("sha256:")
    raw = b"discovery-unbound"
    service.ingest_object(raw, original_name="raw.bin", idempotency_key="discovery-unbound")
    unbound = {"name": "raw", "output_port": "raw", "filename": "raw.bin", "object_id": digest(raw),
               "size": len(raw), "media_type": "application/octet-stream"}
    with pytest.raises(AuthorizationError, match="authenticated upload receipt"):
        authority(service, attempt, refs=[unbound])
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    child = admit(service, receipt, refs=[ref])
    assert child["task"]["spec"]["delegated_inputs"][0]["association_id"] == receipt["derived_inputs"][0]["association_id"]
    assert "child_delegation" not in child["task"]["spec"]


@pytest.mark.parametrize("field", ["project_id", "run_id", "task_id", "attempt_id", "capability_id", "capability_digest"])
def test_discovery_grant_rejects_parent_or_selected_tuple_mismatch(runtime, field):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    body["child_delegation"]["discovery_grant"][field] = digest("foreign") if field == "capability_digest" else "foreign"
    with pytest.raises(AuthorizationError, match="discovery grant"):
        service.create_task(body, enforce_readiness=True)


@pytest.mark.parametrize("bad", [None, [], {}, {"authority": "caller-forged"}])
def test_discovery_grant_rejects_malformed_object(runtime, bad):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    body["child_delegation"]["discovery_grant"] = bad
    with pytest.raises(ValidationError, match="discovery_grant"):
        service.create_task(body)


@pytest.mark.parametrize("field", ["project_id", "run_id", "task_id", "attempt_id", "capability_id", "capability_digest", "limits"])
def test_discovery_grant_rejects_missing_required_fields(runtime, field):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    del body["child_delegation"]["discovery_grant"][field]
    with pytest.raises(ValidationError, match="discovery_grant"):
        service.create_task(body)


@pytest.mark.parametrize("field", list(service_module.DISCOVERY_GRANT_CEILINGS))
@pytest.mark.parametrize("bad", [None, True, 0, -1, 1.5, "1", "missing", "excessive"])
def test_discovery_grant_requires_every_finite_budget(runtime, field, bad):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    bounds = body["child_delegation"]["discovery_grant"]["limits"]
    if bad == "missing":
        del bounds[field]
    else:
        bounds[field] = service_module.DISCOVERY_GRANT_CEILINGS[field] + 1 if bad == "excessive" else bad
    with pytest.raises(ValidationError, match="finite prototype bound"):
        service.create_task(body)


@pytest.mark.parametrize("change", ["wildcard", "empty_identity", "list_identity", "bare_digest", "extra_grant", "extra_limit", "empty_limits", "forged_parent_attempt", "spec", "body"])
def test_discovery_grant_rejects_wildcard_unknown_and_caller_authority(runtime, change):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    grant = body["child_delegation"]["discovery_grant"]
    if change == "wildcard":
        grant["run_id"] = "*"
    elif change == "empty_identity":
        grant["run_id"] = ""
    elif change == "list_identity":
        grant["task_id"] = [grant["task_id"]]
    elif change == "bare_digest":
        grant["capability_digest"] = digest(PARENT)[7:]
    elif change == "extra_grant":
        grant["authority"] = "caller-forged"
    elif change == "extra_limit":
        grant["limits"]["extra"] = 1
    elif change == "empty_limits":
        grant["limits"] = {}
    elif change == "forged_parent_attempt":
        grant["parent_attempt_id"] = "caller-forged"
    else:
        (body["spec"] if change == "spec" else body)["discovery_grant"] = grant
    with pytest.raises(ValidationError):
        service.create_task(body)


@pytest.mark.parametrize("change", ["grant", "policy", "signature", "redelegation"])
def test_discovery_grant_policy_is_signed_and_cannot_redelegate(runtime, change):
    service, _ = runtime
    body = discovery_parent_body(runtime)
    service.create_task(body)
    attempt = claim(service, PARENT, "claim-discovery-parent")
    receipt = authority(service, attempt)
    if change in {"grant", "policy"}:
        spec = load_task_spec(service, attempt["task_id"])
        if change == "grant":
            spec["child_delegation"]["discovery_grant"]["limits"]["max_discovery_rows"] -= 1
        else:
            spec["child_delegation"]["limits"]["max_children"] -= 1
        store_task_spec(service, attempt["task_id"], spec)
    elif change == "signature":
        payload = service._decode_child_authority(receipt["authority"])
        payload["policy_digest"] = digest("caller-forged")
        _, signature = receipt["authority"].split(".")
        receipt["authority"] = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "." + signature
    else:
        with pytest.raises(ValidationError, match="cannot delegate further"):
            service.create_task(body, _delegated_lineage={"parent_attempt_id": attempt["attempt_id"]})
        child = admit(service, receipt)
        child_attempt = claim(service, CHILD, "claim-discovery-child")
        spec = load_task_spec(service, child["task"]["id"])
        spec["child_delegation"] = body["child_delegation"]
        store_task_spec(service, child["task"]["id"], spec)
        with pytest.raises(AuthorizationError, match="cannot delegate further"):
            authority(service, child_attempt)
        return
    with pytest.raises(AuthorizationError):
        admit(service, receipt)


@pytest.mark.parametrize("end", ["cancel", "expired", "epoch", "fence", "recovered"])
def test_discovery_grant_uses_live_parent_lifecycle(runtime, monkeypatch, end):
    service, _ = runtime
    service.create_task(discovery_parent_body(runtime))
    attempt = claim(service, PARENT, "claim-discovery-parent")
    receipt = authority(service, attempt)
    if end == "cancel":
        service.cancel_task_canonical(attempt["task_id"], {}, idempotency_key="discovery-cancel")
    elif end == "expired":
        expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
    elif end == "epoch":
        service.store.begin_runtime_session("discovery-next-boot")
    elif end == "fence":
        service.store.conn.execute("UPDATE tasks SET lease_fence=lease_fence+1 WHERE id=?", (attempt["task_id"],))
    else:
        monkeypatch.setattr(service.store, "placement_recovery", lambda task_id: {
            "placement_version": 1, "replacement_target": dict(TARGET),
        })
    with pytest.raises((LeaseError, AuthorizationError, ConflictError)):
        admit(service, receipt)


def _captured_cancel_set(runtime):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    child = admit(service, authority(service, attempt))
    child_attempt = claim(service, CHILD, "owned-child-claim")
    service.cancel_task_canonical(attempt["task_id"], idempotency_key="owned-parent-cancel")
    captured = service.store._capture_owned_local_cancellations("worker", IDENTITY["execution_binding"])
    assert {entry["task"]["id"] for entry in captured["entries"]} == {attempt["task_id"], child["task"]["id"]}
    # Contract fixture only: production creates this after original positive
    # child ACK and retained host wait and durably records it in the daemon.
    stop_proof = {"fixture_positive_owned_stop": "generation-1"}
    return captured, stop_proof, (attempt, child_attempt)


@pytest.mark.parametrize("drift", ["attempt", "reservation", "binding", "run", "additional_work"])
def test_owned_cancel_whole_set_rejects_postcapture_drift(runtime, drift):
    service, _ = runtime
    captured, proof, attempts = _captured_cancel_set(runtime)
    victim = attempts[-1]
    if drift == "attempt":
        service.store.conn.execute("UPDATE attempts SET fence=fence+1 WHERE id=?", (victim["attempt_id"],))
    elif drift == "reservation":
        # Existing schema; an unaccounted active reservation cannot hide
        # behind the same task ID as an otherwise captured attempt.
        service.store.conn.execute("INSERT INTO reservations (task_id,executor_id,resource_key,lease_token,fence,runtime_epoch,lease_expires_at,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (victim["task_id"], "worker", "cpu", "foreign-lease", victim["fence"], victim["runtime_epoch"], "2099-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"))
    elif drift == "binding":
        row = service.store.conn.execute("SELECT resolved_target_json FROM execution_bindings WHERE task_id=?", (victim["task_id"],)).fetchone()
        placement = json.loads(row[0])
        placement["executor_incarnation"] = "replacement"
        service.store.conn.execute("UPDATE execution_bindings SET resolved_target_json=? WHERE task_id=?", (json.dumps(placement), victim["task_id"]))
    elif drift == "run":
        service.store.conn.execute("UPDATE runs SET project_id=NULL WHERE id=?", (victim["run_id"],))
    else:
        parent(runtime, targeted=True, key="another-running-parent")
    with pytest.raises(ConflictError):
        service.store._finalize_owned_local_cancellations(captured, proof)
    assert all(service.store.get_task(value["task_id"])["task"]["status"] == "cancel_requested" for value in attempts)
    assert all(service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (value["attempt_id"],)).fetchone()[0] == 0 for value in attempts)


def test_owned_cancel_whole_set_transaction_rolls_back_and_replays_once(runtime, monkeypatch):
    service, _ = runtime
    captured, proof, attempts = _captured_cancel_set(runtime)
    original = service.store._append_event
    calls = []
    def append(run_id, task_id, kind, payload, **kwargs):
        if kind == "task.cancelled":
            calls.append(task_id)
            if len(calls) == 2:
                raise OSError("injected second task write failure")
        return original(run_id, task_id, kind, payload, **kwargs)
    monkeypatch.setattr(service.store, "_append_event", append)
    with pytest.raises(OSError):
        service.store._finalize_owned_local_cancellations(captured, proof)
    assert all(service.store.get_task(value["task_id"])["task"]["status"] == "cancel_requested" for value in attempts)
    assert all(service.store.execution_binding(value["task_id"])["status"] == "stale" for value in attempts)
    monkeypatch.setattr(service.store, "_append_event", original)
    service.store._finalize_owned_local_cancellations(captured, proof)
    before = service.store.conn.total_changes
    service.store._finalize_owned_local_cancellations(captured, proof)
    assert service.store.conn.total_changes == before
    assert all(service.store.get_task(value["task_id"])["task"]["status"] == "cancelled" for value in attempts)
    assert all(service.store.execution_binding(value["task_id"])["status"] == "released" for value in attempts)


# Named publication coverage shares the existing fenced Runtime fixtures above.
def publication_effect(project, port):
    return {"effect_type": "generation.publish_v1", "target_id": project, "payload": {
        "version": 1, "modality": "video", "generation_type": "delegated_h3",
        "metadata": {"publication": port}, "partial_success_policy": "reject",
        "groups": [{"group_key": "main", "selectors": [{"selector": port,
            "ordinal": 0, "variant_key": "original", "output_port": port}]}],
    }}


def publication_policy(project):
    def stage(name, cap, inputs):
        return {"name": name, "capability_id": cap, "capability_digest": digest(cap),
                "target": {"kind": "default"}, "inputs": inputs}
    def ref(name, producer, port):
        return {"name": name, "producer_stage": producer, "output_port": port}
    final_effect = publication_effect(project, "verified_candidate")
    final_effect["payload"]["metadata"]["h3_av"] = {
        "request_digest": digest("sealed-h3-request"), "publication_scope": "final_composition",
    }
    return {
        "capabilities": [{"capability_id": cap, "capability_digest": digest(cap)} for cap in (CHILD, OTHER)],
        "targets": [{"kind": "default"}, TARGET], "input_object_ids": [],
        "stages": [stage("raw", CHILD, []), stage("compose", CHILD, [ref("raw", "raw", "raw_video")]),
            stage("verify", OTHER, [ref("candidate", "compose", "candidate")]),
            stage("final", CHILD, [ref("candidate", "compose", "candidate"), ref("verification", "verify", "verification")])],
        "publications": {
            "raw": {"stage": "raw", "output_port": "raw_video", "effect": publication_effect(project, "raw_video")},
            "final": {"stage": "final", "output_port": "verified_candidate", "candidate_stage": "compose",
                "candidate_output_port": "candidate", "verify_stage": "verify", "verify_output_port": "verification",
                "effect": final_effect},
        },
    }


def publication_parent(runtime, *, key="publication-parent", policy=None):
    service, project = runtime
    service.create_task({"project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
        "input_object_ids": [], "spec": {}, "child_delegation": policy or publication_policy(project),
        "idempotency_key": key}, enforce_readiness=True)
    return claim(service, PARENT, "claim-" + key)


def stage_task(service, p, policy, name, associations):
    stage = next(stage for stage in policy["stages"] if stage["name"] == name)
    refs = []
    for item in stage["inputs"]:
        association = associations[(item["producer_stage"], item["output_port"])]
        refs.append({"name": item["name"], "producer_task_id": association["task_id"],
                     "association_id": association["association_id"], "output_port": item["output_port"]})
    return {"capability_id": stage["capability_id"], "capability_digest": stage["capability_digest"],
            "stage": name, "input_refs": refs, "spec": {}}


def admit_stage(service, p, policy, name, associations, *, key=None, task=None):
    task = task or stage_task(service, p, policy, name, associations)
    return service.admit_delegated_child({"authority": authority(service, p)["authority"], "task": task},
                                       idempotency_key=key or "stage-" + name, identity=IDENTITY)


def publication_output(data, port):
    return {"name": port, "output_port": port, "kind": "object", "digest": digest(data),
            "data_base64": base64.b64encode(data).decode(), "size": len(data),
            "media_type": "application/json" if port in {"verification", "manifest", "final_receipt"} else "video/mp4",
            "group_key": "main", "variant_key": "original", "ordinal": 0}


def stage_settlement(service, attempt, data, port):
    body = {**lease(attempt), "outputs": [publication_output(data, port)]}
    if attempt.get("expected_effect"):
        body["effect"] = attempt["expected_effect"]
    return body


def publication_journey(runtime, *, through="final"):
    service, project = runtime
    policy = publication_policy(project)
    p = publication_parent(runtime, policy=policy)
    attempts, associations, bodies = {}, {}, {}
    values = [("raw", b"raw-generation-video", "raw_video"),
              ("compose", b"composed-candidate-video", "candidate"),
              ("verify", b'{"candidate_verified":true}', "verification"),
              ("final", b"composed-candidate-video", "verified_candidate")]
    for name, data, port in values:
        admitted = admit_stage(service, p, policy, name, associations)
        attempt = claim(service, admitted["task"]["capability"], "claim-stage-" + name)
        attempts[name] = attempt
        body = stage_settlement(service, attempt, data, port)
        if name in {"raw", "final"}:
            # Native H3 finalization also emits the existing result manifest.
            manifest = publication_output(b'{"outputs":[]}', "manifest")
            manifest["role"] = "manifest"
            body["outputs"].insert(0, manifest)
        bodies[name] = body
        service.settle_attempt(attempt["attempt_id"], body, idempotency_key="settle-stage-" + name, identity=IDENTITY)
        associations[(name, port)] = next(item for item in service.managed_outputs(attempt["task_id"]) if item["output_port"] == port)
        if name == through:
            break
    return p, policy, attempts, associations, bodies


def test_named_publications_preserve_distinct_raw_final_and_parent_result(runtime):
    service, project = runtime
    p, policy, attempts, associations, bodies = publication_journey(runtime)
    raw = associations[("raw", "raw_video")]
    candidate = associations[("compose", "candidate")]
    verification = associations[("verify", "verification")]
    final = associations[("final", "verified_candidate")]
    assert raw["object_id"] != candidate["object_id"] == final["object_id"]
    assert raw["association_id"] != final["association_id"]
    assert raw["generation_id"] != final["generation_id"]
    assert raw["generation_id"] and final["generation_id"]
    for publication in (raw, final):
        outputs = service.managed_outputs(publication["task_id"])
        assert {item["output_port"] for item in outputs} == {publication["output_port"], "manifest"}
        manifest = next(item for item in outputs if item["output_port"] == "manifest")
        assert "delegated_publication" not in manifest["provenance"]
        assert publication["manifest_ref"] == manifest["object_id"]
    binding = final["provenance"]["delegated_publication"]
    assert binding["name"] == "final" and binding["parent_attempt_id"] == p["attempt_id"]
    assert binding["candidate"]["association_id"] == candidate["association_id"]
    assert binding["verification"]["association_id"] == verification["association_id"]
    assert binding["raw"]["association_id"] == raw["association_id"]
    assert binding["raw_publication"] == service.task(raw["task_id"])["task"]["result"]["generation_publish_v1"]
    for item in (raw, final):
        assert service.get_generation(item["generation_id"])["source_task_id"] == item["task_id"]
        published = service.task(item["task_id"])["task"]["result"]["generation_publish_v1"]["publications"][0]["variants"][0]
        assert service.get_variant(published["variant_id"])["generation_id"] == item["generation_id"]
    final_effect = service.task(final["task_id"])["task"]["expected_effect"]
    h3_binding = final_effect["payload"]["metadata"]["h3_av"]
    raw_variant = binding["raw_publication"]["publications"][0]["variants"][0]
    assert h3_binding == {
        "request_digest": digest("sealed-h3-request"), "publication_scope": "final_composition",
        "candidate_sha256": candidate["object_id"].removeprefix("sha256:"),
        "raw_sha256": raw["object_id"].removeprefix("sha256:"),
        "raw_generation_id": raw["generation_id"], "raw_variant_id": raw_variant["variant_id"],
        "raw_association_id": raw["association_id"], "raw_group_key": raw["group_key"],
        "raw_variant_key": raw["variant_key"], "raw_output_port": raw["output_port"],
    }
    assert service.get_generation(final["generation_id"])["metadata"]["h3_av"] == h3_binding
    for name, attempt in attempts.items():
        lineage = load_task_spec(service, attempt["task_id"])["delegated_parent"]
        assert lineage["parent_attempt_id"] == p["attempt_id"]
        assert lineage["parent_fence"] == p["fence"]
        assert lineage["project_id"] == project
    final_spec = load_task_spec(service, attempts["final"]["task_id"])
    assert {ref["association_id"] for ref in final_spec["delegated_inputs"]} == {
        candidate["association_id"], verification["association_id"]}
    # The parent uses the canonical output mechanism for its final video and receipt.
    receipt = json.dumps({"overall_status": "candidate_verified", "raw": raw["association_id"],
                          "final": final["association_id"]}).encode()
    result = {"overall_status": "candidate_verified"}
    settled = service.settle_attempt(p["attempt_id"], {**lease(p), "result": result,
        "outputs": [publication_output(b"composed-candidate-video", "verified_candidate"),
                    publication_output(receipt, "final_receipt")]}, idempotency_key="settle-publication-parent", identity=IDENTITY)
    task = service.task(p["task_id"])["task"]
    assert task["status"] == "completed" and task["result"]["overall_status"] == "candidate_verified"
    assert {item["output_port"] for item in service.managed_outputs(p["task_id"])} == {"verified_candidate", "final_receipt"}
    assert settled["data"]["state"] == "succeeded"
    parent_final = next(item for item in service.managed_outputs(p["task_id"]) if item["output_port"] == "verified_candidate")
    assert parent_final["provenance"]["delegated_publication"]["source_association_id"] == final["association_id"]
    assert parent_final["provenance"]["delegated_publication"]["raw"]["association_id"] == raw["association_id"]
    # Both existing managed publication associations survive a fresh reader.
    realm_root = service.store.root
    service.close()
    reader = RuntimeService(realm_root)
    try:
        assert reader.managed_output(raw["association_id"])["generation_id"] == raw["generation_id"]
        assert reader.managed_output(final["association_id"])["generation_id"] == final["generation_id"]
    finally:
        reader.close()


@pytest.mark.parametrize("field", ["candidate_stage", "candidate_output_port", "verify_stage", "verify_output_port", "output_port"])
def test_named_publication_policy_rejects_mismatched_relationships(runtime, field):
    service, project = runtime
    policy = publication_policy(project)
    policy["publications"]["final"][field] = "substitution"
    with pytest.raises((ValidationError, AuthorizationError)):
        publication_parent(runtime, policy=policy)
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["candidate_without_raw", "verify_without_candidate", "extra_final_input", "same_effect", "both_policy_forms", "partial_policy"])
def test_named_publication_policy_requires_exact_dependency_graph(runtime, mutation):
    _, project = runtime
    policy = publication_policy(project)
    if mutation == "candidate_without_raw":
        policy["stages"][1]["inputs"] = []
    elif mutation == "verify_without_candidate":
        policy["stages"][2]["inputs"] = []
    elif mutation == "extra_final_input":
        policy["stages"][-1]["inputs"].append({"name": "raw", "producer_stage": "raw", "output_port": "raw_video"})
    elif mutation == "same_effect":
        policy["publications"]["final"]["effect"] = copy.deepcopy(policy["publications"]["raw"]["effect"])
    elif mutation == "partial_policy":
        policy["publications"]["raw"]["effect"]["payload"]["partial_success_policy"] = "allow"
    else:
        policy["final_publication"] = {"stage": "final", "verify_stage": "verify", "verify_output_port": "verification", "effect": policy["publications"]["final"]["effect"]}
    with pytest.raises((ValidationError, AuthorizationError)):
        publication_parent(runtime, policy=policy)


@pytest.mark.parametrize("input_name", ["candidate", "verification"])
def test_named_final_rejects_substituted_managed_input(runtime, input_name):
    service, _ = runtime
    p, policy, attempts, associations, _ = publication_journey(runtime, through="verify")
    task = stage_task(service, p, policy, "final", associations)
    ref = next(item for item in task["input_refs"] if item["name"] == input_name)
    wrong = associations[("raw", "raw_video")]
    ref.update(producer_task_id=wrong["task_id"], association_id=wrong["association_id"])
    before = service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    with pytest.raises((AuthorizationError, ConflictError)):
        admit_stage(service, p, policy, "final", associations, task=task)
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before


def test_named_final_rejects_nested_path_and_caller_effect_authority(runtime):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    task = stage_task(service, p, policy, "final", associations)
    task["input_refs"][0]["path"] = "/caller/chosen/video.mp4"
    with pytest.raises(AuthorizationError):
        admit_stage(service, p, policy, "final", associations, task=task)
    task = stage_task(service, p, policy, "final", associations)
    task["settlement_effect"] = policy["publications"]["final"]["effect"]
    with pytest.raises(ValidationError):
        admit_stage(service, p, policy, "final", associations, task=task)
    task.pop("settlement_effect")
    task["spec"]["verified_publication_source"] = {"path": "/caller/chosen/video.mp4"}
    with pytest.raises(ValidationError):
        admit_stage(service, p, policy, "final", associations, task=task)


@pytest.mark.parametrize("replacement", [b"raw-generation-video", b"unrelated-video"])
def test_named_final_rejects_raw_or_unverified_output_bytes(runtime, replacement):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    admit_stage(service, p, policy, "final", associations)
    final = claim(service, CHILD, "claim-final-invalid")
    with pytest.raises(AuthorizationError):
        service.settle_attempt(final["attempt_id"], stage_settlement(service, final, replacement, "verified_candidate"),
                               idempotency_key="settle-final-invalid", identity=IDENTITY)
    assert not service.managed_outputs(final["task_id"])
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1


@pytest.mark.parametrize("field", ["fence", "lease_id", "runtime_epoch"])
def test_named_final_rejects_stale_fence_lease_epoch(runtime, field):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    admit_stage(service, p, policy, "final", associations)
    final = claim(service, CHILD, "claim-final-stale")
    body = stage_settlement(service, final, b"composed-candidate-video", "verified_candidate")
    body[field] = "stale" if field == "lease_id" else body[field] + (1 if field == "runtime_epoch" else -1)
    with pytest.raises((LeaseError, ConflictError)):
        service.settle_attempt(final["attempt_id"], body, idempotency_key="settle-final-stale", identity=IDENTITY)
    assert not service.managed_outputs(final["task_id"])


@pytest.mark.parametrize("publication_name", ["raw", "final"])
def test_named_publications_exact_replay_is_idempotent_and_new_replay_rejected(runtime, publication_name):
    service, _ = runtime
    p, policy, attempts, associations, bodies = publication_journey(runtime)
    final = attempts[publication_name]
    before = service.task(final["task_id"])
    service.settle_attempt(final["attempt_id"], bodies[publication_name], idempotency_key="settle-stage-" + publication_name, identity=IDENTITY)
    assert service.task(final["task_id"]) == before
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 2
    with pytest.raises(LeaseError):
        service.settle_attempt(final["attempt_id"], bodies[publication_name], idempotency_key="new-final-replay", identity=IDENTITY)
    changed = copy.deepcopy(bodies[publication_name])
    changed["result"] = {"forged": True}
    with pytest.raises(ConflictError):
        service.settle_attempt(final["attempt_id"], changed, idempotency_key="settle-stage-" + publication_name, identity=IDENTITY)
    with pytest.raises(ConflictError, match="already admitted"):
        admit_stage(service, p, policy, "final", associations, key="duplicate-final")


@pytest.mark.parametrize("result", [
    {"overall_status": "complete"},
    {"overall_status": "complete", "states": {"editorially_approved": {"status": "passed", "evidence": {"source": "review"}}}},
    {"overall_status": "complete", "states": {"editorially_approved": {"status": "passed", "evidence": {"source": "review"}},
        "cleanup_verified": {"status": "cleanup_pending", "evidence": {"resources": []}}}},
    {"overall_status": "complete", "states": {"editorially_approved": {"status": "passed", "evidence": {}},
        "cleanup_verified": {"status": "passed", "evidence": {"resources": ["fixture"]}}}},
    {"overall_status": "candidate_verified", "status": "task_failed"},
    {"overall_status": "complete", "states": {"editorially_approved": {"status": "passed", "evidence": {"source": "review"}},
        "cleanup_verified": {"status": "passed", "evidence": {"resources": []}}}},
    {"overall_status": "complete", "states": {"editorially_approved": {"status": "passed", "evidence": {"source": "review"}},
        "cleanup_verified": {"status": "passed", "evidence": {"resources": [{"verified": False}]}}}},
])
def test_named_parent_rejects_incomplete_complete_or_conflicting_outcomes(runtime, result):
    service, _ = runtime
    p, _, _, _, _ = publication_journey(runtime)
    with pytest.raises((ValidationError, AuthorizationError)):
        service.settle_attempt(p["attempt_id"], {**lease(p), "outputs": [publication_output(b"composed-candidate-video", "verified_candidate")], "result": result},
                               idempotency_key="invalid-outcome", identity=IDENTITY)
    assert service.task(p["task_id"])["task"]["status"] == "running"


def test_named_parent_complete_requires_native_editorial_cleanup_evidence(runtime):
    service, _ = runtime
    p, _, _, _, _ = publication_journey(runtime)
    result = {"overall_status": "complete", "states": {
        "editorially_approved": {"status": "passed", "evidence": {"source": "fixture-review"}},
        "cleanup_verified": {"status": "passed", "evidence": {"resources": [{"kind": "fixture", "verified": True}]}},
    }}
    service.settle_attempt(p["attempt_id"], {**lease(p), "outputs": [publication_output(b"composed-candidate-video", "verified_candidate")], "result": result},
                           idempotency_key="complete-outcome", identity=IDENTITY)
    assert service.task(p["task_id"])["task"]["result"]["overall_status"] == "complete"


def test_named_parent_task_failed_uses_existing_fenced_failure(runtime):
    service, _ = runtime
    p = publication_parent(runtime)
    with pytest.raises((ValidationError, AuthorizationError), match="fail_attempt"):
        service.settle_attempt(p["attempt_id"], {**lease(p), "outputs": [], "result": {"overall_status": "task_failed"}},
                               idempotency_key="cannot-succeed-failed", identity=IDENTITY)
    service.fail_attempt(p["attempt_id"], {**lease(p), "error": {"code": "h3_task_failed", "message": "H3 task_failed"}},
                         idempotency_key="fail-h3", identity=IDENTITY)
    assert service.task(p["task_id"])["task"]["status"] == "failed"


@pytest.mark.parametrize("corruption", ["raw_generation", "raw_result", "candidate_raw_input", "verification_candidate_input"])
def test_named_final_revalidates_actual_lineage_at_settlement(runtime, corruption):
    service, _ = runtime
    p, policy, attempts, associations, _ = publication_journey(runtime, through="verify")
    admit_stage(service, p, policy, "final", associations)
    final = claim(service, CHILD, "claim-final-corruption")
    raw = associations[("raw", "raw_video")]
    if corruption == "raw_generation":
        service.store.conn.execute("UPDATE managed_output_associations SET generation_id=NULL WHERE association_id=?", (raw["association_id"],))
    elif corruption == "raw_result":
        result = service.task(raw["task_id"])["task"]["result"]
        result["generation_publish_v1"]["publications"][0]["variants"][0]["variant_id"] = "foreign-variant"
        service.store.conn.execute("UPDATE tasks SET result_json=? WHERE id=?", (json.dumps(result), raw["task_id"]))
    else:
        task_id = attempts["compose" if corruption == "candidate_raw_input" else "verify"]["task_id"]
        spec = load_task_spec(service, task_id)
        spec["delegated_inputs"][0]["association_id"] = "foreign-association"
        store_task_spec(service, task_id, spec)
    with pytest.raises((AuthorizationError, ConflictError)):
        service.settle_attempt(final["attempt_id"], stage_settlement(service, final, b"composed-candidate-video", "verified_candidate"),
                               idempotency_key="settle-final-corrupt", identity=IDENTITY)
    assert not service.managed_outputs(final["task_id"])
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1


def test_named_final_is_fenced_when_parent_lease_expires(runtime):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    admit_stage(service, p, policy, "final", associations)
    final = claim(service, CHILD, "claim-final-parent-stale")
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, p["attempt_id"]))
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, p["task_id"]))
    with pytest.raises((LeaseError, AuthorizationError)):
        service.settle_attempt(final["attempt_id"], stage_settlement(service, final, b"composed-candidate-video", "verified_candidate"),
                               idempotency_key="settle-expired-parent", identity=IDENTITY)
    assert not service.managed_outputs(final["task_id"])


def test_legacy_single_verified_publication_still_settles(runtime):
    service, project = runtime
    policy = publication_policy(project)
    policy.pop("publications")
    policy["stages"] = [
        {"name": "verify", "capability_id": OTHER, "capability_digest": digest(OTHER), "target": {"kind": "default"}, "inputs": []},
        {"name": "final", "capability_id": CHILD, "capability_digest": digest(CHILD), "target": {"kind": "default"},
         "inputs": [{"name": "verified", "producer_stage": "verify", "output_port": "video"}]},
    ]
    policy["final_publication"] = {"stage": "final", "verify_stage": "verify", "verify_output_port": "video", "effect": publication_effect(project, "video")}
    p = publication_parent(runtime, policy=policy)
    associations = {}
    for name, cap in (("verify", OTHER), ("final", CHILD)):
        admit_stage(service, p, policy, name, associations)
        attempt = claim(service, cap, "claim-legacy-" + name)
        service.settle_attempt(attempt["attempt_id"], stage_settlement(service, attempt, b"verified-legacy-video", "video"),
                               idempotency_key="settle-legacy-" + name, identity=IDENTITY)
        associations[(name, "video")] = service.managed_outputs(attempt["task_id"])[0]
    settle(service, p, "legacy-parent")
    assert service.task(p["task_id"])["task"]["status"] == "completed"
    assert associations[("final", "video")]["generation_id"]


@pytest.mark.parametrize("field", ["fence", "lease_id", "runtime_epoch"])
def test_named_raw_publication_is_fenced_before_mutation(runtime, field):
    service, project = runtime
    policy = publication_policy(project)
    p = publication_parent(runtime, policy=policy)
    admit_stage(service, p, policy, "raw", {})
    raw = claim(service, CHILD, "claim-raw-stale")
    body = stage_settlement(service, raw, b"raw-generation-video", "raw_video")
    body[field] = "stale" if field == "lease_id" else body[field] + 1
    with pytest.raises((LeaseError, ConflictError)):
        service.settle_attempt(raw["attempt_id"], body, idempotency_key="stale-raw", identity=IDENTITY)
    assert not service.managed_outputs(raw["task_id"])
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["effect", "provenance"])
def test_named_publication_rejects_caller_effect_and_provenance_substitution(runtime, mutation):
    service, project = runtime
    policy = publication_policy(project)
    p = publication_parent(runtime, policy=policy)
    admit_stage(service, p, policy, "raw", {})
    raw = claim(service, CHILD, "claim-raw-substitution")
    body = stage_settlement(service, raw, b"raw-generation-video", "raw_video")
    if mutation == "effect":
        body["effect"] = policy["publications"]["final"]["effect"]
    else:
        body["outputs"][0]["provenance"] = {"delegated_publication": {"name": "final", "raw": {"association_id": "foreign"}}}
    with pytest.raises((ValidationError, AuthorizationError)):
        service.settle_attempt(raw["attempt_id"], body, idempotency_key="caller-substitution", identity=IDENTITY)
    assert not service.managed_outputs(raw["task_id"])


def test_named_parent_cannot_expose_raw_as_verified_final(runtime):
    service, _ = runtime
    p, _, _, _, _ = publication_journey(runtime)
    with pytest.raises(AuthorizationError):
        service.settle_attempt(p["attempt_id"], {**lease(p), "result": {"overall_status": "candidate_verified"},
            "outputs": [publication_output(b"raw-generation-video", "verified_candidate")]},
            idempotency_key="parent-raw-substitution", identity=IDENTITY)
    assert not service.managed_outputs(p["task_id"])


@pytest.mark.parametrize("input_name", ["candidate", "verification"])
def test_named_final_rejects_same_bytes_same_port_from_foreign_task(runtime, input_name):
    service, project = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    foreign = service.create_task({"project": project, "capability_id": OTHER, "capability_digest": digest(OTHER),
                                   "idempotency_key": "foreign-producer"})
    foreign_attempt = claim(service, OTHER, "claim-foreign-producer")
    value = b"composed-candidate-video" if input_name == "candidate" else b'{"candidate_verified":true}'
    settle(service, foreign_attempt, "settle-foreign-producer", [publication_output(value, input_name)])
    wrong = service.managed_outputs(foreign["task"]["id"])[0]
    task = stage_task(service, p, policy, "final", associations)
    ref = next(ref for ref in task["input_refs"] if ref["name"] == input_name)
    ref.update(producer_task_id=wrong["task_id"], association_id=wrong["association_id"])
    with pytest.raises((AuthorizationError, ConflictError)):
        admit_stage(service, p, policy, "final", associations, task=task)


@pytest.mark.parametrize("corruption", ["raw_publication", "final_binding"])
def test_named_parent_revalidates_final_and_raw_before_association(runtime, corruption):
    service, _ = runtime
    p, _, _, associations, _ = publication_journey(runtime)
    if corruption == "raw_publication":
        raw = associations[("raw", "raw_video")]
        service.store.conn.execute("UPDATE managed_output_associations SET generation_id=NULL WHERE association_id=?", (raw["association_id"],))
    else:
        final = associations[("final", "verified_candidate")]
        provenance = copy.deepcopy(final["provenance"])
        provenance["delegated_publication"]["parent_attempt_id"] = "foreign-parent"
        service.store.conn.execute("UPDATE managed_output_associations SET provenance_json=? WHERE association_id=?", (json.dumps(provenance), final["association_id"]))
    with pytest.raises((AuthorizationError, ConflictError)):
        service.settle_attempt(p["attempt_id"], {**lease(p), "result": {"overall_status": "candidate_verified"},
            "outputs": [publication_output(b"composed-candidate-video", "verified_candidate")]},
            idempotency_key="parent-corrupt-final", identity=IDENTITY)
    assert not service.managed_outputs(p["task_id"])


def test_named_publication_accepts_raw_as_candidate_with_distinct_final_association(runtime):
    service, project = runtime
    policy = publication_policy(project)
    policy["stages"].pop(1)
    for stage in policy["stages"]:
        for ref in stage["inputs"]:
            if ref["producer_stage"] == "compose":
                ref.update(producer_stage="raw", output_port="raw_video")
    policy["publications"]["final"].update(candidate_stage="raw", candidate_output_port="raw_video")
    p = publication_parent(runtime, policy=policy)
    associations = {}
    for name, cap, data, port in (("raw", CHILD, b"same-candidate-video", "raw_video"),
                                 ("verify", OTHER, b'{"verified":true}', "verification"),
                                 ("final", CHILD, b"same-candidate-video", "verified_candidate")):
        admit_stage(service, p, policy, name, associations)
        attempt = claim(service, cap, "claim-direct-candidate-" + name)
        service.settle_attempt(attempt["attempt_id"], stage_settlement(service, attempt, data, port),
                               idempotency_key="settle-direct-candidate-" + name, identity=IDENTITY)
        associations[(name, port)] = service.managed_outputs(attempt["task_id"])[0]
    raw, final = associations[("raw", "raw_video")], associations[("final", "verified_candidate")]
    assert raw["object_id"] == final["object_id"]
    assert raw["association_id"] != final["association_id"] and raw["generation_id"] != final["generation_id"]


@pytest.mark.parametrize("field", ["candidate_sha256", "raw_association_id"])
def test_named_final_rejects_effect_metadata_substitution(runtime, field):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    admit_stage(service, p, policy, "final", associations)
    final = claim(service, CHILD, "claim-final-effect-substitution")
    body = stage_settlement(service, final, b"composed-candidate-video", "verified_candidate")
    body["effect"] = copy.deepcopy(body["effect"])
    body["effect"]["payload"]["metadata"]["h3_av"][field] = "foreign-lineage"
    with pytest.raises(ValidationError, match="predeclared"):
        service.settle_attempt(final["attempt_id"], body, idempotency_key="final-effect-substitution", identity=IDENTITY)
    assert not service.managed_outputs(final["task_id"])


def test_named_selector_tracks_video_with_same_port_auxiliary_audio(runtime):
    service, project = runtime
    policy = publication_policy(project)
    p = publication_parent(runtime, policy=policy)
    associations = {}
    for name, data, port in (("raw", b"raw-video", "raw_video"),
                             ("compose", b"candidate-video", "candidate"),
                             ("verify", b'{"verified":true}', "verification"),
                             ("final", b"candidate-video", "verified_candidate")):
        admit_stage(service, p, policy, name, associations)
        attempt = claim(service, CHILD if name != "verify" else OTHER, "selector-claim-" + name)
        body = stage_settlement(service, attempt, data, port)
        if name in {"raw", "final"}:
            audio = publication_output(("audio-" + name).encode(), port)
            audio.update(media_type="audio/wav", variant_key="auxiliary", ordinal=1)
            body["outputs"].insert(0, audio)
        service.settle_attempt(attempt["attempt_id"], body, idempotency_key="selector-settle-" + name, identity=IDENTITY)
        outputs = service.managed_outputs(attempt["task_id"])
        association = next(item for item in outputs if item["variant_key"] == "original")
        associations[(name, port)] = association
        if name in {"raw", "final"}:
            audio = next(item for item in outputs if item["variant_key"] == "auxiliary")
            assert audio["generation_id"] is None
            assert "delegated_publication" not in audio["provenance"]
            assert association["provenance"]["delegated_publication"]["name"] == name
    raw = associations[("raw", "raw_video")]
    final = associations[("final", "verified_candidate")]
    assert final["provenance"]["delegated_publication"]["raw"]["association_id"] == raw["association_id"]
    service.settle_attempt(p["attempt_id"], {**lease(p), "result": {"overall_status": "candidate_verified"},
        "outputs": [publication_output(b"candidate-video", "verified_candidate")]},
        idempotency_key="selector-settle-parent", identity=IDENTITY)
    parent_output = service.managed_outputs(p["task_id"])[0]
    assert parent_output["provenance"]["delegated_publication"]["source_association_id"] == final["association_id"]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "temporary"])
def test_named_selector_rejects_invalid_selected_settlement(runtime, mutation):
    service, project = runtime
    policy = publication_policy(project)
    p = publication_parent(runtime, policy=policy)
    admit_stage(service, p, policy, "raw", {})
    raw = claim(service, CHILD, "selector-invalid-claim")
    body = stage_settlement(service, raw, b"raw-video", "raw_video")
    if mutation == "missing":
        body["outputs"][0]["variant_key"] = "other"
    elif mutation == "duplicate":
        body["outputs"].append(copy.deepcopy(body["outputs"][0]))
    else:
        body["outputs"][0]["durability"] = "temporary"
    with pytest.raises((ConflictError, AuthorizationError, ValidationError)):
        service.settle_attempt(raw["attempt_id"], body, idempotency_key="selector-invalid", identity=IDENTITY)
    assert not service.managed_outputs(raw["task_id"])
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0


def test_named_selector_rejects_compose_using_same_port_auxiliary(runtime):
    service, project = runtime
    policy = publication_policy(project)
    p = publication_parent(runtime, policy=policy)
    admit_stage(service, p, policy, "raw", {})
    attempt = claim(service, CHILD, "selector-raw-claim")
    body = stage_settlement(service, attempt, b"raw-video", "raw_video")
    auxiliary = publication_output(b"raw-audio", "raw_video")
    auxiliary.update(media_type="audio/wav", variant_key="auxiliary", ordinal=1)
    body["outputs"].append(auxiliary)
    service.settle_attempt(attempt["attempt_id"], body, idempotency_key="selector-raw", identity=IDENTITY)
    wrong = next(item for item in service.managed_outputs(attempt["task_id"]) if item["variant_key"] == "auxiliary")
    refs = {("raw", "raw_video"): wrong}
    with pytest.raises(AuthorizationError, match="selected raw"):
        admit_stage(service, p, policy, "compose", refs)
    assert len(service.store.delegated_children(p["task_id"], p["attempt_id"])) == 1


@pytest.mark.parametrize("include_selected", [True, False])
def test_named_compose_allows_same_port_auxiliary_only_with_selected_video(runtime, include_selected):
    service, project = runtime
    policy = publication_policy(project)
    policy["stages"][1]["inputs"].append({"name": "audio", "producer_stage": "raw", "output_port": "raw_video"})
    p = publication_parent(runtime, policy=policy)
    admit_stage(service, p, policy, "raw", {})
    attempt = claim(service, CHILD, "selector-pair-claim")
    body = stage_settlement(service, attempt, b"raw-video", "raw_video")
    audio = publication_output(b"raw-audio", "raw_video")
    audio.update(media_type="audio/wav", variant_key="auxiliary", ordinal=1)
    body["outputs"].append(audio)
    other = publication_output(b"other-audio", "raw_video")
    other.update(media_type="audio/wav", variant_key="other", ordinal=2)
    body["outputs"].append(other)
    service.settle_attempt(attempt["attempt_id"], body, idempotency_key="selector-pair", identity=IDENTITY)
    outputs = service.managed_outputs(attempt["task_id"])
    selected = next(item for item in outputs if item["variant_key"] == "original")
    auxiliary = next(item for item in outputs if item["variant_key"] == "auxiliary")
    other = next(item for item in outputs if item["variant_key"] == "other")
    task = stage_task(service, p, policy, "compose", {("raw", "raw_video"): selected})
    task["input_refs"][1]["association_id"] = auxiliary["association_id"]
    if not include_selected:
        task["input_refs"][0]["association_id"] = other["association_id"]
        with pytest.raises(AuthorizationError, match="selected raw"):
            admit_stage(service, p, policy, "compose", {}, task=task)
    else:
        admitted = admit_stage(service, p, policy, "compose", {}, task=task)
        recorded = load_task_spec(service, admitted["task"]["id"])["delegated_inputs"]
        assert [ref["association_id"] for ref in recorded] == [selected["association_id"], auxiliary["association_id"]]


def test_named_final_rejects_raw_selector_drift_after_admission(runtime):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="verify")
    admit_stage(service, p, policy, "final", associations)
    final = claim(service, CHILD, "selector-drift-final")
    raw = associations[("raw", "raw_video")]
    service.store.conn.execute("UPDATE managed_output_associations SET variant_key=? WHERE association_id=?",
                               ("drifted", raw["association_id"]))
    with pytest.raises(ConflictError, match="selector"):
        service.settle_attempt(final["attempt_id"], stage_settlement(service, final, b"composed-candidate-video", "verified_candidate"),
                               idempotency_key="selector-drift", identity=IDENTITY)
    assert not service.managed_outputs(final["task_id"])


@pytest.mark.parametrize("corruption", ["wrong_attempt", "stale"])
def test_named_compose_rejects_unusable_selected_raw_association(runtime, corruption):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="raw")
    raw = associations[("raw", "raw_video")]
    if corruption == "wrong_attempt":
        service.store.conn.execute("UPDATE managed_output_associations SET attempt_id=? WHERE association_id=?",
                                   (p["attempt_id"], raw["association_id"]))
    else:
        service.store.conn.execute("UPDATE managed_output_lifecycle SET state='reclaimed' WHERE association_id=?",
                                   (raw["association_id"],))
    with pytest.raises((AuthorizationError, ConflictError)):
        admit_stage(service, p, policy, "compose", associations)
    assert len(service.store.delegated_children(p["task_id"], p["attempt_id"])) == 1


@pytest.mark.parametrize("corruption", ["selector", "wrong_attempt", "stale", "omission", "substitution"])
def test_named_compose_revalidates_selected_raw_at_settlement(runtime, corruption):
    service, _ = runtime
    p, policy, _, associations, _ = publication_journey(runtime, through="raw")
    admitted = admit_stage(service, p, policy, "compose", associations)
    attempt = claim(service, CHILD, "compose-revalidate-claim")
    body = stage_settlement(service, attempt, b"candidate", "candidate_video")
    raw = associations[("raw", "raw_video")]
    if corruption == "selector":
        service.store.conn.execute("UPDATE managed_output_associations SET variant_key='substituted' WHERE association_id=?", (raw["association_id"],))
    elif corruption == "wrong_attempt":
        service.store.conn.execute("UPDATE managed_output_associations SET attempt_id=? WHERE association_id=?", (p["attempt_id"], raw["association_id"]))
    elif corruption == "stale":
        service.store.conn.execute("UPDATE managed_output_lifecycle SET state='reclaimed' WHERE association_id=?", (raw["association_id"],))
    else:
        spec = load_task_spec(service, admitted["task"]["id"])
        if corruption == "omission":
            spec["delegated_inputs"] = []
        else:
            spec["delegated_inputs"][0]["association_id"] = "substituted-association"
        store_task_spec(service, admitted["task"]["id"], spec)
    with pytest.raises((AuthorizationError, ConflictError)):
        service.settle_attempt(attempt["attempt_id"], body, idempotency_key="compose-revalidate", identity=IDENTITY)
    assert not service.managed_outputs(attempt["task_id"])
