"""Exact authenticated delegated claims never select a sibling or queue fallback.

Only pytest-owned realms and ephemeral bearer credentials are used. Service
negatives corrupt one persisted/input invariant at a time; the real generated
client/HTTP case proves this same boundary and replay rejection over transport.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, NotFoundError, ValidationError
from runtime_protocol.local_execution_handoff import FENCE_VERSION, write_protected
from runtime_protocol.store import MAX_TASK_ATTEMPTS, RealmStore
from tests.test_runtime_child_delegation import (
    CHILD, IDENTITY, PARENT, TARGET, authority, digest, lease, load_task_spec,
    parent, runtime, store_task_spec,
)

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from astrid_runtime_client import ApiError, WorkspaceClient

DEFAULT = {"kind": "default"}
REJECTED = (AuthorizationError, ConflictError, LeaseError, NotFoundError, ValidationError)


def _case(runtime, *, targeted=False, target=DEFAULT, exact_authority=False, managed_input=False):
    service, project = runtime
    attempt = parent(runtime, targeted=targeted)
    queued = service.create_task({
        "project": project, "capability_id": CHILD, "capability_digest": digest(CHILD),
        "input_object_ids": [], "spec": {}, "idempotency_key": "unrelated-before-child",
    }, enforce_readiness=True)["task"]["id"]
    receipt = authority(service, attempt, refs=[] if exact_authority else None, key="chosen-child")
    task = {"capability_id": CHILD, "capability_digest": digest(CHILD), "spec": {},
            "execution_request": {"schema_version": 1, "target": target, "inputs": []}}
    if managed_input:
        from tests.test_runtime_child_delegation import upload
        descriptor = upload(service, attempt)
        receipt = authority(service, attempt, refs=[descriptor], key="chosen-child")
        ref = receipt["derived_inputs"][0]
        task["input_object_ids"] = [ref["object_id"]]
        task["execution_request"]["inputs"] = [{
            "name": ref["name"], "object_id": ref["object_id"], "filename": ref["filename"],
            "digest": ref["object_id"],
        }]
    else:
        task["input_object_ids"] = []
    general = authority(service, attempt)
    sibling = service.admit_delegated_child({"authority": general["authority"], "task": {
        "capability_id": CHILD, "capability_digest": digest(CHILD), "input_object_ids": [],
        "spec": {}, "execution_request": {"schema_version": 1, "target": target},
    }}, idempotency_key="sibling-before-child", identity=IDENTITY)["task"]["id"]
    child = service.admit_delegated_child({"authority": receipt["authority"], "task": task},
        idempotency_key="chosen-child", identity=IDENTITY)["task"]["id"]
    body = {"executor_id": "worker", "capability_ids": [CHILD],
            "runtime_epoch": service.health()["runtime_epoch"], "target": target,
            "authority": receipt["authority"]}
    return attempt, child, body, (queued, sibling)


def _claim(service, child, body, *, identity=IDENTITY, key="exact-claim"):
    return service.claim_delegated_child(child, body, idempotency_key=key, identity=identity)


def _unclaimed(service, *task_ids):
    for task_id in task_ids:
        row = service.store.conn.execute("SELECT status, attempt FROM tasks WHERE id=?", (task_id,)).fetchone()
        assert row["status"] == "queued" and row["attempt"] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,)).fetchone()[0] == 0


def _no_claim_receipt(service):
    for ledger in ("command_idempotency", "session_command_replay"):
        assert service.store.conn.execute(f"SELECT COUNT(*) FROM {ledger} WHERE command_kind='task.claim_delegated_child'").fetchone()[0] == 0


@pytest.mark.parametrize("targeted", [False, True], ids=["untargeted-parent", "targeted-parent"])
@pytest.mark.parametrize("target", [DEFAULT, TARGET], ids=["explicit-default", "exact-machine"])
@pytest.mark.parametrize("managed_input", [False, True], ids=["scalar", "managed-input"])
def test_claims_only_named_child_and_replays_one_live_attempt(runtime, targeted, target, managed_input):
    service, _ = runtime
    _, child, body, others = _case(runtime, targeted=targeted, target=target, managed_input=managed_input)
    admitted = service._task_resource(service.store.get_task(child))
    result = _claim(service, child, body)
    assert result["task_id"] == child
    assert result["execution_request"] == admitted["execution_request"]
    assert result["spec"] == admitted["spec"]
    assert result["input_object_ids"] == admitted["spec"]["input_object_ids"]
    binding = result["execution_binding"]
    assert binding["actual_target"] == TARGET and binding["resolved_target"] == target
    assert binding["verification"] == IDENTITY["execution_binding"]["verification"]
    assert binding["attempt_id"] == result["attempt_id"]
    assert _claim(service, child, body) == result
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (child,)).fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM session_command_replay WHERE command_kind='task.claim_delegated_child'").fetchone()[0] == 1
    assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency WHERE command_kind='task.claim_delegated_child'").fetchone()[0] == 0
    _unclaimed(service, *others)


@pytest.mark.parametrize("selection", ["missing", "unrelated", "sibling-bound-to-other-child"])
def test_missing_foreign_or_receipt_bound_child_does_not_fall_through(runtime, selection):
    service, _ = runtime
    _, child, body, others = _case(runtime, exact_authority=True)
    selected = {"missing": "missing-child", "unrelated": others[0], "sibling-bound-to-other-child": others[1]}[selection]
    with pytest.raises(REJECTED):
        _claim(service, selected, body)
    _unclaimed(service, child, *others)
    _no_claim_receipt(service)


@pytest.mark.parametrize("field", ["authority", "target", "executor_id", "runtime_epoch", "capability_ids"])
@pytest.mark.parametrize("malformed", ["missing", "null"])
def test_requires_every_exact_claim_field(runtime, field, malformed):
    service, _ = runtime
    _, child, body, others = _case(runtime)
    if malformed == "missing":
        body.pop(field)
    else:
        body[field] = None
    with pytest.raises(REJECTED):
        _claim(service, child, body)
    _unclaimed(service, child, *others)
    _no_claim_receipt(service)


@pytest.mark.parametrize("field", [
    "parent_task_id", "parent_attempt_id", "parent_lease_id", "parent_fence", "runtime_epoch",
    "executor_id", "project_id", "policy_digest", "parent_placement", "parent_effective_target",
    "parent_placement_version",
])
def test_rejects_every_foreign_stored_lineage_component(runtime, field):
    service, _ = runtime
    _, child, body, others = _case(runtime)
    spec = load_task_spec(service, child)
    value = spec["delegated_parent"][field]
    spec["delegated_parent"][field] = value + 1 if type(value) is int else "foreign"
    store_task_spec(service, child, spec)
    with pytest.raises(AuthorizationError, match="lineage"):
        _claim(service, child, body)
    _unclaimed(service, child, *others)
    _no_claim_receipt(service)


@pytest.mark.parametrize("mutation", [
    "child-project", "parent-project", "child-capability", "actor", "admin-actor", "executor",
    "missing-placement", "machine", "incarnation", "unverified", "non-machine", "target",
    "epoch", "fence", "lease", "expired-parent", "missing-parent-deadline", "parent-deadline-mismatch",
    "revoked", "cancelled-parent", "changed-policy", "parent-binding-missing", "parent-binding-fence",
    "parent-binding-machine", "authority-signature",
])
def test_authority_executor_machine_target_and_parent_rejections_are_atomic(runtime, mutation):
    service, _ = runtime
    p, child, body, others = _case(runtime, targeted=mutation.startswith("parent-binding"))
    identity = copy.deepcopy(IDENTITY)
    if mutation in {"child-project", "parent-project"}:
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
        task_id = child if mutation == "child-project" else p["task_id"]
        service.store.conn.execute("UPDATE runs SET project_id=? WHERE id=(SELECT run_id FROM tasks WHERE id=?)", (foreign, task_id))
    elif mutation == "child-capability":
        service.store.conn.execute("UPDATE tasks SET capability='foreign' WHERE id=?", (child,))
    elif mutation in {"actor", "admin-actor"}:
        identity["actor"] = "foreign"
        if mutation == "admin-actor": identity["scopes"].append("admin")
    elif mutation == "executor": body["executor_id"] = "foreign"
    elif mutation == "missing-placement": identity.pop("execution_binding")
    elif mutation == "machine": identity["execution_binding"]["actual"] = {"kind": "machine", "id": "foreign"}
    elif mutation == "incarnation": identity["execution_binding"]["executor_incarnation"] = "foreign"
    elif mutation == "unverified": identity["execution_binding"]["verification"]["verified"] = False
    elif mutation == "non-machine": identity["execution_binding"]["actual"] = {"kind": "default"}
    elif mutation == "target": body["target"] = {"kind": "machine", "id": "foreign"}
    elif mutation == "epoch": body["runtime_epoch"] += 1
    elif mutation == "fence": service.store.conn.execute("UPDATE attempts SET fence=fence+1 WHERE id=?", (p["attempt_id"],))
    elif mutation == "lease": service.store.conn.execute("UPDATE attempts SET lease_id='foreign' WHERE id=?", (p["attempt_id"],))
    elif mutation == "expired-parent": service.store.conn.execute("UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (p["attempt_id"],))
    elif mutation == "missing-parent-deadline": service.store.conn.execute("UPDATE attempts SET lease_expires_at=NULL WHERE id=?", (p["attempt_id"],))
    elif mutation == "parent-deadline-mismatch": service.store.conn.execute("UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (p["task_id"],))
    elif mutation == "cancelled-parent": service.store.conn.execute("UPDATE tasks SET status='cancelled' WHERE id=?", (p["task_id"],))
    elif mutation in {"revoked", "changed-policy"}:
        spec = load_task_spec(service, p["task_id"])
        if mutation == "revoked": spec["delegation_closed_attempt_id"] = p["attempt_id"]
        else: spec["child_delegation"]["limits"]["max_children"] += 1
        store_task_spec(service, p["task_id"], spec)
    elif mutation == "parent-binding-missing": service.store.conn.execute("DELETE FROM execution_bindings WHERE task_id=?", (p["task_id"],))
    elif mutation == "parent-binding-fence": service.store.conn.execute("UPDATE execution_bindings SET fence=fence+1 WHERE task_id=?", (p["task_id"],))
    elif mutation == "parent-binding-machine":
        value = json.loads(service.store.conn.execute("SELECT resolved_target_json FROM execution_bindings WHERE task_id=?", (p["task_id"],)).fetchone()[0])
        value["actual"] = {"kind": "machine", "id": "foreign"}
        service.store.conn.execute("UPDATE execution_bindings SET resolved_target_json=? WHERE task_id=?", (json.dumps(value), p["task_id"]))
    elif mutation == "authority-signature": body["authority"] += "bad"
    with pytest.raises(REJECTED):
        _claim(service, child, body, identity=identity)
    _unclaimed(service, child, *others)
    _no_claim_receipt(service)


@pytest.mark.parametrize("mutation,reason", [
    ("executor-readiness", "waiting_for_worker"), ("capability-readiness", "capability_unavailable"),
    ("capability-digest", "capability_unavailable"), ("missing-advertisement", "waiting_for_worker"),
    ("executor-expired", "waiting_for_worker"), ("concurrency", "waiting_for_worker"),
    ("missing-resource", "waiting_for_cpu"), ("reserved-resource", "waiting_for_cpu"),
    ("storage", "insufficient_storage"), ("facts", "waiting_for_executor_facts"),
])
def test_exact_claim_reuses_store_preflight_and_rolls_back_waiting(runtime, monkeypatch, mutation, reason):
    service, _ = runtime
    p, child, body, others = _case(runtime)
    if mutation == "executor-readiness": service.store.conn.execute("UPDATE executors SET readiness='not_ready' WHERE id='worker'")
    elif mutation == "capability-readiness": service.store.conn.execute("UPDATE capabilities SET status='unavailable' WHERE id=?", (CHILD,))
    elif mutation == "capability-digest": service.store.conn.execute("UPDATE capabilities SET definition_digest=? WHERE id=?", (digest("foreign"), CHILD))
    elif mutation == "missing-advertisement": service.store.conn.execute("UPDATE executors SET capabilities_json='[]' WHERE id='worker'")
    elif mutation == "executor-expired": service.store.conn.execute("UPDATE executors SET last_seen_at='2000-01-01T00:00:00+00:00' WHERE id='worker'")
    elif mutation == "concurrency": service.store.conn.execute("UPDATE executors SET max_concurrency=1 WHERE id='worker'")
    elif mutation in {"missing-resource", "reserved-resource"}:
        service.store.conn.execute("UPDATE capabilities SET required_resource_keys_json='[\"cpu\"]' WHERE id=?", (CHILD,))
        if mutation == "reserved-resource":
            service.store.conn.execute("UPDATE executors SET resource_keys_json='[\"cpu\"]' WHERE id='worker'")
            service.store.conn.execute("INSERT INTO reservations(task_id, resource_key, lease_token, created_at, executor_id, fence, lease_expires_at, runtime_epoch) VALUES (?, 'cpu', ?, ?, 'worker', ?, ?, ?)", (p["task_id"], p["lease_id"], p["lease_expires_at"], p["fence"], p["lease_expires_at"], p["runtime_epoch"]))
    elif mutation == "storage": monkeypatch.setattr(service.store, "storage_preflight", lambda *a, **kw: {"ok": False})
    elif mutation == "facts":
        spec = load_task_spec(service, child); spec["required_facts"] = {"exact": {"driver": "required"}, "minimum": {}}
        store_task_spec(service, child, spec)
    before = service.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    with pytest.raises(ConflictError, match="preflight") as error:
        _claim(service, child, body)
    assert error.value.details["waiting_reason"] == reason
    assert service.store.conn.execute("SELECT waiting_reason FROM tasks WHERE id=?", (child,)).fetchone()[0] is None
    assert service.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
    _unclaimed(service, child, *others)
    _no_claim_receipt(service)


@pytest.mark.parametrize("mutation", ["provider-unknown", "runtime-recovery", "retry-limit", "absolute-deadline", "binding-stale", "recovery-qualification", "child-count", "active-child-count"])
def test_recovery_lifetime_retry_and_parent_capacity_fail_closed(runtime, mutation):
    service, _ = runtime
    p, child, body, others = _case(runtime)
    if mutation in {"provider-unknown", "runtime-recovery"}:
        reason = "provider_state_unknown" if mutation == "provider-unknown" else "runtime_recovery"
        service.store.conn.execute("UPDATE tasks SET waiting_reason=? WHERE id=?", (reason, child))
    elif mutation == "retry-limit": service.store.conn.execute("UPDATE tasks SET attempt=? WHERE id=?", (MAX_TASK_ATTEMPTS, child))
    elif mutation == "absolute-deadline": service.store.conn.execute("UPDATE runs SET created_at='2000-01-01T00:00:00+00:00' WHERE id=(SELECT run_id FROM tasks WHERE id=?)", (child,))
    elif mutation == "binding-stale": service.store.conn.execute("UPDATE execution_bindings SET status='stale' WHERE task_id=?", (child,))
    elif mutation == "recovery-qualification":
        decision = {"replacement_target": DEFAULT, "placement_version": 1, "decision_digest": digest("decision"), "qualification": {"evidence_digest": digest("foreign"), "executor_incarnation": "foreign"}}
        service.store._append_event(service.store.get_task(child)["run"]["id"], child, "task.placement_recovered", decision)
    elif mutation in {"child-count", "active-child-count"}:
        spec = load_task_spec(service, p["task_id"])
        spec["child_delegation"]["limits"]["max_children" if mutation == "child-count" else "max_active_children"] = 1
        store_task_spec(service, p["task_id"], spec)
        # A new live receipt changes the policy binding; keep stored child
        # lineage current so this case reaches the capacity check itself.
        receipt = authority(service, p)
        body["authority"] = receipt["authority"]
        for item in (child, others[1]):
            spec = load_task_spec(service, item)
            payload = service._decode_child_authority(receipt["authority"])
            spec["delegated_parent"]["policy_digest"] = payload["policy_digest"]
            store_task_spec(service, item, spec)
    with pytest.raises(REJECTED):
        _claim(service, child, body)
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (child,)).fetchone()[0] == 0
    _unclaimed(service, *others)
    _no_claim_receipt(service)


@pytest.mark.parametrize("mutation", ["parent-revoked", "parent-expired", "child-expired", "child-settled", "child-cancelled", "child-fence", "child-binding", "heartbeat", "missing-attempt-deadline", "mismatched-attempt-deadline", "reservation-deadline", "readiness", "capability", "capacity"])
def test_replay_rechecks_live_parent_and_same_live_child(runtime, mutation):
    service, _ = runtime
    p, child, body, others = _case(runtime)
    if mutation == "reservation-deadline":
        service.store.conn.execute("UPDATE capabilities SET required_resource_keys_json='[\"cpu\"]' WHERE id=?", (CHILD,))
        service.store.conn.execute("UPDATE executors SET resource_keys_json='[\"cpu\"]' WHERE id='worker'")
    result = _claim(service, child, body)
    if mutation == "parent-revoked":
        spec = load_task_spec(service, p["task_id"]); spec["delegation_closed_attempt_id"] = p["attempt_id"]
        store_task_spec(service, p["task_id"], spec)
    elif mutation == "parent-expired": service.store.conn.execute("UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (p["attempt_id"],))
    elif mutation == "child-expired": service.store.conn.execute("UPDATE attempts SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (result["attempt_id"],))
    elif mutation == "child-settled": service.store.conn.execute("UPDATE attempts SET settled=1 WHERE id=?", (result["attempt_id"],))
    elif mutation == "child-cancelled": service.store.conn.execute("UPDATE tasks SET status='cancel_requested' WHERE id=?", (child,))
    elif mutation == "child-fence": service.store.conn.execute("UPDATE tasks SET lease_fence=lease_fence+1 WHERE id=?", (child,))
    elif mutation == "child-binding": service.store.conn.execute("UPDATE execution_bindings SET fence=fence+1 WHERE task_id=?", (child,))
    elif mutation == "missing-attempt-deadline": service.store.conn.execute("UPDATE attempts SET lease_expires_at=NULL WHERE id=?", (result["attempt_id"],))
    elif mutation == "mismatched-attempt-deadline": service.store.conn.execute("UPDATE attempts SET lease_expires_at='2099-01-01T00:00:00+00:00' WHERE id=?", (result["attempt_id"],))
    elif mutation == "reservation-deadline": service.store.conn.execute("UPDATE reservations SET lease_expires_at='2099-01-01T00:00:00+00:00' WHERE task_id=?", (child,))
    elif mutation == "heartbeat":
        service.store.conn.execute("UPDATE tasks SET lease_expires_at='2099-01-01T00:00:00+00:00' WHERE id=?", (child,))
        service.store.conn.execute("UPDATE attempts SET lease_expires_at='2099-01-01T00:00:00+00:00' WHERE id=?", (result["attempt_id"],))
    elif mutation == "readiness": service.store.conn.execute("UPDATE executors SET readiness='not_ready' WHERE id='worker'")
    elif mutation == "capability": service.store.conn.execute("UPDATE capabilities SET status='unavailable' WHERE id=?", (CHILD,))
    elif mutation == "capacity": service.store.conn.execute("UPDATE executors SET max_concurrency=1 WHERE id='worker'")
    with pytest.raises(REJECTED):
        _claim(service, child, body)
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (child,)).fetchone()[0] == 1
    _unclaimed(service, *others)


def test_held_local_claim_fence_rejects_new_and_replayed_exact_claim(runtime):
    service, _ = runtime
    _, child, body, others = _case(runtime)
    _claim(service, child, body)
    generation = digest("fixture-credential-generation")
    service.set_local_claim_generation_verifier(lambda fence, identity: generation, actor="worker")
    write_protected(service._local_claim_fence_path(), {
        "version": FENCE_VERSION, "state": "held", "workspace_uuid": service.realm["id"],
        "executor_incarnation": IDENTITY["execution_binding"]["executor_incarnation"],
        "credential_generation_digest": generation, "operation_id": "operation", "handoff_id": "handoff",
        "intent_digest": digest("intent"), "source_owner_epoch": "A", "target_owner_epoch": "B",
        "fence_generation": 1, "release_ack_digest": None,
    })
    for key in ("exact-claim", "new-exact-claim"):
        with pytest.raises(ConflictError, match="claims are fenced"):
            _claim(service, child, body, key=key)
    _unclaimed(service, *others)


@pytest.mark.parametrize("change", ["child", "target", "authority"])
def test_idempotency_key_cannot_be_rebound_to_child_target_or_authority(runtime, change):
    service, _ = runtime
    p, child, body, others = _case(runtime)
    _claim(service, child, body)
    if change == "child": child = others[1]
    elif change == "target": body["target"] = TARGET
    else:
        # An independently minted authority bound to this child is valid but
        # distinct input, and cannot reuse the original command key.
        body["authority"] = authority(service, p, refs=[], key="chosen-child")["authority"]
    with pytest.raises(REJECTED):
        _claim(service, child, body)
    _unclaimed(service, *others)


def test_generated_exact_claim_real_http_transport_and_revoked_replay(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        service = daemon.service
        for cap in (PARENT, CHILD):
            service.register_capability({"capability_id": cap, "definition_digest": digest(cap)})
        service.register_executor({"executor_id": "worker", "capabilities": [PARENT, CHILD], "max_concurrency": 64}, idempotency_key="transport-register")
        project = service.create_project({"slug": "transport", "name": "Transport"})["id"]
        # Ephemeral test credential, created only inside this pytest realm.
        token, _ = daemon.credentials.provision("worker", ["handshake", "worker:execute", "tasks:read"], metadata={"execution_binding": IDENTITY["execution_binding"]})
        client = WorkspaceClient(daemon.endpoint, token)
        p, child, body, others = _case((service, project), targeted=True)
        from tests.http_helpers import Api
        route = f"/v1/tasks/{child}/claim-delegated-child"
        for bad_body in ({key: value for key, value in body.items() if key != "target"},
                         {**body, "authority": "invalid"},
                         {**body, "target": {"kind": "machine", "id": "foreign"}},
                         {**body, "actor": "worker"}):
            with pytest.raises(RuntimeError):
                Api(daemon.endpoint, token).request("POST", route, bad_body, headers={"Idempotency-Key": "transport-invalid"})
            _unclaimed(service, child, *others)
        for bad_token in (None, daemon.token):
            with pytest.raises(RuntimeError):
                Api(daemon.endpoint, bad_token).request("POST", route, body, headers={"Idempotency-Key": "transport-actor"})
            _unclaimed(service, child, *others)
        _no_claim_receipt(service)
        payload = {key: value for key, value in body.items() if key != "authority"}
        result = client.claim_delegated_child(child, **payload, authority=body["authority"], idempotency_key="transport-claim")
        assert result.task_id == child and result.execution_binding["actual_target"] == TARGET
        replay = client.claim_delegated_child(child, **payload, authority=body["authority"], idempotency_key="transport-claim")
        assert replay == result
        with pytest.raises(ApiError):
            client.claim_delegated_child("missing", **payload, authority=body["authority"], idempotency_key="transport-missing")
        with pytest.raises(ApiError):
            client.claim_delegated_child(others[0], **payload, authority=body["authority"], idempotency_key="transport-unrelated")
        spec = load_task_spec(service, p["task_id"])
        spec["delegation_closed_attempt_id"] = p["attempt_id"]
        store_task_spec(service, p["task_id"], spec)
        with pytest.raises(ApiError):
            client.claim_delegated_child(child, **payload, authority=body["authority"], idempotency_key="transport-claim")
        _unclaimed(service, *others)
    finally:
        daemon.stop()


def test_unsettled_historical_attempt_blocks_untargeted_scalar_child(runtime):
    service, _ = runtime
    p = parent(runtime)
    receipt = authority(service, p)
    child = service.admit_delegated_child({"authority": receipt["authority"], "task": {
        "capability_id": CHILD, "capability_digest": digest(CHILD), "input_object_ids": [], "spec": {},
    }}, idempotency_key="scalar-child", identity=IDENTITY)["task"]["id"]
    assert service.store.execution_binding(child) is None
    body = {"executor_id": "worker", "capability_ids": [CHILD], "runtime_epoch": p["runtime_epoch"], "target": DEFAULT, "authority": receipt["authority"]}
    service.store.conn.execute("INSERT INTO attempts(id, task_id, lease_id, fence, executor_id, lease_expires_at, settled, runtime_epoch) VALUES ('unresolved', ?, 'old-lease', 1, 'worker', ?, 0, ?)", (child, p["lease_expires_at"], p["runtime_epoch"]))
    with pytest.raises(ConflictError, match="unresolved prior attempt"):
        _claim(service, child, body)
    assert service.store.conn.execute("SELECT attempt FROM tasks WHERE id=?", (child,)).fetchone()[0] == 0
    _no_claim_receipt(service)


def test_untargeted_scalar_exact_child_uses_explicit_default_selector(runtime):
    service, _ = runtime
    p = parent(runtime)
    receipt = authority(service, p)
    child = service.admit_delegated_child({"authority": receipt["authority"], "task": {
        "capability_id": CHILD, "capability_digest": digest(CHILD), "input_object_ids": [], "spec": {},
    }}, idempotency_key="scalar-child", identity=IDENTITY)["task"]["id"]
    body = {"executor_id": "worker", "capability_ids": [CHILD], "runtime_epoch": p["runtime_epoch"], "target": DEFAULT, "authority": receipt["authority"]}
    result = _claim(service, child, body)
    assert result["task_id"] == child and "execution_binding" not in result
    assert _claim(service, child, body) == result
