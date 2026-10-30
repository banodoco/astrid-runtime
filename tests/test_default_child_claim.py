"""Integrated child target semantics through real Runtime admission and claims."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, ValidationError
from runtime_protocol.local_execution_handoff import FENCE_VERSION
from tests.test_child_target_preservation import (
    DEFAULT, EXPLICIT, admit_resource, child_case,
)
from tests.test_runtime_child_delegation import (
    CHILD, IDENTITY, PARENT, TARGET, admit, authority, claim, digest, parent, runtime, upload,
)


@pytest.fixture
def local_identity(runtime):
    service, _ = runtime
    identity = copy.deepcopy(IDENTITY)
    identity["actor"] = service._local_claim_actor
    service.register_executor({
        "executor_id": identity["actor"], "capabilities": [CHILD],
        "max_concurrency": 2, "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key="local-register", identity=identity)
    return identity


def claim_body(service, identity):
    return {
        "executor_id": identity["actor"], "capability_ids": [CHILD],
        "runtime_epoch": service.health()["runtime_epoch"],
    }


def assert_unclaimed(service, task_id):
    assert service.task(task_id)["task"]["status"] == "queued"
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM attempts WHERE task_id=?", (task_id,),
    ).fetchone()[0] == 0


@pytest.mark.parametrize("staged", [False, True], ids=["ordinary", "staged"])
def test_explicit_default_under_targeted_parent_is_preserved(runtime, staged):
    service, _ = runtime
    _, receipt, task, descriptor = child_case(runtime, target=DEFAULT, staged=staged)
    resource = admit_resource(service, receipt, task)
    assert resource["execution_request"] == {
        "schema_version": 1, "target": DEFAULT, "inputs": [descriptor],
    }
    assert resource["execution_binding"]["resolved_target"] == DEFAULT
    assert resource["spec"]["delegated_parent"]["parent_effective_target"] == TARGET
    assert admit_resource(service, receipt, task) == resource


@pytest.mark.parametrize("staged", [False, True], ids=["ordinary", "staged"])
def test_local_managed_file_claims_without_selector(runtime, local_identity, staged):
    service, _ = runtime
    _, receipt, task, descriptor = child_case(runtime, targeted=False, target=DEFAULT, staged=staged)
    resource = admit_resource(service, receipt, task)
    body = claim_body(service, local_identity)
    claimed = service.claim_next(body, idempotency_key="local-file", identity=local_identity)
    assert claimed is not None
    assert claimed["task_id"] == resource["task_id"]
    assert claimed["execution_request"] == resource["execution_request"] == {
        "schema_version": 1, "target": DEFAULT, "inputs": [descriptor],
    }
    assert claimed["input_object_ids"] == [descriptor["object_id"]]
    assert claimed["spec"] == resource["spec"]
    assert claimed["spec"]["spec"]["inputs"] == task["spec"]["inputs"]
    binding = claimed["execution_binding"]
    assert binding["status"] == "claimed"
    assert binding["resolved_target"] == DEFAULT
    assert binding["actual_target"] == local_identity["execution_binding"]["actual"]
    assert binding["verification"] == local_identity["execution_binding"]["verification"]
    assert binding["executor_incarnation"] == local_identity["execution_binding"]["executor_incarnation"]
    assert service.claim_next(body, idempotency_key="local-file", identity=local_identity) == claimed


def test_local_scalar_still_claims_without_request_or_selector(runtime, local_identity):
    service, _ = runtime
    attempt = parent(runtime, targeted=False)
    resource = service._task_resource(admit(service, authority(service, attempt)))
    assert "execution_request" not in resource
    claimed = service.claim_next(
        claim_body(service, local_identity), idempotency_key="local-scalar", identity=local_identity,
    )
    assert claimed["task_id"] == resource["task_id"]
    assert "execution_request" not in claimed
    assert "execution_binding" not in claimed


def test_local_derived_file_claim_retains_exact_receipt(runtime, local_identity):
    service, _ = runtime
    attempt = parent(runtime)
    ref = upload(service, attempt)
    receipt = authority(service, attempt, refs=[ref])
    admitted = admit(service, receipt, refs=[ref])
    resource = service._task_resource(admitted)
    assert resource["spec"]["delegated_inputs"] == receipt["derived_inputs"]
    claimed = service.claim_next(
        claim_body(service, local_identity), idempotency_key="derived-file", identity=local_identity,
    )
    assert claimed["task_id"] == resource["task_id"]
    assert claimed["execution_request"] == resource["execution_request"]
    assert claimed["spec"] == resource["spec"]
    assert claimed["input_object_ids"] == [ref["object_id"]]


def test_explicit_default_scalar_under_targeted_parent(runtime, local_identity):
    service, _ = runtime
    attempt = parent(runtime, targeted=True)
    task = {
        "capability_id": CHILD, "capability_digest": digest(CHILD), "spec": {"params": {"value": 7}},
        "execution_request": {"schema_version": 1, "target": DEFAULT, "inputs": []},
    }
    resource = admit_resource(service, authority(service, attempt), task)
    assert resource["execution_request"] == task["execution_request"]
    claimed = service.claim_next(
        claim_body(service, local_identity), idempotency_key="explicit-default-scalar", identity=local_identity,
    )
    assert claimed["task_id"] == resource["task_id"]
    assert claimed["execution_binding"]["resolved_target"] == DEFAULT


@pytest.mark.parametrize("staged", [False, True], ids=["ordinary", "staged"])
def test_default_file_descriptor_order_digest_and_requiredness(runtime, local_identity, staged):
    service, project = runtime
    descriptors = [{
        "name": name, "object_id": service.ingest(project, name.encode(), idempotency_key=name)["data"]["digest"],
        "filename": name + ".bin", "required": required,
    } for name, required in (("second", False), ("first", True))]
    descriptors[0]["digest"] = descriptors[0]["object_id"]
    refs = [{"name": item["name"], "root_object_id": item["object_id"]} for item in descriptors]
    object_ids = [item["object_id"] for item in descriptors]
    policy = {
        "capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}],
        "targets": [DEFAULT], "input_object_ids": object_ids,
    }
    if staged:
        policy["stages"] = [{
            "name": "process", "capability_id": CHILD, "capability_digest": digest(CHILD),
            "target": DEFAULT, "inputs": refs,
        }]
    service.create_task({
        "project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
        "input_object_ids": object_ids, "child_delegation": policy, "spec": {}, "idempotency_key": "parent",
    }, enforce_readiness=True)
    receipt = authority(service, claim(service, PARENT, "parent-claim"))
    task = {
        "capability_id": CHILD, "capability_digest": digest(CHILD),
        "spec": {"inputs": {item["name"]: {k: v for k, v in item.items() if k != "name"}
                            for item in reversed(descriptors)}},
        "execution_request": {"schema_version": 1, "target": DEFAULT},
    }
    if staged:
        task.update(stage="process", input_refs=refs)
    else:
        task["input_object_ids"] = object_ids
        task["execution_request"]["inputs"] = list(reversed(descriptors))
        with pytest.raises(ValidationError, match="exactly mirror.*in order"):
            admit_resource(service, receipt, task)
        task["execution_request"]["inputs"] = descriptors
    resource = admit_resource(service, receipt, task)
    assert resource["execution_request"]["inputs"] == descriptors
    claimed = service.claim_next(
        claim_body(service, local_identity), idempotency_key="ordered-files", identity=local_identity,
    )
    assert claimed["task_id"] == resource["task_id"]
    assert claimed["execution_request"]["inputs"] == descriptors
    assert claimed["input_object_ids"] == object_ids


@pytest.mark.parametrize("change", [
    "missing-placement", "remote-placement", "profile-placement", "unverified", "default-actual",
    "wrong-executor", "remote-activation", "body-binding", "missing-binding", "changed-binding",
])
def test_no_selector_default_claim_requires_verified_local_binding(runtime, local_identity, change):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime, targeted=False, target=DEFAULT)
    resource = admit_resource(service, receipt, task)
    identity = copy.deepcopy(local_identity)
    error = None
    if change == "missing-placement":
        identity.pop("execution_binding")
    elif change == "remote-placement":
        identity["execution_binding"]["actual"] = {
            "kind": "runpod", "pod_id": "fixture-pod", "provider_account_ref": "fixture-account",
        }
    elif change == "profile-placement":
        identity["execution_binding"]["actual"] = {"kind": "profile", "id": "fixture-profile"}
    elif change == "unverified":
        identity["execution_binding"]["verification"]["verified"] = False
        error = AuthorizationError
    elif change == "default-actual":
        identity["execution_binding"]["actual"] = DEFAULT
        error = AuthorizationError
    elif change == "wrong-executor":
        identity = copy.deepcopy(IDENTITY)
    elif change == "remote-activation":
        identity["qualified_activation"] = {"activation_id": "foreign"}
    elif change == "missing-binding":
        service.store.conn.execute("DELETE FROM execution_bindings WHERE task_id=?", (resource["task_id"],))
    elif change == "changed-binding":
        service.store.conn.execute(
            "UPDATE execution_bindings SET resolved_target_json=? WHERE task_id=?",
            ('{"selected":{"kind":"machine","id":"foreign"}}', resource["task_id"]),
        )
    body = claim_body(service, identity)
    if change == "body-binding":
        body["execution_binding"] = identity["execution_binding"]
        error = ValidationError
    if error is not None:
        with pytest.raises(error):
            service.claim_next(body, idempotency_key="rejected-claim", identity=identity)
    else:
        assert service.claim_next(body, idempotency_key="rejected-claim", identity=identity) is None
    assert_unclaimed(service, resource["task_id"])


@pytest.mark.parametrize("selector", [None, DEFAULT, TARGET])
def test_local_claim_cannot_select_nondefault_work(runtime, local_identity, selector):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime)
    resource = admit_resource(service, receipt, task)
    body = claim_body(service, local_identity)
    if selector is not None:
        body["target"] = selector
    assert service.claim_next(body, idempotency_key="wrong-selector", identity=local_identity) is None
    assert_unclaimed(service, resource["task_id"])
    # Even the exact selector still needs matching credential-backed actual placement.
    body["target"] = EXPLICIT
    result = service.claim_next(body, idempotency_key="wrong-actual", identity=local_identity)
    assert result["waiting_reason"] == "execution_binding_mismatch"
    assert_unclaimed(service, resource["task_id"])


@pytest.mark.parametrize("end", ["epoch", "fence"])
def test_default_child_admission_retains_parent_guards(runtime, end):
    service, _ = runtime
    attempt, receipt, task, _ = child_case(runtime, targeted=False, target=DEFAULT)
    if end == "epoch":
        service.store.begin_runtime_session("default-next-boot")
    else:
        service.store.conn.execute("UPDATE tasks SET lease_fence=lease_fence+1 WHERE id=?", (attempt["task_id"],))
    with pytest.raises((LeaseError, ConflictError)):
        admit_resource(service, receipt, task)
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability=?", (CHILD,)).fetchone()[0] == 0


def test_no_selector_default_claim_rejects_stale_epoch(runtime, local_identity):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime, targeted=False, target=DEFAULT)
    resource = admit_resource(service, receipt, task)
    body = claim_body(service, local_identity)
    service.store.begin_runtime_session("claim-next-boot")
    with pytest.raises(ConflictError):
        service.claim_next(body, idempotency_key="stale-claim", identity=local_identity)
    # Reading after restart also contains descendants of the stale parent.
    assert service.task(resource["task_id"])["task"]["status"] == "cancelled"
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM attempts WHERE task_id=?", (resource["task_id"],),
    ).fetchone()[0] == 0


def test_no_selector_default_claim_retains_held_local_fence(runtime, local_identity):
    service, _ = runtime
    body = claim_body(service, local_identity)
    assert service.claim_next(body, idempotency_key="empty-claim", identity=local_identity) is None
    _, receipt, task, _ = child_case(runtime, targeted=False, target=DEFAULT)
    resource = admit_resource(service, receipt, task)
    # The credential-generation boundary is deterministic; fence publication,
    # reconstruction and both claim paths use the real Runtime helpers.
    generation = digest("fixture-generation")
    service.set_local_claim_generation_verifier(lambda fence, identity: generation, actor=local_identity["actor"])
    fence = {
        "version": FENCE_VERSION, "state": "held", "workspace_uuid": service.realm["id"],
        "executor_incarnation": local_identity["execution_binding"]["executor_incarnation"],
        "credential_generation_digest": generation, "operation_id": "operation", "handoff_id": "handoff",
        "intent_digest": digest("intent"), "source_owner_epoch": "A", "target_owner_epoch": "B",
        "fence_generation": 1, "release_ack_digest": None,
    }

    def assert_no_work():
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE executor_id=? AND settled=0", (local_identity["actor"],),
        ).fetchone()[0] == 0

    service.hold_local_claim_fence(fence, assert_no_work=assert_no_work)
    for key in ("empty-claim", "new-claim"):
        with pytest.raises(ConflictError, match="claims are fenced"):
            service.claim_next(body, idempotency_key=key, identity=local_identity)
    assert_unclaimed(service, resource["task_id"])


@pytest.mark.parametrize("change", ["missing", "object", "digest", "filename", "required", "caller-inputs"])
def test_default_child_retains_canonical_descriptor_validation(runtime, change):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime, targeted=False, target=DEFAULT)
    descriptor = task["spec"]["inputs"]["frame"]
    if change == "missing":
        task["spec"]["inputs"].clear()
    elif change in ("object", "digest"):
        descriptor["object_id" if change == "object" else "digest"] = "sha256:" + "f" * 64
    elif change == "filename":
        descriptor["filename"] = "../frame.bin"
    elif change == "required":
        descriptor["required"] = "yes"
    else:
        task["execution_request"]["inputs"] = []
    with pytest.raises((AuthorizationError, ValidationError)):
        admit_resource(service, receipt, task)
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability=?", (CHILD,)).fetchone()[0] == 0
