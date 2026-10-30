"""Child target admission uses the real service, CAS, projection and claim guards."""
from __future__ import annotations

import copy
import json

import pytest

from runtime_protocol.errors import AuthorizationError, LeaseError, ValidationError
from tests.test_runtime_child_delegation import (
    CHILD, IDENTITY, PARENT, TARGET, admit, authority, claim, digest, parent, runtime,
)


DEFAULT = {"kind": "default"}
EXPLICIT = {
    "kind": "machine", "id": "child-machine", "profile_revision": "revision-1",
    "profile_digest": digest("profile"), "release_digest": digest("release"),
    "storage": {"volume": "child-volume"},
    "mounts": [{"source": "child-volume", "target": "/workspace", "read_only": True}],
}


def child_case(runtime, *, targeted=True, target=EXPLICIT, staged=True):
    service, project = runtime
    object_id = service.ingest(project, b"child-frame", idempotency_key="frame")["data"]["digest"]
    refs = [{"name": "frame", "root_object_id": object_id}]
    policy = {
        "capabilities": [{"capability_id": CHILD, "capability_digest": digest(CHILD)}],
        "targets": [DEFAULT, TARGET, EXPLICIT], "input_object_ids": [object_id],
    }
    if staged:
        policy["stages"] = [{
            "name": "process", "capability_id": CHILD, "capability_digest": digest(CHILD),
            "target": target, "inputs": refs,
        }]
    body = {
        "project": project, "capability_id": PARENT, "capability_digest": digest(PARENT),
        "input_object_ids": [object_id], "spec": {}, "child_delegation": policy,
        "idempotency_key": "parent",
    }
    if targeted:
        body["execution_request"] = {"schema_version": 1, "target": TARGET, "inputs": []}
        # The parent's request must mirror its real admitted root input too.
        body["execution_request"]["inputs"] = [{"name": "frame", "object_id": object_id}]
    service.create_task(body, enforce_readiness=True)
    attempt = claim(service, PARENT, "parent-claim")
    descriptor = {"object_id": object_id, "digest": object_id, "filename": "frame.bin", "required": True}
    task = {
        "capability_id": CHILD, "capability_digest": digest(CHILD),
        "spec": {"inputs": {"frame": descriptor}},
        "execution_request": {"schema_version": 1, "target": target},
    }
    if staged:
        task.update(stage="process", input_refs=refs)
    else:
        task["input_object_ids"] = [object_id]
        task["execution_request"]["inputs"] = [{"name": "frame", **descriptor}]
    return attempt, authority(service, attempt), task, {"name": "frame", **descriptor}


def admit_resource(service, receipt, task):
    # Match the JSON body and resource projection used by POST /v1/delegated-tasks.
    body = json.loads(json.dumps({"authority": receipt["authority"], "task": task}))
    admitted = service.admit_delegated_child(body, idempotency_key="child", identity=IDENTITY)
    return service._task_resource(admitted)


def claim_child(service, selector, *, actual=TARGET, key="child-claim"):
    identity = copy.deepcopy(IDENTITY)
    identity["execution_binding"]["actual"] = actual
    body = {"executor_id": "worker", "capability_ids": [CHILD],
            "runtime_epoch": service.health()["runtime_epoch"]}
    if selector is not None:
        body["target"] = selector
    return service.claim_next(body, idempotency_key=key, identity=identity)


@pytest.mark.parametrize("targeted", [False, True], ids=["local-parent", "targeted-parent"])
@pytest.mark.parametrize("staged", [False, True], ids=["ordinary", "staged"])
def test_explicit_target_survives_child_admission_and_projection(runtime, targeted, staged):
    service, _ = runtime
    attempt, receipt, task, descriptor = child_case(runtime, targeted=targeted, staged=staged)
    resource = admit_resource(service, receipt, task)
    assert resource["execution_request"] == {"schema_version": 1, "target": EXPLICIT, "inputs": [descriptor]}
    assert resource["execution_binding"]["resolved_target"] == EXPLICIT
    assert service._task_resource(service.task(resource["task_id"])) == resource
    assert resource["spec"]["delegated_parent"]["parent_effective_target"] == (TARGET if targeted else None)
    assert resource["spec"]["delegated_parent"]["parent_attempt_id"] == attempt["attempt_id"]
    assert admit_resource(service, receipt, task) == resource
    assert claim_child(service, TARGET, key="wrong-selector") is None
    claimed = claim_child(service, EXPLICIT, actual=EXPLICIT)
    assert claimed["task_id"] == resource["task_id"]
    assert claimed["execution_request"] == resource["execution_request"]
    assert claimed["execution_binding"]["actual_target"] == EXPLICIT


@pytest.mark.parametrize("target", [DEFAULT, TARGET], ids=["default-inherits", "inherited-selector"])
def test_inherited_target_retains_canonical_staged_inputs(runtime, target):
    service, _ = runtime
    _, receipt, task, descriptor = child_case(runtime, target=target)
    resource = admit_resource(service, receipt, task)
    assert resource["execution_request"] == {"schema_version": 1, "target": TARGET, "inputs": [descriptor]}
    assert resource["execution_binding"]["resolved_target"] == TARGET
    assert claim_child(service, TARGET)["task_id"] == resource["task_id"]


def test_local_default_retains_request_inputs_and_guarded_claim_path(runtime):
    service, _ = runtime
    _, receipt, task, descriptor = child_case(runtime, targeted=False, target=DEFAULT)
    resource = admit_resource(service, receipt, task)
    assert resource["execution_request"] == {"schema_version": 1, "target": DEFAULT, "inputs": [descriptor]}
    assert resource["execution_binding"]["resolved_target"] == DEFAULT
    # A request still requires a matching selector and credential-verified placement.
    assert claim_child(service, None, key="no-selector") is None
    assert claim_child(service, DEFAULT)["task_id"] == resource["task_id"]


@pytest.mark.parametrize("targeted", [False, True])
def test_missing_scalar_request_preserves_local_or_inherited_path(runtime, targeted):
    service, _ = runtime
    attempt = parent(runtime, targeted=targeted)
    resource = service._task_resource(admit(service, authority(service, attempt)))
    if targeted:
        assert resource["execution_request"]["target"] == TARGET
    else:
        assert "execution_request" not in resource
    assert claim(service, CHILD, "scalar-claim")["task_id"] == resource["task_id"]


@pytest.mark.parametrize("change", ["policy", "stage", "malformed", "binding"])
def test_invalid_target_or_forged_binding_is_rejected_before_queue(runtime, change):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime, staged=change != "policy")
    error, message = AuthorizationError, "outside parent policy"
    if change == "policy":
        task["execution_request"]["target"] = {"kind": "machine", "id": "foreign"}
    elif change == "stage":
        task["execution_request"]["target"] = DEFAULT
        message = "declared stage"
    elif change == "malformed":
        task["execution_request"]["target"] = {"kind": "default", "id": "forged"}
        error, message = ValidationError, "cannot carry placement"
    else:
        task["execution_request"]["execution_binding"] = {"resolved_target": EXPLICIT}
        error, message = ValidationError, "caller-supplied"
    with pytest.raises(error, match=message):
        admit_resource(service, receipt, task)
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability=?", (CHILD,)).fetchone()[0] == 0


@pytest.mark.parametrize("change", ["missing", "object", "digest", "filename", "required", "caller-inputs"])
def test_staged_input_validation_remains_active_with_explicit_target(runtime, change):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime)
    descriptor = task["spec"]["inputs"]["frame"]
    error, message = ValidationError, "managed input descriptor"
    if change == "missing":
        task["spec"]["inputs"].clear()
    elif change in ("object", "digest"):
        descriptor["object_id" if change == "object" else "digest"] = digest("foreign")
        error, message = AuthorizationError, "disagrees"
    elif change == "filename":
        descriptor["filename"] = "../frame.bin"
        message = "filename"
    elif change == "required":
        descriptor["required"] = "yes"
        message = "boolean"
    else:
        task["execution_request"]["inputs"] = []
        message = "resolved by Runtime"
    with pytest.raises(error, match=message):
        admit_resource(service, receipt, task)
    assert service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability=?", (CHILD,)).fetchone()[0] == 0


def test_preserved_selector_cannot_claim_mismatched_actual_placement(runtime):
    service, _ = runtime
    _, receipt, task, _ = child_case(runtime)
    resource = admit_resource(service, receipt, task)
    mismatch = claim_child(service, EXPLICIT, actual=TARGET)
    assert mismatch["waiting_reason"] == "execution_binding_mismatch"
    assert service.task(resource["task_id"])["task"]["status"] == "queued"
    assert service.store.conn.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?", (resource["task_id"],)).fetchone()[0] == 0


def test_explicit_target_does_not_bypass_parent_fence(runtime):
    service, _ = runtime
    attempt, receipt, task, _ = child_case(runtime)
    service.store.conn.execute("UPDATE tasks SET lease_fence=lease_fence+1 WHERE id=?", (attempt["task_id"],))
    with pytest.raises(LeaseError, match="no longer live"):
        admit_resource(service, receipt, task)
