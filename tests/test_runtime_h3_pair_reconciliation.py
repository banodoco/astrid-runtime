"""Cross-track admission: selected targets coexist with frozen stage requests."""
import copy

import pytest

from runtime_protocol.errors import AuthorizationError
from tests.test_child_target_preservation import (
    DEFAULT, EXPLICIT, TARGET, admit_resource, child_case, claim_child, runtime,
)


def frozen_case(runtime, monkeypatch, target):
    service, _ = runtime
    frozen = {"schema_version": 1, "target": target,
              "lifecycle": {"mode": "leave_running"}}
    create = service.create_task

    def create_frozen_parent(body, *args, **kwargs):
        body = copy.deepcopy(body)
        if "child_delegation" in body:
            body["child_delegation"]["stages"][0]["execution_request"] = copy.deepcopy(frozen)
        return create(body, *args, **kwargs)

    monkeypatch.setattr(service, "create_task", create_frozen_parent)
    _, receipt, task, descriptor = child_case(runtime, target=target)
    task["execution_request"] = copy.deepcopy(frozen)
    return receipt, task, descriptor, frozen


@pytest.mark.parametrize("target", [DEFAULT, TARGET, EXPLICIT],
                         ids=["explicit-default", "inherited-selector", "explicit-machine"])
def test_selected_frozen_request_survives_canonical_inputs_and_claim(runtime, monkeypatch, target):
    service, _ = runtime
    receipt, task, descriptor, frozen = frozen_case(runtime, monkeypatch, target)
    resource = admit_resource(service, receipt, task)
    assert resource["execution_request"] == {**frozen, "inputs": [descriptor]}
    assert resource["execution_binding"]["resolved_target"] == target
    assert resource["spec"]["delegated_parent"]["parent_effective_target"] == TARGET
    assert admit_resource(service, receipt, task) == resource
    claimed = claim_child(service, target, actual=target if target != DEFAULT else TARGET)
    assert claimed["task_id"] == resource["task_id"]
    assert claimed["execution_request"] == resource["execution_request"]


@pytest.mark.parametrize("drift", ["missing", "target", "lifecycle"])
def test_explicit_selection_cannot_replace_frozen_stage_request(runtime, monkeypatch, drift):
    service, _ = runtime
    receipt, task, _, _ = frozen_case(runtime, monkeypatch, DEFAULT)
    if drift == "missing":
        del task["execution_request"]
    elif drift == "target":
        # The parent's target passes the generic stage selector check, but
        # cannot replace the exact frozen default request.
        task["execution_request"]["target"] = TARGET
    else:
        task["execution_request"]["lifecycle"]["mode"] = "terminate"
    with pytest.raises(AuthorizationError, match="differs from its admitted stage"):
        admit_resource(service, receipt, task)
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE capability=?", (task["capability_id"],),
    ).fetchone()[0] == 0


@pytest.mark.parametrize("frozen", [False, True], ids=["recovery-projection", "exact-frozen-stage"])
def test_recovery_projects_only_unfrozen_parent_selector(tmp_path, monkeypatch, frozen):
    from tests.test_placement_recovery import (
        CHILD, CHILD_DIGEST, NEW, OLD, OWNER, _admit_parent, _claim, _fail,
        _identity, _recovery_body, _service,
    )

    service = _service(tmp_path / "realm")
    request = {"schema_version": 1, "target": OLD}
    create = service.create_task

    def create_staged_parent(body, *args, **kwargs):
        body = copy.deepcopy(body)
        if "child_delegation" in body:
            stage = {"name": "process", "capability_id": CHILD,
                     "capability_digest": CHILD_DIGEST, "target": OLD, "inputs": []}
            if frozen:
                stage["execution_request"] = request
            body["child_delegation"]["stages"] = [stage]
        return create(body, *args, **kwargs)

    monkeypatch.setattr(service, "create_task", create_staged_parent)
    try:
        admitted = _admit_parent(service, child_delegation=True)
        task_id = admitted["task"]["id"]
        original = _claim(service, "original-parent", OLD, _identity(OLD))
        _fail(service, original, _identity(OLD))
        service.recover_task_placement(task_id, _recovery_body(service, task_id),
                                       idempotency_key="recover", identity=OWNER)
        service.retry_task(task_id, {"expected_version": service._task_resource(service.task(task_id))["version"]},
                           idempotency_key="retry")
        successor = _claim(service, "recovered-parent", NEW, _identity(NEW))
        authority = service.issue_child_authority(successor["attempt_id"],
            {key: successor[key] for key in ("lease_id", "fence", "runtime_epoch")},
            identity=_identity(NEW))["authority"]
        child = service._task_resource(service.admit_delegated_child({"authority": authority,
            "task": {"capability_id": CHILD, "capability_digest": CHILD_DIGEST,
                     "stage": "process", "input_refs": [], "spec": {"inputs": {}},
                     "execution_request": request}}, idempotency_key="child", identity=_identity(NEW)))
        selected = OLD if frozen else NEW
        assert child["execution_request"] == {"schema_version": 1, "target": selected, "inputs": []}
        assert child["execution_binding"]["resolved_target"] == selected
        assert child["spec"]["delegated_parent"]["parent_effective_target"] == NEW
        other = NEW if frozen else OLD
        assert _claim(service, "wrong-child-selector", other, _identity(other)) is None
        claimed = _claim(service, "exact-child-selector", selected, _identity(selected))
        assert claimed["task_id"] == child["task_id"]
        assert claimed["execution_request"] == child["execution_request"]
    finally:
        service.close()
