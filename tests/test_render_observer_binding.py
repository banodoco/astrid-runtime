from __future__ import annotations

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.render_observer import admitted_run_id
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def test_admitted_render_run_id_accepts_only_matching_lowercase_runtime_identity():
    run_id = "a" * 32
    assert admitted_run_id(run_id, run_id) == run_id


@pytest.mark.parametrize("task_run_id,run_id", [
    ("a" * 32, None),
    ("a" * 32, "A" * 32),
    ("a" * 32, "a" * 31),
    ("a" * 32, "b" * 32),
])
def test_admitted_render_run_id_refuses_missing_malformed_or_mismatched_values(task_run_id, run_id):
    with pytest.raises(ConflictError, match="admitted render run_id"):
        admitted_run_id(task_run_id, run_id)


def test_render_claim_ignores_overlay_identity_and_observer_values(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        capability = "rendering.render"
        digest = "sha256:" + "a" * 64
        service.register_capability({"capability_id": capability, "definition_digest": digest})
        service.register_executor({"executor_id": "worker", "capabilities": [capability]})
        overlay_run_id = "f" * 32
        admitted = service.create_task({
            "capability_id": capability,
            "capability_digest": digest,
            "idempotency_key": "overlay-render",
            "spec": {
                "run_id": overlay_run_id,
                "env": {"ASTRID_TIMELINE_OBSERVER_FD": "999"},
            },
        })
        claimed = service.claim_next({
            "executor_id": "worker",
            "capability_ids": [capability],
            "runtime_epoch": service.health()["runtime_epoch"],
        })
        assert claimed["run_id"] == admitted["task"]["run_id"]
        assert claimed["run_id"] != overlay_run_id
        # The task body remains opaque Runtime input; the admitted action
        # identity is always its top-level Runtime-owned claim field.
        assert claimed["spec"]["spec"]["run_id"] == overlay_run_id
        assert claimed["spec"]["spec"]["env"]["ASTRID_TIMELINE_OBSERVER_FD"] == "999"
    finally:
        service.close()
