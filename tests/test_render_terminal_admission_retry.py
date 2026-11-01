"""Original admission replay after actual terminal settlement and a new head."""
from __future__ import annotations

import copy
import http.client
import json
import subprocess
import threading

import pytest

from door_helpers import HOSTED, DoorWorld
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.errors import ConflictError, LeaseError
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest
from test_canonical_render_admission import canonical_scene, _publish, _request, _snapshot
from test_managed_output_public_api import _output, _settle
from test_render_admission_exact_retry import _advance, _state
from test_task_admission_replay_identity import _receipt_state
from test_timeline_commit_acceptance import validate_prepared


def _receipt(service, request):
    row = service.store.conn.execute(
        "SELECT * FROM command_idempotency WHERE command_kind='task.create' "
        "AND aggregate_id=? AND idempotency_key=?",
        (request["project"], request["idempotency_key"]),
    ).fetchone()
    return dict(row) if row else None


@pytest.fixture
def lost_render_admission(canonical_scene, tmp_path, monkeypatch):
    f = canonical_scene
    _publish(f)
    root = f["service"].store.root
    f["service"].close()
    config = DoorConfig(origin=HOSTED, port=0, credential_file=tmp_path / "product.json")
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=config).start()
    world = DoorWorld(tmp_path, daemon, config.credential_file)
    f.update(service=daemon.service, world=world, door_config=config)
    durable, release, finished = threading.Event(), threading.Event(), threading.Event()
    saved = []
    original = daemon.service.create_task

    def lose_ack(*args, **kwargs):
        result = original(*args, **kwargs)
        saved.append(result)
        durable.set()
        try:
            assert release.wait(15)
            return result
        finally:
            finished.set()

    request = _request(f)
    request["spec"]["params"]["output_name"] = "original.mp4"
    request["spec"]["authority_context"] = {"render_toolchain_digest": digest("fixture-toolchain")}
    connection = http.client.HTTPConnection("127.0.0.1", world.port, timeout=15)
    try:
        world.provision()
        daemon.service.register_executor({
            "executor_id": "worker", "capabilities": ["rendering.render"],
            "runtime_epoch": daemon.service.health()["runtime_epoch"],
            "source_digest": digest("fixture-renderer"), "source_epoch": "fixture-source-1",
        }, idempotency_key="terminal-worker")
        body = json.dumps(request).encode()
        with monkeypatch.context() as patch:
            patch.setattr(daemon.service, "create_task", lose_ack)
            connection.request("POST", "/api/runtime/v1/tasks", body, {
                "Origin": HOSTED, "Content-Type": "application/json",
                "Idempotency-Key": request["idempotency_key"],
            })
            assert durable.wait(15)
            connection.close()  # The durable admission ACK never reaches the caller.
            release.set()
            assert finished.wait(15)
        f.update(request=request, request_bytes=body, admitted=saved[0])
        f["admission_receipt"] = _receipt(daemon.service, request)
        assert f["admission_receipt"]["txn_id"]
        yield f
    finally:
        connection.close()
        release.set()
        f["world"].stop()


@pytest.mark.parametrize("terminal,receipt", [
    ("completed", "current"), ("completed", "absent"), ("failed", "current"),
])
def test_terminal_original_admission_replays_after_new_head_and_restart(
    lost_render_admission, tmp_path, monkeypatch, terminal, receipt,
):
    f = lost_render_admission
    service = f["service"]
    admitted, request = f["admitted"], f["request"]
    task_id, run_id = admitted["task"]["id"], admitted["run"]["id"]
    frozen = copy.deepcopy(admitted["task"]["spec"])
    snapshot = _snapshot(service, frozen)
    attempt = service.claim_next({
        "executor_id": "worker", "capability_ids": ["rendering.render"],
        "runtime_epoch": service.health()["runtime_epoch"],
    }, idempotency_key="terminal-claim")
    assert attempt["task_id"] == task_id
    assert attempt["spec"] == frozen
    outputs = []
    if terminal == "completed":
        payload = b"fenced-render-output"
        output = _output(payload, name="render", filename="original.mp4", output_port="render",
                         role="result", is_primary=True, durability="durable")
        before = _state(service.store)
        with pytest.raises(LeaseError):
            _settle(service, {**attempt, "fence": attempt["fence"] + 1}, [output], key="stale-settle")
        assert _state(service.store) == before
        settled = _settle(service, attempt, [output], key="terminal-settle", result={"rendered_revision": "parent-1"})
        assert settled["receipt"]["command_kind"] == "attempt.settle"
        association, = service.managed_outputs(task_id)
        assert association["task_id"] == task_id and association["run_id"] == run_id
        assert association["attempt_id"] == attempt["attempt_id"]
        assert association["project_id"] == f["project"]
        assert association["object_id"] == association["digest"] == output["digest"]
        assert association["filename"] == "original.mp4"
        for field in ("fence", "runtime_epoch"):
            assert association["provenance"][field] == attempt[field]
        assert association["provenance"]["executor_id"] == "worker"
        assert service.object(output["digest"])[1] == payload
        pinned = service.update_managed_output_lifecycle(
            association["association_id"], {"operation": "pin", "expected_version": 1},
            idempotency_key="pin-original-render",
        )
        assert pinned["data"]["state"] == "available" and pinned["data"]["pinned_at"]
        outputs = service.managed_outputs(task_id)
        assert outputs == [pinned["data"]]
        assert service.store._reusable_render_output(task_id, frozen["spec"])
    else:
        error = {"code": "fixture_render_failed", "message": "terminal executor failure"}
        failed = service.fail_attempt(attempt["attempt_id"], {
            "lease_id": attempt["lease_id"], "fence": attempt["fence"],
            "runtime_epoch": attempt["runtime_epoch"], "error": error,
        }, idempotency_key="terminal-fail")
        assert failed["receipt"]["command_kind"] == "attempt.fail"
        assert service.task(task_id)["task"]["result"] == {"error": error}
        assert service.managed_outputs(task_id) == []
    terminal_task = service.task(task_id)
    assert terminal_task["task"]["status"] == terminal_task["run"]["status"] == terminal
    assert terminal_task["task"]["spec"] == frozen
    head = _advance(f)
    assert head["revision_id"] == "parent-C"
    root = service.store.root
    f["world"].stop()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=f["door_config"]).start()
    f["world"] = DoorWorld(tmp_path, daemon, f["door_config"].credential_file)
    f["service"] = service = daemon.service
    assert service.health()["runtime_epoch"] != attempt["runtime_epoch"]
    assert service.task(task_id) == terminal_task
    assert service.managed_outputs(task_id) == outputs
    assert _receipt(service, request) == f["admission_receipt"]
    _receipt_state(service.store, receipt)  # Only the receipt is faulted, never task/attempt state.

    def forbidden(*_args, **_kwargs):
        pytest.fail("admission replay must not start a renderer or seek semantic output reuse")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(service.store, "_reusable_render_output", forbidden)
    before = _state(service.store)
    changed = copy.deepcopy(request)
    changed["spec"]["params"]["output_name"] = "changed.mp4"
    with pytest.raises(ConflictError, match="different input"):
        service.create_task(changed)
    assert _state(service.store) == before
    reply = f["world"].call("/api/runtime/v1/tasks", "POST", body=f["request_bytes"], headers={
        "Content-Type": "application/json", "Idempotency-Key": request["idempotency_key"],
    })
    assert reply.status == 201, reply.body
    result = reply.json()
    assert result["data"]["task_id"] == task_id and result["data"]["run_id"] == run_id
    replay = service.create_task(json.loads(f["request_bytes"]))
    assert replay["task"]["id"] == task_id and replay["run"]["id"] == run_id
    assert replay["task"]["spec"] == frozen
    assert _snapshot(service, replay["task"]["spec"]) == snapshot
    assert replay["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["parent_revision_id"] == "parent-1"
    assert f["C_media"]["object_id"] not in replay["task"]["spec"]["input_object_ids"]
    assert service.task(task_id) == terminal_task
    assert service.managed_outputs(task_id) == outputs
    after = _state(service.store)
    if receipt == "current":
        # Cached admission results may still say queued; terminal truth is task lookup.
        assert replay == admitted
        assert result["receipt"]["receipt_id"] == f["admission_receipt"]["txn_id"]
        assert after == before
    else:
        assert result["receipt"]["command_kind"] == "task.create"
        assert result["receipt"]["idempotency_key"] == request["idempotency_key"]
        assert _receipt(service, request)["request_hash"] == f["admission_receipt"]["request_hash"]
        assert _receipt(service, request)["primary_stream_id"] == run_id
        for table in before["rows"]:
            if table not in {"command_idempotency", "project_sequences"}:
                assert after["rows"][table] == before["rows"][table], table
        assert after["files"] == before["files"]
        assert service.create_task(copy.deepcopy(request)) == replay
        assert _state(service.store) == after
    assert len(after["rows"]["tasks"]) == len(after["rows"]["runs"]) == len(after["rows"]["attempts"]) == 1
    assert TimelineCommitStore(service.store, validate_prepared=validate_prepared).head(f["project"], "main") == head

    fresh = _request(f, head=head["revision_id"], key="fresh-current-C")
    fresh["spec"]["params"]["expected_version"] = service.store.conn.execute(
        "SELECT version FROM timelines WHERE project_id=? AND id='main'", (f["project"],),
    ).fetchone()[0]
    for field, value in (("canonical_head_revision_id", "parent-1"), ("expected_version", 999)):
        invalid = copy.deepcopy(fresh)
        invalid["spec"]["params"][field] = value
        with pytest.raises(ConflictError, match=field):
            service.create_task(invalid)
        assert _state(service.store) == after
    current = service.create_task(fresh)
    assert current["task"]["id"] != task_id and current["run"]["id"] != run_id
    assert current["task"]["status"] == "queued"
    assert f["C_media"]["object_id"] in current["task"]["spec"]["input_object_ids"]
    assert f["package"]["object_id"] not in current["task"]["spec"]["input_object_ids"]
    assert _snapshot(service, current["task"]["spec"])["config"]["app"] == {"sentinel": "C"}
    assert service.task(task_id) == terminal_task
    assert service.managed_outputs(task_id) == outputs
