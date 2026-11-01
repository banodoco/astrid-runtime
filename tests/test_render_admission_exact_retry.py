"""Admission retransmission, distinct from retrying an admitted worker attempt."""
from __future__ import annotations

import copy
import http.client
import json
import threading

import pytest

from door_helpers import HOSTED, DoorWorld
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.door import DoorConfig
from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest
from test_canonical_render_admission import canonical_scene, _publish, _request, _snapshot
from test_timeline_commit_acceptance import accept, context, prepared, validate_prepared


def _advance(f):
    service = f["service"]
    commits = TimelineCommitStore(service.store, validate_prepared=validate_prepared)
    head = commits.install_verified_baseline(f["project"], "main", authorize=lambda: None)
    ctx = context(service, f["project"], head, key="advance-C")
    candidate = prepared(commits, ctx, revision="parent-C")
    # Trusted host fixture acceptance; no provider meaning or renderer is involved.
    parent = candidate["canonical_document"]["parent_revision"]
    parent["payload"]["config"]["app"] = {"sentinel": "C"}
    media = service.ingest(f["project"], b"C-audio", media_type="audio/wav", idempotency_key="C-audio")["data"]
    parent["payload"]["registry"]["assets"]["music"] = {"media_id": media["object_id"], "type": "audio",
                                                               "content_sha256": media["digest"]}
    candidate["canonical_document"]["dependency_manifest"]["media"] = [
        {"media_id": media["object_id"], "content_digest": media["digest"]},
    ]
    f["C_media"] = media
    parent["content_digest"] = digest(parent["payload"])
    candidate["document_digest"] = digest(candidate["canonical_document"])
    accept(commits, ctx, candidate)
    return commits.head(f["project"], "main")


def _state(store):
    tables = [row[0] for row in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    return {
        "rows": {table: [tuple(row) for row in store.conn.execute(f'SELECT * FROM "{table}"')] for table in tables},
        "files": {str(p.relative_to(store.root)): p.read_bytes() for root in (store.cas_root, store.staging_root)
                  for p in root.rglob("*") if p.is_file()},
    }


def _reopen(f):
    root = f["service"].store.root
    f["service"].close()
    f["service"] = RuntimeService(root)
    return f["service"]


@pytest.mark.parametrize("status", ["queued", "running", "cancelled"])
@pytest.mark.parametrize("pinned", [True, False])
def test_original_admission_after_new_head_and_restart(canonical_scene, status, pinned):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    if not pinned:
        request["spec"]["params"].pop("expected_version")
        request["spec"]["params"].pop("canonical_head_revision_id")
    admitted = f["service"].create_task(copy.deepcopy(request))
    frozen = copy.deepcopy(admitted["task"]["spec"])
    snapshot = _snapshot(f["service"], frozen)
    if status == "running":
        claim = f["service"].claim_next({"executor_id": "worker", "capability_ids": ["rendering.render"],
                                           "runtime_epoch": f["service"].health()["runtime_epoch"]})
        assert claim["task_id"] == admitted["task"]["id"]
    elif status == "cancelled":
        f["service"].cancel_task_canonical(admitted["task"]["id"], idempotency_key="cancel")
    _advance(f)
    service = _reopen(f)
    try:
        current_status = service.task(admitted["task"]["id"])["task"]["status"]
        before = _state(service.store)
        replay = service.create_task(copy.deepcopy(request))
        assert replay["task"]["id"] == admitted["task"]["id"]
        assert replay["run"]["id"] == admitted["run"]["id"]
        assert replay["task"]["spec"] == frozen
        assert replay["task"]["status"] == current_status
        assert f["C_media"]["object_id"] not in replay["task"]["spec"]["input_object_ids"]
        assert _snapshot(service, replay["task"]["spec"]) == snapshot
        assert replay["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["parent_revision_id"] == "parent-1"
        assert _state(service.store) == before
    finally:
        service.close()


def test_door_lost_admission_ack_new_head_restart(canonical_scene, tmp_path, monkeypatch):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    root = f["service"].store.root
    f["service"].close()
    credential_file = tmp_path / "product.json"
    config = DoorConfig(origin=HOSTED, port=0, credential_file=credential_file)
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=config).start()
    world = DoorWorld(tmp_path, daemon, credential_file)
    durable, release = threading.Event(), threading.Event()
    saved = []
    original = daemon.service.create_task

    def lose_ack(*args, **kwargs):
        result = original(*args, **kwargs)
        saved.append(result)
        durable.set()
        assert release.wait(15)
        return result

    monkeypatch.setattr(daemon.service, "create_task", lose_ack)
    connection = http.client.HTTPConnection("127.0.0.1", world.port, timeout=15)
    try:
        world.provision()
        connection.request("POST", "/api/runtime/v1/tasks", json.dumps(request),
                           {"Origin": HOSTED, "Content-Type": "application/json", "Idempotency-Key": request["idempotency_key"]})
        assert durable.wait(15)
        connection.close()  # Close before the durable result can reach the caller.
        release.set()
        f["service"] = daemon.service
        _advance(f)
        world.stop()
        daemon = RuntimeDaemon(root, support_root=tmp_path / "support", door=config).start()
        world = DoorWorld(tmp_path, daemon, credential_file)
        before = _state(daemon.service.store)
        reply = world.call("/api/runtime/v1/tasks", "POST", body=json.dumps(request).encode(),
                           headers={"Content-Type": "application/json", "Idempotency-Key": request["idempotency_key"]})
        assert reply.status == 201, reply.body
        assert reply.json()["data"]["task_id"] == saved[0]["task"]["id"]
        assert reply.json()["data"]["run_id"] == saved[0]["run"]["id"]
        task = daemon.service.task(saved[0]["task"]["id"])["task"]
        assert task["spec"] == saved[0]["task"]["spec"]
        assert task["status"] == "queued"
        assert _state(daemon.service.store) == before
    finally:
        connection.close()
        release.set()
        world.stop()


@pytest.mark.parametrize("changed", ["output", "null-param", "execution-request", "digest", "effect"])
def test_changed_keyed_request_refuses_without_writes(canonical_scene, changed):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    f["service"].create_task(copy.deepcopy(request))
    if changed == "output":
        request["spec"]["params"]["output_name"] = "different.mp4"
    elif changed == "null-param":
        request["spec"]["params"]["profile"] = None
    elif changed == "execution-request":
        request["execution_request"] = {"schema_version": 1, "target": {"kind": "default"}, "inputs": []}
    elif changed == "digest":
        request["capability_digest"] = digest("different-capability")
    else:
        request["settlement_effect"] = {"effect_type": "fixture.changed"}
    before = _state(f["service"].store)
    with pytest.raises(ConflictError, match="idempotency key"):
        f["service"].create_task(request)
    assert _state(f["service"].store) == before


def test_original_request_facts_are_not_retained_in_frozen_identity(canonical_scene):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    admitted = f["service"].create_task(copy.deepcopy(request))
    inputs = admitted["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["input_object_ids"]
    # These distinctions are deliberately collapsed by today's admission contract.
    for patch in ({"spec": {**request["spec"], "inputs": None}},
                  {"spec": {**request["spec"], "inputs": {}}},
                  {"input_object_ids": inputs},
                  {"storage_estimate": {"scratch_bytes": 0, "output_bytes": 0}},
                  {"execution_request": None}):
        before = _state(f["service"].store)
        replay = f["service"].create_task({**copy.deepcopy(request), **patch})
        assert replay == admitted
        assert _state(f["service"].store) == before


def test_new_key_validates_current_head_version_and_objects(canonical_scene):
    f = canonical_scene
    _publish(f)
    original = _request(f)
    admitted = f["service"].create_task(copy.deepcopy(original))
    head = _advance(f)
    request = _request(f, head=head["revision_id"], key="new-render")
    row = f["service"].store.conn.execute(
        "SELECT version FROM timelines WHERE id='main' AND project_id=?", (f["project"],),
    ).fetchone()
    request["spec"]["params"]["expected_version"] = int(row[0])
    for field, value in (("canonical_head_revision_id", "parent-1"), ("expected_version", 999)):
        invalid = copy.deepcopy(request)
        invalid["spec"]["params"][field] = value
        before = _state(f["service"].store)
        with pytest.raises(ConflictError, match=field):
            f["service"].create_task(invalid)
        assert _state(f["service"].store) == before
    invalid = copy.deepcopy(request)
    invalid["input_object_ids"] = [f["audio"]["object_id"]]
    before = _state(f["service"].store)
    with pytest.raises(ConflictError, match="input_object_ids"):
        f["service"].create_task(invalid)
    assert _state(f["service"].store) == before
    current = f["service"].create_task(request)
    assert current["task"]["id"] != admitted["task"]["id"]
    assert current["run"]["id"] != admitted["run"]["id"]
    assert f["C_media"]["object_id"] in current["task"]["spec"]["input_object_ids"]
    assert f["package"]["object_id"] not in current["task"]["spec"]["input_object_ids"]
    assert _snapshot(f["service"], current["task"]["spec"])["config"]["app"] == {"sentinel": "C"}


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
def test_normalized_replay_after_restart_reconstructs_receipt(canonical_scene, receipt):
    from test_task_admission_replay_identity import _receipt_state

    f = canonical_scene
    _publish(f)
    request = _request(f)
    admitted = f["service"].create_task(copy.deepcopy(request))
    media = admitted["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["input_object_ids"]
    _advance(f)
    service = _reopen(f)
    try:
        _receipt_state(service.store, receipt)
        before = _state(service.store)
        for patch in ({"spec": {**request["spec"], "inputs": None}},
                      {"spec": {**request["spec"], "inputs": {"timeline_ref": "main", "selector": "rendering.remotion"}}},
                      {"input_object_ids": [oid.removeprefix("sha256:") for oid in media]},
                      {"storage_estimate": {"scratch_bytes": 0, "output_bytes": 0}},
                      {"execution_request": None}):
            replay = service.create_task({**copy.deepcopy(request), **patch})
            assert replay["task"]["id"] == admitted["task"]["id"]
            assert replay["run"]["id"] == admitted["run"]["id"]
            assert replay["task"]["spec"] == admitted["task"]["spec"]
        after = _state(service.store)
        assert {k: v for k, v in after["rows"].items() if k not in {"command_idempotency", "project_sequences"}} == {
            k: v for k, v in before["rows"].items() if k not in {"command_idempotency", "project_sequences"}}
        assert after["files"] == before["files"]
        assert service.create_task(copy.deepcopy(request))["task"]["id"] == admitted["task"]["id"]
        assert _state(service.store) == after
    finally:
        service.close()


@pytest.mark.parametrize("changed", ["output", "null-param", "execution-request", "digest", "effect", "snapshot", "media", "storage"])
def test_changed_request_after_restart_has_zero_writes(canonical_scene, changed):
    f = canonical_scene
    _publish(f)
    request = _request(f)
    admitted = f["service"].create_task(copy.deepcopy(request))
    _advance(f)
    service = _reopen(f)
    try:
        if changed == "output":
            request["spec"]["params"]["output_name"] = "changed.mp4"
        elif changed == "null-param":
            request["spec"]["params"]["profile"] = None
        elif changed == "execution-request":
            request["execution_request"] = {"schema_version": 1, "target": {"kind": "default"}, "inputs": []}
        elif changed == "digest":
            request["capability_digest"] = digest("changed")
        elif changed == "effect":
            request["settlement_effect"] = {"effect_type": "fixture.changed"}
        elif changed == "snapshot":
            request["spec"]["authority_context"] = {"capture_snapshot": {"config": {"clips": []}, "registry": {}}}
        elif changed == "media":
            request["input_object_ids"] = [f["C_media"]["object_id"]]
        else:
            request["storage_estimate"] = {k: v + 1 for k, v in admitted["task"]["spec"]["storage_estimate"].items()}
        before = _state(service.store)
        with pytest.raises(ConflictError):
            service.create_task(request)
        assert _state(service.store) == before
    finally:
        service.close()


def test_oversized_storage_override_does_not_make_default_equivalent(canonical_scene):
    f = canonical_scene
    _publish(f)
    original = _request(f)
    first = f["service"].create_task(copy.deepcopy(original))
    request = _request(f, key="oversized")
    request["storage_estimate"] = {k: v + 1 for k, v in first["task"]["spec"]["storage_estimate"].items()}
    admitted = f["service"].create_task(copy.deepcopy(request))
    assert admitted["task"]["id"] != first["task"]["id"]
    _advance(f)
    service = _reopen(f)
    try:
        before = _state(service.store)
        assert service.create_task(copy.deepcopy(request))["task"]["id"] == admitted["task"]["id"]
        for estimate in (None, {"scratch_bytes": 0, "output_bytes": 0}):
            changed = copy.deepcopy(request)
            if estimate is None:
                changed.pop("storage_estimate")
            else:
                changed["storage_estimate"] = estimate
            with pytest.raises(ConflictError, match="different input"):
                service.create_task(changed)
            assert _state(service.store) == before
    finally:
        service.close()


def test_render_alias_replays_original_revision_and_rejects_changes(canonical_scene):
    f = canonical_scene
    _publish(f)
    admitted = f["service"].create_task(_request(f))
    alias = _request(f, key="render-alias")
    assert f["service"].create_task(copy.deepcopy(alias))["task"]["id"] == admitted["task"]["id"]
    _advance(f)
    service = _reopen(f)
    try:
        before = _state(service.store)
        assert service.create_task(copy.deepcopy(alias))["task"]["spec"] == admitted["task"]["spec"]
        changed = copy.deepcopy(alias)
        changed["spec"]["authority_context"] = {"capture_snapshot": {"config": {"clips": []}, "registry": {}}}
        with pytest.raises(ConflictError, match="different input"):
            service.create_task(changed)
        assert _state(service.store) == before
    finally:
        service.close()


def test_proven_render_replay_repairs_original_snapshot_after_head_advance(canonical_scene):
    from runtime_protocol.cas import ContentAddressedStore

    f = canonical_scene
    _publish(f)
    request = _request(f)
    admitted = f["service"].create_task(copy.deepcopy(request))
    snapshot = _snapshot(f["service"], admitted["task"]["spec"])
    _advance(f)
    service = _reopen(f)
    try:
        bare = admitted["task"]["spec"]["spec"]["timeline_snapshot_ref"]["digest"].removeprefix("sha256:")
        # Controlled loss of an actual published snapshot, as in inline repair tests.
        with service.store._transaction():
            service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (bare,))
            service.store.conn.execute("DELETE FROM objects WHERE digest=?", (bare,))
        ContentAddressedStore(service.store.cas_root).path_for(bare).unlink()
        before = _state(service.store)
        changed = copy.deepcopy(request)
        changed["spec"]["params"]["output_name"] = "changed.mp4"
        with pytest.raises(ConflictError, match="different input"):
            service.create_task(changed)
        assert _state(service.store) == before
        replay = service.create_task(copy.deepcopy(request))
        assert replay["task"]["id"] == admitted["task"]["id"]
        assert replay["run"]["id"] == admitted["run"]["id"]
        assert replay["task"]["spec"] == admitted["task"]["spec"]
        assert _snapshot(service, replay["task"]["spec"]) == snapshot
        after = _state(service.store)
        assert after["rows"]["tasks"] == before["rows"]["tasks"]
        assert after["rows"]["runs"] == before["rows"]["runs"]
        assert after["rows"]["events"] == before["rows"]["events"]
    finally:
        service.close()


def test_old_admission_without_retained_floor_requires_current_full_equivalence(canonical_scene, monkeypatch):
    f = canonical_scene
    _publish(f)
    store = f["service"].store
    original = store._store_spec

    def legacy_spec(spec):
        spec = dict(spec)
        spec.pop("_runtime_render_admission", None)
        return original(spec)

    # Persist the older spec shape through real admission, without inventing history.
    request = _request(f)
    request["spec"]["params"].pop("expected_version")
    request["spec"]["params"].pop("canonical_head_revision_id")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_store_spec", legacy_spec)
        admitted = f["service"].create_task(copy.deepcopy(request))
    before = _state(store)
    assert f["service"].create_task(copy.deepcopy(request)) == admitted
    assert _state(store) == before
    _advance(f)
    service = _reopen(f)
    try:
        before = _state(service.store)
        with pytest.raises(ConflictError):
            service.create_task(copy.deepcopy(request))
        assert _state(service.store) == before
    finally:
        service.close()


def test_replay_uses_saved_digest_but_fresh_key_still_checks_readiness(canonical_scene):
    from runtime_protocol.errors import CapabilityUnavailableError

    f = canonical_scene
    _publish(f)
    request = _request(f)
    admitted = f["service"].create_task(copy.deepcopy(request))
    head = _advance(f)
    service = _reopen(f)
    try:
        service.register_capability({"capability_id": "rendering.render", "definition_digest": request["capability_digest"],
                                     "status": "unavailable", "unavailable_reason": "fixture-renderer-offline"})
        before = _state(service.store)
        replay = service.create_task(copy.deepcopy(request), enforce_readiness=True)
        assert replay["task"]["id"] == admitted["task"]["id"]
        assert replay["task"]["spec"] == admitted["task"]["spec"]
        assert _state(service.store) == before
        fresh = _request(f, head=head["revision_id"], key="fresh-offline")
        fresh["spec"]["params"]["expected_version"] = service.store.conn.execute(
            "SELECT version FROM timelines WHERE id='main' AND project_id=?", (f["project"],),
        ).fetchone()[0]
        with pytest.raises(CapabilityUnavailableError):
            service.create_task(fresh, enforce_readiness=True)
        after = _state(service.store)
        for table in ("tasks", "runs", "events"):
            assert after["rows"][table] == before["rows"][table]
    finally:
        service.close()


def test_bound_execution_request_and_effect_keep_independent_replay_identity(canonical_scene):
    f = canonical_scene
    _publish(f)
    first = f["service"].create_task(_request(f))
    request = _request(f, key="bound-render")
    request["input_object_ids"] = first["task"]["spec"]["spec"]["inputs"]["timeline_authority"]["input_object_ids"]
    request["execution_request"] = {
        "schema_version": 1, "target": {"kind": "machine", "machine_id": "render-machine"},
        "creative_options": {"value": True},
    }
    project = f["service"].get_project(f["project"])
    request["settlement_effect"] = {"effect_type": "project.update", "target_id": project["id"],
                                    "expected_version": project["version"], "payload": {"metadata": {"value": True}}}
    admitted = f["service"].create_task(copy.deepcopy(request))
    _advance(f)
    service = _reopen(f)
    try:
        before = _state(service.store)
        replay = service.create_task(copy.deepcopy(request))
        assert replay["task"]["id"] == admitted["task"]["id"]
        assert replay["task"]["spec"] == admitted["task"]["spec"]
        assert replay["task"]["execution_request"] == admitted["task"]["execution_request"]
        assert replay["task"]["expected_effect"] == request["settlement_effect"]
        for field in ("execution_request", "settlement_effect"):
            changed = copy.deepcopy(request)
            value = changed[field]["payload"]["metadata"] if field == "settlement_effect" else changed[field]["creative_options"]
            value["value"] = 1  # JSON true and 1 remain distinct after normalization.
            with pytest.raises(ConflictError, match="different input"):
                service.create_task(changed)
            assert _state(service.store) == before
    finally:
        service.close()
