"""Persisted admission identity fences legacy receipt refresh/reconstruction."""
from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.cas import ContentAddressedStore
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError
from runtime_protocol.store import (
    GENERATION_INTENT_STORAGE_KEY,
    LEGACY_GENERATION_INTENT_STORAGE_KEY,
    RealmStore,
)

CAPABILITY = "fixture.replay-identity"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def store(tmp_path):
    store = RealmStore.initialize(tmp_path / "realm")
    store.begin_runtime_session("replay-test-session")
    try:
        yield store
    finally:
        store.close()


def _admit(store, *, spec=None, effect=None, digest=DIGEST, request=None, project=None):
    return store.create_task(CAPABILITY, spec if spec is not None else {"message": "hello"},
        idempotency_key="same-admission", expected_effect=effect, capability_digest=digest,
        execution_request=request, project=project)


def _effect(store, metadata):
    project = store.create_project("replay-effect", "Replay effect")
    return {"effect_type": "project.update", "target_id": project["id"],
            "expected_version": project["version"], "payload": {"metadata": metadata}}


def _receipt_state(store, mode):
    if mode in {"partial_current", "partial_stale"}:
        store.conn.execute("UPDATE command_idempotency SET txn_id=NULL, primary_stream_id=NULL, resulting_stream_seq=NULL, first_project_seq=NULL, last_project_seq=NULL, event_ids_json=NULL WHERE command_kind='task.create'")
    if mode in {"stale", "partial_stale"}:
        store.conn.execute("UPDATE command_idempotency SET request_hash='legacy-stale-hash' WHERE command_kind='task.create'")
    elif mode == "absent":
        store.conn.execute("DELETE FROM command_idempotency WHERE command_kind='task.create'")
    store.conn.commit()


def _snapshot(store):
    tables = [row[0] for row in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    return {
        **{table: [dict(row) for row in store.conn.execute(f'SELECT * FROM "{table}" ORDER BY rowid')]
           for table in tables},
        "files": {str(path.relative_to(store.root)): path.read_bytes()
                  for root in (store.cas_root, store.staging_root)
                  for path in root.rglob("*") if path.is_file()},
    }


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("changed", ["effect", "digest", "removed_effect", "effect_scalar_type"])
def test_changed_effect_or_digest_conflicts_without_mutating_any_admission_evidence(store, receipt, changed):
    effect = _effect(store, {"value": True})
    _admit(store, effect=effect)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    requested_effect, requested_digest = copy.deepcopy(effect), DIGEST
    if changed == "effect":
        requested_effect["payload"]["metadata"]["value"] = False
    elif changed == "digest":
        requested_digest = OTHER_DIGEST
    elif changed == "removed_effect":
        requested_effect = None
    else:
        requested_effect["payload"]["metadata"]["value"] = 1  # JSON true and 1 are distinct identity.
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, effect=requested_effect, digest=requested_digest)
    assert _snapshot(store) == before


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("changed", ["spec", "execution_request"])
def test_json_boolean_and_number_are_distinct_replay_identity(store, receipt, changed):
    spec = {"value": True}
    request = {
        "schema_version": 1,
        "target": {"kind": "machine", "id": "chosen-machine"},
        "inputs": [],
        "creative_options": {"value": True},
    }
    admitted = _admit(store, spec=spec, request=request)
    _receipt_state(store, receipt)
    before = _snapshot(store)

    if changed == "spec":
        spec = {"value": 1}
    else:
        request["creative_options"]["value"] = 1
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, spec=spec, request=request)

    assert _snapshot(store) == before
    assert _admit(store, spec={"value": True}, request={
        "schema_version": 1,
        "target": {"kind": "machine", "id": "chosen-machine"},
        "inputs": [],
        "creative_options": {"value": True},
    }) == admitted


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("requested_effect", [None, {}])
@pytest.mark.parametrize("omit_digest", [False, True])
def test_no_effect_and_omitted_digest_remain_compatible_with_persisted_evidence(store, receipt, requested_effect, omit_digest):
    admitted = _admit(store)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, effect=requested_effect, digest=None if omit_digest else DIGEST)
    assert replay["task"]["id"] == admitted["task"]["id"]
    after = _snapshot(store)
    assert after["tasks"] == before["tasks"]
    assert after["runs"] == before["runs"]
    assert after["events"] == before["events"]
    assert len(after["command_idempotency"]) == 1
    row = after["command_idempotency"][0]
    assert row["txn_id"] and row["first_project_seq"] and row["last_project_seq"]
    if receipt in {"current", "stale"}:
        saved = before["command_idempotency"][0]
        assert {key: value for key, value in row.items() if key not in {"request_hash", "result_json"}} == {key: value for key, value in saved.items() if key not in {"request_hash", "result_json"}}
    else:
        assert json.loads(row["event_ids_json"]) == []
    assert _admit(store, effect=requested_effect, digest=None if omit_digest else DIGEST) == replay


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_equivalent_effect_mapping_order_refreshes_without_rewriting_task(store, receipt):
    effect = _effect(store, {"nested": {"first": 1, "second": 2}})
    admitted = _admit(store, effect=effect)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    reordered = {**dict(reversed(list(effect.items()))),
                 "payload": {"metadata": {"nested": {"second": 2, "first": 1}}}}
    replay = _admit(store, effect=reordered)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_legacy_nested_request_and_intent_refresh_only_equivalent_admission(store, receipt):
    request = {"schema_version": 1, "target": {"kind": "machine", "id": "chosen-machine"}, "inputs": []}
    intent = {"modality": "video", "members": [{"ordinal": 0}]}
    spec = {"message": "hello", GENERATION_INTENT_STORAGE_KEY: intent}
    admitted = _admit(store, spec=spec, request=request)
    # Represent precisely the inventoried pre-correction outer-spec shape.
    legacy = {"message": "hello", LEGACY_GENERATION_INTENT_STORAGE_KEY: intent, "execution_request": request}
    legacy_digest = store._store_spec(legacy)
    store.conn.execute("UPDATE tasks SET spec_digest=?, execution_request_json=NULL", (legacy_digest,))
    store.conn.execute("UPDATE runs SET spec_digest=?", (legacy_digest,))
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, spec=spec, request=request)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert replay["task"]["execution_request"] == request
    assert replay["task"]["generation_intent"] == intent
    after = _snapshot(store)
    assert after["tasks"] == before["tasks"] and after["runs"] == before["runs"]
    assert after["events"] == before["events"]
    assert len(after["command_idempotency"]) == 1
    assert _admit(store, spec=spec, request=request) == replay
    bad_intent = {**spec, GENERATION_INTENT_STORAGE_KEY: {**intent, "modality": "image"}}
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, spec=bad_intent, request=request)
    assert _snapshot(store) == after


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_explicit_digest_can_use_consistent_legacy_spec_evidence(store, receipt):
    spec = {"capability_digest": DIGEST, "message": "hello"}
    admitted = _admit(store, spec=spec)
    store.conn.execute("UPDATE tasks SET capability_digest=NULL")
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, spec=spec)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("missing", ["task", "digest", "inconsistent_digest"])
def test_insufficient_or_conflicting_persisted_identity_fails_closed(store, receipt, missing):
    spec = {"capability_digest": DIGEST} if missing == "inconsistent_digest" else {"message": "hello"}
    _admit(store, spec=spec)
    if missing == "task":
        store.conn.execute("DELETE FROM tasks")
    elif missing == "digest":
        store.conn.execute("UPDATE tasks SET capability_digest=NULL")
    elif missing == "inconsistent_digest":
        store.conn.execute("UPDATE tasks SET capability_digest=?", (OTHER_DIGEST,))
    _receipt_state(store, receipt)
    before = _snapshot(store)
    with pytest.raises(ConflictError):
        _admit(store, spec=spec)
    assert _snapshot(store) == before


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_current_catalog_is_not_persisted_replay_digest_authority(store, receipt):
    admitted = _admit(store)
    store.register_capability(CAPABILITY, OTHER_DIGEST, status="unavailable")
    _receipt_state(store, receipt)
    replay = _admit(store)
    assert replay["task"]["id"] == admitted["task"]["id"]


def test_generated_http_concurrent_exact_requests_converge_and_changed_effect_conflicts(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root).start()
    try:
        daemon.service.register_capability({"capability_id": CAPABILITY, "definition_digest": DIGEST})
        arguments = dict(capability_id=CAPABILITY, capability_digest=DIGEST, input_object_ids=[],
                        idempotency_key="concurrent-admission", settlement_effect=_effect(daemon.service.store, {}))
        def admit(_):
            return WorkspaceClient(daemon.endpoint, daemon.token).admit_task(**arguments)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(admit, range(2)))
        assert results[0] == results[1]
        before = _snapshot(daemon.service.store)
        with pytest.raises(ApiError) as conflict:
            WorkspaceClient(daemon.endpoint, daemon.token).admit_task(**{**arguments, "settlement_effect": None})
        assert conflict.value.code == "conflict"
        assert _snapshot(daemon.service.store) == before
    finally:
        daemon.stop()


@pytest.mark.parametrize("receipt", ["current", "stale", "absent", "partial_current", "partial_stale"])
@pytest.mark.parametrize("registered", [False, True])
def test_initially_omitted_digest_replays_without_inventing_new_digest(store, receipt, registered):
    if registered:
        store.register_capability(CAPABILITY, DIGEST)
    admitted = _admit(store, digest=None)
    assert admitted["task"]["capability_digest"] == (DIGEST if registered else None)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, digest=None)
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_persisted_empty_effect_uses_existing_no_effect_semantics(store, receipt):
    admitted = _admit(store)
    store.conn.execute("UPDATE tasks SET expected_effect_json='{}'")
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, effect={})
    assert replay["task"]["id"] == admitted["task"]["id"]
    assert _snapshot(store)["tasks"] == before["tasks"]
    assert _snapshot(store)["runs"] == before["runs"]


@pytest.mark.parametrize("receipt", ["stale", "absent", "partial_current", "partial_stale"])
def test_generated_http_equivalent_reconstruction_returns_valid_receipt_without_task_events(tmp_path, receipt):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root).start()
    try:
        daemon.service.register_capability({"capability_id": CAPABILITY, "definition_digest": DIGEST})
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        arguments = dict(capability_id=CAPABILITY, capability_digest=DIGEST, input_object_ids=[], idempotency_key="same-admission")
        first = client.admit_task(**arguments)
        store = daemon.service.store
        _receipt_state(store, receipt)
        before = _snapshot(store)
        replay = client.admit_task(**arguments)
        assert replay["task_id"] == first["task_id"] and replay["run_id"] == first["run_id"]
        assert replay.receipt["receipt_id"]
        assert replay.receipt["command_kind"] == "task.create"
        assert replay.receipt["project_seq"][0] > 0
        assert replay.receipt["project_seq"][1] >= replay.receipt["project_seq"][0]
        after = _snapshot(store)
        assert after["tasks"] == before["tasks"] and after["runs"] == before["runs"]
        assert after["events"] == before["events"]
        if receipt == "stale":
            assert replay.receipt["receipt_id"] == first.receipt["receipt_id"]
            assert replay.receipt["project_seq"] == first.receipt["project_seq"]
        else:
            assert replay.receipt["event_ids"] == []
        second_replay = client.admit_task(**arguments)
        assert second_replay.receipt == replay.receipt
        assert _snapshot(store) == after
    finally:
        daemon.stop()


def test_unkeyed_store_admission_still_creates_fresh_tasks(store):
    first = store.create_task(CAPABILITY, {"message": "hello"})
    second = store.create_task(CAPABILITY, {"message": "hello"})
    assert first["task"]["id"] != second["task"]["id"]


@pytest.mark.parametrize("receipt", ["current", "stale", "absent"])
@pytest.mark.parametrize("changed", ["effect", "digest", "execution_request", "spec"])
def test_changed_snapshot_and_identity_refuse_before_any_store_publication(store, receipt, changed):
    project = store.create_project("snapshot-replay", "Snapshot replay")["id"]
    snapshot = {"config": {"clips": [], "metadata": {"value": True}}, "registry": {}}
    spec = {"timeline_snapshot": snapshot}
    request = {"schema_version": 1, "target": {"kind": "machine", "id": "chosen-machine"}}
    _admit(store, spec=spec, request=request, project=project)
    _receipt_state(store, receipt)
    before = _snapshot(store)
    changed_spec = copy.deepcopy(spec)
    changed_spec["timeline_snapshot"]["config"]["metadata"]["value"] = False
    arguments = {"spec": changed_spec, "request": request, "project": project}
    if changed == "effect":
        arguments["effect"] = {"effect_type": "timeline.update", "target_id": "unused"}
    elif changed == "digest":
        arguments["digest"] = OTHER_DIGEST
    elif changed == "execution_request":
        arguments["request"] = {**request, "creative_options": {"changed": True}}
    with pytest.raises(ConflictError, match="different input"):
        _admit(store, **arguments)
    assert _snapshot(store) == before


@pytest.mark.parametrize("receipt", ["current", "stale", "absent"])
@pytest.mark.parametrize("location", ["timeline", "inputs", "filmstrip", "input", "capture"])
def test_exact_inline_snapshot_keeps_published_spec_and_admission_hash(store, receipt, location):
    project = store.create_project("snapshot-replay", "Snapshot replay")["id"]
    snapshot = {"config": {"clips": [], "metadata": {"keep": True}}, "registry": {}}
    # The existing publisher is the independent identity oracle. Preparation
    # must produce exactly its ref, including revision provenance and source kind.
    ref = store._publish_spec_snapshot(snapshot, {}, project)
    if location == "timeline":
        spec, expected = {"timeline_snapshot": snapshot}, {"timeline_snapshot_ref": ref}
    elif location == "inputs":
        spec = {"inputs": {"timeline_snapshot": snapshot}}
        expected = {"inputs": {"timeline_snapshot_ref": ref}}
    else:
        key = location + "_snapshot"
        spec = {"authority_context": {key: snapshot}}
        expected = {"authority_context": {key + "_ref": ref}}
    expected["input_object_ids"] = [ref["digest"]]
    first = _admit(store, spec=spec, project=project)
    assert first["task"]["spec"] == expected
    original_hash = store.conn.execute("SELECT request_hash FROM command_idempotency WHERE command_kind='task.create'").fetchone()[0]
    _receipt_state(store, receipt)
    before = _snapshot(store)
    replay = _admit(store, spec=spec, project=project)
    assert replay["task"]["id"] == first["task"]["id"]
    assert replay["task"]["spec"] == expected
    after = _snapshot(store)
    assert {key: value for key, value in after.items() if key not in {"command_idempotency", "project_sequences"}} == {
        key: value for key, value in before.items() if key not in {"command_idempotency", "project_sequences"}}
    assert after["command_idempotency"][0]["request_hash"] == original_hash
    assert _admit(store, spec=spec, project=project) == replay
    assert _snapshot(store) == after


@pytest.mark.parametrize("receipt", ["current", "stale", "absent"])
def test_proven_exact_replay_retains_inline_snapshot_republication(store, receipt):
    project = store.create_project("snapshot-repair", "Snapshot repair")["id"]
    spec = {"timeline_snapshot": {"config": {"clips": []}, "registry": {}}}
    first = _admit(store, spec=spec, project=project)
    digest = first["task"]["spec"]["timeline_snapshot_ref"]["digest"].removeprefix("sha256:")
    cas = ContentAddressedStore(store.cas_root)
    payload = cas.read(digest)
    # Controlled storage damage: equivalent inline retries have always been
    # able to republish missing snapshot bytes and associations.
    store.conn.execute("DELETE FROM project_objects WHERE digest=?", (digest,))
    store.conn.execute("DELETE FROM objects WHERE digest=?", (digest,))
    cas.path_for(digest).unlink()
    _receipt_state(store, receipt)
    task_before = _snapshot(store)["tasks"]
    assert _admit(store, spec=spec, project=project)["task"]["id"] == first["task"]["id"]
    assert cas.read(digest) == payload
    assert store.conn.execute("SELECT size FROM objects WHERE digest=?", (digest,)).fetchone()[0] == len(payload)
    assert store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'", (project, digest)).fetchone()
    assert _snapshot(store)["tasks"] == task_before
