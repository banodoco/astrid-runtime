"""Compatibility checks for render admission replay and snapshot custody."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from runtime_protocol.cas import ContentAddressedStore
from runtime_protocol.errors import NotFoundError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore, expired_command_result
from runtime_protocol.util import canonical_json
from test_canonical_render_admission import _accept_publication, _publish, _request, canonical_scene
from test_timeline_commit_port import PreparedProvider


def _digest(value):
    encoded = value.encode() if isinstance(value, str) else canonical_json(value).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@pytest.fixture
def inline_snapshot_scene(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project = service.create_project(
            {"slug": "snapshot-replay", "name": "Snapshot replay"}, idempotency_key="project"
        )["id"]
        service.register_timeline_commit_provider(PreparedProvider())
        service.create_timeline(project, "main", idempotency_key="timeline")
        capability_digest = _digest("synthetic.render")
        service.register_capability(
            {"capability_id": "synthetic.render", "definition_digest": capability_digest}
        )
        publication = {
            "project_id": project,
            "timeline_id": "main",
            "expected_head": None,
            "parent_revision_id": "revision-1",
            "parent_composition": {
                "config": {"clips": []},
                "registry": {},
                "clips": [],
                "occurrences": [],
            },
            "shot_revisions": [],
            "internal_timeline_revisions": [],
            "dependency_manifest": {"media": [], "shots": [], "internal_timelines": []},
        }
        _accept_publication({"service": service, "project": project}, publication, idempotency_key="publish")
        snapshot = {"config": {"clips": [{"id": "saved", "hold": 2}]}, "registry": {}}
        authority = {
            "project_id": project,
            "timeline_id": "main",
            "parent_revision_id": "revision-1",
            "parent_content_digest": _digest(publication["parent_composition"]),
        }
        yield {
            "service": service,
            "project": project,
            "capability_digest": capability_digest,
            "snapshot": snapshot,
            "authority": authority,
        }
    finally:
        service.close()


def _inline_request(scene, *, key="render"):
    return {
        "project": scene["project"],
        "capability_id": "synthetic.render",
        "capability_digest": scene["capability_digest"],
        "input_object_ids": [],
        "idempotency_key": key,
        "spec": {
            "timeline_snapshot": copy.deepcopy(scene["snapshot"]),
            "inputs": {"timeline_authority": copy.deepcopy(scene["authority"])},
        },
    }


def _admission_state(service):
    """State whose mutation would duplicate the accepted task or its bytes."""
    tables = ("tasks", "runs", "events", "task_specs", "objects", "project_objects")
    return {
        "tables": {
            table: [tuple(row) for row in service.store.conn.execute(f'SELECT * FROM "{table}" ORDER BY rowid')]
            for table in tables
        },
        "files": {
            str(path.relative_to(service.store.root)): path.read_bytes()
            for root in (service.store.cas_root, service.store.staging_root)
            for path in root.rglob("*")
            if path.is_file()
        },
    }


def _remove_snapshot(scene, ref):
    service = scene["service"]
    bare = ref["digest"].removeprefix("sha256:")
    with service.store._transaction():
        service.store.conn.execute("DELETE FROM project_objects WHERE digest=?", (bare,))
        service.store.conn.execute("DELETE FROM objects WHERE digest=?", (bare,))
    ContentAddressedStore(service.store.cas_root).path_for(bare).unlink()


def test_same_head_inline_and_equivalent_cas_snapshot_forms_replay_same_admission(inline_snapshot_scene):
    scene = inline_snapshot_scene
    service = scene["service"]
    first = service.create_task(_inline_request(scene))
    ref = first["task"]["spec"]["spec"]["timeline_snapshot_ref"]

    cas_request = _inline_request(scene)
    cas_request["input_object_ids"] = [ref["digest"]]
    cas_request["spec"].pop("timeline_snapshot")
    cas_request["spec"]["timeline_snapshot_ref"] = copy.deepcopy(ref)
    before = _admission_state(service)

    replay = service.create_task(cas_request)

    assert replay == first
    assert _admission_state(service) == before


@pytest.mark.parametrize("receipt_damage", ["missing", "expired"])
def test_same_head_render_replay_reconstructs_missing_or_expired_receipt_without_duplicate_admission(
    inline_snapshot_scene, receipt_damage
):
    scene = inline_snapshot_scene
    service = scene["service"]
    request = _inline_request(scene)
    first = service.create_task(copy.deepcopy(request))
    receipt = service.store.conn.execute(
        "SELECT * FROM command_idempotency WHERE command_kind='task.create' AND idempotency_key=?",
        (request["idempotency_key"],),
    ).fetchone()
    assert receipt is not None
    if receipt_damage == "missing":
        service.store.conn.execute(
            "DELETE FROM command_idempotency WHERE command_kind='task.create' AND idempotency_key=?",
            (request["idempotency_key"],),
        )
    else:
        service.store.conn.execute(
            "UPDATE command_idempotency SET result_json=? WHERE command_kind='task.create' AND idempotency_key=?",
            (expired_command_result(receipt["result_json"]), request["idempotency_key"]),
        )
    service.store.conn.commit()
    before = _admission_state(service)

    replay = service.create_task(request)

    assert replay == first
    assert _admission_state(service) == before
    rebuilt = service.store.conn.execute(
        "SELECT * FROM command_idempotency WHERE command_kind='task.create' AND idempotency_key=?",
        (request["idempotency_key"],),
    ).fetchone()
    assert rebuilt is not None
    if receipt_damage == "missing":
        assert rebuilt["primary_stream_id"] == first["run"]["id"]
        assert json.loads(rebuilt["event_ids_json"]) == []
    else:
        assert rebuilt["result_json"] == expired_command_result(receipt["result_json"])


def test_same_head_normalized_execution_request_alias_replays_without_snapshot_or_task_writes(canonical_scene):
    scene = canonical_scene
    service = scene["service"]
    _publish(scene)
    request = _request(scene, key="normalized-execution-request")
    request["execution_request"] = {
        "schema_version": 1,
        "target": {"kind": "profile", "profile_alias": "h3"},
    }
    first = service.create_task(copy.deepcopy(request))
    alias_form = copy.deepcopy(request)
    alias_form["execution_request"]["target"] = {"kind": "profile", "id": "h3"}
    before = _admission_state(service)

    replay = service.create_task(alias_form)

    assert replay == first
    assert replay["task"]["execution_request"]["target"] == {"kind": "profile", "id": "h3"}
    assert _admission_state(service) == before


def test_inline_snapshot_replay_repairs_missing_cas_object_but_cas_only_form_refuses_atomically(
    inline_snapshot_scene,
):
    scene = inline_snapshot_scene
    service = scene["service"]
    request = _inline_request(scene)
    first = service.create_task(copy.deepcopy(request))
    ref = first["task"]["spec"]["spec"]["timeline_snapshot_ref"]
    _remove_snapshot(scene, ref)

    repaired = service.create_task(copy.deepcopy(request))

    assert repaired == first
    assert service.object(ref["digest"])[1] == canonical_json(scene["snapshot"]).encode()
    assert service.store.conn.execute(
        "SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
        (scene["project"], ref["digest"].removeprefix("sha256:")),
    ).fetchone() is not None

    _remove_snapshot(scene, ref)
    cas_request = _inline_request(scene)
    cas_request["input_object_ids"] = [ref["digest"]]
    cas_request["spec"].pop("timeline_snapshot")
    cas_request["spec"]["timeline_snapshot_ref"] = copy.deepcopy(ref)
    before = _admission_state(service)
    with pytest.raises(NotFoundError, match="missing or corrupt"):
        service.create_task(cas_request)
    assert _admission_state(service) == before
