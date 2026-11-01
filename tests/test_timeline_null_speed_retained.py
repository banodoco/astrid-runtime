"""Retained reads after trusted TEST SETUP, not Agent semantic acceptance.

The legacy visual publisher rejects speed:null. PreparedProvider supplies the
already prepared images only at Runtime's existing test acceptance boundary;
normal scope, authority, closure, digest, receipt and event checks still run.
No immutable image or accepted history is rewritten by this fixture.
"""
from __future__ import annotations

import copy
import json

import pytest

from astrid_runtime_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import RetiredRouteError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import digest, route_path
from runtime_protocol.util import canonical_json
from test_timeline_commit_port import PreparedProvider
from test_timeline_native_inspection import _clip, _parent_clip, _project_speed, _publication, _publish, _service


def _cas_bytes(service):
    root = service.store.cas_root
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _images(service):
    return {table: [tuple(row) for row in service.store.conn.execute(f"SELECT * FROM {table} ORDER BY id")]
            for table in ("parent_composition_revisions", "shot_revisions", "internal_timeline_revisions")}


def _trusted_setup(tmp_path, speed):
    service, project, root = _service(tmp_path)
    try:
        media = service.ingest(project, b"retained-speed-media", media_type="video/mp4",
                               original_name="speed.mp4", idempotency_key="speed-media")["data"]["object_id"]
        publication = _publication(project)
        publication["parent_composition"]["occurrences"] = publication["parent_composition"]["occurrences"][:1]
        for payload, clip in (
                (publication["parent_composition"], _parent_clip("parent", duration_ms=500)),
                (publication["internal_timeline_revisions"][0]["payload"], _clip("child"))):
            payload["clips"] = [{**clip, "asset": "picture", "extension": {"keep": [None, True]}}]
            payload["registry"] = {"assets": {"picture": {"object_id": media, "type": "video"}}}
        _publish(service, project, publication, idempotency_key="valid-public-seed")
        prepared_values = []

        def prepare(context, port):
            head = port.head()
            document = port.revision_closure(head["revision_id"])
            parent = document["parent_revision"]
            before = {k: parent[k] for k in ("revision_id", "content_digest")}
            internal = document["internal_timeline_revisions"][0]
            internal["revision_id"] = "trusted-internal"
            internal["payload"]["clips"][0]["speed"] = copy.deepcopy(speed)
            internal["content_digest"] = digest(internal["payload"])
            shot = document["shot_revisions"][0]
            shot["revision_id"] = "trusted-shot"
            shot["internal_timeline_revision_id"] = internal["revision_id"]
            shot["payload"]["internal_timeline_revision_id"] = internal["revision_id"]
            shot["content_digest"] = digest(shot["payload"])
            parent["revision_id"] = "trusted-parent"
            parent["payload"]["clips"][0]["speed"] = copy.deepcopy(speed)
            parent["payload"]["occurrences"][0]["shot_revision_id"] = shot["revision_id"]
            parent["content_digest"] = digest(parent["payload"])
            document["dependency_manifest"]["shots"] = [
                {k: shot[k] for k in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}]
            document["dependency_manifest"]["internal_timelines"] = [
                {k: internal[k] for k in ("timeline_id", "revision_id", "content_digest")}]
            record = {"ordinal": 0, "command": copy.deepcopy(context["request"]["commands"][0]),
                      "writes": [{"ref": "timeline", "path": [], "before": {"state": "present", "value": before},
                                  "after": {"state": "present", "value": {
                                      k: parent[k] for k in ("revision_id", "content_digest")}}}],
                      "reads": [{"ref": "timeline", "path": [], "state": {"state": "present", "value": before}}],
                      "selections": [], "bindings": [], "created": [], "dependencies": [], "derived_writes": []}
            value = {"expected_head": head, "canonical_document": document, "document_digest": digest(document),
                     "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
                     "id_map": {}, "semantic_events": [], "provider_version": "trusted-test-setup-1",
                     "compiler_version": "trusted-test-setup-1"}
            prepared_values.append(copy.deepcopy(value))
            return port.accept(value)

        provider = PreparedProvider(prepare)
        service.register_timeline_commit_provider(provider)
        initial = service.get_project_timeline(project, "main")
        base = {"revision_id": initial["head_revision_id"], "publication_id": initial["head_publication_id"]}
        body = {"api_version": 1, "project_id": project, "timeline_id": "main",
                "base_revision_id": base["revision_id"], "base_publication_id": base["publication_id"],
                "commands": [{"schema_version": 1, "op": "clip.move", "version": "1",
                              "select": "parent/clip:parent", "args": {"on": 0}}],
                "rationale": "Trusted TEST SETUP for retained inspection; not Agent semantic acceptance"}
        authorized = []
        accepted = service.commit_timeline(
            project, "main", body, idempotency_key="trusted-speed", publisher="trusted-test-setup",
            invocation_path=route_path(project, "main"), authorize=lambda: authorized.append(project),
        )
        assert authorized and provider.calls == 1
        value = prepared_values[0]
        assert accepted["data"]["canonical_document"] == value["canonical_document"]
        receipt = accepted["receipt"]
        assert receipt["command_kind"] == "timeline.commit"
        assert receipt["result"] == accepted["data"]
        event = service.store.conn.execute("SELECT * FROM timeline_events WHERE id=?", (receipt["event_ids"][0],)).fetchone()
        assert event["kind"] == "timeline.commit.accepted"
        assert json.loads(event["payload_json"])["previous"] == base
        assert json.loads(event["payload_json"])["records_digest"] == digest(value["records"])
        assert service.store.integrity_report()["ok"]
        return project, root, accepted, value, _images(service), _cas_bytes(service)
    finally:
        service.close()


def _assert_reads(reader, project, accepted, speed, expected_speed, expected_duration):
    document = accepted["data"]["canonical_document"]
    parent = document["parent_revision"]
    internal = document["internal_timeline_revisions"][0]
    shot = document["shot_revisions"][0]
    head = reader.get_project_timeline(project, "main")
    assert head["head_revision_id"] == parent["revision_id"]
    assert head["head_publication_id"] == accepted["receipt"]["receipt_id"]
    for options in ({}, {"revision_id": parent["revision_id"]}):
        result = reader.inspect_timeline(project, "main", options)
        assert result["revision_id"] == parent["revision_id"]
        for projected, image in ((result["selected"][0]["clips"][0], internal),
                                 (result["selected_parent_clips"][0], parent)):
            assert projected["speed"] == expected_speed
            assert projected["duration"] == expected_duration
            assert canonical_json(projected["authored_fields"]) == canonical_json(image["payload"]["clips"][0])
            assert canonical_json(projected["authored_timing"]["speed"]) == canonical_json(speed)
    for image, stored in (
            (parent, reader.get_project_parent_composition_revision(project, "main", parent["revision_id"])),
            (internal, reader.get_project_timeline_revision(project, internal["timeline_id"], internal["revision_id"])),
            (shot, reader.get_project_shot_revision(project, shot["shot_id"], shot["revision_id"]))):
        assert canonical_json(stored["payload"]) == canonical_json(image["payload"])
        assert stored["content_digest"] == image["content_digest"]


def _assert_history(history, accepted, value):
    entry = history["items"][-1]
    assert entry["receipt"] == accepted["receipt"]
    assert entry["records"] == value["records"]
    assert entry["intent"] == "recorded"
    assert history["head"] == {"revision_id": "trusted-parent", "publication_id": accepted["receipt"]["receipt_id"]}


@pytest.mark.parametrize(("speed", "expected_speed", "expected_duration"), [
    (None, [1, 1], [1, 2]),
    ([3, 2], [3, 2], [1, 3]),
    ("3/2", [3, 2], [1, 3]),
])
def test_trusted_speed_images_survive_reopen_without_read_writes(tmp_path, speed, expected_speed, expected_duration):
    project, root, accepted, value, images, cas = _trusted_setup(tmp_path, speed)
    service = RuntimeService(root)
    try:
        assert service.store.admission_report["ok"]
        before = tuple(service.store.conn.iterdump())
        _assert_reads(service, project, accepted, speed, expected_speed, expected_duration)
        _assert_history(service.list_timeline_commits(project, "main", authorize=lambda: None), accepted, value)
        commits, _ = service._timeline_commits()
        assert commits.revision_closure(project, "main", "trusted-parent") == value["canonical_document"]
        assert commits.integrity_errors() == []
        assert _images(service) == images
        assert _cas_bytes(service) == cas
        assert tuple(service.store.conn.iterdump()) == before
    finally:
        service.close()


def test_trusted_null_speed_native_http_reads_preserve_images_and_receipt(tmp_path):
    project, root, accepted, value, images, cas = _trusted_setup(tmp_path, None)
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        before = tuple(daemon.service.store.conn.iterdump())
        _assert_reads(client, project, accepted, None, [1, 1], [1, 2])
        _assert_history(client.list_timeline_commits(project, "main"), accepted, value)
        assert _images(daemon.service) == images
        assert _cas_bytes(daemon.service) == cas
        assert tuple(daemon.service.store.conn.iterdump()) == before
    finally:
        daemon.stop()


@pytest.mark.parametrize("scope", ["child", "parent"])
@pytest.mark.parametrize("field", ["at_ms", "duration_ms"])
def test_null_start_and_duration_remain_invalid(scope, field):
    raw = {**_clip("invalid"), "speed": None, field: None}
    before = canonical_json(raw)
    with pytest.raises(ValidationError, match="start" if field == "at_ms" else "duration"):
        _project_speed(scope, raw)
    assert canonical_json(raw) == before


@pytest.mark.parametrize("scope", ["child", "parent"])
@pytest.mark.parametrize("speed", [None, [3, 2], "3/2"])
def test_legacy_visual_publisher_cannot_seed_retained_speed_shapes(tmp_path, scope, speed):
    # The publisher only serves a headless timeline: a tracked one is refused before its speed is read.
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "views", "name": "Views"}, idempotency_key="project")["id"]
    service.create_timeline(project, "main", idempotency_key="timeline")
    try:
        publication = _publication(project)
        if scope == "parent":
            publication["parent_composition"]["clips"] = [{**_parent_clip("parent"), "speed": speed}]
        else:
            publication["internal_timeline_revisions"][0]["payload"]["clips"][0]["speed"] = speed
        before, cas = tuple(service.store.conn.iterdump()), _cas_bytes(service)
        with pytest.raises(RetiredRouteError) as error:
            service.publish_parent_composition(project, "main", publication, idempotency_key="public-speed-refusal")
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        details = error.value.details
        assert isinstance(details, dict)
        assert details["reason"] == "timeline_commit_required"
        assert tuple(service.store.conn.iterdump()) == before
        assert _cas_bytes(service) == cas
    finally:
        service.close()
