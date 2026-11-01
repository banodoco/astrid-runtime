"""The retired timeline family cannot publish, including before retry lookup.

Run the whole file through the central restore-integration lane with the actual
Agent checkout. Only the HTTP cases need sockets; service cases run directly.
"""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import NotFoundError, RetiredRouteError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.util import canonical_json
from test_shot_composition_runtime import restore_provider as actual_provider  # noqa: F401 (fixture)


FAMILIES = (
    "update_timeline", "replace_timeline_clip", "create_timeline_document",
    "replace_parent_composition_media", "publish_parent_composition",
    "publish_timeline_render",
)
STATES = ("tracked", "fresh", "unused")


def seed(root, provider):
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": "authority", "name": "Authority"})["id"]
    service.create_timeline(project, "fresh", idempotency_key="fresh-create")
    service.ingest(project, b"ordinary artifact", idempotency_key="artifact")
    service.register_timeline_commit_provider(provider)
    service.create_timeline(project, "tracked", idempotency_key="tracked-create")
    return service, project


@pytest.fixture
def service_case(tmp_path, actual_provider):
    service, project = seed(tmp_path / "realm", actual_provider)
    try:
        yield SimpleNamespace(service=service, project=project)
    finally:
        service.close()


@pytest.fixture
def http_case(tmp_path, actual_provider):
    root = tmp_path / "realm"
    service, project = seed(root, actual_provider)
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", authoring_profile="astrid").start()
    try:
        yield SimpleNamespace(service=daemon.service, project=project,
                              client=WorkspaceClient(daemon.endpoint, daemon.token), daemon=daemon)
    finally:
        daemon.stop()


def snapshot(service):
    with service.store._mutex:
        database = tuple(service.store.conn.iterdump())
        objects = {str(path.relative_to(service.store.cas_root)): path.read_bytes()
                   for path in service.store.cas_root.rglob("*") if path.is_file()}
        staging = {str(path.relative_to(service.store.staging_root)): path.read_bytes()
                   for path in service.store.staging_root.rglob("*") if path.is_file()}
    return database, objects, staging


def _recover_request_hash(timeline_id, body):
    return hashlib.sha256(canonical_json({
        "timeline_id": timeline_id, "body": body, "action": "recover",
    }).encode()).hexdigest()


def _inject_recover_receipt(service, project, timeline_id, body, key, *, event_payload=None):
    """Inject review-only receipt evidence through the existing store helper."""
    result = service._timeline_resource(timeline_id)
    result["archived"] = False
    with service.store._mutex, service.store._transaction():
        event_ids = ()
        if event_payload is not None:
            event_ids = (service.store._append_timeline_event(
                timeline_id, "timeline.recovered", event_payload,
            ),)
        event_seq = service.store.conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE timeline_id=?",
            (timeline_id,),
        ).fetchone()[0]
        service.store._record_command_receipt(
            "timeline.recover", timeline_id, key, _recover_request_hash(timeline_id, body),
            result, project_id=project, event_ids=event_ids,
            primary_stream_id=timeline_id, resulting_stream_seq=event_seq,
        )


def legacy_request(case, family, timeline):
    project = case.project
    resource = None if timeline == "unused" else case.service.get_project_timeline(project, timeline)
    head = resource["head_revision_id"] if resource else None
    version = resource["version"] if resource else 1
    object_id = "sha256:" + "0" * 64
    requests = {
        "update_timeline": ("PATCH", f"/v1/timelines/{timeline}",
                            {"expected_version": version, "shots": [], "references": []}),
        "replace_timeline_clip": ("POST", f"/v1/timelines/{timeline}/replace-clip",
                                  {"expected_version": version, "clip_id": "clip", "source_object_id": object_id}),
        "create_timeline_document": ("POST", f"/v1/projects/{project}/timeline-documents",
                                     {"timeline_id": timeline, "config": {}, "registry": {}}),
        "publish_parent_composition": ("POST", f"/v1/projects/{project}/timelines/{timeline}/composition-revisions",
                                       {"project_id": project, "timeline_id": timeline, "expected_head": head,
                                        "parent_revision_id": "legacy-parent", "parent_composition": {
                                            "config": {}, "registry": {}, "clips": [], "occurrences": []}}),
        "replace_parent_composition_media": ("POST", f"/v1/projects/{project}/timelines/{timeline}/replace-parent-media",
                                             {"expected_head": head or "old-parent", "occurrence_id": "occurrence",
                                              "clip_id": "clip", "source_object_id": object_id}),
        "publish_timeline_render": ("POST", f"/v1/attempts/{timeline}/publish-timeline-render", {}),
        "archive_timeline": ("POST", f"/v1/timelines/{timeline}/archive", {"expected_version": version}),
        "recover_timeline": ("POST", f"/v1/timelines/{timeline}/recover", {"expected_version": version, "version": 1}),
    }
    return requests[family]


def call_service(case, family, timeline, body, key):
    if family == "publish_timeline_render":
        args = (timeline, body)
    elif family == "create_timeline_document":
        args = (case.project, body)
    elif family in ("publish_parent_composition", "replace_parent_composition_media"):
        args = (case.project, timeline, body)
    else:
        args = (timeline, body)
    return getattr(case.service, family)(*args, idempotency_key=key)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("timeline", STATES)
def test_service_legacy_family_refuses_without_writes(service_case, family, timeline):
    case = service_case
    _, _, body = legacy_request(case, family, timeline)
    before, changes = snapshot(case.service), case.service.store.conn.total_changes
    for key in ("legacy-key", None):
        with pytest.raises(RetiredRouteError) as error:
            call_service(case, family, timeline, body, key)
        assert error.value.status == 410
        assert error.value.details["reason"] == "timeline_commit_required"
        assert snapshot(case.service) == before
        assert case.service.store.conn.total_changes == changes


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("timeline", STATES)
def test_service_refusal_precedes_accepted_retry_lookup(service_case, monkeypatch, family, timeline):
    case = service_case
    _, _, body = legacy_request(case, family, timeline)
    before = snapshot(case.service)

    def replay(*args, **kwargs):
        pytest.fail("retired writer consulted accepted legacy retries")

    monkeypatch.setattr(case.service, "_command_replay", replay)
    with pytest.raises(RetiredRouteError):
        call_service(case, family, timeline, body, "exact-old-legacy-retry")
    assert snapshot(case.service) == before


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("timeline", STATES)
def test_http_authenticated_legacy_family_refuses_without_writes(http_case, monkeypatch, family, timeline):
    case = http_case
    method, path, body = legacy_request(case, family, timeline)
    before, changes = snapshot(case.service), case.service.store.conn.total_changes
    reader_token, _ = case.daemon.credentials.provision("reader", ["projects:read"])
    for client, status in ((WorkspaceClient(case.daemon.endpoint, None), 401),
                           (WorkspaceClient(case.daemon.endpoint, reader_token), 401)):
        with pytest.raises(ApiError) as error:
            client._request(method, path, body=json.dumps(body).encode(),
                            headers={"Content-Type": "application/json", "Idempotency-Key": "legacy-key"})
        assert error.value.status == status
        assert snapshot(case.service) == before
        assert case.service.store.conn.total_changes == changes

    def replay(*args, **kwargs):
        pytest.fail("retired HTTP writer consulted accepted legacy retries")

    monkeypatch.setattr(case.service, "_command_replay", replay)
    for key in ("legacy-key", "exact-old-legacy-retry"):
        with pytest.raises(ApiError) as error:
            case.client._request(method, path, body=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Idempotency-Key": key})
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        assert error.value.details["reason"] == "timeline_commit_required"
        assert error.value.details["hint"]
        assert error.value.details["suggested_command"]
        assert snapshot(case.service) == before
        assert case.service.store.conn.total_changes == changes


@pytest.mark.parametrize("family", ("archive_timeline", "recover_timeline"))
@pytest.mark.parametrize("timeline", STATES)
def test_http_visibility_routes_preserve_auth_without_writes(http_case, family, timeline):
    case = http_case
    method, path, body = legacy_request(case, family, timeline)
    before, changes = snapshot(case.service), case.service.store.conn.total_changes
    reader_token, _ = case.daemon.credentials.provision("visibility-reader", ["projects:read"])
    for client in (WorkspaceClient(case.daemon.endpoint, None),
                   WorkspaceClient(case.daemon.endpoint, reader_token)):
        with pytest.raises(ApiError) as error:
            client._request(method, path, body=json.dumps(body).encode(),
                            headers={"Content-Type": "application/json", "Idempotency-Key": "visibility-request"})
        assert error.value.status == 401
        assert snapshot(case.service) == before
        assert case.service.store.conn.total_changes == changes


def test_service_publish_parent_composition_refuses_tracked_timeline_without_writes(service_case):
    case = service_case
    _, _, body = legacy_request(case, "publish_parent_composition", "tracked")
    before, changes = snapshot(case.service), case.service.store.conn.total_changes
    for key in ("legacy-key", "legacy-key"):
        with pytest.raises(RuntimeErrorBase) as error:
            call_service(case, "publish_parent_composition", "tracked", body, key)
        assert error.value.status == 410
        assert error.value.details["reason"] == "timeline_commit_required"
        assert snapshot(case.service) == before
        assert case.service.store.conn.total_changes == changes


def test_http_publish_parent_composition_refuses_tracked_timeline_without_writes(http_case):
    case = http_case
    method, path, body = legacy_request(case, "publish_parent_composition", "tracked")
    before, changes = snapshot(case.service), case.service.store.conn.total_changes
    with pytest.raises(ApiError) as error:
        case.client._request(method, path, body=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json", "Idempotency-Key": "legacy-key"})
    assert error.value.status == 410
    assert error.value.details["reason"] == "timeline_commit_required"
    assert snapshot(case.service) == before
    assert case.service.store.conn.total_changes == changes


@pytest.mark.parametrize("operation", ("create", "update"))
def test_service_documents_cannot_carry_timeline_id(service_case, operation, monkeypatch):
    case = service_case
    service = case.service
    if operation == "create":
        body = {"document_id": "ordinary-document", "kind": "example.notes",
                "timeline_id": "tracked", "content": {"draft": True}}

        def call():
            return service.create_document(case.project, body, idempotency_key="document-timeline")

    else:
        created = service.create_document(
            case.project,
            {"document_id": "ordinary-document", "kind": "example.notes", "content": {"draft": True}},
            idempotency_key="document-create",
        )
        body = {"expected_version": created["data"]["version"], "timeline_id": "tracked",
                "content": {"draft": False}}

        def call():
            return service.update_document(
                case.project, "ordinary-document", body, idempotency_key="document-timeline",
            )

    def replay(*args, **kwargs):
        pytest.fail("timeline-bearing document write consulted idempotency replay")

    monkeypatch.setattr(service, "_command_replay", replay)
    before = snapshot(service)
    with pytest.raises(RetiredRouteError) as error:
        call()
    assert error.value.status == 410
    assert error.value.details["reason"] == "timeline_commit_required"
    assert snapshot(service) == before


def test_http_documents_cannot_carry_timeline_id_but_ordinary_metadata_stays_live(http_case):
    case = http_case
    ordinary = case.client.create_document(
        case.project, "ordinary-document", "example.notes", {"draft": True},
        idempotency_key="ordinary-create",
    )
    before = snapshot(case.service)
    for method, path, body, key in (
        ("POST", f"/v1/projects/{case.project}/documents",
         {"document_id": "smuggled", "kind": "example.notes", "timeline_id": "tracked",
          "content": {"draft": True}}, "smuggled-create"),
        ("PATCH", f"/v1/projects/{case.project}/documents/ordinary-document",
         {"expected_version": ordinary.version, "timeline_id": "tracked",
          "content": {"draft": False}}, "smuggled-update"),
    ):
        with pytest.raises(ApiError) as error:
            case.client._request(
                method, path, body=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "Idempotency-Key": key},
            )
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        assert error.value.details["reason"] == "timeline_commit_required"
        assert snapshot(case.service) == before
    assert case.client.get_document(case.project, "ordinary-document").content == {"draft": True}


def test_service_catalog_visibility_unarchives_current_or_absent_version(service_case):
    case = service_case
    service = case.service
    created = service.get_project_timeline(case.project, "tracked")
    commits = service._timeline_commits()[0]
    closure_before = commits.revision_closure(case.project, "tracked", created["head_revision_id"])
    history_count = service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0]
    archived = service.archive_timeline(
        "tracked", {"expected_version": created["version"]}, idempotency_key="visibility-archive",
    )
    archived_data = archived["data"]
    absent = service.recover_timeline(
        "tracked", {"expected_version": archived_data["version"]}, idempotency_key="visibility-recover-absent",
    )
    absent_data = absent["data"]
    assert absent_data["archived"] is False
    current = service.recover_timeline(
        "tracked", {"expected_version": absent_data["version"], "version": absent_data["version"]},
        idempotency_key="visibility-recover-current",
    )
    assert current["data"]["archived"] is False
    assert commits.revision_closure(case.project, "tracked", created["head_revision_id"]) == closure_before
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == history_count


@pytest.mark.parametrize("evidence", [
    "missing_event", "empty_payload", "malformed_payload", "wrong_project",
    "bool_version", "missing_version", "wrong_version", "legacy_target_version",
])
def test_service_visibility_receipt_proof_refuses_malformed_evidence(service_case, monkeypatch, evidence):
    case = service_case
    service = case.service
    created = service.get_project_timeline(case.project, "tracked")
    archived = service.archive_timeline(
        "tracked", {"expected_version": created["version"]}, idempotency_key="proof-archive",
    )
    body = {"expected_version": archived["data"]["version"]}
    if evidence == "legacy_target_version":
        body["version"] = archived["data"]["version"]
    event_version = archived["data"]["version"] + 1
    payloads = {
        "missing_event": None,
        "empty_payload": {},
        "malformed_payload": [],
        "wrong_project": {"project_id": "different-project", "version": event_version},
        "bool_version": {"project_id": case.project, "version": True},
        "missing_version": {"project_id": case.project},
        "wrong_version": {"project_id": case.project, "version": event_version + 1},
        "legacy_target_version": {
            "project_id": case.project, "version": event_version, "target_version": 1,
        },
    }
    _inject_recover_receipt(
        service, case.project, "tracked", body, "proof-recover",
        event_payload=payloads[evidence],
    )
    before = snapshot(service)

    def replay(*args, **kwargs):
        pytest.fail("legacy current-target recover consulted idempotency replay")

    monkeypatch.setattr(service, "_command_replay", replay)
    with pytest.raises(RetiredRouteError) as error:
        service.recover_timeline("tracked", body, idempotency_key="proof-recover")
    assert error.value.status == 410
    assert error.value.details["reason"] == "timeline_restore_required"
    assert error.value.details["replacement"] == "timeline.restore"
    assert snapshot(service) == before


def test_service_exact_new_visibility_replay_survives_catalog_version_change(service_case):
    case = service_case
    service = case.service
    created = service.get_project_timeline(case.project, "tracked")
    archived = service.archive_timeline(
        "tracked", {"expected_version": created["version"]}, idempotency_key="new-current-archive",
    )
    body = {"expected_version": archived["data"]["version"], "version": archived["data"]["version"]}
    accepted = service.recover_timeline("tracked", body, idempotency_key="new-current-recover")
    service.archive_timeline(
        "tracked", {"expected_version": accepted["data"]["version"]}, idempotency_key="later-archive",
    )
    before = snapshot(service)

    replayed = service.recover_timeline("tracked", body, idempotency_key="new-current-recover")
    assert replayed == accepted
    assert snapshot(service) == before


@pytest.mark.parametrize("timeline", STATES)
def test_service_historical_recover_refuses_before_legacy_replay_or_writes(service_case, monkeypatch, timeline):
    case = service_case
    service = case.service
    if timeline == "unused":
        body = {"expected_version": 1, "version": 1}
    else:
        created = service.get_project_timeline(case.project, timeline)
        archived = service.archive_timeline(
            timeline, {"expected_version": created["version"]}, idempotency_key=f"{timeline}-historical-archive",
        )
        body = {"expected_version": archived["data"]["version"], "version": created["version"]}
    before, changes = snapshot(service), service.store.conn.total_changes

    def replay(*args, **kwargs):
        pytest.fail("historical recover consulted a legacy idempotency replay")

    monkeypatch.setattr(service, "_command_replay", replay)
    with pytest.raises((NotFoundError, RetiredRouteError)) as error:
        service.recover_timeline(
            timeline, body, idempotency_key=f"{timeline}-historical-recover",
        )
    if timeline == "unused":
        assert error.value.status == 404
        assert error.value.code == "not_found"
    else:
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        assert "timeline.restore" in str(error.value)
        assert error.value.details["replacement"] == "timeline.restore"
    assert snapshot(service) == before
    assert service.store.conn.total_changes == changes


def command_body(case, commands):
    timeline = case.service.get_project_timeline(case.project, "tracked")
    return {"api_version": 1, "project_id": case.project, "timeline_id": "tracked",
            "base_revision_id": timeline["head_revision_id"],
            "base_publication_id": timeline["head_publication_id"], "commands": commands}


def test_service_actual_bootstrap_command_restore_and_exact_retries(service_case, monkeypatch):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document

    case = service_case
    service = case.service
    before = snapshot(service)
    created = service.create_timeline(case.project, "tracked", idempotency_key="tracked-create")
    assert snapshot(service) == before
    initial = service.get_project_timeline(case.project, "tracked")
    assert initial["head_revision_id"] == created["data"]["head_revision_id"]
    assert initial["head_publication_id"] == created["data"]["head_publication_id"]
    history = service.list_timeline_commits(case.project, "tracked", authorize=lambda: None)["items"]
    assert len(history) == 1
    bootstrap = history[0]
    assert bootstrap["intent"] == "bootstrap" and bootstrap["previous"] is None
    assert bootstrap["receipt"]["command_kind"] == "parent_composition.publish"
    assert bootstrap["publication_id"] == initial["head_publication_id"]
    document = service._timeline_commits()[0].revision_closure(case.project, "tracked", initial["head_revision_id"])
    assert document["parent_revision"]["payload"]["clips"] == []
    assert document["shot_revisions"] == document["internal_timeline_revisions"] == []

    def forbidden(*args, **kwargs):
        pytest.fail("bootstrap, commit or restore called the retired public publisher or renderer")

    monkeypatch.setattr(service, "publish_parent_composition", forbidden)
    monkeypatch.setattr("runtime_protocol.service.evaluate_closure", forbidden)
    # Exercise a second creation while the public publisher is unavailable.
    service.create_timeline(case.project, "second", idempotency_key="second-create")
    command = capture_track_create(bundle_from_document(document), "parent", {"id": "video", "kind": "visual"})
    body = command_body(case, [command])
    accepted = service.commit_timeline(case.project, "tracked", body, idempotency_key="real-command",
        publisher="editor", invocation_path=route_path(case.project, "tracked"), authorize=lambda: None)
    assert accepted["receipt"]["command_kind"] == "timeline.commit"
    assert accepted["data"]["canonical_document"]["parent_revision"]["payload"]["config"]["tracks"] == [
        {"id": "video", "kind": "visual"}]
    guards = {"expected_head": accepted["data"]["accepted_revision_id"],
              "expected_publication_id": accepted["receipt"]["receipt_id"]}
    path = route_path(case.project, "tracked", f"composition-revisions/{initial['head_revision_id']}/restore")
    def restore():
        return service.restore_project_parent_composition_revision(
            case.project, "tracked", initial["head_revision_id"], guards, idempotency_key="real-restore",
            publisher="editor", invocation_path=path, authorize=lambda: None)
    restored = restore()
    assert restored["data"]["canonical_document"] == document
    assert restored["receipt"]["command_kind"] == "timeline.commit"
    entry = service.list_timeline_commits(case.project, "tracked", authorize=lambda: None)["items"][-1]
    assert entry["records"]["restored_from"]["revision_id"] == initial["head_revision_id"]
    before = snapshot(service)
    assert restore() == restored
    assert service.commit_timeline(case.project, "tracked", body, idempotency_key="real-command",
        publisher="editor", invocation_path=route_path(case.project, "tracked"), authorize=lambda: None) == accepted
    assert snapshot(service) == before
    with pytest.raises(RuntimeErrorBase) as error:
        service.restore_project_parent_composition_revision(
            case.project, "tracked", initial["head_revision_id"], guards, idempotency_key="stale-restore",
            publisher="editor", invocation_path=path, authorize=lambda: None)
    assert error.value.status == 409 and error.value.details["reason"] == "stale_head"
    assert snapshot(service) == before


def test_http_actual_create_command_restore_rename_and_ordinary_artifact_metadata(http_case):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.commit import bundle_from_document

    case = http_case
    before = case.service._timeline_commits()[0].head(case.project, "tracked")
    renamed = case.client.rename_timeline(case.project, "tracked", "Display name", idempotency_key="rename")
    assert renamed["name"] == "Display name"
    assert case.service._timeline_commits()[0].head(case.project, "tracked") == before
    created = case.client.create_timeline(case.project, "http-empty", idempotency_key="http-create")
    assert created["head_revision_id"] and created["head_publication_id"]
    document = case.service._timeline_commits()[0].revision_closure(
        case.project, "http-empty", created["head_revision_id"])
    command = capture_track_create(bundle_from_document(document), "parent", {"id": "audio", "kind": "audio"})
    body = {"api_version": 1, "project_id": case.project, "timeline_id": "http-empty",
            "base_revision_id": created["head_revision_id"],
            "base_publication_id": created["head_publication_id"], "commands": [command]}
    accepted = case.client.commit_timeline(case.project, "http-empty", body, idempotency_key="http-command")
    assert accepted["receipt"]["command_kind"] == "timeline.commit"
    assert accepted["data"]["canonical_document"]["parent_revision"]["payload"]["config"]["tracks"] == [
        {"id": "audio", "kind": "audio"}]
    restored = case.client.restore_project_parent_composition_revision(
        case.project, "http-empty", created["head_revision_id"],
        expected_head=accepted["data"]["accepted_revision_id"],
        expected_publication_id=accepted["receipt"]["receipt_id"], idempotency_key="http-restore")
    assert restored["receipt"]["command_kind"] == "timeline.commit"
    assert restored["data"]["canonical_document"] == document
    document = case.client.create_document(case.project, "notes", "artifact.notes", {"title": "draft"},
                                           idempotency_key="notes-create")
    updated = case.client.update_document(case.project, "notes", expected_version=document["version"],
                                           content={"title": "final"}, idempotency_key="notes-update")
    assert updated["content"] == {"title": "final"}
    assert case.service._timeline_commits()[0].head(case.project, "tracked") == before
