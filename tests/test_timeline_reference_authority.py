"""Project catalogs stay writable; timeline reference writers stay retired.

Existing reference/association pins and accepted retry keys come from the genuine
pre-cut archive. Run the whole file centrally for real authenticated HTTP.
"""
from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, RetiredRouteError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.util import now
from precut_realm_fixture import load_precut_realm_fixture
from test_shot_composition_runtime import restore_provider as actual_provider  # noqa: F401 (fixture)


CATALOG_FAMILIES = (
    "create_project_reference", "update_project_reference", "archive_project_reference",
    "recover_project_reference", "associate_reference", "set_primary_reference",
    "link_references",
)
TIMELINE_FAMILIES = (
    "create_reference", "update_reference", "archive_reference",
    "recover_reference",
)
FAMILIES = CATALOG_FAMILIES + TIMELINE_FAMILIES
STATES = ("fresh", "unused", "existing")


def seed(root, provider):
    captured = load_precut_realm_fixture(root.parent)
    copied_root = captured.copy_roots[1]
    # The committed archive is intentionally historical. Refresh the copied
    # catalog receipts before RuntimeService opens the realm, otherwise its
    # startup compaction replaces an old result body with the expiry marker.
    with sqlite3.connect(copied_root / "realm.sqlite3") as connection:
        connection.execute(
            "UPDATE command_idempotency SET created_at=? "
            "WHERE (command_kind='reference.create' AND aggregate_id=?) "
            "OR (command_kind='reference.associate' AND aggregate_id=?)",
            (now(), captured.pins["project_id"], captured.pins["reference_id"]),
        )
    service = RuntimeService(copied_root)
    if provider is not None:
        service.register_timeline_commit_provider(provider)
    cases = {}
    for state in ("fresh", "unused"):
        project = service.create_project({"slug": state, "name": state.title()})["id"]
        media = service.ingest(project, b"ordinary media", idempotency_key=f"media-{state}")
        cases[state] = SimpleNamespace(project=project, timeline=state, media=media["data"]["object_id"],
                                       reference="uncreated-reference", association="association", version=1,
                                       retry="old-reference-retry")
    service.create_timeline(cases["fresh"].project, "fresh", idempotency_key="bootstrap")
    pins = captured.pins
    reference = service.get_project_reference(pins["project_id"], pins["reference_id"])
    assert reference["media_references"]
    retry = service.store.conn.execute(
        "SELECT idempotency_key FROM command_idempotency WHERE command_kind='reference.create' AND aggregate_id=?",
        (pins["project_id"],),
    ).fetchone()[0]
    cases["existing"] = SimpleNamespace(
        project=pins["project_id"], timeline=pins["timeline_id"], media=pins["association_media_id"],
        reference=pins["reference_id"], association=pins["association_id"], version=reference["version"], retry=retry,
    )
    return service, cases


@pytest.fixture(params=("neutral", "astrid"))
def service_case(tmp_path, actual_provider, request):
    service, cases = seed(tmp_path / "realm", actual_provider if request.param == "astrid" else None)
    try:
        yield SimpleNamespace(service=service, cases=cases)
    finally:
        service.close()


@pytest.fixture
def http_case(tmp_path, actual_provider):
    root = tmp_path / "realm"
    service, cases = seed(root, actual_provider)
    root = service.store.root
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", authoring_profile="astrid").start()
    try:
        yield SimpleNamespace(service=daemon.service, cases=cases, daemon=daemon,
                              client=WorkspaceClient(daemon.endpoint, daemon.token))
    finally:
        daemon.stop()


def test_admission_verifies_snapshot_when_source_wal_closes(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    reader = None
    try:
        project = service.create_project({"slug": "snapshot", "name": "Snapshot"})["id"]
        service.create_timeline(project, "main", idempotency_key="timeline")
        service._timeline_commits()[0].bootstrap(project, "main", authorize=lambda: None)
        reader = sqlite3.connect(root / "realm.sqlite3")
        reader.execute("SELECT * FROM realm").fetchall()
        service.close()
        wal = root / "realm.sqlite3-wal"
        assert wal.exists()
        physical_version = TimelineCommitStore._physical_version
        calls = 0

        def close_source_reader(commits):
            nonlocal calls
            calls += 1
            if calls == 2:
                # The source's last reader can close after snapshot capture,
                # including when an old SQLite handle is garbage-collected.
                reader.close()
                assert not wal.exists()
            return physical_version(commits)

        monkeypatch.setattr(TimelineCommitStore, "_physical_version", close_source_reader)
        report = RealmStore.inspect_realm(root)
        assert report["ok"], report
        assert calls >= 2
    finally:
        if reader is not None:
            reader.close()
        service.close()


def snapshot(service):
    # Whole DB covers canonical/reference rows, heads, history, receipts, events
    # and sequence counters; total_changes also catches rolled-back SQL writes.
    with service.store._mutex:
        database = tuple(service.store.conn.iterdump())
        objects = {str(path.relative_to(service.store.cas_root)): path.read_bytes()
                   for path in service.store.cas_root.rglob("*") if path.is_file()}
        return database, objects, service.store.conn.total_changes


def reference_request(case, family):
    project, reference = case.project, case.reference
    prefix = f"/v1/projects/{project}/references"
    resource = f"{prefix}/{reference}"
    version = {"expected_version": case.version}
    requests = {
        "create_project_reference": ("POST", prefix, {
            "reference_id": reference, "kind": "character", "name": "Character", "media_id": case.media}),
        "update_project_reference": ("PATCH", resource, {**version, "name": "Renamed"}),
        "archive_project_reference": ("POST", f"{resource}/archive", version),
        "recover_project_reference": ("POST", f"{resource}/recover", {**version, "version": 1}),
        "associate_reference": ("POST", f"{resource}/associations", {
            "association_id": case.association, "media_id": case.media, "role": "canonical"}),
        "set_primary_reference": ("POST", f"{resource}/primary", {**version, "association_id": case.association}),
        "link_references": ("POST", f"/v1/projects/{project}/reference-links", {
            "from_reference_id": reference, "to_reference_id": "uncreated-target", "kind": "related_to"}),
        "create_reference": ("POST", f"/v1/timelines/{case.timeline}/references", {
            "reference_id": reference, "object_id": case.media, "role": "source"}),
        "update_reference": ("PATCH", f"/v1/references/{reference}", {**version, "object_id": case.media}),
        "archive_reference": ("POST", f"/v1/references/{reference}/archive", version),
        "recover_reference": ("POST", f"/v1/references/{reference}/recover", {**version, "version": 1}),
    }
    return requests[family]


def call_service(service, case, family, body, key):
    reference = case.reference
    kwargs = {"idempotency_key": key}
    if family in ("archive_project_reference", "recover_project_reference"):
        kwargs["archived"] = family == "archive_project_reference"
        family = "update_project_reference"
    if family in ("create_project_reference", "link_references"):
        args = (case.project, body)
    elif family == "set_primary_reference":
        args = (case.project, reference, case.association, body)
    elif family in ("update_project_reference", "associate_reference"):
        args = (case.project, reference, body)
    elif family == "create_reference":
        args = (case.timeline, body)
    else:
        args = (reference, body)
    return getattr(service, family)(*args, **kwargs)


@pytest.mark.parametrize("family", TIMELINE_FAMILIES)
@pytest.mark.parametrize("state", STATES)
def test_service_reference_writers_refuse_before_lookup_or_replay(service_case, monkeypatch, family, state):
    service, case = service_case.service, service_case.cases[state]
    _, _, body = reference_request(case, family)
    before = snapshot(service)

    def replay(*args, **kwargs):
        pytest.fail("retired reference writer consulted legacy retries")

    monkeypatch.setattr(service, "_command_replay", replay)
    for key in ("reference-request", case.retry, None):
        with pytest.raises(RetiredRouteError) as error:
            call_service(service, case, family, body, key)
        assert error.value.status == 410
        assert error.value.details["reason"] == "timeline_commit_required"
        assert snapshot(service) == before


@pytest.mark.parametrize("archived", (None, True, False))
def test_service_private_reference_state_writer_is_also_retired(service_case, archived):
    service = service_case.service
    before = snapshot(service)
    with pytest.raises(RetiredRouteError):
        service._update_reference_state("uncreated-reference", {"expected_version": 1}, archived=archived)
    assert snapshot(service) == before


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("state", STATES)
def test_http_reference_writers_preserve_auth_without_writes(http_case, family, state):
    case = http_case
    method, path, body = reference_request(case.cases[state], family)
    reader_token, _ = case.daemon.credentials.provision("reader", ["projects:read"])
    before = snapshot(case.service)
    for client in (WorkspaceClient(case.daemon.endpoint, None),
                   WorkspaceClient(case.daemon.endpoint, reader_token)):
        with pytest.raises(ApiError) as error:
            client._request(method, path, body=json.dumps(body).encode(),
                            headers={"Content-Type": "application/json", "Idempotency-Key": "reference-request"})
        assert error.value.status == 401
        assert snapshot(case.service) == before


@pytest.mark.parametrize("family", TIMELINE_FAMILIES)
@pytest.mark.parametrize("state", STATES)
def test_http_timeline_reference_writers_refuse_without_writes(http_case, monkeypatch, family, state):
    case = http_case
    method, path, body = reference_request(case.cases[state], family)
    before = snapshot(case.service)

    def replay(*args, **kwargs):
        pytest.fail("retired HTTP reference writer consulted legacy retries")

    monkeypatch.setattr(case.service, "_command_replay", replay)
    for key in ("reference-request", case.cases[state].retry):
        with pytest.raises(ApiError) as error:
            case.client._request(method, path, body=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Idempotency-Key": key})
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        assert error.value.details["reason"] == "timeline_commit_required"
        assert snapshot(case.service) == before


def test_http_ordinary_media_artifacts_and_project_metadata_remain_writable(http_case):
    case = http_case
    project = case.cases["fresh"].project
    before = case.service.get_project_timeline(project, "fresh")
    media = case.client.ingest_project_object(project, b"new ordinary artifact", media_type="application/octet-stream",
                                               idempotency_key="ordinary-media")
    objects, _ = case.client.list_project_objects(project)
    assert media["object_id"] in {item.object_id for item in objects}
    document = case.client.create_document(project, "notes", "artifact.notes", {"title": "draft"},
                                           idempotency_key="notes-create")
    updated = case.client.update_document(project, "notes", expected_version=document["version"],
                                           content={"title": "final"}, idempotency_key="notes-update")
    assert updated["content"] == {"title": "final"}
    renamed = case.client.update_project(project, name="Renamed", metadata={"note": "ordinary metadata"},
                                          idempotency_key="project-update")
    assert renamed.name == "Renamed"
    assert case.client.list_project_references(project)[0] == []
    after = case.service.get_project_timeline(project, "fresh")
    for field in ("head_revision_id", "head_publication_id", "version"):
        assert after[field] == before[field]


def captured_retry(service, case, family):
    reference = service.get_project_reference(case.project, case.reference)
    if family == "create_project_reference":
        body = {key: reference[key] for key in ("reference_id", "kind", "name", "description", "metadata")}
        body["media_id"] = case.media
        command, aggregate = "reference.create", case.project
    else:
        association = next(item for item in reference["media_references"] if item["role"] == "depicts")
        body = {key: association[key] for key in ("association_id", "media_id", "role", "metadata")}
        command, aggregate = "reference.associate", case.reference
    receipt = service.store.conn.execute(
        "SELECT idempotency_key, request_hash FROM command_idempotency WHERE command_kind=? AND aggregate_id=?",
        (command, aggregate),
    ).fetchone()
    from runtime_protocol.timeline_commit_store import digest
    assert digest(body).removeprefix("sha256:") == receipt["request_hash"]
    return body, receipt["idempotency_key"]


@pytest.mark.parametrize("family", ["create_project_reference", "associate_reference"])
def test_service_genuine_accepted_catalog_retry_replays_without_writes(service_case, family):
    service, case = service_case.service, service_case.cases["existing"]
    body, key = captured_retry(service, case, family)
    before = snapshot(service)
    result = call_service(service, case, family, body, key)
    receipt = service.committed_receipt(
        "reference.create" if family == "create_project_reference" else "reference.associate",
        case.project if family == "create_project_reference" else case.reference,
        key, project_id=case.project,
    )
    assert result == {"data": receipt["result"], "receipt": receipt}
    assert snapshot(service) == before


@pytest.mark.parametrize("family", ["create_project_reference", "associate_reference"])
def test_http_genuine_accepted_catalog_retry_replays_without_writes(http_case, family):
    case = http_case.cases["existing"]
    body, key = captured_retry(http_case.service, case, family)
    method, path, _ = reference_request(case, family)
    before = snapshot(http_case.service)
    _, _, raw = http_case.client._request(method, path, body=json.dumps(body).encode(),
                                          headers={"Content-Type": "application/json", "Idempotency-Key": key},
                                          expected=(200, 201))
    receipt = http_case.service.committed_receipt(
        "reference.create" if family == "create_project_reference" else "reference.associate",
        case.project if family == "create_project_reference" else case.reference,
        key, project_id=case.project,
    )
    assert json.loads(raw) == {"data": receipt["result"], "receipt": receipt}
    assert snapshot(http_case.service) == before


def film_snapshot(service, case):
    head = service.get_project_timeline(case.project, case.timeline)
    # Neutral startup need not install a legacy publication identity. Read the
    # existing history rows without manufacturing one for a catalog operation.
    history = (service.list_project_parent_composition_revisions(case.project, case.timeline),
               service.list_timeline_history(case.timeline),
               tuple(tuple(row) for row in service.store.conn.execute(
                   "SELECT * FROM timeline_commit_history WHERE project_id=? AND timeline_id=? ORDER BY project_seq",
                   (case.project, case.timeline))),
               tuple(tuple(row) for row in service.store.conn.execute(
                   "SELECT * FROM timeline_events WHERE timeline_id=? ORDER BY id", (case.timeline,))))
    document = service._timeline_commits()[0].revision_closure(
        case.project, case.timeline, head["head_revision_id"],
    )
    objects = {str(path.relative_to(service.store.cas_root)): path.read_bytes()
               for path in service.store.cas_root.rglob("*") if path.is_file()}
    return head, history, document, objects


def catalog_request(service, case, family):
    case = SimpleNamespace(**vars(case))
    case.kind = "character"
    if family == "create_project_reference":
        case.reference += "-new"
    else:
        if case.reference == "uncreated-reference":
            service.create_project_reference(case.project, {
                "reference_id": case.reference, "kind": "character", "name": "Character", "media_id": case.media,
            }, idempotency_key="catalog-setup")
        current = service.get_project_reference(case.project, case.reference)
        case.kind = current["kind"]
        if family == "recover_project_reference":
            current = service.update_project_reference(
                case.project, case.reference, {"expected_version": current["version"]},
                archived=True, idempotency_key="catalog-setup-archive",
            )["data"]
        case.version = current["version"]
        case.association = current["media_references"][0]["association_id"]
        if family == "associate_reference":
            case.association = "catalog-new-association"
    method, path, body = reference_request(case, family)
    if family == "associate_reference":
        body["role"] = "inspired_by"
    if family == "link_references":
        service.create_project_reference(case.project, {
            "reference_id": "catalog-target", "kind": "object", "name": "Prop", "media_id": case.media,
        }, idempotency_key="catalog-target")
        body["to_reference_id"] = "catalog-target"
    return case, method, path, body


def assert_catalog_result(service, case, family, result):
    data = result["data"]
    assert result["receipt"]["result"] == data
    assert result["receipt"]["project_id"] == case.project
    if family == "link_references":
        assert data == {"from_reference_id": case.reference, "to_reference_id": "catalog-target", "kind": "related_to"}
        assert service.get_project_reference(case.project, case.reference)["links"]
    else:
        assert service.get_project_reference(case.project, case.reference) == data
        assert data["reference_id"] == case.reference and data["kind"] == case.kind
        if family == "create_project_reference":
            assert data["version"] == 1 and data["name"] == "Character"
        else:
            assert data["version"] == case.version + 1
        if family == "update_project_reference":
            assert data["name"] == "Renamed"
        if family in ("archive_project_reference", "recover_project_reference"):
            assert data["archived"] == (family == "archive_project_reference")
        if family == "associate_reference":
            assert data["media_references"][-1]["association_id"] == case.association
        if family == "set_primary_reference":
            primary = [item for item in data["media_references"] if item["is_primary"]]
            assert len(primary) == 1 and primary[0]["association_id"] == case.association


@pytest.mark.parametrize("family", CATALOG_FAMILIES)
@pytest.mark.parametrize("state", STATES)
def test_service_project_catalog_keep_crud_and_exact_retry(service_case, family, state):
    service = service_case.service
    case, _, _, body = catalog_request(service, service_case.cases[state], family)
    before = film_snapshot(service, service_case.cases["existing"])
    result = call_service(service, case, family, body, "catalog-request")
    assert_catalog_result(service, case, family, result)
    assert film_snapshot(service, service_case.cases["existing"]) == before
    unchanged = snapshot(service)
    assert call_service(service, case, family, body, "catalog-request") == result
    assert snapshot(service) == unchanged
    with pytest.raises(ConflictError):
        call_service(service, case, family, {**body, "metadata": {"changed": True}}, "catalog-request")
    assert snapshot(service) == unchanged


@pytest.mark.parametrize("family", CATALOG_FAMILIES)
@pytest.mark.parametrize("state", STATES)
def test_http_project_catalog_keep_crud_and_exact_retry(http_case, family, state):
    case, method, path, body = catalog_request(http_case.service, http_case.cases[state], family)
    before = film_snapshot(http_case.service, http_case.cases["existing"])

    def request(value):
        _, _, raw = http_case.client._request(
            method, path, body=json.dumps(value).encode(), expected=(200, 201),
            headers={"Content-Type": "application/json", "Idempotency-Key": "catalog-request"},
        )
        return json.loads(raw)

    result = request(body)
    assert_catalog_result(http_case.service, case, family, result)
    assert film_snapshot(http_case.service, http_case.cases["existing"]) == before
    unchanged = snapshot(http_case.service)
    assert request(body) == result
    assert snapshot(http_case.service) == unchanged
    with pytest.raises(ApiError) as error:
        request({**body, "metadata": {"changed": True}})
    assert error.value.status == 409
    assert snapshot(http_case.service) == unchanged
