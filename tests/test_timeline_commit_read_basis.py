"""Read the exact immutable basis used by the first App edit."""
from __future__ import annotations

import copy

import pytest

from astrid_runtime_client import WorkspaceClient
from runtime_protocol.errors import InvalidRequestError, NotFoundError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore, expired_publication_result
from runtime_protocol.timeline_commit_store import TimelineCommitStore, digest
from runtime_protocol.util import canonical_json

from baseline_fixture import load_baseline_fixture
from test_timeline_commit_port import PreparedProvider, prepared, request


def _canonical_from_public_reads(service, project_id, timeline_id, page):
    """Rebuild CanonicalDocument from the fixed head and immutable GETs."""
    head = page["head"]
    parent = service.get_project_parent_composition_revision(
        project_id, timeline_id, head["revision_id"]
    )
    manifest = parent["dependency_manifest"]
    document = {
        "schema_version": 1,
        "project_id": project_id,
        "timeline_id": timeline_id,
        "parent_revision": {
            key: parent[key] for key in ("revision_id", "content_digest", "payload")
        },
        "shot_revisions": [],
        "internal_timeline_revisions": [],
        "dependency_manifest": manifest,
    }
    for pin in manifest["shots"]:
        image = service.get_project_shot_revision(
            project_id, pin["shot_id"], pin["revision_id"]
        )
        document["shot_revisions"].append(
            {
                key: image[key]
                for key in (
                    "revision_id",
                    "shot_id",
                    "internal_timeline_revision_id",
                    "content_digest",
                    "payload",
                )
            }
        )
    for pin in manifest["internal_timelines"]:
        image = service.get_project_timeline_revision(
            project_id, pin["timeline_id"], pin["revision_id"]
        )
        document["internal_timeline_revisions"].append(
            {
                key: image[key]
                for key in (
                    "revision_id",
                    "timeline_id",
                    "content_digest",
                    "payload",
                )
            }
        )
    return document


def _assert_public_read_equals_store(service, commits, project_id, timeline_id, page):
    actual = _canonical_from_public_reads(service, project_id, timeline_id, page)
    expected = commits.revision_closure(project_id, timeline_id, page["head"]["revision_id"])
    assert canonical_json(actual) == canonical_json(expected)
    return actual


@pytest.fixture
def bootstrapped(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    provider = PreparedProvider()
    service.register_timeline_commit_provider(provider)
    project_id = service.create_project(
        {"slug": "read-basis", "name": "Read basis"}, idempotency_key="project"
    )["id"]
    service.test_project = project_id
    service.create_timeline(project_id, "main", idempotency_key="timeline")
    commits, _ = service._timeline_commits()
    try:
        yield service, commits, project_id, root
    finally:
        service.close()


def _accept_recorded_revision(service, project_id, *, key, opaque=None):
    body = request(service)

    def action(context, port):
        candidate = prepared(context, port)
        if opaque is not None:
            payload = candidate["canonical_document"]["parent_revision"]["payload"]
            payload["opaque"] = copy.deepcopy(opaque)
            candidate["canonical_document"]["parent_revision"]["content_digest"] = digest(payload)
            candidate["document_digest"] = digest(candidate["canonical_document"])
        return port.accept(candidate)

    service._timeline_commit_provider = PreparedProvider(action)
    return service.commit_timeline(
        project_id,
        "main",
        body,
        idempotency_key=key,
        publisher="editor",
        invocation_path=f"/v1/projects/{project_id}/timelines/main/commit",
        authorize=lambda: None,
    )


def test_bootstrap_manifest_is_the_exact_empty_read_basis(bootstrapped):
    service, commits, project_id, _ = bootstrapped
    page = service.list_timeline_commits(
        project_id, "main", limit="50", authorize=lambda: None
    )
    assert page["head"]["publication_id"]
    document = _assert_public_read_equals_store(
        service, commits, project_id, "main", page
    )
    assert document["dependency_manifest"] == {
        "shots": [],
        "internal_timelines": [],
        "media": [],
        "documents": [],
    }


def test_recorded_read_keeps_unknown_payload_fields_and_explicit_null(bootstrapped):
    service, commits, project_id, _ = bootstrapped
    accepted = _accept_recorded_revision(
        service,
        project_id,
        key="opaque-recorded",
        opaque={"vendor_field": None, "nested": {"unknown": "kept"}},
    )
    page = service.list_timeline_commits(
        project_id, "main", authorize=lambda: None
    )
    document = _assert_public_read_equals_store(
        service, commits, project_id, "main", page
    )
    assert page["head"]["revision_id"] == accepted["data"]["accepted_revision_id"]
    assert document["parent_revision"]["payload"]["opaque"] == {
        "vendor_field": None,
        "nested": {"unknown": "kept"},
    }


def test_pinned_head_stays_readable_after_disjoint_advance(bootstrapped):
    service, commits, project_id, _ = bootstrapped
    first = _accept_recorded_revision(service, project_id, key="first")
    pinned = service.list_timeline_commits(
        project_id, "main", limit="1", authorize=lambda: None
    )
    original_head = pinned["head"]
    _accept_recorded_revision(service, project_id, key="second")
    after = service.list_timeline_commits(
        project_id, "main", cursor=pinned["next_cursor"], limit="1", authorize=lambda: None
    ) if pinned["next_cursor"] else pinned
    assert after["head"] == original_head
    document = _assert_public_read_equals_store(
        service, commits, project_id, "main", {"head": original_head}
    )
    assert document["parent_revision"]["revision_id"] == first["data"]["accepted_revision_id"]


def test_verified_legacy_baseline_exposes_manifest_without_replaying_compacted_result(tmp_path, monkeypatch):
    service, project_id, _ = load_baseline_fixture(tmp_path)
    try:
        commits = TimelineCommitStore(service.store, validate_prepared=lambda value: None)
        head = commits.install_verified_baseline(project_id, "main", authorize=lambda: None)
        row = service.store.conn.execute(
            "SELECT result_json FROM command_idempotency WHERE command_kind='parent_composition.publish'"
        ).fetchone()
        service.store.conn.execute(
            "UPDATE command_idempotency SET result_json=? WHERE command_kind='parent_composition.publish'",
            (expired_publication_result(row["result_json"]),),
        )

        def renderer_must_not_run(*args, **kwargs):
            raise AssertionError("immutable read expanded the compacted result")

        monkeypatch.setattr("runtime_protocol.service.evaluate_closure", renderer_must_not_run)
        page = service.list_timeline_commits(
            project_id, "main", authorize=lambda: None
        )
        assert page["head"] == head
        document = _assert_public_read_equals_store(
            service, commits, project_id, "main", page
        )
        assert document["dependency_manifest"]["documents"] == []
    finally:
        service.close()


def test_unverified_or_missing_manifest_is_not_defaulted(tmp_path):
    service, project_id, _ = load_baseline_fixture(tmp_path)
    try:
        revision = "parent-1"
        unverified = service.get_project_parent_composition_revision(
            project_id, "main", revision
        )
        assert "dependency_manifest" not in unverified

        commits = TimelineCommitStore(service.store, validate_prepared=lambda value: None)
        commits.install_verified_baseline(project_id, "main", authorize=lambda: None)
        service.store.conn.execute(
            "UPDATE parent_composition_revisions SET commit_manifest_json=NULL WHERE id=?",
            (revision,),
        )
        missing = service.get_project_parent_composition_revision(
            project_id, "main", revision
        )
        assert "dependency_manifest" not in missing
    finally:
        service.close()


def test_foreign_scope_and_consumer_reads_do_not_write_or_invoke_provider(bootstrapped, monkeypatch):
    service, commits, project_id, _ = bootstrapped
    page = service.list_timeline_commits(
        project_id, "main", authorize=lambda: None
    )
    foreign_project = service.create_project(
        {"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign-project"
    )["id"]
    before = service.store.conn.total_changes

    class ExplodingProvider:
        def commit(self, *_args):
            raise AssertionError("consumer read invoked the provider")

    service._timeline_commit_provider = ExplodingProvider()
    monkeypatch.setattr(
        "runtime_protocol.service.evaluate_closure",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("renderer invoked")),
    )
    with pytest.raises(NotFoundError):
        service.get_project_parent_composition_revision(
            foreign_project, "main", page["head"]["revision_id"]
        )
    _assert_public_read_equals_store(service, commits, project_id, "main", page)
    assert service.store.conn.total_changes == before


@pytest.mark.parametrize("limit", [True, 0, 201, "not-a-number", ""])
def test_real_service_rejects_invalid_public_commit_limits(bootstrapped, limit):
    service, _, project_id, _ = bootstrapped
    with pytest.raises(InvalidRequestError):
        service.list_timeline_commits(
            project_id, "main", limit=limit, authorize=lambda: None
        )


def test_generated_python_client_lists_commits_over_real_http(bootstrapped):
    """This socket test is run by the central Runtime targeted service."""
    service, _, project_id, root = bootstrapped
    service.close()

    from runtime_protocol.daemon import RuntimeDaemon

    daemon = RuntimeDaemon(root, support_root=root / "support").start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        page = client.list_timeline_commits(project_id, "main", limit=50)
        assert page["head"]["revision_id"]
        assert page["head"]["publication_id"]
    finally:
        daemon.stop()
