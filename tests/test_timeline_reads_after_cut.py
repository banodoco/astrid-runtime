"""Canonical timeline reads remain usable after the authoring cuts.

The first test uses a deliberately labelled provider at the Runtime boundary:
it accepts through ``RequestCommitPort`` and never writes SQLite itself.  The
second test reads a genuine schema-31 backup and changes only its mutable
transcript source, proving that the historical text binding remains the pin.
"""
from __future__ import annotations

from copy import deepcopy

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import digest, route_path

from timeline_commit_film_fixture import build_film_fixture


class _HostBoundaryProvider:
    """A legal provider seam; acceptance is still performed by Runtime."""

    # Runtime's ABI intentionally admits only the installed provider identity;
    # this local provider is the host-boundary implementation of that ABI.
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def commit(self, context, port):
        head = port.head()
        document = port.revision_closure(head["revision_id"])
        payload = document["parent_revision"]["payload"]
        payload.setdefault("config", {})["read_fixture_marker"] = "accepted"
        document["parent_revision"]["revision_id"] = "read-fixture-v1"
        document["parent_revision"]["content_digest"] = digest(payload)
        command = context["request"]["commands"][0]
        record = {
            "ordinal": 0,
            "command": command,
            "writes": [{
                "ref": "parent",
                "path": ["config", "read_fixture_marker"],
                "before": {"state": "absent"},
                "after": {"state": "present", "value": "accepted"},
            }],
            "reads": [],
            "selections": [],
            "bindings": [],
            "created": [],
            "dependencies": [],
            "derived_writes": [],
        }
        candidate = {
            "expected_head": head,
            "canonical_document": document,
            "document_digest": digest(document),
            "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None},
            "id_map": {},
            "semantic_events": [],
            "provider_version": "read-fixture-1",
            "compiler_version": "read-fixture-1",
        }
        return port.accept(candidate)


def _snapshot(service):
    with service.store._mutex:
        return tuple(service.store.conn.iterdump()), {
            str(path.relative_to(service.store.cas_root)): path.read_bytes()
            for path in service.store.cas_root.rglob("*") if path.is_file()
        }, service.store.conn.total_changes


def _commit_body(service, project_id, timeline_id):
    head = service.get_project_timeline(project_id, timeline_id)
    return {
        "api_version": 1,
        "project_id": project_id,
        "timeline_id": timeline_id,
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"],
        "commands": [{
            "schema_version": 1,
            "op": "vendor.decorate",
            "version": "1",
            "select": None,
            "args": {"read_fixture": True},
        }],
    }


def test_bootstrap_command_then_history_revision_and_neutral_reads(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project_id = service.create_project(
            {"slug": "reads-after-cut", "name": "Reads after cut"}, idempotency_key="project"
        )["id"]
        service.register_timeline_commit_provider(_HostBoundaryProvider())
        service.create_timeline(project_id, "main", idempotency_key="timeline")
        # Reading the fresh bootstrap legally installs its accepted history
        # identity; the subsequent command therefore has a real base pair.
        service.list_timeline_commits(
            project_id, "main", authorize=lambda: {"actor": "bootstrap-reader"}
        )
        accepted = service.commit_timeline(
            project_id,
            "main",
            _commit_body(service, project_id, "main"),
            idempotency_key="read-fixture-command",
            publisher="reader-test-editor",
            invocation_path=route_path(project_id, "main"),
            authorize=lambda: {"actor": "reader-test-editor", "scopes": ["projects:write"]},
        )
        revision = accepted["data"]["accepted_revision_id"]
        calls = []

        def allow_reader():
            calls.append("projects:read")
            return {"actor": "read-only-client", "scopes": ["projects:read"]}

        before = _snapshot(service)
        monkeypatch.setattr(
            "runtime_protocol.service.evaluate_closure",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("renderer invoked by read")),
        )
        history = service.list_timeline_commits(
            project_id, "main", authorize=allow_reader
        )
        revisions = service.list_project_parent_composition_revisions(project_id, "main")
        image = service.get_project_parent_composition_revision(project_id, "main", revision)
        shown = service.inspect_timeline(project_id, "main", {})
        timeline = service.get_project_timeline(project_id, "main")

        assert len(calls) >= 2 and set(calls) == {"projects:read"}
        assert history["head"]["revision_id"] == revision
        assert {item["revision_id"] for item in revisions["items"]} >= {revision}
        assert image["payload"]["config"]["read_fixture_marker"] == "accepted"
        assert shown["revision_id"] == revision
        assert shown["evidence_kind"] == "declared_inputs"
        assert shown["render_requested"] is False
        assert timeline["head_revision_id"] == revision
        assert _snapshot(service) == before
    finally:
        service.close()


def test_precut_catalog_reference_shot_and_binding_pins_survive_source_change(tmp_path):
    fixture = build_film_fixture(tmp_path)
    service = RuntimeService(fixture.duplicate_root)
    try:
        parent = service.get_project_parent_composition_revision(
            fixture.project_id, fixture.timeline_id, fixture.parent_revision_id
        )
        shot_revision = service.get_project_shot_revision(
            fixture.project_id, "shot-1", "film-shot-revision-1"
        )
        internal_revision = service.get_project_timeline_revision(
            fixture.project_id, fixture.timeline_id, "film-internal-1"
        )
        original_document = service.get_document(
            fixture.project_id, fixture.transcript_document_id
        )
        binding = service.get_project_shot_text_binding(
            fixture.project_id, fixture.text_binding_id
        )
        objects = service.list_project_objects(fixture.project_id)["items"]
        reference = service.get_project_reference(
            fixture.project_id, "film-legacy-reference"
        )
        shot = service.get_project_shot(fixture.project_id, "shot-1")

        assert {item["object_id"] for item in objects} == set(fixture.media_ids)
        assert reference["metadata"] == {"fixture": "schema31/pre-cut80973d3"}
        assert reference["media_references"][1]["metadata"] == {"shot_id": "shot-1"}
        assert shot["metadata"]["transcript_anchor"]["word_id"] == "word-1"
        assert parent["payload"]["occurrences"][0]["shot_revision_id"] == shot_revision["revision_id"]
        assert shot_revision["internal_timeline_revision_id"] == internal_revision["revision_id"]
        assert binding["media_id"] in fixture.media_ids

        changed = deepcopy(original_document["content"])
        changed["segments"][0]["text"] = "MUTATED SOURCE"
        service.update_document(
            fixture.project_id,
            fixture.transcript_document_id,
            {"expected_version": original_document["version"], "content": changed},
            idempotency_key="mutate-source-only",
        )
        current_source = service.get_document(fixture.project_id, fixture.transcript_document_id)
        shown = service.inspect_timeline(
            fixture.project_id,
            fixture.timeline_id,
            {"revision_id": fixture.parent_revision_id, "occurrence": "occurrence-1"},
        )
        pinned_binding = shown["selected"][0]["occurrence"]["text_bindings"][0]

        assert current_source["content"]["segments"][0]["text"] == "MUTATED SOURCE"
        assert pinned_binding["media_id"] == binding["media_id"]
        assert pinned_binding["text"] == "Open on the river"
        assert pinned_binding["authority"] == "shot_text_binding"
    finally:
        service.close()
