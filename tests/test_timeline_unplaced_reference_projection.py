"""Accepted parent-owned raw references project into the existing read model."""
from __future__ import annotations

import copy
import json

import pytest
from test_timeline_commit_port import prepared
from test_timeline_raw_capture import _commit, _seed

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_port import digest


class SourceAcceptanceSetup:
    """Trusted ephemeral fixture provider using the approved raw pin port."""

    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def __init__(self, *, reference_id=None, include_manifest=True, malformed=False):
        self.reference_id = reference_id
        self.include_manifest = include_manifest
        self.malformed = malformed
        self.calls = 0

    def commit(self, context, port):
        self.calls += 1
        candidate = prepared(context, port)
        pin = context["request"]["commands"][0]["args"]["values"]["raw_pin"]
        port.raw_media_info(pin)
        payload = candidate["canonical_document"]["parent_revision"]["payload"]
        astrid = payload.setdefault("config", {}).setdefault("app", {}).setdefault("astrid", {})
        astrid["timeline_references"] = {}
        if self.reference_id is not None:
            leaf = {"version": 1, "reference_id": self.reference_id, "role": "source", "media": pin}
            if self.malformed:
                leaf["role"] = "catalog"
            astrid["timeline_references"][self.reference_id] = leaf
        if self.include_manifest:
            candidate["canonical_document"]["dependency_manifest"]["media"] = [copy.deepcopy(pin)]
        candidate["canonical_document"]["parent_revision"]["content_digest"] = digest(payload)
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "media:raw", "kind": "media", "pin": copy.deepcopy(pin), "policy": "exact"},
        ]
        return port.accept(candidate)


def _install(service, provider):
    # Keep the approved startup/door fixture while varying only provider behavior.
    service._timeline_commit_provider = provider
    return provider


def _next_request(service, project, previous, *, pin):
    request = copy.deepcopy(previous)
    head = service.get_project_timeline(project, "main")
    request["base_revision_id"] = head["head_revision_id"]
    request["base_publication_id"] = head["head_publication_id"]
    request["commands"][0]["args"]["values"]["raw_pin"] = pin
    return request


def _references(service):
    return [dict(row) for row in service.store.conn.execute(
        "SELECT id, timeline_id, object_id, role FROM timeline_references ORDER BY id"
    )]


def _snapshot(service):
    row = service.store.conn.execute(
        "SELECT version, shots_json, references_json FROM timeline_revisions "
        "WHERE timeline_id='main' ORDER BY version DESC LIMIT 1"
    ).fetchone()
    return None if row is None else {
        "version": row["version"], "shots": json.loads(row["shots_json"]),
        "references": json.loads(row["references_json"]),
    }


def test_owned_unplaced_reference_projects_row_and_snapshot_and_preserves_unrelated(tmp_path):
    service, _root, project, request, pin, _object_id = _seed(
        tmp_path, provider=SourceAcceptanceSetup(reference_id="owned")
    )
    try:
        unrelated = "sha256:" + "b" * 64
        service.store.conn.execute(
            "INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?, 'main', ?, 'source')",
            ("unrelated", unrelated),
        )
        provider = service._timeline_commit_provider
        accepted = _commit(service, project, request, key="owned-reference")
        assert provider.calls == 1
        assert _references(service) == [
            {"id": "owned", "timeline_id": "main", "object_id": pin["media_id"], "role": "source"},
            {"id": "unrelated", "timeline_id": "main", "object_id": unrelated, "role": "source"},
        ]
        snapshot = _snapshot(service)
        assert snapshot["version"] == service.get_project_timeline(project, "main")["version"]
        assert snapshot["references"] == [
            {"reference_id": "owned", "object_id": pin["media_id"], "role": "source"},
            {"reference_id": "unrelated", "object_id": unrelated, "role": "source"},
        ]
        assert accepted["data"]["canonical_document"]["parent_revision"]["payload"]["occurrences"] == []
    finally:
        service.close()


def test_occupied_or_invalid_custody_refuses_before_any_write(tmp_path):
    service, _root, project, request, pin, _object_id = _seed(
        tmp_path, provider=SourceAcceptanceSetup(reference_id="occupied")
    )
    try:
        service.store.conn.execute(
            "INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?, 'main', ?, 'source')",
            ("occupied", pin["media_id"]),
        )
        before = list(service.store.conn.iterdump())
        with pytest.raises((CommitRejected, RuntimeErrorBase)) as error:
            _commit(service, project, request, key="occupied-reference")
        assert "occupied" in str(error.value).lower()
        assert list(service.store.conn.iterdump()) == before
    finally:
        service.close()

    service, _root, project, request, _pin, _object_id = _seed(
        tmp_path / "invalid", provider=SourceAcceptanceSetup(reference_id="invalid", include_manifest=False)
    )
    try:
        before = list(service.store.conn.iterdump())
        with pytest.raises((CommitRejected, RuntimeErrorBase)):
            _commit(service, project, request, key="invalid-reference")
        assert list(service.store.conn.iterdump()) == before
    finally:
        service.close()


def test_foreign_occupied_reference_refuses_without_disclosing_scope(tmp_path):
    service, _root, project, request, pin, _object_id = _seed(
        tmp_path, provider=SourceAcceptanceSetup(reference_id="foreign")
    )
    try:
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
        service.create_timeline(foreign, "other", idempotency_key="create-foreign")
        service.store.conn.execute(
            "INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?, 'other', ?, 'source')",
            ("foreign", pin["media_id"]),
        )
        before = list(service.store.conn.iterdump())
        with pytest.raises((CommitRejected, RuntimeErrorBase)) as error:
            _commit(service, project, request, key="foreign-reference")
        assert "foreign" not in str(error.value).lower()
        assert list(service.store.conn.iterdump()) == before
    finally:
        service.close()


def test_inverse_shaped_removal_and_restoration_are_exactly_projected(tmp_path):
    service, _root, project, request, pin, _object_id = _seed(
        tmp_path, provider=SourceAcceptanceSetup(reference_id="restore-me")
    )
    try:
        _commit(service, project, request, key="reference-add")
        remove = _next_request(service, project, request, pin=pin)
        _install(service, SourceAcceptanceSetup())
        _commit(service, project, remove, key="reference-remove")
        assert _references(service) == []
        restore = _next_request(service, project, request, pin=pin)
        _install(service, SourceAcceptanceSetup(reference_id="restore-me"))
        _commit(service, project, restore, key="reference-restore")
        assert [row["id"] for row in _references(service)] == ["restore-me"]
    finally:
        service.close()


def test_ledger_first_retry_after_restart_does_not_reexecute_projection_provider(tmp_path):
    provider = SourceAcceptanceSetup(reference_id="retry")
    service, root, project, request, _pin, _object_id = _seed(tmp_path, provider=provider)
    try:
        accepted = _commit(service, project, request, key="reference-retry")
    finally:
        service.close()
    restarted = RuntimeService(root)
    try:
        assert _commit(restarted, project, request, key="reference-retry") == accepted
        assert _references(restarted)[0]["id"] == "retry"
    finally:
        restarted.close()
    assert provider.calls == 1
