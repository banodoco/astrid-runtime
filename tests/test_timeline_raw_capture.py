from __future__ import annotations

import copy
from pathlib import Path

import pytest

from test_timeline_commit_port import prepared

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.errors import ConflictError, NotFoundError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_port import RequestCommitPort, digest, route_path


class RawCaptureProvider:
    provider_id = "astrid-v1"
    interface_version = 1
    contract_digest = SCHEMA_DIGEST

    def __init__(self, *, tamper: bool = False):
        self.tamper = tamper
        self.calls = 0

    def commit(self, context, port):
        self.calls += 1
        candidate = prepared(context, port)
        pin = context["request"]["commands"][0]["args"]["values"]["raw_pin"]
        info = port.raw_media_info(pin)
        assert info == {"object_id": pin["media_id"], "media_type": "video/mp4", "size": 12}
        manifest = candidate["canonical_document"]["dependency_manifest"]
        manifest["media"] = [copy.deepcopy(pin)]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [
            {"key": "media:raw", "kind": "media", "pin": copy.deepcopy(pin), "policy": "exact"}
        ]
        if self.tamper:
            path = self._service.cas.path_for(pin["media_id"][7:])
            original = path.read_bytes()
            path.write_bytes(b"tampered!!!")
            try:
                return port.accept(candidate)
            finally:
                path.write_bytes(original)
        return port.accept(candidate)


def _seed(tmp_path: Path, *, pin=None, provider=None):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    service.register_timeline_commit_provider(provider or RawCaptureProvider())
    project = service.create_project({"slug": "raw-capture", "name": "Raw capture"})["id"]
    service.create_timeline(project, "main", idempotency_key="create-main")
    media = service.ingest(project, b"raw-video\x00\x01\x02", media_type="video/mp4", original_name="raw.mp4",
                           idempotency_key="raw")['data']
    selected = pin or {"media_id": media["object_id"], "content_digest": media["object_id"]}
    head = service.get_project_timeline(project, "main")
    request = {
        "api_version": 1,
        "project_id": project,
        "timeline_id": "main",
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"],
        "commands": [{
            "schema_version": 1,
            "op": "clip.set-params",
            "version": "1",
            "select": "parent/clip:clip-1",
            "args": {"values": {"raw_pin": selected}, "clear": []},
        }],
    }
    return service, root, project, request, selected, media["object_id"]


def _commit(service, project, request, *, key="raw-capture", publisher="test"):
    return service.commit_timeline(project, "main", request, idempotency_key=key, publisher=publisher,
                                   invocation_path=route_path(project, "main"), authorize=lambda: None)


def test_owned_raw_capture_from_empty_parent_is_unplaced_and_exact(tmp_path):
    service, _root, project, request, pin, _object_id = _seed(tmp_path)
    try:
        result = _commit(service, project, request)
        document = result["data"]["canonical_document"]
        assert document["dependency_manifest"]["media"] == [pin]
        assert document["parent_revision"]["payload"]["occurrences"] == []
        assert document["parent_revision"]["payload"]["clips"] == []
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM composition_revision_occurrences WHERE project_id=?", (project,)
        ).fetchone()[0] == 0
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM timeline_references WHERE timeline_id='main'"
        ).fetchone()[0] == 0
    finally:
        service.close()


@pytest.mark.parametrize("case", ["missing", "unowned", "foreign"])
def test_raw_capture_refuses_missing_unowned_or_foreign_object_without_writes(tmp_path, case):
    service, _root, project, request, pin, object_id = _seed(tmp_path)
    try:
        if case == "missing":
            pin = {"media_id": "sha256:" + "0" * 64, "content_digest": "sha256:" + "0" * 64}
        elif case == "unowned":
            service.store.conn.execute(
                "UPDATE project_objects SET relation='referenced' WHERE project_id=? AND digest=?",
                (project, object_id[7:]),
            )
        else:
            foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]
            foreign_media = service.ingest(foreign, b"foreign-only", media_type="video/mp4", original_name="foreign.mp4",
                                           idempotency_key="foreign")['data']
            pin = {"media_id": foreign_media["object_id"], "content_digest": foreign_media["object_id"]}
        request["commands"][0]["args"]["values"]["raw_pin"] = pin
        before = list(service.store.conn.iterdump())
        with pytest.raises((CommitRejected, NotFoundError)):
            _commit(service, project, request, key="refused-" + case)
        assert list(service.store.conn.iterdump()) == before
        assert service.get_project_timeline(project, "main")["head_revision_id"] == request["base_revision_id"]
    finally:
        service.close()


def test_raw_capture_rechecks_same_descriptor_before_writes(tmp_path):
    provider = RawCaptureProvider(tamper=True)
    service, _root, project, request, _pin, _object_id = _seed(tmp_path, provider=provider)
    provider._service = service
    try:
        before = list(service.store.conn.iterdump())
        with pytest.raises(ConflictError):
            _commit(service, project, request, key="race")
        assert provider.calls == 1
        assert list(service.store.conn.iterdump()) == before
        assert service.get_project_timeline(project, "main")["head_revision_id"] == request["base_revision_id"]
    finally:
        service.close()


def test_exact_retry_after_restart_replays_ledger_before_raw_capture(tmp_path, monkeypatch):
    service, root, project, request, _pin, _object_id = _seed(tmp_path)
    try:
        accepted = _commit(service, project, request, key="restart-retry")
    finally:
        service.close()

    restarted = RuntimeService(root)
    try:
        provider = RawCaptureProvider()
        restarted.register_timeline_commit_provider(provider)
        monkeypatch.setattr(RequestCommitPort, "raw_media_info",
                            lambda *_args, **_kwargs: pytest.fail("ledger replay reread raw media"))
        assert _commit(restarted, project, request, key="restart-retry") == accepted
        assert provider.calls == 0
    finally:
        restarted.close()
