"""Production-port authority checks for cross-timeline source duplication."""
from __future__ import annotations

import copy
import json

import pytest
from test_timeline_commit_port import PreparedProvider, prepared

from runtime_protocol.errors import AuthorizationError, NotFoundError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import digest, route_path


@pytest.fixture
def service(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    provider = PreparedProvider()
    runtime.test_provider = provider
    runtime.register_timeline_commit_provider(provider)
    project = runtime.create_project({"slug": "source-authority", "name": "Source authority"})["id"]
    runtime.create_timeline(project, "main", idempotency_key="create-main")
    runtime.create_timeline(project, "source", idempotency_key="create-source")
    runtime.test_project = project
    try:
        yield runtime
    finally:
        runtime.close()


def _request(service, timeline, *, command=None):
    head = service.get_project_timeline(service.test_project, timeline)
    return {
        "api_version": 1,
        "project_id": service.test_project,
        "timeline_id": timeline,
        "base_revision_id": head["head_revision_id"],
        "base_publication_id": head["head_publication_id"],
        "commands": [command or {
            "schema_version": 1,
            "op": "clip.move",
            "version": "1",
            "select": "parent/clip:clip-1",
            "args": {"on": 2},
        }],
    }


def _commit(service, timeline, body, key, *, authorize=lambda: None):
    return service.commit_timeline(
        service.test_project,
        timeline,
        body,
        idempotency_key=key,
        publisher="source-authority-test",
        invocation_path=route_path(service.test_project, timeline),
        authorize=authorize,
    )


def _source_ref(service):
    resource = service.get_project_timeline(service.test_project, "source")
    row = service.store.conn.execute(
        "SELECT commit_manifest_json FROM parent_composition_revisions WHERE id=?",
        (resource["head_revision_id"],),
    ).fetchone()
    if row["commit_manifest_json"] is None:
        _commit(service, "source", _request(service, "source"), "source-reference")
        resource = service.get_project_timeline(service.test_project, "source")
    closure = service._timeline_commits()[0].revision_closure(
        service.test_project, "source", resource["head_revision_id"]
    )
    return {
        "project_id": service.test_project,
        "timeline_id": "source",
        "revision_id": resource["head_revision_id"],
        "publication_id": resource["head_publication_id"],
        "content_digest": closure["parent_revision"]["content_digest"],
    }


def _source_command(ref, **args):
    return {
        "schema_version": 1,
        "op": "timeline.duplicate",
        "version": "1",
        "select": None,
        "args": {"source_ref": copy.deepcopy(ref), **args},
    }


def _install_source_reader(service, *, after_capture=None):
    def action(context, port):
        ref = context["request"]["commands"][0]["args"].get("source_ref")
        if ref is not None:
            port.revision_closure(ref)
            if after_capture is not None:
                after_capture(context, port, ref)
        candidate = prepared(context, port)
        return port.accept(candidate)

    service.test_provider.action = action


def _reason(error):
    details = getattr(error.value, "details", {}) or {}
    return details.get("reason")


def test_real_port_accepts_exact_historical_source_and_rechecks_pair(service):
    ref = _source_ref(service)
    _install_source_reader(service)

    # The source head may move after the immutable source was captured.  The
    # exact accepted historical pair remains authoritative; Runtime must not
    # silently refresh it to the new source head.
    source_edit = _request(service, "source")
    _commit(service, "source", source_edit, "source-edit")
    result = _commit(service, "main", _request(service, "main", command=_source_command(ref)), "copy-exact")

    assert result["data"]["status"] == "accepted"
    assert result["receipt"]["result"] == result["data"]


@pytest.mark.parametrize("mutation", ["foreignsource", "outsidesource", "stalesource", "pairdigest"])
def test_source_pair_scope_and_access_fail_closed(service, mutation):
    ref = _source_ref(service)
    if mutation == "foreignsource":
        foreign = service.create_project({"slug": "foreign-source", "name": "Foreign source"})["id"]
        service.create_timeline(foreign, "foreign-source", idempotency_key="foreign-timeline")
        ref["project_id"] = foreign
        ref["timeline_id"] = "foreign-source"
    elif mutation == "outsidesource":
        ref["timeline_id"] = "outside-source"
    elif mutation == "stalesource":
        service.archive_timeline("source", {"expected_version": 1}, idempotency_key="archive-source")
    else:
        ref["publication_id"] = "not-the-source-publication"

    _install_source_reader(service)
    with pytest.raises((RuntimeErrorBase, NotFoundError)) as error:
        _commit(service, "main", _request(service, "main", command=_source_command(ref)), mutation)
    if _reason(error) is not None:
        assert _reason(error) in {"dependency_unavailable", "history_unavailable"}


def test_digest_mismatch_is_refused_without_destination_write(service):
    ref = _source_ref(service)
    ref["content_digest"] = "sha256:" + "0" * 64
    _install_source_reader(service)
    before = service.get_project_timeline(service.test_project, "main")

    with pytest.raises((RuntimeErrorBase, NotFoundError)) as error:
        _commit(service, "main", _request(service, "main", command=_source_command(ref)), "pair-digest")

    assert isinstance(error.value, (RuntimeErrorBase, NotFoundError))
    assert service.get_project_timeline(service.test_project, "main") == before


def test_forged_media_and_caller_source_access_are_inside_port_authority(service):
    ref = _source_ref(service)
    fake_media = {"media_id": "sha256:" + "1" * 64, "content_digest": "sha256:" + "1" * 64}

    def forged_media(context, port):
        port.revision_closure(ref)
        port.raw_media_info(fake_media)
        return port.accept(prepared(context, port))

    service.test_provider.action = forged_media
    with pytest.raises((RuntimeErrorBase, NotFoundError)) as error:
        _commit(
            service,
            "main",
            _request(service, "main", command=_source_command(ref, media=fake_media)),
            "forged-media",
        )
    assert isinstance(error.value, (RuntimeErrorBase, NotFoundError))

    access = {"allowed": True}

    def authorize():
        if not access["allowed"]:
            raise AuthorizationError("source access revoked")

    def revoke_after_capture(context, port, source_ref):
        access["allowed"] = False

    _install_source_reader(service, after_capture=revoke_after_capture)
    with pytest.raises(AuthorizationError):
        _commit(
            service,
            "main",
            _request(service, "main", command=_source_command(ref)),
            "source-access",
            authorize=authorize,
        )


def test_changed_source_capture_is_rejected_at_acceptance(service):
    ref = _source_ref(service)

    def change_capture(context, port, source_ref):
        row = service.store.conn.execute(
            "SELECT payload_json FROM parent_composition_revisions WHERE id=?",
            (source_ref["revision_id"],),
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["tampered_source_capture"] = True
        service.store.conn.execute(
            "UPDATE parent_composition_revisions SET payload_json=? WHERE id=?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), source_ref["revision_id"]),
        )

    _install_source_reader(service, after_capture=change_capture)
    with pytest.raises(RuntimeErrorBase) as error:
        _commit(service, "main", _request(service, "main", command=_source_command(ref)), "changed-capture")
    assert _reason(error) in {"dependency_unavailable", "invalid_closure"}


def _source_media_setup(service):
    media = service.ingest(
        service.test_project, b"source-video", media_type="video/mp4", original_name="source.mp4",
        idempotency_key="source-media",
    )["data"]
    pin = {"media_id": media["object_id"], "content_digest": media["object_id"]}

    def write_source(context, port):
        candidate = prepared(context, port)
        source_pin = context["request"]["commands"][0]["args"]["values"]["raw_pin"]
        port.raw_media_info(source_pin)
        candidate["canonical_document"]["dependency_manifest"]["media"] = [copy.deepcopy(source_pin)]
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [{
            "key": "media:raw", "kind": "media", "pin": copy.deepcopy(source_pin), "policy": "exact",
        }]
        return port.accept(candidate)

    service.test_provider.action = write_source
    source_request = _request(service, "source", command={
        "schema_version": 1,
        "op": "clip.set-params",
        "version": "1",
        "select": "parent/clip:clip-1",
        "args": {"values": {"raw_pin": pin}, "clear": []},
    })
    _commit(service, "source", source_request, "source-media-commit")
    return _source_ref(service), pin


def _install_source_media_reader(service, pin, *, capture, after_capture=None):
    def action(context, port):
        ref = context["request"]["commands"][0]["args"]["source_ref"]
        source = port.revision_closure(ref)
        source_pin = source["dependency_manifest"]["media"][0]
        assert source_pin == pin
        if after_capture is not None:
            after_capture(ref)
        candidate = prepared(context, port)
        candidate["canonical_document"]["dependency_manifest"]["media"] = [copy.deepcopy(source_pin)]
        if capture:
            port.raw_media_info(source_pin)
        candidate["document_digest"] = digest(candidate["canonical_document"])
        candidate["records"]["commands"][0]["dependencies"] = [{
            "key": "media:raw", "kind": "media", "pin": copy.deepcopy(source_pin), "policy": "exact",
        }]
        return port.accept(candidate)

    service.test_provider.action = action


def test_source_media_copy_requires_raw_capture_and_accepts_captured_pin(service):
    ref, pin = _source_media_setup(service)
    _install_source_media_reader(service, pin, capture=True)

    result = _commit(service, "main", _request(service, "main", command=_source_command(ref)), "copy-source-media")

    assert result["data"]["canonical_document"]["dependency_manifest"]["media"] == [pin]


def test_source_media_copy_without_raw_capture_fails_before_destination_write(service):
    ref, _pin = _source_media_setup(service)
    _install_source_media_reader(service, _pin, capture=False)
    before = service.get_project_timeline(service.test_project, "main")

    with pytest.raises(RuntimeErrorBase) as error:
        _commit(service, "main", _request(service, "main", command=_source_command(ref)), "missing-source-media-capture")

    assert _reason(error) == "dependency_unavailable"
    assert service.get_project_timeline(service.test_project, "main") == before


def test_source_media_forged_pin_is_rejected_even_with_source_closure(service):
    ref, pin = _source_media_setup(service)
    forged = {"media_id": "sha256:" + "1" * 64, "content_digest": "sha256:" + "1" * 64}

    def action(context, port):
        port.revision_closure(ref)
        candidate = prepared(context, port)
        candidate["canonical_document"]["dependency_manifest"]["media"] = [forged]
        port.raw_media_info(forged)
        return port.accept(candidate)

    service.test_provider.action = action
    with pytest.raises((RuntimeErrorBase, NotFoundError)):
        _commit(service, "main", _request(service, "main", command=_source_command(ref, media=pin)), "forged-source-media")


def test_changed_source_media_capture_is_rejected_before_destination_write(service):
    ref, pin = _source_media_setup(service)

    def change_capture(source_ref):
        row = service.store.conn.execute(
            "SELECT payload_json FROM parent_composition_revisions WHERE id=?",
            (source_ref["revision_id"],),
        ).fetchone()
        payload = json.loads(row["payload_json"])
        payload["tampered_source_media_capture"] = True
        service.store.conn.execute(
            "UPDATE parent_composition_revisions SET payload_json=? WHERE id=?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), source_ref["revision_id"]),
        )

    _install_source_media_reader(service, pin, capture=True, after_capture=change_capture)
    before = service.get_project_timeline(service.test_project, "main")
    with pytest.raises(RuntimeErrorBase) as error:
        _commit(service, "main", _request(service, "main", command=_source_command(ref)), "changed-source-media")

    assert _reason(error) in {"dependency_unavailable", "invalid_closure"}
    assert service.get_project_timeline(service.test_project, "main") == before


def test_missing_source_closure_is_refused_before_destination_write(service, monkeypatch):
    ref = _source_ref(service)
    store = service._timeline_commits()[0]
    revision_closure = store.revision_closure

    def unavailable_source(project_id, timeline_id, revision_id):
        if timeline_id == "source":
            return None
        return revision_closure(project_id, timeline_id, revision_id)

    monkeypatch.setattr(store, "revision_closure", unavailable_source)
    _install_source_reader(service)
    before = service.get_project_timeline(service.test_project, "main")
    history_count = service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0]

    with pytest.raises(RuntimeErrorBase) as error:
        _commit(service, "main", _request(service, "main", command=_source_command(ref)), "missing-source-closure")

    assert _reason(error) == "dependency_unavailable"
    assert service.get_project_timeline(service.test_project, "main") == before
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == history_count
