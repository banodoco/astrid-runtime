"""Offline F230 diagnosis: fresh IDs and an owned deterministic scene relay.

The shape follows F226's retained occurrence.add, never its live envelope.
Runtime storage/port and the separately pinned Astrid provider remain real.
"""
import copy
import json
from types import SimpleNamespace

import pytest

from test_authoring_scene import bound, fixture  # noqa: F401
from test_timeline_accept import wire
from test_selected_media_commit import snapshot
from runtime_protocol.errors import AuthorizationError, ConflictError, ForbiddenError, ValidationError
from runtime_protocol.timeline_commit import RuntimeCommitPort, digest, result_template


@pytest.fixture(params=["issued", "saved"])
def occurrence_preview(bound, request):
    w = bound
    s, p = w.s, w.p
    # Replace only this disposable fixture's head with the retained empty shape.
    s.publish_parent_composition(p, "main", dict(
        project_id=p, timeline_id="main", expected_head=s.head(p, "main")["revision_id"],
        parent_revision_id="empty-voice-parent", shot_revisions=[], internal_timeline_revisions=[],
        parent_composition=dict(config=dict(tracks=[dict(id="voice", kind="audio", label="Voice")]),
                                registry={}, clips=[], occurrences=[])), idempotency_key="empty-voice")
    shot = s.create_project_shot(p, dict(shot_id="preview-shot", name="Offline empty holder"),
                                 idempotency_key="preview-shot")["data"]
    body = wire(p, key="offline-occurrence-preview", dry_run=True)
    head = s.head(p, "main")
    body.update(base_revision_id=head["revision_id"], base_publication_id=head["publication_id"])
    body["change"]["commands"] = [dict(op="occurrence.add", select="occurrence:offline-occurrence",
        args=dict(source=dict(shot_id=shot["shot_id"], shot_revision_id=shot["revision_id"],
                              internal_revision_id=shot["internal_timeline_revision_id"]),
                  mode="linked", placement=dict(start_ms=0, duration_ms=500, track="voice"),
                  identities=dict(occurrence_id="offline-occurrence")))]
    if request.param == "saved":
        # F226's canonical saved-call fields, with all identities replaced by
        # this fixture's own locators. No retained session/body is loaded.
        call = body["change"]["commands"][0]
        sid = call["select"]
        call.update(version="0.1.0", resolved=[sid], expect={"": {"state": "absent"}},
                    bindings={}, created=[sid, sid + "/shot"], authorship={
                        "": "direct", **{sid + suffix: "consequence" for suffix in (
                            "/registry::", "/shot::", "/source::")}})
    body["source"] = dict(via="python")
    body.pop("asserted_actor")  # saved_publish._prepare uses authenticated actor
    body["label"] = "Offline occurrence preview"
    return w, body


def test_exact_provider_on_offline_occurrence_shape(occurrence_preview):
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    w, body = occurrence_preview
    before = snapshot(w.s)
    port = w.s._request_commit_port(body, w.identity)
    try:
        result = create_runtime_commit_service().commit(copy.deepcopy(body), port)
        assert result["status"] == "preview", result
        port.validate_scene(result["canonical_document"])
    finally:
        port.close()
    assert snapshot(w.s) == before


def runtime_preview(w, body):
    return w.s.commit_timeline(w.p, "main", body, idempotency_key=body["request_id"], identity=w.identity)


def test_runtime_preview_on_offline_occurrence_shape(occurrence_preview):
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    w, body = occurrence_preview
    w.s._timeline_commit_provider = create_runtime_commit_service()
    before = snapshot(w.s)
    result = runtime_preview(w, body)
    assert result["status"] == "preview", result
    assert (result["request_id"], result["request_hash"], result["base_revision_id"]) == (
        body["request_id"], digest(body), body["base_revision_id"])
    assert result["accepted_revision_id"] is result["accepted_publication_id"] is result["runtime_receipt"] is None
    assert len(result["canonical_document"]["placements"]) == 1
    assert snapshot(w.s) == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


@pytest.mark.parametrize("stage", ["provider", "scene-binding", "preview-validation"])
def test_distinct_private_failures_are_indistinguishable_and_redacted(occurrence_preview, monkeypatch, stage):
    from astrid.sdk.timeline.commit import create_runtime_commit_service
    from runtime_protocol import authoring_scene
    w, body = occurrence_preview
    secret = "credential=synthetic-secret session=synthetic-handle fd=914 /private/fixture request-body-marker"
    seen = []
    def fail(*args, **kwargs):
        seen.append(stage)
        raise (ConflictError if stage == "scene-binding" else RuntimeError)(secret)
    w.s._timeline_commit_provider = create_runtime_commit_service()
    if stage == "provider":
        w.s._timeline_commit_provider = SimpleNamespace(commit=fail)
    elif stage == "scene-binding":
        monkeypatch.setattr(authoring_scene, "check_binding", fail)
    else:
        monkeypatch.setattr(RuntimeCommitPort, "validate_scene", fail)
    before = snapshot(w.s)
    result = runtime_preview(w, body)
    expected = result_template(body, digest(body))
    expected["error"] = dict(code="runtime_unavailable",
        message="Astrid commit provider failed; outcome may be unknown",
        hint="Acceptance may already be durable", next_action="Retry the original request id unchanged")
    assert result == expected
    assert seen == [stage]
    public = json.dumps(result)
    assert all(value not in public for value in (secret, "synthetic-secret", "synthetic-handle", "914",
                                                "/private/fixture", "request-body-marker", body["session_id"]))
    assert snapshot(w.s) == before
    assert w.s.lookup_request(w.p, "main", body["request_id"]) is None


@pytest.mark.parametrize("error", [AuthorizationError, ForbiddenError, ConnectionError, TimeoutError])
def test_authority_and_uncertain_transport_still_escape(occurrence_preview, error):
    w, body = occurrence_preview
    original = error("synthetic refusal")
    def fail(*args):
        raise original
    w.s._timeline_commit_provider = SimpleNamespace(commit=fail)
    before = snapshot(w.s)
    with pytest.raises(error) as caught:
        runtime_preview(w, body)
    assert caught.value is original
    assert snapshot(w.s) == before


@pytest.mark.parametrize("field", ["request_id", "request_hash", "base_revision_id", "status"])
def test_provider_result_identity_and_dry_run_acceptance_remain_closed(occurrence_preview, field):
    w, body = occurrence_preview
    def prepared(request, port):
        result = result_template(request, digest(request))
        result["status"] = "preview"
        result[field] = "accepted" if field == "status" else "foreign"
        return result
    w.s._timeline_commit_provider = SimpleNamespace(commit=prepared)
    before = snapshot(w.s)
    with pytest.raises(AuthorizationError if field == "status" else ValidationError):
        runtime_preview(w, body)
    assert snapshot(w.s) == before
