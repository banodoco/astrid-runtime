"""Native Agent revision admission survives a lost render acknowledgement."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from precut_realm_fixture import load_precut_realm_fixture
from timeline_commit_film_fixture import FilmFixture

from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

pytestmark = pytest.mark.integration


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def native_render_case(tmp_path, astrid_importable):
    from astrid.sdk.timeline.capture import capture_move
    from astrid.sdk.timeline.commit import bundle_from_document

    captured = load_precut_realm_fixture(tmp_path, variant="music-documents")
    pins = captured.pins
    film = FilmFixture(
        source_root=captured.copy_roots[0], duplicate_root=captured.copy_roots[1],
        project_id=pins["project_id"], timeline_id=pins["timeline_id"],
        parent_revision_id=pins["parent_revision_id"], media_ids=pins["media_ids"],
        transcript_document_id=pins["transcript_document_id"], text_binding_id=pins["text_binding_id"],
    )
    assert Path(capture_move.__code__.co_filename).resolve().is_relative_to(astrid_importable)
    service = RuntimeService(film.duplicate_root)
    service.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    render_digest = _digest("rendering.render")
    service.register_capability({"capability_id": "rendering.render", "definition_digest": render_digest})
    service.register_executor({"executor_id": "render-worker", "capabilities": ["rendering.render"]})
    try:
        yield SimpleNamespace(service=service, film=film, move=capture_move, bundle=bundle_from_document,
                              render_digest=render_digest)
    finally:
        service.close()


def _head(case):
    value = case.service.get_project_timeline(case.film.project_id, case.film.timeline_id)
    return {"revision_id": value["head_revision_id"], "publication_id": value["head_publication_id"]}


def _document(case, revision):
    return case.service._timeline_commits()[0].revision_closure(
        case.film.project_id, case.film.timeline_id, revision,
    )


def _move(case, clip, at, key):
    base = _head(case)
    command = case.move(case.bundle(_document(case, base["revision_id"])), f"parent/clip:{clip}", at)
    body = {"api_version": 1, "project_id": case.film.project_id, "timeline_id": case.film.timeline_id,
            "base_revision_id": base["revision_id"], "base_publication_id": base["publication_id"],
            "commands": [command], "source": {"via": "python"}}
    return case.service.commit_timeline(
        case.film.project_id, case.film.timeline_id, body, idempotency_key=key,
        publisher="native-render-admission", invocation_path=route_path(case.film.project_id, case.film.timeline_id),
        authorize=lambda: None,
    )


def test_native_accepted_revision_render_admission_replays_after_lost_ack_and_restart(native_render_case):
    from astrid.core.dev.journey import build_app_render_admission

    case = native_render_case
    accepted_a = _move(case, "music-bed", 1, "native-render-A")
    capability = case.service.list_capabilities()["items"][0]
    built = build_app_render_admission(
        project=case.film.project_id, timeline_id=case.film.timeline_id, output_name="native-a.mp4",
        capability=capability, token="test-token",
    )
    assert built["body"]["capability_id"] == "rendering.render"
    assert built["body"]["spec"]["family"] == "rendering.render"
    request = copy.deepcopy(built["body"])
    request["idempotency_key"] = built["headers"]["Idempotency-Key"]
    accepted_parent = accepted_a["data"]["canonical_document"]["parent_revision"]
    request["spec"]["params"]["canonical_revision"] = {
        "project_id": case.film.project_id, "timeline_id": case.film.timeline_id,
        "revision_id": accepted_a["data"]["accepted_revision_id"],
        "publication_id": accepted_a["receipt"]["receipt_id"],
        "content_digest": accepted_parent["content_digest"],
    }

    admitted = case.service.create_task(request)
    original_admission = copy.deepcopy(admitted)
    original_task = original_admission["task"]
    original_run = original_admission["run"]
    authority = original_task["spec"]["spec"]["inputs"]["timeline_authority"]
    parent = accepted_parent
    assert authority["parent_revision_id"] == accepted_a["data"]["accepted_revision_id"]
    assert authority["publication_id"] == accepted_a["receipt"]["receipt_id"]
    assert authority["parent_content_digest"] == parent["content_digest"]
    snapshot_ref = original_task["spec"]["spec"]["timeline_snapshot_ref"]
    retained_a = case.service.object(snapshot_ref["digest"])[1]

    # The caller loses this response after the durable admission; it keeps the
    # exact body/key for recovery, as the real outbox does.
    accepted_c = _move(case, "music-other", 2, "native-render-C")
    assert accepted_c["data"]["accepted_revision_id"] != accepted_a["data"]["accepted_revision_id"]
    case.service.close()
    case.service = RuntimeService(case.film.duplicate_root)
    case.service.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))
    try:
        replay = case.service.create_task(copy.deepcopy(request))
        assert replay == original_admission
        assert replay["task"] == original_task
        assert replay["run"] == original_run
        assert case.service.object(snapshot_ref["digest"])[1] == retained_a
        assert case.service.get_project_timeline(case.film.project_id, case.film.timeline_id)["head_revision_id"] == accepted_c["data"]["accepted_revision_id"]
        assert case.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert case.service.store.conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    finally:
        case.service.close()
