from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from precut_realm_fixture import load_precut_realm_fixture
from runtime_protocol.errors import ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline
from runtime_protocol.timeline_commit_validation import validate_commit_value
from runtime_protocol.util import canonical_json
from test_timeline_commit_validation import prepared
from timeline_commit_film_fixture import build_film_fixture


ROOT = Path(__file__).resolve().parents[1]


def test_prepared_accepts_exact_api_produced_raw_immutable_images(tmp_path):
    film = build_film_fixture(tmp_path)
    captured = load_precut_realm_fixture(tmp_path, variant="raw")
    service = RuntimeService(film.duplicate_root)
    try:
        original = verify_baseline(
            service.store.conn, film.project_id, film.timeline_id,
            read_object=service.cas.read,
        )["canonical_document"]
        parent = copy.deepcopy(original["parent_revision"]["payload"])
        internal = copy.deepcopy(original["internal_timeline_revisions"][0])
        shot = next(copy.deepcopy(image) for image in original["shot_revisions"]
                    if image["internal_timeline_revision_id"] == internal["revision_id"])
        parent["config"]["output"] = {
            "fps": 24,
            "background": None, "future_output": {"clear": None},
        }
        parent["config"]["future_config"] = None
        parent["future_parent"] = {"opaque": [None, False]}
        raw = internal["payload"]
        raw["output"] = copy.deepcopy(parent["config"]["output"])
        raw["output"]["fps"] = {"numerator": 30000, "denominator": 1001}
        raw["playback"] = {"future_playback": None}
        raw["future_internal"] = {"opaque": [None, False]}
        raw["tracks"][0]["future_track"] = None
        raw["clips"][0].update(volume=None, future_clip={"clear": None})
        old_shot_revision = shot["revision_id"]
        internal["revision_id"] = "raw-internal"
        shot["revision_id"] = "raw-shot"
        shot["internal_timeline_revision_id"] = internal["revision_id"]
        for occurrence in parent["occurrences"]:
            if occurrence["shot_revision_id"] == old_shot_revision:
                occurrence["shot_revision_id"] = shot["revision_id"]
        service.close()
        service = RuntimeService(captured.copy_roots[1])
        baseline = verify_baseline(
            service.store.conn, film.project_id, film.timeline_id,
            read_object=service.cas.read,
        )
        assert baseline["head"] == {
            "revision_id": "raw-parent",
            "publication_id": captured.pins["publication_receipt_id"],
        }
        receipt = baseline["entries"][-1]["receipt"]
        assert receipt["idempotency_key"] == "raw-publication"
        assert receipt["event_ids"] == list(captured.pins["publication_event_ids"])
        document = baseline["canonical_document"]
        value = prepared()
        value["canonical_document"] = document
        value["document_digest"] = service._revision_digest(document)
        before = canonical_json(value)
        validate_commit_value(value, "PreparedCommit")
        assert canonical_json(value) == before
        assert canonical_json(document["parent_revision"]["payload"]) == canonical_json(parent)
        stored = next(image for image in document["internal_timeline_revisions"]
                      if image["revision_id"] == internal["revision_id"])
        assert canonical_json(stored["payload"]) == canonical_json(raw)
        for image in [document["parent_revision"], *document["internal_timeline_revisions"]]:
            assert image["content_digest"] == service._revision_digest(image["payload"])
    finally:
        service.close()


def test_raw_conformance_payloads_validate_without_mutation():
    matrix = json.loads((ROOT / "conformance/fixtures/shot-composition-compatibility.json").read_text())
    for case in matrix["raw_timeline_payloads"]:
        value = prepared()
        value["canonical_document"]["parent_revision"]["payload"]["config"] = copy.deepcopy(case["payload"])
        value["canonical_document"]["internal_timeline_revisions"][0]["payload"] = copy.deepcopy(case["payload"])
        before = canonical_json(value)
        validate_commit_value(value, "PreparedCommit")
        assert canonical_json(value) == before, case["id"]
        parent = value["canonical_document"]["parent_revision"]["payload"]
        assert canonical_json(RuntimeService._complete_parent_payload(parent)["config"]) == canonical_json(case["payload"])


@pytest.mark.parametrize("visual_fields", [
    {
        "entrance": {"id": "fade-up", "durationFrames": 12, "easing": "ease-out",
                     "params": {"easing": "ease-out"}},
        "exit": {"id": "slide-up", "durationFrames": 8},
        "transition": {"id": "cross-fade", "durationFrames": 10},
    },
    {
        "entrance": {"type": "fade", "duration": 0.5},
        "exit": {"type": "fade", "duration": 0.25},
        "transition": {"type": "crossfade", "duration": 0.4},
    },
])
def test_prepared_schema_accepts_canonical_and_drawable_legacy_visual_fields(visual_fields):
    value = prepared()
    document = value["canonical_document"]
    clip = {"id": "visual", **copy.deepcopy(visual_fields),
            "params": {"entrance": {"id": "project-custom", "durationFrames": 12}}}
    document["parent_revision"]["payload"]["clips"] = [clip]
    document["parent_revision"]["payload"]["config"]["clips"] = [copy.deepcopy(clip)]
    document["internal_timeline_revisions"][0]["payload"]["clips"] = [copy.deepcopy(clip)]

    before = canonical_json(value)
    validate_commit_value(value, "PreparedCommit")
    assert canonical_json(value) == before


@pytest.mark.parametrize("location", ["parent", "internal"])
@pytest.mark.parametrize("field,malformed", [
    ("tracks", {}), ("tracks", [None]), ("tracks", [{"id": 4}]),
    ("tracks", [{"role": "draft"}]), ("clips", {}), ("clips", [None]),
    ("clips", [{"track": []}]),
    ("effects", {}), ("effects", [False]), ("assets", {}),
    ("audio", {}), ("audio", [False]), ("layout", []),
    ("registry", []), ("output", []), ("output", {"fps": False}),
    ("output", {"fps": {"numerator": "bad"}}), ("playback", []),
])
def test_malformed_known_raw_containers_refuse_422(location, field, malformed):
    value = prepared()
    document = value["canonical_document"]
    payload = (document["parent_revision"]["payload"]["config"] if location == "parent"
               else document["internal_timeline_revisions"][0]["payload"])
    payload[field] = malformed
    with pytest.raises(ValidationError) as caught:
        validate_commit_value(value, "PreparedCommit")
    assert caught.value.status == 422


@pytest.mark.parametrize("location", ["prepared", "document", "parent", "internal"])
def test_raw_openness_does_not_open_outer_envelopes(location):
    value = prepared()
    document = value["canonical_document"]
    target = {"prepared": value, "document": document,
              "parent": document["parent_revision"],
              "internal": document["internal_timeline_revisions"][0]}[location]
    target["future"] = None
    with pytest.raises(ValidationError) as caught:
        validate_commit_value(value, "PreparedCommit")
    assert caught.value.status == 422


@pytest.mark.parametrize("field,malformed", [
    ("config", []), ("registry", []), ("clips", {}), ("clips", [None]),
    ("occurrences", {}), ("occurrences", [None]),
])
def test_malformed_parent_containers_refuse_422(field, malformed):
    value = prepared()
    value["canonical_document"]["parent_revision"]["payload"][field] = malformed
    with pytest.raises(ValidationError) as caught:
        validate_commit_value(value, "PreparedCommit")
    assert caught.value.status == 422
