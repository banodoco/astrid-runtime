from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contract" / "schemas" / "shot-composition.json"
MATRIX_PATH = ROOT / "conformance" / "fixtures" / "shot-composition-compatibility.json"
TIMELINE_SCHEMA_PATH = ROOT / "contract" / "schemas" / "timeline-config.schema.json"
TIMELINE_SCHEMA_PROVENANCE_PATH = ROOT / "contract" / "schemas" / "timeline-config.schema.provenance.json"
TIMELINE_SCHEMA_URI = "https://astrid.haus/workspace/v1/schemas/timeline-config.schema.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _matrix() -> dict:
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def _composition_validator(schema: dict) -> Draft202012Validator:
    canonical = json.loads(TIMELINE_SCHEMA_PATH.read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        (
            (TIMELINE_SCHEMA_URI, Resource.from_contents(canonical)),
        )
    )
    return Draft202012Validator(schema, registry=registry)


def _shot_payload_validator(schema: dict) -> Draft202012Validator:
    canonical = json.loads(TIMELINE_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$id": schema["$id"],
            "$ref": "#/$defs/ShotPayload",
            "$defs": schema["$defs"],
        },
        registry=Registry().with_resources(
            (
                (TIMELINE_SCHEMA_URI, Resource.from_contents(canonical)),
            )
        ),
    )


def _nonempty_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _read_name(payload: dict, shot_id: str) -> str:
    provenance = payload.get("provenance") if isinstance(payload.get("provenance"), dict) else {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    for value in (
        payload.get("name"),
        provenance.get("name"),
        provenance.get("title"),
        metadata.get("name"),
        metadata.get("title"),
        shot_id,
    ):
        normalized = _nonempty_text(value)
        if normalized is not None:
            return normalized
    raise AssertionError("fixture shot identity must be stable and non-empty")


def _read_media_kind(managed_media: dict) -> str:
    media_type = managed_media.get("media_type")
    if not isinstance(media_type, str):
        return "unknown"
    normalized = media_type.strip().lower()
    for kind in ("image", "video", "audio"):
        if normalized.startswith(kind + "/"):
            return kind
    return "unknown"


def test_schema_declares_raw_container_boundary_without_a_second_compiled_schema() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)

    assert schema["x-astrid-runtime-owner"] == "astrid-runtime"
    assert schema["x-astrid-runtime-canonical-timeline-owner"] == "@banodoco/timeline-schema"
    config = schema["$defs"]["ParentComposition"]["properties"]["config"]
    assert config["$ref"] == "#/$defs/RawTimelinePayload"
    registry = schema["$defs"]["ParentComposition"]["properties"]["registry"]
    assert registry["x-astrid-runtime-schema-owner"] == "astrid-runtime#ManagedMediaRegistry"
    assert "outside the canonical TimelineConfig" in registry["description"]
    assert registry["additionalProperties"] is True
    internal = schema["$defs"]["InternalTimelineRevisionInput"]["properties"]["payload"]
    assert internal["$ref"] == "#/$defs/RawTimelinePayload"
    raw = schema["$defs"]["RawTimelinePayload"]
    assert raw["additionalProperties"] is True
    assert "required" not in raw
    assert "TimelineConfig" not in schema["$defs"]
    assert "TimelineClip" not in schema["$defs"]


def test_dependency_manifest_extension_keys_remain_open_and_lossless() -> None:
    manifest = {
        "future_dependency_family": [{"id": "extension-1", "opaque": {"keep": True}}]
    }
    validator = Draft202012Validator(_schema()["$defs"]["DependencyManifest"])

    assert not list(validator.iter_errors(manifest))
    assert json.loads(json.dumps(manifest, sort_keys=True)) == manifest


def test_empty_and_ordinary_only_composition_fixtures_validate_losslessly() -> None:
    schema = _schema()
    validator = _composition_validator(schema)

    for case in _matrix()["composition_shapes"]:
        original = copy.deepcopy(case["publication"])
        errors = sorted(validator.iter_errors(case["publication"]), key=lambda error: list(error.path))
        assert errors == [], (case["id"], [error.message for error in errors])
        assert json.loads(json.dumps(case["publication"], sort_keys=True)) == original
        assert case["publication"] == original


def test_pinned_compiled_timeline_schema_remains_strict() -> None:
    canonical = json.loads(TIMELINE_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(canonical)
    assert canonical["required"] == ["clips", "tracks"]
    for case in _matrix()["composition_shapes"]:
        config = case["publication"]["parent_composition"]["config"]
        assert not list(Draft7Validator(canonical).iter_errors(config)), case["id"]

    invalid = {"tracks": [], "clips": "not-a-list"}
    assert list(Draft7Validator(canonical).iter_errors(invalid))

    role_config = {
        "tracks": [{"id": "source", "kind": "visual", "label": "Source", "role": "source"}],
        "clips": [],
    }
    assert not list(Draft7Validator(canonical).iter_errors(role_config))
    track_schema = canonical["properties"]["tracks"]["items"]
    assert "role" not in track_schema["required"]
    role_config["tracks"][0]["role"] = "draft"
    assert list(Draft7Validator(canonical).iter_errors(role_config))


def test_standalone_timeline_schema_validates_meta_without_registry() -> None:
    canonical = json.loads(TIMELINE_SCHEMA_PATH.read_text(encoding="utf-8"))
    config = {
        "meta": {"org.example.config": {"nullable": None}},
        "tracks": [{
            "id": "video",
            "kind": "visual",
            "label": "Video",
            "meta": {"org.example.track": {"enabled": True}},
        }],
        "clips": [{
            "id": "clip",
            "at": 0,
            "track": "video",
            "meta": {"org.example.clip": {"items": [1, None]}},
        }],
    }

    validator = Draft7Validator(canonical)
    assert not list(validator.iter_errors(config))
    assert list(validator.iter_errors({**config, "meta": {"org..invalid": {}}}))


def test_materialized_timeline_schema_provenance_and_compatible_raw_field_reuse() -> None:
    schema = json.loads(TIMELINE_SCHEMA_PATH.read_text(encoding="utf-8"))
    provenance = json.loads(TIMELINE_SCHEMA_PROVENANCE_PATH.read_text(encoding="utf-8"))
    digest = hashlib.sha256(TIMELINE_SCHEMA_PATH.read_bytes()).hexdigest()
    composition = _schema()
    raw_role = composition["$defs"]["RawTrack"]["properties"]["role"]

    assert schema["properties"]["tracks"]["items"]["properties"]["role"]["enum"] == ["output", "source"]
    assert provenance["sha256"] == digest
    assert provenance["base_sha256"] == "f52b82024ecd44a5e6c9c68d5cb326d50d70efe9aaad6f8ac6352ea1c87b97b1"
    assert provenance["role_extension"]["source_commit"] == "3bd1d019715de79cd54aa208cf26de10427c29d5"
    assert provenance["role_extension"]["source_artifact_sha256"] == provenance["base_sha256"]
    assert provenance["runtime_meta_extension"]["owner"] == "astrid-runtime"
    assert raw_role == {"$ref": "timeline-config.schema.json#/properties/tracks/items/properties/role"}


def test_meta_is_bounded_opaque_and_available_on_all_v1_locations() -> None:
    schema = _schema()
    publication = copy.deepcopy(_matrix()["composition_shapes"][0]["publication"])
    publication["parent_composition"]["meta"] = {
        "org.example.notes": {"nullable": None, "items": [2, {"keep": True}]}
    }
    publication["parent_composition"]["config"] = {
        "meta": {"com.example.config": {}},
        "clips": [{"id": "clip", "at": 0, "track": "video", "meta": {"org.example.clip": {}}}],
        "tracks": [{"id": "video", "kind": "visual", "label": "Video", "meta": {"org.example.track": {}}}],
        "assets": [{"meta": {"org.example.asset": {"source": "raw"}}}],
        "registry": {"assets": {"asset": {"meta": {"org.example.asset": {"source": "registry"}}}}},
    }
    publication["parent_composition"]["clips"] = [
        {"id": "clip", "at": 0, "track": "video", "meta": {"org.example.clip": {}}}
    ]
    publication["parent_composition"]["occurrences"] = [{
        "occurrence_id": "occurrence",
        "shot_id": "shot",
        "shot_revision_id": "shot-revision",
        "placement": {},
        "duration_ms": 1,
        "track": "video",
        "meta": {"org.example.occurrence": {}},
    }]
    publication["shot_revisions"] = [{
        "shot_id": "shot",
        "revision_id": "shot-revision",
        "internal_timeline_revision_id": "internal-revision",
        "payload": {"meta": {"org.example.shot": {}}, "assets": [{"meta": {"org.example.asset": {}}}]},
    }]
    publication["internal_timeline_revisions"] = [{
        "timeline_id": "internal",
        "revision_id": "internal-revision",
        "payload": {"meta": {"org.example.internal": {}}, "clips": [], "tracks": []},
    }]

    assert not list(_composition_validator(schema).iter_errors(publication))

    meta = schema["$defs"]["ParentComposition"]["properties"]["meta"]
    assert meta["$ref"] == "timeline-config.schema.json#/definitions/Meta"
    canonical = json.loads(TIMELINE_SCHEMA_PATH.read_text(encoding="utf-8"))
    meta_schema = {"$ref": "#/definitions/Meta", "definitions": canonical["definitions"]}
    validator = Draft7Validator(meta_schema)
    assert not list(validator.iter_errors({"a": {}, "z9.test": {"null": None, "array": [False]}}))
    for invalid in (
        None,
        {"Org.example.bad": {}},
        {"org..bad": {}},
        {"org.example.bad": None},
        {str(index): {} for index in range(65)},
    ):
        assert list(validator.iter_errors(invalid)), invalid


def test_supported_silent_voiceover_legacy_audio_and_extension_payloads_validate() -> None:
    schema = _schema()
    validator = _shot_payload_validator(schema)

    for case in _matrix()["shot_payload_shapes"]:
        original = copy.deepcopy(case["payload"])
        errors = sorted(validator.iter_errors(case["payload"]), key=lambda error: list(error.path))
        assert errors == [], (case["id"], [error.message for error in errors])
        assert _read_name(case["payload"], case["shot_id"]) == case["read_normalization"]["name"]
        assert json.loads(json.dumps(case["payload"], sort_keys=True)) == original
        assert case["payload"] == original

    by_id = {case["id"]: case for case in _matrix()["shot_payload_shapes"]}
    assert "audio" not in by_id["silent-canonical-name"]["payload"]
    assert "audio_bindings" not in by_id["silent-canonical-name"]["payload"]
    assert "audio" not in by_id["single-voiceover"]["payload"]
    assert "audio" not in by_id["multi-voiceover"]["payload"]
    assert by_id["legacy-aggregate-audio"]["payload"]["audio"]["future_gain_curve"] == [0, 1]
    assert by_id["unknown-extensions"]["payload"]["future_sibling"]["payload"] == ["a", "b"]


def test_name_read_precedence_and_write_preservation_matrix() -> None:
    validator = _shot_payload_validator(_schema())

    for case in _matrix()["name_normalization"]:
        original = copy.deepcopy(case["payload"])
        assert not list(validator.iter_errors(case["payload"])), case["id"]
        assert _read_name(case["payload"], case["shot_id"]) == case["expected"]
        assert case["payload"] == original


def test_media_kind_uses_managed_media_and_never_defaults_to_image() -> None:
    for case in _matrix()["media_kind_normalization"]:
        aliases = copy.deepcopy(case["payload_aliases"])
        assert _read_media_kind(case["managed_media"]) == case["expected"], case["id"]
        assert case["payload_aliases"] == aliases

    by_id = {case["id"]: case for case in _matrix()["media_kind_normalization"]}
    assert by_id["known-video-conflicting-image-alias"]["expected"] == "video"
    assert by_id["unknown-authoritative-type"]["expected"] == "unknown"
    assert by_id["missing-authoritative-type"]["expected"] == "unknown"


def test_malformed_known_core_and_invalid_present_media_are_rejected() -> None:
    validator = _shot_payload_validator(_schema())

    for case in _matrix()["invalid_shot_payloads"]:
        errors = list(validator.iter_errors(case["payload"]))
        assert errors, case["id"]


def test_open_shot_payload_keeps_unknown_siblings_but_outer_envelope_stays_closed() -> None:
    schema = _schema()
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["ShotPayload"]["additionalProperties"] is True
    assert schema["$defs"]["ShotAsset"]["additionalProperties"] is True
    assert schema["$defs"]["OpenBinding"]["additionalProperties"] is True

    valid = copy.deepcopy(_matrix()["composition_shapes"][0]["publication"])
    valid["unknown_envelope_field"] = True
    assert list(_composition_validator(schema).iter_errors(valid))
