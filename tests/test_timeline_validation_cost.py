from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from referencing.exceptions import Unresolvable

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol import timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError
from runtime_protocol.timeline_commit import CommitRejected

FIXTURE = Path(__file__).parent / "fixtures/timeline_sequential_capture.json"


def _packet():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_retained_capture_boundaries_call_the_shared_validator_once_each(monkeypatch):
    packet = _packet()
    boundaries = [
        document
        for side in ("original", "landing")
        for command in packet["capture"][side]["commands"]
        for document in (command["input"], command["output"])
    ]
    original_validator = validation._validator("CanonicalDocument")
    calls = []

    class CountingValidator:
        def validate(self, value):
            calls.append(value)
            return original_validator.validate(value)

    monkeypatch.setattr(validation, "_validator", lambda _definition: CountingValidator())
    for document in boundaries:
        auth._capture_document_images(copy.deepcopy(document))

    assert len(calls) == len(boundaries)
    assert len(boundaries) == 8


def test_validation_does_not_reuse_a_previous_result_after_mutation(monkeypatch):
    packet = _packet()
    value = copy.deepcopy(packet["capture"]["original"]["commands"][0]["input"])
    original_validator = validation._validator("CanonicalDocument")
    calls = 0

    class CountingValidator:
        def validate(self, candidate):
            nonlocal calls
            calls += 1
            return original_validator.validate(candidate)

    monkeypatch.setattr(validation, "_validator", lambda _definition: CountingValidator())
    validation.validate_commit_value(value, "CanonicalDocument")
    value["unexpected"] = True
    with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
        validation.validate_commit_value(value, "CanonicalDocument")

    assert calls == 2


def test_validation_preserves_finite_nested_and_reference_refusals():
    packet = _packet()
    value = copy.deepcopy(packet["capture"]["original"]["commands"][0]["input"])
    value["parent_revision"]["revision_id"] = None
    with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
        validation.validate_commit_value(value, "CanonicalDocument")

    value = copy.deepcopy(packet["capture"]["original"]["commands"][0]["input"])
    value["parent_revision"]["payload"]["nested"] = float("nan")
    with pytest.raises(ValidationError, match="finite JSON"):
        validation.validate_commit_value(value, "CanonicalDocument")

    _, registry = validation._schema_resources()
    with pytest.raises(Unresolvable):
        registry.resolver().lookup("https://example.invalid/schema.json")
    with pytest.raises(ValidationError, match="unknown commit schema"):
        validation.validate_commit_value({}, "https://example.invalid/schema.json")


@pytest.mark.parametrize("damage", [
    "unknown_field", "nested_schema", "nonfinite", "digest", "duplicate_image",
])
@pytest.mark.parametrize("caller", ["images", "binding", "owners"])
def test_capture_callers_recheck_the_whole_document_after_prior_validation(caller, damage):
    document = _packet()["capture"]["original"]["commands"][0]["input"]
    shot = document["shot_revisions"][0]
    physical = "shot-revision:" + shot["revision_id"]
    binding = {"physical_ref": physical, "revision_id": shot["revision_id"],
               "content_digest": shot["content_digest"]}

    def check():
        if caller == "images":
            return auth._capture_document_images(document)
        if caller == "binding":
            return auth._capture_binding_image(document, binding)
        return auth._capture_owners(document, physical)

    before = copy.deepcopy(document)
    assert check()
    assert check()
    assert document == before
    if damage == "unknown_field":
        document["unexpected"] = True
    elif damage == "nested_schema":
        document["parent_revision"]["revision_id"] = None
    elif damage == "nonfinite":
        document["parent_revision"]["payload"]["unrelated"] = float("inf")
    elif damage == "digest":
        document["parent_revision"]["payload"]["unrelated"] = True
    else:
        document["internal_timeline_revisions"].append(
            copy.deepcopy(document["internal_timeline_revisions"][0]))
    damaged = copy.deepcopy(document)
    with pytest.raises((ValidationError, CommitRejected)):
        check()
    assert document == damaged


@pytest.mark.parametrize("damage", ["unknown_field", "digest", "owner"])
def test_genuine_capture_is_authenticated_again_after_a_successful_verification(damage):
    from test_timeline_commit_sequential_verifier import _verify_packet

    packet = _packet()
    before = copy.deepcopy(packet)
    _verify_packet(packet)
    assert packet == before
    if damage == "unknown_field":
        packet["capture"]["landing"]["commands"][0]["input"]["unexpected"] = True
    elif damage == "digest":
        document = packet["capture"]["landing"]["commands"][0]["input"]
        document["parent_revision"]["payload"]["unrelated"] = True
    else:
        packet["capture"]["replay_bindings"][-1]["source"].update(
            owner="occurrence:foreign/shot", owners=["occurrence:foreign/shot"])
    damaged = copy.deepcopy(packet)
    with pytest.raises((ValidationError, CommitRejected)):
        _verify_packet(packet)
    assert packet == damaged
