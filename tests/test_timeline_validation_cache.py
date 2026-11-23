from __future__ import annotations

import copy
import json
import sys
from collections import OrderedDict

import pytest
from jsonschema import Draft202012Validator

from runtime_protocol import timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError
from test_timeline_validation_cost import _packet


def _document():
    return _packet()["capture"]["original"]["commands"][0]["input"]


def _counting_validator(monkeypatch):
    original = validation._validator("CanonicalDocument")
    calls = []

    class Counting:
        def validate(self, value):
            calls.append(value)
            return original.validate(value)

    compiled = Counting()
    monkeypatch.setattr(validation, "_validator", lambda _definition: compiled)
    return calls


def test_equivalent_canonical_document_clones_reuse_successful_schema_result(monkeypatch):
    calls = _counting_validator(monkeypatch)
    source = _document()
    reordered = {key: copy.deepcopy(source[key]) for key in reversed(source)}

    validation.validate_commit_value(source, "CanonicalDocument")
    validation.validate_commit_value(reordered, "CanonicalDocument")

    assert calls == [source]


def test_cache_key_includes_compiled_validator_identity(monkeypatch):
    original = validation._validator("CanonicalDocument")
    validators = [original, Draft202012Validator({"not": {}})]
    monkeypatch.setattr(validation, "_validator", lambda _definition: validators.pop(0))
    value = _document()
    validation.validate_commit_value(value, "CanonicalDocument")
    with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
        validation.validate_commit_value(copy.deepcopy(value), "CanonicalDocument")


def test_cache_key_includes_installed_contract_digest(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    for contract in ("sha256:" + "a" * 64, "sha256:" + "b" * 64):
        monkeypatch.setattr(validation, "SCHEMA_DIGEST", contract, raising=False)
        validation.validate_commit_value(copy.deepcopy(value), "CanonicalDocument")
        validation.validate_commit_value(copy.deepcopy(value), "CanonicalDocument")

    assert calls == [value, value]


def test_equal_python_values_with_different_canonical_bytes_miss(monkeypatch):
    calls = _counting_validator(monkeypatch)
    whole = _document()
    whole["parent_revision"]["payload"]["opaque"] = 1
    fractional = copy.deepcopy(whole)
    fractional["parent_revision"]["payload"]["opaque"] = 1.0
    assert whole == fractional

    for value in (whole, fractional, copy.deepcopy(fractional)):
        validation.validate_commit_value(value, "CanonicalDocument")

    assert [type(value["parent_revision"]["payload"]["opaque"]) for value in calls] == [int, float]


def test_other_definitions_do_not_use_the_document_memo(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    for definition in ("CanonicalDocument", "CanonicalDocument", "PreparedCommit", "PreparedCommit"):
        validation.validate_commit_value(copy.deepcopy(value), definition)

    assert calls == [value, value, value]


def test_invalid_value_after_success_is_never_a_cache_hit(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    validation.validate_commit_value(value, "CanonicalDocument")
    invalid = copy.deepcopy(value)
    invalid["unexpected"] = True

    with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
        validation.validate_commit_value(invalid, "CanonicalDocument")
    assert len(calls) == 2


def test_document_mutation_cannot_validate_different_bytes_under_the_same_key(monkeypatch):
    compiled = validation._validator("CanonicalDocument")
    invalid = _document()
    invalid["unexpected"] = True
    original = copy.deepcopy(invalid)

    class MutatingValidator:
        def validate(self, candidate):
            invalid.pop("unexpected", None)
            compiled.validate(candidate)

    validator = MutatingValidator()
    monkeypatch.setattr(validation, "_validator", lambda _definition: validator)

    with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
        validation.validate_commit_value(invalid, "CanonicalDocument")
    assert "unexpected" not in invalid
    with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
        validation.validate_commit_value(original, "CanonicalDocument")


@pytest.mark.parametrize(
    "changed, normalized, error",
    [
        pytest.param(("later",), ["later"], "finite JSON", id="tuple"),
        pytest.param({1: "later"}, {"1": "later"}, "keys must be strings", id="integer-key"),
    ],
)
def test_encoder_uses_strict_owned_capture_after_caller_mutation(monkeypatch, changed, normalized, error):
    calls = _counting_validator(monkeypatch)
    source = _document()
    payload = source["parent_revision"]["payload"]
    payload["opaque"] = "before"
    encode = validation.canonical_json

    def mutate_then_encode(captured):
        payload["opaque"] = changed
        return encode(captured)

    monkeypatch.setattr(validation, "canonical_json", mutate_then_encode)
    validation.validate_commit_value(source, "CanonicalDocument")
    assert calls[0]["parent_revision"]["payload"]["opaque"] == "before"
    assert payload["opaque"] is changed
    with pytest.raises(ValidationError, match=error):
        validation.validate_commit_value(source, "CanonicalDocument")

    valid = _document()
    valid["parent_revision"]["payload"]["opaque"] = normalized
    validation.validate_commit_value(valid, "CanonicalDocument")
    assert len(calls) == 2


def test_schema_failures_are_rechecked_and_never_cached(monkeypatch):
    calls = _counting_validator(monkeypatch)
    invalid = _document()
    invalid["parent_revision"]["revision_id"] = None
    for _ in range(2):
        with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
            validation.validate_commit_value(invalid, "CanonicalDocument")
    assert len(calls) == 2


def test_nonfinite_values_are_rejected_before_memo_lookup(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    validation.validate_commit_value(value, "CanonicalDocument")
    invalid = copy.deepcopy(value)
    invalid["parent_revision"]["payload"]["opaque"] = float("nan")

    with pytest.raises(ValidationError, match="finite JSON"):
        validation.validate_commit_value(invalid, "CanonicalDocument")
    assert len(calls) == 1


def test_success_memo_reports_bounded_retention_and_redacted_work(monkeypatch, capsys):
    from runtime_protocol._timeline_reopen_diagnostics import observe_verified_head

    monkeypatch.setenv("ASTRID_RUNTIME_TIMELINE_DIAGNOSTICS", "1")
    monkeypatch.setattr(validation, "_document_memo", OrderedDict(), raising=False)
    calls = _counting_validator(monkeypatch)
    private = "private document payload"
    value = _document()

    def check(index):
        candidate = copy.deepcopy(value)
        candidate["parent_revision"]["payload"][private] = index
        validation.validate_commit_value(candidate, "CanonicalDocument")

    with observe_verified_head():
        for index in range(256):
            check(index)
        check(0)
        check(256)
        check(0)
        check(1)
        for _ in range(2):
            with pytest.raises(ValidationError, match="invalid CanonicalDocument"):
                validation.validate_commit_value({private: True}, "CanonicalDocument")
        with pytest.raises(ValidationError, match="finite JSON"):
            validation.validate_commit_value({private: ()}, "CanonicalDocument")

    assert len(calls) == 260
    assert len(validation._document_memo) == 256
    message, = capsys.readouterr().err.splitlines()
    assert private not in message
    counts = json.loads(message.removeprefix("runtime.timeline_commit.verified_head "))["counts"]
    assert counts["document_schema_cache_hits"] == 2
    assert counts["document_schema_cache_misses"] == 260
    assert counts["document_schema_cache_evictions"] == 2


def test_unencodable_valid_document_falls_back_to_normal_validation(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    value["parent_revision"]["payload"]["opaque"] = "\ud800"

    # Finite JSON accepts this string, while UTF-8 canonical bytes cannot encode it.
    for _ in range(2):
        validation.validate_commit_value(value, "CanonicalDocument")
    assert len(calls) == 2


def test_cyclic_document_is_refused_before_encoder_or_validator(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    cycle = []
    cycle.append({"again": cycle})
    value["parent_revision"]["payload"]["opaque"] = cycle
    monkeypatch.setattr(validation, "canonical_json", lambda _: pytest.fail("encoded a cycle"))

    with pytest.raises(ValidationError, match="must not contain cycles"):
        validation.validate_commit_value(value, "CanonicalDocument")
    assert not calls


def test_deep_opaque_document_preserves_uncached_validation_fallback(monkeypatch):
    calls = _counting_validator(monkeypatch)
    value = _document()
    deep = None
    for _ in range(sys.getrecursionlimit() + 10):
        deep = [deep]
    value["parent_revision"]["payload"]["opaque"] = deep

    def encode(_):
        raise RecursionError("simulated encoder depth limit")

    monkeypatch.setattr(validation, "canonical_json", encode)
    for _ in range(2):
        validation.validate_commit_value(value, "CanonicalDocument")
    assert len(calls) == 2
