from __future__ import annotations

import copy
from collections import Counter
from functools import cache

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012
from test_timeline_commit_sequential_verifier import _verify_packet
from test_timeline_validation_cost import _packet

from runtime_protocol import timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError


@pytest.mark.parametrize("reuse", [False, True])
def test_genuine_capture_reuses_resolution_but_revalidates_every_value(monkeypatch, reuse):
    packet = _packet()
    before = copy.deepcopy(packet)
    bundle, registry = validation._schema_resources()

    @cache
    def original(definition):
        return Draft202012Validator(
            {"$ref": bundle["root"] + "#/$defs/" + definition}, registry=registry
        )

    factory = validation._validator if reuse else original
    finite = validation.finite_json
    counts = Counter()

    def validator(definition):
        counts[definition] += 1
        return factory(definition)

    def finite_json(value):
        counts["finite_json"] += 1
        return finite(value)

    monkeypatch.setattr(validation, "_validator", validator)
    monkeypatch.setattr(validation, "finite_json", finite_json)
    _verify_packet(packet)
    assert counts == {"CanonicalDocument": 54, "Recorder": 2, "finite_json": 56}
    assert packet == before


def _validators(resources, root):
    def unavailable(uri):
        from referencing.exceptions import NoSuchResource

        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=unavailable).with_resources(
        (uri, Resource.from_contents(schema, default_specification=DRAFT202012))
        for uri, schema in resources.items()
    )
    original = Draft202012Validator({"$ref": root}, registry=registry)
    cached = validation._reuse_schema_validators(Draft202012Validator)(
        original.schema, registry=registry
    ).evolve(
        _resolver=validation._reuse_schema_resolution(
            validation._validator_resolver(original)
        )
    )
    return original, cached


def _errors(validator, value):
    return [(list(e.path), list(e.schema_path), e.message)
            for e in validator.iter_errors(value)]


def test_compiled_validators_traverse_every_keyword_and_create_fresh_errors():
    from jsonschema.validators import extend

    calls = Counter()
    keywords = {}
    for name, check in Draft202012Validator.VALIDATORS.items():
        def counted(validator, constraint, instance, schema, name=name, check=check):
            calls[name] += 1
            yield from check(validator, constraint, instance, schema) or ()
        keywords[name] = counted
    base = extend(Draft202012Validator, validators=keywords)
    schema = {"type": "object", "properties": {
        "items": {"type": "array", "items": {"type": "integer", "minimum": 2}}
    }, "additionalProperties": False}
    original = base(schema)
    cached = validation._reuse_schema_validators(base)(schema)
    value: dict[str, list[object]] = {"items": [2, 3, 4]}
    for _ in range(2):
        for item in (2, True, 0, "bad", 5):
            value["items"][0] = item
            calls.clear()
            expected = _errors(original, value)
            expected_calls = calls.copy()
            calls.clear()
            assert _errors(cached, value) == expected
            assert calls == expected_calls
    value["items"][0] = False
    first = list(cached.iter_errors(value))
    first[0].path.append("tampered")
    assert _errors(cached, value) == _errors(original, value)


def test_compiled_validator_identity_includes_parent_registry_and_checker():
    from jsonschema import FormatChecker

    root = "https://example.invalid/shared"
    compiled = validation._reuse_schema_validators(Draft202012Validator)
    schema = {"$ref": root}
    validators = [compiled(schema, registry=Registry().with_resource(
        root, Resource.from_contents({"type": kind}, default_specification=DRAFT202012)
    )) for kind in ("string", "integer")]
    for _ in range(3):
        assert not _errors(validators[0], "ok")
        assert _errors(validators[0], 2)
        assert not _errors(validators[1], 2)
        assert _errors(validators[1], "ok")
    checked = compiled({"properties": {"x": {"format": "email"}}},
                       format_checker=FormatChecker())
    unchecked = checked.evolve(format_checker=None)
    for _ in range(2):
        assert _errors(checked, {"x": "bad"})
        assert not _errors(unchecked, {"x": "bad"})


def test_compiled_setup_concurrent_eviction_keeps_constraints_and_releases_values():
    import gc
    import weakref
    from concurrent.futures import ThreadPoolExecutor

    class Value(dict):
        pass

    compiled = validation._reuse_schema_validators(Draft202012Validator)
    validator = compiled({"properties": {
        str(i): {"const": i} for i in range(300)
    }})

    def check(i):
        value = Value({str(i % 300): i % 300})
        validator.validate(value)
        reference = weakref.ref(value)
        value[str(i % 300)] = -1
        assert _errors(validator, value)
        return reference

    with ThreadPoolExecutor(max_workers=4) as pool:
        references = list(pool.map(check, range(900)))
    gc.collect()
    assert all(reference() is None for reference in references)


def test_installed_schema_copy_survives_nested_resource_replacement():
    packet = _packet()
    bundle, registry = validation._schema_resources()
    root = bundle["root"]
    cached = validation._validator("CommitRequest")
    native = Draft202012Validator(
        {"$ref": root + "#/$defs/CommitRequest"}, registry=registry
    )

    nested_uri = next(
        uri for uri in bundle["resources"] if uri.endswith("edit-command.json")
    )
    installed = registry.resolver().lookup(nested_uri).contents
    installed_before = copy.deepcopy(installed)
    bundle["resources"][nested_uri].clear()
    bundle["resources"][nested_uri].update(
        {"$id": installed_before["$id"], "type": "null"}
    )
    assert installed == installed_before

    valid = packet["request"]
    invalid = copy.deepcopy(valid)
    invalid["commands"][0]["version"] = None
    for value in (valid, invalid):
        assert _errors(cached, value) == _errors(native, value)
    assert not _errors(cached, valid)
    assert _errors(cached, invalid)


def test_resolution_preserves_nested_ids_relative_uris_anchors_and_ref_siblings():
    root = "https://example.invalid/root"
    resources = {root: {
        "$id": root,
        "$defs": {
            "a": {"$id": "a/", "$defs": {
                "target": {"$anchor": "target", "type": "integer"},
                "use": {"$ref": "#target", "minimum": 2},
            }, "$ref": "#/$defs/use"},
            "b": {"$id": "b/", "$defs": {
                "target": {"$anchor": "target", "type": "string"},
                "use": {"$ref": "#target", "minLength": 2},
            }, "$ref": "#/$defs/use"},
        },
        "type": "object",
        "properties": {"a": {"$ref": "a/"}, "b": {"$ref": "b/"}},
        "required": ["a", "b"],
        "additionalProperties": False,
    }}
    original, cached = _validators(resources, root)
    valid = {"a": 2, "b": "ok"}
    for value in (valid, {"a": 1, "b": "ok"}, {"a": 2, "b": "x"},
                  {"a": "ok", "b": 2}, {**valid, "unknown": True}, valid):
        assert _errors(cached, value) == _errors(original, value)
    assert not _errors(cached, valid)
    for value in ({"a": 1, "b": "ok"}, {"a": 2, "b": "x"}):
        assert _errors(cached, value)


def test_dynamic_reference_retains_the_full_scope_on_alternating_calls():
    tree = "https://example.invalid/tree"
    strict = "https://example.invalid/strict"
    loose = "https://example.invalid/loose"
    resources = {
        tree: {"$id": tree, "$dynamicAnchor": "node", "type": "object",
               "properties": {"child": {"$dynamicRef": "#node"}}},
        strict: {"$id": strict, "$dynamicAnchor": "node", "$ref": tree,
                 "required": ["tag"]},
        loose: {"$id": loose, "$dynamicAnchor": "node", "$ref": tree},
    }
    validators = [_validators(resources, root) for root in (strict, loose)]
    for _ in range(2):
        for original, cached in validators:
            for value in ({"tag": 1}, {"tag": 1, "child": {}},
                          {"tag": 1, "child": {"tag": 2}}):
                assert _errors(cached, value) == _errors(original, value)
    assert _errors(validators[0][1], {"tag": 1, "child": {}})
    assert not _errors(validators[1][1], {"tag": 1, "child": {}})


@pytest.mark.parametrize("ref", [
    "https://example.invalid/missing", "file:///unpackaged.json",
    "#missing", "#/$defs/missing",
])
def test_unknown_references_fail_identically_after_a_successful_lookup(ref, monkeypatch):
    root = "https://example.invalid/root"
    resources = {root: {"$id": root, "$defs": {"ok": {"type": "integer"}},
                        "properties": {"ok": {"$ref": "#/$defs/ok"},
                                       "bad": {"$ref": ref}}}}
    original, cached = _validators(resources, root)
    for validator in (original, cached):
        validator.validate({"ok": 1})
        for _ in range(2):
            with pytest.raises(Unresolvable):
                validator.validate({"ok": 1, "bad": 1})
        monkeypatch.setattr(validation, "_validator", lambda _definition, v=validator: v)
        with pytest.raises(ValidationError, match="cannot validate CommitRequest"):
            validation.validate_commit_value({"ok": 1, "bad": 1}, "CommitRequest")


def test_resolution_cache_evicts_without_retaining_values_or_losing_constraints():
    root = "https://example.invalid/root"
    resources = {root: {"$id": root,
                        "$defs": {str(i): {"const": i} for i in range(300)},
                        "properties": {str(i): {"$ref": f"#/$defs/{i}"}
                                       for i in range(300)}}}
    original, cached = _validators(resources, root)
    value = {str(i): i for i in range(300)}
    for validator in (original, cached):
        validator.validate(value)
    value["0"] = -1
    assert _errors(cached, value) == _errors(original, value)
    assert _errors(cached, value)
