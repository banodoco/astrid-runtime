from __future__ import annotations

import copy
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_timeline_schema_resolution import _errors, _validators
from test_timeline_validation_cost import _packet

from runtime_protocol import timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError
from runtime_protocol.timeline_commit_validation import (
    finite_json,
    validate_commit_value,
)


@pytest.mark.parametrize("base", [str, int, float, dict, list])
def test_finite_walk_refuses_subclasses_and_non_string_keys(base):
    class Foreign(base):
        pass

    with pytest.raises(ValidationError, match="only finite JSON"):
        finite_json({"opaque": [Foreign()]})

    class ForeignKey(str):
        pass

    for key in (ForeignKey("key"), 1, False, None):
        with pytest.raises(ValidationError, match="keys must be strings"):
            finite_json({"opaque": {key: None}})


def test_finite_walk_handles_deep_shared_values_and_checks_each_fresh_mutation():
    scalars = [None, True, False, 1, 1.5, "text"]
    leaf: dict[str, object] = {"value": scalars}
    value = leaf
    for _ in range(2 * sys.getrecursionlimit()):
        value = [value]
    finite_json([value, value])
    scalars.append(float("nan"))
    with pytest.raises(ValidationError, match="only finite JSON"):
        finite_json([value, value])
    scalars.pop()
    leaf["cycle"] = value
    with pytest.raises(ValidationError, match="cycles"):
        finite_json([value, value])
    leaf.pop("cycle")
    finite_json([value, value])


@pytest.mark.parametrize("container", [dict, list])
def test_finite_walk_distinguishes_shared_children_from_ancestor_cycles(container):
    shared = {"nested": [1, None, False]}
    finite_json({"a": [shared, shared], "b": shared})
    cycle = container()
    if container is dict:
        cycle["self"] = cycle
    else:
        cycle.append(cycle)
    with pytest.raises(ValidationError, match="cycles"):
        finite_json([shared, cycle, shared])


def test_finite_walk_preserves_key_checks_and_reverse_child_error_order():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValidationError, match="keys must be strings"):
        finite_json({1: cycle})
    with pytest.raises(ValidationError, match="cycles"):
        finite_json({"first": (), "last": cycle})
    with pytest.raises(ValidationError, match="only finite JSON"):
        finite_json([cycle, ()])


def test_finite_walk_snapshots_siblings_before_synchronized_nested_mutation(
    monkeypatch,
):
    value = [0.0, [1.0]]
    nested_float_reached = threading.Event()
    release_nested_float = threading.Event()
    original_isfinite = validation.math.isfinite

    def synchronized_isfinite(item):
        if item == 1.0:
            nested_float_reached.set()
            assert release_nested_float.wait(5)
        return original_isfinite(item)

    monkeypatch.setattr(validation.math, "isfinite", synchronized_isfinite)

    with ThreadPoolExecutor(max_workers=1) as pool:
        worker = pool.submit(finite_json, value)
        assert nested_float_reached.wait(5)
        value[0] = float("inf")
        release_nested_float.set()
        worker.result(timeout=5)


def test_concurrent_validation_rechecks_independent_mutations_without_changing_inputs():
    document = _packet()["capture"]["original"]["commands"][0]["input"]

    def check(index):
        value = copy.deepcopy(document)
        validate_commit_value(value, "CanonicalDocument")
        if index % 2:
            value["parent_revision"]["payload"]["opaque"] = float("inf")
        else:
            value["parent_revision"]["revision_id"] = None
        before = copy.deepcopy(value)
        with pytest.raises(ValidationError):
            validate_commit_value(value, "CanonicalDocument")
        assert value == before

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(check, range(16)))
    validate_commit_value(document, "CanonicalDocument")


def test_validation_keeps_nested_dialect_selection_and_error_context():
    root = "https://example.invalid/root"
    old = "https://example.invalid/draft7"
    new = "https://example.invalid/draft2020"
    resources = {
        root: {"$id": root, "type": "object", "properties": {
            "old": {"$ref": old}, "new": {"type": "array", "items": {"$ref": new}},
        }},
        old: {"$id": old, "$schema": "http://json-schema.org/draft-07/schema#",
              "type": "object", "dependencies": {"a": ["b"]},
              "dependentRequired": {"a": ["unexpected"]}},
        new: {"$id": new, "$schema": "https://json-schema.org/draft/2020-12/schema",
              "$defs": {"target": {"anyOf": [{"type": "integer"}, {"type": "null"}]}},
              "$ref": "#/$defs/target", "maximum": 0},
    }
    native, installed = _validators(resources, root)
    valid = {"old": {"a": 1, "b": 2}, "new": [0]}
    assert not _errors(installed, valid)
    for value in (valid, {"old": {"a": 1}, "new": [0]},
                  {**valid, "new": [2]}, {**valid, "new": ["bad"]}):
        finite_json(value)
        assert _errors(installed, value) == _errors(native, value)
    assert _errors(installed, {"old": {"a": 1}, "new": [0]})
    error = next(iter(installed.iter_errors({**valid, "new": ["bad"]})))
    assert list(error.path) == ["new", 0]
    assert [list(child.schema_path) for child in error.context] == [[0, "type"], [1, "type"]]
