"""SV-L10: differential and real PreparedCommit one-edit schema work."""
from __future__ import annotations

import copy
import json
import math
import sys
import time
from collections import Counter
from functools import cache
from importlib.resources import files
from statistics import median

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT202012

from runtime_protocol import timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError
from test_timeline_commit_validation import prepared, request
from test_timeline_commit_integration import agent, editing, film  # noqa: F401


@cache
def _plain_validator(definition):
    # Independent correctness oracle: read the same installed bundle, create
    # its own offline registry and use the stock validator without wrappers.
    bundle = json.loads(files("runtime_protocol").joinpath(
        "schemas/timeline-commit-bundle.json").read_text(encoding="utf-8"))

    def unavailable(uri):
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=unavailable)
    for uri, schema in bundle["resources"].items():
        resource = Resource.from_contents(schema, default_specification=DRAFT202012)
        registry = registry.with_resource(uri, resource)
        if resource.id() is not None:
            registry = registry.with_resource(resource.id(), resource)
    return Draft202012Validator(
        {"$ref": bundle["root"] + "#/$defs/" + definition}, registry=registry
    )


def _plain_finite_json(value):
    # Independent copy of the frozen base raw guard: reverse child traversal
    # and exact built-in types; do not share the candidate's capture or guard.
    active = set()
    parents = []
    children = iter((value,))
    while True:
        for item in children:
            kind = type(item)
            if kind is str or kind is int or kind is bool or item is None:
                continue
            if kind is float and math.isfinite(item):
                continue
            if kind is not dict and kind is not list:
                raise ValidationError("commit value must contain only finite JSON")
            if id(item) in active:
                raise ValidationError("commit value must not contain cycles")
            if kind is dict and any(type(key) is not str for key in item):
                raise ValidationError("commit JSON object keys must be strings")
            active.add(id(item))
            parents.append((item, children))
            children = reversed(tuple(item.values() if kind is dict else item))
            break
        else:
            if not parents:
                return
            parent, children = parents.pop()
            active.remove(id(parent))


def _plain_validate(value, definition="PreparedCommit"):
    _plain_finite_json(value)
    try:
        _plain_validator(definition).validate(value)
    except SchemaValidationError as exc:
        raise ValidationError(f"invalid {definition}: {exc.message}") from exc
    except (Unresolvable, RecursionError) as exc:
        raise ValidationError(
            f"cannot validate {definition} against the installed contract"
        ) from exc


@cache
def _base_validator(definition):
    # TIMING ONLY: preserve the optimized pre-SV-L10 compiler and resolver
    # path used for the previous 1.173 s gate; the plain oracle above is
    # deliberately NOT the performance denominator.
    bundle, registry = validation._schema_resources()
    compiled = validation._reuse_schema_validators(Draft202012Validator)(
        {"$ref": bundle["root"] + "#/$defs/" + definition}, registry=registry
    )
    return compiled.evolve(
        _resolver=validation._reuse_schema_resolution(
            validation._validator_resolver(compiled)
        )
    )


def _base_validate(value, definition="PreparedCommit"):
    validation.finite_json(value)
    try:
        _base_validator(definition).validate(value)
    except SchemaValidationError as exc:
        raise ValidationError(f"invalid {definition}: {exc.message}") from exc
    except (Unresolvable, RecursionError) as exc:
        raise ValidationError(
            f"cannot validate {definition} against the installed contract"
        ) from exc


def _candidate(value, definition="PreparedCommit"):
    validation.validate_commit_value(value, definition)


def _outcome(check, value, definition="PreparedCommit"):
    try:
        check(value, definition)
    except ValidationError as exc:
        cause = exc.__cause__
        detail = (
            (cause.message, tuple(cause.path), tuple(cause.schema_path))
            if isinstance(cause, SchemaValidationError) else None
        )
        return (type(exc), str(exc), type(cause), detail)
    # Include opaque Unicode values for which the key's strict UTF-8 encoding
    # refuses; surrogatepass here is an oracle for unchanged bytes, NOT a key.
    return ("accepted", json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8", "surrogatepass"))


def _same(value, definition="PreparedCommit"):
    old = _outcome(_plain_validate, value, definition)
    new = _outcome(_candidate, value, definition)
    assert new == old
    return old


class _CountingMemo(validation._SubtreeMemo):
    def __init__(self, **limits):
        super().__init__(**limits)
        self.counts = Counter()

    def contains(self, key):
        hit = super().contains(key)
        self.counts["hits" if hit else "misses"] += 1
        self.counts["key_bytes"] += len(key[1])
        return hit

    def remember(self, key):
        self.counts["successes"] += 1
        super().remember(key)


@pytest.fixture
def memo(monkeypatch):
    instance = _CountingMemo()
    monkeypatch.setattr(validation, "_prepared_subtrees", instance)
    return instance


def _parent(value):
    return value["canonical_document"]["parent_revision"]["payload"]


def _clip(identifier="same"):
    return {"id": identifier, "clipType": "text", "track": "picture",
            "effects": [{"opacity": 1}],
            "meta": {"vendor.test": {"nested": [1, False, None, "text"]}}}


def _state(identifier="same"):
    return {"state": "present", "value": {
        "id": identifier, "nested": [{"name": "long enough for memo eligibility",
                                      "values": [1, False, None, "text"]}],
    }}


def _read(identifier="same"):
    return {"kind": "field", "ref": "parent", "path": ["clips", "id:" + identifier],
            "state": _state(identifier)}


def _record(value):
    return value["records"]["commands"][0]


def _step(value):
    return value["records"]["steps"][0]


def _four_targets():
    value = prepared()
    parent = _parent(value)
    parent["clips"] = [_clip()]
    parent["config"]["clips"] = [_clip()]
    parent["config"]["tracks"] = [
        {"id": "picture", "kind": "visual", "label": "Picture",
         "role": "output", "volume": 1}
    ]
    read = _read()
    # AgentRead reaches the edit-command AgentState and recursive JSON;
    # CommitRead reaches the timeline AgentState alias, which reaches the
    # edit-command target. Equal bytes at distinct source refs stay distinct.
    _record(value)["reads"] = [{k: copy.deepcopy(v) for k, v in read.items()
                               if k != "kind"}]
    value["records"]["steps"] = [{
        "id": "step", "label": "Step", "intent": "Edit", "tags": ["proof"],
        "command_ordinals": [0], "patch": [], "reads": [copy.deepcopy(read)],
        "dependencies": [copy.deepcopy(read)],
    }]
    return value


def test_cold_warm_four_targets_edit_insert_and_reorder(memo):
    value = _four_targets()
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] > 0
    assert {key[0][-1].split("/")[-1] for key in memo.entries} == {
        "JSON", "AgentState", "CommitRead",
    }
    targets = {key[0][-1] for key in memo.entries}
    assert targets == {
        "https://astrid.haus/workspace/v1/schemas/edit-command.json#/$defs/JSON",
        "https://astrid.haus/workspace/v1/schemas/edit-command.json#/$defs/AgentState",
        "https://astrid.haus/workspace/v1/schemas/timeline-commit.json#/$defs/AgentState",
        "https://astrid.haus/workspace/v1/schemas/timeline-commit.json#/$defs/CommitRead",
    }
    state_keys = [key for key in memo.entries if key[1] ==
                  validation.canonical_json(_state()).encode()]
    assert len({key[0][-2] for key in state_keys}) > 1
    cold = memo.counts.copy()
    assert _same(value)[0] == "accepted"
    assert memo.counts["hits"] > cold["hits"]
    assert memo.counts["misses"] == cold["misses"]

    # RawClip/RawTrack locations are deliberately dropped. Clip edits still
    # get the original checks; the recorder's changed/new reads are misses.
    parent = _parent(value)
    parent["clips"][0]["track"] = "changed"
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == cold["misses"]
    parent["clips"].append(_clip("new"))
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == cold["misses"]
    parent["clips"].reverse()
    assert _same(value)[0] == "accepted"
    internal = value["canonical_document"]["internal_timeline_revisions"][0]["payload"]
    internal["clips"] = copy.deepcopy(parent["config"]["clips"])
    internal["tracks"] = copy.deepcopy(parent["config"]["tracks"])
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == cold["misses"]
    step = _step(value)
    step["reads"][0]["state"]["value"]["id"] = "changed"
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] > cold["misses"]
    before = memo.counts["misses"]
    step["reads"].append(_read("new"))
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] > before
    step["reads"].reverse()
    before = memo.counts["misses"]
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == before


def test_first_refusal_order_and_invalid_never_published(memo):
    value = _four_targets()
    assert _same(value)[0] == "accepted"
    parent = _parent(value)
    parent["clips"][0]["id"] = 3
    parent["config"]["tracks"][0]["kind"] = "not-a-kind"
    before = len(memo.entries)
    first = _same(value)
    assert first[0] is ValidationError
    assert _same(value) == first
    assert len(memo.entries) == before
    parent["clips"][0]["id"] = "same"
    second = _same(value)
    assert second[0] is ValidationError and second != first
    assert len(memo.entries) == before
    parent["config"]["tracks"][0]["kind"] = "visual"
    assert _same(value)[0] == "accepted"

    # An enclosing array's uniqueItems and the envelope still run on hits.
    value["records"]["undo_of"] = ["r", "r"]
    value["provider_version"] = ""
    assert _same(value)[0] is ValidationError
    value["provider_version"] = "1"
    assert _same(value)[0] is ValidationError
    value["records"]["undo_of"] = ["r"]
    assert _same(value)[0] == "accepted"


def test_invalid_nested_record_json_first_refusal_path_and_order(memo):
    value = _four_targets()
    assert _same(value)[0] == "accepted"
    state = _record(value)["reads"][0]["state"]
    # Arbitrary JSON admits every finite built-in JSON value. A malformed
    # descendant must still fail the raw guard, even with warmed successes.
    state["value"]["nested"][0]["invalid"] = {1: "non-string key"}
    _step(value)["reads"][0]["path"] = [1]
    before = memo.counts.copy()
    first = _same(value)
    assert first[0] is ValidationError
    assert first[1] == "commit JSON object keys must be strings"
    assert memo.counts == before
    del state["value"]["nested"][0]["invalid"]

    # Valid raw JSON in an invalid AgentState envelope must still fail the
    # original oneOf. Simultaneous malformed CommitRead must be later.
    state["unexpected"] = {"nested": ["invalid state field"]}
    invalid_key = validation.canonical_json(state).encode()
    first = _same(value)
    assert first[0] is ValidationError and first[3] is not None
    assert first[3][1] == ("records", "commands", 0, "reads", 0, "state")
    assert _same(value) == first
    assert all(key[1] != invalid_key for key in memo.entries)
    del state["unexpected"]
    second = _same(value)
    assert second[0] is ValidationError and second != first
    assert second[3][1] == ("records", "steps", 0, "reads", 0)
    _step(value)["reads"][0]["path"] = ["clips", "id:same"]
    assert _same(value)[0] == "accepted"


def test_type_sensitive_bytes_and_mutation_after_validation(memo):
    value = _four_targets()
    state = _record(value)["reads"][0]["state"]
    for item in (True, 1, 1.0, -0.0, 0.0):
        state["value"]["typed"] = item
        before = memo.counts["misses"]
        assert _same(value)[0] == "accepted"
        assert memo.counts["misses"] > before
        encoded = validation.canonical_json(state).encode()
        assert any(key[1] == encoded for key in memo.entries)
    state["state"] = False
    assert _same(value)[0] is ValidationError
    state["state"] = "present"
    assert _same(value)[0] == "accepted"
    track = _parent(value)["config"]["tracks"][0]
    track["volume"] = True
    assert _same(value)[0] is ValidationError
    track["volume"] = 1.0
    assert _same(value)[0] == "accepted"


@pytest.mark.parametrize("malformed", [float("nan"), float("inf"), -float("inf")])
def test_raw_nonfinite_refusal_before_memo(memo, malformed):
    value = _four_targets()
    assert _same(value)[0] == "accepted"
    before = memo.counts.copy()
    _record(value)["reads"][0]["state"]["value"]["opaque"] = malformed
    assert _same(value)[0] is ValidationError
    assert memo.counts == before


def test_cycle_refusal_and_encoding_fallback(memo):
    value = _four_targets()
    assert _same(value)[0] == "accepted"
    state = _record(value)["reads"][0]["state"]
    before = memo.counts.copy()
    state["value"]["opaque"] = state
    assert _same(value)[0] is ValidationError
    assert memo.counts == before
    state["value"]["opaque"] = "\ud800"
    assert validation._subtree_bytes(state) is None
    assert _same(value)[0] == "accepted"
    assert _same(value)[0] == "accepted"


def test_deep_nested_json_near_recursion_limit_uncached(memo, monkeypatch):
    value = _four_targets()
    assert _same(value)[0] == "accepted"
    state = _record(value)["reads"][0]["state"]
    leaf = {"svl10-warmed-leaf": "x" * 80}
    state["value"] = {"next": leaf}
    assert _same(value)[0] == "accepted"
    encoded = validation.canonical_json(leaf).encode()
    keys = [key for key in memo.entries if key[1] == encoded and
            key[0][-2].endswith("/$defs/JSON/anyOf/2/additionalProperties")]
    assert len(keys) == 1
    warmed_key = keys[0]

    headroom = validation._has_subtree_recursion_headroom
    contains = memo.contains
    root_checks, leaf_checks, leaf_hits = [], [], []

    def observe_headroom():
        allowed = headroom()
        caller = sys._getframe(1)
        if caller.f_code.co_name == "validate_commit_value":
            root_checks.append(allowed)
        elif caller.f_locals.get("instance") == leaf:
            leaf_checks.append(allowed)
        return allowed

    def observe_contains(key):
        hit = contains(key)
        if key == warmed_key:
            leaf_hits.append(hit)
        return hit

    monkeypatch.setattr(validation, "_has_subtree_recursion_headroom", observe_headroom)
    monkeypatch.setattr(memo, "contains", observe_contains)

    def wrap_leaf(layers, tag):
        nested = leaf
        for index in range(layers):
            # Different ancestors for each run; no cached ancestor can hide
            # the warmed recursive JSON reference we are testing.
            nested = {"next": nested, "tag": f"{tag}-{index}"}
        return nested

    limit = sys.getrecursionlimit()

    def compare_with_budget(budget):
        # Consume actual Python frames, keeping the interpreter's normal
        # recursion limit unchanged. Budget is approximate remaining frames.
        frame = sys._getframe()
        used = 0
        while frame is not None:
            used += 1
            frame = frame.f_back

        def dive(n):
            return dive(n - 1) if n else _same(value)

        return dive(max(0, limit - used - budget))

    state["value"] = wrap_leaf(20, "normal")
    assert validation._subtree_bytes(state) is None
    assert _same(value)[0] == "accepted"
    assert root_checks == [True] and leaf_checks == [True] and leaf_hits == [True]

    root_checks.clear()
    leaf_checks.clear()
    leaf_hits.clear()
    state["value"] = wrap_leaf(20, "deep")
    assert compare_with_budget(560)[0] == "accepted"
    assert root_checks == [True] and leaf_checks == [False] and not leaf_hits
    assert warmed_key in memo.entries

    root_checks.clear()
    leaf_checks.clear()
    leaf_hits.clear()
    state["value"] = wrap_leaf(120, "near-limit")
    before = memo.counts.copy()
    assert compare_with_budget(400)[0] is ValidationError
    assert memo.counts == before
    assert root_checks == [False]
    assert sys.getrecursionlimit() == limit


def test_lru_entry_and_byte_budget_and_oversize(memo, monkeypatch):
    value = _four_targets()
    memo.entry_limit = 2
    assert _same(value)[0] == "accepted"
    assert len(memo.entries) == 2
    before = memo.counts["misses"]
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] > before

    key_bytes = len(validation.canonical_json(_state()).encode())
    small = _CountingMemo(entries=10, size=key_bytes + 1, key_size=key_bytes + 1)
    monkeypatch.setattr(validation, "_prepared_subtrees", small)
    assert _same(value)[0] == "accepted"
    assert small.size == sum(len(key[1]) for key in small.entries)
    assert 0 < small.size <= small.byte_limit
    assert len(small.entries) < 3
    state = _record(value)["reads"][0]["state"]
    state["value"]["opaque"] = "x" * (small.key_limit + 1)
    assert validation._subtree_bytes(state) is None
    assert _same(value)[0] == "accepted"
    assert all(len(key[1]) <= small.key_limit for key in small.entries)
    assert small.size == sum(len(key[1]) for key in small.entries) <= small.byte_limit


def test_minimum_key_size_skips_scalar_and_tiny_subtrees(memo):
    minimum = validation._SUBTREE_MIN_BYTES
    assert minimum == 64
    assert validation._subtree_bytes("x" * 1000) is None
    assert validation._subtree_bytes({"state": "present", "value": 1}) is None
    # JSON object {"x":"..."} has eight bytes of syntax overhead.
    assert validation._subtree_bytes({"x": "a" * (minimum - 9)}) is None
    key = validation._subtree_bytes({"x": "a" * (minimum - 8)})
    assert key is not None and len(key) == minimum
    assert _same(_four_targets())[0] == "accepted"
    assert memo.entries
    assert all(len(key[1]) >= minimum for key in memo.entries)


def test_commit_request_has_no_item_memo(memo):
    value = request()
    assert _same(value, "CommitRequest")[0] == "accepted"
    value["commands"][0]["args"]["on"] = "invalid"
    _same(value, "CommitRequest")
    assert not memo.entries and not memo.counts


def _measure(check, value, memo):
    """Same profiler for base and candidate; time the root schema invocation."""
    active = None
    started = 0
    schema_ns = 0
    descents = 0
    before = memo.counts.copy()

    def profile(frame, event, arg):
        nonlocal active, started, schema_ns, descents
        if event == "call" and frame.f_globals.get("__name__", "").startswith("jsonschema."):
            if frame.f_code.co_name == "validate" and active is None:
                active = frame
                started = time.perf_counter_ns()
            elif frame.f_code.co_name == "descend" and active is not None:
                # Count Python call/resume events, not distinct object identities.
                descents += 1
        elif event == "return" and frame is active:
            schema_ns += time.perf_counter_ns() - started
            active = None

    previous = sys.getprofile()
    wall = time.perf_counter_ns()
    try:
        sys.setprofile(profile)
        check(value)
    finally:
        sys.setprofile(previous)
    wall_ns = time.perf_counter_ns() - wall
    assert schema_ns > 0 and descents > 0
    delta = memo.counts - before
    return {"schema_ns": schema_ns, "wall_ns": wall_ns, "descend_events": descents,
            "hits": delta["hits"], "misses": delta["misses"],
            "key_bytes": delta["key_bytes"]}


@pytest.mark.integration
@pytest.mark.parametrize("count", (3, 30, 300))
def test_one_edit_prepared_schema_work(editing, count, monkeypatch):
    # Same actual Agent film, seed and repeated observations as SV-L3. Capture
    # the untouched provider PreparedCommit at the real store preflight, then
    # replay exactly those two values against old/new validation in isolation.
    from test_timeline_save_work_counters import _seed_clips

    _seed_clips(editing, count)
    store = editing.service._timeline_commits()[0]
    captured = []
    original = store.validate_prepared

    def observe(value):
        captured.append(copy.deepcopy(value))
        return original(value)

    monkeypatch.setattr(store, "validate_prepared", observe)
    initial = editing.document()["parent_revision"]["payload"]["clips"][0]
    target_id, original_at = initial["id"], initial["at"]
    for index in range(2):
        document = editing.document()
        clips = document["parent_revision"]["payload"]["clips"]
        assert len(clips) == count
        target = next(clip for clip in clips if clip["id"] == target_id)
        # Move once, then back to the known legal original position. Each
        # measured input is distinct and exactly one clip position changes.
        destination = original_at + 1 if index == 0 else original_at
        body = editing.body([editing.move(target["id"], destination, document=document)])
        reads = [{"kind": "field", "ref": "parent",
                  "path": ["clips", "id:" + clip["id"], "at"],
                  "state": {"state": "present", "value": clip["at"]}} for clip in clips]
        body["reads"] = reads
        body["steps"][0]["reads"] = copy.deepcopy(reads)
        result = editing.commit(body, f"svl10-move-{index}")
        assert result["data"]["status"] == "accepted"
        actual = result["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
        assert {row["id"]: row["at"] for row in actual} == {
            row["id"]: destination if row["id"] == target["id"] else row["at"]
            for row in clips
        }
    assert len(captured) == 2
    first, second = captured
    assert validation.canonical_json(first) != validation.canonical_json(second)
    assert _same(first)[0] == _same(second)[0] == "accepted"

    rows = []
    for _ in range(3):
        # Fresh compiled validators and empty value memo for cold cost; the
        # next save measures the distinct changed value, not an exact repeat.
        _base_validator.cache_clear()
        validation._validator.cache_clear()
        memo = _CountingMemo()
        monkeypatch.setattr(validation, "_prepared_subtrees", memo)
        base_cold = _measure(_base_validate, first, memo)
        base_warm = _measure(_base_validate, second, memo)
        candidate_cold = _measure(_candidate, first, memo)
        candidate_warm = _measure(_candidate, second, memo)
        assert candidate_cold["misses"] >= count
        assert candidate_warm["hits"] >= count - 1
        assert candidate_warm["misses"] > 0
        assert candidate_warm["descend_events"] < base_warm["descend_events"]
        rows.append({"base_cold": base_cold, "base_warm": base_warm,
                     "candidate_cold": candidate_cold, "candidate_warm": candidate_warm})
    old = median(row["base_warm"]["schema_ns"] for row in rows)
    new = median(row["candidate_warm"]["schema_ns"] for row in rows)
    # Timing is reported, not a flaky test assertion. The orchestrator gates
    # the exact-head 300-clip result at 70%, including cold overhead separately.
    print("SV-L10 " + json.dumps({"clips": count, "prepared_bytes": len(
        validation.canonical_json(second).encode()), "samples": rows,
        "min_subtree_bytes": validation._SUBTREE_MIN_BYTES,
        "base_warm_median_ns": old, "candidate_warm_median_ns": new,
        "schema_reduction": 1 - new / old}, sort_keys=True))

    # Measure the cutoff on the SAME captured 300-clip pair. The default
    # above is the sole candidate gate; controls are diagnostic, not an
    # authorization to retune production. No additional fixture builds.
    if count == 300:
        controls = {}
        for minimum in (0, 128):
            with monkeypatch.context() as control:
                control.setattr(validation, "_SUBTREE_MIN_BYTES", minimum)
                control_memo = _CountingMemo()
                control.setattr(validation, "_prepared_subtrees", control_memo)
                validation._validator.cache_clear()
                controls[minimum] = {
                    "cold": _measure(_candidate, first, control_memo),
                    "warm": _measure(_candidate, second, control_memo),
                }
        print("SV-L10-MIN " + json.dumps({
            "clips": count, "candidate_min": validation._SUBTREE_MIN_BYTES,
            "candidate_samples": rows, "controls": controls,
        }, sort_keys=True))
