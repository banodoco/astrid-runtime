"""SV-L10: differential and real PreparedCommit one-edit schema work."""
from __future__ import annotations

import copy
import json
import sys
import time
from collections import Counter
from functools import cache
from statistics import median

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as SchemaValidationError
from referencing.exceptions import Unresolvable

from runtime_protocol import timeline_commit_validation as validation
from runtime_protocol.errors import ValidationError
from test_timeline_commit_validation import prepared, request
from test_timeline_commit_integration import agent, editing, film  # noqa: F401


@cache
def _base_validator(definition):
    # The exact pre-SV-L10 compiler and resolver path, with no item hook.
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
    return ("accepted", validation.canonical_json(value).encode("utf-8", "surrogatepass"))


def _same(value, definition="PreparedCommit"):
    old = _outcome(_base_validate, value, definition)
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


def _three_locations():
    value = prepared()
    parent = _parent(value)
    # Same bytes at the two RawClip locations must not share a result.
    parent["clips"] = [_clip()]
    parent["config"]["clips"] = [_clip()]
    parent["config"]["tracks"] = [
        {"id": "picture", "kind": "visual", "label": "Picture",
         "role": "output", "volume": 1}
    ]
    return value


def test_cold_warm_three_locations_edit_insert_and_reorder(memo):
    value = _three_locations()
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == 3
    assert len(memo.entries) == 3
    assert _same(value)[0] == "accepted"
    assert memo.counts["hits"] == 3

    parent = _parent(value)
    parent["clips"][0]["track"] = "changed"
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == 4
    parent["clips"].append(_clip("new"))
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == 5
    parent["clips"].reverse()
    before = memo.counts["misses"]
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == before
    # The internal-timeline payload uses the same raw item schema location.
    internal = value["canonical_document"]["internal_timeline_revisions"][0]["payload"]
    internal["clips"] = copy.deepcopy(parent["config"]["clips"])
    internal["tracks"] = copy.deepcopy(parent["config"]["tracks"])
    before = memo.counts["hits"]
    assert _same(value)[0] == "accepted"
    assert memo.counts["hits"] - before == 6


def test_first_refusal_order_and_invalid_never_published(memo):
    value = _three_locations()
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

    # An enclosing array's uniqueItems and the envelope still run when all
    # clips are hits. The order of the first two faults remains the base order.
    value["records"]["undo_of"] = ["r", "r"]
    value["provider_version"] = ""
    assert _same(value)[0] is ValidationError
    value["provider_version"] = "1"
    assert _same(value)[0] is ValidationError
    value["records"]["undo_of"] = ["r"]
    assert _same(value)[0] == "accepted"


def test_type_sensitive_bytes_and_mutation_after_validation(memo):
    value = _three_locations()
    clip = _parent(value)["clips"][0]
    opaque = clip["meta"]["vendor.test"]
    for item in (True, 1, 1.0, -0.0, 0.0):
        opaque["typed"] = item
        before = memo.counts["misses"]
        assert _same(value)[0] == "accepted"
        assert memo.counts["misses"] == before + (3 if before == 0 else 1)
    # The same mutable object no longer describes the previously valid clip.
    clip["id"] = False
    assert _same(value)[0] is ValidationError
    clip["id"] = "same"
    assert _same(value)[0] == "accepted"
    track = _parent(value)["config"]["tracks"][0]
    track["volume"] = True
    assert _same(value)[0] is ValidationError
    track["volume"] = 1.0
    assert _same(value)[0] == "accepted"


@pytest.mark.parametrize("malformed", [float("nan"), float("inf"), -float("inf")])
def test_raw_nonfinite_refusal_before_memo(memo, malformed):
    value = _three_locations()
    assert _same(value)[0] == "accepted"
    before = memo.counts.copy()
    _parent(value)["clips"][0]["opaque"] = malformed
    assert _same(value)[0] is ValidationError
    assert memo.counts == before


def test_cycle_refusal_and_encoding_fallback(memo):
    value = _three_locations()
    assert _same(value)[0] == "accepted"
    clip = _parent(value)["clips"][0]
    before = memo.counts.copy()
    clip["opaque"] = clip
    assert _same(value)[0] is ValidationError
    assert memo.counts == before
    clip["opaque"] = "\ud800"
    before = memo.counts["misses"]
    assert _same(value)[0] == "accepted"
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] == before


def test_deep_metadata_near_recursion_limit_uncached(memo):
    value = _three_locations()
    assert _same(value)[0] == "accepted"
    # A recursively validated metadata value, not merely an open opaque field.
    nested = {"leaf": 1}
    for _ in range(35):
        nested = {"next": nested}
    _parent(value)["clips"][0]["meta"] = {"vendor.test": nested}
    before = memo.counts["misses"]
    _same(value)
    assert memo.counts["misses"] == before
    # Lower headroom only after both compiled validators exist.
    limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(500)
        _same(value)
    finally:
        sys.setrecursionlimit(limit)
    assert memo.counts["misses"] == before


def test_lru_entry_and_byte_budget_and_oversize(memo, monkeypatch):
    # Exercise actual successful item validation under small budgets, not
    # manufactured cache entries that were never schema-checked.
    value = _three_locations()
    memo.entry_limit = 2
    assert _same(value)[0] == "accepted"
    assert len(memo.entries) == 2
    before = memo.counts["misses"]
    assert _same(value)[0] == "accepted"
    assert memo.counts["misses"] > before

    key_bytes = len(validation.canonical_json(_clip()).encode())
    small = _CountingMemo(entries=10, size=key_bytes + 1, key_size=key_bytes + 1)
    monkeypatch.setattr(validation, "_prepared_subtrees", small)
    assert _same(value)[0] == "accepted"
    assert small.size == sum(len(key[1]) for key in small.entries)
    assert small.size <= small.byte_limit
    assert len(small.entries) < 3
    _parent(value)["clips"][0]["opaque"] = "x" * (small.key_limit + 1)
    before = small.counts["successes"]
    assert _same(value)[0] == "accepted"
    assert all(len(key[1]) <= small.key_limit for key in small.entries)
    # The oversized parent clip was not even a lookup/miss; other locations
    # may have been evicted and legitimately need to validate again.
    assert small.counts["successes"] - before <= 2


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
    for index in range(2):
        document = editing.document()
        clips = document["parent_revision"]["payload"]["clips"]
        assert len(clips) == count
        target = clips[0]
        destination = target["at"] + 1
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
        "base_warm_median_ns": old, "candidate_warm_median_ns": new,
        "schema_reduction": 1 - new / old}, sort_keys=True))
