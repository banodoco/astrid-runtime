"""SV-L3: count one accepted save, not fixture construction or elapsed time.

History and clip count are independent axes. The installed Agent integration
is required only for the clip-axis measurements. The old covers loop is a
separate negative control: growing history at fixed document size does not
necessarily exercise the quadratic dependency search.
"""
from __future__ import annotations

import copy
import json
import sys
import time
from collections import Counter, defaultdict
from contextlib import contextmanager

import pytest

from runtime_protocol import timeline_commit_auth as auth
from runtime_protocol.service import RuntimeService
from test_timeline_commit_cost import Film, film
from test_timeline_commit_integration import agent, editing


SIZES = (3, 30, 300)


def _bytes(value):
    # Preserve JSON types (including 1 versus 1.0 versus true), array order,
    # and the sign of zero; sort only object keys.
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class SaveCounts:
    """Observe existing Python calls, including imported aliases.

    No production hooks, replacement validators, memo, or changed inputs.
    Count recursive calls as work, and root copy calls separately as boundaries.
    Schema times are instrumented, not production wall-clock estimates.
    """

    def __init__(self, *, detail=False):
        self.detail = detail
        self.calls = Counter()
        self.boundaries = defaultdict(Counter)
        self.schema = defaultdict(Counter)
        self.keys = defaultdict(set)
        self.pending = {}
        self.provider = set()
        self.acceptance = set()

    def phase(self):
        return "acceptance" if self.acceptance else "provider" if self.provider else "request"

    def boundary(self, site, value):
        row = self.boundaries[site]
        row["calls"] += 1
        try:
            row["bytes"] += len(_bytes(value))
        except (TypeError, ValueError, RecursionError):
            row["unencodable"] += 1

    def schema_start(self, frame, sites, value):
        started = time.perf_counter_ns()
        key = _bytes(value)
        key_ns = time.perf_counter_ns() - started
        self.pending[frame] = (sites, key, key_ns, time.perf_counter_ns())

    def profile(self, frame, event, arg):
        if event == "return":
            self.provider.discard(frame)
            self.acceptance.discard(frame)
            pending = self.pending.pop(frame, None)
            if pending is not None:
                sites, key, key_ns, started = pending
                elapsed = time.perf_counter_ns() - started
                for site in sites:
                    row = self.schema[site]
                    row["total"] += 1
                    row["key_bytes"] += len(key)
                    row["key_ns"] += key_ns
                    row["schema_ns"] += elapsed
                    self.keys[site].add(key)
            return
        if event not in ("call", "c_call"):
            return
        module = frame.f_globals.get("__name__", "")
        name = frame.f_code.co_name
        production = module.startswith(("runtime_protocol.", "astrid."))
        if event == "c_call":
            if production and getattr(arg, "__name__", "") in ("openssl_sha256", "sha256"):
                self.calls[(self.phase(), "sha256")] += 1
            return
        if (module == "test_timeline_commit_cost" and name == "execute"
                or module == "astrid.sdk.timeline.commit" and name == "commit"):
            self.provider.add(frame)
        if module == "runtime_protocol.timeline_commit_port" and name == "accept":
            self.acceptance.add(frame)
        if production and name in ("value_equal", "digest", "_digest", "_digest_bytes"):
            operation = "value_equal" if name == "value_equal" else "digest"
            self.calls[(self.phase(), operation)] += 1
        parent = frame.f_back
        if module == "copy" and name == "deepcopy":
            self.calls[(self.phase(), "deepcopy")] += 1
            if parent is not None and parent.f_globals.get("__name__") != "copy":
                self.calls[(self.phase(), "deepcopy_root")] += 1
                if self.detail:
                    source = parent.f_globals.get("__name__", "")
                    if source in (
                        "runtime_protocol.timeline_commit_validation",
                        "astrid.sdk.timeline._commit_patch",
                        "astrid.core.timeline.authoring_bundle",
                        "astrid.sdk.timeline.commit",
                    ):
                        site = f"{source}:{parent.f_lineno}:{parent.f_code.co_name}:deepcopy"
                        self.boundary(site, frame.f_locals["x"])
        if not self.detail:
            return
        if module == "runtime_protocol.timeline_commit_validation" and name == "detached":
            self.boundary("runtime_protocol.timeline_commit_validation:detached",
                          frame.f_locals["value"])
        if parent is None or not module.startswith("jsonschema."):
            return
        source = parent.f_globals.get("__name__", "")
        caller = parent.f_code.co_name
        if (name == "validate" and source == "runtime_protocol.timeline_commit_validation"
                and caller == "validate_commit_value"):
            definition = parent.f_locals["definition"]
            if definition in ("PreparedCommit", "CommitRequest"):
                self.schema_start(frame, (f"Runtime.{definition}",), parent.f_locals["value"])
        if name == "iter_errors" and source == "astrid.sdk.timeline._commit_patch" and caller == "validate_reads":
            outer = parent.f_back
            site = f"Agent.CommitRead:{outer.f_code.co_name}:{outer.f_lineno}"
            self.schema_start(frame, ("Agent.CommitRead", site), parent.f_locals["read"])

    @contextmanager
    def observe(self):
        previous = sys.getprofile()
        sys.setprofile(self.profile)
        try:
            yield
        finally:
            sys.setprofile(previous)

    def table(self):
        return {f"{phase}.{operation}": count
                for (phase, operation), count in sorted(self.calls.items())}

    def details(self):
        schemas = {}
        for site, row in sorted(self.schema.items()):
            distinct = len(self.keys[site])
            schemas[site] = {**row, "distinct": distinct,
                             "hit_eligible": row["total"] - distinct}
        return {"schema": schemas,
                "copy_boundaries": {site: dict(row) for site, row in sorted(self.boundaries.items())}}


def _emit(axis, size, counts, **extra):
    print("SV-L3 " + json.dumps({"axis": axis, "size": size,
                                "calls": counts.table(), **extra}, sort_keys=True))


def test_one_warm_save_work_is_independent_of_accepted_history(film):
    """Use the existing captured film and real port acceptance; provider is prepared."""
    fixture = film.fixture
    subject = Film(fixture.duplicate_root, fixture)
    rows = []
    try:
        for size in SIZES:
            subject.grow(size - subject.next)
            assert subject.next == size

            # Separate cold startup/verified-head work from the warm save.
            provider = subject.service._timeline_commit_provider
            subject.service.close()
            startup = SaveCounts()
            with startup.observe():
                subject.service = RuntimeService(fixture.duplicate_root)
                subject.service.get_timeline_verified_head(
                    subject.project, subject.timeline, authorize=lambda: None)
            subject.service.register_timeline_commit_provider(provider)
            _emit("startup_history", size, startup)

            counts = SaveCounts()
            with counts.observe():
                result = subject.edit()
            assert result["data"]["status"] == "accepted"
            _emit("warm_history", size, counts)
            rows.append(counts.calls)
    finally:
        subject.service.close()

    assert all(sum(row.values()) > 0 for row in rows)
    assert rows[0][("provider", "deepcopy")] > 0
    assert rows[0][("acceptance", "value_equal")] > 0
    assert sum(n for (_, op), n in rows[0].items() if op == "digest") > 0
    # Compare the entire phase/operation table, not only its grand total.
    assert rows[0] == rows[1] == rows[2], rows


@pytest.mark.parametrize("count", SIZES)
def test_covers_comparison_budget(count, monkeypatch):
    """Reuse SV-L6's synthetic film-shaped dependency/reads corpus.

    Run this selector on the actual pre-index checkout as the negative control.
    It imports neither the index class nor any other post-index-only symbol.
    """
    dependencies = [
        {"kind": "field", "ref": f"clip:{i}", "path": ["config", "clips"],
         "state": {"state": "present", "value": {"position": i, "name": f"clip {i}"}}}
        for i in range(count)
    ]
    reads = copy.deepcopy(dependencies)
    step = {"id": "synthetic", "dependencies": dependencies, "command_ordinals": [], "patch": []}
    original = auth.value_equal
    calls = 0

    def equal(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(auth, "value_equal", equal)
    auth.validate_step({"commands": []}, {"commands": []}, step, {}, reads, {})
    print(f"SV-L3 covers count={count} value_equal_roots={calls}")
    assert 0 < calls <= count + 1, (count, calls)


def _seed_clips(editing, count):
    # Use the same native list.insert route as the existing real Agent film
    # integration tests; fixture setup is deliberately outside the measured save.
    clips = editing.document()["parent_revision"]["payload"]["clips"]
    assert len(clips) <= count
    order = [row["id"] for row in clips]
    changes, created = [], []
    next_at = max(row["at"] + row["hold"] for row in clips) + 10
    for i in range(count - len(clips)):
        row = copy.deepcopy(clips[-1])
        row.update(id=f"svl3-clip-{i:03d}", at=next_at)
        next_at += row["hold"] + 1
        changes.append({"op": "list.insert", "ref": "parent", "path": ["clips"],
                        "before": {"state": "absent"}, "id": row["id"], "value": row,
                        "order_before": list(order), "after_id": order[-1]})
        order.append(row["id"])
        created.append("parent/clip:" + row["id"])
    if changes:
        seed = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                "args": {"changes": changes}, "created": created}
        body = editing.body([seed])
        body["steps"][0]["patch"] = changes
        assert editing.commit(body, "svl3-seed")["data"]["status"] == "accepted"


@pytest.mark.integration
@pytest.mark.parametrize("count", SIZES)
def test_one_edit_validation_and_copy_boundaries(editing, count):
    """Measure one native move with repeated declared reads, not a synthetic validator loop."""
    _seed_clips(editing, count)
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
    # Both Agent validate_reads sites see the declared observations.
    counts = SaveCounts(detail=True)
    with counts.observe():
        result = editing.commit(body, "svl3-measured-move")
    assert result["data"]["status"] == "accepted"
    actual = result["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
    assert len(actual) == count
    assert {row["id"]: row["at"] for row in actual} == {
        row["id"]: destination if row["id"] == target["id"] else row["at"] for row in clips
    }
    details = counts.details()
    _emit("one_edit_clips", count, counts, **details)
    for site in ("Runtime.PreparedCommit", "Runtime.CommitRequest", "Agent.CommitRead"):
        row = details["schema"][site]
        assert 0 < row["distinct"] <= row["total"]
        assert row["total"] == row["distinct"] + row["hit_eligible"]
        assert row["key_bytes"] > 0
    assert details["schema"]["Agent.CommitRead"]["total"] >= 2 * count
    assert details["copy_boundaries"]
