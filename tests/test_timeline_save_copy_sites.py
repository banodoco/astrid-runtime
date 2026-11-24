"""SV-L11 count gate only; use the SV-L3 real 300-clip one-edit fixture.

This observer does not change any production value, schema, or existing
counter/assertion. Run with the lane's Agent checkout and CPU integration
stack. JSON byte counts are the SV-L3 payload-size proxy, not heap allocations.
"""
from __future__ import annotations

import copy
import json
import sys
import threading
import time
from collections import Counter, defaultdict
from contextlib import contextmanager

import pytest

from runtime_protocol import timeline_commit_validation
from test_timeline_commit_cost import film
from test_timeline_commit_integration import agent, editing
from test_timeline_save_work_counters import _bytes, _seed_clips


def _production(module):
    return module.startswith(("runtime_protocol.", "astrid."))


def _site(frame):
    # Distinguish multiple calls on the same source line by bytecode offset.
    name = frame.f_globals.get("__name__", "")
    site = f"{name}:{frame.f_lineno}:{frame.f_code.co_qualname}@{frame.f_lasti}"
    # The Agent authoring helper otherwise combines unrelated snapshot sites.
    if name == "astrid.core.timeline.authoring_bundle" and frame.f_code.co_name == "_copy":
        parent = frame.f_back
        if parent is not None:
            site += f"<-{parent.f_lineno}:{parent.f_code.co_qualname}@{parent.f_lasti}"
    return site


def _container_bytes(value):
    """Explicitly separate a non-JSON reachable-container size proxy."""
    total, seen, stack = 0, set(), [value]
    while stack:
        item = stack.pop()
        if not isinstance(item, (dict, list, tuple, set, frozenset)) or id(item) in seen:
            continue
        seen.add(id(item))
        total += sys.getsizeof(item)
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        else:
            stack.extend(item)
    return total


class CopySites:
    def __init__(self):
        self.rows = defaultdict(Counter)

    def record(self, kind, site, value, copy_ns, boundary_ns):
        row = self.rows[(kind, site)]
        row["calls"] += 1
        row["copy_ns"] += copy_ns
        row["boundary_ns"] += boundary_ns
        # Account after the timed operation, never within the copy or detached
        # timer. No serialized keys, values or object identities are printed.
        try:
            row["json_bytes"] += len(_bytes(value))
            row["json_calls"] += 1
        except (TypeError, ValueError, RecursionError, OverflowError):
            row["nonjson_calls"] += 1
            row["nonjson_container_bytes"] += _container_bytes(value)

    @contextmanager
    def observe(self, monkeypatch):
        original_copy = copy.deepcopy
        original_detached = timeline_commit_validation.detached
        thread = threading.get_ident()
        depth = 0
        inside_detached = None

        def measured_copy(x, *args, **kwargs):
            nonlocal depth
            if threading.get_ident() != thread or depth:
                return original_copy(x, *args, **kwargs)
            caller = sys._getframe(1)
            production = _production(caller.f_globals.get("__name__", ""))
            site = _site(caller) if production and inside_detached is None else None
            depth += 1
            started = time.perf_counter_ns()
            try:
                result = original_copy(x, *args, **kwargs)
            finally:
                elapsed = time.perf_counter_ns() - started
                depth -= 1
            if inside_detached is not None:
                # Aggregate into the detached CALLER row, not a second copy
                # row: summing copy_ns over all rows must not double-count.
                inside_detached.append(elapsed)
            elif production:
                self.record("deepcopy", site, x, elapsed, elapsed)
            return result

        def measured_detached(value):
            nonlocal inside_detached
            if threading.get_ident() != thread:
                return original_detached(value)
            assert inside_detached is None, "unexpected nested detached boundary"
            site = _site(sys._getframe(1))
            times = []
            inside_detached = times
            started = time.perf_counter_ns()
            try:
                result = original_detached(value)
            finally:
                elapsed = time.perf_counter_ns() - started
                inside_detached = None
            assert len(times) == 1, "detached no longer performs one root deepcopy"
            self.record("detached", site, value, times[0], elapsed)
            return result

        with monkeypatch.context() as patch:
            patch.setattr(copy, "deepcopy", measured_copy)
            # Match by identity, including imported aliases. Later imports
            # obtain the same wrappers from the patched source modules.
            for name, module in tuple(sys.modules.items()):
                if module is None or not _production(name):
                    continue
                for key, value in tuple(vars(module).items()):
                    if value is original_copy:
                        patch.setattr(module, key, measured_copy)
                    elif value is original_detached:
                        patch.setattr(module, key, measured_detached)
            yield

    def report(self):
        return [
            {"kind": kind, "site": site, **{
                field: row[field] for field in (
                    "calls", "json_calls", "json_bytes", "nonjson_calls",
                    "nonjson_container_bytes", "copy_ns", "boundary_ns",
                )
            }}
            for (kind, site), row in sorted(self.rows.items())
        ]


@pytest.mark.integration
def test_sv_l11_count_one_edit_300(editing, monkeypatch):
    count = 300
    # Keep the exact SV-L3 clip-axis workload. Seed and body construction are
    # outside the observed save; one accepted native move is observed.
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

    counts = CopySites()
    with counts.observe(monkeypatch):
        result = editing.commit(body, "svl11-counted-move")
    assert result["data"]["status"] == "accepted"
    actual = result["data"]["canonical_document"]["parent_revision"]["payload"]["clips"]
    assert len(actual) == count
    assert {row["id"]: row["at"] for row in actual} == {
        row["id"]: destination if row["id"] == target["id"] else row["at"] for row in clips
    }
    rows = counts.report()
    for row in rows:
        print("SV-L11-SITE " + json.dumps(row, sort_keys=True))
        assert row["calls"] == row["json_calls"] + row["nonjson_calls"]
        assert 0 < row["copy_ns"] <= row["boundary_ns"]
    assert any(row["kind"] == "detached" for row in rows)
    assert any(row["kind"] == "deepcopy" and "CommitPatch.before" in row["site"]
               for row in rows)
    print("SV-L11-TOTAL " + json.dumps({
        "clips": count,
        "detached_calls": sum(r["calls"] for r in rows if r["kind"] == "detached"),
        "detached_json_bytes": sum(r["json_bytes"] for r in rows if r["kind"] == "detached"),
        "copy_ns": sum(r["copy_ns"] for r in rows),
        "boundary_ns": sum(r["boundary_ns"] for r in rows),
    }, sort_keys=True))
