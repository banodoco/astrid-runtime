"""Permit only the native authority-only guard's explicit recorder defaults.

Acceptance with a real semantic provider is covered by the frozen Agent
producer integration lane; these tests exercise matching and forged records.
"""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.timeline_commit_port import RequestCommitPort, _producer_guard_matches
from test_timeline_producer_guards import (
    _assert_refused,
    _body,
    _candidate,
    _context,
    _settle,
)
from test_timeline_producer_guards import producer as producer  # noqa: PLC0414


DEFAULTS = {
    "intent": {}, "resolved": [], "reads": [], "selections": [],
    "bindings": {}, "created": [], "expect": {}, "authorship": {},
}


@pytest.mark.parametrize("fields", [[], list(DEFAULTS), *[[field] for field in DEFAULTS]])
def test_guard_permits_only_explicit_empty_recorder_forms(producer, fields):
    original = _body(producer)["commands"][0]
    recorded = {**copy.deepcopy(original), **{key: copy.deepcopy(DEFAULTS[key]) for key in fields}}
    before = copy.deepcopy(recorded)
    assert _producer_guard_matches(recorded, original)
    assert recorded == before
    assert set(original) == {"schema_version", "op", "version", "select", "args"}


@pytest.fixture
def captured(producer):
    _settle(producer)
    service = producer.service
    commits, _ = service._timeline_commits()
    context = _context(producer)
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        port.producer_attempt(producer.pin)
        candidate = _candidate(context, port, producer.pin)
        candidate["records"]["commands"][0]["command"].update(copy.deepcopy(DEFAULTS))
        yield service, port, candidate
    finally:
        port.close()


@pytest.mark.parametrize("field,value", [
    ("intent", {"ripple": True}), ("resolved", ["parent"]),
    ("reads", [{"ref": "parent", "path": [], "state": {"state": "absent"}}]),
    ("selections", [{"key": "forged"}]), ("bindings", {"target": "parent/clip:forged"}),
    ("created", ["parent/track:forged"]), ("expect", {"parent::x": {"state": "absent"}}),
    ("authorship", {"parent::x": "direct"}),
    *[(key, [] if isinstance(value, dict) else {}) for key, value in DEFAULTS.items()],
    ("semantic_override", {}), ("rationale", "forged"), ("group_id", "forged"),
])
def test_forged_guard_metadata_refuses_without_writes(captured, field, value):
    service, port, candidate = captured
    candidate["records"]["commands"][0]["command"][field] = value
    _assert_refused(service, lambda: port._producer_captures(candidate), {"producer_dependency_unavailable"})


@pytest.mark.parametrize("field", ["writes", "reads", "selections", "bindings", "created", "derived_writes"])
def test_authority_only_guard_cannot_hide_record_effects(captured, field):
    service, port, candidate = captured
    candidate["records"]["commands"][0][field].append({"forged": True})
    _assert_refused(service, lambda: port._producer_captures(candidate), {"producer_dependency_unavailable"})


@pytest.mark.parametrize("mutation", [
    "schema_type", "schema", "op", "version", "select", "args", "missing",
    "fence_bool", "fence_float", "digest", "admission", "command_number", "command_bool",
    "command_rationale", "command_unknown", "command_metadata", "missing_command", "extra_command",
    "undo", "restore",
])
def test_normalization_preserves_typed_pin_and_all_proposed_command_values(captured, mutation):
    service, port, candidate = captured
    records = candidate["records"]
    commands = records["commands"]
    guard = commands[0]["command"]
    if mutation == "schema_type":
        guard["schema_version"] = 1.0
    elif mutation in {"schema", "op", "version", "select"}:
        guard[{"schema": "schema_version"}.get(mutation, mutation)] = "forged"
    elif mutation == "args":
        guard["args"]["extra"] = None
    elif mutation == "missing":
        del guard["select"]
    elif mutation in {"fence_bool", "fence_float"}:
        guard["args"]["pin"]["fence"] = True if mutation == "fence_bool" else float(guard["args"]["pin"]["fence"])
    elif mutation == "digest":
        guard["args"]["pin"]["proposal_digest"] = "sha256:" + "f" * 64
    elif mutation == "admission":
        guard["args"]["pin"]["admitted_target"]["timeline_id"] = "other"
    elif mutation in {"command_number", "command_bool"}:
        commands[1]["command"]["args"]["on"] = 2 if mutation == "command_number" else True
    elif mutation in {"command_rationale", "command_unknown", "command_metadata"}:
        commands[1]["command"][{"command_rationale": "rationale", "command_unknown": "unknown",
                                 "command_metadata": "expect"}[mutation]] = "forged"
    elif mutation == "missing_command":
        commands.pop()
    elif mutation == "extra_command":
        commands.append(copy.deepcopy(commands[1]))
    elif mutation == "undo":
        records["undo_of"] = ["forged"]
    else:
        records["restored_from"] = {"revision_id": "forged"}
    _assert_refused(service, lambda: port._producer_captures(candidate), {"producer_dependency_unavailable"})
