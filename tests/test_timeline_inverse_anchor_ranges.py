"""Anchor inverse ranges keep compiler timing separate from native writes."""
from __future__ import annotations

import copy

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import (
    _inverse_stage_history,
    _inverse_stage_ranges,
    _inverse_stage_timing,
)


PUBLICATION = "anchor-publication"
CLIP = "parent/clip:card"


def _present(value):
    return {"state": "present", "value": value}


def _write(ref, path, before, after):
    return {"ref": ref, "path": list(path), "before": before, "after": after}


def _anchor_history(*, root_step=False):
    """Accepted source with an authored anchor and separately derived timing."""
    choice = {"source": "occurrence:occ/clip:voice", "word_ids": ["word:one"]}
    anchor_writes = [
        _write(CLIP, ["app", "astrid", "on"], {"state": "absent"}, _present('"again"')),
        # The container was absent before first use; the source write still
        # addresses its authored leaf.
        _write(CLIP, ["app", "astrid", "word_anchors", "on"], {"state": "absent"}, _present(choice)),
    ]
    derived = [
        _write(CLIP, ["at"], _present(3.5), _present(3.4701333333333335)),
        _write(CLIP, ["hold"], _present(1), _present(0.5)),
    ]
    commands = []
    steps = []
    if root_step:
        commands.append({"ordinal": 0, "command": {"op": "clip.add"},
                         "writes": [_write(CLIP, [], {"state": "absent"}, _present({"id": "card"}))],
                         "derived_writes": [], "bindings": []})
        steps.append({"id": "birth", "command_ordinals": [0], "patch": []})
    ordinal = len(commands)
    commands.append({"ordinal": ordinal, "command": {"op": "clip.anchor"},
                     "writes": anchor_writes, "derived_writes": derived, "bindings": []})
    steps.append({"id": "anchor", "command_ordinals": [ordinal], "patch": []})
    entry = {"publication_id": PUBLICATION, "intent": "recorded",
             "receipt": {"receipt_id": PUBLICATION},
             "records": {"commands": commands, "steps": steps}}
    return entry


def _inverse_packet(entry, *, damaged=None):
    source = entry["records"]["commands"][-1]
    inverse_writes = [
        {**copy.deepcopy(write), "before": copy.deepcopy(write["after"]),
         "after": copy.deepcopy(write["before"])}
        for write in reversed(source["writes"])
    ]
    inverse_effects = [
        {"op": "remove", "ref": write["ref"], "path": list(write["path"]),
         "before": copy.deepcopy(write["after"])}
        for write in reversed(source["writes"])
    ]
    boundary = {"publication_id": PUBLICATION, "step_id": "anchor",
                "command_ordinals": [source["ordinal"]],
                "native_write_range": [0, len(inverse_writes)],
                "effect_range": [0, len(inverse_effects)]}
    record = {"ordinal": 0,
              "command": {"op": "timeline.inverse", "args": {"publications": [PUBLICATION]}},
              "writes": inverse_writes,
              "bindings": [{"key": "inverse.stage", "ref": "parent", "policy": "fixed",
                            "dependencies": [], "boundary": boundary}]}
    step = {"id": "undo", "command_ordinals": [0], "patch": inverse_effects}
    records = {"undo_of": [PUBLICATION], "undo_steps": None,
               "commands": [record], "steps": [step]}
    if damaged == "range":
        boundary["native_write_range"] = [0, 1]
    elif damaged == "site":
        record["writes"][0]["path"][-1] = "forged"
    elif damaged == "add":
        record["writes"].append(copy.deepcopy(record["writes"][-1]))
        boundary["native_write_range"][1] += 1
    elif damaged == "remove":
        record["writes"].pop()
        boundary["native_write_range"][1] -= 1
    elif damaged == "reorder":
        record["writes"].reverse()
    return step, records


def test_anchor_inverse_range_contains_authored_writes_but_not_derived_timing():
    entry = _anchor_history()
    expected, = _inverse_stage_history({"undo_of": [PUBLICATION], "undo_steps": None},
                                       {PUBLICATION: entry})
    assert expected["native_sites"] == [
        (CLIP, ["app", "astrid", "word_anchors", "on"]),
        (CLIP, ["app", "astrid", "on"]),
    ]
    step, records = _inverse_packet(entry)
    stages = _inverse_stage_ranges(step, records, {PUBLICATION: entry})
    assert len(stages) == 1
    assert stages[0]["native_range"] == [0, 2]
    assert len(entry["records"]["commands"][-1]["derived_writes"]) == 2


@pytest.mark.parametrize("damage", ["range", "site", "add", "remove", "reorder"])
def test_anchor_inverse_native_range_rejects_capture_corruption(damage):
    entry = _anchor_history()
    step, records = _inverse_packet(entry, damaged=damage)
    with pytest.raises(CommitRejected):
        _inverse_stage_ranges(step, records, {PUBLICATION: entry})


def test_derived_timing_is_native_only_when_its_whole_clip_root_is_selected():
    entry = _anchor_history(root_step=True)
    selection = {"undo_of": [PUBLICATION], "undo_steps": {PUBLICATION: ["anchor"]}}
    anchor_only, = _inverse_stage_history(selection, {PUBLICATION: entry})
    assert anchor_only["step_id"] == "anchor"
    assert all(path not in (["at"], ["hold"]) for _, path in anchor_only["native_sites"])

    selection["undo_steps"][PUBLICATION] = ["birth", "anchor"]
    selected_stages = _inverse_stage_history(selection, {PUBLICATION: entry})
    assert [stage["step_id"] for stage in selected_stages] == ["anchor", "birth"]
    anchor_stage = selected_stages[0]
    assert (CLIP, ["at"]) in anchor_stage["native_sites"]
    assert (CLIP, ["hold"]) in anchor_stage["native_sites"]


def _clip_image(at, hold, *, anchor=True):
    row = {"id": "card", "at": at, "hold": hold}
    if anchor:
        row["app"] = {"astrid": {"on": '"again"',
                                  "word_anchors": {"on": {"word_ids": ["word:one"]}}}}
    else:
        row["app"] = {"astrid": {"on": '"again"'}}
    return {"parent": {"payload": {
        "config": {"clips": [copy.deepcopy(row)]},
        "clips": [copy.deepcopy(row)],
    }}}


def _timing_packet(*, live=False):
    stage_before = _clip_image(3.4701333333333335, 0.5)
    if live:
        # The accepted edit changed the anchor; undo restores the previous live
        # anchor, so the compiler recomputes timing to this prior anchor.
        stage_after = _clip_image(2.0, 1.5)
        stage_after["parent"]["payload"]["config"]["clips"][0]["app"]["astrid"]["word_anchors"]["on"] = {
            "word_ids": ["word:prior"]}
        stage_after["parent"]["payload"]["clips"][0]["app"]["astrid"]["word_anchors"]["on"] = {
            "word_ids": ["word:prior"]}
    else:
        stage_after = _clip_image(3.5, 1.0, anchor=False)

    native_image = copy.deepcopy(stage_before)
    for row in (native_image["parent"]["payload"]["config"]["clips"][0],
                native_image["parent"]["payload"]["clips"][0]):
        astrid = row["app"]["astrid"]
        astrid.pop("on", None)
        astrid.pop("word_anchors", None)
    if live:
        prior = stage_after["parent"]["payload"]["config"]["clips"][0]["app"]["astrid"]["word_anchors"]
        for row in (native_image["parent"]["payload"]["config"]["clips"][0],
                    native_image["parent"]["payload"]["clips"][0]):
            row["app"]["astrid"]["word_anchors"] = copy.deepcopy(prior)
            row["app"]["astrid"]["on"] = '"again"'

    source_caches = [
        _write(CLIP, ["at"], _present(3.5), _present(3.4701333333333335)),
        _write(CLIP, ["hold"], _present(1.0), _present(0.5)),
    ]
    captures = [
        _write(CLIP, ["at"], _present(3.4701333333333335), _present(2.0 if live else 3.5)),
        _write(CLIP, ["hold"], _present(0.5), _present(1.5 if live else 1.0)),
    ]
    source_step = {"command_ordinals": [0]}
    source_commands = [{"derived_writes": source_caches}]
    stage = {"record": {"derived_writes": captures}}
    return native_image, stage_before, stage_after, stage, source_step, source_commands


def test_inverse_stage_timing_restores_authenticated_literal_cache_in_both_mirrors():
    packet = _timing_packet()
    _inverse_stage_timing(*packet)
    native_image = packet[0]["parent"]["payload"]
    for rows in (native_image["config"]["clips"], native_image["clips"]):
        assert rows[0]["at"] == 3.5
        assert rows[0]["hold"] == 1.0
        assert "word_anchors" not in rows[0]["app"]["astrid"]


@pytest.mark.parametrize("damage", ["source-literal", "capture-before", "capture-after",
                                    "missing", "extra", "duplicate", "omitted-restoration"])
def test_inverse_stage_timing_rejects_bad_derived_captures(damage):
    packet = list(_timing_packet())
    native_image, stage_before, stage_after, stage, source_step, source_commands = packet
    if damage == "source-literal":
        source_commands[0]["derived_writes"][0]["before"] = _present(99)
    elif damage == "capture-before":
        stage["record"]["derived_writes"][0]["before"] = _present(99)
    elif damage == "capture-after":
        stage["record"]["derived_writes"][0]["after"] = _present(99)
    elif damage == "missing":
        stage["record"]["derived_writes"].pop()
    elif damage == "omitted-restoration":
        # The inverse removes the anchor but leaves its derived cache values.
        # Stage effects consequently match the native image, even though those
        # values are not the literal cache authenticated by the source.
        stage_after["parent"]["payload"]["config"]["clips"][0]["at"] = 3.4701333333333335
        stage_after["parent"]["payload"]["config"]["clips"][0]["hold"] = 0.5
        stage_after["parent"]["payload"]["clips"][0]["at"] = 3.4701333333333335
        stage_after["parent"]["payload"]["clips"][0]["hold"] = 0.5
        stage["record"]["derived_writes"] = []
    elif damage == "extra":
        stage["record"]["derived_writes"].append(
            _write("parent/clip:other", ["at"], _present(1), _present(2)))
    else:
        stage["record"]["derived_writes"].append(copy.deepcopy(
            stage["record"]["derived_writes"][0]))
    with pytest.raises(CommitRejected):
        _inverse_stage_timing(native_image, stage_before, stage_after, stage,
                              source_step, source_commands)


def test_inverse_stage_timing_accepts_matching_recompute_for_a_live_anchor():
    packet = _timing_packet(live=True)
    _inverse_stage_timing(*packet)
    native_image = packet[0]["parent"]["payload"]
    for rows in (native_image["config"]["clips"], native_image["clips"]):
        assert rows[0]["at"] == 2.0
        assert rows[0]["hold"] == 1.5
        assert rows[0]["app"]["astrid"]["word_anchors"]["on"]["word_ids"] == ["word:prior"]

