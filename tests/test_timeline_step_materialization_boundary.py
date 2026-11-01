"""Bounded validator controls; these do not stand in for provider acceptance."""
from __future__ import annotations

import copy
from typing import Any

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import validate_bindings
from runtime_protocol.timeline_commit_validation import digest


def _boundary(suffix):
    def image(revision, payload, **fields):
        return {"revision_id": revision, "payload": payload,
                "content_digest": digest(payload), **fields}

    shot, internal = "shot-" + suffix, "internal-" + suffix
    return {
        "parent": image("parent-" + suffix, {"occurrences": [
            {"occurrence_id": "child", "shot_id": "child", "shot_revision_id": shot}]}),
        "shot-revision:" + shot: image(shot, {"internal_timeline_revision_id": internal},
                                      shot_id="child", internal_timeline_revision_id=internal),
        "internal-revision:" + internal: image(internal, {"tracks": [{"id": suffix}]},
                                              timeline_id="child"),
    }


def _case(kind) -> dict[str, Any]:
    source, command_input, output = [_boundary(suffix) for suffix in ("source", "middle", "final")]
    request = {"base_revision_id": "base", "base_publication_id": "publication"}
    head = {"revision_id": "landing", "publication_id": "landing-publication"}
    step = {"id": "edit", "command_ordinals": [0, 1]}
    physical = kind + "-revision:" + kind + "-source"
    companion = "internal" if kind == "shot" else "shot"
    binding = {
        "key": "commit.materialization", "ref": physical, "physical_ref": physical,
        "revision_id": source[physical]["revision_id"],
        "content_digest": source[physical]["content_digest"],
        "owner": "occurrence:child/shot", "owners": ["occurrence:child/shot"],
        "successor": kind + "-revision:" + kind + "-final",
        "edge_before": companion + "-revision:" + companion + "-source",
        "edge_after": companion + "-revision:" + companion + "-final",
        "step_id": "edit", "command_ordinal": 1,
        "boundary": {**request, "evaluated_head": head, "phase": "input",
                     "step_id": "edit", "command_ordinal": 1},
    }
    records = {"commands": [{"bindings": []}, {"bindings": [binding]}]}
    return {"request": request, "records": records, "expected": head,
            "boundary": command_input, "output": output, "step": step, "ordinal": 1,
            "continuations": {}, "original": source, "step_input": source}


@pytest.mark.parametrize("kind", ["shot", "internal"])
def test_complete_step_materialization_uses_outer_source_and_final_output(kind):
    validate_bindings(**_case(kind))


@pytest.mark.parametrize("kind", ["shot", "internal"])
@pytest.mark.parametrize("damage", [
    "step_input", "source", "revision", "digest", "owner", "owners",
    "edge_before", "edge_after", "successor", "output_edge", "output_companion",
    "missing_output", "step", "ordinal", "attribution", "head", "base", "phase",
])
def test_step_materialization_keeps_physical_and_attribution_guards(kind, damage):
    args = _case(kind)
    binding = args["records"]["commands"][1]["bindings"][0]
    if damage == "step_input":
        args["step_input"] = args["boundary"]
    elif damage == "source":
        binding["physical_ref"] = binding["ref"] = kind + "-revision:" + kind + "-middle"
    elif damage in {"revision", "digest"}:
        binding["revision_id" if damage == "revision" else "content_digest"] = "forged"
    elif damage == "owner":
        binding["owner"] = "occurrence:foreign/shot"
    elif damage == "owners":
        binding["owners"] = ["occurrence:foreign/shot"]
    elif damage in {"edge_before", "edge_after", "successor"}:
        binding[damage] = "shot-revision:foreign"
    elif damage == "output_edge":
        args["output"]["parent"]["payload"]["occurrences"][0]["shot_revision_id"] = "foreign"
    elif damage == "output_companion":
        args["output"]["shot-revision:shot-final"]["internal_timeline_revision_id"] = "foreign"
    elif damage == "missing_output":
        del args["output"][binding["successor"]]
    elif damage == "step":
        binding["boundary"]["step_id"] = "foreign"
    elif damage == "ordinal":
        binding["boundary"]["command_ordinal"] = 0
    elif damage == "attribution":
        binding["command_ordinal"] = 0
    elif damage == "head":
        binding["boundary"]["evaluated_head"] = {}
    elif damage == "base":
        binding["boundary"]["base_revision_id"] = "foreign"
    elif damage == "phase":
        binding["boundary"]["phase"] = "effect"

    with pytest.raises(CommitRejected):
        validate_bindings(**args)


@pytest.mark.parametrize("use_step_pin", [False, True])
def test_command_binding_still_uses_exact_command_input(use_step_pin):
    args = _case("shot")
    image = args["step_input" if use_step_pin else "boundary"]["parent"]
    boundary = copy.deepcopy(args["records"]["commands"][1]["bindings"][0]["boundary"])
    args["records"]["commands"][1]["bindings"] = [{
        "key": "commit.read", "ref": "parent", "physical_ref": "parent",
        "revision_id": image["revision_id"], "content_digest": image["content_digest"],
        "boundary": boundary,
    }]
    if use_step_pin:
        with pytest.raises(CommitRejected):
            validate_bindings(**args)
    else:
        validate_bindings(**args)
