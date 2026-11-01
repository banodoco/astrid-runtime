from __future__ import annotations

import importlib
import json
import subprocess
from pathlib import Path
from typing import TypedDict, Union, get_args, get_origin, get_type_hints, is_typeddict

import pytest

from generators import timeline_commit_types


ROOT = Path(__file__).resolve().parents[1]


def union_members(alias, namespace):
    holder = TypedDict("Holder", {"args": alias})
    resolved = get_type_hints(holder, namespace)["args"]
    assert get_origin(resolved) is Union
    members = get_args(resolved)
    assert all(is_typeddict(member) for member in members)
    return members


@pytest.mark.parametrize(
    "module_name",
    ["runtime_protocol.timeline_commit_types", "astrid_runtime_client.timeline_commit_types"],
)
def test_track_label_union_imports_and_retains_field_types(module_name):
    dto = importlib.import_module(module_name)
    labeled, cleared = union_members(dto.TrackSetArgs, vars(dto))
    for branch in (labeled, cleared):
        assert branch.__required_keys__ == {"values", "clear"}
        assert branch.__optional_keys__ == set()
    label_values = get_type_hints(labeled)["values"]
    clear_values = get_type_hints(cleared)["values"]
    assert label_values.__required_keys__ == {"label"}
    assert label_values.__optional_keys__ == set()
    assert clear_values.__required_keys__ == set()
    assert clear_values.__optional_keys__ == {"label"}
    assert get_type_hints(label_values) == get_type_hints(clear_values) == {"label": str}
    assert labeled(values=label_values(label="é 🎬"), clear=[]) == {
        "values": {"label": "é 🎬"}, "clear": []
    }
    assert cleared(values=clear_values(), clear=["label"]) == {
        "values": {}, "clear": ["label"]
    }


@pytest.mark.parametrize("keyword", ["oneOf", "anyOf"])
def test_object_unions_keep_shared_and_branch_required_fields(tmp_path, monkeypatch, keyword):
    schemas = tmp_path / "contract/schemas"
    schemas.mkdir(parents=True)
    (schemas / "timeline-commit.json").write_text(json.dumps({"$defs": {}}))
    (schemas / "edit-command.json").write_text(json.dumps({"$defs": {
        "ChangeArgs": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            keyword: [
                {"properties": {"target": {}, "value": {"type": "string"}, "note": {"type": "string"}},
                 "required": ["value"], "additionalProperties": False},
                {"properties": {"target": {}, "clear": {"const": "value"}},
                 "required": ["clear"], "additionalProperties": False},
            ],
        },
    }}))
    openapi = tmp_path / "contract/openapi"
    openapi.mkdir()
    (openapi / "workspace-v1.yaml").write_text(json.dumps({"components": {"schemas": {
        "CommittedMutation": {"properties": {"receipt": {"type": "object"}}},
    }}}))
    monkeypatch.setattr(timeline_commit_types, "ROOT", tmp_path)
    outputs = timeline_commit_types.render()
    namespace = {}
    exec(outputs["runtime_protocol/timeline_commit_types.py"], namespace)
    set_value, clear_value = union_members(namespace["ChangeArgs"], namespace)
    assert set_value.__required_keys__ == {"target", "value"}
    assert set_value.__optional_keys__ == {"note"}
    assert clear_value.__required_keys__ == {"target", "clear"}
    assert clear_value.__optional_keys__ == set()
    assert get_type_hints(set_value, namespace) == {
        "target": str, "value": str, "note": str,
    }
    source = tmp_path / "generic.mts"
    source.write_text(outputs["packages/typescript/src/timeline-commit-types.ts"] + """
const setValue: ChangeArgs = { target: "t", value: "", note: "optional" };
const clearValue: ChangeArgs = { target: "t", clear: "value" };
// @ts-expect-error Shared required field is missing.
const missingTarget: ChangeArgs = { value: "x" };
// @ts-expect-error Neither branch has its required field.
const missingBranch: ChangeArgs = { target: "t", note: "optional" };
// @ts-expect-error Closed branches reject unrelated fields.
const unknownField: ChangeArgs = { target: "t", value: "x", extra: true };
""")
    subprocess.run(["tsc", "--noEmit", "--strict", "--target", "ES2022", str(source)], check=True)


def test_typescript_track_label_positive_and_negative_fixtures():
    subprocess.run([
        "tsc", "--noEmit", "--strict", "--module", "NodeNext", "--target", "ES2022",
        str(ROOT / "tests/fixtures/timeline-commit-types.mts"),
    ], check=True)


@pytest.mark.parametrize(
    "module_name",
    ["runtime_protocol.timeline_commit_types", "astrid_runtime_client.timeline_commit_types"],
)
def test_inverse_args_generate_optional_step_selection(module_name):
    dto = importlib.import_module(module_name)
    inverse = dto.InverseArgs
    assert inverse.__required_keys__ == {"publications"}
    assert inverse.__optional_keys__ == {"steps"}
    assert get_type_hints(inverse) == {
        "publications": list[str],
        "steps": dict[str, list[str]],
    }

    rendered = timeline_commit_types.render()["packages/typescript/src/timeline-commit-types.ts"]
    assert "export type InverseArgs = { publications: [ID, ...Array<ID>]; steps?: { [key: string]: [ID, ...Array<ID>] } };" in rendered
