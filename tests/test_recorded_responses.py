"""conformance/responses/ must be what a real Runtime daemon sends (testing plan C2.1, R-4).

Consumers trust only responses they reproduce from those files, so a contract change
must force `python scripts/record_responses.py` and a reviewed diff.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from astrid_runtime_client import ApiError, WorkspaceClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tests.astrid_checkout import astrid_checkout

ROOT = Path(__file__).resolve().parents[1]
COMMITTED = ROOT / "conformance" / "responses"
SCHEMAS = ROOT / "contract" / "schemas"
_spec = importlib.util.spec_from_file_location("record_responses", ROOT / "scripts" / "record_responses.py")
record_responses = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(record_responses)

ERROR = "common.json#/$defs/Error"
# case -> (schema ref for the body or for each item of body["items"], validate the committed envelope's "data")
SCHEMA_FOR = {
    "retired_route_410": (ERROR, None),
    "commit_conflict_409": (ERROR, None),
    "task_admission_201": ("task.json", "data"),
    "task_read_200": ("task.json", None),
    "managed_outputs_200": ("managed-output.json", "items"),
    "events_page_1_200": ("event.json", "items"),
    "events_page_2_200": ("event.json", "items"),
    "not_found_404": (ERROR, None),
    "validation_error_422": (ERROR, None),
    "invalid_cursor_400": (ERROR, None),
}


@pytest.fixture(scope="module")
def recorded(tmp_path_factory):
    out = tmp_path_factory.mktemp("responses")
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(astrid_checkout()))
        return out, record_responses.record(out)


def _validator(ref: str) -> Draft202012Validator:
    schemas = [json.loads(path.read_text()) for path in sorted(SCHEMAS.glob("*.json")) if "$id" in json.loads(path.read_text())]
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas)
    return Draft202012Validator({"$ref": "https://astrid.haus/workspace/v1/schemas/" + ref}, registry=registry)


def test_every_case_is_committed_and_nothing_else(recorded) -> None:
    out, _ = recorded
    assert sorted(path.name for path in COMMITTED.glob("*.json")) == sorted(path.name for path in out.glob("*.json"))
    assert {path.stem for path in COMMITTED.glob("*.json")} == set(SCHEMA_FOR)


def test_rerecording_is_byte_identical_to_committed_responses(recorded) -> None:
    out, _ = recorded
    for path in sorted(out.glob("*.json")):
        committed = COMMITTED / path.name
        assert committed.is_file(), f"{path.name} is not committed; run `python scripts/record_responses.py`"
        assert committed.read_bytes() == path.read_bytes(), f"{path.name} drifted; run `python scripts/record_responses.py`"


def test_committed_files_have_the_documented_shape() -> None:
    for path in sorted(COMMITTED.glob("*.json")):
        entry = json.loads(path.read_text())
        assert list(entry) == sorted(["case", "request", "status", "headers", "body"]), path.name
        assert entry["case"] == path.stem and set(entry["request"]) == {"method", "path", "body"}
        assert entry["headers"] == {"content-type": "application/json"}


@pytest.mark.parametrize("case", list(SCHEMA_FOR))
def test_unnormalized_bodies_satisfy_their_contract_schema(recorded, case: str) -> None:
    """Placeholders would fail id/digest patterns, so validate what the daemon actually sent."""
    _, raw = recorded
    ref, part = SCHEMA_FOR[case]
    body = raw[case]["body"]
    validator = _validator(ref)
    if part == "items":
        assert set(body) == {"items", "next_cursor"} and body["items"]
        values = body["items"]
    else:
        values = [body[part] if part else body]
    for value in values:
        errors = [error.message for error in validator.iter_errors(value)]
        assert not errors, f"{case}: {errors}"


def test_recorded_retirement_and_canonical_conflict_are_distinct(recorded):
    _, raw = recorded
    retired, conflict = raw["retired_route_410"], raw["commit_conflict_409"]
    assert retired["status"] == 410 and retired["body"]["code"] == "retired_route"
    assert conflict["status"] == 409 and conflict["body"]["code"] == "conflict"
    details = conflict["body"]["details"]
    assert details["reason"] == "stale_head"
    assert details["base"] != details["current"]


@pytest.mark.parametrize("case", ["retired_route_410", "commit_conflict_409"])
def test_product_client_preserves_recorded_errors(recorded, case):
    out, raw = recorded
    response = raw[case]
    entry = json.loads((out / f"{case}.json").read_text())

    def transport(method, path, headers, body):
        assert method == entry["request"]["method"]
        assert path.endswith("/commit" if case == "commit_conflict_409" else "/composition-revisions")
        expected = dict(entry["request"]["body"])
        if case == "retired_route_410":
            expected.update(project_id="project", timeline_id="main")
        assert json.loads(body) == expected
        return response["status"], {}, json.dumps(response["body"]).encode()

    client = WorkspaceClient("http://runtime", "token", transport=transport)
    with pytest.raises(ApiError) as caught:
        if case == "commit_conflict_409":
            client.commit_timeline("project", "main", entry["request"]["body"], idempotency_key=case)
        else:
            client.publish_parent_composition("project", "main", entry["request"]["body"], idempotency_key=case)
    assert caught.value.status == response["status"]
    assert caught.value.code == response["body"]["code"]
    assert caught.value.details == response["body"]["details"]
