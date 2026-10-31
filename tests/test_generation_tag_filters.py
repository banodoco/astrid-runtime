from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from runtime_protocol.errors import InvalidRequestError
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


def _insert(service, project_id, generation_id, metadata, *, stamp="2026-10-01T00:00:00Z"):
    body = metadata if isinstance(metadata, str) else json.dumps(metadata)
    service.store.conn.execute(
        "INSERT INTO generations(id, project_id, metadata_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?)", (generation_id, project_id, body, stamp, stamp),
    )


@pytest.fixture
def fixture_generations(tmp_path):
    RealmStore.initialize(tmp_path).close()
    service = RuntimeService(tmp_path)
    project = service.create_project({"name": "Tags", "slug": "tags"}, idempotency_key="tags")
    foreign = service.create_project({"name": "Other", "slug": "other"}, idempotency_key="other")
    for generation_id, gen in (
        ("managed", {"kind": "image", "model": "X", "target": "managed", "tags": ["hero", "local"]}),
        ("runpod", {"kind": "video", "model": "X", "target": "runpod", "tags": ["hero", "remote"]}),
        ("fal", {"kind": "video", "model": "Y", "target": "fal", "tags": ["remote"]}),
    ):
        _insert(service, project["id"], generation_id, {"prompt": "preserved", "gen": gen})
    _insert(service, foreign["id"], "foreign", {"gen": {
        "kind": "video", "model": "X", "target": "runpod", "tags": ["hero"],
    }})
    try:
        yield service, project["id"]
    finally:
        service.close()


@pytest.mark.parametrize(("filters", "expected"), [
    ({"kind": "image"}, ["managed"]),
    ({"model": "X"}, ["managed", "runpod"]),
    ({"target": "runpod"}, ["runpod"]),
    ({"tag": "hero"}, ["managed", "runpod"]),
    ({"kind": "video", "model": "X", "target": "runpod", "tag": "hero"}, ["runpod"]),
    ({"model": "X", "target": "runpod"}, ["runpod"]),
    ({"model": "missing"}, []),
    ({"tag": "her"}, []),
])
def test_generation_filters_match_only_project_fixture_rows(fixture_generations, filters, expected):
    service, project_id = fixture_generations
    page = service.list_generations(project_id, **filters)
    assert [row["generation_id"] for row in page["items"]] == expected
    assert page["next_cursor"] is None
    assert all(row["metadata"]["prompt"] == "preserved" for row in page["items"])


def test_generation_filters_ignore_malformed_optional_fields(fixture_generations):
    service, project_id = fixture_generations
    malformed = [
        {}, {"gen": None}, {"gen": "bad"}, {"gen": []},
        {"gen": {"kind": [], "model": {}, "target": True, "tags": "hero"}},
        {"gen": {"kind": 7, "model": False, "target": ["runpod"], "tags": {"hero": True}}},
        {"gen": {"tags": [1, None, {"hero": True}, ["hero"]]}},
        "{broken-json",
    ]
    for index, metadata in enumerate(malformed):
        _insert(service, project_id, f"malformed-{index}", metadata)
    for filters, expected in (
        ({"kind": "video"}, ["fal", "runpod"]),
        ({"model": "X"}, ["managed", "runpod"]),
        ({"target": "runpod"}, ["runpod"]),
        ({"tag": "hero"}, ["managed", "runpod"]),
        ({"model": "{}"}, []),
        ({"tag": '{"hero":true}'}, []),
    ):
        assert [row["generation_id"] for row in service.list_generations(project_id, **filters)["items"]] == expected


def test_generation_filters_are_exact_bound_values(fixture_generations):
    service, project_id = fixture_generations
    model = "FLUX1\\ae_'%?.safetensors"
    tag = "' OR 1=1 --"
    _insert(service, project_id, "literal", {"gen": {"model": model, "tags": [tag]}})
    rows = service.list_generations(project_id, model=model, tag=tag)["items"]
    assert [row["generation_id"] for row in rows] == ["literal"]
    assert service.list_generations(project_id, model="%", tag=tag)["items"] == []


def test_generation_filter_pages_keep_order_and_bind_cursor_to_filters(fixture_generations):
    service, project_id = fixture_generations
    _insert(service, project_id, "newest", {"gen": {"model": "X", "tags": ["hero"]}},
            stamp="2026-10-02T00:00:00Z")
    first = service.list_generations(project_id, model="X", tag="hero", limit=1)
    assert [row["generation_id"] for row in first["items"]] == ["newest"]
    second = service.list_generations(project_id, model="X", tag="hero", limit=1, cursor=first["next_cursor"])
    third = service.list_generations(project_id, model="X", tag="hero", limit=1, cursor=second["next_cursor"])
    assert [row["generation_id"] for row in second["items"] + third["items"]] == ["managed", "runpod"]
    assert third["next_cursor"] is None
    with pytest.raises(InvalidRequestError, match="collection"):
        service.list_generations(project_id, model="Y", tag="hero", cursor=first["next_cursor"])
    with pytest.raises(InvalidRequestError, match="collection"):
        service.list_generations(project_id, cursor=first["next_cursor"])
    unfiltered = service.list_generations(project_id, limit=1)
    assert service.list_generations(project_id, limit=1, cursor=unfiltered["next_cursor"])["items"][0]["generation_id"] == "fal"


@pytest.mark.parametrize("field", ["kind", "model", "target", "tag"])
@pytest.mark.parametrize("value", ["", 1, [], False])
def test_generation_filters_reject_invalid_arguments(fixture_generations, field, value):
    service, project_id = fixture_generations
    with pytest.raises(InvalidRequestError, match=f"{field} must be a non-empty string"):
        service.list_generations(project_id, **{field: value})


def test_generation_filter_http_route_forwards_filters_and_preserves_blank_validation(fixture_generations):
    service, project_id = fixture_generations

    class Handler(RuntimeHandler):
        def _identity(self, scope):
            assert scope == "projects:read"

        def _send(self, status, payload):
            assert status == 200
            return payload

    handler = object.__new__(Handler)
    handler.server = SimpleNamespace(runtime=service)
    handler.command = "GET"
    handler.path = f"/v1/projects/{project_id}/generations?" + urlencode({
        "kind": "video", "model": "X", "target": "runpod", "tag": "hero", "limit": 1,
    })
    assert [row["generation_id"] for row in handler._route()["items"]] == ["runpod"]
    handler.path = f"/v1/projects/{project_id}/generations?tag="
    with pytest.raises(InvalidRequestError, match="tag must be a non-empty string"):
        handler._route()
