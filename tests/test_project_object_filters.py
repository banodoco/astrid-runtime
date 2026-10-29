from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest
import yaml
from jsonschema import Draft202012Validator

from runtime_protocol.errors import InvalidRequestError
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.service import RuntimeService, _page_cursor
from runtime_protocol.store import RealmStore


STAMP = "2026-10-01T00:00:00Z"


def _object(service, project_id, index, *, stamp=STAMP, relation="managed"):
    digest = f"{index:064x}"
    service.store.record_object(digest, index, "video/mp4", f"{index}.mp4")
    service.store.add_object_ref(project_id, digest, relation=relation)
    service.store.conn.execute("UPDATE objects SET created_at=? WHERE digest=?", (stamp, digest))
    return digest


def _generation(service, project_id, generation_id, metadata, *digests, stamp=STAMP):
    encoded = metadata if isinstance(metadata, str) else json.dumps(metadata)
    service.store.conn.execute(
        "INSERT INTO generations(id, project_id, metadata_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (generation_id, project_id, encoded, stamp, stamp),
    )
    for index, digest in enumerate(digests):
        service.store.conn.execute(
            "INSERT INTO generation_variants(id, generation_id, object_id, created_at) VALUES (?, ?, ?, ?)",
            (f"{generation_id}-{index}", generation_id, digest, stamp),
        )


@pytest.fixture
def catalog(tmp_path):
    RealmStore.initialize(tmp_path).close()
    service = RuntimeService(tmp_path)
    project = service.create_project({"name": "Media", "slug": "media"}, idempotency_key="media")
    foreign = service.create_project({"name": "Other", "slug": "other"}, idempotency_key="other")
    digests = {}
    for index, name, gen in (
        (3, "managed", {"kind": "image", "model": "X", "target": "managed", "tags": ["hero", "local"]}),
        (1, "runpod", {"kind": "video", "model": "X", "target": "runpod", "tags": ["hero", "remote"]}),
        (2, "fal", {"kind": "video", "model": "Y", "target": "fal", "tags": ["remote"]}),
    ):
        digests[name] = _object(service, project["id"], index)
        # Generation time must not order the object results.
        _generation(service, project["id"], name, {"gen": gen}, digests[name],
                    stamp=f"2026-10-0{index + 1}T00:00:00Z")
    try:
        yield service, project["id"], foreign["id"], digests
    finally:
        service.close()


def _ids(page):
    return [row["object_id"].removeprefix("sha256:") for row in page["items"]]


@pytest.mark.parametrize(("filters", "names"), [
    ({"kind": "image"}, ["managed"]),
    ({"kind": "video"}, ["runpod", "fal"]),
    ({"model": "X"}, ["runpod", "managed"]),
    ({"target": "runpod"}, ["runpod"]),
    ({"tag": "hero"}, ["runpod", "managed"]),
    ({"model": "X", "target": "runpod"}, ["runpod"]),
    ({"kind": "video", "model": "X", "target": "runpod", "tag": "hero"}, ["runpod"]),
    ({"model": "missing"}, []),
    ({"kind": "Video"}, []),
    ({"model": "x"}, []),
    ({"target": "RunPod"}, []),
    ({"tag": "her"}, []),
    ({"tag": "Hero"}, []),
])
def test_object_filters_return_unchanged_object_rows(catalog, filters, names):
    service, project_id, _, digests = catalog
    original = {row["object_id"]: row for row in service.list_project_objects(project_id)["items"]}
    page = service.list_project_objects(project_id, **filters)
    assert page == {
        "items": [original["sha256:" + digests[name]] for name in names], "next_cursor": None,
    }
    schema = json.loads((Path(__file__).parents[1] / "contract/schemas/managed-object.json").read_text())
    for row in page["items"]:
        Draft202012Validator(schema).validate(row)


def test_object_filters_ignore_missing_and_malformed_generation_metadata(catalog):
    service, project_id, _, digests = catalog
    malformed = [
        {}, {"gen": None}, {"gen": "bad"}, {"gen": []},
        {"gen": {"kind": [], "model": {}, "target": True, "tags": "hero"}},
        {"gen": {"kind": 7, "model": False, "target": ["runpod"], "tags": {"hero": True}}},
        {"gen": {"tags": [1, None, {"hero": True}, ["hero"]]}},
        None, [], 3, "{broken-json",
    ]
    for index, metadata in enumerate(malformed, start=10):
        digest = _object(service, project_id, index)
        _generation(service, project_id, f"bad-{index}", metadata, digest)
    for filters, names in (
        ({"kind": "video"}, ["runpod", "fal"]),
        ({"model": "X"}, ["runpod", "managed"]),
        ({"target": "runpod"}, ["runpod"]),
        ({"tag": "hero"}, ["runpod", "managed"]),
        ({"model": "{}"}, []),
        ({"tag": '{"hero":true}'}, []),
    ):
        assert _ids(service.list_project_objects(project_id, **filters)) == [digests[name] for name in names]
    # Object rows still decode normally even if an associated generation is corrupt.
    assert len(service.list_project_objects(project_id)["items"]) == 3 + len(malformed)
    mixed = _object(service, project_id, 30)
    _generation(service, project_id, "mixed", {"gen": {
        "model": "X", "target": [], "tags": [1, None, {"hero": True}, "hero"],
    }}, mixed)
    assert mixed in _ids(service.list_project_objects(project_id, model="X", tag="hero"))
    assert mixed not in _ids(service.list_project_objects(project_id, model="X", target="runpod"))


def test_object_filters_require_one_matching_generation_in_the_selected_project(catalog):
    service, project_id, foreign_id, digests = catalog
    shared = _object(service, project_id, 10)
    _generation(service, project_id, "split-model", {"gen": {"model": "X", "target": "managed", "tags": ["hero"]}}, shared)
    _generation(service, project_id, "split-target", {"gen": {"model": "Y", "target": "runpod"}}, shared)
    _generation(service, foreign_id, "foreign-shared", {"gen": {"model": "X", "target": "runpod"}}, shared)
    foreign_object = _object(service, foreign_id, 11)
    _generation(service, project_id, "unowned", {"gen": {"model": "X", "target": "runpod"}}, foreign_object)
    assert _ids(service.list_project_objects(project_id, model="X", target="runpod")) == [digests["runpod"]]
    assert _ids(service.list_project_objects(project_id, target="runpod", tag="hero")) == [digests["runpod"]]


def test_object_filters_include_all_primary_variants_without_duplicate_objects(catalog):
    service, project_id, _, digests = catalog
    sibling = _object(service, project_id, 4)
    # Repeated objects in one generation and across generations must not consume page slots.
    _generation(service, project_id, "duplicates", {"gen": {"model": "X", "target": "runpod"}},
                digests["runpod"], digests["runpod"], sibling, None)
    _generation(service, project_id, "also-matching", {"gen": {"model": "X", "target": "runpod"}}, sibling)
    service.store.conn.execute("UPDATE generation_variants SET variant_type='edited' WHERE id='duplicates-2'")
    service.store.conn.execute("UPDATE generations SET status='custom' WHERE id='duplicates'")
    service.store.add_object_ref(project_id, sibling, relation="promoted")
    page = service.list_project_objects(project_id, model="X", target="runpod", limit=1)
    assert _ids(page) == [digests["runpod"]]
    second = service.list_project_objects(project_id, model="X", target="runpod", cursor=page["next_cursor"], limit=1)
    assert _ids(second) == [sibling]
    assert second["items"][0]["relation"] == "managed"
    assert second["next_cursor"] is None
    promoted = _object(service, project_id, 5, relation="promoted")
    _generation(service, project_id, "promoted", {"gen": {"model": "X"}}, promoted)
    assert service.list_project_objects(project_id, model="X")["items"][-1]["relation"] == "promoted"


def test_object_filters_do_not_infer_associations_from_thumbnails_or_variant_metadata(catalog):
    service, project_id, _, digests = catalog
    thumbnail = _object(service, project_id, 10)
    variant_only = _object(service, project_id, 11)
    unassociated = _object(service, project_id, 12)
    service.store.conn.execute(
        "UPDATE generation_variants SET thumbnail_object_id=?, thumbnail_source_object_id=?, thumbnail_recipe_version=1 WHERE id='runpod-0'",
        (thumbnail, digests["runpod"]),
    )
    _generation(service, project_id, "variant-only", {}, variant_only)
    service.store.conn.execute("UPDATE generation_variants SET metadata_json=? WHERE id='variant-only-0'",
                               (json.dumps({"gen": {"model": "X", "target": "runpod"}}),))
    _generation(service, project_id, "no-variants", {"gen": {"model": "X", "target": "runpod"}})
    assert _ids(service.list_project_objects(project_id, model="X", target="runpod")) == [digests["runpod"]]
    assert {thumbnail, variant_only, unassociated}.issubset(_ids(service.list_project_objects(project_id)))


def test_object_filter_values_are_exact_bound_strings(catalog):
    service, project_id, _, _ = catalog
    model, tag = "FLUX1\\ae_'%?.safetensors", "' OR 1=1 --"
    literal = _object(service, project_id, 10)
    _generation(service, project_id, "literal", {"gen": {"model": model, "tags": [tag]}}, literal)
    assert _ids(service.list_project_objects(project_id, model=model, tag=tag)) == [literal]
    assert service.list_project_objects(project_id, model="%", tag=tag)["items"] == []


def test_object_filter_pages_follow_object_keys_and_preserve_legacy_unfiltered_cursors(catalog):
    service, project_id, _, digests = catalog
    earlier = _object(service, project_id, 10, stamp="2026-09-01T00:00:00Z")
    later = _object(service, project_id, 11, stamp="2026-11-01T00:00:00Z")
    _generation(service, project_id, "other-time", {"gen": {"model": "X", "tags": ["hero"]}}, later, earlier)
    expected = [earlier, digests["runpod"], digests["managed"], later]
    first = service.list_project_objects(project_id, model="X", tag="hero", limit=1)
    second = service.list_project_objects("media", tag="hero", model="X", limit=2, cursor=first["next_cursor"])
    third = service.list_project_objects(project_id, model="X", tag="hero", limit=1, cursor=second["next_cursor"])
    assert _ids(first) + _ids(second) + _ids(third) == expected
    assert third["next_cursor"] is None
    full = service.list_project_objects(project_id)
    boundary = full["items"][0]
    legacy = _page_cursor(f"objects:{project_id}", (boundary["created_at"], boundary["digest"].removeprefix("sha256:")))
    assert service.list_project_objects(project_id, cursor=legacy, kind=None, model=None, target=None, tag=None) == {
        "items": full["items"][1:], "next_cursor": None,
    }


@pytest.mark.parametrize("changed", [
    {"kind": "image"}, {"model": "Y"}, {"target": "fal"}, {"tag": "remote"},
    {"kind": None}, {"model": None}, {"target": None}, {"tag": None},
])
def test_object_cursor_rejects_changed_or_removed_filters(catalog, changed):
    service, project_id, _, digests = catalog
    filters = {"kind": "video", "model": "X", "target": "runpod", "tag": "hero"}
    _generation(service, project_id, "two-matches", {"gen": {
        "kind": "video", "model": "X", "target": "runpod", "tags": ["hero"],
    }}, digests["fal"])
    first = service.list_project_objects(project_id, **filters, limit=1)
    assert first["next_cursor"]
    with pytest.raises(InvalidRequestError, match="collection") as error:
        service.list_project_objects(project_id, **(filters | changed), cursor=first["next_cursor"])
    assert error.value.status == 400


def test_object_cursors_reject_added_filters_other_projects_and_other_collections(catalog):
    service, project_id, foreign_id, _ = catalog
    unfiltered = service.list_project_objects(project_id, limit=1)["next_cursor"]
    filtered = service.list_project_objects(project_id, model="X", limit=1)["next_cursor"]
    generation = service.list_generations(project_id, model="X", limit=1)["next_cursor"]
    for selected_project, filters, cursor in (
        (project_id, {"model": "X"}, unfiltered),
        (project_id, {}, filtered),
        (project_id, {"model": "X", "tag": "hero"}, filtered),
        (foreign_id, {"model": "X"}, filtered),
        (project_id, {"model": "X"}, generation),
    ):
        with pytest.raises(InvalidRequestError, match="collection"):
            service.list_project_objects(selected_project, **filters, cursor=cursor)


@pytest.mark.parametrize("field", ["kind", "model", "target", "tag"])
@pytest.mark.parametrize("value", ["", 1, [], False])
def test_object_filters_reject_invalid_service_arguments(catalog, field, value):
    service, project_id, _, _ = catalog
    with pytest.raises(InvalidRequestError, match=f"{field} must be a non-empty string") as error:
        service.list_project_objects(project_id, **{field: value})
    assert error.value.status == 400


def test_object_filter_http_route_forwards_filters_and_object_cursors(catalog):
    service, project_id, _, digests = catalog

    class Handler(RuntimeHandler):
        def _identity(self, scope):
            assert scope == "objects:read"

        def _send(self, status, payload):
            assert status == 200
            return payload

    handler = object.__new__(Handler)
    handler.server = SimpleNamespace(runtime=service)
    handler.command = "GET"

    def request(**query):
        handler.path = f"/v1/projects/{project_id}/objects?" + urlencode(query)
        return handler._route()

    assert _ids(request(kind="video", model="X", target="runpod", tag="hero")) == [digests["runpod"]]
    assert request(cursor="", limit="") == service.list_project_objects(project_id)
    first = request(model="X", limit=1)
    assert _ids(request(model="X", cursor=first["next_cursor"], limit=2)) == [digests["managed"]]
    with pytest.raises(InvalidRequestError, match="collection"):
        request(model="Y", cursor=first["next_cursor"])
    for field in ("kind", "model", "target", "tag"):
        with pytest.raises(InvalidRequestError, match=f"{field} must be a non-empty string"):
            request(**{field: ""})


def test_object_filter_openapi_retains_page_schema_and_declares_exact_filters():
    document = yaml.safe_load((Path(__file__).parents[1] / "contract/openapi/workspace-v1.yaml").read_text())
    operation = document["paths"]["/v1/projects/{project_id}/objects"]["get"]
    filters = {parameter["name"]: parameter for parameter in operation["parameters"] if "name" in parameter}
    assert set(filters) == {"kind", "model", "target", "tag"}
    for parameter in filters.values():
        assert parameter["in"] == "query" and parameter["required"] is False
        assert parameter["schema"] == {"type": "string", "minLength": 1}
    assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ManagedObjectPage",
    }
