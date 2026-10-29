"""Real temporary Runtime admissions; no provider or engine execution."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from astrid_runtime_client.generated import WorkspaceClient
from runtime_protocol.auth import CredentialStore
from runtime_protocol.errors import AuthorizationError, ConflictError, InvalidRequestError, ValidationError
from runtime_protocol.server import RuntimeHandler
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore, retire_terminal_specs
from tests.test_generation_publish_v1_settlement import _effect
from tests.test_runtime_child_delegation import (
    admit_stage, publication_parent, publication_policy, runtime,
)


QUERY = {"kind": "root_generation", "order": "admitted_desc"}


@pytest.fixture
def project_runtime(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"name": "Selection", "slug": "selection"})["id"]
    try:
        yield service, project
    finally:
        service.close()


def _admit(service, project, *, generation=True, **fields):
    return service.create_task({
        "project": project, "capability_id": "test.same.capability", "spec": {},
        **({"settlement_effect": _effect(project)} if generation else {}), **fields,
    })["task"]["id"]


def _facts(service, task_id):
    return json.loads(service.store.conn.execute(
        "SELECT payload_json FROM events WHERE task_id=? AND kind='task.admitted'", (task_id,),
    ).fetchone()[0])["classification"]


def _legacy(service, task_id):
    # Model a pre-extension immutable admission, never an application mutation.
    service.store.conn.execute(
        "UPDATE events SET payload_json=? WHERE task_id=? AND kind='task.admitted'",
        (json.dumps({"capability": "test.same.capability"}), task_id),
    )


def _terminal(service, task_id, state):
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat(timespec="milliseconds")
    service.store.conn.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=?", (state, old, task_id))
    service.store.conn.execute(
        "UPDATE runs SET status=?, updated_at=? WHERE id=(SELECT run_id FROM tasks WHERE id=?)",
        (state, old, task_id),
    )
    service.store.conn.execute(
        "UPDATE command_idempotency SET created_at=? WHERE command_kind='task.create' "
        "AND primary_stream_id=(SELECT run_id FROM tasks WHERE id=?)", (old, task_id),
    )


def _ids(page):
    return [item["task_id"] for item in page["items"]]


def test_admission_facts_are_minimal_validated_and_cannot_be_display_claims(project_runtime):
    service, project = project_runtime
    generation = _admit(service, project)
    ordinary = _admit(service, project, generation=False,
        generation_intent={"is_generation": True}, spec={"classification": {
            "is_generation": True, "is_root": False}, "generation_publication": True})
    assert _facts(service, generation) == {"version": 1, "is_root": True, "is_generation": True}
    assert _facts(service, ordinary) == {"version": 1, "is_root": True, "is_generation": False}
    assert _ids(service.list_project_tasks(project, **QUERY)) == [generation]
    before = service.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    with pytest.raises(ValidationError, match="delegation fields"):
        _admit(service, project, spec={"delegated_parent": {"parent_task_id": generation}})
    invalid = _effect(project)
    invalid["payload"]["modality"] = "unknown"
    with pytest.raises(ValidationError):
        _admit(service, project, settlement_effect=invalid)
    assert service.store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before


@pytest.mark.parametrize("state,public", [("failed", "failed"), ("cancelled", "cancelled"), ("completed", "succeeded")])
def test_terminal_roots_survive_real_spec_retirement(project_runtime, state, public):
    service, project = project_runtime
    _admit(service, project)
    newest = _admit(service, project)
    original = _facts(service, newest)
    _terminal(service, newest, state)
    assert retire_terminal_specs(service.store.conn)["retired_tasks"] == 1
    assert service.store.get_task(newest)["task"]["spec_retired"] is True
    page = service.list_project_tasks(project, limit=1, **QUERY)
    assert _ids(page) == [newest]
    assert page["items"][0]["state"] == public
    assert _facts(service, newest) == original


def test_retained_legacy_envelopes_prove_generation_and_ordinary(project_runtime):
    service, project = project_runtime
    generation = _admit(service, project)
    ordinary = _admit(service, project, generation=False)
    _legacy(service, generation)
    _legacy(service, ordinary)
    assert _ids(service.list_project_tasks(project, **QUERY)) == [generation]


@pytest.mark.parametrize("generation,state", [(True, "failed"), (True, "cancelled"), (False, "failed")])
def test_newer_retired_legacy_candidate_is_structured_barrier(project_runtime, generation, state):
    service, project = project_runtime
    _admit(service, project)
    unknown = _admit(service, project, generation=generation)
    _legacy(service, unknown)
    _terminal(service, unknown, state)
    retire_terminal_specs(service.store.conn)
    with pytest.raises(ConflictError) as error:
        service.list_project_tasks(project, limit=1, **QUERY)
    assert error.value.code == "conflict" and error.value.status == 409
    assert error.value.details == {
        "reason": "root_generation_selection_barrier", "project_id": project,
        "task_id": unknown, "admission_sequence": service.store.conn.execute(
            "SELECT id FROM events WHERE task_id=? AND kind='task.admitted'", (unknown,),
        ).fetchone()[0], "missing": "validated_root_generation_classification",
    }


def test_older_unknown_yields_proven_prefix_then_cursor_barrier(project_runtime):
    service, project = project_runtime
    _admit(service, project)
    unknown = _admit(service, project)
    _legacy(service, unknown)
    _terminal(service, unknown, "failed")
    retire_terminal_specs(service.store.conn)
    newest = _admit(service, project)
    for limit in (1, 20):
        page = service.list_project_tasks(project, limit=limit, **QUERY)
        assert _ids(page) == [newest] and page["next_cursor"]
        with pytest.raises(ConflictError) as error:
            service.list_project_tasks(project, cursor=page["next_cursor"], limit=limit, **QUERY)
        assert error.value.details["task_id"] == unknown


def test_retry_timestamp_ties_numeric_admission_pagination_and_project_scope(project_runtime):
    service, project = project_runtime
    roots = [_admit(service, project) for _ in range(12)]
    foreign = service.create_project({"name": "Foreign", "slug": "foreign"})["id"]
    foreign_task = _admit(service, foreign)
    _legacy(service, foreign_task)
    _terminal(service, foreign_task, "cancelled")
    retire_terminal_specs(service.store.conn)
    service.store.conn.execute("UPDATE tasks SET created_at='2000-01-01T00:00:00Z'")
    service.store.conn.execute("UPDATE events SET created_at='2000-01-01T00:00:00Z'")
    _terminal(service, roots[0], "failed")
    admission_before = service.store.conn.execute(
        "SELECT id,payload_json FROM events WHERE task_id=? AND kind='task.admitted'", (roots[0],),
    ).fetchone()
    service.retry_task(roots[0], idempotency_key="retry-old-root")
    assert service.store.get_task(roots[0])["task"]["created_at"] != "2000-01-01T00:00:00Z"
    assert tuple(service.store.conn.execute(
        "SELECT id,payload_json FROM events WHERE task_id=? AND kind='task.admitted'", (roots[0],),
    ).fetchone()) == tuple(admission_before)
    cursor, seen = None, []
    while True:
        page = service.list_project_tasks(project, cursor=cursor, limit=2, **QUERY)
        seen.extend(_ids(page))
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == list(reversed(roots))
    assert len(set(seen)) == 12


def test_signed_cursor_rejects_tampering_and_collection_reuse(project_runtime):
    service, project = project_runtime
    for _ in range(3):
        _admit(service, project)
    foreign = service.create_project({"name": "Foreign", "slug": "foreign"})["id"]
    cursor = service.list_project_tasks(project, limit=1, **QUERY)["next_cursor"]
    with pytest.raises(InvalidRequestError):
        service.list_project_tasks(foreign, cursor=cursor, **QUERY)
    with pytest.raises(InvalidRequestError):
        service.list_project_tasks(project, cursor=cursor)
    with pytest.raises(InvalidRequestError):
        service.list_project_tasks(project, cursor=cursor[:-1] + ("0" if cursor[-1] != "0" else "1"), **QUERY)
    default = service.list_project_tasks(project, limit=1)["next_cursor"]
    with pytest.raises(InvalidRequestError):
        service.list_project_tasks(project, cursor=default, **QUERY)
    for bad in ({"kind": "root_generation"}, {"order": "admitted_desc"}, {"kind": "", "order": "admitted_desc"}):
        with pytest.raises(InvalidRequestError):
            service.list_project_tasks(project, **bad)


def test_possible_root_without_admission_anchor_fails_closed(project_runtime):
    service, project = project_runtime
    missing = _admit(service, project)
    service.store.conn.execute("DELETE FROM events WHERE task_id=?", (missing,))
    _admit(service, project)
    with pytest.raises(ConflictError) as error:
        service.list_project_tasks(project, **QUERY)
    assert error.value.details["task_id"] == missing
    assert error.value.details["admission_sequence"] is None
    assert error.value.details["missing"] == "original_admission_sequence"


@pytest.mark.parametrize("legacy", [False, True])
def test_validated_parent_declaration_is_root_and_child_is_never_root(runtime, legacy):
    service, project = runtime
    policy = publication_policy(project)
    parent = publication_parent(runtime, policy=policy)
    child = admit_stage(service, parent, policy, "raw", {})["task"]["id"]
    assert _facts(service, parent["task_id"]) == {"version": 1, "is_root": True, "is_generation": True}
    assert _facts(service, child) == {"version": 1, "is_root": False, "is_generation": True}
    if legacy:
        _legacy(service, parent["task_id"])
        _legacy(service, child)
    else:
        _terminal(service, child, "cancelled")
        retire_terminal_specs(service.store.conn)
        assert service.store.get_task(child)["task"]["spec_retired"]
    assert _ids(service.list_project_tasks(project, **QUERY)) == [parent["task_id"]]


def test_legacy_creation_effect_validation_is_not_weakened_or_newly_required(project_runtime):
    service, project = project_runtime
    source = service.ingest(project, b"source", idempotency_key="source")["data"]["digest"]
    effect = {"effect_type": "generation.create_with_variant", "target_id": project,
        "payload": {"generation_type": "image", "metadata": {}, "variant_type": "original",
                    "output_name": "output", "output_ordinal": 0, "primary_policy": "preserve"}}
    valid = _admit(service, project, settlement_effect=effect, input_object_ids=[source])
    assert _facts(service, valid)["is_generation"] is True
    _legacy(service, valid)
    assert _ids(service.list_project_tasks(project, **QUERY)) == [valid]
    effect["payload"]["metadata"] = {"params": "invalid"}
    invalid = _admit(service, project, settlement_effect=effect, input_object_ids=[source])
    assert _facts(service, invalid) == {"version": 1, "is_root": True}
    with pytest.raises(ConflictError) as error:
        service.list_project_tasks(project, **QUERY)
    assert error.value.details["task_id"] == invalid


def test_retired_legacy_child_can_use_retained_containment_authority(runtime):
    service, project = runtime
    policy = publication_policy(project)
    parent = publication_parent(runtime, policy=policy)
    child = admit_stage(service, parent, policy, "raw", {})["task"]["id"]
    service.store.contain_delegated_children(
        parent["task_id"], attempt_id=parent["attempt_id"], reason="fixture_parent_ended",
    )
    assert service.store.conn.execute(
        "SELECT 1 FROM events WHERE task_id=? AND kind='task.parent_contained'", (child,),
    ).fetchone()
    _legacy(service, child)
    _terminal(service, child, "cancelled")
    assert retire_terminal_specs(service.store.conn)["retired_tasks"] == 1
    assert _ids(service.list_project_tasks(project, **QUERY)) == [parent["task_id"]]


@pytest.mark.parametrize("payload", ["{broken", '{"classification":{"version":true,"is_root":true,"is_generation":false}}'])
def test_malformed_retired_admission_facts_fail_closed(project_runtime, payload):
    service, project = project_runtime
    _admit(service, project)
    unknown = _admit(service, project)
    _terminal(service, unknown, "failed")
    retire_terminal_specs(service.store.conn)
    service.store.conn.execute(
        "UPDATE events SET payload_json=? WHERE task_id=? AND kind='task.admitted'", (payload, unknown),
    )
    with pytest.raises(ConflictError) as error:
        service.list_project_tasks(project, **QUERY)
    assert error.value.details["reason"] == "root_generation_selection_barrier"
    assert error.value.details["task_id"] == unknown


@pytest.mark.parametrize("kind", [[], {}])
def test_malformed_unvalidated_effect_type_cannot_certify_ordinary(project_runtime, kind):
    service, project = project_runtime
    _admit(service, project)
    unknown = _admit(service, project, settlement_effect={"effect_type": kind})
    assert _facts(service, unknown) == {"version": 1, "is_root": True}
    with pytest.raises(ConflictError) as error:
        service.list_project_tasks(project, **QUERY)
    assert error.value.details["task_id"] == unknown


def test_http_client_query_forwards_typed_filters_and_requires_task_read(project_runtime):
    service, project = project_runtime
    root = _admit(service, project)
    _admit(service, project, generation=False)

    class FixtureCredentials(CredentialStore):
        def __init__(self):
            self.scopes = ["tasks:read"]

        def load(self, token):
            assert token == "fixture-only"
            return {"actor": "fixture", "scopes": self.scopes}

    class Handler(RuntimeHandler):
        def _send(self, status, payload):
            assert status == 200
            return payload

    handler = object.__new__(Handler)
    credentials = FixtureCredentials()
    handler.server = SimpleNamespace(runtime=service, credentials=credentials)
    handler.headers = {"Authorization": "Bearer fixture-only"}
    handler.command = "GET"

    def transport(method, path, headers, body):
        assert method == "GET" and body is None
        handler.path = path
        return 200, {}, json.dumps(handler._route()).encode()

    client = WorkspaceClient("http://runtime", transport=transport)
    items, cursor = client.list_project_tasks(project, limit=1, **QUERY)
    assert [item.task_id for item in items] == [root] and cursor is None
    credentials.scopes = ["projects:read"]
    with pytest.raises(AuthorizationError) as error:
        client.list_project_tasks(project, **QUERY)
    assert error.value.details == {"scope": "tasks:read"}
    credentials.scopes = ["tasks:read"]
    handler.path = f"/v1/projects/{project}/tasks?kind=&order=admitted_desc"
    with pytest.raises(InvalidRequestError):
        handler._route()
