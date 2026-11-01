"""Historical render admission through real Agent commits and retained inputs.

A and C are real Agent commits. No render exists before restart; this is not
createTask replay. The selector is request data, never a snapshot or
caller-supplied authority.
"""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from test_canonical_render_admission import _accept_publication, _digest, _publication, _snapshot
from test_canonical_render_admission import (
    canonical_scene as canonical_scene,  # noqa: PLC0414 (shared pytest fixture)
)

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
from runtime_protocol.util import canonical_json, now

pytestmark = pytest.mark.integration


@pytest.fixture
def astrid_provider(astrid_importable, monkeypatch):
    # Provider registration is startup-only: the scene must bootstrap with Agent's real provider.
    import test_canonical_render_admission as scene

    monkeypatch.setattr(scene, "PreparedProvider", lambda: load_timeline_commit_provider("astrid"))


@pytest.fixture
def historical(astrid_provider, canonical_scene, astrid_importable):
    from astrid.sdk.timeline.capture import capture_move
    from astrid.sdk.timeline.commit import bundle_from_document

    f = canonical_scene
    service, project = f["service"], f["project"]
    seed = _publication(f, revision="historical-seed")
    seed["parent_composition"] = {
        "config": {"output": {"fps": 30}, "tracks": [{"id": "audio", "kind": "audio"}]},
        "registry": {"assets": {"music": {"object_id": f["audio"]["object_id"], "type": "audio"}}},
        "clips": [{"id": "music", "clipType": "audio", "asset": "music", "at": 0,
                   "hold": 3, "track": "audio"}],
        "occurrences": [],
    }
    # The fixture's acceptance boundary seeds the parent; measured A/C use commits.
    seed_receipt = _accept_publication(f, seed, idempotency_key="seed")["accepted"]
    service.create_timeline(project, "other", idempotency_key="other-timeline")
    foreign = service.create_project({"slug": "foreign", "name": "Foreign"})["id"]

    def move(on, key):
        head = service.get_project_timeline(project, "main")
        document = service._timeline_commits()[0].revision_closure(project, "main", head["head_revision_id"])
        command = capture_move(bundle_from_document(document), "parent/clip:music", on)
        body = {"api_version": 1, "project_id": project, "timeline_id": "main",
                "base_revision_id": head["head_revision_id"],
                "base_publication_id": head["head_publication_id"], "commands": [command],
                "source": {"via": "python"}}
        result = service.commit_timeline(project, "main", body, idempotency_key=key,
                                         publisher="historical-editor", invocation_path=route_path(project, "main"),
                                         authorize=lambda: None)
        assert result["data"]["status"] == "accepted"
        assert result["receipt"]["result"] == result["data"]
        return result

    accepted_a = move(1, "accepted-A")
    accepted_c = move(2, "accepted-C")
    assert accepted_a["data"]["accepted_revision_id"] != accepted_c["data"]["accepted_revision_id"]
    assert _admissions(service) == ([], [])
    dependency = f["audio"]["object_id"]
    dependency_bytes = service.object(dependency)[1]
    assert _digest(dependency_bytes) == dependency
    root = service.store.root
    service.close()
    restarted = RuntimeService(root)
    case = SimpleNamespace(service=restarted, root=root, project=project, foreign=foreign,
                           a=accepted_a, c=accepted_c, dependency=dependency,
                           dependency_bytes=dependency_bytes, seed=seed_receipt)
    try:
        assert restarted.store.admission_report["ok"]
        assert _admissions(restarted) == ([], [])
        _assert_retained(case)
        yield case
    finally:
        case.service.close()


def _selector(case, accepted=None):
    accepted = accepted or case.a
    return {"project_id": case.project, "timeline_id": "main",
            "revision_id": accepted["data"]["accepted_revision_id"],
            "publication_id": accepted["receipt"]["receipt_id"],
            "content_digest": accepted["data"]["canonical_document"]["parent_revision"]["content_digest"]}


def _request(case, key="first-ever-historical-A"):
    return {"project": case.project, "capability_id": "rendering.render",
            "capability_digest": _digest("rendering.render"), "input_object_ids": [], "idempotency_key": key,
            "spec": {"family": "render", "params": {"timeline_ref": "main", "selector": "rendering.remotion",
                                                       "canonical_revision": _selector(case)}}}


def _admissions(service):
    return tuple([tuple(row) for row in service.store.conn.execute(f"SELECT * FROM {table} ORDER BY id")]
                 for table in ("tasks", "runs"))


def _state(service):
    return (_digest(canonical_json(list(service.store.conn.iterdump()))),
            {str(path.relative_to(service.store.root)): _digest(path.read_bytes())
             for directory in (service.store.cas_root, service.store.staging_root)
             for path in directory.rglob("*") if path.is_file()})


def _assert_retained(case):
    service = case.service
    selected = _selector(case)
    historical = service.get_project_parent_composition_revision(case.project, "main", selected["revision_id"])
    assert historical["payload"] == case.a["data"]["canonical_document"]["parent_revision"]["payload"]
    assert historical["content_digest"] == selected["content_digest"]
    entry = next(item for item in service.list_timeline_commits(case.project, "main", authorize=lambda: None)["items"]
                 if item["publication_id"] == selected["publication_id"])
    assert entry["revision_id"] == selected["revision_id"]
    assert entry["receipt"] == case.a["receipt"]
    head = service.get_project_timeline(case.project, "main")
    assert head["head_revision_id"] == case.c["data"]["accepted_revision_id"]
    assert head["head_publication_id"] == case.c["receipt"]["receipt_id"]


def _assert_admitted_a(case, admitted):
    service = case.service
    selected = _selector(case)
    spec = admitted["task"]["spec"]
    authority = spec["spec"]["inputs"]["timeline_authority"]
    # The accepted revision is selected independently of the current head.
    assert authority["parent_revision_id"] == selected["revision_id"], "historical admission silently selected current C"
    assert authority["parent_content_digest"] == selected["content_digest"]
    assert authority["publication_id"] == selected["publication_id"]
    assert authority["head_event_id"] == case.a["receipt"]["event_ids"][-1]
    ref = spec["spec"]["timeline_snapshot_ref"]
    assert {key: ref[key] for key in ("project_id", "timeline_id", "revision_id", "revision_digest", "source_kind")} == {
        "project_id": case.project, "timeline_id": "main", "revision_id": selected["revision_id"],
        "revision_digest": selected["content_digest"], "source_kind": "revision"}
    _assert_snapshot(case, spec, case.a)
    tasks, runs = _admissions(service)
    assert len(tasks) == len(runs) == 1
    _assert_retained(case)


def _assert_snapshot(case, spec, accepted):
    service = case.service
    authority = spec["spec"]["inputs"]["timeline_authority"]
    ref = spec["spec"]["timeline_snapshot_ref"]
    parent = accepted["data"]["canonical_document"]["parent_revision"]["payload"]
    expected_config = copy.deepcopy(parent["config"])
    expected_config["clips"] = copy.deepcopy(parent["clips"])
    expected = {"config": expected_config, "registry": {"assets": {
        "music": {"type": "audio", "media_id": case.dependency,
                  "content_sha256": case.dependency.removeprefix("sha256:")}}}}
    assert _snapshot(service, spec) == expected
    assert service.object(ref["digest"])[1] == canonical_json(expected).encode()
    assert authority["snapshot_digest"] == ref["digest"] == _digest(canonical_json(expected))
    assert authority["input_object_ids"] == [case.dependency]
    assert authority["dependency_digests"] == [{"dependency_kind": "media", "dependency_id": case.dependency,
                                                 "content_digest": case.dependency}]
    assert spec["input_object_ids"] == [case.dependency, ref["digest"]]
    assert service.object(case.dependency)[1] == case.dependency_bytes


def test_current_c_control_checks_exact_snapshot_and_dependency_bytes(historical):
    case = historical
    request = _request(case, key="current-C-control")
    del request["spec"]["params"]["canonical_revision"]
    request["spec"]["params"]["canonical_head_revision_id"] = case.c["data"]["accepted_revision_id"]
    admitted = case.service.create_task(request)
    _assert_snapshot(case, admitted["task"]["spec"], case.c)
    assert all(len(rows) == 1 for rows in _admissions(case.service))
    _assert_retained(case)


def test_first_render_of_accepted_a_after_c_and_restart(historical):
    case = historical
    request = _request(case)
    assert _admissions(case.service) == ([], [])
    admitted = case.service.create_task(request)
    _assert_admitted_a(case, admitted)
    # Replay is a subsequent control, never the means of obtaining A's snapshot.
    before = _state(case.service)
    assert case.service.create_task(request) == admitted
    assert _state(case.service) == before
    case.service.close()
    case.service = RuntimeService(case.root)
    before = _state(case.service)
    assert case.service.create_task(request) == admitted
    assert _state(case.service) == before


def test_first_historical_admission_over_authenticated_door(historical, tmp_path):
    from runtime_protocol.daemon import RuntimeDaemon
    from runtime_protocol.door import DoorConfig
    from tests.door_helpers import HOSTED, DoorWorld

    case = historical
    case.service.close()
    credential = tmp_path / "product.json"
    daemon = RuntimeDaemon(case.root, support_root=tmp_path / "support",
                           door=DoorConfig(origin=HOSTED, port=0, credential_file=credential)).start()
    world = DoorWorld(tmp_path, daemon, credential)
    case.service = daemon.service
    try:
        world.provision()
        handshake = world.call("/api/runtime/v1/handshake", "POST", body=b"{}",
                               headers={"Content-Type": "application/json"})
        assert handshake.status == 200, handshake.body
        assert "rendering.render.historical_revision.v1" in handshake.json()["capabilities"]
        assert _admissions(case.service) == ([], [])
        request = _request(case)
        key = request.pop("idempotency_key")
        response = world.call("/api/runtime/v1/tasks", "POST", body=json.dumps(request).encode(),
                              headers={"Content-Type": "application/json", "Idempotency-Key": key})
        assert response.status == 201, response.body
        assert response.json()["receipt"]["command_kind"] == "task.create"
        _assert_admitted_a(case, {"task": response.json()["data"]})
    finally:
        world.stop()


@pytest.mark.parametrize("field", ["project_id", "timeline_id", "revision_id", "publication_id", "content_digest"])
def test_selector_mismatch_refuses_without_writes(historical, field):
    case = historical
    request = _request(case)
    other = {**_selector(case, case.c), "project_id": case.foreign, "timeline_id": "other"}
    request["spec"]["params"]["canonical_revision"][field] = other[field]
    before = _state(case.service)
    try:
        with pytest.raises(ConflictError) as refused:
            case.service.create_task(request)
        assert refused.value.details == {"reason": "render_revision_mismatch", "field": field}
    finally:
        assert _state(case.service) == before, "selector refusal must write no database/CAS/staging state"


def test_corrupt_retained_dependency_refuses_without_writes(historical):
    case = historical
    path = case.service.cas.path_for(case.dependency.removeprefix("sha256:"))
    # Damage isolated fixture bytes, never fabricate accepted history or provenance.
    path.write_bytes(b"corrupt-retained-audio")
    before = _state(case.service)
    try:
        with pytest.raises(ConflictError) as refused:
            case.service.create_task(_request(case))
        assert refused.value.details == {"reason": "render_revision_integrity", "dependency_id": case.dependency}
    finally:
        assert _state(case.service) == before, "integrity refusal must write no database/CAS/staging state"


@pytest.mark.parametrize("selector", [None, {}, [], "A", {"revision_id": "A"},
    {"project_id": "P", "timeline_id": "T", "revision_id": "A", "publication_id": "receipt", "content_digest": "sha256:" + "A" * 64},
    {"project_id": "P", "timeline_id": "T", "revision_id": "A", "publication_id": "", "content_digest": "sha256:" + "a" * 64},
    {"project_id": "P", "timeline_id": "T", "revision_id": "A", "publication_id": 42, "content_digest": "sha256:" + "a" * 64},
    {"project_id": "P", "timeline_id": "T", "revision_id": "A", "publication_id": "receipt", "content_digest": "sha256:" + "a" * 64, "extra": True},
])
def test_malformed_selector_refuses_without_writes(historical, selector):
    from runtime_protocol.errors import ValidationError

    case = historical
    request = _request(case)
    request["spec"]["params"]["canonical_revision"] = selector
    before = _state(case.service)
    with pytest.raises(ValidationError):
        case.service.create_task(request)
    assert _state(case.service) == before


@pytest.mark.parametrize("field,value", [("canonical_head_revision_id", "A"),
    ("canonical_occurrence_ids", ["missing"]), ("expected_version", 100000)])
def test_historical_selector_preserves_current_expectations(historical, field, value):
    case = historical
    request = _request(case)
    request["spec"]["params"][field] = case.a["data"]["accepted_revision_id"] if value == "A" else value
    before = _state(case.service)
    with pytest.raises(ConflictError):
        case.service.create_task(request)
    assert _state(case.service) == before
    request["spec"]["params"].pop(field)
    request["spec"]["params"]["canonical_head_revision_id"] = case.c["data"]["accepted_revision_id"]
    _assert_admitted_a(case, case.service.create_task(request))


@pytest.mark.parametrize("changed", ["selector", "output", "null"])
def test_changed_historical_request_after_restart_refuses_without_writes(historical, changed):
    case = historical
    request = _request(case)
    admitted = case.service.create_task(request)
    case.service.close()
    case.service = RuntimeService(case.root)
    changed_request = copy.deepcopy(request)
    params = changed_request["spec"]["params"]
    if changed == "selector":
        params["canonical_revision"] = _selector(case, case.c)
    elif changed == "output":
        params["output_name"] = "changed.mp4"
    else:
        params["opaque"] = None
    before = _state(case.service)
    with pytest.raises(ConflictError):
        case.service.create_task(changed_request)
    assert _state(case.service) == before
    assert case.service.create_task(request) == admitted
    assert _state(case.service) == before


@pytest.mark.parametrize("field", ["revision_id", "publication_id"])
def test_unavailable_scoped_tuple_refuses_without_writes(historical, field):
    case = historical
    request = _request(case)
    request["spec"]["params"]["canonical_revision"][field] = "unavailable"
    before = _state(case.service)
    with pytest.raises(ConflictError) as refused:
        case.service.create_task(request)
    assert refused.value.details == {"reason": "render_revision_mismatch", "field": field}
    assert _state(case.service) == before


@pytest.mark.parametrize("damage", ["missing", "same-size", "custody", "size", "parent", "dependency", "event"])
def test_retained_integrity_is_checked_before_any_publication(historical, damage):
    case = historical
    store = case.service.store
    selected = _selector(case)
    path = case.service.cas.path_for(case.dependency.removeprefix("sha256:"))
    if damage == "missing":
        path.unlink()
    elif damage == "same-size":
        path.write_bytes(b"x" * len(case.dependency_bytes))
    elif damage == "custody":
        store.conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=?",
                           (case.project, case.dependency.removeprefix("sha256:")))
    elif damage == "size":
        store.conn.execute("UPDATE objects SET size=size+1 WHERE digest=?", (case.dependency.removeprefix("sha256:"),))
    elif damage == "parent":
        store.conn.execute("UPDATE parent_composition_revisions SET payload_json='{}' WHERE id=?", (selected["revision_id"],))
    elif damage == "dependency":
        store.conn.execute("DELETE FROM composition_revision_dependencies WHERE parent_revision_id=?", (selected["revision_id"],))
    else:
        store.conn.execute("UPDATE timeline_events SET event_hash=? WHERE id=?", ("0" * 64, case.a["receipt"]["event_ids"][0]))
    # Only corrupt an already accepted isolated fixture; never fabricate acceptance.
    before = _state(case.service)
    with pytest.raises(ConflictError) as refused:
        case.service.create_task(_request(case))
    expected = ({"reason": "render_revision_mismatch", "field": "publication_id"} if damage == "event" else
                {"reason": "render_revision_integrity", "dependency_id": selected["revision_id"] if damage in {"parent", "dependency"} else case.dependency})
    assert refused.value.details == expected
    assert _state(case.service) == before


def test_historical_admission_requires_durable_key(historical):
    from runtime_protocol.errors import ValidationError

    case = historical
    request = _request(case)
    request.pop("idempotency_key")
    before = _state(case.service)
    with pytest.raises(ValidationError):
        case.service.create_task(request)
    assert _state(case.service) == before


def test_capability_refusal_precedes_snapshot_publication(historical):
    case = historical
    request = _request(case)
    request["capability_digest"] = "sha256:" + "f" * 64
    before = _state(case.service)
    with pytest.raises(ConflictError):
        case.service.create_task(request)
    assert _state(case.service) == before


@pytest.fixture
def archive_for_admission():
    """Set only archive state for the admission guard; no archive command exists yet."""
    def archive(service, project, timeline):
        with service.store._mutex, service.store._transaction():
            changed = service.store.conn.execute(
                "UPDATE timelines SET archived_at=? WHERE project_id=? AND id=? AND archived_at IS NULL",
                (now(), project, timeline),
            )
            assert changed.rowcount == 1
    return archive


@pytest.mark.parametrize("admitted", [False, True])
def test_archived_timeline_refuses_first_admission_and_replay(historical, admitted, archive_for_admission):
    case = historical
    request = _request(case)
    if admitted:
        case.service.create_task(request)
    archive_for_admission(case.service, case.project, "main")
    before = _state(case.service)
    with pytest.raises(ConflictError):
        case.service.create_task(request)
    assert _state(case.service) == before


def test_selected_a_does_not_depend_on_current_c_payload(historical):
    case = historical
    case.service.store.conn.execute("UPDATE parent_composition_revisions SET payload_json='{}' WHERE id=?",
                                    (case.c["data"]["accepted_revision_id"],))
    _assert_admitted_a(case, case.service.create_task(_request(case)))


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_historical_replay_never_repairs_a_missing_or_corrupt_snapshot(historical, damage):
    case = historical
    request = _request(case)
    admitted = case.service.create_task(request)
    snapshot_id = admitted["task"]["spec"]["spec"]["timeline_snapshot_ref"]["digest"]
    path = case.service.cas.path_for(snapshot_id.removeprefix("sha256:"))
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"corrupt")
    before = _state(case.service)
    with pytest.raises(ConflictError) as refused:
        case.service.create_task(request)
    assert refused.value.details == {"reason": "render_revision_integrity", "dependency_id": snapshot_id}
    assert _state(case.service) == before


def test_real_retained_legacy_publication_uses_verified_source(historical):
    case = historical
    selected = {"project_id": case.project, "timeline_id": "main",
                "revision_id": case.seed["data"]["accepted_revision_id"],
                "publication_id": case.seed["receipt"]["receipt_id"],
                "content_digest": case.seed["data"]["canonical_document"]["parent_revision"]["content_digest"]}
    request = _request(case)
    request["spec"]["params"]["canonical_revision"] = selected
    admitted = case.service.create_task(request)
    authority = admitted["task"]["spec"]["spec"]["inputs"]["timeline_authority"]
    assert authority["parent_revision_id"] == selected["revision_id"]
    assert authority["parent_content_digest"] == selected["content_digest"]
    assert authority["publication_id"] == selected["publication_id"]
    assert _snapshot(case.service, admitted["task"]["spec"])["config"]["clips"][0]["at"] == 0


@pytest.mark.parametrize("reason", ["readiness", "storage"])
def test_historical_late_admission_refusal_writes_no_snapshot(historical, monkeypatch, reason):
    case = historical
    if reason == "readiness":
        case.service.register_capability({"capability_id": "rendering.render", "definition_digest": _digest("rendering.render"),
                                          "status": "unavailable", "unavailable_reason": "offline"})
    else:
        monkeypatch.setattr(case.service.store, "storage_preflight", lambda *args, **kwargs: {"ok": False})
    before = _state(case.service)
    with pytest.raises(ConflictError):
        case.service.create_task(_request(case), enforce_readiness=True)
    assert _state(case.service) == before


@pytest.mark.parametrize("inputs", [42, [], "invalid"])
def test_historical_inputs_keep_existing_object_validation(historical, inputs):
    from runtime_protocol.errors import ValidationError

    case = historical
    request = _request(case)
    request["spec"]["inputs"] = inputs
    before = _state(case.service)
    with pytest.raises(ValidationError):
        case.service.create_task(request)
    assert _state(case.service) == before
