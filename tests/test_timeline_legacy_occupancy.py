"""Legacy occupancy properties exercised through the authenticated v2 commit path."""
from __future__ import annotations

import base64
import copy
from typing import Any

import pytest
import test_shot_composition_runtime as _shot_composition_runtime
from astrid_runtime_client import ApiError, WorkspaceClient
from test_timeline_commit_acceptance import (
    validate_prepared,
)

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import RetiredRouteError, RuntimeErrorBase
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_store import TimelineCommitStore

_publication = _shot_composition_runtime._publication
_service = _shot_composition_runtime._service
_validation_no_writes = _shot_composition_runtime._validation_no_writes
_restore_provider = _shot_composition_runtime.restore_provider

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


@pytest.fixture
def occupancy_provider(request):
    return request.getfixturevalue("_restore_provider")


def publish(service, project, body, key):
    """The retired route is kept as a direct-authority probe only."""
    return service.publish_parent_composition(project, "main", body, idempotency_key=key)


def _commits(service):
    return TimelineCommitStore(service.store, validate_prepared=validate_prepared)


def _conn(service) -> Any:
    return service.store.conn


def _head(service, project, timeline):
    resource = service.get_project_timeline(project, timeline)
    return {"revision_id": resource["head_revision_id"],
            "publication_id": resource["head_publication_id"]}


def _document(commits, project, timeline, service):
    return commits.revision_closure(project, timeline, _head(service, project, timeline)["revision_id"])


def _body(service, project, timeline, commands, key, *, steps=None, reads=(), label=None) -> Any:
    label = label or key
    steps = steps or [{"id": "edit", "label": label, "intent": "Occupancy proof",
                       "tags": ["occupancy"], "command_ordinals": list(range(len(commands))),
                       "patch": [], "reads": list(reads)}]
    return {
        "api_version": 1, "project_id": project, "timeline_id": timeline,
        "base_revision_id": _head(service, project, timeline)["revision_id"],
        "base_publication_id": _head(service, project, timeline)["publication_id"],
        "commands": copy.deepcopy(commands), "label": label, "steps": copy.deepcopy(steps),
        "merge": "fields", "reads": copy.deepcopy(list(reads)), "dry_run": False,
        "source": {"via": "python", "detail": "legacy occupancy"},
        "rationale": "Preserve legacy occupancy safety through v2",
        "group_id": "legacy-occupancy",
    }


def _submit(service, project, timeline, commands, key, *, steps=None, reads=(), label=None):
    body = _body(service, project, timeline, commands, key, steps=steps, reads=reads, label=label)
    result = service.commit_timeline(
        project, timeline, body, idempotency_key=key, publisher="occupancy-test",
        invocation_path=route_path(project, timeline), authorize=lambda: None,
    )
    return result, body


def _bundle(commits, service, project, timeline):
    from astrid.sdk.timeline.commit import bundle_from_document

    return bundle_from_document(_document(commits, project, timeline, service))


def _prepare_timeline(service, commits, project, timeline):
    row = _conn(service).execute(
        "SELECT revision_id, publication_id FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
        (project, timeline),
    ).fetchone()
    if row is None:
        service.create_timeline(project, timeline, name=timeline, idempotency_key=f"timeline-{timeline}")
        commits.bootstrap(project, timeline, authorize=lambda: None)
    document = _document(commits, project, timeline, service)
    config = document["parent_revision"]["payload"].setdefault("config", {})
    if "output" not in config:
        from astrid.sdk.timeline.native_initialize import capture_initialize

        command = capture_initialize(
            _bundle(commits, service, project, timeline), name=timeline, slug=timeline,
            output={"resolution": "1280x720", "fps": 30, "file": "output.mp4",
                    "background": None, "background_scale": None},
        )
        _submit(service, project, timeline, [command], f"{timeline}-init")
        document = _document(commits, project, timeline, service)
    tracks = document["parent_revision"]["payload"].get("config", {}).get("tracks", [])
    if not any(row.get("id") == "picture" for row in tracks):
        from astrid.sdk.timeline.capture import capture_track_create

        _submit(service, project, timeline, [capture_track_create(
            _bundle(commits, service, project, timeline), "parent",
            {"id": "picture", "kind": "visual", "role": "output"},
        )], f"{timeline}-track")


def _seed_occupied(service, commits, project, timeline, *, archived=False):
    _prepare_timeline(service, commits, project, timeline)
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create

    _submit(service, project, timeline, [capture_occurrence_create(
        _bundle(commits, service, project, timeline), "occ-1", "shot-1",
        name="KEEP OWNER NAME", track="picture", on=0, duration=1,
    )], f"{timeline}-occurrence")
    _submit(service, project, timeline, [capture_track_create(
        _bundle(commits, service, project, timeline), "occurrence:occ-1",
        {"id": "picture", "kind": "visual"},
    )], f"{timeline}-child-track")

    imported = service.import_media(
        project, PNG, media_type="image/png", original_name="occupancy.png",
        actor_id="occupancy-test", idempotency_key=f"{timeline}-media",
    )["data"]
    pin = service.get_project_media_selection(project, {
        "asset": imported["variant_id"], "generation_id": imported["generation_id"],
        "variant_id": imported["variant_id"],
    }, authorize=lambda: None)
    verified = service.get_project_verified_media(project, pin, authorize=lambda: None)
    from astrid.sdk.timeline.native_occurrence_media_commands import (
        capture_occurrence_add_media,
    )

    bundle = _bundle(commits, service, project, timeline)
    media_command = capture_occurrence_add_media(
        bundle, "occurrence:occ-1",
        {"id": "keep-owner-item", "clipType": "image", "asset": pin["asset"],
         "track": "picture", "at": 0, "hold": 1},
        pin, verified_media=[verified],
    )
    shot = next(row for row in _document(commits, project, timeline, service)["shot_revisions"]
                if row["shot_id"] == "shot-1")
    payload = shot["payload"]
    changes = [
        {"op": "set", "ref": "shot:shot-1", "path": ["items"],
         "before": {"state": "present", "value": payload["items"]},
         "value": [{"item_id": "keep-owner-item", "media_id": pin["object_id"],
                    "metadata": {"opaque": None}}]},
        {"op": "set", "ref": "shot:shot-1", "path": ["metadata"],
         "before": {"state": "absent"}, "value": {"opaque": [None]}},
        {"op": "set", "ref": "shot:shot-1", "path": ["archived"],
         "before": {"state": "absent"}, "value": archived},
    ]
    patch = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
             "args": {"changes": changes}}
    reads = [{"kind": "field", "ref": change["ref"], "path": change["path"],
              "state": change["before"]} for change in changes]
    steps = [
        {"id": "media", "label": "Attach occupancy media", "intent": "Attach media",
         "tags": ["occupancy"], "command_ordinals": [0], "patch": [], "reads": []},
        {"id": "shot", "label": "Record occupied shot", "intent": "Preserve shot facts",
         "tags": ["occupancy"], "command_ordinals": [1], "patch": changes, "reads": reads},
    ]
    result, _ = _submit(service, project, timeline, [media_command, patch],
                        f"{timeline}-occupied", steps=steps, reads=reads)
    assert result["data"]["status"] == "accepted"
    return result


def _candidate(service, commits, project, timeline, *, occupied_name="Intruder"):
    _prepare_timeline(service, commits, project, timeline)
    from astrid.sdk.timeline.native_occurrence_create import capture_occurrence_create
    bundle = _bundle(commits, service, project, timeline)
    free = capture_occurrence_create(bundle, "free-occurrence", "free", name="Free",
                                      track="picture", on=0, duration=1)
    from astrid.sdk.timeline.commands import execute

    bundle = execute(bundle, [free]).bundle
    occupied = capture_occurrence_create(bundle, "occupied-occurrence", "shot-1",
                                         name=occupied_name, track="picture", on=1, duration=1)
    steps = [
        {"id": "free", "label": "Free first", "intent": "Exercise ordering", "tags": ["occupancy"],
         "command_ordinals": [0], "patch": [], "reads": []},
        {"id": "occupied", "label": "Occupied second", "intent": "Reject occupied destination",
         "tags": ["occupancy"], "command_ordinals": [1], "patch": [], "reads": []},
    ]
    return _body(service, project, timeline, [free, occupied], "intruder", steps=steps)


def _patch_shot_body(service, commits, project, timeline, *, name, key, retained=False):
    shot = next(row for row in _document(commits, project, timeline, service)["shot_revisions"]
                if row["shot_id"] == "shot-1")
    ref = "shot-revision:" + shot["revision_id"] if retained else "shot:shot-1"
    change = {"op": "set", "ref": ref, "path": ["name"],
              "before": {"state": "present", "value": shot["payload"]["name"]}, "value": name}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    read = {"kind": "field", "ref": change["ref"], "path": change["path"], "state": change["before"]}
    steps = [{"id": "shot", "label": "Update current shot", "intent": "Update closure",
              "tags": ["occupancy"], "command_ordinals": [0], "patch": [change], "reads": [read]}]
    return _body(service, project, timeline, [command], key, steps=steps, reads=[read])


def _patch_shot(service, commits, project, timeline, *, name, key):
    body = _patch_shot_body(service, commits, project, timeline, name=name, key=key)
    return service.commit_timeline(
        project, timeline, body, idempotency_key=key, publisher="occupancy-test",
        invocation_path=route_path(project, timeline), authorize=lambda: None,
    ), body


def _assert_legacy_guard(error, reason="destination_occupied"):
    assert error.value.as_dict() == {
        "code": "conflict", "message": reason,
        "details": {"status": "refused", "reason": reason,
                     "base": None, "current": None, "conflicts": []},
    }


def _historical_shared_request(*, project_id, timeline_id, base_revision_id,
                               base_publication_id, source_ref, source_occurrence_id,
                               occurrence_id, idempotency_key, origin, dry_run=False):
    """Build the registered historical-sharing carrier from an accepted source."""
    source_keys = ("project_id", "timeline_id", "revision_id", "publication_id", "content_digest")
    assert set(source_ref) == set(source_keys)
    assert source_ref["project_id"] == project_id
    assert source_ref["timeline_id"] != timeline_id
    command = {
        "schema_version": 1,
        "op": "occurrence.place-shared",
        "version": "1",
        "select": "parent",
        "args": {
            "occurrence_id": occurrence_id,
            "on": 12,
            "source_ref": copy.deepcopy(source_ref),
            "source_occurrence_id": source_occurrence_id,
        },
        "created": ["occurrence:" + occurrence_id],
    }
    label = "Historical shared placement (" + origin + ")"
    steps = [{
        "id": "historical-share",
        "label": label,
        "intent": "Place authenticated historical occurrence",
        "tags": ["occupancy", "historical"],
        "command_ordinals": [0],
        "patch": [],
        "reads": [],
    }]
    body = {
        "api_version": 1,
        "project_id": project_id,
        "timeline_id": timeline_id,
        "base_revision_id": base_revision_id,
        "base_publication_id": base_publication_id,
        "commands": [command],
        "label": label,
        "steps": steps,
        "merge": "fields",
        "reads": [],
        "dry_run": dry_run,
        "source": {"via": "python", "detail": "legacy occupancy historical preparation"},
        "rationale": "Preserve authenticated historical occurrence occupancy",
        "group_id": "legacy-occupancy",
    }
    # Runtime receives this key in the existing commit header/call argument,
    # not in the C0v2 JSON body.
    return body, idempotency_key


def _accepted_source_ref(result, occurrence_id):
    canonical = result["data"]["canonical_document"]
    parent = canonical["parent_revision"]
    assert parent["revision_id"] == result["data"]["accepted_revision_id"]
    assert any(row["occurrence_id"] == occurrence_id
               for row in parent["payload"]["occurrences"])
    return {
        "project_id": canonical["project_id"],
        "timeline_id": canonical["timeline_id"],
        "revision_id": parent["revision_id"],
        "publication_id": result["receipt"]["receipt_id"],
        "content_digest": parent["content_digest"],
    }


def _seed_collision(service, commits, project, *, foreign=False, archived=False):
    owner = service.create_project({"slug": "private", "name": "Private film"})["id"] if foreign else project
    _seed_occupied(service, commits, owner, "owner", archived=archived)
    _prepare_timeline(service, commits, project, "target")


@pytest.mark.parametrize("foreign", [False, True])
@pytest.mark.parametrize("archived", [False, True])
def test_legacy_publication_refuses_unrelated_destination_before_any_write(
        tmp_path, occupancy_provider, foreign, archived):
    service, project = _service(tmp_path)
    try:
        service.register_timeline_commit_provider(occupancy_provider)
        commits = _commits(service)
        commits.bootstrap(project, "main", authorize=lambda: None)
        _seed_collision(service, commits, project, foreign=foreign, archived=archived)
        body = _candidate(service, commits, project, "target")
        before = tuple(_conn(service).iterdump())
        owner_project = _conn(service).execute(
            "SELECT project_id FROM timelines WHERE id='owner'"
        ).fetchone()[0]
        owner_head = _head(service, owner_project, "owner")
        for _ in range(2):
            with _validation_no_writes(service), pytest.raises(RuntimeErrorBase) as error:
                service.commit_timeline(project, "target", body, idempotency_key="intruder",
                                        publisher="occupancy-test", invocation_path=route_path(project, "target"),
                                        authorize=lambda: None)
            _assert_legacy_guard(error)
            assert _head(service, owner_project, "owner") == owner_head
        assert tuple(_conn(service).iterdump()) == before
        assert _conn(service).execute("SELECT name FROM project_shots WHERE id='shot-1'").fetchone()[0] == "KEEP OWNER NAME"
        assert _conn(service).execute("SELECT COUNT(*) FROM shot_items WHERE id='keep-owner-item'").fetchone()[0] == 1
    finally:
        service.close()


def test_exact_f1_over_http(tmp_path, occupancy_provider):
    service, project = _service(tmp_path)
    service.register_timeline_commit_provider(occupancy_provider)
    commits = _commits(service)
    commits.bootstrap(project, "main", authorize=lambda: None)
    _seed_collision(service, commits, project)
    root = service.store.root
    service.close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support", authoring_profile="astrid").start()
    try:
        commits = _commits(daemon.service)
        body = _candidate(daemon.service, commits, project, "target")
        owner_project = _conn(daemon.service).execute(
            "SELECT project_id FROM timelines WHERE id='owner'"
        ).fetchone()[0]
        target_head = _head(daemon.service, project, "target")
        owner_head = _head(daemon.service, owner_project, "owner")
        before = tuple(_conn(daemon.service).iterdump())
        before_receipts = tuple(_conn(daemon.service).execute(
            "SELECT * FROM command_idempotency WHERE command_kind='timeline.commit' ORDER BY rowid"
        ))
        assert daemon.endpoint is not None
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        with _validation_no_writes(daemon.service), pytest.raises(ApiError) as error:
            client.commit_timeline(project, "target", body, idempotency_key="intruder")
        assert (error.value.status, error.value.code, error.value.message, error.value.details) == (
            409, "conflict", "destination_occupied",
            {"status": "refused", "reason": "destination_occupied",
             "base": None, "current": None, "conflicts": []},
        )
        assert _head(daemon.service, project, "target") == target_head
        assert _head(daemon.service, owner_project, "owner") == owner_head
        assert _conn(daemon.service).execute(
            "SELECT name FROM project_shots WHERE id='shot-1'"
        ).fetchone()[0] == "KEEP OWNER NAME"
        assert _conn(daemon.service).execute(
            "SELECT COUNT(*) FROM shot_items WHERE id='keep-owner-item'"
        ).fetchone()[0] == 1
        assert tuple(_conn(daemon.service).execute(
            "SELECT * FROM command_idempotency WHERE command_kind='timeline.commit' ORDER BY rowid"
        )) == before_receipts
        assert tuple(_conn(daemon.service).iterdump()) == before
    finally:
        daemon.stop()


def test_legacy_publication_route_is_directly_retired_without_write(tmp_path):
    service, project = _service(tmp_path)
    try:
        body = _publication(project)
        before = tuple(_conn(service).iterdump())
        with _validation_no_writes(service), pytest.raises(RetiredRouteError) as error:
            publish(service, project, body, "legacy")
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        assert error.value.details is not None
        assert error.value.details["reason"] == "timeline_commit_required"
        assert tuple(_conn(service).iterdump()) == before
    finally:
        service.close()


@pytest.mark.parametrize("existing", [False, True])
def test_legacy_occupied_destination_without_shot_head_is_not_adopted(
        tmp_path, occupancy_provider, existing):
    service, project = _service(tmp_path)
    try:
        service.register_timeline_commit_provider(occupancy_provider)
        commits = _commits(service)
        commits.bootstrap(project, "main", authorize=lambda: None)
        _seed_occupied(service, commits, project, "main")
        _conn(service).execute("DELETE FROM shot_revision_heads WHERE shot_id='shot-1'")
        body = _patch_shot_body(
            service, commits, project, "main",
            name="Existing head" if existing else "New head", key="missing-head", retained=existing,
        )
        submitted_ref = body["commands"][0]["args"]["changes"][0]["ref"]
        assert submitted_ref == "shot:shot-1" if not existing else submitted_ref.startswith("shot-revision:")
        assert body["commands"][0]["args"]["changes"][0]["value"] == (
            "Existing head" if existing else "New head"
        )
        before = tuple(_conn(service).iterdump())
        head = _head(service, project, "main")
        before_receipts = tuple(_conn(service).execute(
            "SELECT * FROM command_idempotency WHERE command_kind='timeline.commit' ORDER BY rowid"
        ))
        with _validation_no_writes(service), pytest.raises(RuntimeErrorBase) as error:
            service.commit_timeline(project, "main", body, idempotency_key="missing-head",
                                    publisher="occupancy-test", invocation_path=route_path(project, "main"),
                                    authorize=lambda: None)
        _assert_legacy_guard(error)
        assert _head(service, project, "main") == head
        assert _conn(service).execute(
            "SELECT revision_id FROM shot_revision_heads WHERE shot_id='shot-1'"
        ).fetchone() is None
        assert tuple(_conn(service).execute(
            "SELECT * FROM command_idempotency WHERE command_kind='timeline.commit' ORDER BY rowid"
        )) == before_receipts
        assert tuple(_conn(service).iterdump()) == before
    finally:
        service.close()


def test_legacy_current_closure_update_and_exact_retry_precede_live_checks(tmp_path, occupancy_provider):
    service, project = _service(tmp_path)
    try:
        service.register_timeline_commit_provider(occupancy_provider)
        commits = _commits(service)
        commits.bootstrap(project, "main", authorize=lambda: None)
        _seed_occupied(service, commits, project, "main")
        accepted, body = _patch_shot(service, commits, project, "main", name="Updated own shot", key="second")
        assert accepted["data"]["status"] == "accepted"
        assert accepted["data"]["base_revision_id"] == body["base_revision_id"]
        assert accepted["data"]["base_publication_id"] == body["base_publication_id"]
        assert accepted["data"]["previous_revision_id"] == body["base_revision_id"]
        assert accepted["data"]["previous_publication_id"] == body["base_publication_id"]
        assert accepted["data"]["rebased_onto"] is None
        assert accepted["receipt"]["result"] == accepted["data"]
        revision = next(row["revision_id"] for row in accepted["data"]["canonical_document"]["shot_revisions"]
                        if row["shot_id"] == "shot-1")
        assert service.get_project_shot_revision(project, "shot-1", revision)["payload"]["name"] == "Updated own shot"
        newer, _ = _patch_shot(service, commits, project, "main", name="Newest shot", key="third")
        assert newer["data"]["status"] == "accepted"
        _conn(service).execute("UPDATE project_shots SET name='changed after receipt' WHERE id='shot-1'")
        with _validation_no_writes(service):
            assert service.commit_timeline(project, "main", body, idempotency_key="second",
                                           publisher="occupancy-test", invocation_path=route_path(project, "main"),
                                           authorize=lambda: None) == accepted
        with _validation_no_writes(service), pytest.raises(RuntimeErrorBase) as error:
            service.commit_timeline(project, "main", body, idempotency_key="different-key",
                                    publisher="occupancy-test", invocation_path=route_path(project, "main"),
                                    authorize=lambda: None)
        assert error.value.code == "conflict"
        assert error.value.message == "intervening publication changed a guarded address"
        details = error.value.details or {}
        assert details["status"] == "conflict"
        assert details["reason"] == details["code"] == "value_conflict"
        assert details["path"] == ["name"]
        assert details["base"] == {
            "revision_id": body["base_revision_id"],
            "publication_id": body["base_publication_id"],
        }
        assert details["current"] == _head(service, project, "main")
        assert len(details["conflicts"]) == 1
        assert details["conflicts"][0]["kind"] == "value_conflict"
        assert details["conflicts"][0]["path"] == ["name"]
    finally:
        service.close()


@pytest.mark.parametrize("tamper", ["receipt", "occurrence", "digest", "projection", "removed"])
def test_legacy_current_destination_requires_verified_current_closure(tmp_path, occupancy_provider, tamper):
    service, project = _service(tmp_path)
    try:
        service.register_timeline_commit_provider(occupancy_provider)
        commits = _commits(service)
        commits.bootstrap(project, "main", authorize=lambda: None)
        _seed_occupied(service, commits, project, "main")
        if tamper == "receipt":
            body = _patch_shot_body(service, commits, project, "main", name="Unverified", key="tampered")
            _conn(service).execute("DELETE FROM command_idempotency WHERE command_kind='timeline.commit'")
        elif tamper == "occurrence":
            body = _patch_shot_body(service, commits, project, "main", name="Unverified", key="tampered")
            _conn(service).execute("DELETE FROM composition_revision_occurrences WHERE parent_revision_id=(SELECT revision_id FROM parent_composition_heads WHERE timeline_id='main')")
        elif tamper == "digest":
            body = _patch_shot_body(service, commits, project, "main", name="Unverified", key="tampered")
            revision = _head(service, project, "main")["revision_id"]
            _conn(service).execute("UPDATE parent_composition_revisions SET content_digest=? WHERE id=?", ("sha256:" + "0" * 64, revision))
        elif tamper == "projection":
            body = _patch_shot_body(service, commits, project, "main", name="Unverified", key="tampered")
            foreign_project = service.create_project({"slug": "projection-owner", "name": "Projection owner"})["id"]
            _conn(service).execute(
                "UPDATE project_shots SET name='unaccounted', project_id=? WHERE id='shot-1'",
                (foreign_project,),
            )
        else:
            from astrid.sdk.timeline.native_occurrence_delete import (
                capture_occurrence_delete,
            )

            _submit(service, project, "main", [capture_occurrence_delete(
                _bundle(commits, service, project, "main"), "occurrence:occ-1")], "removed")
            body = _candidate(service, commits, project, "main")
        before = tuple(_conn(service).iterdump())
        with _validation_no_writes(service), pytest.raises(RuntimeErrorBase) as error:
            service.commit_timeline(project, "main", body, idempotency_key="tampered",
                                    publisher="occupancy-test", invocation_path=route_path(project, "main"),
                                    authorize=lambda: None)
        if tamper in {"receipt", "occurrence", "projection", "removed"}:
            if tamper in {"receipt", "occurrence", "projection"}:
                if tamper in {"receipt", "occurrence"}:
                    _assert_legacy_guard(error, "history_unavailable")
                else:
                    assert error.value.as_dict() == {
                        "code": "protocol_error", "message": "accepted commit record is corrupt",
                    }
            else:
                assert error.value.code == "conflict"
                assert error.value.message == "created identity was already reserved"
                details = error.value.details or {}
                assert details["status"] == "conflict"
                assert details["reason"] == details["code"] == "identity_collision"
                assert details["path"] == []
                assert len(details["conflicts"]) == 1
                assert details["conflicts"][0]["kind"] == "identity_collision"
        else:
            assert error.value.as_dict() == {
                "code": "validation_error", "message": "revision content digest mismatch",
                "details": {"status": "refused", "reason": "invalid_closure",
                             "base": None, "current": None, "conflicts": []},
            }
        assert tuple(_conn(service).iterdump()) == before
    finally:
        service.close()


@pytest.mark.parametrize("inline", [False, True])
def test_legacy_historical_reuse_keeps_newer_global_shot_head(tmp_path, occupancy_provider, inline):
    service, project = _service(tmp_path)
    try:
        service.register_timeline_commit_provider(occupancy_provider)
        commits = _commits(service)
        commits.bootstrap(project, "main", authorize=lambda: None)
        source_result = _seed_occupied(service, commits, project, "source")
        _prepare_timeline(service, commits, project, "main")
        source_occurrence_id = next(
            row["occurrence_id"]
            for row in source_result["data"]["canonical_document"]["parent_revision"]["payload"]["occurrences"]
            if row["shot_id"] == "shot-1"
        )
        source_ref = _accepted_source_ref(source_result, source_occurrence_id)
        if not inline:
            _prepare_timeline(service, commits, project, "reference-source")
            reference_body, reference_key = _historical_shared_request(
                project_id=project,
                timeline_id="reference-source",
                base_revision_id=_head(service, project, "reference-source")["revision_id"],
                base_publication_id=_head(service, project, "reference-source")["publication_id"],
                source_ref=source_ref,
                source_occurrence_id=source_occurrence_id,
                occurrence_id="reference-one",
                idempotency_key="reference-source",
                origin="reference",
            )
            reference_result = service.commit_timeline(
                project, "reference-source", reference_body,
                idempotency_key=reference_key, publisher="occupancy-test",
                invocation_path=route_path(project, "reference-source"), authorize=lambda: None,
            )
            assert reference_result["data"]["status"] == "accepted"
            source_occurrence_id = "reference-one"
            source_ref = _accepted_source_ref(reference_result, source_occurrence_id)
            source_document = reference_result["data"]["canonical_document"]
        else:
            source_document = _document(commits, project, "source", service)
        assert source_ref["timeline_id"] == ("source" if inline else "reference-source")
        source_timeline = source_ref["timeline_id"]
        assert source_document is not None
        source_shots = copy.deepcopy(source_document["shot_revisions"])
        source_internals = copy.deepcopy(source_document["internal_timeline_revisions"])
        shot = source_shots[0]
        internal = source_internals[0]
        newer_tracks = copy.deepcopy(internal["payload"]["tracks"])
        assert newer_tracks
        newer_tracks[0]["label"] = "newer global track"
        changes = [
            {"op": "set", "ref": "shot:shot-1", "path": ["name"],
             "before": {"state": "present", "value": shot["payload"]["name"]},
             "value": "NEWER GLOBAL SHOT"},
            {"op": "set", "ref": "internal-revision:" + internal["revision_id"], "path": ["tracks"],
             "before": {"state": "present", "value": internal["payload"]["tracks"]},
             "value": newer_tracks},
        ]
        reads = [{"kind": "field", "ref": change["ref"], "path": change["path"],
                  "state": change["before"]} for change in changes]
        newer_command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                         "args": {"changes": changes}}
        newer_steps = [{"id": "newer", "label": "Update current closure", "intent": "Update closure",
                        "tags": ["occupancy"], "command_ordinals": [0], "patch": changes, "reads": reads}]
        newer_body = _body(service, project, source_timeline, [newer_command], "newer",
                           steps=newer_steps, reads=reads, label="newer")
        newer = service.commit_timeline(
            project, source_timeline, newer_body, idempotency_key="newer", publisher="occupancy-test",
            invocation_path=route_path(project, source_timeline), authorize=lambda: None,
        )
        assert newer["data"]["status"] == "accepted"
        assert newer["receipt"]["result"] == newer["data"]
        newer_receipt = newer["receipt"]["receipt_id"]
        assert newer_body["base_revision_id"] == source_ref["revision_id"]
        assert newer_body["base_publication_id"] == source_ref["publication_id"]
        assert _head(service, project, source_timeline) == {
            "revision_id": newer["data"]["accepted_revision_id"],
            "publication_id": newer_receipt,
        }
        assert newer["data"]["accepted_revision_id"] != source_ref["revision_id"]
        assert newer_receipt != source_ref["publication_id"]
        newer_head = _conn(service).execute(
            "SELECT revision_id FROM shot_revision_heads WHERE shot_id='shot-1'"
        ).fetchone()[0]
        assert newer_head != source_shots[0]["revision_id"]
        source_after_newer = _document(commits, project, source_timeline, service)
        assert source_after_newer is not None
        assert source_after_newer == newer["data"]["canonical_document"]
        assert source_after_newer["shot_revisions"][0]["revision_id"] == newer_head
        assert source_after_newer["shot_revisions"][0]["payload"]["name"] == "NEWER GLOBAL SHOT"
        assert source_after_newer["internal_timeline_revisions"][0]["revision_id"] != internal["revision_id"]
        assert source_after_newer["internal_timeline_revisions"][0]["payload"]["tracks"] == newer_tracks
        assert commits.revision_closure(project, source_timeline, source_ref["revision_id"]) == source_document
        body, key = _historical_shared_request(
            project_id=project,
            timeline_id="main",
            base_revision_id=_head(service, project, "main")["revision_id"],
            base_publication_id=_head(service, project, "main")["publication_id"],
            source_ref=source_ref,
            source_occurrence_id=source_occurrence_id,
            occurrence_id="historical-copy",
            idempotency_key="historical-reuse-" + str(inline),
            origin="inline" if inline else "reference",
        )
        before = _document(commits, project, "main", service)
        assert before is not None
        assert before["parent_revision"]["payload"]["occurrences"] == []
        before_destination = tuple(_conn(service).iterdump())
        physical_counts = tuple(_conn(service).execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                                for table in ("shot_revisions", "internal_timeline_revisions"))
        preview = service.commit_timeline(
            project, "main", {**body, "dry_run": True}, idempotency_key=key + "-preview",
            publisher="occupancy-test", invocation_path=route_path(project, "main"), authorize=lambda: None,
        )
        assert preview["receipt"] is None
        assert preview["data"]["would_status"] == "accepted"
        assert tuple(_conn(service).iterdump()) == before_destination
        result = service.commit_timeline(
            project, "main", body, idempotency_key=key, publisher="occupancy-test",
            invocation_path=route_path(project, "main"), authorize=lambda: None,
        )
        assert result["data"]["status"] == "accepted"
        assert result["receipt"]["result"] == result["data"]
        assert _document(commits, project, source_timeline, service) == source_after_newer
        assert commits.revision_closure(project, source_timeline, source_ref["revision_id"]) == source_document
        assert tuple(_conn(service).execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                     for table in ("shot_revisions", "internal_timeline_revisions")) == physical_counts
        assert _conn(service).execute("SELECT revision_id FROM shot_revision_heads WHERE shot_id='shot-1'").fetchone()[0] == newer_head
        assert result["data"]["canonical_document"]["shot_revisions"] == source_shots
        assert result["data"]["canonical_document"]["internal_timeline_revisions"] == source_internals
        assert result["data"]["canonical_document"]["shot_revisions"][0]["shot_id"] == "shot-1"
        after = result["data"]["canonical_document"]
        row = next(row for row in after["parent_revision"]["payload"]["occurrences"]
                   if row["occurrence_id"] == "historical-copy")
        assert row["shot_id"] == "shot-1"
        assert row["shot_revision_id"] == source_shots[0]["revision_id"]
        assert row["placement"]["start_ms"] == 12000
        assert after == _document(commits, project, "main", service)
        assert result["data"]["steps"][0]["patch"]
        assert body["commands"][0]["select"] == "parent"
        assert body["commands"][0]["args"]["source_ref"] == source_ref
        assert body["commands"][0]["args"]["source_occurrence_id"] == source_occurrence_id
        assert body["commands"][0]["created"] == ["occurrence:historical-copy"]
        assert body["steps"][0]["patch"] == body["steps"][0]["reads"] == body["reads"] == []
        assert body["dry_run"] is False
        history = commits.history_entry(project, "main", result["receipt"]["receipt_id"])
        assert history["records"]["commands"][0]["created"] == [
            {"ref": "occurrence:historical-copy", "kind": "occurrence", "owner": "parent"},
        ]
        # Preserve the original whole/per-step inverse acceptance after the real
        # historical placement; inverse is not a source-creation shortcut.
        inverse = {"schema_version": 1, "op": "timeline.inverse", "version": "1", "select": None,
                   "args": {"publications": [newer_receipt]}}
        if inline:
            inverse["args"]["steps"] = {newer_receipt: ["newer"]}
        inverse_result, inverse_body = _submit(
            service, project, source_timeline, [inverse], "historical-inverse-" + str(inline),
            label="historical inline" if inline else "historical referenced",
        )
        assert inverse_result["data"]["status"] == "accepted"
        assert inverse_result["receipt"]["result"] == inverse_result["data"]
        assert _conn(service).execute("SELECT revision_id FROM shot_revision_heads WHERE shot_id='shot-1'").fetchone()[0] == newer_head
        assert inverse_result["data"]["canonical_document"]["shot_revisions"] == source_shots
        assert inverse_result["data"]["canonical_document"]["internal_timeline_revisions"] == source_internals
        assert inverse_result["data"]["canonical_document"]["shot_revisions"][0]["shot_id"] == "shot-1"
        assert inverse_result["data"]["steps"][0]["patch"]
        if inline:
            assert inverse_body["commands"][0]["args"]["steps"] == {newer_receipt: ["newer"]}
        else:
            assert "steps" not in inverse_body["commands"][0]["args"]
        assert commits.history_entry(project, source_timeline, inverse_result["receipt"]["receipt_id"])["records"]["undo_steps"] == (
            {newer_receipt: ["newer"]} if inline else None
        )
        source_row = service.get_project_timeline(project, source_ref["timeline_id"])
        service.archive_timeline(
            source_ref["timeline_id"], {"expected_version": source_row["version"]},
            idempotency_key="archive-" + source_ref["timeline_id"],
        )
        with _validation_no_writes(service):
            assert service.commit_timeline(
                project, "main", body, idempotency_key=key, publisher="occupancy-test",
                invocation_path=route_path(project, "main"), authorize=lambda: None,
            ) == result
    finally:
        service.close()
