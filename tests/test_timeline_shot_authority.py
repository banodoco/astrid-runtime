"""M2 shot authority: only commit acceptance may change canonical shot state.

PreparedProvider is a host persistence fixture, not evidence of Agent semantics.
"""
from __future__ import annotations

import copy
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, NotFoundError, RetiredRouteError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_port import digest, route_path
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from runtime_protocol.util import now
from test_timeline_commit_acceptance import context, prepared as detached_prepared, validate_prepared
from test_timeline_commit_port import PreparedProvider


def seed(service):
    project = service.create_project({"slug": "shot-authority", "name": "Shot authority"})["id"]
    service.test_project = project
    media = service.ingest(project, b"immutable shot candidate", media_type="application/octet-stream",
                           idempotency_key="media")["data"]["object_id"]

    def candidate(ctx):
        value = detached_prepared(commits, ctx, revision="candidate-" + ctx["idempotency_key"])
        document = value["canonical_document"]
        operation = ctx["request"]["commands"][0]["op"]
        if operation == "fixture.seed-shots":
            for shot_id in ("placed", "unused"):
                internal = {"timeline_id": f"shot:{shot_id}", "revision_id": f"internal-{shot_id}",
                            "payload": {"clips": [], "tracks": [], "opaque": {"keep": None}}}
                internal["content_digest"] = digest(internal["payload"])
                payload = {"name": shot_id, "metadata": {"opaque": None},
                           "internal_timeline_revision_id": internal["revision_id"],
                           "items": [{"item_id": f"{shot_id}-{status}", "media_id": media,
                                      "metadata": {"role": "primary_visual", "status": status}}
                                     for status in ("primary", "candidate")]}
                shot = {"shot_id": shot_id, "revision_id": f"shot-{shot_id}", "payload": payload,
                        "internal_timeline_revision_id": internal["revision_id"], "content_digest": digest(payload)}
                document["shot_revisions"].append(shot)
                document["internal_timeline_revisions"].append(internal)
                document["parent_revision"]["payload"]["occurrences"].append({
                    "occurrence_id": f"occ-{shot_id}", "shot_id": shot_id, "shot_revision_id": shot["revision_id"],
                    "placement": {"start_ms": 0}, "duration_ms": 1000, "source_offset": 0,
                    "speed": {"numerator": 1, "denominator": 1}, "track": "picture", "transform": {},
                    "gain": 1, "muted": False, "provenance": {},
                })
            document["dependency_manifest"]["media"] = [{"media_id": media, "content_digest": media}]
        elif operation == "fixture.detach-shot":
            document["shot_revisions"] = [s for s in document["shot_revisions"] if s["shot_id"] == "placed"]
            document["internal_timeline_revisions"] = [i for i in document["internal_timeline_revisions"]
                                                       if i["timeline_id"] == "shot:placed"]
            document["parent_revision"]["payload"]["occurrences"] = [
                o for o in document["parent_revision"]["payload"]["occurrences"] if o["shot_id"] == "placed"]
        if operation in ("fixture.seed-shots", "fixture.detach-shot"):
            document["dependency_manifest"]["shots"] = [
                {k: s[k] for k in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}
                for s in document["shot_revisions"]]
            document["dependency_manifest"]["internal_timelines"] = [
                {k: i[k] for k in ("timeline_id", "revision_id", "content_digest")}
                for i in document["internal_timeline_revisions"]]
            document["parent_revision"]["content_digest"] = digest(document["parent_revision"]["payload"])
            value["document_digest"] = digest(document)
        return value

    service.register_timeline_commit_provider(PreparedProvider())
    created = service.create_timeline(project, "main", idempotency_key="bootstrap")
    commits = TimelineCommitStore(service.store, validate_prepared=validate_prepared)
    for operation, key in (("fixture.seed-shots", "seed-shots"), ("fixture.detach-shot", "detach-shot")):
        ctx = context(service, project, commits.head(project, "main"), key, op=operation)
        result = commits.accept(ctx, candidate(ctx), authorize=lambda: None)
        assert result["data"]["status"] == "accepted"
    assert service.get_project_shot(project, "unused")["items"]
    return project, media, created


@pytest.fixture
def authority(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        project, media, created = seed(service)
        yield service, project, media, created
    finally:
        service.close()


@pytest.fixture
def http_authority(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        project, media, _ = seed(daemon.service)
        yield daemon, project, media
    finally:
        daemon.stop()


def snapshot(service):
    with service.store._mutex:
        database = tuple(service.store.conn.iterdump())
        cas = {str(p.relative_to(service.store.cas_root)): p.read_bytes()
               for p in service.store.cas_root.rglob("*") if p.is_file()}
    return database, cas


OPERATIONS = (
    "project-create", "project-update", "project-archive", "project-recover",
    "item-add", "item-remove", "item-reorder",
    "timeline-create", "timeline-update", "timeline-archive", "timeline-recover",
)


def invocation(operation, project, media, shot):
    base = f"/v1/projects/{project}"
    path = f"{base}/shots/{shot}"
    body = {"expected_version": 1}
    if operation == "project-create":
        return "POST", f"{base}/shots", {"shot_id": shot, "name": "Changed"}, "create_project_shot", (project,), {}
    if operation.startswith("project-"):
        action = operation.removeprefix("project-")
        body["name"] = "Changed"
        return ("PATCH" if action == "update" else "POST", path + ("" if action == "update" else f"/{action}"),
                body, "update_project_shot", (project, shot), {} if action == "update" else {"archived": action == "archive"})
    if operation == "item-add":
        return "POST", path + "/items", {"item_id": "added", "media_id": media}, "add_shot_item", (project, shot), {}
    if operation == "item-remove":
        return "DELETE", path + f"/items/{shot}-primary", body, "remove_shot_item", (project, shot, f"{shot}-primary"), {}
    if operation == "item-reorder":
        body["item_ids"] = [f"{shot}-candidate", f"{shot}-primary"]
        return "POST", path + "/reorder", body, "reorder_shot_items", (project, shot), {}
    if operation == "item-promote":
        return ("POST", path + "/promote-candidate", {"candidate_item_id": f"{shot}-candidate", "expected_head_seq": 1},
                "promote_project_shot_candidate", (project, shot), {})
    if operation.startswith("binding-"):
        binding_id = RuntimeService._text_binding_id(project, shot, "prompt", "hero")
        body = {"expected_head": 0, "text": "new bytes must never enter CAS", "shot_id": shot, "kind": "prompt", "slot": "hero"}
        if operation == "binding-set":
            return "POST", base + "/shot-text-bindings", body, "set_project_shot_text_binding", (project,), {}
        body = {"binding_id": binding_id, "expected_head": 1, "text": body["text"]}
        suffix, method = "", "set_project_shot_text_binding"
        if operation == "binding-rebind":
            body = {"binding_id": binding_id, "expected_head": 1, "media_id": media}
            suffix, method = "/rebind", "rebind_project_shot_text_binding"
        return "POST", f"{base}/shot-text-bindings/{binding_id}{suffix}", body, method, (project,), {}
    if operation == "timeline-create":
        return ("POST", "/v1/timelines/main/shots", {"shot_id": shot, "start_ms": 0, "duration_ms": 1000},
                "create_shot", ("main",), {})
    action = operation.removeprefix("timeline-")
    return ("PATCH" if action == "update" else "POST", f"/v1/shots/{shot}" + ("" if action == "update" else f"/{action}"),
            {**body, "start_ms": 100, "duration_ms": 1000}, f"{action}_shot", (shot,), {})


@pytest.mark.parametrize(
    ("operation", "shot"),
    [(operation, "placed") for operation in OPERATIONS if not operation.startswith("timeline-")]
    + [(operation, shot) for operation in OPERATIONS if operation.startswith("timeline-") for shot in ("placed", "unused", "fresh")],
)
def test_service_shot_writes_refuse_before_replay_or_writes(authority, monkeypatch, operation, shot):
    service, project, media, _ = authority
    _, _, body, method, args, kwargs = invocation(operation, project, media, shot)
    before = snapshot(service)
    if operation.startswith("timeline-"):
        monkeypatch.setattr(service, "_command_replay", lambda *a, **kw: pytest.fail("retired writer consulted old receipt"))
    # A real existing acceptance identity must not resurrect a retired writer.
    for key in ("new-denied", "seed-shots"):
        with pytest.raises(RetiredRouteError) as error:
            getattr(service, method)(*args, copy.deepcopy(body), idempotency_key=key, **kwargs)
        assert (error.value.status, error.value.code) == (410, "retired_route")
        assert snapshot(service) == before


@pytest.mark.parametrize("shot", ["placed", "unused", "fresh"])
def test_direct_store_promotion_stale_version_rolls_back_item_updates(authority, shot):
    service, _, _, _ = authority
    before = snapshot(service)
    from runtime_protocol.errors import ConflictError
    with pytest.raises(ConflictError), service.store._transaction():
        service.store.promote_shot_items(shot, 99, [(f"{shot}-candidate", {"status": "primary"})], timestamp="changed")
    assert snapshot(service) == before


@pytest.mark.parametrize("operation", ["project-update", "item-reorder"])
def test_service_same_value_shot_writes_are_also_retired(authority, operation):
    service, project, media, _ = authority
    _, _, body, method, args, kwargs = invocation(operation, project, media, "placed")
    if operation == "project-update":
        body["name"] = "placed"
    else:
        body["item_ids"] = ["placed-primary", "placed-candidate"]
    before = snapshot(service)
    with pytest.raises(RetiredRouteError):
        getattr(service, method)(*args, body, idempotency_key="same-value", **kwargs)
    assert snapshot(service) == before


@pytest.mark.parametrize(("shot", "error"), [("placed", ConflictError), ("unused", ConflictError), ("fresh", NotFoundError)])
def test_direct_text_binding_is_limited_to_unplaced_project_shots(authority, shot, error):
    service, project, _, _ = authority
    before = snapshot(service)
    with pytest.raises(error):
        service.set_project_shot_text_binding(
            project,
            {"shot_id": shot, "kind": "prompt", "slot": "hero", "text": "must not write", "expected_head": 0},
            idempotency_key="text-scope-" + shot,
        )
    assert snapshot(service) == before


def http_request(daemon, method, path, body, token):
    raw = json.dumps(body).encode()
    value = Request(daemon.endpoint + path, raw, method=method,
                    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Idempotency-Key": "seed-shots"})
    try:
        with urlopen(value, timeout=10) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


@pytest.mark.parametrize(
    ("operation", "shot"),
    [(operation, "placed") for operation in OPERATIONS if not operation.startswith("timeline-")]
    + [(operation, shot) for operation in OPERATIONS if operation.startswith("timeline-") for shot in ("placed", "unused", "fresh")],
)
def test_authenticated_http_shot_writes_are_retired(http_authority, operation, shot):
    daemon, project, media = http_authority
    method, path, body, *_ = invocation(operation, project, media, shot)
    before = snapshot(daemon.service)
    status, payload = http_request(daemon, method, path, body, daemon.token)
    assert status == 410, payload
    assert payload["code"] == "retired_route"
    assert snapshot(daemon.service) == before


@pytest.mark.parametrize("operation", (*OPERATIONS, "item-promote"))
@pytest.mark.parametrize("shot", ["placed", "unused", "fresh"])
def test_http_auth_and_scope_checks_precede_retirement(http_authority, operation, shot):
    daemon, project, media = http_authority
    token, _ = daemon.credentials.provision("reader", ["projects:read"])
    method, path, body, *_ = invocation(operation, project, media, shot)
    before = snapshot(daemon.service)
    for credential in ("invalid", token):
        status, payload = http_request(daemon, method, path, body, credential)
        assert status == 401, payload
        assert payload["code"] == "unauthorized"
        assert snapshot(daemon.service) == before


@pytest.mark.parametrize("operation", [op for op in (*OPERATIONS, "item-promote") if not op.startswith("timeline-")])
def test_http_foreign_project_never_mutates_shot(http_authority, operation):
    daemon, _, media = http_authority
    project = daemon.service.create_project({"slug": "other", "name": "Other"})["id"]
    method, path, body, *_ = invocation(operation, project, media, "placed")
    before = snapshot(daemon.service)
    status, payload = http_request(daemon, method, path, body, daemon.token)
    assert status == 404, payload
    assert snapshot(daemon.service) == before


def test_http_text_binding_auth_and_film_scope_checks_precede_writes(http_authority):
    daemon, project, media = http_authority
    method, path, body, *_ = invocation("binding-set", project, media, "unused")
    before = snapshot(daemon.service)
    reader, _ = daemon.credentials.provision("text-reader", ["projects:read"])
    for credential in ("invalid", reader):
        status, payload = http_request(daemon, method, path, body, credential)
        assert status == 401, payload
        assert payload["code"] == "unauthorized"
        assert snapshot(daemon.service) == before
    status, payload = http_request(daemon, method, path, body, daemon.token)
    assert status == 409, payload
    assert payload["details"]["reason"] == "shot_in_film_history"
    assert snapshot(daemon.service) == before


def test_empty_bootstrap_commit_and_guarded_restore_remain_functional(authority, monkeypatch):
    service, project, _, created = authority
    import runtime_protocol.service as service_module
    monkeypatch.setattr(service_module, "evaluate_closure", lambda *a, **kw: pytest.fail("scene evaluation in save"))
    assert created["data"]["head_publication_id"]
    assert service.create_timeline(project, "main", idempotency_key="bootstrap") == created
    source = created["data"]["head_revision_id"]
    current = service.get_project_timeline(project, "main")
    body = {"expected_head": current["head_revision_id"], "expected_publication_id": current["head_publication_id"]}
    path = route_path(project, "main", f"composition-revisions/{source}/restore")
    restored = service.restore_project_parent_composition_revision(project, "main", source, body,
        idempotency_key="restore", publisher="editor", invocation_path=path, authorize=lambda: None)
    assert restored["data"]["accepted_revision_id"] == source
    assert restored["data"]["commands"][0]["op"] == "timeline.restore"
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        service.restore_project_parent_composition_revision(project, "main", source, body,
            idempotency_key="stale-restore", publisher="editor", invocation_path=path, authorize=lambda: None)
    assert snapshot(service) == before
    assert service.store.integrity_report()["ok"]


@pytest.fixture(params=["service", "http"])
def historical_binding(request, tmp_path):
    from precut_realm_fixture import load_precut_realm_fixture, readonly_tree_digest

    captured = load_precut_realm_fixture(tmp_path)
    source_before = readonly_tree_digest(captured.backup_root)
    root = captured.copy_roots[1]
    daemon = None
    if request.param == "http":
        daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
        service = daemon.service
    else:
        service = RuntimeService(root)
    try:
        binding = service.get_project_shot_text_binding(captured.pins["project_id"], captured.pins["text_binding_id"])
        assert binding["kind"] == "transcript" and binding["head"] == 1
        # The committed archive is intentionally historical. Keep the copied
        # receipt inside the bounded replay window so this test remains a
        # positive exact-retry/no-write check as wall-clock time advances.
        with service.store._mutex, service.store._transaction():
            service.store.conn.execute(
                "UPDATE command_idempotency SET created_at=? "
                "WHERE command_kind='shot.text_binding.set' AND aggregate_id=?",
                (now(), binding["binding_id"]),
            )
        yield service, daemon, binding
        assert readonly_tree_digest(captured.backup_root) == source_before
    finally:
        if daemon:
            daemon.stop()
        else:
            service.close()


@pytest.mark.parametrize("operation", ["set", "set-by-id", "rebind", "exact-set-retry"])
def test_historical_text_binding_cannot_be_changed_or_replayed(historical_binding, operation):
    service, daemon, binding = historical_binding
    project = binding["project_id"]
    prefix = f"/v1/projects/{project}/shot-text-bindings"
    text = service.object(binding["media_id"])[1].decode()
    method, path = "set_project_shot_text_binding", prefix
    key = "historical-binding-denied"
    body = {"shot_id": binding["shot_id"], "kind": binding["kind"], "text": text,
            "expected_head": binding["head"]}
    if operation == "exact-set-retry":
        body["expected_head"] = 0
        receipt = service.store.conn.execute(
            "SELECT idempotency_key, request_hash FROM command_idempotency "
            "WHERE command_kind='shot.text_binding.set' AND aggregate_id=?", (binding["binding_id"],),
        ).fetchone()
        identity = {"command_kind": "shot.text_binding.set", "project_id": project,
                    "binding_id": binding["binding_id"], "event_stream_id": binding["event_stream_id"],
                    "expected_head": body["expected_head"], "desired_content_hash": binding["content_hash"]}
        assert digest(identity).removeprefix("sha256:") == receipt["request_hash"]
        key = receipt["idempotency_key"]
    elif operation == "set-by-id":
        path += f"/{binding['binding_id']}"
        body = {"binding_id": binding["binding_id"], "expected_head": binding["head"], "text": text}
    elif operation == "rebind":
        path += f"/{binding['binding_id']}/rebind"
        method = "rebind_project_shot_text_binding"
        body = {"binding_id": binding["binding_id"], "expected_head": binding["head"], "media_id": binding["media_id"]}
    before, changes = snapshot(service), service.store.conn.total_changes
    if operation == "exact-set-retry":
        if daemon:
            from http_helpers import Api
            replay = Api(daemon.endpoint, daemon.token).request("POST", path, body, headers={"Idempotency-Key": key})
        else:
            replay = getattr(service, method)(project, body, idempotency_key=key)
        assert replay["receipt"]["command_kind"] == "shot.text_binding.set"
        assert snapshot(service) == before
        assert service.store.conn.total_changes == changes
        return
    if daemon:
        from http_helpers import Api
        with pytest.raises(RuntimeError) as error:
            Api(daemon.endpoint, daemon.token).request("POST", path, body, headers={"Idempotency-Key": key})
        assert error.value.status == 409 and error.value.detail["code"] == "conflict"
    else:
        with pytest.raises(ConflictError):
            getattr(service, method)(project, body, idempotency_key=key)
    assert snapshot(service) == before
    assert service.store.conn.total_changes == changes
    assert service.get_project_shot_text_binding(project, binding["binding_id"]) == binding
