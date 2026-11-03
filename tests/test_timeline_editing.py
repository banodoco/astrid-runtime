"""Owner/tab fencing and real Runtime/Agent publication interleavings."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event, RLock

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import AuthorizationError, RuntimeErrorBase, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_port import RequestCommitPort, route_path
from runtime_protocol.timeline_editing import TimelineEditingLeases
from test_shot_composition_runtime import restore_provider as real_provider  # noqa: F401
from test_timeline_commit_acceptance import accept, context, counts, prepared, realm  # noqa: F401


def test_owner_tabs_expiry_cap_and_ordered_release():
    clock = [100.0]
    leases = TimelineEditingLeases(RLock(), clock=lambda: clock[0])
    def update(actor, tab, sequence, **kwargs):
        return leases.update("p", "t", actor, {"tab_session_id": tab, "sequence": sequence}, **kwargs)
    assert leases.update("p", "t", "alice", {"tab_session_id": "one", "sequence": 1, "ttl_seconds": 100})["expires_in_seconds"] == 10
    update("alice", "two", 1)
    update("bob", "one", 1)
    update("alice", "one", 3, release=True)
    assert not update("alice", "one", 2)["active"]  # delayed renewal is fenced
    assert leases.live("p", "t")
    update("alice", "two", 2, release=True)
    assert leases.live("p", "t")  # Bob still owns an independent lease
    assert not leases.live("other-project", "t")
    assert not leases.live("p", "other-timeline")
    clock[0] = 109.0
    assert update("bob", "one", 1)["expires_in_seconds"] == 1  # replay doesn't extend TTL
    clock[0] = 110.0
    assert not leases.live("p", "t")
    assert not update("bob", "one", 1)["active"]  # expired replay doesn't resurrect
    assert update("alice", "one", 4)["active"]  # new edit uses a later sequence
    assert update("alice", "one", 3, release=True)["active"]  # stale release cannot clear it


@pytest.mark.parametrize("body", [
    {}, {"tab_session_id": "", "sequence": 1}, {"tab_session_id": "x", "sequence": True},
    {"tab_session_id": "x", "sequence": 0}, {"tab_session_id": "x", "sequence": 2**53},
    {"tab_session_id": "x", "sequence": 1, "ttl_seconds": 0},
    {"tab_session_id": "x", "sequence": 1, "ttl_seconds": float("nan")},
    {"tab_session_id": "x", "sequence": 1, "actor": "forged"},
])
def test_invalid_lease_never_gates(body):
    leases = TimelineEditingLeases(RLock())
    with pytest.raises(ValidationError):
        leases.update("p", "t", "actor", body)
    assert not leases.live("p", "t")


def test_active_credential_is_scoped_and_revoked_with_lease():
    clock = [1.0]
    leases = TimelineEditingLeases(RLock(), clock=lambda: clock[0])
    body = {"tab_session_id": "opaque-app-tab", "sequence": 1}
    leases.update("p", "t", "alice", body)
    assert leases.owns_live("p", "t", "alice", "opaque-app-tab")
    for project, timeline, actor, tab in (("other", "t", "alice", "opaque-app-tab"),
            ("p", "other", "alice", "opaque-app-tab"), ("p", "t", "bob", "opaque-app-tab"),
            ("p", "t", "alice", "invented"), ("p", "t", "alice", None)):
        assert not leases.owns_live(project, timeline, actor, tab)
    leases.update("p", "t", "alice", {**body, "sequence": 2}, release=True)
    assert not leases.owns_live("p", "t", "alice", "opaque-app-tab")
    leases.update("p", "t", "alice", {**body, "sequence": 3})
    clock[0] = 11.0
    assert not leases.owns_live("p", "t", "alice", "opaque-app-tab")


def test_direct_acceptance_checks_lease_after_replay(realm):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head)
    candidate = prepared(commits, ctx)
    before = counts(service)
    commits.editing.update(project, "main", "user", {"tab_session_id": "tab", "sequence": 1})
    with pytest.raises(CommitRejected) as caught:
        accept(commits, ctx, candidate)
    details = caught.value.failure["details"]
    assert details["status"] == "refused" and details["reason"] == "user_editing"
    assert details["base"] == details["current"] == head
    assert details["conflicts"] == [] and details["hint"]
    assert counts(service) == before
    commits.editing.update(project, "main", "user", {"tab_session_id": "tab", "sequence": 2}, release=True)
    result = accept(commits, ctx, candidate)
    after = counts(service)
    commits.editing.update(project, "main", "user", {"tab_session_id": "tab", "sequence": 3})
    assert accept(commits, ctx, candidate) == result  # durable receipt wins even under a new lease
    assert counts(service) == after


@pytest.fixture
def editing_runtime(tmp_path, real_provider):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    runtime.register_timeline_commit_provider(real_provider)
    project = runtime.create_project({"slug": "editing", "name": "Editing"})["id"]
    runtime.create_timeline(project, "main", idempotency_key="create")
    runtime.test_project = project
    try:
        yield runtime
    finally:
        runtime.close()


def lease(runtime, sequence, *, release=False, tab="tab", actor="user", **extra):
    return runtime.update_timeline_editing(
        runtime.test_project, "main", {"tab_session_id": tab, "sequence": sequence, **extra},
        publisher=actor, authorize=lambda: {"actor": actor}, release=release,
    )["data"]


def patch(runtime, value, *, field="title", via="python"):
    head = runtime.get_project_timeline(runtime.test_project, "main")
    return {"api_version": 1, "project_id": runtime.test_project, "timeline_id": "main",
            "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
            "source": {"via": via}, "label": "Set " + field, "merge": "fields", "reads": [],
            "commands": [{"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                          "args": {"changes": [{"op": "set", "ref": "parent", "path": ["config", field],
                                                "before": {"state": "absent"}, "value": value}]}}]}


def submit(runtime, body, key, *, editing_session=None):
    return runtime.commit_timeline(runtime.test_project, "main", body, idempotency_key=key,
        publisher="shared-product", authorize=lambda: {"actor": "shared-product"},
        invocation_path=route_path(runtime.test_project, "main"),
        **({"editing_session": editing_session} if editing_session is not None else {}))


@pytest.mark.integration
def test_source_via_app_is_cooperative_and_caller_spoofable(editing_runtime):
    runtime = editing_runtime
    app_claim = patch(runtime, "claimed-app", via="app")
    lease(runtime, 1)
    # Attribution alone, an invented credential, and another actor's live tab
    # all remain behind the live-user gate. Refusal is not terminally cached.
    for credential in (None, "invented-tab", "tab"):
        with pytest.raises(RuntimeErrorBase) as caught:
            submit(runtime, app_claim, "spoofed-app-source", editing_session=credential)
        assert caught.value.status == 409
        assert caught.value.details["reason"] == "user_editing"
    lease(runtime, 1, tab="own-app-tab", actor="shared-product")
    accepted = submit(runtime, app_claim, "spoofed-app-source", editing_session="own-app-tab")
    assert accepted["data"]["status"] == "accepted"
    document = accepted["data"]["canonical_document"]
    assert document["parent_revision"]["payload"]["config"]["title"] == "claimed-app"
    lease(runtime, 2, tab="own-app-tab", actor="shared-product", release=True)
    # Replay precedes gating even after the authority for a new write is gone.
    assert submit(runtime, app_claim, "spoofed-app-source") == accepted


@pytest.mark.integration
def test_app_preview_retry_and_saved_user_conflict(editing_runtime):
    runtime = editing_runtime
    agent = patch(runtime, "agent")
    compatible = patch(runtime, "subtitle", field="subtitle")
    user = patch(runtime, "user", via="app")
    other_app = patch(runtime, "other-user", via="app")
    before = counts(runtime)
    assert lease(runtime, 1)["active"]
    assert lease(runtime, 1, tab="app", actor="shared-product")["active"]
    with pytest.raises(RuntimeErrorBase) as caught:
        submit(runtime, agent, "same-flight")
    assert caught.value.status == 409
    assert caught.value.details["status"] == "refused"
    assert caught.value.details["reason"] == "user_editing"
    assert caught.value.details["conflicts"] == []
    assert caught.value.details["base"] == caught.value.details["current"]
    assert counts(runtime) == before
    preview = submit(runtime, {**agent, "dry_run": True}, "preview")
    assert preview["data"]["status"] == "preview"
    assert counts(runtime) == before
    saved = submit(runtime, user, "user-save", editing_session="app")
    assert saved["data"]["status"] == "accepted"
    after_save = counts(runtime)
    with pytest.raises(RuntimeErrorBase) as app_conflict:
        submit(runtime, other_app, "stale-app", editing_session="app")
    assert app_conflict.value.details["reason"] == "value_conflict"
    assert counts(runtime) == after_save
    lease(runtime, 2, release=True)
    lease(runtime, 2, tab="app", actor="shared-product", release=True)
    with pytest.raises(RuntimeErrorBase) as conflict:
        submit(runtime, agent, "same-flight")
    assert conflict.value.status == 409 and conflict.value.details["reason"] == "value_conflict"
    assert conflict.value.details["status"] in {"refused", "conflict"}
    assert counts(runtime) == after_save
    merged = submit(runtime, compatible, "compatible")
    assert merged["data"]["status"] == "merged"
    assert merged["data"]["canonical_document"]["parent_revision"]["payload"]["config"]["title"] == "user"


@pytest.mark.integration
def test_app_credential_is_rechecked_at_serialized_acceptance(editing_runtime, monkeypatch):
    runtime = editing_runtime
    body = patch(runtime, "app", via="app")
    lease(runtime, 1)  # another actor's draft remains live throughout
    lease(runtime, 1, tab="app", actor="shared-product")
    ready, proceed = Event(), Event()
    original = RequestCommitPort.accept
    def paused_accept(port, candidate):
        ready.set()
        assert proceed.wait(10)
        return original(port, candidate)
    monkeypatch.setattr(RequestCommitPort, "accept", paused_accept)
    before = counts(runtime)
    with ThreadPoolExecutor(max_workers=1) as pool:
        flight = pool.submit(submit, runtime, body, "revoked-app", editing_session="app")
        try:
            assert ready.wait(10)
            lease(runtime, 2, tab="app", actor="shared-product", release=True)
        finally:
            proceed.set()
        with pytest.raises(RuntimeErrorBase) as caught:
            flight.result(timeout=15)
    assert caught.value.details["reason"] == "user_editing"
    assert counts(runtime) == before
    monkeypatch.setattr(RequestCommitPort, "accept", original)
    lease(runtime, 3, tab="app", actor="shared-product")
    accepted = submit(runtime, body, "revoked-app", editing_session="app")
    assert accepted["data"]["status"] == "accepted"


@pytest.mark.integration
@pytest.mark.parametrize("operation", ["commit", "restore-adapter", "restore-command"])
def test_admission_acceptance_interleaving_and_same_key_replay(editing_runtime, monkeypatch, operation):
    runtime = editing_runtime
    body = patch(runtime, "agent")
    source = body["base_revision_id"]
    if operation == "restore-command":
        document = runtime._timeline_commits()[0].revision_closure(runtime.test_project, "main", source)
        body["commands"] = [{"schema_version": 1, "op": "timeline.restore", "version": "1", "select": None,
                             "args": {"revision_id": source, "content_digest": document["parent_revision"]["content_digest"]}}]
        body.pop("reads")
    def execute():
        if operation != "restore-adapter":
            return submit(runtime, body, "interleaved")
        return runtime.restore_project_parent_composition_revision(runtime.test_project, "main", source,
            {"expected_head": source, "expected_publication_id": body["base_publication_id"]},
            idempotency_key="interleaved", publisher="shared-product", authorize=lambda: {"actor": "shared-product"},
            invocation_path=route_path(runtime.test_project, "main", f"composition-revisions/{source}/restore"))
    ready, proceed = Event(), Event()
    original = RequestCommitPort.accept
    def paused_accept(port, candidate):
        ready.set()
        assert proceed.wait(10)
        return original(port, candidate)
    monkeypatch.setattr(RequestCommitPort, "accept", paused_accept)
    before = counts(runtime)
    with ThreadPoolExecutor(max_workers=1) as pool:
        flight = pool.submit(execute)
        try:
            assert ready.wait(10)  # real provider has finished preparing its proposal
            assert lease(runtime, 1)["active"]
        finally:
            proceed.set()
        with pytest.raises(RuntimeErrorBase) as caught:
            flight.result(timeout=15)
    assert caught.value.status == 409 and caught.value.details["reason"] == "user_editing"
    assert counts(runtime) == before
    # Also cover admission before provider work for each alternate path.
    monkeypatch.setattr(RequestCommitPort, "accept", lambda *_: pytest.fail("provider reached acceptance under a lease"))
    with pytest.raises(RuntimeErrorBase) as admission:
        execute()
    assert admission.value.details["reason"] == "user_editing"
    assert counts(runtime) == before
    monkeypatch.setattr(RequestCommitPort, "accept", original)
    lease(runtime, 2, release=True)
    accepted = execute()
    after = counts(runtime)
    assert accepted["data"]["status"] == "accepted"
    lease(runtime, 3)
    monkeypatch.setattr(RequestCommitPort, "accept", lambda *_: pytest.fail("receipt replay invoked provider"))
    assert execute() == accepted
    assert counts(runtime) == after


@pytest.mark.integration
def test_expiry_allows_original_flight(editing_runtime):
    runtime = editing_runtime
    commits = runtime._timeline_commits()[0]
    clock = [1.0]
    commits.editing._clock = lambda: clock[0]
    body = patch(runtime, "agent")
    assert lease(runtime, 1, ttl_seconds=100)["expires_in_seconds"] == 10
    with pytest.raises(RuntimeErrorBase, match="user is editing"):
        submit(runtime, body, "expired-flight")
    clock[0] = 11.0
    assert submit(runtime, body, "expired-flight")["data"]["status"] == "accepted"


@pytest.mark.integration
def test_runtime_restart_drops_memory_lease_and_preserves_best_effort_boundary(tmp_path, real_provider):
    root = tmp_path / "restart-realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    runtime.register_timeline_commit_provider(real_provider)
    project = runtime.create_project({"slug": "restart-editing", "name": "Restart editing"})["id"]
    runtime.create_timeline(project, "main", idempotency_key="create")
    runtime.test_project = project
    body = patch(runtime, "agent")
    runtime.update_timeline_editing(
        project, "main", {"tab_session_id": "tab", "sequence": 1},
        publisher="user", authorize=lambda: {"actor": "user"},
    )
    with pytest.raises(RuntimeErrorBase) as blocked:
        submit(runtime, body, "restart-flight")
    assert blocked.value.details["reason"] == "user_editing"
    runtime.close()

    restarted = RuntimeService(root)
    restarted.register_timeline_commit_provider(real_provider)
    restarted.test_project = project
    try:
        assert not restarted._timeline_commits()[0].editing.live(project, "main")
        # Presence is process memory. The stale flight can now land after restart;
        # user priority across an unobserved restart is a documented best-effort limit.
        result = submit(restarted, body, "restart-flight")
        assert result["data"]["status"] == "accepted"
    finally:
        restarted.close()


def test_editing_service_authenticates_actor_before_mutation(realm):
    runtime, _, project, _, _ = realm
    body = {"tab_session_id": "tab", "sequence": 1}
    for authorize in (None, lambda: None, lambda: {"actor": "different"}):
        with pytest.raises(AuthorizationError):
            runtime.update_timeline_editing(project, "main", body, publisher="user", authorize=authorize)
    assert not runtime._timeline_commits()[0].editing.live(project, "main")


def test_real_editing_route_authentication_and_owner_isolation(tmp_path):
    import http.client
    import json
    from urllib.parse import urlsplit

    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root, support_root=tmp_path / "support").start()
    try:
        runtime = daemon.service
        project = runtime.create_project({"slug": "http-editing", "name": "HTTP editing"})["id"]
        runtime.create_timeline(project, "main", idempotency_key="create")
        path = f"/v1/projects/{project}/timelines/main/editing"
        alice, _ = daemon.credentials.provision("alice", ["projects:write"])
        bob, _ = daemon.credentials.provision("bob", ["projects:write"])
        reader, _ = daemon.credentials.provision("reader", ["projects:read"])
        endpoint = urlsplit(daemon.endpoint)
        def call(method, token, body, route=path):
            connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            try:
                connection.request(method, route, json.dumps(body), headers)
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()
        body = {"tab_session_id": "one", "sequence": 1}
        for method in ("PUT", "DELETE"):
            for token in (None, "invalid-test-token", reader):
                status, _ = call(method, token, body)
                assert status == 401
        assert call("PUT", alice, body)[0] == 200
        assert call("DELETE", bob, {**body, "sequence": 2})[1]["data"]["active"] is False
        commits = runtime._timeline_commits()[0]
        assert commits.editing.live(project, "main")
        assert call("PUT", alice, {**body, "tab_session_id": "two"})[0] == 200
        assert call("DELETE", alice, {**body, "sequence": 3})[1]["data"]["active"] is False
        assert call("PUT", alice, {**body, "sequence": 2})[1]["data"]["active"] is False
        assert commits.editing.live(project, "main")
        assert call("DELETE", alice, {**body, "tab_session_id": "two", "sequence": 2})[0] == 200
        assert not commits.editing.live(project, "main")
        assert call("PUT", alice, body, path + "?actor=bob")[0] == 400
        assert call("PUT", alice, {**body, "actor": "bob"})[0] == 422
        assert call("PUT", alice, body, path.replace("/main/", "/missing/"))[0] == 404
    finally:
        daemon.stop()


def test_initialization_and_adoption_cannot_replace_leased_head(realm):
    runtime, commits, project, head, _ = realm
    commits.editing.update(project, "main", "user", {"tab_session_id": "tab", "sequence": 1})
    before = counts(runtime)
    assert commits.bootstrap(project, "main", authorize=lambda: None, document={"different": True}) == head
    assert commits.install_verified_baseline(project, "main", authorize=lambda: None) == head
    with pytest.raises(CommitRejected):
        commits.adopt_empty_shell(project, "main", authorize=lambda: None)
    assert counts(runtime) == before


@pytest.mark.integration
def test_headless_shell_publication_is_gated_and_create_retry_is_soft(editing_runtime):
    runtime = editing_runtime
    project = runtime.test_project
    runtime.create_timeline(project, "shell", idempotency_key="shell", _bootstrap=False)
    runtime.update_timeline_editing(project, "shell", {"tab_session_id": "tab", "sequence": 1},
                                   publisher="user", authorize=lambda: {"actor": "user"})
    commits = runtime._timeline_commits()[0]
    # Every adapter for this realm sees the same owner, even a new adapter.
    from runtime_protocol.timeline_commit_store import TimelineCommitStore
    other = TimelineCommitStore(runtime.store, validate_prepared=commits.validate_prepared)
    assert other.editing is commits.editing
    before = counts(runtime)
    for adapter in (commits, other):
        with pytest.raises(CommitRejected) as caught:
            adapter.bootstrap(project, "shell", authorize=lambda: None)
        assert caught.value.failure["details"]["reason"] == "user_editing"
        assert caught.value.failure["details"]["base"] is None
        assert caught.value.failure["details"]["current"] is None
    with pytest.raises(RuntimeErrorBase) as caught:
        runtime.create_timeline(project, "shell", idempotency_key="adopt-shell")
    assert caught.value.status == 409 and caught.value.details["reason"] == "user_editing"
    assert counts(runtime) == before
    runtime.update_timeline_editing(project, "shell", {"tab_session_id": "tab", "sequence": 2},
                                   publisher="user", authorize=lambda: {"actor": "user"}, release=True)
    result = runtime.create_timeline(project, "shell", idempotency_key="adopt-shell")
    assert result["data"]["head_publication_id"]
    after = counts(runtime)
    assert runtime.create_timeline(project, "shell", idempotency_key="adopt-shell") == result
    assert counts(runtime) == after
