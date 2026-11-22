"""Exercise public timeline head and history through the Runtime request dispatcher."""
import copy
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from urllib.parse import quote

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.door import classify
from runtime_protocol.errors import AuthorizationError, HeadBusyError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import digest
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_integration import film
from test_timeline_commit_port import commit, service
from test_timeline_commit_routes import make_handler


def handler(runtime, route, *, project=None, timeline="main"):
    if project is None:
        project = runtime.test_project
    path = f"/v1/projects/{quote(project, safe='')}/timelines/{quote(timeline, safe='')}/{route}"
    request = make_handler(runtime, b"", path=path, command="GET")
    send = request._send

    def capture(status, payload=None, **kwargs):
        request.error = kwargs.get("error")
        send(status, payload, **kwargs)

    request._send = capture
    return request


def test_verified_head_route_returns_exact_accepted_closure_without_history(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    project = service.test_project
    head = {"revision_id": accepted["data"]["accepted_revision_id"],
            "publication_id": accepted["receipt"]["receipt_id"]}
    commits, _ = service._timeline_commits()
    document = commits.revision_closure(project, "main", head["revision_id"])
    monkeypatch.setattr(service, "list_timeline_commits", lambda *args, **kwargs: pytest.fail("listed history"))

    request = handler(service, "verified-head")
    request._dispatch()
    assert request.reply == (200, {
        "project_id": project, "timeline_id": "main", "head": head,
        "canonical_document": document,
    })
    assert request.scopes_seen and set(request.scopes_seen) == {"projects:read"}
    parent = document["parent_revision"]
    assert parent["revision_id"] == head["revision_id"]
    assert parent["content_digest"] == digest(parent["payload"])
    assert classify("/api/runtime" + request.path, "GET") is not None


def test_handshake_advertises_verified_head_with_existing_core_digest(service):
    handshake = service.handshake({
        "authenticated_actor": "editor", "authenticated_scopes": ["projects:read"],
        "requested_scopes": ["projects:read"],
    })
    assert "timeline.verified_head.v1" in handshake["capabilities"]
    assert handshake["schema_digest"] == SCHEMA_DIGEST


def test_verified_head_denies_authority_and_other_timeline_scope(service):
    def refuse():
        raise AuthorizationError("read revoked")

    with pytest.raises(AuthorizationError, match="read revoked"):
        service.get_timeline_verified_head(service.test_project, "main", authorize=refuse)
    with pytest.raises(RuntimeErrorBase, match="timeline not found"):
        service.get_timeline_verified_head(service.test_project, "elsewhere", authorize=lambda: None)


def next_request(runtime):
    request = body(runtime)
    change = request["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    change["value"] = {"org.example.timeline": {"note": "second"}}
    request["steps"][0]["patch"] = [copy.deepcopy(change)]
    return request


@pytest.mark.parametrize("route", ["commits?limit=1", "verified-head"])
def test_cold_replay_does_not_block_commit_or_publish_a_stale_current_head(service, monkeypatch, route):
    provider(service)
    first = commit(service, body(service))
    first_publication = first["receipt"]["receipt_id"]
    request = next_request(service)
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    reading = threading.Event()
    resume = threading.Event()
    verify = TimelineCommitStore._verify_accepted_record

    def blocked(self, row, edge, **kwargs):
        if threading.current_thread().name.startswith("history-reader") and not reading.is_set():
            assert edge["publication_id"] == first_publication
            reading.set()
            assert resume.wait(15), "reader barrier was never released"
        return verify(self, row, edge, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_record", blocked)
    public = handler(service, route)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="history-reader") as reader, \
            ThreadPoolExecutor(max_workers=1) as writer:
        read = reader.submit(public._dispatch)
        try:
            assert reading.wait(5), f"cold replay did not reach barrier: {getattr(public, 'reply', None)}"
            written = writer.submit(commit, service, request, key="second")
            accepted = written.result(timeout=5)
            assert accepted["data"]["status"] == "accepted"
        finally:
            resume.set()
        read.result(timeout=5)

    if public.reply[0] == 409:
        assert public.error["details"]["reason"] == "head_busy"
    else:
        assert public.reply[0] == 200, public.error
        assert public.reply[1]["head"]["publication_id"] == accepted["receipt"]["receipt_id"]


def test_verified_head_replays_after_restart_then_reuses_the_completed_proof(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    root, project = service.store.root, service.test_project
    service.close()
    replay = TimelineCommitStore._verify_accepted_replay
    calls = []

    def counted(self, *args, **kwargs):
        calls.append(args[1]["publication_id"])
        return replay(self, *args, **kwargs)

    reopened = RuntimeService(root)
    try:
        monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", counted)
        first = reopened.get_timeline_verified_head(project, "main", authorize=lambda: None)
        assert first["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
        assert calls == [first["head"]["publication_id"]]
        assert reopened.get_timeline_verified_head(project, "main", authorize=lambda: None) == first
        assert calls == [first["head"]["publication_id"]]
    finally:
        reopened.close()


def test_memo_custody_loss_replays_and_does_not_retain_proof(service, monkeypatch):
    provider(service)
    commit(service, body(service))
    project = service.test_project
    expected = service.get_timeline_verified_head(project, "main", authorize=lambda: None)
    commits, _ = service._timeline_commits()
    physical_policy = TimelineCommitStore._memo_failure
    snapshot = service.store._read_snapshot
    changed = False

    def custody(self, version):
        if changed:
            return "simulated loss of memo permissions without SQL movement"
        return physical_policy(self, version)

    @contextmanager
    def lose_custody(**kwargs):
        nonlocal changed
        with snapshot(**kwargs) as connection:
            yield connection
        changed = True

    replay = TimelineCommitStore._verify_accepted_replay
    calls = []

    def counted(self, *args, **kwargs):
        calls.append(args[1]["publication_id"])
        return replay(self, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_memo_failure", custody)
    monkeypatch.setattr(service.store, "_read_snapshot", lose_custody)
    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", counted)
    assert service.get_timeline_verified_head(project, "main", authorize=lambda: None) == expected
    assert calls == [expected["head"]["publication_id"]]
    assert not any(commits._history_state.values())


def test_history_and_head_read_safe_permissions_beyond_owner_only(service):
    project = service.test_project
    previous = service.store.db_path.stat().st_mode & 0o777
    expected = service.list_timeline_commits(project, "main", authorize=lambda: None)
    service.store.db_path.chmod(0o644)
    try:
        public = handler(service, "commits")
        public._dispatch()
        assert public.reply == (200, expected)
        assert service.get_timeline_verified_head(project, "main", authorize=lambda: None)["head"] == expected["head"]
    finally:
        service.store.db_path.chmod(previous)


def test_cas_changes_after_snapshot_cannot_seed_head_proof(film, monkeypatch):
    project, timeline = film.fixture.project_id, film.fixture.timeline_id
    runtime = RuntimeService(film.fixture.duplicate_root)
    try:
        commits, _ = runtime._timeline_commits()
        commits.install_verified_baseline(project, timeline, authorize=lambda: None)
        expected = runtime.get_timeline_verified_head(project, timeline, authorize=lambda: None)
        media = expected["canonical_document"]["dependency_manifest"]["media"][0]["media_id"][7:]
        path = runtime.cas.path_for(media)
        original = path.read_bytes()
        snapshot = runtime.store._read_snapshot
        version = commits._store_version()

        @contextmanager
        def change_object(**kwargs):
            with snapshot(**kwargs) as connection:
                yield connection
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])

        monkeypatch.setattr(runtime.store, "_read_snapshot", change_object)
        with pytest.raises(HeadBusyError, match="changed during verification"):
            runtime.get_timeline_verified_head(project, timeline, authorize=lambda: None)
        assert runtime.get_project_timeline(project, timeline)["head_publication_id"] == expected["head"]["publication_id"]
        actual = commits._store_version()
        assert version[:3] == actual[:3]
        assert not any(commits._history_state.values())
    finally:
        runtime.close()


def test_checkpoint_without_sql_change_preserves_the_pinned_head(service, monkeypatch):
    provider(service)
    commit(service, body(service))
    project = service.test_project
    expected = service.get_timeline_verified_head(project, "main", authorize=lambda: None)
    snapshot = service.store._read_snapshot
    counts = []

    @contextmanager
    def checkpoint(**kwargs):
        with snapshot(**kwargs) as connection:
            yield connection
        counts.append(service.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0])

    monkeypatch.setattr(service.store, "_read_snapshot", checkpoint)
    assert service.get_timeline_verified_head(project, "main", authorize=lambda: None) == expected
    assert counts == [0]


def test_http_history_refuses_repeated_external_writes_during_verification(service, monkeypatch, caplog):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    verify = TimelineCommitStore._verify_accepted
    readers = set()

    def changed(reader, *args, **kwargs):
        result = verify(reader, *args, **kwargs)
        if reader not in readers:
            assert reader.store.conn is not service.store.conn
            assert reader.store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as connection:
                connection.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
            readers.add(reader)
        return result

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted", changed)
    public = handler(service, "commits")
    public._dispatch()
    assert len(readers) == 2
    assert public.reply[0] == 409
    assert public.error["code"] == "conflict"
    assert public.error["details"]["status"] == "refused"
    assert public.error["details"]["reason"] == "head_busy"
    assert public.error["message"] == "accepted commit inputs changed during verification"
    assert any("moved" in record.getMessage() and "files" in record.getMessage() for record in caplog.records)
    assert not any(commits._history_state.values())
