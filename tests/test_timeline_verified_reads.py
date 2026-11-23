"""Exercise public timeline head and history through the Runtime request dispatcher."""
import copy
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, redirect_stderr
from urllib.parse import quote

import pytest

from runtime_protocol.contract_metadata import SCHEMA_DIGEST
from runtime_protocol.door import classify
from runtime_protocol.errors import AuthorizationError, HeadBusyError, RuntimeErrorBase
from runtime_protocol.logs import RotatingLog
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


def verified_head_receipts(stderr):
    prefix = "runtime.timeline_commit.verified_head "
    return [json.loads(line.removeprefix(prefix))
            for line in stderr.splitlines() if line.startswith(prefix)]


def test_verified_head_emits_only_opt_in_fixed_counts_to_rotating_log(service, monkeypatch, tmp_path):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    live_total_changes = service.store.conn.total_changes
    log_path = tmp_path / "runtime.log"
    monkeypatch.delenv("ASTRID_RUNTIME_TIMELINE_DIAGNOSTICS", raising=False)
    requests = []
    with RotatingLog(log_path) as log, redirect_stderr(log):
        for enabled in (None, "0", "1", "1", "1"):
            if enabled is not None:
                monkeypatch.setenv("ASTRID_RUNTIME_TIMELINE_DIAGNOSTICS", enabled)
            if enabled == "0":
                commits.clear_replay_memo()
            if len(requests) == 2:
                assert not log_path.read_text()
                commits.clear_replay_memo()
            if len(requests) == 4:
                # Keep the semantic key while forcing the record verifier to consult it.
                commits._history_state["records"].clear()
            request = handler(service, "verified-head")
            request._dispatch()
            requests.append(request)
    assert all(request.reply == requests[0].reply for request in requests)
    assert requests[0].reply[0] == 200
    lines = log_path.read_text().splitlines()
    assert len(lines) == 3
    prefix = "runtime.timeline_commit.verified_head "
    assert all(line.startswith(prefix) for line in lines)
    receipts = [json.loads(line.removeprefix(prefix)) for line in lines]
    assert all(set(receipt) == {"counts", "live_total_changes_before", "live_total_changes_after"}
               for receipt in receipts)
    assert all(receipt["live_total_changes_before"] == receipt["live_total_changes_after"] == live_total_changes
               for receipt in receipts)
    cold, warm, retained_replay = (receipt["counts"] for receipt in receipts)
    assert set(cold) == set(warm) == set(retained_replay) == {
        "document_schema_cache_hits", "document_schema_cache_misses", "document_schema_cache_evictions",
        "selected_record_cache_hits", "selected_record_verification_attempts",
        "selected_replay_key_hits", "selected_record_replay_attempts", "isolated_read_retries",
        "snapshot_prefix_history_queries", "snapshot_prefix_history_rows_read",
        "snapshot_prefix_receipt_queries", "snapshot_prefix_receipt_rows_read",
    }
    assert all(type(value) is int and value >= 0 for receipt in receipts for value in receipt["counts"].values())
    assert cold["selected_record_verification_attempts"] == cold["selected_record_replay_attempts"] == 1
    assert cold["selected_record_cache_hits"] == cold["selected_replay_key_hits"] == 0
    assert warm["selected_record_cache_hits"] == 1
    assert all(warm[name] == 0 for name in warm if name != "selected_record_cache_hits")
    assert retained_replay["selected_record_verification_attempts"] == retained_replay["selected_replay_key_hits"] == 1
    assert retained_replay["selected_record_cache_hits"] == retained_replay["selected_record_replay_attempts"] == 0


def test_verified_head_receipt_omits_unobserved_final_live_changes(service, monkeypatch, capsys):
    provider(service)
    commit(service, body(service))
    monkeypatch.setenv("ASTRID_RUNTIME_TIMELINE_DIAGNOSTICS", "1")
    authorizations = []

    def refuse_final_authorization():
        authorizations.append(True)
        if len(authorizations) == 3:
            raise AuthorizationError("read revoked at final fence")

    with pytest.raises(AuthorizationError, match="read revoked at final fence"):
        service.get_timeline_verified_head(service.test_project, "main", authorize=refuse_final_authorization)
    assert len(authorizations) == 3
    receipt, = verified_head_receipts(capsys.readouterr().err)
    assert receipt["live_total_changes_before"] == service.store.conn.total_changes
    assert "live_total_changes_after" not in receipt


@pytest.mark.parametrize("append_during_replay", [False, True], ids=["stable", "retry"])
def test_verified_head_materializes_each_snapshot_prefix_once(service, monkeypatch, capsys, append_during_replay):
    monkeypatch.setenv("ASTRID_RUNTIME_TIMELINE_DIAGNOSTICS", "1")
    provider(service)
    accepted = commit(service, body(service))
    followup = next_request(service)
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    live_total_changes = service.store.conn.total_changes
    open_snapshot = service.store._read_snapshot
    replay = TimelineCommitStore._verify_accepted_replay
    snapshots = []
    appended = []

    @contextmanager
    def trace_snapshot(**kwargs):
        with open_snapshot(**kwargs) as connection:
            assert connection is not service.store.conn
            assert connection.in_transaction
            assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
            queries = []
            connection.set_trace_callback(queries.append)
            snapshots.append((connection, queries))
            yield connection

    def append(reader, *args, **kwargs):
        if reader is not commits and append_during_replay and not appended:
            appended.append(commit(service, followup, key="append-during-replay"))
            # Exercise a cold retry against the newly committed prefix.
            commits.clear_replay_memo()
        return replay(reader, *args, **kwargs)

    monkeypatch.setattr(service.store, "_read_snapshot", trace_snapshot)
    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", append)
    request = handler(service, "verified-head")
    request._dispatch()

    assert request.reply[0] == 200, request.error
    assert len(appended) == int(append_during_replay)
    latest = appended[0] if append_during_replay else accepted
    assert request.reply[1]["head"]["publication_id"] == latest["receipt"]["receipt_id"]
    assert len({connection for connection, _ in snapshots}) == len(snapshots) == 1 + int(append_during_replay)
    bounds = []
    for _, queries in snapshots:
        history_ranges = [query for query in queries if query.startswith(
            "SELECT * FROM timeline_commit_history WHERE project_id=") and "AND project_seq>" in query]
        receipt_ranges = [query for query in queries if query.startswith(
            "SELECT * FROM command_idempotency WHERE txn_id IN (SELECT publication_id FROM timeline_commit_history")]
        assert len(history_ranges) == len(receipt_ranges) == 1
        history_where = history_ranges[0].split(" WHERE ")[1].split(" ORDER BY ")[0]
        assert receipt_ranges[0].endswith(f" WHERE {history_where})")
        bounds.append(history_where)
        assert sum(query.startswith("SELECT * FROM command_idempotency WHERE txn_id=") for query in queries) > 1
        assert sum(query.startswith("SELECT * FROM timeline_commit_history WHERE publication_id=") for query in queries) > 1

    assert len(set(bounds)) == len(snapshots)
    receipt, = verified_head_receipts(capsys.readouterr().err)
    assert receipt["live_total_changes_before"] == live_total_changes
    assert receipt["live_total_changes_after"] == service.store.conn.total_changes
    assert (receipt["live_total_changes_after"] > live_total_changes) == append_during_replay
    counts = receipt["counts"]
    assert counts["selected_record_verification_attempts"] == len(snapshots)
    assert counts["selected_record_replay_attempts"] == len(snapshots)
    assert counts["isolated_read_retries"] == int(append_during_replay)
    for name in ("history", "receipt"):
        assert counts[f"snapshot_prefix_{name}_queries"] == len(snapshots)
        # Baseline plus the first commit, followed by three rows on retry.
        assert counts[f"snapshot_prefix_{name}_rows_read"] == 2 + 3 * int(append_during_replay)


def test_verified_head_rechecks_prefix_after_snapshot_transaction_reentry(service, monkeypatch, caplog):
    provider(service)
    first = commit(service, body(service))
    commit(service, next_request(service), key="second")
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    replay = TimelineCommitStore._verify_accepted_replay
    reentered = []

    def change_prefix(reader, *args, **kwargs):
        assert reader is not commits and reader.store.conn.in_transaction
        reader.store.conn.rollback()
        with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
            writer.execute("UPDATE command_idempotency SET created_at=created_at || ' changed' WHERE txn_id=?",
                           (first["receipt"]["receipt_id"],))
        reader.store.conn.execute("BEGIN")
        assert reader.store.conn.in_transaction
        reentered.append(reader)
        return replay(reader, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", change_prefix)
    with pytest.raises(HeadBusyError, match="changed during verification"):
        service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert len(reentered) == 1
    assert any("row-recheck" in message and "command_idempotency WHERE txn_id IN" in message
               for message in caplog.messages)
    assert not any(commits._history_state.values())


@pytest.mark.parametrize("mode", ["text-persistent", "text-restored", "row-restored"])
def test_verified_head_rechecks_prefix_after_result_factory_changes(service, monkeypatch, caplog, mode):
    provider(service)
    older_key = "old-receipt-only"
    commit(service, body(service), key=older_key)
    commit(service, next_request(service), key="second")
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    version = commits._store_version()
    converted = []
    history_reads = []

    def change_text(raw, *, restore=None):
        value = raw.decode()
        if value == older_key:
            converted.append(value)
            if restore is not None:
                restore.text_factory = str
            return value + "-converted"
        return value

    if mode == "text-persistent":
        replay = TimelineCommitStore._verify_accepted_replay

        def replace_decoder(reader, *args, **kwargs):
            assert reader is not commits and reader.store.conn.in_transaction
            reader.store.conn.text_factory = change_text
            return replay(reader, *args, **kwargs)

        monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", replace_decoder)
    else:
        open_snapshot = service.store._read_snapshot

        @contextmanager
        def trace_snapshot(**kwargs):
            with open_snapshot(**kwargs) as connection:
                installed = False

                def change_row(cursor, row):
                    if older_key in row:
                        converted.append(older_key)
                        connection.row_factory = sqlite3.Row
                        row = tuple(value + "-converted" if value == older_key else value for value in row)
                    return sqlite3.Row(cursor, row)

                def install_before_receipts(query):
                    nonlocal installed
                    # The history range runs after tracking starts and before
                    # SQLite creates the cursor that fetches the receipt range.
                    if (query.startswith("SELECT * FROM timeline_commit_history WHERE project_id=")
                            and "AND project_seq>" in query):
                        history_reads.append(query)
                        if installed:
                            return
                        installed = True
                        if mode == "text-restored":
                            connection.text_factory = lambda raw: change_text(raw, restore=connection)
                        else:
                            connection.row_factory = change_row

                connection.set_trace_callback(install_before_receipts)
                yield connection

        monkeypatch.setattr(service.store, "_read_snapshot", trace_snapshot)

    with pytest.raises(HeadBusyError, match="changed during verification"):
        service.get_timeline_verified_head(service.test_project, "main", authorize=lambda: None)
    assert converted == [older_key]
    assert commits._store_version()[:3] == version[:3]
    if mode != "text-persistent":
        assert len(history_reads) == 2 and history_reads[0] == history_reads[1]
    assert any("row-recheck" in message and "command_idempotency WHERE txn_id IN" in message
               for message in caplog.messages)
    assert not any(commits._history_state.values())


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


def test_transient_memo_custody_loss_forces_a_fresh_replay_on_retry(service, monkeypatch):
    provider(service)
    commit(service, body(service))
    project = service.test_project
    expected = service.get_timeline_verified_head(project, "main", authorize=lambda: None)
    publication = expected["head"]["publication_id"]
    commits, _ = service._timeline_commits()
    initial_generation = commits._replay_generation
    initial_version = commits._store_version()
    assert commits._replay_memo
    physical_policy = TimelineCommitStore._memo_failure
    replay = TimelineCommitStore._verify_accepted_replay
    lost = []
    replays = []

    def custody(self, version):
        if self is not commits and not lost:
            lost.append(self)
            return "simulated transient native memo permission loss"
        return physical_policy(self, version)

    def counted(self, row, edge, *args, **kwargs):
        replays.append((self, edge["publication_id"], commits._replay_generation))
        return replay(self, row, edge, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_memo_failure", custody)
    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", counted)
    assert service.get_timeline_verified_head(project, "main", authorize=lambda: None) == expected
    assert commits._store_version()[:3] == initial_version[:3]
    assert [replayed for _, replayed, _ in replays] == [publication, publication]
    (fallback, _, fallback_generation), (retry, _, retry_generation) = replays
    assert lost == [fallback]
    assert fallback is not retry
    assert fallback_generation == initial_generation < retry_generation
    assert commits._history_state is retry._history_state
    assert commits._replay_memo


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


def test_http_history_serves_snapshot_after_external_write_but_does_not_retain_proof(service, monkeypatch):
    provider(service)
    commit(service, body(service))
    commits, _ = service._timeline_commits()
    commits.clear_replay_memo()
    verify = TimelineCommitStore._verify_accepted
    readers = set()

    def changed(reader, *args, **kwargs):
        result = verify(reader, *args, **kwargs)
        if not readers:
            assert reader.store.conn is not service.store.conn
            assert reader.store.conn.execute("PRAGMA query_only").fetchone()[0] == 1
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as connection:
                connection.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
            readers.add(reader)
        return result

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted", changed)
    public = handler(service, "commits")
    public._dispatch()
    assert len(readers) == 1
    assert public.reply[0] == 200, public.error
    assert not commits._replay_memo
    assert not any(commits._history_state.values())
    replayed = []
    replay = TimelineCommitStore._verify_accepted_replay

    def count_replay(reader, *args, **kwargs):
        replayed.append(reader)
        return replay(reader, *args, **kwargs)

    monkeypatch.setattr(TimelineCommitStore, "_verify_accepted_replay", count_replay)
    second = handler(service, "commits")
    second._dispatch()
    assert second.reply[0] == 200, second.error
    assert replayed
    assert commits._replay_memo
