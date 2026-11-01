"""D94 keeps only process-owned proofs behind a fresh storage boundary."""
from __future__ import annotations

import copy
import os
import shutil
import sqlite3
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_timeline_commit_integration as real
import test_timeline_commit_port as port_tests
import test_timeline_request_verification as verification_cases
from test_timeline_commit_authentication import body, provider
from test_timeline_commit_port import commit, rows

from runtime_protocol import timeline_commit_store as store_module
from runtime_protocol.errors import AuthorizationError, ProtocolError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_store import TimelineCommitStore

film = real.film
service = port_tests.service


def warm(service, monkeypatch):
    provider(service)
    accepted = commit(service, body(service))
    commits, _ = service._timeline_commits()
    publication = accepted["receipt"]["receipt_id"]
    commits.clear_replay_memo()
    calls = Counter()
    original = commits._verify_accepted_record

    def counted(row, edge, **kwargs):
        calls[edge["publication_id"]] += 1
        return original(row, edge, **kwargs)

    monkeypatch.setattr(commits, "_verify_accepted_record", counted)
    entry = commits.history_entry(service.test_project, "main", publication)
    assert calls == {publication: 1}
    return commits, publication, entry, calls


def test_warm_entries_and_closures_are_detached_and_only_new_entry_is_verified(service, monkeypatch):
    commits, publication, expected, calls = warm(service, monkeypatch)
    for _ in range(3):
        value = commits.history_entry(service.test_project, "main", publication)
        assert value == expected
        value["records"]["steps"].clear()
        document = commits.revision_closure(service.test_project, "main", expected["revision_id"])
        document["parent_revision"]["payload"].clear()
    next_body = body(service)
    change = next_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    change["value"] = {"org.example.timeline": {"note": "next"}}
    next_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    accepted = commit(service, next_body, key="next")
    assert calls == {publication: 1, accepted["receipt"]["receipt_id"]: 1}
    assert commits.history_entry(service.test_project, "main", publication) == expected
    assert calls == {publication: 1, accepted["receipt"]["receipt_id"]: 1}


@pytest.mark.parametrize("writer", ["same-connection", "external", "wal-checkpoint", "file-size"])
def test_nonaccept_change_forces_full_verification(service, monkeypatch, writer):
    commits, publication, expected, calls = warm(service, monkeypatch)
    version = commits._store_version()
    if writer == "same-connection":
        service.store.conn.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
    elif writer == "external":
        assert service.store.conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as connection:
            connection.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
    elif writer == "wal-checkpoint":
        service.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    else:
        with service.store.db_path.open("ab") as stream:
            stream.write(b"\0" * 4096)
    assert commits._store_version() != version
    assert commits.history_entry(service.test_project, "main", publication) == expected
    assert calls == {publication: 2}


@pytest.mark.parametrize("component", ["database", "wal"])
def test_replaced_sqlite_file_reopens_and_fully_verifies_current_state(service, monkeypatch, tmp_path,
                                                                       component):
    commits, publication, expected, calls = warm(service, monkeypatch)
    old_connection = commits._connection
    target = service.store.db_path if component == "database" else service.store.db_path.with_name("realm.sqlite3-wal")
    replacement = tmp_path / "replacement.sqlite3"
    shutil.copyfile(target, replacement)
    replacement.replace(target)
    assert commits.history_entry(service.test_project, "main", publication) == expected
    assert calls == {publication: 2}
    assert commits._connection is service.store.conn
    assert commits._connection is not old_connection
    assert any(commits._history_state.values())


@pytest.mark.parametrize("component", ["database", "wal"])
def test_recovered_identity_does_not_accept_tampered_history(service, monkeypatch, tmp_path, component):
    commits, publication, expected, _ = warm(service, monkeypatch)
    target = service.store.db_path if component == "database" else service.store.db_path.with_name("realm.sqlite3-wal")
    replacement = tmp_path / "replacement.sqlite3"
    shutil.copyfile(target, replacement)
    replacement.replace(target)
    assert commits.history_entry(service.test_project, "main", publication) == expected

    service.store.conn.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE txn_id=?", (publication,))
    before = rows(service)
    with pytest.raises(RuntimeErrorBase):
        commits.history_entry(service.test_project, "main", publication)
    assert rows(service) == before
    assert not any(commits._history_state.values())


@pytest.mark.parametrize("writer", ["same-connection", "external"])
def test_change_after_warm_hit_is_refused_before_return(service, monkeypatch, writer):
    commits, publication, _, _ = warm(service, monkeypatch)
    original = commits._verify_accepted

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if writer == "external":
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as connection:
                connection.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
        else:
            service.store.conn.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
        return result

    monkeypatch.setattr(commits, "_verify_accepted", changed)
    with pytest.raises(ProtocolError, match="changed during verification"):
        commits.history_entry(service.test_project, "main", publication)
    assert not any(commits._history_state.values())


def test_retained_warm_forgery_is_also_rejected_after_an_external_write(service, monkeypatch):
    connection = service.store.conn
    original = verification_cases.read
    with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
        class ExternalMutations:
            def __getattr__(self, name):
                return getattr(connection, name)

            def execute(self, query, parameters=()):
                # Route only the unchanged retained witness's mutations through
                # the second real connection. Reads still use Runtime's handle.
                return (writer if query.startswith("UPDATE") else connection).execute(query, parameters)

        reads = []

        def read(*args, **kwargs):
            # Keep Runtime's pinned handle intact at each verification. The
            # unchanged witness uses this adapter only for its SQL mutations.
            service.store.conn = connection
            result = original(*args, **kwargs)
            if not reads:
                service.store.conn = ExternalMutations()
            reads.append(True)
            return result

        monkeypatch.setattr(verification_cases, "read", read)
        try:
            verification_cases.test_retained_rehashed_step_forgery_refuses_with_warm_memo(service, monkeypatch)
        finally:
            service.store.conn = connection


@pytest.mark.parametrize("corrupt", [False, True])
def test_external_write_before_begin_immediate_cannot_be_absorbed(service, monkeypatch, corrupt):
    commits, publication, expected, calls = warm(service, monkeypatch)
    next_body = body(service)
    change = next_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    next_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    transaction = service.store._transaction
    writes = []

    @contextmanager
    def external_then_begin():
        with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
            if corrupt:
                writer.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE txn_id=?", (publication,))
            else:
                writer.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
        writes.append(True)
        with transaction():
            yield

    monkeypatch.setattr(service.store, "_transaction", external_then_begin)
    if corrupt:
        before = service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0]
        with pytest.raises(RuntimeErrorBase):
            commit(service, next_body, key="race")
        assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == before
        assert not any(commits._history_state.values())
    else:
        assert commit(service, next_body, key="race")["data"]["status"] == "accepted"
        assert calls[publication] == 2
        assert commits.history_entry(service.test_project, "main", publication) == expected
    assert writes == [True]


@pytest.mark.parametrize("moment", ["before-sample", "after-sample"])
@pytest.mark.parametrize("corrupt", [False, True])
def test_external_write_after_own_commit_is_not_a_new_trusted_baseline(service, monkeypatch, moment, corrupt):
    commits, publication, expected, calls = warm(service, monkeypatch)
    next_body = body(service)
    change = next_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    next_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    version = commits._store_version
    writes = []

    def changed():
        current = commits._verification.current
        race = current is not None and current["accepting"] and not service.store.conn.in_transaction and not writes

        def external_write():
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
                if corrupt:
                    writer.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE idempotency_key=?",
                                   ("post-commit-race",))
                else:
                    writer.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
            writes.append(True)

        if race and moment == "before-sample":
            external_write()
        result = version()
        if race and moment == "after-sample":
            external_write()
        return result

    monkeypatch.setattr(commits, "_store_version", changed)
    generation = commits._replay_generation
    if corrupt:
        with pytest.raises(RuntimeErrorBase):
            commit(service, next_body, key="post-commit-race")
        assert not any(commits._history_state.values())
    else:
        # The production coordinator recovers a committed winner after the
        # store invalidates its proofs. It must authenticate the old rows anew.
        accepted = commit(service, next_body, key="post-commit-race")
        assert accepted["data"]["status"] == "accepted"
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls[publication] == 2
        assert commit(service, next_body, key="post-commit-race") == accepted
    assert writes == [True]
    assert commits._replay_generation > generation
    # Our transaction did commit; its lost acknowledgement must not erase it.
    assert service.store.conn.execute("SELECT COUNT(*) FROM timeline_commit_history").fetchone()[0] == 3


@pytest.mark.parametrize("component", ["database", "wal"])
@pytest.mark.parametrize("timestamp", ["mtime", "ctime"])
def test_same_size_file_timestamp_change_invalidates_verified_state(service, monkeypatch, component, timestamp):
    commits, publication, expected, calls = warm(service, monkeypatch)
    path = service.store.db_path if component == "database" else service.store.db_path.with_name("realm.sqlite3-wal")
    before = path.stat()
    version = commits._store_version()
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
    if timestamp == "ctime":
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert path.stat().st_mtime_ns == before.st_mtime_ns
        assert path.stat().st_ctime_ns != before.st_ctime_ns
    assert path.stat().st_size == before.st_size
    assert commits._store_version() != version
    assert commits.history_entry(service.test_project, "main", publication) == expected
    assert calls[publication] == 2


def test_every_cached_read_checks_after_begin_and_across_threads(service, monkeypatch):
    commits, publication, expected, calls = warm(service, monkeypatch)
    verify = commits._verify_accepted

    def checked(*args, **kwargs):
        assert service.store.conn is commits._connection
        assert service.store.conn.in_transaction
        assert service.store._mutex._is_owned()
        return verify(*args, **kwargs)

    monkeypatch.setattr(commits, "_verify_accepted", checked)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(commits.history_entry, service.test_project, "main", publication) for _ in range(4)]
        assert [future.result(timeout=10) for future in futures] == [expected] * 4
    assert calls == {publication: 1}
    assert not service.store.conn.in_transaction


def test_replacing_connection_rebinds_and_fully_verifies(service, monkeypatch):
    commits, publication, expected, calls = warm(service, monkeypatch)
    connection = service.store.conn
    with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as other:
        assert other.execute("PRAGMA data_version").fetchone()[0] == connection.execute("PRAGMA data_version").fetchone()[0]
        service.store.conn = other
        try:
            assert commits.history_entry(service.test_project, "main", publication) == expected
            assert calls == {publication: 2}
            assert commits._connection is other
            assert commits._connection.row_factory is sqlite3.Row
        finally:
            service.store.conn = connection


def test_closed_store_refuses_and_reopened_handle_verifies_cold(service, monkeypatch):
    commits, publication, expected, _ = warm(service, monkeypatch)
    root = service.store.root
    service.close()
    with pytest.raises(ProtocolError, match="reopen required"):
        commits.history_entry(service.test_project, "main", publication)
    assert not any(commits._history_state.values())
    reopened = RuntimeService(root)
    try:
        fresh, _ = reopened._timeline_commits()
        assert not any(fresh._history_state.values())
        calls = []
        verify = fresh._verify_accepted_record

        def counted(*args, **kwargs):
            calls.append(True)
            return verify(*args, **kwargs)

        monkeypatch.setattr(fresh, "_verify_accepted_record", counted)
        assert fresh.history_entry(service.test_project, "main", publication) == expected
        assert calls == [True]
    finally:
        reopened.close()


def test_refusal_discards_state_and_a_new_store_always_verifies_cold(service, monkeypatch):
    commits, publication, expected, calls = warm(service, monkeypatch)

    def refuse():
        raise AuthorizationError("refused")

    with pytest.raises(AuthorizationError):
        service.list_timeline_commits(service.test_project, "main", authorize=refuse)
    assert not any(commits._history_state.values())
    assert commits.history_entry(service.test_project, "main", publication) == expected
    assert calls == {publication: 2}


def test_external_write_at_read_begin_invalidates_before_a_cache_hit(service, monkeypatch):
    commits, publication, expected, calls = warm(service, monkeypatch)
    writes = []

    def before_begin(query):
        if query == "BEGIN" and not writes:
            with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as writer:
                writer.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
            writes.append(True)

    service.store.conn.set_trace_callback(before_begin)
    try:
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls == {publication: 2}
        assert writes == [True]
    finally:
        service.store.conn.set_trace_callback(None)
    reopened = TimelineCommitStore(service.store, validate_prepared=commits.validate_prepared,
                                   validate_event=commits.validate_event)
    verified = []
    original = reopened._verify_accepted_record

    def counted(*args, **kwargs):
        verified.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(reopened, "_verify_accepted_record", counted)
    assert reopened.history_entry(service.test_project, "main", publication) == expected
    assert verified == [True]


def test_rolled_back_accept_publishes_no_history_state(service, monkeypatch):
    commits, _, _, _ = warm(service, monkeypatch)
    next_body = body(service)
    change = next_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    next_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    before = rows(service)
    original = commits._publish
    attempted = []

    def fail(*args, **kwargs):
        original(*args, **kwargs)
        attempted.append(True)
        raise ValueError("rollback after publish")

    monkeypatch.setattr(commits, "_publish", fail)
    with pytest.raises(RuntimeErrorBase):
        commit(service, next_body, key="rollback")
    assert rows(service) == before
    assert attempted == [True]
    assert not any(commits._history_state.values())


def test_integrity_diagnostics_keep_reporting_corrupt_rows(service, monkeypatch):
    commits, publication, _, _ = warm(service, monkeypatch)
    service.store.conn.execute("UPDATE command_idempotency SET event_ids_json='[]' WHERE txn_id=?", (publication,))
    before = rows(service)
    errors = commits.integrity_errors()
    assert any(error["id"] == publication for error in errors)
    assert rows(service) == before


@pytest.mark.parametrize("operation", ["lookup", "accept"])
def test_authorization_refusal_precedes_cached_object_reads(service, monkeypatch, operation):
    commits, _, _, _ = warm(service, monkeypatch)

    def refuse():
        raise AuthorizationError("refused")

    def unreadable():
        pytest.fail("cached CAS read before authorization")

    monkeypatch.setattr(commits, "_check_history_objects", unreadable)
    with pytest.raises(AuthorizationError):
        if operation == "lookup":
            commits.lookup({}, authorize=refuse)
        else:
            commits.accept({}, {}, authorize=refuse)


def test_cached_legacy_closure_still_checks_physical_cas_bytes(film):
    runtime = RuntimeService(film.fixture.duplicate_root)
    try:
        project, timeline = film.fixture.project_id, film.fixture.timeline_id
        commits, _ = runtime._timeline_commits()
        commits.install_verified_baseline(project, timeline, authorize=lambda: None)
        runtime.list_timeline_commits(project, timeline, authorize=lambda: None)
        pin = commits.head(project, timeline)
        document = commits.revision_closure(project, timeline, pin["revision_id"])
        media = document["dependency_manifest"]["media"][0]["media_id"].removeprefix("sha256:")
        assert media in commits._history_state["objects"]
        path = runtime.cas.path_for(media)
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        before = rows(runtime)
        with pytest.raises(RuntimeErrorBase):
            commits.revision_closure(project, timeline, pin["revision_id"])
        assert rows(runtime) == before
        assert not any(commits._history_state.values())
    finally:
        runtime.close()


def protection_path(service, component):
    database = service.store.db_path
    return {"DB": database, "WAL": Path(str(database) + "-wal"),
            "SHM": Path(str(database) + "-shm"), "store directory": database.parent}[component]


def stat_owner(monkeypatch, path, uid):
    original = os.stat

    def changed(target, *args, **kwargs):
        value = original(target, *args, **kwargs)
        if target == path:
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            return SimpleNamespace(**{**fields, "st_uid": uid})
        return value

    monkeypatch.setattr(os, "stat", changed)


@pytest.mark.parametrize("component", ["DB", "WAL", "SHM", "store directory"])
@pytest.mark.parametrize("write_bit", [0o020, 0o002], ids=["group", "world"])
def test_writable_store_fully_verifies_every_request(service, monkeypatch, caplog, component, write_bit):
    commits, publication, expected, calls = warm(service, monkeypatch)
    path = protection_path(service, component)
    path.chmod(path.stat().st_mode | write_bit)
    for count in range(2, 5):
        caplog.clear()
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls == {publication: count}
        assert [record.getMessage() for record in caplog.records] == [
            f"timeline history memo disabled; full verification for this request: {component} is group/world-writable"]


@pytest.mark.parametrize("component", ["DB", "WAL", "SHM", "store directory"])
def test_different_owner_fully_verifies_every_request(service, monkeypatch, caplog, component):
    commits, publication, expected, calls = warm(service, monkeypatch)
    package = Path(store_module.__file__).resolve().parent
    package_uid = package.stat().st_uid
    other_uid = package_uid + 1
    path = protection_path(service, component)
    before = commits._store_version()
    # Controlled stat witness makes this protection test portable without
    # requiring chown privileges; SQLite still reads the real fixture bytes.
    stat_owner(monkeypatch, path if component in ("DB", "store directory") else str(path), other_uid)
    assert commits._store_version() != before
    for count in range(2, 5):
        caplog.clear()
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls == {publication: count}
        assert [record.getMessage() for record in caplog.records] == [
            ("timeline history memo disabled; full verification for this request: "
             f"{component} owner uid {other_uid} differs from root and installed runtime package owner uid {package_uid}")]


@pytest.mark.parametrize("component", ["DB", "WAL", "SHM", "store directory"])
def test_protected_chmod_invalidates_then_reuses_verified_state(service, monkeypatch, caplog, component):
    commits, publication, expected, calls = warm(service, monkeypatch)
    path = protection_path(service, component)
    before = commits._store_version()
    path.chmod(path.stat().st_mode ^ 0o040)
    assert commits._store_version() != before
    for _ in range(3):
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls == {publication: 2}
    assert not caplog.records


@pytest.mark.parametrize("owner", ["root", "package"])
def test_package_owner_comes_from_loaded_module_and_allowed_owners_are_eligible(service, monkeypatch, caplog, owner):
    commits, publication, expected, calls = warm(service, monkeypatch)
    package = os.path.dirname(os.path.realpath(store_module.__file__))
    package_uid = os.stat(package).st_uid
    store_uid = 0 if owner == "root" else package_uid + 1
    for component in ("DB", "WAL", "SHM", "store directory"):
        path = protection_path(service, component)
        stat_owner(monkeypatch, path if component in ("DB", "store directory") else str(path), store_uid)
    stat_owner(monkeypatch, package, package_uid + 1)
    assert commits._store_version()[4] == package_uid + 1
    for _ in range(3):
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls == {publication: 2}
    assert not caplog.records


def test_missing_shm_is_optional_but_missing_database_requires_reopen(service, monkeypatch, caplog):
    commits, publication, expected, calls = warm(service, monkeypatch)
    original = os.stat
    missing = {str(service.store.db_path) + "-shm"}

    def absent(path, *args, **kwargs):
        if path in missing:
            raise FileNotFoundError(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", absent)
    for _ in range(3):
        assert commits.history_entry(service.test_project, "main", publication) == expected
        assert calls == {publication: 2}
    assert not caplog.records
    missing.add(service.store.db_path)
    with pytest.raises(ProtocolError, match="database is missing; reopen required"):
        commits.history_entry(service.test_project, "main", publication)
    assert not any(commits._history_state.values())


def test_absent_wal_in_delete_journal_mode_is_normal_sqlite_state(service, monkeypatch, caplog):
    commits, publication, expected, _ = warm(service, monkeypatch)
    assert service.store.conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    fresh = TimelineCommitStore(service.store, validate_prepared=commits.validate_prepared,
                                validate_event=commits.validate_event)
    calls = []
    verify = fresh._verify_accepted_record

    def counted(*args, **kwargs):
        calls.append(True)
        return verify(*args, **kwargs)

    monkeypatch.setattr(fresh, "_verify_accepted_record", counted)
    assert fresh._store_version()[3][1:3] == (None, None)
    for _ in range(3):
        assert fresh.history_entry(service.test_project, "main", publication) == expected
        assert calls == [True]
    assert not caplog.records


def test_protected_chmod_after_own_commit_is_not_absorbed(service, monkeypatch):
    commits, publication, expected, calls = warm(service, monkeypatch)
    next_body = body(service)
    change = next_body["commands"][0]["args"]["changes"][0]
    change["before"] = {"state": "present", "value": copy.deepcopy(change["value"])}
    next_body["steps"][0]["patch"] = [copy.deepcopy(change)]
    original = commits._store_version
    changes = []

    def changed():
        current = commits._verification.current
        if current is not None and current["accepting"] and not service.store.conn.in_transaction and not changes:
            path = service.store.db_path
            path.chmod(path.stat().st_mode ^ 0o040)
            changes.append(True)
        return original()

    monkeypatch.setattr(commits, "_store_version", changed)
    assert commit(service, next_body, key="post-commit-chmod")["data"]["status"] == "accepted"
    assert changes == [True]
    assert commits.history_entry(service.test_project, "main", publication) == expected
    assert calls[publication] == 2
