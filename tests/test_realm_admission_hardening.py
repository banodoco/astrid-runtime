from __future__ import annotations

import copy
import hashlib
import os
import json
import multiprocessing
import sqlite3
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from tests.lanes import requires_posix_fork

from runtime_protocol.backup import verify_restore_candidate
from runtime_protocol.cli import main as runtime_main
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, OwnerBusyError, RealmAdmissionError, ValidationError
from runtime_protocol.canonical_schema import CANONICAL_FORMAT_ID
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import SCHEMA_VERSION, RealmStore
from runtime_protocol.timeline_commit_port import RequestCommitPort
from runtime_protocol.timeline_commit_store import digest, request_identity
from runtime_protocol import platform as runtime_platform
from precut_realm_fixture import load_precut_realm_fixture
from test_timeline_commit_port import prepared
from tests.schema_fixtures import walk_back_to_v30


def _tree_bytes(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _new_service(root: Path, **kwargs):
    initialize_kwargs = {key: kwargs[key] for key in ("display_name", "realm_id") if key in kwargs}
    RealmStore.initialize(root, **initialize_kwargs).close()
    return RuntimeService(root, **kwargs)


def _new_daemon(root: Path, support_root: Path):
    RealmStore.initialize(root).close()
    return RuntimeDaemon(root, support_root=support_root).start()


def _payload_media_ids(value):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"media_id", "object_id"} and isinstance(child, str):
                found.add(child)
            found.update(_payload_media_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_payload_media_ids(child))
    return found


def _accept_unrelated_child_fixture(service, project_id, source_timeline, source_revision, *, omit_gain=False):
    """Use Runtime acceptance to capture a valid same-project child graph."""
    source = service.get_project_parent_composition_revision(
        project_id, source_timeline, source_revision,
    )["payload"]
    occurrence = copy.deepcopy(source["occurrences"][0])
    source_shot_revision = occurrence["shot_revision_id"]
    shot_row = service.store.conn.execute(
        "SELECT * FROM shot_revisions WHERE id=?", (source_shot_revision,),
    ).fetchone()
    internal_row = service.store.conn.execute(
        "SELECT * FROM internal_timeline_revisions WHERE id=?",
        (shot_row["internal_timeline_revision_id"],),
    ).fetchone()
    shot_payload = json.loads(shot_row["payload_json"])
    shot_payload["internal_timeline_revision_id"] = "other-internal"
    internal_payload = json.loads(internal_row["payload_json"])
    other_shot = "other-shot"
    other_shot_revision = "other-shot-revision"
    occurrence.update(shot_id=other_shot, shot_revision_id=other_shot_revision)
    if omit_gain:
        occurrence.pop("gain")
    parent_payload = copy.deepcopy(source)
    parent_payload["occurrences"] = [occurrence]

    other_timeline = "other"
    service.create_timeline(project_id, other_timeline, idempotency_key="other-timeline")
    commits, _ = service._timeline_commits()
    head = commits.bootstrap(project_id, other_timeline, authorize=lambda: None)
    request = {
        "api_version": 1,
        "project_id": project_id,
        "timeline_id": other_timeline,
        "base_revision_id": head["revision_id"],
        "base_publication_id": head["publication_id"],
        "commands": [{
            "schema_version": 1, "op": "clip.move", "version": "1",
            "select": "parent/clip:fixture", "args": {"on": 2},
        }],
        "rationale": "host acceptance fixture",
    }
    context = {
        "request": request,
        "invocation": {
            "operation": "commitTimeline",
            "path": f"/v1/projects/{project_id}/timelines/{other_timeline}/commit",
            "body": copy.deepcopy(request),
        },
        "idempotency_key": "other-parent",
        "realm_id": service.realm["id"],
        "publisher": "host-fixture",
    }
    context["request_hash"] = request_identity(context)
    port = RequestCommitPort(service, commits, context, lambda: None)
    try:
        candidate = prepared(context, port, same=True)
    finally:
        port.close()

    internal_image = {
        "timeline_id": other_timeline,
        "revision_id": "other-internal",
        "payload": internal_payload,
        "content_digest": digest(internal_payload),
    }
    media_ids = sorted(
        _payload_media_ids(parent_payload)
        | _payload_media_ids(shot_payload)
        | _payload_media_ids(internal_payload)
    )
    shot_image = {
        "shot_id": other_shot,
        "revision_id": other_shot_revision,
        "internal_timeline_revision_id": "other-internal",
        "payload": shot_payload,
        "content_digest": digest(shot_payload),
    }
    document = {
        "schema_version": 1,
        "project_id": project_id,
        "timeline_id": other_timeline,
        "parent_revision": {
            "revision_id": "other-parent",
            "payload": parent_payload,
            "content_digest": digest(parent_payload),
        },
        "shot_revisions": [shot_image],
        "internal_timeline_revisions": [internal_image],
        "dependency_manifest": {
            "shots": [{
                "shot_id": other_shot,
                "revision_id": other_shot_revision,
                "internal_timeline_revision_id": "other-internal",
                "content_digest": shot_image["content_digest"],
            }],
            "internal_timelines": [{
                "timeline_id": other_timeline,
                "revision_id": "other-internal",
                "content_digest": internal_image["content_digest"],
            }],
            "media": [{"media_id": media_id, "content_digest": media_id}
                      for media_id in media_ids],
            "documents": [],
        },
    }
    candidate["canonical_document"] = document
    candidate["document_digest"] = digest(document)
    commits.accept(context, candidate, authorize=lambda: None)
    return other_shot_revision


def _admission_worker(root, release, results):
    try:
        store = RealmStore(root)
    except Exception as exc:  # pragma: no cover - asserted by the parent
        results.put((type(exc).__name__, getattr(exc, "code", None), str(exc)))
        return
    results.put(("ok", None, ""))
    release.wait(10)
    store.close()


def test_corrupt_startup_fails_before_credentials_catalog_discovery_or_server(tmp_path):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    root.mkdir()
    database = root / "realm.sqlite3"
    database.write_bytes(b"not a sqlite database")

    daemon = RuntimeDaemon(root, support_root=support)
    assert not support.exists()
    with pytest.raises(RealmAdmissionError) as error:
        daemon.start()

    assert error.value.code == "realm_admission_failed"
    assert error.value.details["state"] == "unhealthy"
    assert error.value.details["checks"]["sqlite_integrity"]["ok"] is False
    assert database.read_bytes() == b"not a sqlite database"
    assert not Path(str(database) + "-wal").exists()
    assert not Path(str(database) + "-shm").exists()
    assert daemon.httpd is None
    assert not (support / "credentials").exists()
    assert not (support / "catalog.json").exists()
    assert not (support / "discovery.json").exists()


def test_existing_owner_is_rejected_before_sqlite_admission_snapshot(tmp_path, monkeypatch):
    """A live owner must win before inspection can race its SQLite writes."""
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    owner = (root / "owner.lock").open("a+")
    runtime_platform.lock_file(owner.fileno(), exclusive=True, blocking=False)
    inspected = False

    def fail_inspection(cls, *_args, **_kwargs):
        nonlocal inspected
        inspected = True
        raise AssertionError("owner contention must be detected before inspection")

    monkeypatch.setattr(RealmStore, "inspect_realm", classmethod(fail_inspection))
    try:
        with pytest.raises(OwnerBusyError):
            RealmStore(root)
    finally:
        runtime_platform.unlock_file(owner.fileno())
        owner.close()

    assert not inspected
    assert not (root / "admission.lock").exists()


@requires_posix_fork
def test_concurrent_admission_serializes_owner_and_never_reports_sqlite_race(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    context = multiprocessing.get_context("fork")
    release = context.Event()
    results = context.Queue()
    workers = [
        context.Process(target=_admission_worker, args=(str(root), release, results))
        for _ in range(10)
    ]
    for worker in workers:
        worker.start()
    try:
        observed = [results.get(timeout=10) for _ in workers]
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=10)
    assert all(worker.exitcode == 0 for worker in workers)
    assert sum(result[0] == "ok" for result in observed) == 1
    assert all(result[1] == "owner_busy" for result in observed if result[0] != "ok")
    assert not any("sqlite_integrity" in result[2] for result in observed)


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sidecar_without_main_database_fails_closed_without_discarding_it(tmp_path, suffix):
    root = tmp_path / "realm"
    support = tmp_path / "support"
    root.mkdir()
    sidecar = root / f"realm.sqlite3{suffix}"
    sidecar.write_bytes(b"orphaned committed-state fixture")
    before = sidecar.read_bytes()

    report = RealmStore.inspect_realm(root)
    assert report["state"] == "unhealthy"
    assert report["checks"]["sqlite_integrity"]["reason"] == "unreadable"
    with pytest.raises(RealmAdmissionError):
        RuntimeDaemon(root, support_root=support).start()

    assert not (root / "realm.sqlite3").exists()
    assert sidecar.read_bytes() == before
    assert not support.exists()


def test_malformed_doctor_is_structured_bounded_and_non_mutating(tmp_path, capsys):
    root = tmp_path / "realm"
    root.mkdir()
    (root / "realm.sqlite3").write_bytes(b"malformed")
    before = _tree_bytes(root)

    report = RealmStore.inspect_realm(root)
    assert report["state"] == "unhealthy"
    assert report["checks"]["sqlite_integrity"]["reason"] in {"malformed", "unreadable"}
    assert RealmStore.inspect_realm(root, timeout_seconds=0)["checks"]["sqlite_integrity"]["reason"] == "timeout"
    assert runtime_main(["doctor", "--root", str(root), "--json"]) == 1
    cli_report = json.loads(capsys.readouterr().out)
    assert cli_report["state"] == "unhealthy"
    assert cli_report["checks"]["sqlite_integrity"]["ok"] is False
    assert _tree_bytes(root) == before


@pytest.mark.parametrize("configured_timeout, expected_timeout", [(None, 5.0), (37.0, 37.0)])
def test_doctor_uses_configured_admission_timeout(tmp_path, monkeypatch, configured_timeout, expected_timeout):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    kwargs = {} if configured_timeout is None else {"admission_timeout": configured_timeout}
    store = RealmStore(root, **kwargs)
    observed = {}

    def fake_integrity_report(self, *, catalog_path=None, timeout_seconds=None, deep):
        observed["catalog_path"] = catalog_path
        observed["timeout_seconds"] = timeout_seconds
        observed["deep"] = deep
        return {"ok": True, "state": "healthy"}

    monkeypatch.setattr(RealmStore, "integrity_report", fake_integrity_report)
    try:
        assert store.doctor() == {"ok": True, "state": "healthy"}
    finally:
        store.close()

    assert observed == {"catalog_path": None, "timeout_seconds": expected_timeout, "deep": False}


def test_existing_realm_missing_attempts_table_fails_admission(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("DROP TABLE attempts")
        connection.commit()
    finally:
        connection.close()

    report = RealmStore.inspect_realm(root)
    assert report["ok"] is False
    assert report["checks"]["schema"]["ok"] is False
    assert "attempts" in report["checks"]["schema"]["missing_tables"]
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert error.value.code == "realm_admission_failed"


def test_existing_realm_missing_required_column_fails_admission_with_schema_details(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("ALTER TABLE attempts DROP COLUMN lease_id")
        connection.commit()
    finally:
        connection.close()

    report = RealmStore.inspect_realm(root)
    assert report["ok"] is False
    assert report["issues"] == ["schema"]
    assert report["checks"]["schema"] == {
        "ok": False,
        "expected_format_id": CANONICAL_FORMAT_ID,
        "actual_format_id": CANONICAL_FORMAT_ID,
        "expected_version": SCHEMA_VERSION,
        "actual_version": SCHEMA_VERSION,
        "missing_tables": [],
        "missing_columns": {"attempts": ["lease_id"]},
        "extra_columns": {},
        "unexpected_tables": [],
    }
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert error.value.code == "realm_admission_failed"
    assert error.value.details["checks"]["schema"]["missing_columns"] == {"attempts": ["lease_id"]}


@pytest.mark.parametrize(
    ("case", "expected_reason"),
    [
        ("owned_declared_media_superset", None),
        ("missing_payload_media", "dependency_graph_mismatch"),
        ("unrelated_child_revision", "dependency_graph_mismatch"),
        ("unowned_extra_media", "dependency_closure"),
        ("wrong_extra_media_digest", "dependency_closure"),
        ("duplicate_dependency", "dependency_graph_mismatch"),
        ("noncontiguous_ordinals", "dependency_graph_mismatch"),
    ],
    ids=[
        "owned_declared_media_superset",
        "missing_payload_media",
        "unrelated_child_revision",
        "unowned_extra_media",
        "wrong_extra_media_digest",
        "duplicate_dependency",
        "noncontiguous_ordinals",
    ],
)
def test_revision_admission_legacy_declared_media_boundaries(tmp_path, case, expected_reason):
    captured = load_precut_realm_fixture(tmp_path)
    root = captured.copy_roots[1]
    project_id = captured.pins["project_id"]
    timeline_id = captured.pins["timeline_id"]
    parent_revision_id = captured.pins["parent_revision_id"]
    service = RuntimeService(root)
    try:
        parent_payload = service.get_project_parent_composition_revision(
            project_id, timeline_id, parent_revision_id,
        )["payload"]
        referenced = sorted(_payload_media_ids(parent_payload))[0]
        legacy_extra = service.ingest(
            project_id, b"legacy-declared-media", idempotency_key="legacy-extra",
        )["data"]["digest"]
        if case == "unrelated_child_revision":
            other_shot_revision = _accept_unrelated_child_fixture(
                service, project_id, timeline_id, parent_revision_id,
            )
        assert service.store.integrity_report()["ok"] is True
        dependencies = service.store.conn.execute(
            "SELECT COUNT(*) FROM composition_revision_dependencies WHERE parent_revision_id=?",
            (parent_revision_id,),
        ).fetchone()[0]
        service.store.conn.execute(
            "INSERT INTO composition_revision_dependencies(parent_revision_id,dependency_kind,dependency_id,content_digest,ordinal) VALUES (?, 'media', ?, ?, ?)",
            (parent_revision_id, legacy_extra, legacy_extra, dependencies),
        )
        if case == "missing_payload_media":
            removed = service.store.conn.execute(
                "SELECT ordinal FROM composition_revision_dependencies WHERE parent_revision_id=? AND dependency_kind='media' AND dependency_id=?",
                (parent_revision_id, referenced),
            ).fetchone()["ordinal"]
            service.store.conn.execute(
                "DELETE FROM composition_revision_dependencies WHERE parent_revision_id=? AND dependency_kind='media' AND dependency_id=?",
                (parent_revision_id, referenced),
            )
            # Preserve contiguous ordinals: this case must fail for missing
            # payload closure rather than an incidental ordinal gap.
            service.store.conn.execute(
                "UPDATE composition_revision_dependencies SET ordinal=ordinal-1 WHERE parent_revision_id=? AND ordinal>?",
                (parent_revision_id, removed),
            )
        elif case == "unrelated_child_revision":
            child = service.store.conn.execute(
                "SELECT content_digest FROM shot_revisions WHERE id=?", (other_shot_revision,),
            ).fetchone()
            service.store.conn.execute(
                "INSERT INTO composition_revision_dependencies(parent_revision_id,dependency_kind,dependency_id,content_digest,ordinal) VALUES (?, 'shot_revision', ?, ?, ?)",
                (parent_revision_id, other_shot_revision, child["content_digest"], dependencies + 1),
            )
        elif case == "unowned_extra_media":
            service.store.conn.execute(
                "DELETE FROM project_objects WHERE project_id=? AND digest=?",
                (project_id, legacy_extra.removeprefix("sha256:")),
            )
        elif case == "wrong_extra_media_digest":
            service.store.conn.execute(
                "UPDATE composition_revision_dependencies SET content_digest=? WHERE parent_revision_id=? AND dependency_id=?",
                (referenced, parent_revision_id, legacy_extra),
            )
        elif case == "duplicate_dependency":
            # The canonical primary key includes ordinal, so a duplicate
            # dependency triple at another ordinal is representable.
            service.store.conn.execute(
                "INSERT INTO composition_revision_dependencies(parent_revision_id,dependency_kind,dependency_id,content_digest,ordinal) VALUES (?, 'media', ?, ?, ?)",
                (parent_revision_id, legacy_extra, legacy_extra, dependencies + 1),
            )
        elif case == "noncontiguous_ordinals":
            service.store.conn.execute(
                "UPDATE composition_revision_dependencies SET ordinal=? WHERE parent_revision_id=? AND dependency_id=?",
                (dependencies + 1, parent_revision_id, legacy_extra),
            )
    finally:
        service.close()

    before = _tree_bytes(root)
    report = RealmStore.inspect_realm(root)
    assert _tree_bytes(root) == before
    assert report["checks"]["sqlite_integrity"]["ok"] is True
    assert report["checks"]["schema"]["ok"] is True
    revisions = report["checks"]["revisions"]
    if expected_reason is None:
        assert report["ok"] is True, report
        assert revisions["ok"] is True
    else:
        assert report["ok"] is False
        assert revisions["ok"] is False
        errors = revisions["errors"]
        assert any(
            error["table"] == "composition_revision_dependencies"
            and str(error["identity"]).startswith(parent_revision_id)
            and error["reason"] == expected_reason
            for error in errors
        ), errors
        # Non-media, missing, duplicate and ordinal cases have valid row-level
        # references; their rejection must come from graph reconciliation.
        if expected_reason == "dependency_graph_mismatch":
            assert not any(error["reason"] == "dependency_closure" for error in errors), errors


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("missing", "realm_identity_missing"),
        ("ambiguous", "realm_identity_ambiguous"),
    ],
)
def test_existing_realm_requires_one_unambiguous_identity(tmp_path, mutation, reason):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        if mutation == "missing":
            connection.execute("DELETE FROM realm_lifecycle")
            connection.execute("DELETE FROM realm")
        else:
            connection.execute(
                "INSERT INTO realm(id, display_name, created_at, updated_at) VALUES ('second-realm', 'Second', datetime('now'), datetime('now'))"
            )
        connection.commit()
    finally:
        connection.close()

    report = RealmStore.inspect_realm(root)
    assert report["ok"] is False
    assert report["checks"]["realm_identity"]["ok"] is False
    assert report["checks"]["realm_identity"]["reason"] == reason
    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)
    assert error.value.code == "realm_admission_failed"


def test_runtime_strict_identity_admission_rejects_before_open_and_preserves_bytes(tmp_path):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute("DELETE FROM realm_lifecycle")
        connection.execute("DELETE FROM realm")
        connection.commit()
    finally:
        connection.close()
    before = _tree_bytes(root)

    with pytest.raises(RealmAdmissionError) as error:
        RuntimeService(root)

    assert error.value.details["checks"]["realm_identity"]["reason"] == "realm_identity_missing"
    assert _tree_bytes(root) == before


def test_omitted_occurrence_gain_admits_but_stored_gain_corruption_refuses_before_daemon_boot(tmp_path):
    captured = load_precut_realm_fixture(tmp_path)
    root = captured.copy_roots[1]
    project_id = captured.pins["project_id"]
    timeline_id = captured.pins["timeline_id"]
    parent_revision_id = captured.pins["parent_revision_id"]
    service = RuntimeService(root)
    try:
        connection = service.store.conn
        assert connection is not None
        original = service.get_project_parent_composition_revision(
            project_id, timeline_id, parent_revision_id,
        )["payload"]
        original_parent_bytes = connection.execute(
            "SELECT payload_json FROM parent_composition_revisions WHERE id=?",
            (parent_revision_id,),
        ).fetchone()[0]
        source_occurrence = original["occurrences"][0]
        shared_closure_before = tuple(
            connection.execute(
                "SELECT payload_json FROM " + table + " WHERE id=?",
                (revision_id,),
            ).fetchone()[0]
            for table, revision_id in (
                ("shot_revisions", source_occurrence["shot_revision_id"]),
                ("internal_timeline_revisions", connection.execute(
                    "SELECT internal_timeline_revision_id FROM shot_revisions WHERE id=?",
                    (source_occurrence["shot_revision_id"],),
                ).fetchone()[0]),
            )
        )
        _accept_unrelated_child_fixture(
            service, project_id, timeline_id, parent_revision_id, omit_gain=True,
        )
        omitted_parent = json.loads(connection.execute(
            "SELECT payload_json FROM parent_composition_revisions WHERE id='other-parent'"
        ).fetchone()[0])
        assert "gain" not in omitted_parent["occurrences"][0]
        omitted_row = connection.execute(
            "SELECT gain FROM composition_revision_occurrences WHERE parent_revision_id='other-parent'"
        ).fetchone()
        assert omitted_row["gain"] == 1.0
        assert [row["gain"] for row in connection.execute(
            "SELECT gain FROM composition_revision_occurrences WHERE parent_revision_id=? ORDER BY ordinal",
            (parent_revision_id,),
        )] == [1.0, 1.0, 1.0]
        assert connection.execute(
            "SELECT payload_json FROM parent_composition_revisions WHERE id=?",
            (parent_revision_id,),
        ).fetchone()[0] == original_parent_bytes
        shared_closure_after = tuple(
            connection.execute(
                "SELECT payload_json FROM " + table + " WHERE id=?",
                (revision_id,),
            ).fetchone()[0]
            for table, revision_id in (
                ("shot_revisions", source_occurrence["shot_revision_id"]),
                ("internal_timeline_revisions", connection.execute(
                    "SELECT internal_timeline_revision_id FROM shot_revisions WHERE id=?",
                    (source_occurrence["shot_revision_id"],),
                ).fetchone()[0]),
            )
        )
        assert shared_closure_after == shared_closure_before
    finally:
        service.close()

    assert RealmStore.inspect_realm(root)["ok"]
    assert RealmStore.inspect_realm(root, deep=True)["ok"]
    reopened = RealmStore(root)
    try:
        assert reopened.admission_report["ok"]
    finally:
        reopened.close()

    connection = sqlite3.connect(root / "realm.sqlite3")
    try:
        connection.execute(
            "UPDATE composition_revision_occurrences SET gain=2.0 WHERE parent_revision_id='other-parent'"
        )
        connection.commit()
    finally:
        connection.close()

    corrupt = RealmStore.inspect_realm(root, deep=True)
    assert not corrupt["ok"]
    gain_errors = [
        error for error in corrupt["checks"]["revisions"]["errors"]
        if error["reason"] == "occurrence_field_mismatch" and error["field"] == "gain"
    ]
    assert len(gain_errors) == 1
    assert gain_errors[0]["expected"] == 1
    assert gain_errors[0]["actual"] == 2.0

    daemon = RuntimeDaemon(root, support_root=tmp_path / "support")
    with pytest.raises(RealmAdmissionError):
        daemon.start()
    assert daemon.httpd is None
    assert not (tmp_path / "support" / "credentials").exists()


def test_wal_only_commit_survives_owned_backup_and_restore(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        service.store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        service.store.conn.execute("PRAGMA wal_autocheckpoint=0")
        project = service.create_project({"slug": "wal-only", "name": "WAL only", "metadata": {}})
        wal = Path(str(service.store.db_path) + "-wal")
        assert wal.stat().st_size > 0

        main_only = sqlite3.connect(f"file:{service.store.db_path}?immutable=1", uri=True)
        try:
            assert main_only.execute("SELECT 1 FROM projects WHERE id=?", (project["id"],)).fetchone() is None
        finally:
            main_only.close()

        backup = tmp_path / "backup"
        service.backup(backup)
        restored = tmp_path / "restored"
        service.restore(backup, restored)
        restored_db = sqlite3.connect(f"file:{restored / 'realm.sqlite3'}?immutable=1", uri=True)
        try:
            assert restored_db.execute("SELECT name FROM projects WHERE id=?", (project["id"],)).fetchone()[0] == "WAL only"
        finally:
            restored_db.close()
        for suffix in ("-wal", "-shm", "-journal"):
            assert not Path(str(restored / "realm.sqlite3") + suffix).exists()
    finally:
        service.close()


def test_candidate_verification_is_byte_safe_and_rejects_unmanifested_sidecars(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        backup = tmp_path / "backup"
        candidate = tmp_path / "candidate"
        service.backup(backup)
        service.restore(backup, candidate)
        before = _tree_bytes(candidate)
        assert verify_restore_candidate(candidate)["doctor"]["ok"] is True
        assert _tree_bytes(candidate) == before

        sidecar = Path(str(candidate / "realm.sqlite3") + "-wal")
        sidecar.write_bytes(b"unmanifested")
        sidecar_before = _tree_bytes(candidate)
        with pytest.raises(ConflictError, match="unmanifested SQLite sidecar"):
            verify_restore_candidate(candidate)
        assert _tree_bytes(candidate) == sidecar_before
    finally:
        service.close()


def test_executor_descriptor_upserts_and_rolls_back_partial_visibility(tmp_path, monkeypatch):
    service = _new_service(tmp_path / "realm")
    old_digest = "sha256:" + "a" * 64
    new_digest = "sha256:" + "c" * 64
    try:
        service.register_capability({"capability_id": "render.atomic", "definition_digest": old_digest, "status": "unavailable"})
        service.register_executor(
            {
                "executor_id": "worker",
                "capabilities": [{"capability_id": "render.atomic", "definition_digest": new_digest, "status": "ready"}],
            },
            idempotency_key="register-upsert",
        )
        capability = service.store.list_capabilities()[0]
        assert capability["definition_digest"] == new_digest
        assert capability["status"] == "ready"

        original_register = service.store.register_capability

        def fail_after_descriptor(capability_id, definition_digest, **kwargs):
            value = original_register(capability_id, definition_digest, **kwargs)
            if capability_id == "render.partial":
                raise ValidationError("forced terminal registration failure")
            return value

        monkeypatch.setattr(service.store, "register_capability", fail_after_descriptor)
        with pytest.raises(ValidationError, match="terminal registration failure"):
            service.register_executor(
                {
                    "executor_id": "failed-worker",
                    "capabilities": [{"capability_id": "render.partial", "definition_digest": "sha256:" + "b" * 64}],
                },
                idempotency_key="register-failure",
            )
        assert service.store.conn.execute("SELECT 1 FROM capabilities WHERE id='render.partial'").fetchone() is None
        assert service.store.conn.execute("SELECT 1 FROM executors WHERE id='failed-worker'").fetchone() is None
    finally:
        service.close()


def test_capability_catalog_read_waits_for_atomic_executor_registration(tmp_path, monkeypatch):
    service = _new_service(tmp_path / "realm")
    first_descriptor_written = threading.Event()
    release_registration = threading.Event()
    reader_started = threading.Event()
    reader_done = threading.Event()
    failures = []
    result = {}
    original_register = service.store.register_capability

    def pause_after_first(capability_id, definition_digest, **kwargs):
        value = original_register(capability_id, definition_digest, **kwargs)
        if capability_id == "render.first":
            first_descriptor_written.set()
            if not release_registration.wait(2):
                raise AssertionError("test registration release timed out")
        return value

    monkeypatch.setattr(service.store, "register_capability", pause_after_first)

    def register():
        try:
            service.register_executor(
                {
                    "executor_id": "atomic-worker",
                    "capabilities": [
                        {"capability_id": "render.first", "definition_digest": "sha256:" + "1" * 64},
                        {"capability_id": "render.second", "definition_digest": "sha256:" + "2" * 64},
                    ],
                },
                idempotency_key="register-atomic",
            )
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    def read_catalog():
        reader_started.set()
        result["page"] = service.list_capabilities()
        reader_done.set()

    registration_thread = threading.Thread(target=register)
    reader_thread = threading.Thread(target=read_catalog)
    try:
        registration_thread.start()
        assert first_descriptor_written.wait(2)
        reader_thread.start()
        assert reader_started.wait(2)
        assert not reader_done.wait(0.1)
        release_registration.set()
        registration_thread.join(2)
        reader_thread.join(2)
        assert not failures
        assert reader_done.is_set()
        assert {item["capability_id"] for item in result["page"]["items"]} == {"render.first", "render.second"}
    finally:
        release_registration.set()
        registration_thread.join(2)
        reader_thread.join(2)
        service.close()


def test_health_degradation_revokes_mutations_and_http_errors_are_request_correlated(tmp_path):
    daemon = _new_daemon(tmp_path / "realm", tmp_path / "support")
    try:
        result = daemon.service.ingest_object(b"health-corruption", idempotency_key="health-object")
        digest = result["data"]["digest"].removeprefix("sha256:")
        (daemon.service.store.cas_root / digest[:2] / digest[2:]).write_bytes(b"corrupt")
        # Health is intentionally a cheap liveness probe. Deep CAS and
        # SQLite integrity checks remain behind the explicit doctor route.
        assert daemon.service.health()["status"] == "ok"
        assert daemon.service.doctor()["ok"] is False
        project_count = daemon.service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        with pytest.raises(RealmAdmissionError) as mutation_error:
            daemon.service.create_project({"slug": "must-not-commit", "name": "Must not commit", "metadata": {}})
        assert mutation_error.value.code == "realm_admission_failed"
        assert daemon.service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == project_count

        request = urllib.request.Request(
            daemon.endpoint + "/v1/executors",
            data=b"{}",
            method="POST",
            headers={
                "Authorization": f"Bearer {daemon.worker_token}",
                "Content-Type": "application/json",
                "Content-Length": "2",
                "X-Request-ID": "registration-test-request",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        payload = json.loads(error.value.read().decode("utf-8"))
        assert payload["code"] == "protocol_error"
        assert payload["request_id"] == "registration-test-request"
        assert error.value.headers["X-Request-ID"] == payload["request_id"]
    finally:
        daemon.stop()


def test_health_does_not_run_deep_doctor_and_preserves_latched_degradation(tmp_path, monkeypatch):
    service = _new_service(tmp_path / "realm")
    try:
        def deep_doctor_must_not_run(**_kwargs):
            raise AssertionError("health must not invoke the deep doctor")

        monkeypatch.setattr(service, "doctor", deep_doctor_must_not_run)
        assert service.health()["status"] == "ok"
        service._verified = False
        assert service.health()["status"] == "degraded"
    finally:
        service.close()


def test_writer_holds_admission_fence_through_commit_during_degradation(tmp_path, monkeypatch):
    service = _new_service(tmp_path / "realm")
    writer_in_body = threading.Event()
    release_writer = threading.Event()
    health_attempting_fence = threading.Event()
    health_acquired_fence = threading.Event()
    health_done = threading.Event()
    writer_done = threading.Event()
    failures = []
    results = {}

    class ObservedMutex:
        def __init__(self, mutex):
            self.mutex = mutex

        def __enter__(self):
            if threading.current_thread().name == "degradation-report":
                health_attempting_fence.set()
            self.mutex.acquire()
            if threading.current_thread().name == "degradation-report":
                health_acquired_fence.set()
            return self

        def __exit__(self, *_):
            self.mutex.release()

    service.store._mutex = ObservedMutex(service.store._mutex)
    original_create_project = service.store.create_project

    def pause_after_service_admission(*args, **kwargs):
        writer_in_body.set()
        if not release_writer.wait(2):
            raise AssertionError("writer release timed out")
        return original_create_project(*args, **kwargs)

    monkeypatch.setattr(service.store, "create_project", pause_after_service_admission)

    def write_project():
        try:
            results["project"] = service.create_project(
                {"slug": "fenced-writer", "name": "Fenced writer", "metadata": {}}
            )
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            writer_done.set()

    def report_degradation():
        try:
            # Integrity is an explicit maintenance probe; the normal health
            # endpoint must stay cheap and must not discover CAS corruption.
            results["health"] = service.doctor()
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)
        finally:
            health_done.set()

    writer = threading.Thread(target=write_project, name="fenced-writer")
    health = threading.Thread(target=report_degradation, name="degradation-report")
    try:
        corrupt = service.ingest_object(b"fence-corruption", idempotency_key="fence-object")
        digest = corrupt["data"]["digest"].removeprefix("sha256:")
        (service.store.cas_root / digest[:2] / digest[2:]).write_bytes(b"corrupt")

        writer.start()
        assert writer_in_body.wait(2)
        health.start()
        assert health_attempting_fence.wait(2)
        assert not health_acquired_fence.wait(0.1)
        assert not health_done.is_set()

        release_writer.set()
        writer.join(2)
        health.join(2)

        assert not failures
        assert writer_done.is_set() and health_done.is_set()
        assert results["project"]["slug"] == "fenced-writer"
        assert results["health"]["ok"] is False
        project_count = service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        with pytest.raises(RealmAdmissionError):
            service.create_project({"slug": "after-degradation", "name": "After degradation", "metadata": {}})
        assert service.store.conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == project_count
    finally:
        release_writer.set()
        writer.join(2)
        health.join(2)
        service.close()


@pytest.mark.parametrize("configured, expected", [(None, 5.0), ("37.5", 37.5)])
@pytest.mark.parametrize("healthy", [True, False])
def test_offline_doctor_cli_forwards_bounded_deadline_and_keeps_integrity_rejection(
    tmp_path, monkeypatch, capsys, configured, expected, healthy,
):
    observed = {}
    report = {"ok": healthy, "state": "healthy" if healthy else "unhealthy", "checks": {"sqlite_integrity": {"ok": healthy}}}

    def inspect(cls, root, *, catalog_path=None, timeout_seconds=None, deep):
        observed.update(root=root, catalog_path=catalog_path, timeout_seconds=timeout_seconds, deep=deep)
        return report

    monkeypatch.setattr(RealmStore, "inspect_realm", classmethod(inspect))
    root = tmp_path / "realm"
    argv = ["doctor", "--root", str(root), "--json"]
    if configured is not None:
        argv += ["--admission-timeout", configured]
    assert runtime_main(argv) == (0 if healthy else 1)
    assert json.loads(capsys.readouterr().out) == report
    assert observed == {"root": root, "catalog_path": None, "timeout_seconds": expected, "deep": False}
    assert not root.exists()


@pytest.mark.parametrize("invalid", ["0", "-1", "nan", "inf", "-inf", "not-a-duration"])
def test_offline_doctor_cli_rejects_unbounded_or_nonpositive_deadline_before_inspection(
    tmp_path, monkeypatch, invalid,
):
    def must_not_inspect(*args, **kwargs):
        raise AssertionError("invalid deadline reached realm inspection")

    monkeypatch.setattr(RealmStore, "inspect_realm", must_not_inspect)
    with pytest.raises(SystemExit) as caught:
        runtime_main(["doctor", "--root", str(tmp_path / "realm"), "--admission-timeout=" + invalid])
    assert caught.value.code == 2
    assert not (tmp_path / "realm").exists()


def _authenticated_v28_backup(tmp_path):
    """A genuine supported layout with a retained authentication key."""
    from runtime_protocol.backup import create_backup, _authenticated_digest, _manifest_digest_payload, _manifest_mac
    from runtime_protocol.upgrade import inspect_canonical_schema
    from runtime_protocol.util import canonical_json

    root = tmp_path / "realm"
    store = RealmStore.initialize(root, realm_id="historical-backup")
    backup = tmp_path / "backup"
    try:
        create_backup(store, backup, key_path=tmp_path / "backup-auth.key")
    finally:
        store.close()
    connection = sqlite3.connect(backup / "realm.sqlite3")
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        walk_back_to_v30(connection)
        connection.execute("ALTER TABLE timelines DROP COLUMN name")  # v30 -> v29/v28 layout
        connection.execute("DROP TABLE user_app_state")
        connection.execute("DROP INDEX idx_generations_gen")
        connection.execute("UPDATE runtime_schema SET version=28 WHERE id=1")
        connection.commit()
    finally:
        connection.close()
    assert inspect_canonical_schema(backup)["version"] == 28
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    database = (backup / "realm.sqlite3").read_bytes()
    manifest["files"]["realm.sqlite3"] = {"sha256": hashlib.sha256(database).hexdigest(), "size": len(database)}
    manifest["database_sha256"] = hashlib.sha256(database).hexdigest()
    manifest["schema"]["version"] = 28
    manifest["manifest_sha256"] = _authenticated_digest(_manifest_digest_payload(manifest))
    manifest["manifest_hmac"] = _manifest_mac(manifest, Path(manifest["authentication"]["key_path"]).read_bytes())
    manifest_path.write_text(canonical_json(manifest) + "\n")
    return backup


def test_older_backup_is_only_admitted_for_explicit_migration_verification(tmp_path):
    from runtime_protocol.backup import restore_backup, verify_backup
    backup = _authenticated_v28_backup(tmp_path)
    before = _tree_bytes(backup)
    with pytest.raises(ConflictError, match="integrity"):
        verify_backup(backup)
    with pytest.raises(ConflictError, match="integrity"):
        restore_backup(backup, tmp_path / "restore")
    verified = verify_backup(backup, older_schema=True)
    assert verified["doctor"]["issues"] == ["schema"]
    assert verified["manifest"]["schema"]["version"] == 28
    assert _tree_bytes(backup) == before
    assert not (tmp_path / "restore").exists()


@pytest.mark.parametrize("component", ["wal", "key", "extra_cas"])
def test_older_backup_migration_verification_preserves_other_guards(tmp_path, component):
    from runtime_protocol.backup import verify_backup
    backup = _authenticated_v28_backup(tmp_path)
    if component == "wal":
        (backup / "realm.sqlite3-wal").write_bytes(b"unmanifested")
    elif component == "key":
        (tmp_path / "backup-auth.key").write_bytes(b"x" * 32)
    else:
        prefix = backup / "cas" / "sha256" / "aa"
        prefix.mkdir()
        (prefix / ("0" * 62)).write_bytes(b"unmanifested")
    with pytest.raises(ConflictError):
        verify_backup(backup, older_schema=True)


def test_authenticated_older_backup_manifest_realm_must_match_database(tmp_path):
    from runtime_protocol.backup import verify_backup, _authenticated_digest, _manifest_digest_payload, _manifest_mac
    from runtime_protocol.util import canonical_json
    backup = _authenticated_v28_backup(tmp_path)
    manifest_path = backup / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["realm"]["id"] = "another-authenticated-realm"
    manifest["manifest_sha256"] = _authenticated_digest(_manifest_digest_payload(manifest))
    manifest["manifest_hmac"] = _manifest_mac(manifest, Path(manifest["authentication"]["key_path"]).read_bytes())
    manifest_path.write_text(canonical_json(manifest) + "\n")
    with pytest.raises(ConflictError, match="realm identity mismatch"):
        verify_backup(backup, older_schema=True)
