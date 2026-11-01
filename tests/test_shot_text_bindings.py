from __future__ import annotations

import hashlib

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from runtime_protocol.util import now


@pytest.fixture()
def daemon(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    value = RuntimeDaemon(tmp_path / "realm").start()
    try:
        yield value
    finally:
        value.stop()


def _seed(client, daemon):
    project = client.create_project("text-bindings", idempotency_key="project")
    # The shot CRUD writer is intentionally still retired.  Seed the existing
    # project-library row privately in this ephemeral realm; the binding under
    # test goes through the normal public operation below.
    with daemon.service.store._transaction():
        stamp = now()
        daemon.service.store.conn.execute(
            "INSERT INTO project_shots(id, project_id, name, metadata_json, version, created_at, updated_at, archived_at) "
            "VALUES (?, ?, ?, '{}', 1, ?, ?, NULL)",
            ("opening", project.project_id, "Opening", stamp, stamp),
        )
    return project


def test_set_is_deterministic_project_scoped_and_replays(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client, daemon)
    first = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "prompt", "slot": "hero", "text": "héllo", "expected_head": 0}, idempotency_key="set")
    replay = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "prompt", "slot": "hero", "text": "héllo", "expected_head": 0}, idempotency_key="set")
    assert replay == first
    assert first["binding_id"]
    assert first["head"] == 1
    assert first["byte_size"] == len("héllo".encode())
    assert first.receipt["command_kind"] == "shot.text_binding.set"
    assert client.list_project_shot_text_bindings(project.project_id, shot_id="opening")[0][0]["binding_id"] == first["binding_id"]
    with pytest.raises(ApiError):
        client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "prompt", "slot": "hero", "text": "changed", "expected_head": 0}, idempotency_key="set")


def test_set_rebind_and_event_order(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client, daemon)
    first = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "transcript", "text": "one", "expected_head": 0}, idempotency_key="one")
    second = client.set_project_shot_text_binding(project.project_id, {"binding_id": first["binding_id"], "text": "two", "expected_head": 1}, idempotency_key="two")
    rebound = client.rebind_project_shot_text_binding(project.project_id, first["binding_id"], media_id=first["media_id"], expected_head=2, idempotency_key="rebind")
    assert second["head"] == 2 and rebound["head"] == 3
    rows = daemon.service.store.conn.execute("SELECT seq, kind FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq", (first["binding_id"],)).fetchall()
    assert [tuple(row) for row in rows] == [(1, "shot.text_binding.created"), (2, "shot.text_binding.rebound"), (3, "shot.text_binding.rebound")]


def test_invalid_utf8_and_size_are_zero_write(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client, daemon)
    before = daemon.service.store.conn.execute("SELECT COUNT(*) FROM shot_text_bindings").fetchone()[0]
    with pytest.raises(ApiError):
        client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "transcript", "text": "x" * 1_048_577, "expected_head": 0}, idempotency_key="large")
    with pytest.raises(Exception):
        daemon.service.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "transcript", "text": b"\xff", "expected_head": 0}, idempotency_key="invalid")
    after = daemon.service.store.conn.execute("SELECT COUNT(*) FROM shot_text_bindings").fetchone()[0]
    assert after == before


def test_identity_digest_is_sha256(daemon):
    client = WorkspaceClient(daemon.endpoint, daemon.token)
    project = _seed(client, daemon)
    value = client.set_project_shot_text_binding(project.project_id, {"shot_id": "opening", "kind": "voiceover_script", "text": "voice", "expected_head": 0}, idempotency_key="voice")
    assert value["content_hash"] == "sha256:" + hashlib.sha256(b"voice").hexdigest()


def test_exact_set_retry_after_later_rebind_survives_restart(tmp_path, monkeypatch):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    daemon = RuntimeDaemon(root).start()
    try:
        client = WorkspaceClient(daemon.endpoint, daemon.token)
        project = _seed(client, daemon)
        seed = client.set_project_shot_text_binding(
            project.project_id,
            {"shot_id": "opening", "kind": "transcript", "text": "seed", "expected_head": 0},
            idempotency_key="seed",
        )
        original = client.set_project_shot_text_binding(
            project.project_id,
            {"binding_id": seed["binding_id"], "text": "A", "expected_head": 1},
            idempotency_key="A",
        )
        replacement = client.ingest_project_object(
            project.project_id, b"B", media_type="text/plain", idempotency_key="replacement",
        )
        client.rebind_project_shot_text_binding(
            project.project_id, seed["binding_id"], media_id=replacement.digest,
            expected_head=2, idempotency_key="B",
        )
        before = daemon.service.get_project_shot_text_binding(project.project_id, seed["binding_id"])
        events_before = [
            tuple(row) for row in daemon.service.store.conn.execute(
                "SELECT seq, kind, event_hash FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq",
                (seed["binding_id"],),
            )
        ]
        cas_root = daemon.service.store.cas_root
        cas_before = {str(path.relative_to(cas_root)): path.read_bytes() for path in cas_root.rglob("*") if path.is_file()}
    finally:
        daemon.stop()

    restarted = RuntimeDaemon(root).start()
    try:
        replay_client = WorkspaceClient(restarted.endpoint, restarted.token)
        monkeypatch.setattr(restarted.service, "_resolve_text_binding", lambda *args, **kwargs: pytest.fail("exact retry read live binding"))
        replay = replay_client.set_project_shot_text_binding(
            project.project_id,
            {"binding_id": seed["binding_id"], "text": "A", "expected_head": 1},
            idempotency_key="A",
        )
        assert replay == original
        assert replay.receipt == original.receipt
        assert restarted.service.get_project_shot_text_binding(project.project_id, seed["binding_id"]) == before
        events_after = [
            tuple(row) for row in restarted.service.store.conn.execute(
                "SELECT seq, kind, event_hash FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq",
                (seed["binding_id"],),
            )
        ]
        cas_root = restarted.service.store.cas_root
        cas_after = {str(path.relative_to(cas_root)): path.read_bytes() for path in cas_root.rglob("*") if path.is_file()}
        assert events_after == events_before
        assert cas_after == cas_before
    finally:
        restarted.stop()
