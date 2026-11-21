"""A fresh SDK editor can read an accepted save while SQLite checkpoints."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore

pytestmark = pytest.mark.integration


def _sdk_client(daemon):
    from astrid.sdk.client import AstridClient
    from astrid.sdk.remote import RemoteAstridClient
    from astrid.sdk.workspace_client import WorkspaceClient

    # The pinned Agent and integration Runtime carry different launcher
    # digests. Exercise the SDK over the authenticated loopback transport.
    workspace = WorkspaceClient(daemon.endpoint, daemon.token)
    workspace.handshake("nine-track-wal-reopen", "1", ["projects:read", "projects:write"])
    workspace.actor_id = "owner"
    return AstridClient(remote=RemoteAstridClient(workspace))


def _checkpoint(database, mode):
    with closing(sqlite3.connect(database, timeout=2, isolation_level=None)) as connection:
        return connection.execute(f"PRAGMA wal_checkpoint({mode})").fetchone()


def _describe_version(version):
    return {
        "total_changes": version[1],
        "data_version": version[2],
        **{
            name: {"inode": file[1], "size": file[2], "mtime_ns": file[3]}
            for name, file in zip(("db", "wal"), version[3][:2])
        },
    }


@pytest.mark.parametrize("checkpoint", [None, "PASSIVE", "TRUNCATE"], ids=["control", "backfill", "truncate"])
def test_nine_track_save_reopens_during_checkpoint(tmp_path, astrid_importable, monkeypatch, checkpoint):
    from astrid.sdk.timeline import Timeline

    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(
        realm, support_root=tmp_path / "support", authoring_profile="astrid",
        runtime_checkout=Path(__file__).resolve().parents[1], agent_checkout=astrid_importable,
    ).start()
    try:
        tracks = [(f"visual-{index}", "visual") for index in range(6)]
        tracks += [(f"audio-{index}", "audio") for index in range(3)]

        def add_tracks(editor):
            for track, kind in tracks:
                editor.track(track, kind=kind)

        with _sdk_client(daemon) as client:
            project = client.projects.create(
                slug="nine-track-wal", name="Nine track WAL", idempotency_key="nine-track-project",
            )
            assert project.ok, project.error
            project_id = project.data["project_id"]
            timeline = client.timelines.create_empty(
                project=project_id, timeline_id="main", idempotency_key="nine-track-timeline",
            )
            assert timeline.ok, timeline.error
            editor = Timeline.open(project_id, "main", client=client, outbox_path=tmp_path / "save.json")
            accepted = editor.commit(add_tracks, label="Create nine tracks", idempotency_key="nine-track-commit")
            assert accepted["data"]["status"] == "accepted"

        commits, _ = daemon.service._timeline_commits()
        database = daemon.service.store.db_path
        checkpoints = []
        if checkpoint == "TRUNCATE":
            # A freshly backfilled snapshot can read from the DB while
            # another connection resets the already checkpointed WAL.
            busy, frames, backfilled = _checkpoint(database, "PASSIVE")
            assert busy == 0 and frames == backfilled and frames > 0

        if checkpoint is not None:
            original_sync = commits._sync_replay_memo

            def sync_with_checkpoint():
                scope = commits._verification.current
                if scope["depth"] and not checkpoints:
                    outer = _describe_version(commits._replay_store_version)
                    result = _checkpoint(database, checkpoint)
                    nested = _describe_version(commits._store_version())
                    print(f"{checkpoint} {result}, depth={scope['depth']}, outer={outer}, nested={nested}")
                    busy, frames, backfilled = result
                    assert busy == 0 and frames == backfilled
                    assert (nested["total_changes"], nested["data_version"]) == (
                        outer["total_changes"], outer["data_version"],
                    )
                    assert [nested[name]["inode"] for name in ("db", "wal")] == [
                        outer[name]["inode"] for name in ("db", "wal")
                    ]
                    if checkpoint == "PASSIVE":
                        assert frames > 0
                        assert nested["db"] != outer["db"]
                        assert nested["wal"] == outer["wal"]
                    else:
                        assert outer["wal"]["size"] > nested["wal"]["size"] == 0
                    checkpoints.append(result)
                return original_sync()

            monkeypatch.setattr(commits, "_sync_replay_memo", sync_with_checkpoint)

        with _sdk_client(daemon) as client:
            reopened = Timeline.open(project_id, "main", client=client, outbox_path=tmp_path / "reopen.json")
            assert len(checkpoints) == (checkpoint is not None)
            rows = reopened.bundle["parent"]["config"]["tracks"]
            assert [(row["id"], row["kind"]) for row in rows][-len(tracks):] == tracks
            history = client.timelines.history(project_id, "main", limit=10)
            assert history.ok, history.error
            assert history.data["head"]["publication_id"] == accepted["receipt"]["receipt_id"]
    finally:
        daemon.stop()
