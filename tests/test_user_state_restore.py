from __future__ import annotations

from contextlib import closing

import pytest

from runtime_protocol.errors import ConflictError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore


ALICE = {"actor": "alice"}
BOB = {"actor": "bob"}
KEYS = ("agent.choices", "agent.compute-profiles", "state-imports", "ext.demo", "generation")
DOCUMENTS = {
    "hidden-shots": ("ui.hidden-shots", {"shot_ids": ["shot-1"]}),
    "inpaint-strokes": ("ui.inpaint-strokes", {"strokes": [{"x": 1, "y": 2}]}),
    "join-clips": ("ui.join-clips", {"clips": ["clip-1", "clip-2"]}),
}
DIGEST = "sha256:" + "a" * 64
FIRST_CHOICES = {"agent": "first"}
SECOND_CHOICES = {"agent": "second"}


def service(root):
    RealmStore.initialize(root).close()
    return RuntimeService(root)


def app_state(value, actor):
    return {key: value.get_app_state(key, identity=actor) for key in KEYS}


def snapshot(service):
    current = service.current_project("alice")
    project_id = current["project"]["project_id"]
    return {
        "alice": app_state(service, ALICE),
        "bob": app_state(service, BOB),
        "current_project": current,
        # The public read returns the effective (workspace-first) selection.
        # Include both underlying rows so losing the shadowed user selection fails.
        "selections": [
            dict(row) for row in service.store.conn.execute(
                "SELECT actor_id, scope, project_id, updated_at FROM project_selections "
                "WHERE actor_id=? ORDER BY scope", ("alice",)
            )
        ],
        "documents": {
            document_id: service.get_document(project_id, document_id)
            for document_id in DOCUMENTS
        },
        "grants": service.list_grants(identity=ALICE),
        "grant_document": service.get_app_state("grants.pack", identity=ALICE),
    }


def seed_state(value):
    project = value.create_project({"slug": "demo", "name": "Demo"})
    first = value.update_app_state("agent.choices", FIRST_CHOICES, 0, "alice-first", identity=ALICE)
    value.update_app_state("agent.choices", SECOND_CHOICES, 1, "alice-second", identity=ALICE)
    for key in KEYS[1:]:
        value.update_app_state(key, {"setting": key}, 0, "alice-" + key, identity=ALICE)
    value.update_app_state("agent.choices", {"agent": "bob"}, 0, "bob-first", identity=BOB)
    value.select_project("alice", project["id"], scope="user")
    assert value.current_project("alice")["scope"] == "user"
    value.select_project("alice", project["id"], scope="workspace")
    for document_id, (kind, content) in DOCUMENTS.items():
        value.create_document(
            project["id"], {"document_id": document_id, "kind": kind, "content": content},
            idempotency_key="doc-" + document_id,
        )
    value.approve_grant("pack", "approved-pack", DIGEST, "approve-first", identity=ALICE)
    revoked = value.approve_grant("pack", "revoked-pack", DIGEST, "approve-second", identity=ALICE)
    value.revoke_grant(revoked["grant_id"], "revoke-second", identity=ALICE)
    return first


def backup_restore(value, tmp_path):
    backup = tmp_path / "backup"
    restored = tmp_path / "restored"
    value.backup(backup)
    value.restore(backup, restored)
    return restored


def test_backup_and_restore_keep_user_state(tmp_path):
    with closing(service(tmp_path / "realm")) as original:
        seed_state(original)
        before = snapshot(original)
        assert before["alice"]["agent.choices"]["version"] == 2
        assert all(before["alice"][key]["version"] == 1 for key in KEYS[1:])
        assert before["bob"]["agent.choices"]["content"] == {"agent": "bob"}
        assert before["current_project"]["scope"] == "workspace"
        assert {row["scope"] for row in before["selections"]} == {"user", "workspace"}
        assert {grant["state"] for grant in before["grants"]} == {"approved", "revoked"}
        restored_root = backup_restore(original, tmp_path)
    with closing(RuntimeService(restored_root)) as restored:
        assert snapshot(restored) == before


def test_restored_runtime_replays_old_writes_and_refuses_stale_writers(tmp_path):
    with closing(service(tmp_path / "realm")) as original:
        first = seed_state(original)
        before = snapshot(original)
        restored_root = backup_restore(original, tmp_path)
    with closing(RuntimeService(restored_root)) as restored:
        assert restored.update_app_state(
            "agent.choices", FIRST_CHOICES, 0, "alice-first", identity=ALICE
        ) == first
        assert snapshot(restored) == before
        with pytest.raises(ConflictError):
            restored.update_app_state("agent.choices", {"agent": "stale"}, 1, "stale", identity=ALICE)
        assert snapshot(restored) == before
        updated = restored.update_app_state(
            "agent.choices", {"agent": "third"}, 2, "alice-third", identity=ALICE
        )
        assert updated["data"]["version"] == 3
        assert app_state(restored, BOB) == before["bob"]


def test_restore_from_before_a_revocation_is_corrected_by_the_export(tmp_path):
    early = tmp_path / "early-backup"
    late = tmp_path / "late-backup"
    early_root = tmp_path / "early-restored"
    late_root = tmp_path / "late-restored"
    with closing(service(tmp_path / "realm")) as original:
        first = original.approve_grant("pack", "demo-pack", DIGEST, "approve", identity=ALICE)
        grant_id = first["grant_id"]
        original.backup(early)
        revoked = original.revoke_grant(grant_id, "revoke", identity=ALICE)
        export = original.export_revocations(identity=ALICE)
        assert revoked["state"] == "revoked"
        assert export == [{
            "grant_id": grant_id, "kind": "pack", "subject": "demo-pack",
            "digest": DIGEST, "generation": 1,
        }]
        original.backup(late)
        original.restore(early, early_root)
        original.restore(late, late_root)
    with closing(RuntimeService(early_root)) as restored:
        def status():
            return restored.grant_status("pack", "demo-pack", DIGEST, identity=ALICE)

        assert status()["state"] == "approved"
        assert restored.apply_revocations(export, "apply", identity=ALICE) == {
            "applied": 1, "ignored_newer": 0,
        }
        assert status()["state"] == "revoked" and not status()["authorized"]
        revoked_row = restored.get_app_state("grants.pack", identity=ALICE)
        assert restored.approve_grant("pack", "demo-pack", DIGEST, "approve", identity=ALICE) == first
        assert restored.get_app_state("grants.pack", identity=ALICE) == revoked_row
        assert not status()["authorized"]
        with pytest.raises(ConflictError):
            restored.approve_grant("pack", "demo-pack", DIGEST, "implicit", identity=ALICE)
        renewed = restored.reapprove_grant(grant_id, "renew", identity=ALICE)
        assert renewed["generation"] == 2 and renewed["state"] == "approved"
        before = restored.list_grants(identity=ALICE)
        assert restored.apply_revocations(export, "stale-export", identity=ALICE) == {
            "applied": 0, "ignored_newer": 1,
        }
        assert restored.list_grants(identity=ALICE) == before
        assert status()["authorized"] and status()["generation"] == 2
    with closing(RuntimeService(late_root)) as restored:
        assert restored.list_grants(identity=ALICE) == [revoked]
        revoked_row = restored.get_app_state("grants.pack", identity=ALICE)
        assert restored.approve_grant("pack", "demo-pack", DIGEST, "approve", identity=ALICE) == first
        assert restored.get_app_state("grants.pack", identity=ALICE) == revoked_row
        assert not restored.grant_status("pack", "demo-pack", DIGEST, identity=ALICE)["authorized"]


def test_restored_reapproval_replay_does_not_revive_a_later_revocation(tmp_path):
    with closing(service(tmp_path / "realm")) as original:
        first = original.approve_grant("pack", "demo-pack", DIGEST, "approve", identity=ALICE)
        grant_id = first["grant_id"]
        original.revoke_grant(grant_id, "revoke-first", identity=ALICE)
        renewed = original.reapprove_grant(grant_id, "renew", identity=ALICE)
        original.revoke_grant(grant_id, "revoke-second", identity=ALICE)
        before = original.get_app_state("grants.pack", identity=ALICE)
        restored_root = backup_restore(original, tmp_path)
    with closing(RuntimeService(restored_root)) as restored:
        assert restored.reapprove_grant(grant_id, "renew", identity=ALICE) == renewed
        assert restored.get_app_state("grants.pack", identity=ALICE) == before
        assert restored.grant_status("pack", "demo-pack", DIGEST, identity=ALICE) == {
            "grant_id": grant_id, "state": "revoked", "authorized": False, "generation": 2,
        }


def test_user_state_documents_are_in_the_sqlite_backup_not_the_json_export(tmp_path):
    with closing(service(tmp_path / "realm")) as original:
        seed_state(original)
        before = snapshot(original)
        exported = original.export_structured()
        # Plan 35 tracks this gap; a future structured-export change should update this assertion.
        assert set(exported) == {
            "format_version", "exported_at", "realm", "projects", "objects",
            "project_objects", "media_relations", "documents", "runs", "tasks",
            "events", "capabilities", "executors", "reservations", "generations",
            "variants", "shots", "shot_items", "shot_text_bindings", "shot_text_binding_events",
        }
        restored_root = backup_restore(original, tmp_path)
    with closing(RuntimeService(restored_root)) as restored:
        assert snapshot(restored) == before
