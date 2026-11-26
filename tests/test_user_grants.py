from __future__ import annotations

import hashlib

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


ALICE = {"actor": "alice"}
BOB = {"actor": "bob"}
SUBJECT = "example-pack"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def service(tmp_path):
    root = tmp_path / 'realm'
    RealmStore.initialize(root).close()
    value = RuntimeService(root)
    yield value
    value.close()


def approve(service, key="approve", *, kind="pack", subject=SUBJECT, digest=DIGEST, identity=ALICE, credential_ref=None):
    return service.approve_grant(kind, subject, digest, key, identity=identity, credential_ref=credential_ref)


def status(service, *, kind="pack", subject=SUBJECT, digest=DIGEST, identity=ALICE):
    return service.grant_status(kind, subject, digest, identity=identity)


def test_grant_lifecycle_and_command_replay(service):
    expected_id = "pack-" + hashlib.sha256(canonical_json(["pack", SUBJECT, DIGEST]).encode()).hexdigest()[:24]
    assert status(service) == {"grant_id": expected_id, "state": "absent", "authorized": False, "generation": 0}
    assert service.list_grants(identity=ALICE) == []
    first = approve(service, credential_ref="ModelRef")
    assert first["grant_id"] == expected_id
    assert first["generation"] == 1 and first["state"] == "approved"
    assert first["approved_at"] and first["revoked_at"] is None
    assert approve(service, credential_ref="ModelRef") == first
    assert status(service) == {"grant_id": expected_id, "state": "approved", "authorized": True, "generation": 1}
    row = service.get_app_state("grants.pack", identity=ALICE)
    assert row["content"] == {"schema": "astrid.grants.v1", "kind": "pack", "grants": {
        expected_id: {k: v for k, v in first.items() if k not in ("grant_id", "kind")},
    }}
    assert approve(service, "unchanged") == first
    assert service.get_app_state("grants.pack", identity=ALICE) == row
    updated = approve(service, "replace-ref", credential_ref="NewRef")
    assert updated == {**first, "credential_ref": "NewRef"}
    revoked = service.revoke_grant(expected_id, "revoke", identity=ALICE)
    assert revoked["state"] == "revoked" and revoked["revoked_at"] and revoked["generation"] == 1
    assert status(service) == {"grant_id": expected_id, "state": "revoked", "authorized": False, "generation": 1}
    revoked_row = service.get_app_state("grants.pack", identity=ALICE)
    assert service.revoke_grant(expected_id, "revoke-again", identity=ALICE) == revoked
    with pytest.raises(ConflictError, match="re-approval is an explicit act") as error:
        approve(service, "implicit-reapprove")
    assert error.value.details == {"grant_id": expected_id}
    assert approve(service, credential_ref="ModelRef") == first
    assert service.get_app_state("grants.pack", identity=ALICE) == revoked_row
    assert status(service)["state"] == "revoked"
    renewed = service.reapprove_grant(expected_id, "renew", identity=ALICE)
    assert renewed["generation"] == 2 and renewed["state"] == "approved"
    assert renewed["revoked_at"] is None and renewed["credential_ref"] == "NewRef"
    assert status(service) == {"grant_id": expected_id, "state": "approved", "authorized": True, "generation": 2}
    renewed_row = service.get_app_state("grants.pack", identity=ALICE)
    assert service.reapprove_grant(expected_id, "renew-again", identity=ALICE) == renewed
    assert service.get_app_state("grants.pack", identity=ALICE) == renewed_row
    assert service.revoke_grant(expected_id, "revoke", identity=ALICE) == revoked
    assert status(service)["authorized"] is True
    final = service.revoke_grant(expected_id, "revoke-generation-2", identity=ALICE)
    assert final["generation"] == 2 and final["state"] == "revoked"
    assert service.reapprove_grant(expected_id, "renew", identity=ALICE) == renewed
    assert status(service) == {"grant_id": expected_id, "state": "revoked", "authorized": False, "generation": 2}


def test_actor_and_kind_isolation_and_reserved_keys(service):
    alice = approve(service)
    assert status(service, identity=BOB)["state"] == "absent"
    assert service.list_grants(identity=BOB) == []
    with pytest.raises(NotFoundError):
        service.revoke_grant(alice["grant_id"], "bob-revoke", identity=BOB)
    bob = approve(service, identity=BOB)
    assert bob["grant_id"] == alice["grant_id"]
    service.revoke_grant(alice["grant_id"], "alice-revoke", identity=ALICE)
    assert status(service, identity=BOB)["authorized"]
    assert not status(service)["authorized"]
    model = approve(service, kind="model")
    node = approve(service, kind="node")
    assert model["grant_id"] != node["grant_id"] != alice["grant_id"]
    assert service.list_grants("model", identity=ALICE) == [model]
    assert [g["grant_id"] for g in service.list_grants(identity=ALICE)] == sorted(
        [alice["grant_id"], model["grant_id"], node["grant_id"]])
    for key in ("grants.pack", "grants.model", "grants.node", "grants.other", "grants."):
        with pytest.raises(ValidationError, match="belong to the grant ledger"):
            service.update_app_state(key, {}, 0, "direct", identity=ALICE)
    assert service.get_app_state("grants.pack", identity=ALICE)["content"]["grants"][alice["grant_id"]]["state"] == "revoked"
    service.update_app_state("agent.choices", {"x": 1}, 0, "normal", identity=ALICE)
    assert service.get_app_state("agent.choices", identity=ALICE)["content"] == {"x": 1}


@pytest.mark.parametrize("kind", ["other", "", None, 7, []])
def test_invalid_kind(service, kind):
    with pytest.raises(ValidationError):
        approve(service, kind=kind)
    with pytest.raises(ValidationError):
        status(service, kind=kind)


@pytest.mark.parametrize("subject", ["", None, 7, [], "x" * 97])
def test_invalid_subject(service, subject):
    with pytest.raises(ValidationError):
        approve(service, subject=subject)


@pytest.mark.parametrize("digest", ["", None, 7, "a" * 64, "sha256:" + "A" * 64, "sha256:" + "a" * 63, DIGEST + "\n"])
def test_invalid_digest(service, digest):
    with pytest.raises(ValidationError):
        approve(service, digest=digest)


@pytest.mark.parametrize("ref", ["", 1, [], "9name", "with space", "a/b", "A" * 65,
                                 "sk-secret", "RPA_abc", "GhP_abc", "github_pat_x", "HF_abc", "xoxb-abc"])
def test_invalid_credential_reference(service, ref):
    with pytest.raises(ValidationError):
        approve(service, credential_ref=ref)


def test_unknown_grants_and_missing_identity(service):
    grant_id = status(service)["grant_id"]
    for method in (service.revoke_grant, service.reapprove_grant):
        with pytest.raises(NotFoundError):
            method(grant_id, "unknown", identity=ALICE)
        with pytest.raises(NotFoundError):
            method("bad-id", "unknown", identity=ALICE)
    with pytest.raises(AuthorizationError):
        approve(service, identity={})
    with pytest.raises(AuthorizationError):
        service.list_grants(identity=None)
    with pytest.raises(ConflictError):
        approve(service, "same", credential_ref="RefA")
        approve(service, "same", credential_ref="RefB")


def test_capacity_including_revoked_entries_and_tombstones(service):
    for i in range(32):
        subject = f"{i:02}" + "x" * 94
        entry = approve(service, f"approve-{i}", subject=subject, credential_ref="R" * 64)
        service.revoke_grant(entry["grant_id"], f"revoke-{i}", identity=ALICE)
    row = service.get_app_state("grants.pack", identity=ALICE)
    assert len(row["content"]["grants"]) == 32
    encoded = canonical_json(row["content"])
    assert len(encoded.encode("utf-8")) <= RuntimeService.APP_STATE_MAX_BYTES
    stored = service.store.conn.execute(
        "SELECT content_json FROM user_app_state WHERE actor_id=? AND key=?", ("alice", "grants.pack")
    ).fetchone()[0]
    assert stored == encoded
    with pytest.raises(ValidationError):
        approve(service, "overflow", subject="33rd")
    tombstone = {"grant_id": status(service, subject="33rd")["grant_id"], "kind": "pack",
                 "subject": "33rd", "digest": DIGEST, "generation": 1}
    with pytest.raises(ValidationError):
        service.apply_revocations([tombstone], "overflow-tombstone", identity=ALICE)
    assert service.get_app_state("grants.pack", identity=ALICE) == row
    assert approve(service, "other-kind", kind="node")["state"] == "approved"


def test_revocation_restore_and_stale_export(service, tmp_path):
    first = approve(service)
    service.revoke_grant(first["grant_id"], "revoke", identity=ALICE)
    second = approve(service, "second", kind="model", subject="other")
    service.revoke_grant(second["grant_id"], "revoke-second", identity=ALICE)
    export = service.export_revocations(identity=ALICE)
    assert export == sorted([
        {"grant_id": first["grant_id"], "kind": "pack", "subject": SUBJECT, "digest": DIGEST, "generation": 1},
        {"grant_id": second["grant_id"], "kind": "model", "subject": "other", "digest": DIGEST, "generation": 1},
    ], key=lambda item: item["grant_id"])
    root = tmp_path / "restored-realm"
    RealmStore.initialize(root).close()
    restored = RuntimeService(root)
    try:
        assert approve(restored)["grant_id"] == first["grant_id"]
        existing = [item for item in export if item["grant_id"] == first["grant_id"]]
        assert restored.apply_revocations(existing, "apply", identity=ALICE) == {"applied": 1, "ignored_newer": 0}
        assert status(restored)["state"] == "revoked"
        assert restored.apply_revocations(existing, "apply", identity=ALICE) == {"applied": 1, "ignored_newer": 0}
        assert restored.apply_revocations(existing, "apply-again", identity=ALICE) == {"applied": 0, "ignored_newer": 0}
        renewed = restored.reapprove_grant(first["grant_id"], "renew", identity=ALICE)
        assert renewed["generation"] == 2
        assert restored.apply_revocations(existing, "apply-stale", identity=ALICE) == {"applied": 0, "ignored_newer": 1}
        assert status(restored)["authorized"]
        assert restored.apply_revocations(export, "apply-all", identity=ALICE) == {"applied": 1, "ignored_newer": 1}
        assert status(restored, kind="model", subject="other")["state"] == "revoked"
        with pytest.raises(ConflictError):
            approve(restored, "tombstone", kind="model", subject="other")
        assert restored.export_revocations(identity=ALICE) == [item for item in export if item["grant_id"] == second["grant_id"]]
        assert restored.export_revocations(identity=BOB) == []
        newer = [{**existing[0], "generation": 4}]
        assert restored.apply_revocations(newer, "newer-revocation", identity=ALICE) == {"applied": 1, "ignored_newer": 0}
        assert status(restored)["generation"] == 4
        assert restored.reapprove_grant(first["grant_id"], "renew-newer", identity=ALICE)["generation"] == 5
        assert restored.apply_revocations(newer, "stale-newer", identity=ALICE) == {"applied": 0, "ignored_newer": 1}
    finally:
        restored.close()


@pytest.mark.parametrize("bad", [
    {"grant_id": "wrong"}, {"kind": "unknown"}, {"subject": ""}, {"digest": "bad"},
    {"generation": 0}, {"generation": True}, {"generation": 1.5}, {"generation": "1"},
])
def test_invalid_revocation_is_atomic(service, bad):
    entry = approve(service)
    valid = {"grant_id": entry["grant_id"], "kind": "pack", "subject": SUBJECT, "digest": DIGEST, "generation": 1}
    before = service.get_app_state("grants.pack", identity=ALICE)
    with pytest.raises(ValidationError):
        service.apply_revocations([valid, {**valid, **bad}], "invalid-list", identity=ALICE)
    assert service.get_app_state("grants.pack", identity=ALICE) == before
    assert status(service)["authorized"]
