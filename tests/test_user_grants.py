from __future__ import annotations

import hashlib

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json, now


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
    pytest.param({"generation": 10**20000}, id="unserializable-generation"),
])
def test_invalid_revocation_is_atomic(service, bad):
    entry = approve(service)
    valid = {"grant_id": entry["grant_id"], "kind": "pack", "subject": SUBJECT, "digest": DIGEST, "generation": 1}
    before = service.get_app_state("grants.pack", identity=ALICE)
    with pytest.raises(ValidationError):
        service.apply_revocations([valid, {**valid, **bad}], "invalid-list", identity=ALICE)
    assert service.get_app_state("grants.pack", identity=ALICE) == before
    assert status(service)["authorized"]


@pytest.mark.parametrize("character", ["\U0001f600", "\x00"])
@pytest.mark.parametrize("tombstone", [False, True], ids=["approval", "tombstone"])
def test_byte_capacity_preserves_room_for_revocation_and_reapproval(service, character, tombstone):
    accepted = []
    for index in range(RuntimeService.GRANT_LIMIT_PER_KIND):
        subject = f"{index:02}" + character * 94
        before = service.get_app_state("grants.pack", identity=ALICE)
        commands = service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0]
        try:
            if tombstone:
                entry = {"grant_id": status(service, subject=subject)["grant_id"], "kind": "pack",
                         "subject": subject, "digest": DIGEST, "generation": 9}
                assert service.apply_revocations([entry], f"wide-{index}", identity=ALICE) == {
                    "applied": 1, "ignored_newer": 0,
                }
            else:
                entry = approve(service, f"wide-{index}", subject=subject, credential_ref="R" * 64)
        except ValidationError as error:
            assert "bytes" in str(error)
            assert service.get_app_state("grants.pack", identity=ALICE) == before
            assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0] == commands
            break
        accepted.append(entry)
        row = service.get_app_state("grants.pack", identity=ALICE)
        assert len(canonical_json(row["content"]).encode("utf-8")) <= RuntimeService.APP_STATE_MAX_BYTES
    else:
        pytest.fail("maximum-length encoded subjects must reach the byte limit before the entry limit")

    assert accepted
    for entry in accepted:
        grant_id = entry["grant_id"]
        revoked = service.revoke_grant(grant_id, "revoke-" + grant_id, identity=ALICE)
        assert revoked["state"] == "revoked"
        row = service.get_app_state("grants.pack", identity=ALICE)
        assert len(canonical_json(row["content"]).encode("utf-8")) <= RuntimeService.APP_STATE_MAX_BYTES
    for entry in accepted:
        renewed = service.reapprove_grant(entry["grant_id"], "renew-" + entry["grant_id"], identity=ALICE)
        assert renewed["state"] == "approved" and renewed["generation"] == entry["generation"] + 1
        row = service.get_app_state("grants.pack", identity=ALICE)
        assert len(canonical_json(row["content"]).encode("utf-8")) <= RuntimeService.APP_STATE_MAX_BYTES


def test_oversize_revocation_batch_rolls_back_all_kinds_and_receipt(service):
    pack = approve(service)
    before = {kind: service.get_app_state("grants." + kind, identity=ALICE)
              for kind in RuntimeService.GRANT_KINDS}
    commands = service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0]
    entries = [{field: pack[field] for field in ("grant_id", "kind", "subject", "digest", "generation")}]
    for index in range(RuntimeService.GRANT_LIMIT_PER_KIND):
        subject = f"{index:02}" + "\x00" * 94
        entries.append({"grant_id": status(service, kind="node", subject=subject)["grant_id"],
                        "kind": "node", "subject": subject, "digest": DIGEST, "generation": 1})
    with pytest.raises(ValidationError, match="bytes"):
        service.apply_revocations(entries, "oversize-import", identity=ALICE)
    assert {kind: service.get_app_state("grants." + kind, identity=ALICE)
            for kind in RuntimeService.GRANT_KINDS} == before
    assert service.store.conn.execute("SELECT COUNT(*) FROM command_idempotency").fetchone()[0] == commands
    assert status(service)["authorized"]


def test_large_serializable_generation_is_preserved(service):
    entry = {"grant_id": status(service)["grant_id"], "kind": "pack", "subject": SUBJECT,
             "digest": DIGEST, "generation": 10**2000 - 1}
    assert service.apply_revocations([entry], "large-generation", identity=ALICE)["applied"] == 1
    assert status(service)["generation"] == entry["generation"]
    renewed = service.reapprove_grant(entry["grant_id"], "renew-large", identity=ALICE)
    assert renewed["generation"] == entry["generation"] + 1
    service.revoke_grant(entry["grant_id"], "revoke-large", identity=ALICE)
    assert not status(service)["authorized"]
    row = service.get_app_state("grants.pack", identity=ALICE)
    assert len(canonical_json(row["content"]).encode("utf-8")) <= RuntimeService.APP_STATE_MAX_BYTES


@pytest.mark.parametrize("existing", [False, True], ids=["new-tombstones", "older-approvals"])
def test_reapproval_uses_reserved_capacity_at_a_generation_boundary(service, existing):
    entries = []
    completed = {"schema": "astrid.grants.v1", "kind": "pack", "grants": {}}
    timestamp = now()
    for index in range(7):
        subject = str(index)
        grant_id = status(service, subject=subject)["grant_id"]
        generation = 10**(2000 if index < 6 else 20) - 2
        entries.append({"grant_id": grant_id, "kind": "pack", "subject": subject,
                        "digest": DIGEST, "generation": generation})
        completed["grants"][grant_id] = {
            "subject": subject, "digest": DIGEST, "state": "approved", "generation": generation + 1,
            "approved_at": timestamp, "revoked_at": timestamp,
        }
    # Use the real byte limit, with both lifecycle timestamps present. The
    # next requested generation fits exactly; demanding one more would not.
    padding = RuntimeService.APP_STATE_MAX_BYTES - len(canonical_json(completed).encode("utf-8"))
    assert 0 < padding < 4000
    entries[-1]["generation"] = 10**(20 + padding) - 2
    completed["grants"][entries[-1]["grant_id"]]["generation"] = entries[-1]["generation"] + 1
    assert len(canonical_json(completed).encode("utf-8")) == RuntimeService.APP_STATE_MAX_BYTES
    if existing:
        for entry in entries:
            approve(service, "older-" + entry["grant_id"], subject=entry["subject"])
    before = service.get_app_state("grants.pack", identity=ALICE)
    overflow = [*entries[:-1], {**entries[-1], "generation": entries[-1]["generation"] + 1}]
    with pytest.raises(ValidationError, match="bytes"):
        service.apply_revocations(overflow, "over-boundary", identity=ALICE)
    assert service.get_app_state("grants.pack", identity=ALICE) == before
    assert service.apply_revocations(entries, "boundary-import", identity=ALICE)["applied"] == len(entries)
    for index, entry in enumerate(entries):
        renewed = service.reapprove_grant(entry["grant_id"], "renew-" + entry["grant_id"], identity=ALICE)
        assert renewed["generation"] == entry["generation"] + 1 and renewed["state"] == "approved"
        if index % 2:
            assert service.apply_revocations([
                {**entry, "generation": renewed["generation"]},
            ], "revoke-" + entry["grant_id"], identity=ALICE)["applied"] == 1
        else:
            service.revoke_grant(entry["grant_id"], "revoke-" + entry["grant_id"], identity=ALICE)
        assert not status(service, subject=entry["subject"])["authorized"]
    row = service.get_app_state("grants.pack", identity=ALICE)
    assert len(canonical_json(row["content"]).encode("utf-8")) <= RuntimeService.APP_STATE_MAX_BYTES


def test_preferences_and_project_documents_cannot_write_grant_rows(service):
    entry = approve(service)
    service.revoke_grant(entry["grant_id"], "revoke", identity=ALICE)
    before = service.get_app_state("grants.pack", identity=ALICE)
    forged = {**before["content"], "grants": {entry["grant_id"]: {
        **before["content"]["grants"][entry["grant_id"]], "state": "approved", "revoked_at": None,
    }}}
    project = service.create_project({"slug": "grant-lookalikes", "name": "Grant lookalikes"})
    for scope in ("user", "project"):
        kwargs = {"project_id": project["id"]} if scope == "project" else {}
        for version in (0, 1):
            service.update_preferences(scope, canonical_json(forged), version,
                                       f"preferences-{scope}-{version}", identity=ALICE, **kwargs)
    service.create_document(project["id"], {
        "document_id": "grants.pack", "kind": "grants.pack", "content": forged,
    }, idempotency_key="lookalike-create")
    service.update_document(project["id"], "grants.pack", {
        "expected_version": 1, "content": forged,
    }, idempotency_key="lookalike-update")
    assert service.get_app_state("grants.pack", identity=ALICE) == before
    assert not status(service)["authorized"]
    assert status(service, identity=BOB)["state"] == "absent"
