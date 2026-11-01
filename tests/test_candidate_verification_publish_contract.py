"""Final publication consumes only a Runtime-owned verification record."""
import hashlib

import pytest

from runtime_protocol.errors import ConflictError
from test_runtime_child_delegation import (
    CHILD, IDENTITY, OTHER, add_verification_manifest, admit_stage, claim, load_task_spec, publication_journey,
    digest, publication_output, runtime, stage_settlement, store_task_spec,
)


MANIFEST = b'{"outputs":[]}'

def final_body(service, final):
    body = stage_settlement(service, final, b"composed-candidate-video", "verified_candidate")
    body["outputs"].insert(0, publication_output(MANIFEST, "manifest"))
    body["result"] = {"manifest_ref": {"object_id": digest(MANIFEST), "size": len(MANIFEST)}}
    return body


@pytest.mark.parametrize(
    ("receipt_case", "code"),
    [
        ("missing", "verification_receipt_missing"),
        ("negative", "candidate_not_verified"),
        ("mismatch", "verification_digest_mismatch"),
    ],
)
def test_final_publication_refuses_invalid_runtime_receipt(runtime, receipt_case, code):
    service, _ = runtime
    verification_data = (b'{"candidate_verified":false}' if receipt_case == "negative"
                         else b'{"candidate_verified":true}')
    parent, policy, attempts, associations, _ = publication_journey(
        runtime, through="verify", verification_data=verification_data)
    spec = load_task_spec(service, attempts["verify"]["task_id"])
    if receipt_case == "missing":
        del spec["candidate_verification_receipt"]
        store_task_spec(service, attempts["verify"]["task_id"], spec)
    elif receipt_case == "negative":
        assert spec["candidate_verification_receipt"]["candidate_verified"] is False
    admit_stage(service, parent, policy, "final", associations)
    final = claim(service, CHILD, "claim-receipt-refusal")
    before = service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0]
    body = final_body(service, final)
    if receipt_case == "mismatch":
        other_manifest = b'{"outputs":["different"]}'
        body["outputs"][0] = publication_output(other_manifest, "manifest")
        body["result"]["manifest_ref"] = {"object_id": digest(other_manifest), "size": len(other_manifest)}
    # A settlement caller cannot supply the Runtime-owned receipt.
    body["result"]["candidate_verification_receipt"] = {
        "candidate_verified": True, "candidate_sha256": digest(MANIFEST).removeprefix("sha256:"),
        "verifier": "verify", "verified_at": "2026-01-01T00:00:00Z"}
    before_db = list(service.store.conn.iterdump())
    def cas_snapshot():
        return {path.relative_to(service.cas.root): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in service.cas.root.rglob("*") if path.is_file()}
    before_cas = cas_snapshot()
    with pytest.raises(ConflictError) as exc:
        service.settle_attempt(final["attempt_id"], body, idempotency_key="refuse-receipt", identity=IDENTITY)
    assert exc.value.code == code
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == before
    assert service.managed_outputs(final["task_id"]) == []
    assert service.task(final["task_id"])["task"]["status"] == "running"
    assert list(service.store.conn.iterdump()) == before_db
    assert cas_snapshot() == before_cas


def test_final_publication_accepts_matching_runtime_receipt(runtime):
    service, _ = runtime
    parent, policy, attempts, associations, _ = publication_journey(runtime, through="verify")
    spec = load_task_spec(service, attempts["verify"]["task_id"])
    receipt = spec["candidate_verification_receipt"]
    assert receipt["candidate_verified"] is True
    assert receipt["candidate_sha256"] == digest(MANIFEST).removeprefix("sha256:")
    assert receipt["verifier"] == "verify" and receipt["verified_at"]
    admit_stage(service, parent, policy, "final", associations)
    final = claim(service, CHILD, "claim-receipt-accept")
    before = service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0]
    service.settle_attempt(final["attempt_id"], final_body(service, final),
                           idempotency_key="accept-receipt", identity=IDENTITY)
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == before + 1
    assert any(output["generation_id"] for output in service.managed_outputs(final["task_id"]))


def test_worker_supplied_digest_is_ignored(runtime):
    service, _ = runtime
    parent, policy, attempts, associations, _ = publication_journey(
        runtime, through="verify", verification_data=b'{"candidate_verified":true,"candidate_sha256":"' + b"0" * 64 + b'"}')
    receipt = load_task_spec(service, attempts["verify"]["task_id"])["candidate_verification_receipt"]
    assert receipt["candidate_sha256"] == digest(MANIFEST).removeprefix("sha256:")
    admit_stage(service, parent, policy, "final", associations)
    final = claim(service, CHILD, "claim-worker-digest")
    before = service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0]
    service.settle_attempt(final["attempt_id"], final_body(service, final),
                           idempotency_key="accept-worker-digest", identity=IDENTITY)
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == before + 1


def test_verification_receipt_rolls_back_with_failed_settlement(runtime, monkeypatch):
    service, _ = runtime
    parent, policy, _, associations, _ = publication_journey(runtime, through="compose")
    admit_stage(service, parent, policy, "verify", associations)
    verify = claim(service, OTHER, "claim-verification-rollback")
    body = add_verification_manifest(stage_settlement(
        service, verify, b'{"candidate_verified":true}', "verification"))
    def fail_association(*args, **kwargs):
        raise ConflictError("injected association failure")
    monkeypatch.setattr(service.store, "_associate_managed_outputs", fail_association)
    with pytest.raises(ConflictError, match="injected association failure"):
        service.settle_attempt(verify["attempt_id"], body,
                               idempotency_key="verification-rollback", identity=IDENTITY)
    assert "candidate_verification_receipt" not in load_task_spec(service, verify["task_id"])
    assert service.task(verify["task_id"])["task"]["status"] == "running"
    assert service.managed_outputs(verify["task_id"]) == []
