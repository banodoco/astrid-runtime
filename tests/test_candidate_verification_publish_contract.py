"""Final publication consumes only a Runtime-owned verification record."""
import pytest

from runtime_protocol.errors import ConflictError
from test_runtime_child_delegation import (
    CHILD, IDENTITY, admit_stage, claim, load_task_spec, publication_journey,
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
    parent, policy, attempts, associations, _ = publication_journey(runtime, through="verify")
    spec = load_task_spec(service, attempts["verify"]["task_id"])
    if receipt_case != "missing":
        spec["candidate_verification_receipt"] = {
            "candidate_verified": receipt_case != "negative",
            "candidate_sha256": ("0" * 64 if receipt_case == "mismatch"
                                  else digest(MANIFEST).removeprefix("sha256:")),
            "verifier": "verify", "verified_at": "2026-01-01T00:00:00Z",
        }
        store_task_spec(service, attempts["verify"]["task_id"], spec)
    admit_stage(service, parent, policy, "final", associations)
    final = claim(service, CHILD, "claim-receipt-refusal")
    before = service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0]
    body = final_body(service, final)
    # A settlement caller cannot supply the Runtime-owned receipt.
    body["result"]["candidate_verification_receipt"] = {
        "candidate_verified": True, "candidate_sha256": digest(MANIFEST).removeprefix("sha256:"),
        "verifier": "verify", "verified_at": "2026-01-01T00:00:00Z"}
    with pytest.raises(ConflictError) as exc:
        service.settle_attempt(final["attempt_id"], body, idempotency_key="refuse-receipt", identity=IDENTITY)
    assert exc.value.code == code
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == before
    assert service.managed_outputs(final["task_id"]) == []
    assert service.task(final["task_id"])["task"]["status"] == "running"


def test_final_publication_accepts_matching_runtime_receipt(runtime):
    service, _ = runtime
    parent, policy, attempts, associations, _ = publication_journey(runtime, through="verify")
    # Simulate a Runtime-owned verifier writing its durable task record.
    spec = load_task_spec(service, attempts["verify"]["task_id"])
    spec["candidate_verification_receipt"] = {
        "candidate_verified": True,
        "candidate_sha256": digest(MANIFEST).removeprefix("sha256:"),
        "verifier": "verify", "verified_at": "2026-01-01T00:00:00Z",
    }
    store_task_spec(service, attempts["verify"]["task_id"], spec)
    admit_stage(service, parent, policy, "final", associations)
    final = claim(service, CHILD, "claim-receipt-accept")
    before = service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0]
    service.settle_attempt(final["attempt_id"], final_body(service, final),
                           idempotency_key="accept-receipt", identity=IDENTITY)
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == before + 1
    assert any(output["generation_id"] for output in service.managed_outputs(final["task_id"]))
