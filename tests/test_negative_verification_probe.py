"""A negative verification output must not authorize final publication."""
import pytest

from runtime_protocol.errors import VerificationReceiptMissingError
from test_runtime_child_delegation import (
    CHILD, IDENTITY, OTHER, admit_stage, claim, publication_journey, runtime,
    stage_settlement,
)


def test_failed_verification_receipt_probe(runtime):
    service, _ = runtime
    parent, policy, _, associations, _ = publication_journey(runtime, through="compose")
    admitted = admit_stage(service, parent, policy, "verify", associations)
    verify = claim(service, OTHER, "claim-failed-verification-probe")
    assert admitted["task"]["id"] == verify["task_id"]
    service.settle_attempt(
        verify["attempt_id"], stage_settlement(service, verify, b'{"candidate_verified":false}', "verification"),
        idempotency_key="failed-verification-probe", identity=IDENTITY,
    )
    associations[("verify", "verification")] = service.managed_outputs(verify["task_id"])[0]
    admit_stage(service, parent, policy, "final", associations)
    final = claim(service, CHILD, "claim-final-verification-probe")
    before = service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0]
    with pytest.raises(VerificationReceiptMissingError) as exc:
        service.settle_attempt(
            final["attempt_id"], stage_settlement(service, final, b"composed-candidate-video", "verified_candidate"),
            idempotency_key="final-verification-probe", identity=IDENTITY,
        )
    assert exc.value.code == "verification_receipt_missing"
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == before
    assert service.managed_outputs(final["task_id"]) == []
    assert service.task(final["task_id"])["task"]["status"] == "running"
