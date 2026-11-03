"""The local custody observation is not R18 admission evidence."""
import copy

import pytest

from astrid_runtime._realm_fence import FenceUnavailable
from astrid_runtime.lifecycle_transfer import (
    PreWriterEvidence, PreWriterPhase, begin_transfer,
)
from test_lifecycle_transfer_session import fixture
from test_lifecycle_transfer_transitions import envelope


def observe(session, binding, fence, *, target=PreWriterPhase.PREPARED,
            request_id="one", phase="observed", sequence=0, **changes):
    args = envelope(session, binding, request_id, phase)
    args.update(changes)
    return session.observe_pre_writer(provisional=fence, target=target,
                                      sequence=sequence, **args)


@pytest.mark.parametrize("target", list(PreWriterPhase))
def test_unavailable_pre_writer_states_leave_no_ledger_or_phase_change(tmp_path, target):
    config, _, _, binding = fixture(tmp_path)
    ledger = config.runtime_support / "lifecycle-transfer-ledger.json"
    with begin_transfer(config, binding=binding) as session:
        fence = session.pin_and_acquire_original()
        evidence = observe(session, binding, fence, target=target)
        reason = "installation authority" if target is PreWriterPhase.PREPARED else "stale_phase"
        with pytest.raises(FenceUnavailable, match=reason):
            session.transition_pre_writer(evidence=evidence)
        assert session.query() == {"phase": "observed", "requests": []}
        assert not ledger.exists()
        with pytest.raises(FenceUnavailable, match="consumed evidence"):
            session.transition_pre_writer(evidence=evidence)
    # A reopen requires a new live fence and a fresh observation; the same
    # request cannot turn a previous refusal into native proof.
    with begin_transfer(config, binding=binding) as reopened:
        with pytest.raises(FenceUnavailable, match="consumed evidence"):
            reopened.transition_pre_writer(evidence=evidence)
        fresh = observe(reopened, binding, reopened.pin_and_acquire_original(), target=target)
        with pytest.raises(FenceUnavailable, match=reason):
            reopened.transition_pre_writer(evidence=fresh)
        assert reopened.query()["phase"] == "observed"
        assert not ledger.exists()


@pytest.mark.parametrize("field,value", [
    ("operation_id", "other"), ("generation", "other"),
    ("binding_digest", "0" * 64), ("expected_phase", "prepared"),
])
def test_wrong_envelope_refused_without_ledger_write(tmp_path, field, value):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        evidence = observe(session, binding, session.pin_and_acquire_original(), **{field: value})
        with pytest.raises(FenceUnavailable, match="stale_phase|binding_changed"):
            session.transition_pre_writer(evidence=evidence)
        assert session.query() == {"phase": "observed", "requests": []}


def test_sequence_and_request_id_cannot_reinterpret_legacy_history(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        fence = session.pin_and_acquire_original()
        stale = observe(session, binding, fence)
        session.record_request(**envelope(session, binding, "legacy"))
        before = session.query()
        with pytest.raises(FenceUnavailable, match="stale_sequence"):
            session.transition_pre_writer(evidence=stale)
        reused = observe(session, binding, fence, request_id="legacy", sequence=1)
        with pytest.raises(FenceUnavailable, match="request ID already used"):
            session.transition_pre_writer(evidence=reused)
        fresh = observe(session, binding, fence, sequence=1)
        with pytest.raises(FenceUnavailable, match="installation authority"):
            session.transition_pre_writer(evidence=fresh)
        assert session.query() == before


def test_evidence_is_closed_session_bound_and_single_use(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(FenceUnavailable, match="fence not retained"):
            observe(session, binding, None)
        fence = session.pin_and_acquire_original()
        with pytest.raises(FenceUnavailable, match="unsupported_transfer"):
            observe(session, binding, fence, target="prepared")
        with pytest.raises(FenceUnavailable, match="unsupported_transfer"):
            observe(session, binding, fence, sequence=True)
        old = observe(session, binding, fence)
        fresh = observe(session, binding, fence)
        with pytest.raises(FenceUnavailable, match="consumed evidence"):
            session.transition_pre_writer(evidence=old)
        # Any consumption attempt invalidates the outstanding observation.
        with pytest.raises(FenceUnavailable, match="consumed evidence"):
            session.transition_pre_writer(evidence=fresh)
        with pytest.raises(FenceUnavailable, match="consumed evidence"):
            session.transition_pre_writer(evidence=PreWriterEvidence())
        with begin_transfer(config, binding=copy.deepcopy(binding)) as other:
            with pytest.raises(FenceUnavailable, match="fence not retained"):
                observe(other, binding, fence)
        assert session.query()["requests"] == []


def test_expired_and_changed_runtime_identity_are_refused(tmp_path, monkeypatch):
    config, root, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        fence = session.pin_and_acquire_original()
        monkeypatch.setattr("astrid_runtime.lifecycle_transfer.time.monotonic_ns", lambda: 1)
        expired = observe(session, binding, fence)
        monkeypatch.setattr("astrid_runtime.lifecycle_transfer.time.monotonic_ns", lambda: 10_000_000_002)
        with pytest.raises(FenceUnavailable, match="expired"):
            session.transition_pre_writer(evidence=expired)
        changed = observe(session, binding, fence)
        (root / "owner.lock").rename(root / "original.lock")
        (root / "owner.lock").write_text("replacement")
        with pytest.raises(FenceUnavailable, match="binding changed"):
            session.transition_pre_writer(evidence=changed)
        assert (root / "owner.lock").read_text() == "replacement"
        assert not (config.runtime_support / "lifecycle-transfer-ledger.json").exists()
