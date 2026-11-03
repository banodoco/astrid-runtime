"""Durable conservative transitions do not confer native authority."""
import copy
import json
import os
import stat

import pytest

from astrid_runtime._realm_fence import FenceUnavailable
from astrid_runtime.lifecycle_transfer import begin_transfer
from test_lifecycle_transfer_session import fixture


def envelope(session, binding, request_id, phase="observed"):
    return dict(operation_id=binding["operation_id"], generation=binding["generation"],
                request_id=request_id, expected_phase=phase, binding_digest=session.binding_digest)


def test_recovery_transition_is_durable_and_replayable(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        args = envelope(session, binding, "recover")
        result = session.require_recovery(**args, reason="lease_uncertain")
        assert result == {"code": "recovery_required", "stage": "recovery_required",
                          "lifecycle_side_effect": False, "sequence": 1,
                          "phase": "recovery_required"}
        assert session.require_recovery(**args, reason="lease_uncertain") == result
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            session.require_recovery(**args, reason="unknown_identity")
        with pytest.raises(FenceUnavailable, match="stale_phase"):
            session.record_request(**envelope(session, binding, "stale"))
        assert session.record_request(**envelope(session, binding, "observe", "recovery_required"))["sequence"] == 2
        assert session._custody is None
    with begin_transfer(config, binding=binding) as session:
        assert session.query()["phase"] == "recovery_required"
        assert session.require_recovery(**args, reason="lease_uncertain") == result
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            session.request_transition(**args, target_phase="committed")
        other = copy.deepcopy(binding)
        other["generation"] = "other"
        with begin_transfer(config, binding=other) as changed:
            with pytest.raises(FenceUnavailable, match="binding_changed"):
                changed.query()


@pytest.mark.parametrize("target,code", [
    ("prepared", "recovery_required"), ("held_provisional", "recovery_required"),
    ("restart_fenced", "restart_unfenced"), ("held_admitted", "incomplete_census"),
    ("preparing_data", "recovery_required"), ("selected", "recovery_required"),
    ("writer_claimed", "lease_uncertain"), ("ready", "lease_uncertain"),
    ("commit_intent", "lease_uncertain"), ("commit_decided", "lease_uncertain"),
    ("detach_committed", "lease_uncertain"), ("committed", "lease_uncertain"),
    ("finalize_release", "lease_uncertain"), ("rollback_intent", "lease_uncertain"),
    ("rollback_decided", "lease_uncertain"), ("rolled_back_stopped", "lease_uncertain"),
    ("unknown", "unsupported_transfer"), ("recovery_required", "recovery_required"),
])
def test_native_and_out_of_order_transitions_refuse_and_replay(tmp_path, target, code):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        args = envelope(session, binding, "one")
        result = session.request_transition(**args, target_phase=target)
        assert result == {"code": code, "stage": "transition_refused",
                          "lifecycle_side_effect": False, "sequence": 1}
        assert session.request_transition(**args, target_phase=target) == result
        assert session.query()["phase"] == "observed"
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            session.request_transition(**args, target_phase=target + "-changed")
        with pytest.raises(FenceUnavailable, match="stale_phase"):
            session.request_transition(**envelope(session, binding, "two", "ready"), target_phase=target)
    with begin_transfer(config, binding=binding) as session:
        assert session.request_transition(**args, target_phase=target) == result
        assert session._custody is None


def test_no_exit_from_recovery_or_stale_generation(tmp_path):
    config, _, _, binding = fixture(tmp_path)
    with begin_transfer(config, binding=binding) as session:
        session.require_recovery(**envelope(session, binding, "one"), reason="unknown_identity")
        args = envelope(session, binding, "two", "recovery_required")
        assert session.request_transition(**args, target_phase="committed")["code"] == "lease_uncertain"
        assert session.query()["phase"] == "recovery_required"
        args["request_id"] = "three"
        args["generation"] = "stale"
        with pytest.raises(FenceUnavailable, match="binding_changed"):
            session.require_recovery(**args, reason="unknown_identity")


def test_recovery_write_lost_reply_and_corrupt_history(tmp_path, monkeypatch):
    config, _, _, binding = fixture(tmp_path)
    path = config.runtime_support / "lifecycle-transfer-ledger.json"
    real_fsync = os.fsync
    with begin_transfer(config, binding=binding) as session:
        args = envelope(session, binding, "one")
        def fail_dir(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("lost reply")
            return real_fsync(fd)
        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", fail_dir)
            with pytest.raises(FenceUnavailable, match="durability_failed"):
                session.require_recovery(**args, reason="unknown_identity")
        assert session.require_recovery(**args, reason="unknown_identity")["sequence"] == 1
    ledger = json.loads(path.read_bytes())
    ledger["requests"][0]["result"]["phase"] = "committed"
    path.write_text(json.dumps(ledger, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(FenceUnavailable, match="invalid ledger"):
            session.query()
