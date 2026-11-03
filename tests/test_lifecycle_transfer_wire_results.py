"""F-1 consistency checks do not grant native or transition authority."""
import copy
import itertools

import pytest

from runtime_protocol.lifecycle_transfer_wire_results import InvalidWireResult, validate_result_pair

DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
FAULT = {"field": "/manager", "reason": "incomplete", "detail": "unavailable"}
REF = {"type": "raw:journal", "digest": DIGEST, "byte_length": "1"}
REQUIRED = frozenset({"/manager", "/census"})


def check(field):
    return {"field": field, "producer_digest": DIGEST,
            "native_readback_digest": {"state": "known", "value": DIGEST, "evidence": OTHER},
            "result": "match"}


def records():
    header = {"result": "observed", "code": "none", "faults": [],
              "side_effects": "none", "recovery_refs": []}
    verification = {"result": "verified", "code": "none", "faults": [],
                    "side_effects": "none", "recovery_refs": [],
                    "checks": [check("/manager"), check("/census")]}
    return header, verification


def validate(header, verification, required=REQUIRED):
    return validate_result_pair(header, verification, required_fields=required)


@pytest.mark.parametrize("which,positive", [(0, "observed"), (1, "verified")])
@pytest.mark.parametrize("code,faults", list(itertools.product(["none", "busy_owner"], [[], [FAULT]])))
def test_success_requires_none_and_no_faults(which, positive, code, faults):
    pair = records()
    pair[which].update(result=positive, code=code, faults=faults)
    if code == "none" and not faults:
        assert validate(*pair) is None
    else:
        with pytest.raises(InvalidWireResult):
            validate(*pair)


@pytest.mark.parametrize("which", [0, 1])
@pytest.mark.parametrize("result", ["refused", "unknown", "unsupported", "recovery_required"])
@pytest.mark.parametrize("code_present,fault_present", list(itertools.product([False, True], repeat=2)))
def test_failure_requires_code_and_fault(which, result, code_present, fault_present):
    pair = records()
    # A rejected Header cannot be accompanied by a positive Verification.
    pair[1].update(result="refused", code="busy_owner", faults=[FAULT])
    code = "unsupported_transfer" if result == "unsupported" else "busy_owner"
    fault = {**FAULT, "reason": "unsupported_native"} if result == "unsupported" else FAULT
    pair[which].update(result=result, code=code if code_present else "none",
                       faults=[fault] if fault_present else [],
                       recovery_refs=[REF] if result == "recovery_required" else [])
    if code_present and fault_present:
        assert validate(*pair) is None
    else:
        with pytest.raises(InvalidWireResult):
            validate(*pair)


@pytest.mark.parametrize("header_result,verification_result", [("observed", "refused"), ("refused", "verified"), ("observed", "verified")])
@pytest.mark.parametrize("mutation", ["missing", "mismatch", "unknown", "unsupported", "duplicate", "lying_match", "missing_evidence"])
def test_required_checks_are_positive_before_success(header_result, verification_result, mutation):
    header, verification = records()
    if header_result == "refused":
        header.update(result="refused", code="busy_owner", faults=[FAULT])
    if verification_result == "refused":
        verification.update(result="refused", code="busy_owner", faults=[FAULT])
    checks = verification["checks"]
    if mutation == "missing":
        checks.pop()
    elif mutation == "duplicate":
        checks.append(copy.deepcopy(checks[0]))
    elif mutation == "lying_match":
        checks[1]["native_readback_digest"]["value"] = OTHER
    elif mutation == "missing_evidence":
        del checks[1]["native_readback_digest"]["evidence"]
    elif mutation == "mismatch":
        checks[1]["result"] = "mismatch"
        checks[1]["native_readback_digest"]["value"] = OTHER
    else:
        checks[1]["result"] = mutation
        checks[1]["native_readback_digest"] = {"state": "unknown", "reason": "not_collected", "evidence": None}
    with pytest.raises(InvalidWireResult):
        validate(header, verification)


def test_phase_inapplicable_unknown_is_allowed_but_not_accepted_as_required():
    header, verification = records()
    extra = check("/optional")
    extra.update(result="unknown", native_readback_digest={"state": "unknown", "reason": "not_collected", "evidence": None})
    verification["checks"].append(extra)
    assert validate(header, verification) is None
    with pytest.raises(InvalidWireResult):
        validate(header, verification, REQUIRED | {"/optional"})


def test_failure_checks_can_report_unmatched_fields_but_not_be_forged():
    header, verification = records()
    header.update(result="unknown", code="incomplete_census", faults=[FAULT])
    verification.update(result="refused", code="incomplete_census", faults=[FAULT], checks=[])
    assert validate(header, verification) is None
    verification["checks"] = [check("/manager")]
    verification["checks"][0]["result"] = "mismatch"
    with pytest.raises(InvalidWireResult):
        validate(header, verification)


def test_verified_cannot_upgrade_refused_header():
    header, verification = records()
    header.update(result="refused", code="busy_owner", faults=[FAULT])
    with pytest.raises(InvalidWireResult):
        validate(header, verification)


@pytest.mark.parametrize("which", [0, 1])
def test_recovery_and_unsupported_rules_are_preserved(which):
    pair = records()
    pair[1].update(result="refused", code="busy_owner", faults=[FAULT])
    record = pair[which]
    for result, code, faults, effects, refs in [
        ("unsupported", "busy_owner", [FAULT], "none", []),
        ("unsupported", "unsupported_transfer", [FAULT], "none", []),
        ("recovery_required", "recovery_required", [FAULT], "none", []),
        ("refused", "busy_owner", [FAULT], "owned", []),
        ("unknown", "busy_owner", [FAULT], "uncertain", []),
    ]:
        record.update(result=result, code=code, faults=faults, side_effects=effects, recovery_refs=refs)
        with pytest.raises(InvalidWireResult):
            validate(*pair)
    record.update(result="refused", code="busy_owner", faults=[FAULT], side_effects="owned", recovery_refs=[REF])
    assert validate(*pair) is None


@pytest.mark.parametrize("required", [set(), frozenset(), [], {"bad~pointer"}])
def test_missing_or_invalid_trusted_phase_policy_refuses(required):
    with pytest.raises(InvalidWireResult):
        validate(*records(), required)


@pytest.mark.parametrize("which,field,value", [
    (0, "result", "verified"), (1, "result", "observed"), (0, "code", "invented"),
    (1, "faults", None), (0, "side_effects", []), (1, "recovery_refs", [None]),
    (0, "faults", [{"field": "/x", "reason": [], "detail": "x"}]),
])
def test_malformed_result_related_values_refuse(which, field, value):
    pair = records()
    pair[which][field] = value
    with pytest.raises(InvalidWireResult):
        validate(*pair)


@pytest.mark.parametrize("alter", [False, True])
def test_serialized_results_cannot_be_consumed_by_current_session(tmp_path, alter):
    from astrid_runtime._realm_fence import FenceUnavailable
    from astrid_runtime.lifecycle_transfer import begin_transfer
    from test_lifecycle_transfer_session import fixture

    config, _, _, binding = fixture(tmp_path)
    header, verification = records()
    if alter:
        verification["code"] = "busy_owner"
        with pytest.raises(InvalidWireResult):
            validate(header, verification)
    else:
        assert validate(header, verification) is None
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(FenceUnavailable, match="invalid or consumed evidence"):
            session.transition_pre_writer(evidence={"header": header, "verification": verification})
        assert session.query() == {"phase": "observed", "requests": []}
