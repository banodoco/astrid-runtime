"""Consistency checks for proposed R18 wire results, not an evidence verifier.

The current transfer implementation has no wire evidence ingestion or native
verifier. Passing these checks never constructs or grants VerifiedEvidence.
A future verifier must validate the complete closed schemas, bind the records
and select the complete required field paths from trusted phase policy before
calling this guard; wire input must never select that policy.
"""

import re


class InvalidWireResult(ValueError):
    """A proposed wire result is malformed or internally contradictory."""


_CODES = frozenset({
    "none", "busy_owner", "unknown_identity", "binding_changed",
    "incomplete_census", "restart_unfenced", "busy_work",
    "unsupported_transfer", "lease_uncertain", "durability_failed",
    "recovery_required",
})
_REASONS = frozenset({
    "unreadable", "visibility", "raced", "missing_provenance",
    "unsupported_native", "unauthenticated", "incomplete", "expired",
    "mismatch", "io", "cancelled", "not_collected",
})
_FAILURES = frozenset({"refused", "unknown", "unsupported", "recovery_required"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_POINTER = re.compile(r"(?:/(?:[^~/]|~[01])*)*\Z")
_TOKEN = re.compile(r"[-A-Za-z0-9_.:/@+]{1,256}\Z")
_U64 = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def _invalid():
    raise InvalidWireResult("invalid or contradictory wire result")


def _text(value):
    if not isinstance(value, str) or "\0" in value:
        _invalid()
    try:
        if len(value.encode("utf-8")) > 4096:
            _invalid()
    except UnicodeEncodeError:
        _invalid()


def _pointer(value):
    _text(value)
    if not _POINTER.fullmatch(value):
        _invalid()


def _digest(value):
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        _invalid()


def _fault(fault):
    if type(fault) is not dict or set(fault) != {"field", "reason", "detail"}:
        _invalid()
    _pointer(fault["field"])
    if not isinstance(fault["reason"], str) or fault["reason"] not in _REASONS:
        _invalid()
    _text(fault["detail"])


def _ref(ref):
    if type(ref) is not dict or set(ref) != {"type", "digest", "byte_length"}:
        _invalid()
    if not isinstance(ref["type"], str) or not _TOKEN.fullmatch(ref["type"]):
        _invalid()
    _digest(ref["digest"])
    length = ref["byte_length"]
    if (not isinstance(length, str) or not _U64.fullmatch(length)
            or len(length) > 20 or int(length) > 18446744073709551615):
        _invalid()


def _common(record, success):
    if type(record) is not dict:
        _invalid()
    result, code = record.get("result"), record.get("code")
    faults, effects, refs = record.get("faults"), record.get("side_effects"), record.get("recovery_refs")
    if (not isinstance(result, str) or result not in _FAILURES | {success}
            or not isinstance(code, str) or code not in _CODES
            or type(faults) is not list or type(refs) is not list
            or not isinstance(effects, str) or effects not in {"none", "owned", "uncertain"}):
        _invalid()
    for fault in faults:
        _fault(fault)
    for ref in refs:
        _ref(ref)
    if result == success:
        if code != "none" or faults:
            _invalid()
    elif code == "none" or not faults:
        _invalid()
    if result == "unsupported" and (code != "unsupported_transfer" or
            not any(fault["reason"] == "unsupported_native" for fault in faults)):
        _invalid()
    if (result == "recovery_required" or effects != "none") and not refs:
        _invalid()
    return result


def _checks(checks, required_fields, positive):
    # required_fields is trusted verifier policy, never taken from a wire record.
    if type(required_fields) not in (set, frozenset) or not required_fields:
        _invalid()
    for field in required_fields:
        _pointer(field)
    if type(checks) is not list:
        _invalid()
    seen = {}
    for check in checks:
        if type(check) is not dict or set(check) != {
                "field", "producer_digest", "native_readback_digest", "result"}:
            _invalid()
        field, result, readback = check["field"], check["result"], check["native_readback_digest"]
        _pointer(field)
        if field in seen:
            _invalid()
        _digest(check["producer_digest"])
        if not isinstance(result, str) or result not in {"match", "mismatch", "unknown", "unsupported"}:
            _invalid()
        if type(readback) is not dict:
            _invalid()
        if readback.get("state") == "known" and set(readback) == {"state", "value", "evidence"}:
            _digest(readback["value"])
            _digest(readback["evidence"])
            if result == "match" and readback["value"] != check["producer_digest"]:
                _invalid()
            if result == "mismatch" and readback["value"] == check["producer_digest"]:
                _invalid()
        elif readback.get("state") == "unknown" and set(readback) == {"state", "reason", "evidence"}:
            if not isinstance(readback["reason"], str) or readback["reason"] not in _REASONS:
                _invalid()
            if readback["evidence"] is not None:
                _digest(readback["evidence"])
            if result in {"match", "mismatch"}:
                _invalid()
        else:
            _invalid()
        seen[field] = result
    if positive and any(seen.get(field) != "match" for field in required_fields):
        _invalid()


def validate_result_pair(header, verification, *, required_fields):
    """Reject F-1 contradictions; return no evidence or authorization.

    Header is the flattened evidence object. Its required checks live in the
    separately supplied Verification. This examines result-related fields only;
    schema, challenge, phase, provenance and independent native verification
    remain mandatory and are not implemented here.
    """
    header_result = _common(header, "observed")
    verification_result = _common(verification, "verified")
    _checks(verification.get("checks"), required_fields,
            header_result == "observed" or verification_result == "verified")
    if verification_result == "verified" and header_result != "observed":
        _invalid()
