from __future__ import annotations

import hashlib

import pytest

pytest_plugins = ["test_timeline_commit_port"]

from test_timeline_commit_port import (
    PreparedProvider,
    commit,
    request,
    rows,
    use_provider,
)

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit_auth import (
    _SAFE_OBSERVATION_DETAIL_KEYS,
    _safe_observation_diagnostic,
    command_output,
)


def _missing_observation_action(step_ordinal=7, command_ordinal=11):
    def action(_, __):
        return command_output(
            {},
            {
                "writes": [{
                    "ref": "shot:REF_USER_SENTINEL",
                    "path": ["PATH_USER_SENTINEL"],
                    "before": {"state": "absent"},
                    "after": {"state": "present", "value": "PAYLOAD_USER_SENTINEL"},
                }],
                "derived_writes": [],
                "created": [],
            },
            {"bindings": [{
                "physical_ref": "timeline",
                "owner": "OWNER_USER_SENTINEL",
                "owners": ["OWNER_USER_SENTINEL"],
                "successor": "CONTINUATION_USER_SENTINEL",
            }]},
            step_ordinal=step_ordinal,
            command_ordinal=command_ordinal,
        )

    return action


def test_missing_observation_uses_production_refusal_serializer_and_no_write(service):
    body = request(service)
    before = rows(service)
    use_provider(service, PreparedProvider(_missing_observation_action()))

    with pytest.raises(RuntimeErrorBase) as caught:
        commit(service, body, key="missing-observation")

    failure = caught.value.as_dict()
    details = failure["details"]
    assert isinstance(details, dict)
    diagnostic = details.pop("safe_diagnostic")
    assert failure == {
        "code": "validation_error",
        "message": "provider intermediate command lacks an authenticated physical observation",
        "details": {
            "status": "refused",
            "reason": "invalid_records",
            "base": None,
            "current": None,
            "conflicts": [],
        },
    }
    assert diagnostic == {
        "verification_phase": "command_output",
        "step_ordinal": 7,
        "command_ordinal": 11,
        "captured_ref_present": True,
        "captured_path_present": True,
        "native_site_present": True,
        "physical_digest_present": False,
        "physical_digest_hash": "UNKNOWN",
        "creation_exemption": "created_root_or_projected_site",
        "creation_exemption_outcome": "NOT_APPLIED",
        "ownership_state": "PRESENT",
        "binding_state": "PRESENT",
        "continuation_state": "PRESENT",
    }
    assert rows(service) == before
    assert not any(
        sentinel in repr(diagnostic)
        for sentinel in (
            "REF_USER_SENTINEL", "PATH_USER_SENTINEL", "PAYLOAD_USER_SENTINEL",
            "OWNER_USER_SENTINEL", "CONTINUATION_USER_SENTINEL",
        )
    )


def test_missing_observation_diagnostic_is_closed_and_marks_unknowns():
    sentinel_digest = "sha256:" + "a" * 64
    diagnostic = _safe_observation_diagnostic(
        {},
        {"physical": {"content_digest": sentinel_digest}},
        None,
        None,
        {},
        step_ordinal=-1,
        command_ordinal=1_000_001,
    )

    assert tuple(diagnostic) == _SAFE_OBSERVATION_DETAIL_KEYS
    assert diagnostic["step_ordinal"] == "UNKNOWN"
    assert diagnostic["command_ordinal"] == "UNKNOWN"
    assert diagnostic["captured_ref_present"] is False
    assert diagnostic["captured_path_present"] is False
    assert diagnostic["native_site_present"] is False
    assert diagnostic["physical_digest_present"] is False
    assert diagnostic["physical_digest_hash"] == "UNKNOWN"
    assert diagnostic["ownership_state"] == "UNKNOWN"
    assert diagnostic["binding_state"] == "ABSENT"
    assert diagnostic["continuation_state"] == "UNKNOWN"
    assert sentinel_digest not in repr(diagnostic)
    assert all(type(diagnostic[key]) is bool for key in (
        "captured_ref_present", "captured_path_present", "native_site_present",
        "physical_digest_present",
    ))


def test_physical_digest_detail_is_one_way_when_a_digest_is_available():
    digest = "sha256:" + "b" * 64
    diagnostic = _safe_observation_diagnostic(
        {"ref": "physical", "path": []},
        {"physical": {"content_digest": digest}},
        "physical",
        [],
        {"bindings": []},
        step_ordinal=1,
        command_ordinal=2,
    )

    assert diagnostic["physical_digest_present"] is True
    assert diagnostic["physical_digest_hash"] == "sha256:" + hashlib.sha256(digest.encode("ascii")).hexdigest()
    assert digest not in repr(diagnostic)

