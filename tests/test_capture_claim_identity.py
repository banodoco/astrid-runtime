"""Preserve independently verified capture claims with shared CAS bytes."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest

from runtime_protocol.capture_validation import claim_capture_view, validate_capture
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.snapshot_refs import snapshot_digest
from runtime_protocol.util import canonical_json
from tests.test_capture_candidate_actual import (
    _candidate_snapshot,
    _request,
    candidate as actual_candidate_fixture,
)
from tests.test_snapshot_authority_refusal import (
    CAPABILITY,
    CAPABILITY_DIGEST,
    _ref,
    _state,
    capture as saved_fixture,
)

pytestmark = pytest.mark.integration

ALIASES = ("filmstrip_snapshot", "input_snapshot", "capture_snapshot")


@pytest.fixture
def saved(tmp_path):
    fixture = saved_fixture.__wrapped__(tmp_path)
    try:
        yield next(fixture)
    finally:
        fixture.close()


@pytest.fixture
def actual_candidate(tmp_path, astrid_importable):
    fixture = actual_candidate_fixture.__wrapped__(tmp_path, astrid_importable)
    try:
        yield next(fixture)
    finally:
        fixture.close()


def _persisted(service):
    names = [row[0] for row in service.store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ) if row[0] == "task_specs" or row[0].startswith("timeline_") or row[0] in (
        "parent_composition_revisions", "shot_revisions", "timeline_revisions",
        "internal_timeline_revisions", "shot_revision_heads",
        "composition_revision_occurrences", "composition_revision_dependencies",
    )]
    return {
        name: sorted(
            (tuple(row) for row in service.store.conn.execute('SELECT * FROM "' + name + '"')),
            key=repr,
        )
        for name in names
    }


def _admit_saved(service, project, media, alias, bad, good):
    outer = {"project_id": project, "timeline_id": "main", "revision_id": "parent-1",
             alias + "_ref": bad}
    inner = deepcopy(outer)
    inner[alias + "_ref"] = good
    spec = {
        "input_object_ids": [media],
        "schema_version": "1",
        "capability_digest": CAPABILITY_DIGEST,
        "authority_context": deepcopy(outer),
        "spec": {"authority_context": deepcopy(inner), "inputs": {
            "filmstrip_authority": canonical_json(inner),
            "argv": ["--authority", canonical_json({"nested": [outer]})],
        }},
    }
    task = service.store.create_task(
        CAPABILITY,
        spec,
        project,
        idempotency_key="claim-identity-saved-" + alias,
        capability_digest=CAPABILITY_DIGEST,
    )["task"]
    return spec, task


def _claim(service):
    return service.claim_next({
        "executor_id": "probe",
        "capability_ids": [CAPABILITY],
        "runtime_epoch": service.health()["runtime_epoch"],
    })


def _assert_saved_state_and_retry(service, project, spec, task, before, alias):
    assert service.store.get_task(task["id"])["task"]["spec"] == task["spec"]
    assert _persisted(service) == before[0]
    after = _state(service)
    assert after["CAS"] == before[1]
    assert after["staging"] == before[2]
    retry = service.store.create_task(
        CAPABILITY,
        spec,
        project,
        idempotency_key="claim-identity-saved-" + alias,
        capability_digest=CAPABILITY_DIGEST,
    )["task"]
    assert retry["id"] == task["id"]
    assert retry["spec"] == task["spec"]


@pytest.mark.parametrize("alias", ALIASES)
def test_same_digest_saved_valid_nested_invalid_outer_preserves_valid_claim(saved, alias):
    service, project, _, snapshot, media = saved
    good = _ref(service, project, snapshot)
    bad = {**good, "revision_digest": "sha256:" + "0" * 64}
    assert callable(service._timeline_commit_provider.project_capture)
    assert validate_capture(service, snapshot, good, {}) is True
    with pytest.raises(RuntimeErrorBase):
        validate_capture(service, snapshot, bad, {})

    spec, task = _admit_saved(service, project, media, alias, bad, good)
    before = (_persisted(service), _state(service)["CAS"], _state(service)["staging"])
    result = _claim(service)
    _assert_saved_state_and_retry(service, project, spec, task, before, alias)

    key = alias + "_ref"
    assert result["spec"]["authority_context"][key] == {
        "digest": good["digest"], "project_id": project,
        "timeline_id": "main", "source_kind": "cas",
    }
    assert result["spec"]["spec"]["authority_context"][key] == good
    assert json.loads(result["spec"]["spec"]["inputs"]["filmstrip_authority"])[key] == good
    listed = json.loads(result["spec"]["spec"]["inputs"]["argv"][1])["nested"][0]
    assert listed[key] == {"digest": bad["digest"], "project_id": project,
                           "timeline_id": "main", "source_kind": "cas"}


@pytest.mark.parametrize("alias", ALIASES)
def test_same_digest_candidate_valid_nested_invalid_outer_preserves_valid_claim(actual_candidate, alias):
    snapshot, preview = _candidate_snapshot(actual_candidate)
    request = _request(actual_candidate, snapshot, preview, inline=False)
    inner = request["spec"]
    good = inner["authority_context"].pop("capture_snapshot_ref")
    inner["authority_context"][alias + "_ref"] = good
    bad = deepcopy(good)
    bad["working_copy"]["candidate_digest"] = "sha256:" + "0" * 64
    bad["revision_digest"] = bad["working_copy"]["candidate_digest"]
    assert callable(actual_candidate.service._timeline_commit_provider.project_capture)
    assert validate_capture(actual_candidate.service, snapshot, good, inner["inputs"]) is True
    with pytest.raises(RuntimeErrorBase):
        validate_capture(actual_candidate.service, snapshot, bad, inner["inputs"])

    outer = {**deepcopy(inner["authority_context"]), alias + "_ref": bad}
    spec = {"authority_context": outer, "spec": inner}
    inner["inputs"]["filmstrip_authority"] = canonical_json(inner["authority_context"])
    inner["inputs"]["argv"] = [canonical_json([outer, inner["authority_context"]])]
    before = deepcopy(spec)
    result = claim_capture_view(actual_candidate.service, spec)

    assert spec == before
    assert result["authority_context"][alias + "_ref"]["source_kind"] == "cas"
    assert result["spec"]["authority_context"][alias + "_ref"] == good
    assert json.loads(result["spec"]["inputs"]["filmstrip_authority"])[alias + "_ref"] == good
    listed = json.loads(result["spec"]["inputs"]["argv"][0])
    assert listed[0][alias + "_ref"]["source_kind"] == "cas"
    assert listed[1][alias + "_ref"] == good
    assert snapshot_digest(snapshot) == good["digest"]
