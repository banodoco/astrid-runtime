"""Runtime proves candidate derivation and retained bases before any writes."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from runtime_protocol.capture_validation import _candidate_document
from runtime_protocol.snapshot_refs import snapshot_bytes, snapshot_digest
from runtime_protocol.timeline_commit_port import digest
from runtime_protocol.util import canonical_json
from tests.test_capture_candidate_actual import (
    _candidate_snapshot,
    _claim_and_materialize,
    _request,
    candidate as candidate_fixture,
)
from tests.test_snapshot_authority_refusal import (
    CAPABILITY,
    CAPABILITY_DIGEST,
    _assert_refused_without_writes,
    _refresh_identity,
    _state,
)

pytestmark = pytest.mark.integration
candidate = candidate_fixture


def _rebind(snapshot, preview):
    """Refresh every caller-controlled hash/marker after changing the input."""
    marker = snapshot["metadata"]["working_copy"]
    marker.update(candidate_digest=preview["candidate_digest"],
                  publication_digest=preview["publication_digest"],
                  candidate_parent_revision_id=preview["publication"]["parent_revision_id"])
    for key in ("capture_authority", "canonical_timeline"):
        authority = snapshot["metadata"][key]
        authority.update(parent_revision_id=preview["publication"]["parent_revision_id"],
                         parent_content_digest=preview["publication"]["content_digest"])
        authority["expansion"].update(parent_revision_id=authority["parent_revision_id"],
                                       parent_content_digest=authority["parent_content_digest"],
                                       working_copy=deepcopy(marker))
    _refresh_identity(snapshot)


def _refuse_before_projection(case, snapshot, preview, inline, monkeypatch, message):
    # A surviving Agent verifier must not be the reason this forgery refuses.
    def unexpected_projection(*args, **kwargs):
        raise AssertionError("Runtime must refuse before invoking the projector")

    monkeypatch.setattr(case.service._timeline_commit_provider, "project_capture", unexpected_projection)
    request = _request(case, snapshot, preview, inline=inline)
    error = _assert_refused_without_writes(case.service, request)
    assert message in str(error)


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_publication_must_derive_from_forwarded_candidate(candidate, inline, monkeypatch):
    snapshot, preview = _candidate_snapshot(candidate)
    publication = preview["publication"]
    publication["parent_composition"]["config"]["opaque_parent_config"] = {"forged": True}
    publication["content_digest"] = digest(publication["parent_composition"])
    preview["publication_digest"] = digest(publication)
    _rebind(snapshot, preview)
    _refuse_before_projection(candidate, snapshot, preview, inline, monkeypatch,
                              "is not derived from candidate")


@pytest.mark.parametrize("field", [
    "base_parent_payload", "base_payload", "base_internal_timeline", "base_placements",
    "placement_source", "shot_source", "runtime_document",
])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_embedded_candidate_base_must_equal_retained_base(candidate, inline, field, monkeypatch):
    from astrid.core.timeline.authoring_bundle import preview_authoring_candidate

    snapshot, original = _candidate_snapshot(candidate)
    bundle = deepcopy(original["candidate"])
    shot = next(iter(bundle["shots"].values()))
    placement = bundle["placements"][0]["occurrence_id"]
    if field == "base_parent_payload":
        target = bundle[field]
    elif field in {"base_payload", "base_internal_timeline"}:
        target = shot[field]
    elif field == "base_placements":
        target = bundle[field][placement]
    elif field == "placement_source":
        target = bundle["source_mapping"]["placements"][placement]
    elif field == "shot_source":
        target = next(iter(bundle["source_mapping"]["shots"].values()))
    else:
        bundle["source_mapping"]["_runtime_document"] = deepcopy(candidate.document)
        target = bundle["source_mapping"]["_runtime_document"]["parent_revision"]["payload"]
    target["opaque_forgery"] = {"fresh_hashes": True}
    # The real pure compiler accepts this self-consistent candidate. Its claim
    # about the immutable base still needs Runtime's independent comparison.
    preview = preview_authoring_candidate(bundle)
    assert preview["candidate_digest"] != original["candidate_digest"]
    _rebind(snapshot, preview)
    _refuse_before_projection(candidate, snapshot, preview, inline, monkeypatch, "differs from saved base")


@pytest.mark.parametrize("change", ["parent", "child"])
def test_candidate_comparison_uses_detached_pure_inputs(candidate, change):
    snapshot, preview = _candidate_snapshot(candidate, change)
    before = deepcopy((candidate.document, preview))
    request = _request(candidate, snapshot, preview, inline=False)
    ref = request["spec"]["authority_context"]["capture_snapshot_ref"]
    commits, _ = candidate.service._timeline_commits()
    _candidate_document(commits, candidate.document, preview, ref, candidate.service._timeline_commit_provider)
    assert (candidate.document, preview) == before
    task = candidate.service.create_task(request)["task"]
    claim = candidate.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                          "runtime_epoch": candidate.service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    assert claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"] == ref
    assert ref["source_kind"] == "working_copy"
    assert commits.revision_closure(candidate.project, "main", "parent-1") == before[0]


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_missing_candidate_construction_fails_certification_closed(candidate, inline, monkeypatch):
    snapshot, preview = _candidate_snapshot(candidate)
    monkeypatch.delattr(type(candidate.service._timeline_commit_provider), "capture_candidate_inputs")
    _refuse_before_projection(candidate, snapshot, preview, inline, monkeypatch,
                              "canonical capture candidate provider is unavailable")


@pytest.mark.parametrize("native", [False, True], ids=["candidate-less", "explicit-cas"])
def test_uncertified_preview_does_not_require_candidate_provider(candidate, native, monkeypatch):
    snapshot, preview = _candidate_snapshot(candidate)
    provider = candidate.service._timeline_commit_provider
    monkeypatch.setattr(provider, "capture_candidate_inputs", None, raising=False)
    request = _request(candidate, snapshot, preview if native else None, inline=False, native=native)
    task = candidate.service.create_task(request)["task"]
    claim = candidate.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                          "runtime_epoch": candidate.service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    ref = claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
    assert ref == {"digest": request["spec"]["authority_context"]["capture_snapshot_ref"]["digest"],
                   "project_id": candidate.project, "timeline_id": "main", "source_kind": "cas"}
    assert candidate.service._timeline_commits()[0].revision_closure(
        candidate.project, "main", "parent-1") == candidate.document


def _compile_snapshot(case, bundle):
    from astrid.core.timeline.authoring_bundle import preview_authoring_candidate
    from astrid.sdk.timeline_filmstrip import prepare_filmstrip

    preview = preview_authoring_candidate(bundle)
    snapshot = prepare_filmstrip({"composed_capture": True, "timeline_ref": "main",
                                  "authoring_preview": preview},
                                 project=case.project, client=case.client)["capture_snapshot"]
    return snapshot, preview


def _rename_shot(bundle, *, clone=False):
    identity = next(iter(bundle["shots"]))
    renamed = "opaque-alias::not-a-source-parser"
    shot = deepcopy(bundle["shots"][identity]) if clone else bundle["shots"].pop(identity)
    shot["shot_id"] = renamed
    if clone:
        shot["payload"]["items"][0]["item_id"] = "cloned-item"
        row = deepcopy(bundle["placements"][0])
        row["occurrence_id"] = "cloned-occurrence"
        bundle["placements"].append(row)
    else:
        row = bundle["placements"][0]
    row["shot_id"] = renamed
    bundle["shots"][renamed] = shot
    sources = bundle["source_mapping"]["shots"]
    sources[renamed] = deepcopy(sources[identity]) if clone else sources.pop(identity)
    return renamed


@pytest.mark.parametrize("field", [
    "extra_base_placement", "unused_placement_source", "unused_shot_source",
    "removed_placement_source", "removed_shot_source", "renamed_shot_base",
    "renamed_shot_source", "new_placement_source", "cloned_shot_base",
    "unused_alias_source", "placement_alias_source", "created_shot_base",
    "unused_null_placement_source", "unused_null_shot_source",
])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_every_advertised_base_and_source_is_retained(candidate, field, inline, monkeypatch):
    bundle = deepcopy(candidate.bundle)
    placement = bundle["placements"][0]["occurrence_id"]
    shot_id = next(iter(bundle["shots"]))
    source = bundle["source_mapping"]
    if field == "extra_base_placement":
        bundle["base_placements"]["unretained"] = {"occurrence_id": "unretained", "forged": True}
    elif field == "unused_placement_source":
        source["placements"]["unretained"] = {"occurrence_id": "unretained", "forged": True}
    elif field == "unused_shot_source":
        source["shots"]["unretained"] = {"forged": True}
    elif field == "removed_placement_source":
        bundle["placements"] = []
        source["placements"][placement]["forged"] = True
    elif field == "removed_shot_source":
        bundle["placements"] = []
        bundle["shots"] = {}
        source["shots"][shot_id]["content_digest"] = "sha256:" + "0" * 64
    elif field in {"renamed_shot_base", "renamed_shot_source", "cloned_shot_base"}:
        renamed = _rename_shot(bundle, clone=field == "cloned_shot_base")
        if field == "renamed_shot_source":
            source["shots"][renamed]["content_digest"] = "sha256:" + "0" * 64
        else:
            for key in ("base_payload", "base_internal_timeline"):
                bundle["shots"][renamed][key]["forged"] = True
    elif field == "new_placement_source":
        row = deepcopy(bundle["placements"][0])
        row["occurrence_id"] = "new-occurrence"
        bundle["placements"].append(row)
        source["placements"]["new-occurrence"] = {**deepcopy(row), "forged": True}
    elif field == "unused_alias_source":
        source["shots"]["unused-alias"] = {**deepcopy(source["shots"][shot_id]), "forged": True}
    elif field == "placement_alias_source":
        source["placements"]["unused-alias"] = {**deepcopy(source["placements"][placement]), "forged": True}
    elif field == "created_shot_base":
        shot = bundle["shots"].pop(shot_id)
        shot["shot_id"] = "new-with-false-base"
        bundle["shots"][shot["shot_id"]] = shot
        bundle["placements"][0]["shot_id"] = shot["shot_id"]
        shot.update(_created=True, base_payload={"forged": True}, base_internal_timeline={})
    elif field == "unused_null_placement_source":
        source["placements"]["unretained"] = None
    else:
        source["shots"]["unretained"] = None
    # Rebuild the entire real capture after structural edits. A stale snapshot
    # must not provide an unrelated refusal that conceals a missed source claim.
    snapshot, preview = _compile_snapshot(candidate, bundle)
    before = canonical_json((candidate.document, bundle, snapshot, preview))
    _refuse_before_projection(candidate, snapshot, preview, inline, monkeypatch, "differs from saved base")
    assert canonical_json((candidate.document, bundle, snapshot, preview)) == before


@pytest.mark.parametrize("change", [
    "new_shot", "new_occurrence", "clone", "rename", "delete_occurrence",
    "delete_shot", "prune_deleted_sources", "recorded_clone",
])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_real_structural_drafts_keep_certification(candidate, change, inline):
    bundle = deepcopy(candidate.bundle)
    if change == "new_shot":
        bundle["shots"]["brand-new"] = {
            "shot_id": "brand-new", "_created": True,
            "base_payload": {}, "base_internal_timeline": {},
            "payload": {"items": []},
            "internal_timeline": {"tracks": [], "clips": []},
        }
        row = deepcopy(bundle["placements"][0])
        row.update(occurrence_id="brand-new-occurrence", shot_id="brand-new")
        bundle["placements"].append(row)
    elif change == "new_occurrence":
        row = deepcopy(bundle["placements"][0])
        row["occurrence_id"] = "brand-new-occurrence"
        bundle["placements"].append(row)
    elif change in {"clone", "rename"}:
        _rename_shot(bundle, clone=change == "clone")
    elif change == "recorded_clone":
        from astrid.sdk.timeline.commands import execute
        bundle = execute(bundle, [{"schema_version": 1, "op": "occurrence.duplicate", "version": "1",
                                  "select": "occurrence:occ-1",
                                  "args": {"occurrence_id": "new-occurrence", "shot_id": "new-shot"},
                                  "intent": {"ownership": "occurrence"}}]).bundle
    else:
        bundle["placements"] = []
        if change != "delete_occurrence":
            bundle["shots"] = {}
        if change == "prune_deleted_sources":
            bundle["source_mapping"] = {"shots": {}, "placements": {}}
    snapshot, preview = _compile_snapshot(candidate, bundle)
    before = canonical_json((candidate.document, bundle, snapshot, preview))
    request = _request(candidate, snapshot, preview, inline=inline)
    task = candidate.service.create_task(request)["task"]
    claim = candidate.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                          "runtime_epoch": candidate.service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    ref = claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
    assert ref["source_kind"] == "working_copy"
    assert ref["working_copy"]["candidate_digest"] == preview["candidate_digest"]
    assert candidate.service._timeline_commits()[0].revision_closure(
        candidate.project, "main", "parent-1") == candidate.document
    assert canonical_json((candidate.document, bundle, snapshot, preview)) == before


@pytest.mark.parametrize("number", [0.25, 1.0], ids=["fractional", "integral-float"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_node_stringify_preserves_existing_canonical_number_policy(candidate, number, inline):
    bundle = deepcopy(candidate.bundle)
    bundle["parent"]["config"]["opaque_number"] = number
    snapshot, preview = _compile_snapshot(candidate, bundle)
    node = os.environ.get("ASTRID_NODE_EXECUTABLE") or shutil.which("node")
    assert node, "the actual JSON.stringify check requires Node"
    wire = json.loads(subprocess.run(
        [node, "-e", "process.stdout.write(JSON.stringify(JSON.parse(require('fs').readFileSync(0, 'utf8'))))"],
        input=canonical_json(preview), text=True, capture_output=True, check=True).stdout)
    request = _request(candidate, snapshot, wire, inline=inline)
    if number == 1.0:
        # The existing Python canonical recipe distinguishes 1.0 from 1.
        # Node's normalization changes a frozen candidate's bytes; refreshed
        # caller markers must not substitute for this exact hash/custody rule.
        assert canonical_json(wire) != canonical_json(preview)
        assert wire["candidate"]["parent"]["config"]["opaque_number"] == number
        _assert_refused_without_writes(candidate.service, request)
    else:
        assert canonical_json(wire) == canonical_json(preview)
        task = candidate.service.create_task(request)["task"]
        claim = candidate.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                              "runtime_epoch": candidate.service.health()["runtime_epoch"]})
        assert claim["task_id"] == task["id"]
        assert claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]["source_kind"] == "working_copy"


@pytest.mark.parametrize("value", [False, 0.0], ids=["bool", "float"])
@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_fresh_hashes_do_not_change_saved_json_number_identity(candidate, value, inline, monkeypatch):
    bundle = deepcopy(candidate.bundle)
    assert canonical_json(bundle["base_placements"]["occ-1"]["source_offset"]) == "0"
    bundle["base_placements"]["occ-1"]["source_offset"] = value
    snapshot, preview = _compile_snapshot(candidate, bundle)
    _refuse_before_projection(candidate, snapshot, preview, inline, monkeypatch, "differs from saved base")


def test_provider_cannot_mutate_callers_verified_inputs(candidate, monkeypatch):
    snapshot, preview = _candidate_snapshot(candidate)
    request = _request(candidate, snapshot, preview, inline=False)
    ref = request["spec"]["authority_context"]["capture_snapshot_ref"]
    provider = candidate.service._timeline_commit_provider
    real = provider.capture_candidate_inputs

    def mutate_detached_inputs(document, *, candidate):
        result = real(document, candidate=candidate)
        document["parent_revision"]["payload"]["config"]["provider_mutation"] = True
        candidate["parent"]["config"]["provider_mutation"] = True
        return result

    monkeypatch.setattr(provider, "capture_candidate_inputs", mutate_detached_inputs)
    before = canonical_json((candidate.document, preview, ref))
    state = _state(candidate.service)
    _candidate_document(candidate.service._timeline_commits()[0], candidate.document, preview, ref, provider)
    assert canonical_json((candidate.document, preview, ref)) == before
    assert _state(candidate.service) == state


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
@pytest.mark.parametrize("change", ["parent", "child"])
def test_real_candidate_reaches_verified_host_without_mutating_inputs(candidate, tmp_path, inline, change):
    snapshot, preview = _candidate_snapshot(candidate, change)
    before = canonical_json((candidate.document, snapshot, preview))
    request = _request(candidate, snapshot, preview, inline=inline)
    task, values = _claim_and_materialize(candidate, request, tmp_path / "attempt")
    binding = values.timeline_source.read()
    ref = task["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
    assert binding == {"ref": ref, "snapshot": snapshot,
                       "authority": snapshot["metadata"]["capture_authority"],
                       "prepared": {key: {"path": str(Path(values[field]).resolve()),
                                          "digest": "sha256:" + hashlib.sha256(Path(values[field]).read_bytes()).hexdigest()}
                                    for key, field in (("timeline", "timeline"), ("registry", "assets_registry"))}}
    assert ref["source_kind"] == "working_copy"
    assert json.loads(Path(values["timeline"]).read_text()) == snapshot["config"]
    assert candidate.service.create_task(request)["task"]["id"] == task["id"]
    assert canonical_json((candidate.document, snapshot, preview)) == before


# Preserve the independent 31-case verifier corpus from current-capture-pair;
# the numeric cases use the fixture's existing saved integer source_offset.
@pytest.mark.parametrize("damage", [
    "kind", "head", "candidate_digest", "publication_digest", "publication",
    "project_id", "timeline_id", "base_parent", "base_parent_payload",
    "base_placements", "source", "child_base", "internal_base", "embedded_base",
    "retained_pin", "candidate_after_freeze", "json_bool", "json_float", "reused_pin",
    "publication_derivation", "source_mapping_shape", "source_shots_shape",
    "base_placements_shape", "placement_sources_shape", "base_placement_identity",
    "base_placement_payload", "placements_shape", "placement_shape", "shots_shape",
    "shot_shape", "child_source",
])
def test_runtime_candidate_verifier_covers_removed_agent_checks(candidate, damage):
    from astrid.core.timeline.authoring_bundle import preview_authoring_candidate
    from astrid.sdk.timeline.commit import bundle_from_document
    from runtime_protocol.capture_validation import _candidate_document
    from runtime_protocol.errors import ConflictError, ValidationError
    from runtime_protocol.timeline_commit import CommitRejected

    bundle = bundle_from_document(candidate.document)
    bundle["parent"]["config"]["opaque_draft"] = [None, False, 0, 2.0]
    identity = next(iter(bundle["shots"]))
    if damage in {"project_id", "timeline_id"}:
        bundle[damage] = "foreign"
    elif damage == "base_parent":
        bundle[damage]["revision_id"] = "other-parent"
    elif damage in {"base_parent_payload", "base_placements"}:
        bundle[damage]["forged"] = True
    elif damage == "source":
        bundle["source_mapping"]["placements"] = {}
    elif damage in {"child_base", "internal_base"}:
        key = "base_payload" if damage == "child_base" else "base_internal_timeline"
        bundle["shots"][identity][key]["forged"] = True
    elif damage == "embedded_base":
        bundle["source_mapping"]["_runtime_document"]["project_id"] = "foreign"
    elif damage in {"retained_pin", "reused_pin"}:
        key = "internal_timeline_content_digest" if damage == "retained_pin" else "content_digest"
        bundle["source_mapping"]["shots"][identity][key] = "sha256:" + "0" * 64
    elif damage in {"json_bool", "json_float"}:
        # JSON false/0.0 differ from the exact saved integer zero.
        bundle["base_placements"]["occ-1"]["source_offset"] = (
            False if damage == "json_bool" else 0.0)
    preview = preview_authoring_candidate(bundle)
    frozen = preview["candidate"]
    if damage == "source_mapping_shape":
        frozen["source_mapping"] = []
    elif damage == "source_shots_shape":
        frozen["source_mapping"]["shots"] = []
    elif damage == "base_placements_shape":
        frozen["base_placements"] = []
    elif damage == "placement_sources_shape":
        frozen["source_mapping"]["placements"] = []
    elif damage in {"base_placement_identity", "base_placement_payload"}:
        row = next(iter(frozen["base_placements"].values()))
        row["occurrence_id" if damage == "base_placement_identity" else "gain"] = (
            "foreign" if damage == "base_placement_identity" else 2)
    elif damage == "placements_shape":
        frozen["placements"] = {}
    elif damage == "placement_shape":
        frozen["placements"] = [None]
    elif damage == "shots_shape":
        frozen["shots"] = []
    elif damage == "shot_shape":
        frozen["shots"][identity] = None
    elif damage == "child_source":
        frozen["source_mapping"]["shots"][identity]["content_digest"] = "sha256:" + "0" * 64
    # Keep hashes self-consistent, including for malformed candidate bases.
    preview["candidate_digest"] = digest(frozen)
    ref = {"revision_id": preview["publication"]["parent_revision_id"], "working_copy": {
        "candidate_digest": preview["candidate_digest"], "publication_digest": preview["publication_digest"],
        "base_revision_id": candidate.document["parent_revision"]["revision_id"],
        "base_revision_digest": candidate.document["parent_revision"]["content_digest"]}}
    if damage in {"kind", "candidate_digest", "publication_digest", "head", "publication"}:
        preview[damage] = {} if damage in {"head", "publication"} else "forged"
    elif damage == "candidate_after_freeze":
        preview["candidate"]["parent"]["config"]["opaque_draft"] = "changed after freezing"
    elif damage == "publication_derivation":
        preview["candidate"]["parent"]["config"]["opaque_draft"] = "different authored result"
        preview["candidate_digest"] = digest(preview["candidate"])
        ref["working_copy"]["candidate_digest"] = preview["candidate_digest"]
    commits, _ = candidate.service._timeline_commits()
    before = _state(candidate.service)
    try:
        # Exercise Runtime's verifier directly so Agent's still-present checks
        # cannot conceal a missing Runtime check before their proposed deletion.
        with pytest.raises((ConflictError, ValidationError, CommitRejected)):
            _candidate_document(commits, candidate.document, preview, ref,
                                candidate.service._timeline_commit_provider)
    finally:
        assert _state(candidate.service) == before



def _saved_snapshot(case):
    from astrid.sdk.timeline_filmstrip import prepare_filmstrip

    snapshot = prepare_filmstrip({"composed_capture": True, "timeline_ref": "main",
                                  "revision_id": "parent-1"},
                                 project=case.project, client=case.client)["capture_snapshot"]
    projection = case.service._timeline_commit_provider.project_capture(case.document)
    assert projection == {"config": snapshot["config"], "registry": snapshot["registry"],
                          "expansion": snapshot["metadata"]["capture_authority"]["expansion"]}
    return snapshot


def _saved_request(case, snapshot, *, inline, native=False):
    context = {"mode": "composed_capture", "project_id": case.project, "timeline_id": "main",
               "capture_snapshot": snapshot}
    if not native:
        context["revision_id"] = snapshot["metadata"]["capture_authority"]["parent_revision_id"]
    if not inline:
        context.pop("capture_snapshot")
        digest = snapshot_digest(snapshot)
        result = case.service.ingest(case.project, snapshot_bytes(snapshot), media_type="application/json",
                                     idempotency_key="saved-" + digest.removeprefix("sha256:"))
        assert result["data"]["object_id"] == digest
        ref = {"digest": digest, "project_id": case.project, "timeline_id": "main", "source_kind": "cas"}
        if not native:
            authority = snapshot["metadata"]["capture_authority"]
            ref.update(source_kind="revision", revision_id=authority["parent_revision_id"],
                       revision_digest=authority["parent_content_digest"])
        context["capture_snapshot_ref"] = ref
    return {"project": case.project, "capability_id": CAPABILITY, "capability_digest": CAPABILITY_DIGEST,
            "input_object_ids": [case.media], "idempotency_key": "actual-saved",
            "spec": {"authority_context": context, "inputs": {"filmstrip_authority": canonical_json(context)}}}


@pytest.mark.parametrize("native", [False, True], ids=["saved", "native"])
@pytest.mark.parametrize("inline", [False, True], ids=["ref", "inline"])
def test_actual_saved_and_native_reach_claim_and_host(candidate, tmp_path, native, inline):
    snapshot = _saved_snapshot(candidate)
    if native:
        snapshot["metadata"].pop("capture_authority")
        snapshot["metadata"].pop("canonical_timeline")
    request = _saved_request(candidate, snapshot, inline=inline, native=native)
    before = _state(candidate.service)
    task, values = _claim_and_materialize(candidate, request, tmp_path / "attempt")
    ref = task["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
    assert ref["source_kind"] == ("cas" if native else "revision")
    assert candidate.service.object(ref["digest"])[1] == snapshot_bytes(snapshot)
    assert json.loads(Path(values["timeline"]).read_text()) == snapshot["config"]
    if native:
        assert values.timeline_source is None
    else:
        binding = values.timeline_source.read()
        assert binding["snapshot"] == snapshot
        assert binding["authority"] == snapshot["metadata"]["capture_authority"]
        assert binding["ref"] == ref
    assert candidate.service.create_task(request)["task"]["id"] == task["id"]
    assert candidate.service._timeline_commits()[0].revision_closure(
        candidate.project, "main", "parent-1") == candidate.document
    after = _state(candidate.service)
    assert after["staging"] == before["staging"]
    assert all(after["CAS"][name] == payload for name, payload in before["CAS"].items())


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "ref"])
def test_saved_certification_does_not_require_candidate_method(candidate, inline, monkeypatch):
    snapshot = _saved_snapshot(candidate)
    monkeypatch.setattr(candidate.service._timeline_commit_provider, "capture_candidate_inputs", None)
    task = candidate.service.create_task(_saved_request(candidate, snapshot, inline=inline))["task"]
    claim = candidate.service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                          "runtime_epoch": candidate.service.health()["runtime_epoch"]})
    assert claim["task_id"] == task["id"]
    assert claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]["source_kind"] == "revision"


@pytest.mark.parametrize("field", ["config", "registry", "shot_digest"])
@pytest.mark.parametrize("inline", [False, True], ids=["ref", "inline"])
def test_original_saved_forgeries_refuse_before_writes(candidate, field, inline):
    from tests.test_snapshot_authority_refusal import _refresh_identity

    snapshot = _saved_snapshot(candidate)
    if field == "config":
        snapshot["config"]["clips"][0]["hold"] = 123
    elif field == "registry":
        next(iter(snapshot["registry"]["assets"].values()))["opaque_asset"] = "not from the immutable source"
    else:
        for key in ("capture_authority", "canonical_timeline"):
            snapshot["metadata"][key]["expansion"]["shots"][0]["content_digest"] = "sha256:" + "0" * 64
    _refresh_identity(snapshot)
    request = _saved_request(candidate, snapshot, inline=inline)
    _assert_refused_without_writes(candidate.service, request)


@pytest.mark.parametrize("field", ["config", "registry", "shot_digest"])
@pytest.mark.parametrize("inline", [False, True], ids=["ref", "inline"])
def test_fresh_working_copy_semantic_forgeries_refuse_before_writes(candidate, field, inline):
    snapshot, preview = _candidate_snapshot(candidate)
    if field == "config":
        snapshot["config"]["clips"][0]["hold"] = 123
    elif field == "registry":
        next(iter(snapshot["registry"]["assets"].values()))["opaque_asset"] = "not from the immutable source"
    else:
        for key in ("capture_authority", "canonical_timeline"):
            snapshot["metadata"][key]["expansion"]["shots"][0]["content_digest"] = "sha256:" + "0" * 64
    _refresh_identity(snapshot)
    _assert_refused_without_writes(candidate.service, _request(candidate, snapshot, preview, inline=inline))
