"""Sealed request/provider-record controls through the real service and port."""
from __future__ import annotations

import copy

import pytest
import test_timeline_commit_port as port_tests
from baseline_fixture import load_baseline_fixture
from test_timeline_commit_port import commit, request, rows

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import (
    _coherent_materialization,
    _inverse_stage_restore_clip_order,
    command_output,
    site,
    validate_bindings,
    validate_claims,
)
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_validation import digest, validate_commit_value

service = port_tests.service


def test_authenticated_inverse_effect_accepts_only_derived_hydrated_parent_pin():
    payload = {"tracks": [{"id": "picture"}, {"id": "titles"}],
               "clips": [{"id": "chapter-one", "track": "titles"}]}
    parent = {"revision_id": "landing-parent", "content_digest": digest(payload), "payload": payload}
    boundary = {"parent": parent}
    change = {"op": "set", "ref": "parent", "path": ["clips"],
              "before": {"state": "present", "value": payload["clips"]},
              "value": [{"id": "chapter-one", "track": "titles"}]}
    expected = {"revision_id": "base", "publication_id": "publication"}
    request_value = {"base_revision_id": "base", "base_publication_id": "publication",
                     "commands": [{}]}
    step = {"id": "mixed-edit", "command_ordinals": [0], "patch": [change]}
    binding = {"key": "commit.effect", "ref": "parent", "physical_ref": "parent",
               "revision_id": "hydrated-parent", "content_digest": parent["content_digest"],
               "policy": "fixed", "dependencies": [], "path": change["path"], "effect_ordinal": 0,
               "boundary": {"base_revision_id": "base", "base_publication_id": "publication",
                            "evaluated_head": expected, "step_id": "mixed-edit", "command_ordinal": 0,
                            "phase": "effect", "side": "before"}}
    records = {"commands": [{"bindings": [binding]}]}

    def validate():
        validate_bindings(request_value, records, expected, boundary, boundary, step, 0, {}, boundary, boundary,
                          effect_boundaries={0: (boundary, boundary)}, input_parent_revision="hydrated-parent")

    validate()
    for field, forged in (("revision_id", "foreign-parent"),
                          ("content_digest", "sha256:" + "0" * 64)):
        original = binding[field]
        binding[field] = forged
        with pytest.raises(CommitRejected):
            validate()
        binding[field] = original


def test_inverse_stage_restores_clip_order_from_exact_source_selection():
    rows = [
        {"id": "first", "asset": "a", "extension": {"opaque": [None, {"keep": True}]}},
        {"id": "last", "asset": "b", "effects": [{"type": "fade"}]},
    ]
    boundary = {"parent": {"payload": {"config": {"clips": copy.deepcopy(rows)},
                                         "clips": copy.deepcopy(rows)}}}
    command = {"selections": [{"key": "collection.clips", "owner": "parent",
                                "query_version": 1, "policy": "guard-membership",
                                "members": ["parent/clip:last", "parent/clip:first"],
                                "order": ["parent/clip:last", "parent/clip:first"],
                                "boundaries": ["parent/clip:last", "parent/clip:first"]}]}

    _inverse_stage_restore_clip_order(boundary, command)

    expected = [rows[1], rows[0]]
    assert boundary["parent"]["payload"]["config"]["clips"] == expected
    assert boundary["parent"]["payload"]["clips"] == expected


@pytest.mark.parametrize("shape", [
    "both-lists", "payload-only", "config-only", "null-payload", "null-config",
])
def test_inverse_stage_restores_only_existing_clip_order_mirrors(shape):
    rows = [
        {"id": "first", "asset": "a", "extension": {"keep": True}},
        {"id": "last", "asset": "b", "effects": [{"type": "fade"}]},
    ]
    config = {"extension": "config-keep"}
    payload = {"extension": "payload-keep"}
    if shape in ("both-lists", "config-only", "null-payload"):
        config["clips"] = copy.deepcopy(rows)
    if shape in ("both-lists", "payload-only", "null-config"):
        payload["clips"] = copy.deepcopy(rows)
    if shape == "null-payload":
        payload["clips"] = None
    if shape == "null-config":
        config["clips"] = None
    payload["config"] = config
    boundary = {"parent": {"payload": payload}}
    expected_payload = copy.deepcopy(payload)
    expected_order = [rows[1], rows[0]]
    if isinstance(expected_payload["config"].get("clips"), list):
        expected_payload["config"]["clips"] = copy.deepcopy(expected_order)
    if isinstance(expected_payload.get("clips"), list):
        expected_payload["clips"] = copy.deepcopy(expected_order)
    command = {"selections": [{"key": "collection.clips", "owner": "parent",
                                "query_version": 1, "policy": "guard-membership",
                                "members": ["parent/clip:last", "parent/clip:first"],
                                "order": ["parent/clip:last", "parent/clip:first"],
                                "boundaries": ["parent/clip:last", "parent/clip:first"]}]}

    _inverse_stage_restore_clip_order(boundary, command)

    assert payload == expected_payload


def test_inverse_stage_refuses_divergent_clip_order_mirrors():
    config_rows = [{"id": "first"}, {"id": "last"}]
    payload_rows = [{"id": "last"}, {"id": "first"}]
    boundary = {"parent": {"payload": {"config": {"clips": config_rows},
                                         "clips": payload_rows}}}
    command = {"selections": [{"key": "collection.clips", "owner": "parent",
                                "query_version": 1, "policy": "guard-membership",
                                "members": ["parent/clip:last", "parent/clip:first"],
                                "order": ["parent/clip:last", "parent/clip:first"],
                                "boundaries": ["parent/clip:last", "parent/clip:first"]}]}

    with pytest.raises(CommitRejected):
        _inverse_stage_restore_clip_order(boundary, command)


@pytest.mark.parametrize("mutation", ["duplicate", "missing", "extra-row", "order-proof"])
def test_inverse_stage_rejects_clip_order_selection_not_covering_exact_rows(mutation):
    rows = [{"id": "first", "asset": "a"}, {"id": "last", "asset": "b"}]
    order = ["parent/clip:last", "parent/clip:first"]
    boundaries = list(order)
    if mutation == "duplicate":
        order[1] = order[0]
    elif mutation == "missing":
        order.pop()
    elif mutation == "extra-row":
        rows.append({"id": "extra", "asset": "c"})
    else:
        boundaries.reverse()
    boundary = {"parent": {"payload": {"config": {"clips": copy.deepcopy(rows)}}}}
    command = {"selections": [{"key": "collection.clips", "owner": "parent",
                                "query_version": 1, "policy": "guard-membership",
                                "members": ["parent/clip:last", "parent/clip:first"],
                                "order": order, "boundaries": boundaries}]}

    with pytest.raises(CommitRejected):
        _inverse_stage_restore_clip_order(boundary, command)


def _claim_case(*, op="timeline.inverse", submitted_created=None, include_created=False,
                recorded_created=("parent/clip:restored",), facts=None, publications=None,
                selected_steps=None):
    command = {"schema_version": 1, "op": op, "version": "1", "select": None,
               "args": {"publications": list(publications or ["publication"])} }
    if selected_steps is not None:
        command["args"]["steps"] = copy.deepcopy(selected_steps)
    if include_created:
        command["created"] = list(submitted_created or [])
    submitted = copy.deepcopy(command)
    record_command = copy.deepcopy(command)
    record_command["created"] = list(recorded_created)
    record = {"command": record_command, "created": copy.deepcopy(facts or [
        {"ref": ref, "kind": "clip", "owner": "parent"} for ref in recorded_created]),
              "writes": [{"ref": ref, "path": [], "before": {"state": "absent"},
                          "after": {"state": "present"}} for ref in recorded_created],
              "derived_writes": []}
    records = {"commands": [record], "undo_of": list(publications or ["publication"]),
               "undo_steps": copy.deepcopy(selected_steps)}
    return {"commands": [submitted]}, records


def test_inverse_omitted_created_claim_is_distinguished_from_explicit_empty_and_ordinary():
    request, records = _claim_case()
    validate_claims(request, records)

    for submitted_created in ([], ["parent/clip:forged"]):
        explicit_claim, _ = _claim_case(include_created=True, submitted_created=submitted_created)
        with pytest.raises(CommitRejected):
            validate_claims(explicit_claim, records)

    ordinary, ordinary_records = _claim_case(op="clip.move")
    with pytest.raises(CommitRejected):
        validate_claims(ordinary, ordinary_records)


@pytest.mark.parametrize("mutation", ["publication", "step", "fact", "write"])
def test_inverse_omitted_created_claim_requires_exact_restoration_identity(mutation):
    request, records = _claim_case(selected_steps={"publication": ["step"]})
    if mutation == "publication":
        records["undo_of"] = ["foreign-publication"]
    elif mutation == "step":
        records["undo_steps"] = {"publication": ["foreign-step"]}
    elif mutation == "fact":
        records["commands"][0]["created"][0]["ref"] = "parent/clip:forged"
    else:
        records["commands"][0]["writes"] = []
    with pytest.raises(CommitRejected):
        validate_claims(request, records)


def body(service):
    change = {"op": "set", "ref": "parent", "path": ["meta"],
              "before": {"state": "absent"}, "value": {"org.example.timeline": {"note": "opening"}}}
    command = {"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
               "args": {"changes": [change]}}
    return request(service, commands=[command], label="Annotate film", merge="fields", reads=[], steps=[{
        "id": "note", "label": "Opening note", "intent": "Annotate", "tags": [],
        "command_ordinals": [0], "patch": [change]}])


def candidate(context, port):
    request = context["request"]
    head = port.head()
    source = port.revision_closure(head["revision_id"])
    document = copy.deepcopy(source)
    change = copy.deepcopy(request["commands"][0]["args"]["changes"][0])
    parent = document["parent_revision"]
    parent["payload"]["meta"] = copy.deepcopy(change["value"])
    parent["revision_id"] = "annotated-" + context["idempotency_key"]
    parent["content_digest"] = digest(parent["payload"])
    step = {**copy.deepcopy(request["steps"][0]), "patch": [change],
            "dependencies": copy.deepcopy(request.get("reads", []))}
    step["dependencies"].extend(copy.deepcopy(step.get("reads", [])))
    binding = {"key": "doc.patch:0", "ref": "parent", "physical_ref": "parent",
               "revision_id": source["parent_revision"]["revision_id"],
               "content_digest": source["parent_revision"]["content_digest"],
               "policy": "fixed", "dependencies": [], "path": change["path"], "change": change,
               "write_range": [0, 1], "command_ordinal": 0, "change_ordinal": 0, "phase": "input",
               "boundary": {"base_revision_id": request["base_revision_id"],
                            "base_publication_id": request["base_publication_id"], "evaluated_head": head,
                            "command_ordinal": 0, "change_ordinal": 0, "step_id": step["id"], "phase": "input"}}
    record = {"ordinal": 0, "command": copy.deepcopy(request["commands"][0]),
              "writes": [{"ref": "parent", "path": change["path"], "before": change["before"],
                          "after": {"state": "present", "value": change["value"]}}],
              "reads": [], "selections": [], "bindings": [binding], "created": [],
              "dependencies": [], "derived_writes": []}
    value = {"expected_head": head, "canonical_document": document, "document_digest": digest(document),
             "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None,
                         "label": request["label"], "merge_mode": "fields", "steps": [step]},
             "id_map": {}, "semantic_events": [], "provider_version": "prepared-auth-1", "compiler_version": "fixture-1"}
    validate_commit_value(value, "PreparedCommit")
    return value


def provider(service, mutate=lambda value: None):
    def execute(context, port):
        value = candidate(context, port)
        mutate(value)
        validate_commit_value(value, "PreparedCommit")
        return port.preview(value) if context["request"].get("dry_run") else port.accept(value)
    service.test_provider.action = execute


@pytest.mark.parametrize("dry_run", [False, True])
def test_valid_record_accepts_and_retry_or_preview_preserves_authoritative_steps(service, dry_run):
    provider(service)
    submitted = body(service)
    submitted["dry_run"] = dry_run
    result = commit(service, submitted)
    assert result["data"]["status"] == ("preview" if dry_run else "accepted")
    assert result["data"]["steps"][0]["patch"] == submitted["steps"][0]["patch"]
    if not dry_run:
        assert commit(service, submitted) == result
        page = service.list_timeline_commits(service.test_project, "main", authorize=lambda: None)
        assert page["items"][-1]["steps"] == result["data"]["steps"]


@pytest.mark.parametrize("forged_allocation", [False, True])
def test_provider_command_normalizes_empty_allocation_claims_only(service, forged_allocation):
    def mutate(value):
        value["records"]["commands"][0]["command"]["created"] = ["parent/clip:forged"] if forged_allocation else []
    provider(service, mutate)
    submitted = body(service)
    before = rows(service)
    if forged_allocation:
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, submitted)
        assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
        assert rows(service) == before
    else:
        result = commit(service, submitted)
        assert result["data"]["status"] == "accepted"
        assert commit(service, submitted) == result


@pytest.mark.parametrize("bad_pin", [None, "digest", "disagreement"])
def test_final_parent_reuse_keeps_the_exact_projected_effect_boundary(service, bad_pin):
    def mutate(value):
        record = value["records"]["commands"][0]
        binding = {key: copy.deepcopy(record["bindings"][0][key]) for key in (
            "ref", "physical_ref", "policy", "dependencies", "boundary", "path")}
        parent = value["canonical_document"]["parent_revision"]
        binding.update(key="commit.effect", revision_id="projected-parent", content_digest=parent["content_digest"],
                       effect_ordinal=0, step_id="note")
        binding["boundary"].update(phase="effect", side="after")
        if bad_pin == "digest":
            binding["content_digest"] = "sha256:" + "0" * 64
        record["bindings"].append(binding)
        if bad_pin == "disagreement":
            record["bindings"].append({**copy.deepcopy(binding), "revision_id": "foreign-parent"})
    provider(service, mutate)
    submitted = body(service)
    before = rows(service)
    if bad_pin:
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, submitted)
        assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
        assert rows(service) == before
    else:
        result = commit(service, submitted)
        assert result["data"]["status"] == "accepted"
        assert commit(service, submitted) == result


@pytest.mark.parametrize("mutation", [
    "empty_patch", "different_command", "foreign_alias", "wrong_physical_root", "foreign_base", "foreign_publication",
    "foreign_head", "foreign_step", "foreign_ordinal", "foreign_phase", "different_path",
    "different_change", "outside_write_range", "output_image_as_input",
])
@pytest.mark.parametrize("dry_run", [False, True])
def test_forged_provider_records_are_rejected_without_writes(service, mutation, dry_run):
    def mutate(value):
        record = value["records"]["commands"][0]
        binding = record["bindings"][0]
        boundary = binding["boundary"]
        if mutation == "empty_patch":
            value["records"]["steps"][0]["patch"] = []
        elif mutation == "different_command":
            record["command"]["args"]["changes"][0]["value"] = {"forged": True}
        elif mutation == "foreign_alias":
            binding["ref"] = "foreign-alias"
        elif mutation == "wrong_physical_root":
            binding["physical_ref"] = "shot-revision:foreign"
        elif mutation == "foreign_base":
            boundary["base_revision_id"] = "foreign"
        elif mutation == "foreign_publication":
            boundary["base_publication_id"] = "foreign"
        elif mutation == "foreign_head":
            boundary["evaluated_head"] = {"revision_id": "foreign", "publication_id": "foreign"}
        elif mutation == "foreign_step":
            boundary["step_id"] = "foreign"
        elif mutation == "foreign_ordinal":
            boundary["command_ordinal"] = 1
        elif mutation == "foreign_phase":
            boundary["phase"] = "output"
        elif mutation == "different_path":
            binding["path"] = ["config"]
        elif mutation == "different_change":
            binding["change"]["value"] = {"forged": True}
        elif mutation == "outside_write_range":
            binding["write_range"] = [0, 2]
        elif mutation == "output_image_as_input":
            binding.update({key: value["canonical_document"]["parent_revision"][key]
                            for key in ("revision_id", "content_digest")})
    provider(service, mutate)
    submitted = body(service)
    submitted["dry_run"] = dry_run
    before = rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, submitted)
    assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    assert rows(service) == before


@pytest.mark.parametrize("alias", [
    "occurrence:missing/text-binding:voiceover_script",
    "occurrence:occurrence-1/text-binding:voiceover_script:forged",
    "occurrence:occurrence-1/collection:forged",
])
def test_native_text_alias_refusals_are_atomic(service, alias):
    def mutate(value):
        value["records"]["commands"][0]["bindings"][0].update(
            ref=alias, physical_ref="parent")

    provider(service, mutate)
    before = rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, body(service), key="native-alias-refusal-" + alias.split(":", 1)[0])
    assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    assert rows(service) == before


def test_native_text_alias_duplicate_slot_is_ambiguous():
    boundary = {
        "parent": {"payload": {"occurrences": [{
            "occurrence_id": "occ-1", "shot_revision_id": "shot-r1",
        }]}},
        "shot-revision:shot-r1": {"revision_id": "shot-r1", "content_digest": "digest",
                                   "payload": {"text_bindings": [
                                       {"kind": "prompt", "slot": "hero"},
                                       {"kind": "prompt", "slot": "hero"},
                                   ]}},
    }
    with pytest.raises(CommitRejected):
        site(boundary, "occurrence:occ-1/text-binding:prompt:hero", [])


@pytest.mark.parametrize(("alias", "path", "expected"), [
    ("parent/source", ["source_window"], ("parent", ["config", "source_window"])),
    ("parent/collection:asset", [], ("parent", [])),
])
def test_native_assembly_aliases_project_to_their_agent_physical_sites(alias, path, expected):
    boundary = {"parent": {"revision_id": "parent-1", "content_digest": "digest",
                            "payload": {"config": {"registry": {"assets": {}}},
                                        "registry": {"assets": {}}}}}
    assert site(boundary, alias, path) == expected


@pytest.mark.parametrize("alias", [
    "parent/source/extra",
    "parent/collection:asset/extra",
    "parent/collection:unknown",
    "foreign/collection:asset",
])
def test_native_assembly_aliases_reject_malformed_or_foreign_sites(alias):
    boundary = {"parent": {"revision_id": "parent-1", "content_digest": "digest",
                            "payload": {"config": {"registry": {"assets": {}}}}}}
    with pytest.raises(CommitRejected):
        site(boundary, alias, [])


@pytest.mark.parametrize(("alias", "read", "dependency"), [
    ("parent/source", {"ref": "parent/source", "path": ["source_window"],
                       "state": {"state": "absent"}},
     {"kind": "field", "ref": "parent", "path": ["config", "source_window"],
      "state": {"state": "absent"}}),
    ("parent/collection:asset", {"ref": "parent/collection:asset", "path": [],
                                  "state": {"state": "present", "value": {}}},
     {"kind": "scope", "ref": "parent", "path": []}),
])
def test_native_assembly_aliases_authenticate_at_the_sealed_boundary(service, alias, read, dependency):
    def mutate(value):
        value["records"]["commands"][0]["reads"] = [read]
        value["records"]["steps"][0]["dependencies"] = [dependency]

    provider(service, mutate)
    result = commit(service, body(service), key="native-assembly-alias-" + alias.replace("/", "-").replace(":", "-"))
    assert result["data"]["status"] == "accepted"


def test_materialization_turnover_requires_the_captured_physical_owner():
    boundary = {"parent": {"payload": {"occurrences": [{
        "occurrence_id": "occ-1", "shot_id": "shot-1", "shot_revision_id": "old",
    }]}}, "shot-revision:old": {"payload": {}}}
    effects = [{"op": "set", "ref": "shot-revision:new", "path": [],
                "before": {"state": "absent"},
                "value": {"internal_timeline_revision_id": "internal-new",
                          "text_bindings": [{"shot_id": "shot-1"}]}},
               {"op": "set", "ref": "parent",
                "path": ["occurrences", "occurrence_id:occ-1", "shot_revision_id"],
                "before": {"state": "present", "value": "old"}, "value": "new"}]
    assert _coherent_materialization(boundary, effects[1], effects)
    forged = copy.deepcopy(effects)
    forged[0]["value"]["text_bindings"][0]["shot_id"] = "shot-foreign"
    assert not _coherent_materialization(boundary, forged[1], forged)


@pytest.mark.parametrize("step_read", [False, True])
@pytest.mark.parametrize("bad_state", [False, True])
def test_read_claims_are_checked_at_input_and_in_dependency_union(service, step_read, bad_state):
    provider(service, lambda value: value["records"]["steps"][0].update(dependencies=[]))
    submitted = body(service)
    read = {"kind": "field", "ref": "parent", "path": ["meta"],
            "state": {"state": "present", "value": {"org.example.forged": {"value": "forged"}}}
            if bad_state else {"state": "absent"}}
    if step_read:
        submitted["steps"][0]["reads"] = [read]
    else:
        submitted["reads"] = [read]
    before = rows(service)
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, submitted)
    assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    assert rows(service) == before


@pytest.mark.parametrize("scope", [False, True])
def test_valid_read_union_can_keep_extra_captures_or_conservative_scope(service, scope):
    def mutate(value):
        if scope:
            value["records"]["steps"][0]["dependencies"] = [{"kind": "scope", "ref": "parent", "path": []}]
        else:
            value["records"]["steps"][0]["dependencies"].append({"kind": "scope", "ref": "timeline", "path": []})
    provider(service, mutate)
    submitted = body(service)
    submitted["reads"] = [{"kind": "field", "ref": "parent", "path": ["meta"], "state": {"state": "absent"}}]
    assert commit(service, submitted)["data"]["status"] == "accepted"


@pytest.mark.parametrize("omit_scope", [False, True])
def test_atomic_mode_requires_authoritative_scope_dependencies(service, omit_scope):
    def mutate(value):
        value["records"]["merge_mode"] = "atomic"
        if not omit_scope:
            value["records"]["steps"][0]["dependencies"] = [{"kind": "scope", "ref": "parent", "path": []}]
    provider(service, mutate)
    submitted = body(service)
    submitted.pop("reads")
    if omit_scope:
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, submitted)
        assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    else:
        assert commit(service, submitted)["data"]["merge_mode"] == "atomic"


@pytest.mark.parametrize("forge_input", [False, True])
@pytest.mark.parametrize("same_step", [False, True])
def test_sequential_step_reads_use_the_prior_step_output_and_keep_batch_reads(service, forge_input, same_step):
    submitted = body(service)
    batch_read = {"kind": "field", "ref": "parent", "path": ["meta"], "state": {"state": "absent"}}
    submitted["reads"] = [batch_read]
    change = {"op": "set", "ref": "parent", "path": ["meta", "org.example.timeline", "note"],
              "before": {"state": "present", "value": "opening"}, "value": "ending"}
    submitted["commands"].append({"schema_version": 1, "op": "doc.patch", "version": "1", "select": None,
                                   "args": {"changes": [change]}})
    step_read = {"kind": "field", "ref": "parent", "path": ["meta", "org.example.timeline", "note"], "state": change["before"]}
    submitted["steps"].append({"id": "revise", "label": "Revise note", "intent": "Revise", "tags": [],
                               "command_ordinals": [1], "patch": [change], "reads": [step_read]})
    if same_step:
        submitted["steps"] = [{**submitted["steps"][0], "command_ordinals": [0, 1],
                               "patch": [submitted["steps"][0]["patch"][0], change]}]

    def execute(context, port):
        value = candidate(context, port)
        first_image = copy.deepcopy(value["canonical_document"]["parent_revision"])
        first_image["revision_id"] = "intermediate-parent"
        first_binding = value["records"]["commands"][0]["bindings"][0]
        effect_binding = {key: copy.deepcopy(first_binding[key]) for key in (
            "ref", "physical_ref", "policy", "dependencies", "boundary", "path")}
        effect_binding.update(key="commit.effect", revision_id=first_image["revision_id"],
                              content_digest=first_image["content_digest"], step_id="note", effect_ordinal=0)
        effect_binding["boundary"].update(phase="effect", side="after")
        if not same_step:
            value["records"]["commands"][0]["bindings"].append(effect_binding)
        second_binding = copy.deepcopy(first_binding)
        second_binding.update(path=change["path"], change=change, command_ordinal=1,
                              revision_id=first_image["revision_id"], content_digest=first_image["content_digest"])
        second_binding["boundary"].update(step_id="note" if same_step else "revise", command_ordinal=1)
        if forge_input:
            second_binding.update(revision_id=first_binding["revision_id"], content_digest=first_binding["content_digest"])
        value["records"]["commands"].append({"ordinal": 1, "command": submitted["commands"][1],
            "writes": [{"ref": "parent", "path": change["path"], "before": change["before"],
                        "after": {"state": "present", "value": change["value"]}}],
            "reads": [{"ref": "parent", "path": change["path"], "state": change["before"]}],
            "bindings": [second_binding], "created": [], "selections": [], "dependencies": [], "derived_writes": []})
        if same_step:
            value["records"]["steps"][0].update(patch=submitted["steps"][0]["patch"], dependencies=[batch_read, step_read])
        else:
            value["records"]["steps"].append({**submitted["steps"][1], "dependencies": [batch_read, step_read]})
        parent = value["canonical_document"]["parent_revision"]
        parent["payload"]["meta"]["org.example.timeline"]["note"] = "ending"
        parent["revision_id"] = "sequential-parent"
        parent["content_digest"] = digest(parent["payload"])
        value["document_digest"] = digest(value["canonical_document"])
        validate_commit_value(value, "PreparedCommit")
        return port.accept(value)
    service.test_provider.action = execute
    if forge_input:
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, submitted)
        assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    else:
        result = commit(service, submitted)
        assert result["data"]["steps"][-1]["dependencies"] == [batch_read, step_read]
        assert commit(service, submitted) == result


def test_sequential_created_child_boundary_uses_the_native_birth_not_future_output():
    parent = {"config": {"output": {"fps": 24}}, "occurrences": []}
    boundary = {"parent": {"revision_id": "base-parent", "content_digest": digest(parent),
                            "payload": parent}}
    shot_payload = {"name": "Opening", "items": []}
    internal_payload = {"output": {"fps": 24}, "tracks": [], "clips": [], "registry": {"assets": {}}}
    occurrence = {"occurrence_id": "occ-new", "shot_id": "shot-new", "track": "picture",
                  "placement": {"start_ms": 0}, "duration_ms": 1000, "source_offset": 0,
                  "speed": 1, "gain": 1}
    canonical_shot = {**shot_payload, "internal_timeline_revision_id": "internal-new"}
    accepted = {
        "parent": {"revision_id": "accepted-parent",
                    "content_digest": digest({**parent, "occurrences": [{**occurrence,
                                                                            "shot_revision_id": "shot-new-r1"}]}),
                    "payload": {**parent, "occurrences": [{**occurrence,
                                                               "shot_revision_id": "shot-new-r1"}]}},
        "shot-revision:shot-new-r1": {"shot_id": "shot-new", "revision_id": "shot-new-r1",
                                       "internal_timeline_revision_id": "internal-new",
                                       "payload": canonical_shot, "content_digest": digest(canonical_shot)},
        "internal-revision:internal-new": {"timeline_id": "shot-new", "revision_id": "internal-new",
                                            "payload": {**internal_payload, "future": "must-not-read"},
                                            "content_digest": digest({**internal_payload, "future": "must-not-read"})},
    }
    record = {
        "writes": [
            {"ref": "shot:shot-new", "path": [], "before": {"state": "absent"},
             "after": {"state": "present", "value": {"payload": shot_payload,
                                                        "internal_timeline": internal_payload}}},
            {"ref": "occurrence:occ-new", "path": [], "before": {"state": "absent"},
             "after": {"state": "present", "value": occurrence}},
        ],
        "derived_writes": [],
        "created": [{"ref": "shot:shot-new", "kind": "shot", "owner": None},
                    {"ref": "occurrence:occ-new", "kind": "occurrence", "owner": "parent"}],
    }
    next_record = {"writes": [], "reads": [{"ref": "occurrence:occ-new/source", "path": ["output", "fps"],
                                               "state": {"state": "present", "value": 24}}],
                   "bindings": [
                       {"ref": "parent", "physical_ref": "parent",
                        "revision_id": "created-parent", "content_digest": digest(
                            {**parent, "occurrences": [{**occurrence, "shot_revision_id": "shot-new-r1"}]}),
                        "boundary": {"phase": "input"}},
                       {"ref": "occurrence:occ-new/source", "physical_ref": "internal-revision:internal-new",
                        "revision_id": "internal-new", "content_digest": digest(internal_payload),
                        "boundary": {"phase": "input"}},
                   ]}

    result = command_output(boundary, record, next_record, accepted=accepted)
    assert result["parent"]["payload"]["occurrences"] == [{**occurrence, "shot_revision_id": "shot-new-r1"}]
    assert result["internal-revision:internal-new"]["payload"] == internal_payload

    ambiguous = copy.deepcopy(accepted)
    ambiguous["shot-revision:shot-new-r2"] = copy.deepcopy(ambiguous["shot-revision:shot-new-r1"])
    ambiguous["shot-revision:shot-new-r2"]["revision_id"] = "shot-new-r2"
    with pytest.raises(CommitRejected, match="ambiguous accepted physical shot"):
        command_output(boundary, record, next_record, accepted=ambiguous)

    wrong_owner = copy.deepcopy(accepted)
    wrong_owner["parent"]["payload"]["occurrences"][0]["shot_revision_id"] = "foreign-shot-r1"
    with pytest.raises(CommitRejected, match="ambiguous accepted owner"):
        command_output(boundary, record, next_record, accepted=wrong_owner)

    foreign = copy.deepcopy(next_record)
    foreign["reads"][0]["ref"] = "occurrence:foreign/source"
    foreign["bindings"][1]["ref"] = "occurrence:foreign/source"
    with pytest.raises(CommitRejected):
        command_output(boundary, record, foreign, accepted=accepted)


@pytest.mark.parametrize("assert_effect", [False, True])
@pytest.mark.parametrize("omit_effect", [False, True])
def test_native_record_assertions_and_additional_effects_on_a_real_film(tmp_path, assert_effect, omit_effect):
    runtime, project, _ = load_baseline_fixture(tmp_path, variant="film")
    try:
        commits, _ = runtime._timeline_commits()
        head = commits.install_verified_baseline(project, "main", authorize=lambda: None)
        assert head is not None
        source = commits.revision_closure(project, "main", head["revision_id"])
        assert source is not None
        clip = source["parent_revision"]["payload"]["clips"][0]
        native = {"schema_version": 1, "op": "clip.move", "version": "1", "select": "parent/clip:" + clip["id"],
                  "args": {"on": clip["at"] + 1}}
        effect = {"op": "set", "ref": "parent", "path": ["config", "clips", "id:" + clip["id"], "at"],
                  "before": {"state": "present", "value": clip["at"]}, "value": clip["at"] + 1}
        step = {"id": "move", "label": "Move clip", "intent": "Move", "tags": [],
                "command_ordinals": [0], "patch": [effect] if assert_effect else []}
        submitted = {"api_version": 1, "project_id": project, "timeline_id": "main",
                     "base_revision_id": head["revision_id"], "base_publication_id": head["publication_id"],
                     "commands": [native], "label": "Move clip", "merge": "fields", "reads": [], "steps": [step]}

        def execute(context, port):
            observed_head = port.head()
            document = port.revision_closure(observed_head["revision_id"])
            parent = document["parent_revision"]
            collections = [parent["payload"]["clips"]]
            if "clips" in parent["payload"]["config"]:
                collections.append(parent["payload"]["config"]["clips"])
            for clips in collections:
                next(item for item in clips if item["id"] == clip["id"])["at"] = native["args"]["on"]
            # An additional authoritative observation is permitted even when
            # the caller asserts only its authored move (or asserts nothing).
            extra = {"op": "set", "ref": "parent", "path": ["meta"], "before": {"state": "absent"},
                     "value": {"org.example.provider": {"provider": "move"}}}
            parent["payload"]["meta"] = extra["value"]
            parent["revision_id"] = "native-moved"
            parent["content_digest"] = digest(parent["payload"])
            effects = [extra] if omit_effect else [effect, extra]
            record = {"ordinal": 0, "command": native, "writes": [{"ref": native["select"], "path": ["at"],
                      "before": effect["before"], "after": {"state": "present", "value": effect["value"]}}],
                      "reads": [], "selections": [], "bindings": [], "created": [], "dependencies": [], "derived_writes": []}
            value = {"expected_head": observed_head, "canonical_document": document, "document_digest": digest(document),
                     "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None,
                                 "label": "Move clip", "merge_mode": "fields", "steps": [{**step, "patch": effects, "dependencies": []}]},
                     "id_map": {}, "semantic_events": [], "provider_version": "prepared-auth-1", "compiler_version": "fixture-1"}
            validate_commit_value(value, "PreparedCommit")
            return port.accept(value)

        runtime.register_timeline_commit_provider(port_tests.PreparedProvider(execute))
        call = lambda: runtime.commit_timeline(project, "main", submitted, idempotency_key="native-move", publisher="editor",
                                              invocation_path=route_path(project, "main"), authorize=lambda: None)
        if omit_effect:
            with pytest.raises(RuntimeErrorBase) as error:
                call()
            assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
        else:
            assert len(call()["data"]["steps"][0]["patch"]) == 2
    finally:
        runtime.close()


@pytest.mark.parametrize("foreign_alias", [False, True])
def test_created_child_is_a_valid_later_step_read_boundary(service, foreign_alias):
    submitted = body(service)
    create = {"schema_version": 1, "op": "occurrence.create", "version": "1", "select": "parent",
              "args": {"occurrence_id": "occ-new", "shot_id": "shot-new", "name": "Opening",
                       "track": "picture", "on": 0, "duration": 1}}
    submitted["commands"].insert(0, create)
    submitted["steps"][0]["command_ordinals"] = [1]
    read = {"kind": "field", "ref": "shot:shot-new", "path": ["name"],
            "state": {"state": "present", "value": "Opening"}}
    submitted["steps"][0]["reads"] = [read]
    submitted["steps"].insert(0, {"id": "create", "label": "Create opening", "intent": "Create",
                                   "tags": [], "command_ordinals": [0], "patch": []})

    def execute(context, port):
        head = port.head()
        source = port.revision_closure(head["revision_id"])
        internal_payload = {"clips": [], "tracks": []}
        internal = {"timeline_id": "shot:shot-new", "revision_id": "internal-new", "payload": internal_payload,
                    "content_digest": digest(internal_payload)}
        shot_payload = {"name": "Opening", "metadata": {}, "items": [], "internal_timeline_revision_id": "internal-new"}
        shot = {"shot_id": "shot-new", "revision_id": "shot-new-r1", "internal_timeline_revision_id": "internal-new",
                "payload": shot_payload, "content_digest": digest(shot_payload)}
        occurrence = {"occurrence_id": "occ-new", "shot_id": "shot-new", "shot_revision_id": "shot-new-r1",
                      "placement": {"start_ms": 0}, "duration_ms": 1000, "source_offset": 0,
                      "speed": {"numerator": 1, "denominator": 1}, "track": "picture", "transform": {},
                      "gain": 1, "muted": False, "provenance": {}}
        created = copy.deepcopy(source)
        created["shot_revisions"], created["internal_timeline_revisions"] = [shot], [internal]
        created["parent_revision"]["payload"]["occurrences"] = [occurrence]
        created["parent_revision"]["revision_id"] = "created-parent"
        created["parent_revision"]["content_digest"] = digest(created["parent_revision"]["payload"])
        created["dependency_manifest"]["shots"] = [{key: shot[key] for key in (
            "shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}]
        created["dependency_manifest"]["internal_timelines"] = [{key: internal[key] for key in (
            "timeline_id", "revision_id", "content_digest")}]
        effects = [{"op": "set", "ref": "internal-revision:internal-new", "path": [],
                    "before": {"state": "absent"}, "value": internal_payload},
                   {"op": "set", "ref": "shot-revision:shot-new-r1", "path": [],
                    "before": {"state": "absent"}, "value": shot_payload},
                   {"op": "set", "ref": "parent", "path": ["occurrences"],
                    "before": {"state": "present", "value": []}, "value": [occurrence]}]
        common = {"base_revision_id": submitted["base_revision_id"], "base_publication_id": submitted["base_publication_id"],
                  "evaluated_head": head, "command_ordinal": 0, "step_id": "create", "phase": "effect", "side": "after"}
        effect_binding = {"key": "commit.effect", "ref": "parent", "physical_ref": "parent", "policy": "fixed",
                          "dependencies": [], "path": ["occurrences"], "boundary": common, "effect_ordinal": 2,
                          "step_id": "create", "revision_id": "created-parent",
                          "content_digest": created["parent_revision"]["content_digest"]}
        first = {"ordinal": 0, "command": create, "writes": [], "reads": [], "selections": [],
                 "bindings": [effect_binding], "created": [], "dependencies": [], "derived_writes": []}
        # Reuse the normal complete annotation record on the now-created boundary.
        patch_context = copy.deepcopy(context)
        patch_context["request"] = {**submitted, "commands": submitted["commands"][1:], "steps": submitted["steps"][1:]}
        class BoundaryPort:
            def head(self):
                return head
            def revision_closure(self, revision):
                return copy.deepcopy(created)
        value = candidate(patch_context, BoundaryPort())
        second = value["records"]["commands"][0]
        second["ordinal"] = 1
        for binding in second["bindings"]:
            binding["command_ordinal"] = binding["boundary"]["command_ordinal"] = 1
        normalized_read = {**read, "ref": "shot-revision:shot-new-r1"}
        second["bindings"].append({"key": "commit.read", "ref": "shot:foreign" if foreign_alias else read["ref"],
            "physical_ref": normalized_read["ref"], "revision_id": shot["revision_id"], "content_digest": shot["content_digest"],
            "policy": "fixed", "dependencies": [], "path": ["name"], "dependency": normalized_read,
            "boundary": {**common, "command_ordinal": 1, "step_id": "note", "phase": "input"}})
        value["records"]["commands"] = [first, second]
        value["records"]["steps"][0]["dependencies"] = [normalized_read]
        value["records"]["steps"].insert(0, {**submitted["steps"][0], "patch": effects, "dependencies": []})
        validate_commit_value(value, "PreparedCommit")
        return port.accept(value)
    service.test_provider.action = execute
    if foreign_alias:
        with pytest.raises(RuntimeErrorBase) as error:
            commit(service, submitted)
        assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
    else:
        result = commit(service, submitted)
        assert result["data"]["steps"][1]["dependencies"][0]["ref"] == "shot-revision:shot-new-r1"
        assert commit(service, submitted) == result


@pytest.mark.parametrize("forged_successor", [False, True])
def test_rebased_child_bindings_follow_only_authenticated_owner_edges(tmp_path, forged_successor):
    runtime, project, _ = load_baseline_fixture(tmp_path, variant="single")
    try:
        commits, _ = runtime._timeline_commits()
        base = commits.install_verified_baseline(project, "main", authorize=lambda: None)
        original = commits.revision_closure(project, "main", base["revision_id"])
        assert original is not None
        occurrence_id = original["parent_revision"]["payload"]["occurrences"][0]["occurrence_id"]
        shot_id = original["parent_revision"]["payload"]["occurrences"][0]["shot_revision_id"]
        original_shot = next(row for row in original["shot_revisions"] if row["revision_id"] == shot_id)
        original_ref = "internal-revision:" + original_shot["internal_timeline_revision_id"]

        def execute(context, port):
            request = context["request"]
            head = port.head()
            source = port.revision_closure(head["revision_id"])
            document = copy.deepcopy(source)
            occurrence = next(row for row in document["parent_revision"]["payload"]["occurrences"]
                              if row["occurrence_id"] == occurrence_id)
            shot = next(row for row in document["shot_revisions"] if row["revision_id"] == occurrence["shot_revision_id"])
            internal = next(row for row in document["internal_timeline_revisions"]
                            if row["revision_id"] == shot["internal_timeline_revision_id"])
            old_shot, old_internal = copy.deepcopy((shot, internal))
            call = request["commands"][0]
            claim = call["args"]["changes"][0]
            internal["payload"][claim["path"][0]] = copy.deepcopy(claim["value"])
            internal.update(revision_id="internal-" + context["idempotency_key"], content_digest=digest(internal["payload"]))
            shot["payload"]["internal_timeline_revision_id"] = internal["revision_id"]
            shot.update(revision_id="shot-" + context["idempotency_key"],
                        internal_timeline_revision_id=internal["revision_id"], content_digest=digest(shot["payload"]))
            occurrence["shot_revision_id"] = shot["revision_id"]
            parent = document["parent_revision"]
            parent.update(revision_id="parent-" + context["idempotency_key"], content_digest=digest(parent["payload"]))
            for family, before, after in (("shots", old_shot, shot), ("internal_timelines", old_internal, internal)):
                pin = next(row for row in document["dependency_manifest"][family] if row["revision_id"] == before["revision_id"])
                pin.update({key: after[key] for key in pin})
            old_s, new_s = "shot-revision:" + old_shot["revision_id"], "shot-revision:" + shot["revision_id"]
            old_i, new_i = "internal-revision:" + old_internal["revision_id"], "internal-revision:" + internal["revision_id"]
            effects = [
                {"op": "set", "ref": new_i, "path": [], "before": {"state": "absent"}, "value": internal["payload"]},
                {"op": "set", "ref": new_s, "path": [], "before": {"state": "absent"}, "value": shot["payload"]},
                {"op": "set", "ref": "parent", "path": ["occurrences"],
                 "before": {"state": "present", "value": source["parent_revision"]["payload"]["occurrences"]},
                 "value": parent["payload"]["occurrences"]},
                {"op": "remove", "ref": old_s, "path": [], "before": {"state": "present", "value": old_shot["payload"]}},
                {"op": "remove", "ref": old_i, "path": [], "before": {"state": "present", "value": old_internal["payload"]}},
            ]
            boundary = {"base_revision_id": request["base_revision_id"], "base_publication_id": request["base_publication_id"],
                        "evaluated_head": head, "command_ordinal": 0, "step_id": "edit", "phase": "input"}
            binding = {"key": "doc.patch:0", "ref": claim["ref"], "physical_ref": old_i,
                       "revision_id": old_internal["revision_id"], "content_digest": old_internal["content_digest"],
                       "policy": "fixed", "dependencies": [], "boundary": {**boundary, "change_ordinal": 0},
                       "path": claim["path"], "change": {**claim, "ref": old_i}, "write_range": [0, 1]}
            bindings = [binding]
            for before, after, edge_before, edge_after, image in (
                    (old_s, new_s, old_i, new_i, old_shot), (old_i, new_i, old_s, new_s, old_internal)):
                bindings.append({"key": "commit.materialization", "ref": before, "physical_ref": before,
                    "revision_id": image["revision_id"], "content_digest": image["content_digest"],
                    "policy": "fixed", "dependencies": [], "boundary": boundary,
                    "owner": "occurrence:foreign/shot" if forged_successor and request["label"] == "second" else "occurrence:" + occurrence_id + "/shot",
                    "successor": after, "edge_before": edge_before, "edge_after": edge_after})
            record = {"ordinal": 0, "command": call, "bindings": bindings,
                      "writes": [{"ref": old_i, "path": claim["path"], "before": claim["before"],
                                  "after": {"state": "present", "value": claim["value"]}}],
                      "reads": [], "selections": [], "created": [], "dependencies": [], "derived_writes": []}
            value = {"expected_head": head, "canonical_document": document, "document_digest": digest(document),
                     "records": {"schema_version": 1, "commands": [record], "undo_of": [], "restored_from": None,
                                 "label": request["label"], "merge_mode": "fields", "steps": [{
                                     "id": "edit", "label": request["label"], "intent": "", "tags": [],
                                     "command_ordinals": [0], "patch": effects, "dependencies": []}]},
                     "id_map": {}, "semantic_events": [], "provider_version": "prepared-auth-1", "compiler_version": "fixture-1"}
            return port.accept(value)

        runtime.register_timeline_commit_provider(port_tests.PreparedProvider(execute))
        first = None
        for label, field, value in (("first", "meta", {"org.example.timeline": {"note": "first"}}), ("second", "registry", {"assets": {}})):
            initial = next(row for row in original["internal_timeline_revisions"] if "internal-revision:" + row["revision_id"] == original_ref)
            assert initial is not None
            change = {"op": "set", "ref": original_ref, "path": [field], "value": value,
                      "before": {"state": "present", "value": initial["payload"][field]} if field in initial["payload"] else {"state": "absent"}}
            submitted = {"api_version": 1, "project_id": project, "timeline_id": "main",
                "base_revision_id": base["revision_id"], "base_publication_id": base["publication_id"],
                "label": label, "merge": "fields", "reads": [], "commands": [{
                    "schema_version": 1, "op": "doc.patch", "version": "1", "select": None, "args": {"changes": [change]}}]}
            def publish(submitted=submitted, label=label):
                return runtime.commit_timeline(project, "main", submitted, idempotency_key=label, publisher="editor",
                                               invocation_path=route_path(project, "main"), authorize=lambda: None)
            if label == "second" and forged_successor:
                before = rows(runtime)
                with pytest.raises(RuntimeErrorBase) as error:
                    publish()
                assert error.value.details is not None and error.value.details["reason"] == "invalid_records"
                assert rows(runtime) == before
            else:
                result = publish()
                assert result["data"]["status"] == ("accepted" if first is None else "merged")
                assert publish() == result
                first = result
    finally:
        runtime.close()


@pytest.fixture
def created_child_public(tmp_path, astrid_importable, request):
    with_parent_media = getattr(request, "param", False)
    from importlib import import_module

    from test_generation_publish_v1_settlement import (
        _effect,
        _fixture,
        _output,
        _settle,
    )
    from test_timeline_commit_read_basis import _canonical_from_public_reads

    from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider

    capture_track_create = import_module("astrid.sdk.timeline.capture").capture_track_create
    execute = import_module("astrid.sdk.timeline.commands").execute
    bundle_from_document = import_module("astrid.sdk.timeline.commit").bundle_from_document
    capture_occurrence_create = import_module("astrid.sdk.timeline.native_occurrence_create").capture_occurrence_create
    capture_occurrence_add_media = import_module("astrid.sdk.timeline.native_occurrence_media_commands").capture_occurrence_add_media

    def image_effect(project):
        return _effect(project, groups=[{"group_key": "main", "selectors": [{
            "selector": "image", "ordinal": 0, "variant_key": "image", "output_port": "image"}]}])

    runtime, project, task, attempt, effect = _fixture(tmp_path, effect_factory=image_effect)
    project = project["id"]
    runtime.register_timeline_commit_provider(load_timeline_commit_provider("astrid"))

    def document():
        page = runtime.list_timeline_commits(project, "film", authorize=lambda: None)
        return _canonical_from_public_reads(runtime, project, "film", page)

    def build_request(commands):
        head = runtime.get_project_timeline(project, "film")
        return {"api_version": 1, "project_id": project, "timeline_id": "film",
                "base_revision_id": head["head_revision_id"], "base_publication_id": head["head_publication_id"],
                "commands": commands, "label": "Created child", "merge": "fields", "reads": [], "dry_run": False,
                "steps": [{"id": "child", "label": "Created child", "intent": "Use sequential native reads",
                           "tags": ["r2r"], "command_ordinals": list(range(len(commands))), "patch": [], "reads": []}],
                "source": {"via": "python"}, "rationale": "Authenticate created child", "group_id": "created-child"}

    def publish(submitted, key):
        return runtime.commit_timeline(project, "film", submitted, idempotency_key=key, publisher="editor",
                                       invocation_path=route_path(project, "film"), authorize=lambda: None)

    try:
        _settle(runtime, attempt, [_output(b"created-child-image", output_port="image", group_key="main",
                                         variant_key="image", ordinal=0, filename="image.png", media_type="image/png")],
                effect=effect)
        association = runtime.managed_outputs(task["task"]["id"])[0]
        pin = runtime.get_project_media_selection(project, {"association_id": association["association_id"],
            "object_id": association["object_id"], "version": association["lifecycle"]["version"]}, authorize=lambda: None)
        verified = runtime.get_project_verified_media(project, pin, authorize=lambda: None)
        runtime.create_timeline(project, "film", idempotency_key="bootstrap")
        bundle = bundle_from_document(document())
        publish(build_request([capture_track_create(bundle, "parent", {"id": "picture", "kind": "visual"})]), "parent-track")
        source = document()
        bundle = bundle_from_document(source)
        prefix = []
        if with_parent_media:
            capture_media = import_module("astrid.sdk.timeline.native_parent_media_commands").capture_clip_add_media
            overlay = capture_track_create(bundle, "parent", {"id": "overlay", "kind": "visual"})
            bundle = execute(bundle, [overlay]).bundle
            parent_media = capture_media(bundle, {"id": "parent-image", "clipType": "image", "asset": pin["asset"],
                "track": "overlay", "at": 0, "hold": 3, "opaque": [None, False]}, pin, verified_media=[verified])
            bundle = execute(bundle, [parent_media], verified_media=[verified]).bundle
            prefix = [overlay, parent_media]
        birth = capture_occurrence_create(bundle, "new", "new-shot", name="Opening", track="picture", on=0, duration=10)
        born = execute(bundle, [birth]).bundle
        track = capture_track_create(born, "occurrence:new", {"id": "picture", "kind": "visual"})
        tracked = execute(born, [track]).bundle
        held = {"id": "held", "clipType": "image", "asset": pin["asset"], "track": "picture",
                "at": 0, "hold": 2, "opaque": [None, False]}
        media = capture_occurrence_add_media(tracked, "occurrence:new", held, pin, verified_media=[verified])
        yield runtime, project, source, build_request([*prefix, birth, track, media]), held, document, publish
    finally:
        runtime.close()


def _forge_created_child_promotion(value, source, target):
    # Keep the exact 1204 equal-byte forgery: only intermediate input claims,
    # their parent pins and dependency union change; canonical effects stay intact.
    from runtime_protocol.timeline_commit_auth import _authoring_identity, images

    records = value["records"]["commands"]
    scope = source["project_id"], source["timeline_id"]
    born = command_output(images(source), records[0], records[1],
                          accepted=images(value["canonical_document"]), identity_scope=scope)
    source_ref = next(ref for ref in born if ref.startswith("internal-revision:"))
    payload = copy.deepcopy(born[source_ref]["payload"])
    payload["tracks"].append({"id": "picture", "kind": "visual"})
    media = next(binding for binding in records[2]["bindings"] if binding["key"] == "media.track")
    original_ref = media["physical_ref"]
    target_id = target.partition(":")[2]
    media.update(physical_ref=target, revision_id=target_id, content_digest=digest(payload))
    owner = next(image for image in born.values() if image.get("internal_timeline_revision_id") == source_ref.partition(":")[2])
    shot_payload = copy.deepcopy(owner["payload"])
    shot_payload["internal_timeline_revision_id"] = target_id
    successor = _authoring_identity("authoring-shot-revision", scope[0], owner["shot_id"], shot_payload)
    parent = copy.deepcopy(born["parent"]["payload"])
    next(row for row in parent["occurrences"] if row["shot_revision_id"] == owner["revision_id"])["shot_revision_id"] = successor
    for binding in records[2]["bindings"]:
        if binding.get("physical_ref") == "parent" and binding.get("boundary", {}).get("phase") == "input":
            binding.update(revision_id="future-parent", content_digest=digest(parent))
    for dependency in value["records"]["steps"][0]["dependencies"]:
        if dependency["ref"] in {source_ref, original_ref}:
            dependency["ref"] = target


@pytest.mark.integration
@pytest.mark.parametrize("mutation", [None, "foreign", "future", "wrong-owner", "missing-input", "ambiguous",
                                     "pin-revision", "parent-revision", "birth-parent", "digest", "before",
                                     "effect-range", "missing-effects", "order", "foreign-source", "ambiguous-birth", "unpromoted"])
def test_created_child_public_acceptance_and_strict_refusals(created_child_public, monkeypatch, mutation):
    from runtime_protocol.timeline_commit_auth import _authoring_identity
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, project, source, submitted, held, document, publish = created_child_public
    before_db = tuple(runtime.store.conn.iterdump())
    before_history = runtime.list_timeline_commits(project, "film", authorize=lambda: None)
    accept = RequestCommitPort.accept
    reached = []

    def checked_accept(port, prepared):
        value = copy.deepcopy(prepared)
        records = value["records"]["commands"]
        following = records[2]
        media = next(binding for binding in following["bindings"] if binding["key"] == "media.track")
        if mutation in {"foreign", "future", "wrong-owner"}:
            target = "internal-revision:future-foreign-root"
            if mutation == "future":
                target = "internal-revision:" + value["canonical_document"]["internal_timeline_revisions"][0]["revision_id"]
            elif mutation == "wrong-owner":
                payload = {"clips": [], "output": {}, "registry": {"assets": {}},
                           "tracks": [{"id": "picture", "kind": "visual"}]}
                target = "internal-revision:" + _authoring_identity(
                    "authoring-timeline-revision", project, "film", "foreign-shot", payload)
            _forge_created_child_promotion(value, source, target)
        elif mutation == "unpromoted":
            from runtime_protocol.timeline_commit_auth import images
            born = command_output(images(source), records[0], records[1],
                                  accepted=images(value["canonical_document"]), identity_scope=(project, "film"))
            target = next(ref for ref in born if ref.startswith("internal-revision:"))
            _forge_created_child_promotion(value, source, target)
            for binding in following["bindings"]:
                if binding.get("physical_ref") == "parent" and binding["boundary"]["phase"] == "input":
                    binding["revision_id"] = born["parent"]["revision_id"]
        elif mutation == "missing-input":
            following["bindings"].remove(media)
            following["reads"] = [read for read in following["reads"] if not read["ref"].endswith("/source")]
        elif mutation == "ambiguous":
            duplicate = copy.deepcopy(media)
            duplicate.update(physical_ref="internal-revision:ambiguous", revision_id="ambiguous")
            following["bindings"].append(duplicate)
        elif mutation == "pin-revision":
            media["revision_id"] = "foreign-revision"
        elif mutation in {"parent-revision", "birth-parent"}:
            for binding in records[1 if mutation == "birth-parent" else 2]["bindings"]:
                if binding.get("physical_ref") == "parent" and binding["boundary"]["phase"] == "input":
                    binding["revision_id"] = "foreign-parent"
        elif mutation == "digest":
            media["content_digest"] = "sha256:" + "0" * 64
        elif mutation == "before":
            records[1]["writes"][0]["before"] = {"state": "present", "value": {"id": "picture", "kind": "visual"}}
        elif mutation == "effect-range":
            next(binding for binding in following["bindings"] if binding["key"] == "commit.effect")["effect_ordinal"] = 99
        elif mutation == "missing-effects":
            value["records"]["steps"][0]["patch"] = []
        elif mutation == "order":
            records[0], records[1] = records[1], records[0]
        elif mutation == "foreign-source":
            media["ref"] = "occurrence:foreign/track:picture"
        elif mutation == "ambiguous-birth":
            shot = copy.deepcopy(value["canonical_document"]["shot_revisions"][0])
            shot["revision_id"] = "ambiguous-shot"
            value["canonical_document"]["shot_revisions"].append(shot)
        reached.append(copy.deepcopy(value))
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", checked_accept)
    if mutation is not None:
        with pytest.raises(RuntimeErrorBase) as error:
            publish(submitted, "child")
        reason = "identity_collision" if mutation == "ambiguous-birth" else "invalid_records"
        assert error.value.details is not None and error.value.details["reason"] == reason
        assert reached
        assert tuple(runtime.store.conn.iterdump()) == before_db
        assert runtime.list_timeline_commits(project, "film", authorize=lambda: None) == before_history
        assert document() == source
    else:
        result = publish(submitted, "child")
        assert result["data"]["status"] == "accepted"
        assert result["receipt"]["receipt_id"] != submitted["base_publication_id"]
        canonical = document()
        assert canonical == result["data"]["canonical_document"]
        assert canonical["internal_timeline_revisions"][0]["payload"]["clips"] == [held]
        assert canonical["internal_timeline_revisions"][0]["payload"]["tracks"] == [{"id": "picture", "kind": "visual"}]
        assert len(canonical["parent_revision"]["payload"]["occurrences"]) == 1
        assert len(runtime.list_timeline_commits(project, "film", authorize=lambda: None)["items"]) == 3
        assert publish(submitted, "child") == result


@pytest.mark.integration
@pytest.mark.parametrize(("merge_mode", "separate_steps"), [
    ("fields", False), ("fields", True), ("atomic", False), ("atomic", True),
])
def test_created_child_public_sequential_birth_aliases_accept_fields_and_atomic(
        created_child_public, merge_mode, separate_steps):
    _runtime, _project, _source, submitted, held, document, publish = created_child_public
    submitted = copy.deepcopy(submitted)
    submitted["merge"] = merge_mode
    reads = [{"kind": "scope", "ref": "timeline", "path": []}]
    submitted["reads"] = copy.deepcopy(reads)
    if separate_steps:
        template = submitted["steps"][0]
        submitted["steps"] = [
            {**template, "id": f"child-{ordinal}", "command_ordinals": [ordinal], "reads": copy.deepcopy(reads)}
            for ordinal in range(len(submitted["commands"]))
        ]
    else:
        submitted["steps"][0]["reads"] = copy.deepcopy(reads)

    result = publish(submitted, "atomic-child")

    assert result["data"]["status"] == "accepted"
    assert document() == result["data"]["canonical_document"]
    assert document()["internal_timeline_revisions"][0]["payload"]["clips"] == [held]


@pytest.mark.integration
@pytest.mark.parametrize("separate_steps", [False, True])
@pytest.mark.parametrize("mutation", ["foreign-source", "ambiguous-birth", "foreign", "future", "wrong-owner",
                                     "outside-read", "missing-scope"])
def test_created_child_public_atomic_keeps_birth_tamper_refusals(
        created_child_public, monkeypatch, separate_steps, mutation):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, project, source, submitted, _held, document, publish = created_child_public
    submitted = copy.deepcopy(submitted)
    submitted["merge"] = "atomic"
    if separate_steps:
        template = submitted["steps"][0]
        submitted["steps"] = [
            {**template, "id": f"child-{ordinal}", "command_ordinals": [ordinal], "patch": [], "reads": []}
            for ordinal in range(len(submitted["commands"]))
        ]
    before_db = tuple(runtime.store.conn.iterdump())
    before_history = runtime.list_timeline_commits(project, "film", authorize=lambda: None)
    accept = RequestCommitPort.accept

    def checked_accept(port, prepared):
        value = copy.deepcopy(prepared)
        records = value["records"]["commands"]
        if mutation == "foreign-source":
            media = next(binding for binding in records[2]["bindings"] if binding["key"] == "media.track")
            media["ref"] = "occurrence:foreign/track:picture"
        elif mutation == "ambiguous-birth":
            shot = copy.deepcopy(value["canonical_document"]["shot_revisions"][0])
            shot["revision_id"] = "ambiguous-shot"
            value["canonical_document"]["shot_revisions"].append(shot)
        elif mutation in {"foreign", "future", "wrong-owner"}:
            from runtime_protocol.timeline_commit_auth import _authoring_identity

            target = "internal-revision:future-foreign-root"
            if mutation == "future":
                target = "internal-revision:" + value["canonical_document"]["internal_timeline_revisions"][0]["revision_id"]
            elif mutation == "wrong-owner":
                payload = {"clips": [], "output": {}, "registry": {"assets": {}},
                           "tracks": [{"id": "picture", "kind": "visual"}]}
                target = "internal-revision:" + _authoring_identity(
                    "authoring-timeline-revision", project, "film", "foreign-shot", payload)
            _forge_created_child_promotion(value, source, target)
        elif mutation == "outside-read":
            records[2]["reads"][0]["ref"] = "occurrence:foreign/source"
        else:
            value["records"]["steps"][0]["dependencies"] = [{"kind": "scope", "ref": "parent", "path": []}]
        validate_commit_value(value, "PreparedCommit")
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", checked_accept)
    with pytest.raises(RuntimeErrorBase) as error:
        publish(submitted, f"atomic-child-{mutation}-{separate_steps}")
    expected_reason = "identity_collision" if mutation == "ambiguous-birth" else "invalid_records"
    assert error.value.details is not None and error.value.details["reason"] == expected_reason
    assert tuple(runtime.store.conn.iterdump()) == before_db
    assert runtime.list_timeline_commits(project, "film", authorize=lambda: None) == before_history
    assert document() == source


@pytest.mark.integration
@pytest.mark.parametrize("created_child_public", [True], indirect=True)
def test_created_child_promotion_keeps_prior_parent_media_and_mirror_writes(created_child_public):
    runtime, project, _source, submitted, held, document, publish = created_child_public
    result = publish(submitted, "child-after-parent-media")
    canonical = document()
    assert canonical == result["data"]["canonical_document"]
    assert canonical["internal_timeline_revisions"][0]["payload"]["clips"] == [held]
    parent = canonical["parent_revision"]["payload"]
    assert parent["clips"] == parent["config"]["clips"] == [{
        "id": "parent-image", "clipType": "image", "asset": held["asset"], "track": "overlay",
        "at": 0, "hold": 3, "opaque": [None, False]}]
    assert canonical["dependency_manifest"]["media"]
    assert len(runtime.list_timeline_commits(project, "film", authorize=lambda: None)["items"]) == 3


@pytest.mark.integration
@pytest.mark.parametrize("created_child_public", [True], indirect=True)
def test_created_child_public_refuses_uncaptured_foreign_source_dependency(created_child_public, monkeypatch):
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, project, source, submitted, _held, document, publish = created_child_public
    before_db = tuple(runtime.store.conn.iterdump())
    before_history = runtime.list_timeline_commits(project, "film", authorize=lambda: None)
    accept = RequestCommitPort.accept
    reached = []

    def checked_accept(port, prepared):
        value = copy.deepcopy(prepared)
        value["records"]["commands"][1]["dependencies"].append({
            "key": "source.forged", "kind": "source", "policy": "exact",
            "pin": {"document_id": "foreign-document", "version": 1, "content_digest": "sha256:" + "1" * 64}})
        validate_commit_value(value, "PreparedCommit")
        reached.append(copy.deepcopy(value))
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", checked_accept)
    with pytest.raises(RuntimeErrorBase) as error:
        publish(submitted, "forged-source")
    assert error.value.details is not None and error.value.details["reason"] in {"invalid_records", "dependency_unavailable"}
    assert reached
    assert tuple(runtime.store.conn.iterdump()) == before_db
    assert runtime.list_timeline_commits(project, "film", authorize=lambda: None) == before_history
    assert document() == source


@pytest.mark.integration
@pytest.mark.parametrize("created_child_public", [True], indirect=True)
@pytest.mark.parametrize("damage", [None, "before", "late-source"])
def test_created_child_public_captured_transcript_advances_sequential_manifest(created_child_public, monkeypatch, damage):
    from importlib import import_module

    from runtime_protocol.timeline_commit_port import RequestCommitPort

    capture_track_create = import_module("astrid.sdk.timeline.capture").capture_track_create
    execute = import_module("astrid.sdk.timeline.commands").execute
    bundle_from_document = import_module("astrid.sdk.timeline.commit").bundle_from_document
    capture_occurrence_create = import_module("astrid.sdk.timeline.native_occurrence_create").capture_occurrence_create
    capture_anchor = import_module("astrid.sdk.timeline.native_word_anchor").capture_anchor

    runtime, project, _source, submitted, _held, document, publish = created_child_public
    publish(submitted, "first-child")
    source = document()
    media_id = source["dependency_manifest"]["media"][0]["media_id"]
    word_id = "word:" + "1" * 64
    content = {"schema": "media.transcript/v1", "media_id": media_id, "source_id": "default",
               "segments": [{"id": "segment-1", "start": 0, "end": 1, "text": "hello",
                             "words": [{"id": word_id, "start": 0, "end": 1, "text": "hello"}]}]}
    resource = runtime.create_document(project, {
        "document_id": runtime._transcript_document_id(project, media_id, "default"),
        "kind": "media.transcript", "content": content}, idempotency_key="transcript")["data"]
    pin = {"document_id": resource["document_id"], "version": resource["version"], "content_digest": digest(content)}
    verified = runtime.get_project_verified_document(project, pin, authorize=lambda: None)
    bundle = bundle_from_document(source)
    bundle["source_mapping"]["pinned_documents"] = [verified]
    anchor = capture_anchor(bundle, "parent/clip:parent-image", "on", '"hello"', {
        "source": "occurrence:new/clip:held", "document": pin, "word_ids": [word_id]})
    anchored = execute(bundle, [anchor]).bundle
    birth = capture_occurrence_create(anchored, "next", "next-shot", name="Next", track="picture", on=3, duration=2)
    born = execute(anchored, [birth]).bundle
    track = capture_track_create(born, "occurrence:next", {"id": "picture", "kind": "visual"})
    head = runtime.get_project_timeline(project, "film")
    submitted = {**submitted, "base_revision_id": head["head_revision_id"],
                 "base_publication_id": head["head_publication_id"], "commands": [anchor, birth, track]}
    submitted["steps"] = [{**submitted["steps"][0], "command_ordinals": [0, 1, 2]}]
    before_db = tuple(runtime.store.conn.iterdump())
    before_history = runtime.list_timeline_commits(project, "film", authorize=lambda: None)
    accept = RequestCommitPort.accept

    def checked_accept(port, prepared):
        value = copy.deepcopy(prepared)
        records = value["records"]["commands"]
        if damage == "before":
            for binding in records[-1]["bindings"]:
                if binding.get("key") == "commit.effect" and binding["boundary"].get("side") == "before":
                    binding["revision_id"] = "foreign-parent"
        elif damage == "late-source":
            records[1]["dependencies"].extend(records[0]["dependencies"])
            records[0]["dependencies"] = []
        return accept(port, value)

    monkeypatch.setattr(RequestCommitPort, "accept", checked_accept)
    if damage is not None:
        with pytest.raises(RuntimeErrorBase):
            publish(submitted, "captured-transcript-child")
        assert tuple(runtime.store.conn.iterdump()) == before_db
        assert runtime.list_timeline_commits(project, "film", authorize=lambda: None) == before_history
        assert document() == source
        return
    accepted = publish(submitted, "captured-transcript-child")
    canonical = document()
    assert accepted["data"]["canonical_document"] == canonical
    assert canonical["dependency_manifest"]["documents"] == [pin]
    assert len(canonical["parent_revision"]["payload"]["occurrences"]) == 2
    assert publish(submitted, "captured-transcript-child") == accepted
