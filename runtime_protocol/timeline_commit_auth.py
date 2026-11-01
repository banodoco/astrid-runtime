"""Authenticate provider annotations against sealed requests and recorded boundaries.

This module consumes provider observations; it never executes submitted edits.
Command execution, conflict detection and inverse construction belong to Agent.
"""
from __future__ import annotations

import copy
import hashlib
import re
from typing import cast

from .timeline_commit_producer import value_equal
from .timeline_commit_validation import digest, validate_commit_value
from .util import canonical_json


def require(condition, message, *, safe_details=None):
    if not condition:
        from .timeline_commit_store import reject
        reject("invalid_records", message, status=422, safe_details=safe_details)


def images(document):
    return {"parent": document["parent_revision"], **{
        "shot-revision:" + row["revision_id"]: row for row in document["shot_revisions"]}, **{
        "internal-revision:" + row["revision_id"]: row for row in document["internal_timeline_revisions"]}}


def normalized_path(ref, path):
    if ref == "parent" and path[:1] in (["clips"], ["registry"]):
        return ["config", *path]
    return list(path)


_TEXT_BINDING_REF = re.compile(
    r"occurrence:([^/]+)/text-binding:(prompt|voiceover_script|transcript)"
    r"(?::([a-z][a-z0-9-]{0,63}))?\Z"
)


def _text_binding_key(kind, slot):
    return kind + (":" + slot if slot is not None else "")


def _text_binding_members(owner, rows):
    require(isinstance(rows, list), "provider text-binding collection is absent or malformed")
    members = []
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("kind"), str)
                and (row.get("slot") is None or isinstance(row.get("slot"), str)),
                "provider text-binding collection has an invalid identity")
        member = owner + "/text-binding:" + _text_binding_key(row["kind"], row.get("slot"))
        require(member not in members, "provider text-binding collection has an ambiguous identity")
        members.append(member)
    return members


def _text_binding_site(boundary, ref):
    collection = ref.endswith("/collection:text-binding")
    if collection:
        owner = ref.removesuffix("/collection:text-binding")
        owner_match = re.fullmatch(r"occurrence:([^/]+)", owner)
        require(owner_match is not None, "provider text-binding collection is outside its authenticated boundary")
        if owner_match is None:
            raise AssertionError("unreachable text-binding collection alias")
        occurrence, kind, slot = owner_match.group(1), None, None
    else:
        match = _TEXT_BINDING_REF.fullmatch(ref)
        require(match is not None, "provider text-binding alias is outside its authenticated boundary")
        if match is None:
            raise AssertionError("unreachable text-binding alias")
        occurrence, kind, slot = match.groups()
        require(kind == "prompt" or slot is None,
                "provider text-binding alias has an invalid slot")
    owner = "occurrence:" + occurrence
    rows = boundary.get("parent", {}).get("payload", {}).get("occurrences", [])
    matches = [row for row in rows if isinstance(row, dict) and row.get("occurrence_id") == occurrence]
    require(len(matches) == 1, "provider text-binding occurrence is outside or ambiguous in its boundary")
    shot_ref = "shot-revision:" + str(matches[0].get("shot_revision_id"))
    require(shot_ref in boundary, "provider text-binding occurrence has no authenticated shot")

    bindings = boundary[shot_ref]["payload"].get("text_bindings", [])
    require(isinstance(bindings, list),
            "provider text-binding collection is malformed")
    for row in bindings:
        require(isinstance(row, dict) and row.get("kind") in {"prompt", "voiceover_script", "transcript"}
                and (row.get("slot") is None or isinstance(row.get("slot"), str)),
                "provider text-binding collection has an invalid identity")
    if collection:
        _text_binding_members(owner, bindings)
        return shot_ref, ["text_bindings"]
    identity = _text_binding_key(kind, slot)
    matching = [row for row in bindings
                if _text_binding_key(row["kind"], row.get("slot")) == identity]
    require(len(matching) <= 1, "provider text-binding alias is ambiguous in its boundary")
    return shot_ref, ["text_bindings", "kind:" + identity]


def site(boundary, ref, path, continuations=None):
    """Resolve root and native aliases in one authenticated closure image."""
    path = list(path)
    if ref == "timeline":
        return ref, []
    if ref in boundary:
        return ref, normalized_path(ref, path)
    if ref.startswith(("shot-revision:", "internal-revision:")) and continuations:
        seen = set()
        while ref not in boundary and ref in continuations and ref not in seen:
            seen.add(ref)
            successors = continuations[ref]
            require(len(successors) == 1, "provider source has ambiguous authenticated successors")
            ref = next(iter(successors))
        if ref in boundary:
            return ref, path
    if "/text-binding:" in ref:
        binding_ref, binding_path = _text_binding_site(boundary, ref)
        return binding_ref, [*binding_path, *path]
    if "/collection:" in ref:
        owner, family = ref.rsplit("/collection:", 1)
        if family == "text-binding":
            return _text_binding_site(boundary, owner + "/collection:text-binding")
        if family == "asset":
            require(owner == "parent",
                    "provider collection alias is outside its authenticated boundary")
            # The physical owner is parent; validate_step expands this native
            # shape capture into fields for both authored registry mirrors.
            return "parent", []
        if family in {"clip", "track", "occurrence"}:
            prefix = ["config", family + "s"] if owner == "parent" and family != "occurrence" else [family + "s"]
            return site(boundary, owner if owner == "parent" else owner + "/source", prefix)
        require(False, "provider collection alias is outside its authenticated boundary")
    kind, _, identity = ref.partition(":")
    field = {"shot": "shot_id", "internal": "timeline_id"}.get(kind)
    if field and "/" not in identity:
        matches = [key for key, image in boundary.items() if image.get(field) == identity]
        require(len(matches) == 1, "provider alias is outside or ambiguous in its boundary")
        return matches[0], path[1:] if path[:1] == ["payload"] else path
    owner, _, entity = ref.partition("/")
    if owner == "parent":
        if entity == "source":
            return "parent", ["config", *path]
        if entity == "registry":
            return "parent", ["config", "registry", *path]
        if entity.startswith(("clip:", "track:")):
            family, identity = entity.split(":", 1)
            return "parent", ["config", family + "s", "id:" + identity, *path]
        if entity.startswith("asset:"):
            return "parent", ["config", "registry", "assets", entity[6:], *path]
    if owner.startswith("occurrence:"):
        identity = owner[len("occurrence:"):]
        if not entity:
            return "parent", ["occurrences", "occurrence_id:" + identity, *path]
        rows = boundary["parent"]["payload"]["occurrences"]
        matches = [row for row in rows if row["occurrence_id"] == identity]
        require(len(matches) == 1, "provider occurrence alias is outside its boundary")
        shot_ref = "shot-revision:" + matches[0]["shot_revision_id"]
        require(shot_ref in boundary, "provider occurrence has no authenticated shot")
        if entity == "shot":
            return shot_ref, path[1:] if path[:1] == ["payload"] else path
        internal = "internal-revision:" + boundary[shot_ref]["internal_timeline_revision_id"]
        require(internal in boundary, "provider occurrence has no authenticated internal timeline")
        if entity == "source":
            return internal, path
        if entity == "registry":
            return internal, ["registry", *path]
        if entity.startswith(("clip:", "track:")):
            family, identity = entity.split(":", 1)
            return internal, [family + "s", "id:" + identity, *path]
        if entity.startswith("asset:"):
            return internal, ["registry", "assets", entity[6:], *path]
    require(False, "provider alias is outside its authenticated boundary")


def location(payload, path, *, absent_items=False):
    node = payload
    for index, token in enumerate(path):
        if isinstance(node, list):
            if index and path[index - 1] == "text_bindings" and token.startswith("kind:"):
                identity = token.removeprefix("kind:")
                matches = [row for row in node if isinstance(row, dict)
                           and _text_binding_key(row.get("kind"), row.get("slot")) == identity]
                require(len(matches) <= 1, "provider observation has an ambiguous text-binding path")
                if not matches:
                    return {"state": "absent"}
                node = matches[0]
                continue
            key, separator, identity = token.partition(":")
            matches = [row for row in node if isinstance(row, dict) and row.get(key) == identity]
            if absent_items and separator and not matches:
                return {"state": "absent"}
            require(separator and len(matches) == 1, "provider observation has an ambiguous item path")
            node = matches[0]
        elif isinstance(node, dict) and token in node:
            node = node[token]
        else:
            return {"state": "absent"}
    return {"state": "present", "value": node}


def stored_path(payload, ref, path):
    if (ref == "parent" and path[:2] in (["config", "clips"], ["config", "registry"])
            and path[1] not in payload.get("config", {}) and path[1] in payload):
        return path[1:]
    return path


def normalized(boundary, value, continuations=None):
    ref, path = site(boundary, value["ref"], value["path"], continuations)
    return {**value, "ref": ref, "path": path}


def native_site(boundary, ref, path):
    if ref.startswith("occurrence:") and ref.endswith("/shot") and path[:1] != ["payload"]:
        return site(boundary, ref.removesuffix("/shot"), path)
    if ref.startswith("shot:") and "/" not in ref and path[:1] != ["payload"]:
        return "timeline", []
    return site(boundary, ref, path)


def covers(dependencies, read):
    for dependency in dependencies:
        if value_equal(dependency, read):
            return True
        if dependency["kind"] == "scope" and (
                dependency["ref"] == "timeline" or dependency["ref"] == read["ref"]
                and read["path"][:len(dependency["path"])] == dependency["path"]):
            return True
    return False


def native_asset_reads(payload):
    """Lossless field guards for the native parent asset storage shape.

    C0 fields retain the complete registry value, including malformed containers
    and ordered values. Never resolve one mirror through the other. A missing
    or non-object config must be guarded at config itself.
    """
    paths = [["registry"], ["config", "registry"]
             if isinstance(payload.get("config"), dict) else ["config"]]
    return [{"kind": "field", "ref": "parent", "path": path,
             "state": copy.deepcopy(location(payload, path))} for path in paths]


def validate_read(boundary, read, continuations=None):
    read = normalized(boundary, read, continuations)
    if read["kind"] == "scope":
        return read
    payload = boundary[read["ref"]]["payload"]
    observed = location(payload, stored_path(payload, read["ref"], read["path"]))
    if read["kind"] == "field":
        require(value_equal(observed, read["state"]), "declared field read differs from its input boundary")
    else:
        rows = observed.get("value")
        if not isinstance(rows, list):
            require(False, "declared collection is absent at its input boundary")
            return read
        key = "occurrence_id" if read["path"][-1:] == ["occurrences"] else "id"
        members = [row[key] for row in rows if isinstance(row, dict) and isinstance(row.get(key), str)]
        require(len(members) == len(rows)
                and sorted(members) == read["members"]
                and (read["order"] is None or members == read["order"]),
                "declared collection read differs from its input boundary")
    return read


def _omitted_inverse_created_is_authenticated(submitted, record, records):
    """Allow the inverse provider to report restored allocation facts.

    ``created`` is optional on the wire.  A raw inverse request therefore has
    no caller allocation claim, while the provider must still return the
    authenticated restoration facts in its record.  This helper only admits
    that request/recorder shape; the physical bindings, materialization,
    destination, history, and undo guards below and in the store remain the
    authority for the restored identities.
    """
    if "created" in submitted or submitted.get("op") != "timeline.inverse":
        return False
    args = submitted.get("args")
    command = record["command"]
    created = command.get("created")
    if not isinstance(args, dict) or not isinstance(created, list) or not created:
        return False
    if records.get("undo_of") != args.get("publications"):
        return False
    requested_steps = args.get("steps")
    if records.get("undo_steps") != requested_steps:
        return False
    facts = record["created"]
    if not isinstance(facts, list) or [item["ref"] for item in facts] != created:
        return False
    restoration_writes = {
        write["ref"]
        for write in [*record["writes"], *record["derived_writes"]]
        if write["path"] == []
        and write["before"] == {"state": "absent"}
        and write["after"]["state"] == "present"
    }
    return set(created) <= restoration_writes


def _omitted_track_created_is_authenticated(submitted, record):
    """Authenticate the allocation derived by the legacy track.create recorder.

    Omission asks the native recorder to derive the claim. An explicit claim,
    including an empty one, must still match exactly. The sealed command's row
    and owner must account for the complete authored birth and allocation fact;
    boundary, binding and reservation validation still applies independently.
    """
    if "created" in submitted or submitted.get("op") != "track.create":
        return False
    owner, args = submitted.get("select"), submitted.get("args")
    if not isinstance(owner, str) or not isinstance(args, dict):
        return False
    row = args.get("row")
    if not isinstance(row, dict) or not isinstance(row.get("id"), str):
        return False
    ref = owner + "/track:" + row["id"]
    return (value_equal(record["command"].get("created"), [ref])
            and value_equal(record["created"], [{"ref": ref, "kind": "track", "owner": owner}])
            and any(value_equal(read, {"ref": ref, "path": [], "state": {"state": "absent"}})
                    for read in record["reads"])
            and value_equal(record["writes"], [{
                "ref": ref, "path": [], "before": {"state": "absent"},
                "after": {"state": "present", "value": row}}]))


def validate_claims(request, records):
    commands = records["commands"]
    require(len(commands) == len(request["commands"]), "provider command count differs from request")
    for submitted, record in zip(request["commands"], commands):
        core_matches = all(value_equal(submitted.get(key), record["command"].get(key))
                           for key in ("schema_version", "op", "version", "select", "args"))
        created_matches = value_equal(submitted.get("created", []), record["command"].get("created", []))
        inverse_restoration = _omitted_inverse_created_is_authenticated(submitted, record, records)
        track_creation = _omitted_track_created_is_authenticated(submitted, record)
        require(core_matches and (created_matches or inverse_restoration or track_creation),
                "provider executed a different command")


def _authoring_identity(kind, *parts):
    encoded = "\0".join([kind, *(canonical_json(part) for part in parts)]).encode("utf-8")
    return f"{kind}-" + hashlib.sha256(encoded).hexdigest()


def _sequential_assertion(claim, ordinals, sequential, key, phase="input"):
    if key == "dependency" and claim == {"kind": "scope", "ref": "timeline", "path": []}:
        require(len(ordinals) == 1, "timeline scope read has no unique sequential input")
        ordinal = ordinals[0]
        pairs = [pair for (index, _), pair in sequential["binding_pairs"].items()
                 if index == ordinal and pair["original"]["key"] == "commit.read"
                 and pair["original"]["ref"] == "timeline"
                 and pair["original"]["boundary"]["phase"] == phase]
        # Timeline scope reads expand over the entire closure, rather than
        # carrying one physical dependency. Authenticate every image on both
        # sides at the declaration's own batch/step input boundary.
        for side in ("original", "landing"):
            boundary = images(sequential[side][ordinal]["input"])
            refs = [pair[side]["physical_ref"] for pair in pairs]
            require(len(refs) == len(set(refs)) and set(refs) == set(boundary)
                    and all(pair[side]["key"] == "commit.read"
                            and pair[side]["ref"] == "timeline"
                            and pair[side]["path"] == []
                            and pair[side]["boundary"]["phase"] == phase for pair in pairs),
                    "timeline scope read lacks complete authenticated sequential bindings")
        return ordinal, claim
    matches = []
    for (ordinal, _), pair in sequential["binding_pairs"].items():
        if (ordinal not in ordinals or key not in pair["original"]
                or pair["original"]["boundary"]["phase"] != phase):
            continue
        original_input = images(sequential["original"][ordinal]["input"])
        original = pair["original"][key]
        if claim["ref"] not in {pair["original"]["ref"], original["ref"]}:
            continue
        if value_equal(normalized(original_input, claim), normalized(original_input, original)):
            matches.append((ordinal, pair["landing"][key]))
    require(len(matches) == 1, "submitted assertion has no unique authenticated sequential binding")
    return matches[0]


def _created_occurrence_child(record, ref):
    """Whether ``ref`` is a child of this command's declared occurrence birth."""
    owner, separator, _ = ref.partition("/")
    created = {item.get("ref") for item in record.get("created", [])}
    return separator and owner.startswith("occurrence:") and owner in created


def validate_step(request, records, step, boundary, batch_reads, continuations, command_inputs=None, sequential=None,
                  inverse_boundaries=None, created_inputs=None):
    submitted = next((item for item in request.get("steps", []) if item["id"] == step["id"]), None)
    dependencies = step["dependencies"]
    step_reads = []
    for read in (submitted or {}).get("reads", []):
        if sequential is not None and "binding_pairs" in sequential:
            _, read = _sequential_assertion(read, step["command_ordinals"][:1], sequential, "dependency")
        step_reads.append(validate_read(boundary, read, continuations))
    for read in [*batch_reads, *step_reads]:
        require(covers(dependencies, read), "provider dependency union omits a declared read")
    for ordinal in step["command_ordinals"]:
        record = records["commands"][ordinal]
        command_boundary = (command_inputs or {}).get(ordinal, boundary)
        created_boundary = (created_inputs or {}).get(ordinal)
        created = {item["ref"] for item in record["created"]}
        for read in record["reads"]:
            if read["ref"] in created and read["state"] == {"state": "absent"}:
                continue
            created_child = (_created_occurrence_child(record, read["ref"])
                             and created_boundary is not None)
            owner, separator, _ = read["ref"].partition("/")
            owner_path = ["occurrences", "occurrence_id:" + owner.removeprefix("occurrence:")]
            if (inverse_boundaries is not None and record["command"]["op"] == "timeline.inverse"
                    and separator and read["ref"] == owner + "/collection:track" and not read["path"]
                    and owner.startswith("occurrence:") and owner in created
                    and location(command_boundary["parent"]["payload"], owner_path,
                                 absent_items=True) == {"state": "absent"}):
                # Native inverse reads describe the input even when later
                # stage writes restore their owner. Its authenticated absence
                # guards every child; no restored alias is an input image.
                restorations = [write for write in record["writes"]
                                if write["ref"] == owner and write["path"] == []]
                require(read["state"] == {"state": "absent"} and len(restorations) == 1
                        and restorations[0]["before"] == {"state": "absent"}
                        and restorations[0]["after"].get("state") == "present"
                        and restorations[0]["after"].get("value", {}).get("occurrence_id")
                        == owner.removeprefix("occurrence:"),
                        "inverse child read lacks its authenticated absent restoration owner")
                require(covers(dependencies, {"kind": "field", "ref": "parent", "path": owner_path,
                                              "state": {"state": "absent"}}),
                        "provider dependency union omits a restored owner's input absence")
                continue
            if read["ref"] == "parent/collection:asset" and not read["path"]:
                for capture in native_asset_reads(command_boundary["parent"]["payload"]):
                    require(covers(dependencies, capture), "provider dependency union omits a captured read")
                continue
            read_boundary = (created_boundary if created_boundary is not None
                             and created_child
                             else command_boundary)
            ref, path = native_site(read_boundary, read["ref"], read["path"])
            if created_child:
                # A same-command child has no pre-command physical image. Its
                # root/write/link closure is staged above, while the recorder
                # retains the exact pre-command parent scope as its dependency.
                require(covers(dependencies, {"kind": "scope", "ref": "parent", "path": []}),
                        "provider dependency union omits a created child input parent")
                continue
            if ref == "timeline" or not path or "/collection:" in read["ref"]:
                capture = {"kind": "scope", "ref": ref, "path": []}
                if "/collection:" in read["ref"] and ref != "timeline":
                    observed = location(read_boundary[ref]["payload"], path).get("value")
                    if isinstance(observed, list):
                        if read["ref"].endswith("/collection:text-binding"):
                            owner = read["ref"].rsplit("/collection:", 1)[0]
                            members = _text_binding_members(owner, observed)
                        else:
                            key = "occurrence_id" if path[-1:] == ["occurrences"] else "id"
                            members = [row[key] for row in observed]
                        capture = {"kind": "collection", "ref": ref, "path": path,
                                   "members": sorted(members), "order": members}
            else:
                capture = {"kind": "field", "ref": ref, "path": path, "state": read["state"]}
            require(covers(dependencies, capture), "provider dependency union omits a captured read")
        for binding in record["bindings"]:
            if "dependency" in binding:
                require(covers(dependencies, binding["dependency"]), "provider dependency union omits a bound read")
    assertions = (submitted or {}).get("patch", [])
    calls = [request["commands"][ordinal] for ordinal in step["command_ordinals"]]
    patches = [change for call in calls if call["op"] == "doc.patch" for change in call["args"]["changes"]]
    if submitted is not None and all(call["op"] == "doc.patch" for call in calls):
        require(value_equal(assertions, patches), "submitted step patch differs from its commands")
    for claim in assertions:
        matches = []
        claim_boundary = boundary
        if (sequential is not None and "binding_pairs" in sequential
                and any(value_equal(claim, patch) for patch in patches)):
            ordinal, claim = _sequential_assertion(claim, step["command_ordinals"], sequential, "change")
            claim_boundary = (command_inputs or {}).get(ordinal, boundary)
        for ordinal in step["command_ordinals"]:
            command_boundary = (command_inputs or {}).get(ordinal, boundary)
            for binding in records["commands"][ordinal]["bindings"]:
                if "change" in binding:
                    matches.append(normalized(command_boundary, {**binding["change"], "path": binding["path"]},
                                               continuations))
                    if (binding["change"].get("ref") == claim.get("ref")
                            and binding["change"].get("path") == claim.get("path")):
                        # A submitted claim belongs to the command that owns
                        # its input.  In a sequential step that input can be
                        # an intermediate materialized image, not the step's
                        # first (outer) boundary.
                        claim_boundary = command_boundary
        for effect in step["patch"]:
            if not any(effect.get("ref") == claim.get("ref")
                       and effect.get("path") == claim.get("path")
                       for claim in assertions):
                continue
            effect_boundary = boundary
            for ordinal in step["command_ordinals"]:
                command_boundary = (command_inputs or {}).get(ordinal, boundary)
                if any(binding.get("change", {}).get("ref") == effect.get("ref")
                       and binding.get("change", {}).get("path") == effect.get("path")
                       for binding in records["commands"][ordinal]["bindings"] if "change" in binding):
                    effect_boundary = command_boundary
            matches.append(normalized(effect_boundary,
                                      {**effect, "path": normalized_path(effect["ref"], effect["path"])},
                                      continuations))
        require(any(value_equal(normalized(claim_boundary, claim, continuations), match) for match in matches),
                "provider effects omit a submitted assertion")


def validate_bindings(request, records, expected, boundary, output, step, ordinal, continuations, original,
                      step_input, effect_boundaries=None, input_parent_revision=None, sequential=None,
                      created_input=None):
    record = records["commands"][ordinal]
    for binding_index, binding in enumerate(record["bindings"]):
        if "physical_ref" not in binding:
            continue  # Original ABI-1 captures do not claim physical provenance.
        captured = binding.get("boundary", {})
        phase = captured.get("phase")
        require(phase in {"input", "batch-read", "effect"} and (phase != "batch-read" or ordinal == 0)
                and captured.get("base_revision_id") == request["base_revision_id"]
                and captured.get("base_publication_id") == request["base_publication_id"]
                and value_equal(captured.get("evaluated_head"), expected)
                and captured.get("step_id") == step["id"]
                and captured.get("command_ordinal") == ordinal,
                "provider binding boundary differs from the authenticated invocation")
        bound = boundary
        if phase == "effect":
            side, index = captured.get("side"), binding.get("effect_ordinal")
            require(binding["key"] == "commit.effect" and side in {"before", "after"}
                    and ordinal == step["command_ordinals"][-1]
                    and type(index) is int and 0 <= index < len(step["patch"]),
                    "provider effect binding is misattributed")
            require(step["patch"][index]["ref"] == binding["physical_ref"]
                    and step["patch"][index]["path"] == binding.get("path"),
                    "provider effect binding differs from the recorded effect")
            if effect_boundaries is not None:
                require(index in effect_boundaries,
                        "provider effect binding is outside an authenticated inverse stage")
                bound = effect_boundaries[index][0 if side == "before" else 1]
            else:
                bound = step_input if side == "before" else output
        elif binding["key"] == "commit.materialization":
            bound = step_input
        for key in ("command_ordinal", "step_id", "phase", "change_ordinal"):
            if key in binding:
                require(binding[key] == captured.get(key), "provider binding attribution is inconsistent")
        physical = binding["physical_ref"]
        resolve = site if binding["key"].startswith(("doc.patch:", "commit.")) else native_site
        pair = (sequential or {}).get("binding_pairs", {}).get((ordinal, binding_index))
        if pair is not None:
            require(pair["landing"]["physical_ref"] == physical
                    and pair["original"]["physical_ref"] == pair["source_physical_ref"],
                    "provider sequential source-to-landing binding is inconsistent")
            ref = physical
        else:
            created_child = (created_input is not None
                             and _created_occurrence_child(record, binding["ref"]))
            if created_child and physical == "parent":
                # Same-command child observations have no pre-command child
                # image. Their recorder pin is therefore the exact input
                # parent; the staged creation closure authenticates the alias.
                ref = "parent"
            else:
                if created_child:
                    bound = created_input
                ref, _ = (site(bound, binding["ref"], [], continuations) if resolve is site
                          else resolve(bound, binding["ref"], []))
        require(ref == physical or ref == "timeline" and binding["key"] in {"commit.read", "commit.atomic"},
                "provider alias names a different physical image")
        # Materialization observes the authenticated landing input, whose
        # physical sources can already be successors of the requested base.
        # Its owner/edge correspondence is verified below. Submitted aliases
        # still have to retain their original physical source.
        if (pair is None and ordinal == 0 and phase != "effect" and resolve is site and binding["ref"] != "timeline"
                and not (created_input is not None and _created_occurrence_child(record, binding["ref"]))
                and binding["key"] != "commit.materialization"):
            original_ref, _ = site(original, binding["ref"], [], continuations)
            continued_ref, _ = site(bound, original_ref, [], continuations)
            require(continued_ref == physical, "provider alias changed without an authenticated successor")
        image = bound.get(physical)
        revision_matches = image is not None and binding.get("revision_id") == image["revision_id"]
        if (not revision_matches and image is not None and physical == "parent"
                and phase == "effect" and captured.get("side") == "before"
                and input_parent_revision is not None):
            # Agent hydrates captured documents before deriving effect images,
            # including when the effect-before image is an inverse-stage boundary.
            # The derived input pin, digest and physical parent must all agree.
            revision_matches = binding.get("revision_id") == input_parent_revision
        require(image is not None and binding.get("content_digest") == image["content_digest"]
                and revision_matches,
                "provider binding differs from its authenticated input image")
        if "owners" in binding:
            owners = []
            for row in bound["parent"]["payload"]["occurrences"]:
                shot_ref = "shot-revision:" + row["shot_revision_id"]
                shot = bound.get(shot_ref)
                if physical == shot_ref or shot is not None and physical == "internal-revision:" + shot["internal_timeline_revision_id"]:
                    owners.append("occurrence:" + row["occurrence_id"] + "/shot")
            require(set(owners) == set(binding["owners"]), "provider binding owners differ from its physical edges")
        if "change" in binding:
            change = binding["change"]
            require(change["ref"] == physical and normalized_path(physical, change["path"]) == binding.get("path"),
                    "provider binding path differs from its change")
            start, end = binding.get("write_range", [-1, -1])
            require(0 <= start <= end <= len(record["writes"]), "provider binding has an invalid write range")
            if record["command"]["op"] == "doc.patch":
                index = captured.get("change_ordinal")
                changes = request["commands"][ordinal]["args"]["changes"]
                submitted_boundary, submitted_change = boundary, change
                if pair is not None and sequential is not None:
                    submitted_boundary = images(sequential["original"][ordinal]["input"])
                    submitted_change = pair["original"]["change"]
                require(type(index) is int and 0 <= index < len(changes)
                        and value_equal(normalized(submitted_boundary, changes[index], continuations),
                                        normalized(submitted_boundary, submitted_change, continuations)),
                        "provider binding differs from the submitted change")
        if "dependency" in binding:
            dependency = binding["dependency"]
            require(dependency["ref"] == physical and dependency["path"] == binding.get("path"),
                    "provider read binding differs from its dependency")
        if "successor" in binding:
            from .timeline_materialization import edges
            # Materialization spans the complete step, even when its record is
            # attached to a later command with a different intermediate input.
            before_rows, after_rows = edges({"parent_revision": bound["parent"]}), edges({"parent_revision": output["parent"]})
            owner = binding.get("owner", "").removeprefix("occurrence:").removesuffix("/shot")
            successor = binding["successor"]
            require(binding["key"] == "commit.materialization" and owner in before_rows and owner in after_rows
                    and successor in output, "provider successor lacks an authenticated owner edge")
            before_shot = "shot-revision:" + before_rows[owner][1]
            after_shot = "shot-revision:" + after_rows[owner][1]
            require(before_shot in bound and after_shot in output, "provider successor has an absent owner image")
            before_internal = "internal-revision:" + bound[before_shot]["internal_timeline_revision_id"]
            after_internal = "internal-revision:" + output[after_shot]["internal_timeline_revision_id"]
            require((physical, successor, binding.get("edge_before"), binding.get("edge_after")) in {
                (before_shot, after_shot, before_internal, after_internal),
                (before_internal, after_internal, before_shot, after_shot)},
                "provider successor differs from its authenticated physical edges")


def project_observation(payload, path, state):
    """Project a recorder's full observed value, without interpreting edit operands."""
    if not path:
        require(state["state"] == "present", "provider removed an existing payload")
        return copy.deepcopy(state["value"])
    result = copy.deepcopy(payload)
    node = result
    for token in path[:-1]:
        if isinstance(node, list):
            key, _, identity = token.partition(":")
            matches = [row for row in node if row.get(key) == identity]
            require(len(matches) == 1, "provider observation has no unique ancestor")
            node = matches[0]
        else:
            require(isinstance(node, dict) and token in node, "provider observation has no ancestor")
            node = node[token]
    token = path[-1]
    if isinstance(node, list):
        key, _, identity = token.partition(":")
        indices = [index for index, row in enumerate(node) if row.get(key) == identity]
        require(len(indices) <= 1, "provider observation has an ambiguous item")
        if state["state"] == "absent":
            require(bool(indices), "provider removed an absent item")
            node.pop(indices[0])
        elif indices:
            node[indices[0]] = copy.deepcopy(state["value"])
        else:
            node.append(copy.deepcopy(state["value"]))
    else:
        require(isinstance(node, dict), "provider observation has a scalar ancestor")
        if state["state"] == "absent":
            node.pop(token, None)
        else:
            node[token] = copy.deepcopy(state["value"])
    return result


def _physical_owner(document, ref):
    """Return the occurrence owning an authenticated shot/internal image."""
    parent = document.get("parent", {}).get("payload", {})
    for row in parent.get("occurrences", []):
        occurrence = row.get("occurrence_id")
        shot_ref = "shot-revision:" + str(row.get("shot_revision_id"))
        if ref == shot_ref:
            return occurrence, row.get("shot_id")
        shot = document.get(shot_ref, {})
        if ref == "internal-revision:" + str(shot.get("internal_timeline_revision_id")):
            return occurrence, row.get("shot_id")
    return None


def _coherent_materialization(boundary, effect, effects):
    """Accept a physical turnover only when its sibling effect names its owner."""
    if not effects:
        return False
    parent = boundary.get("parent", {}).get("payload", {})
    occurrences = {row.get("occurrence_id"): row for row in parent.get("occurrences", [])}
    roots = [candidate for candidate in effects
             if not normalized_path(candidate["ref"], candidate["path"])
             and candidate["ref"].startswith("shot-revision:")]

    def payload(effect):
        if effect["op"] == "remove":
            value = effect.get("before")
            return value.get("value") if value.get("state") == "present" else None
        return effect.get("value")

    def shot_ids(image):
        return {binding.get("shot_id") for binding in (image or {}).get("text_bindings", [])
                if binding.get("shot_id") is not None}

    if effect["ref"] == "parent" and effect["path"][-1:] == ["shot_revision_id"]:
        occurrence = next((part.split(":", 1)[1] for part in effect["path"]
                           if part.startswith("occurrence_id:")), None)
        row = occurrences.get(occurrence)
        if row is None:
            return False
        return any(effect.get("value") == root["ref"].partition(":")[2]
                   and row.get("shot_id") in shot_ids(payload(root)) for root in roots)

    if effect["ref"].startswith(("shot-revision:", "internal-revision:")) and not effect["path"]:
        internal_id = effect["ref"].partition(":")[2]
        if effect["ref"].startswith("shot-revision:"):
            image = payload(effect) or {}
            internal_id = image.get("internal_timeline_revision_id")
        if internal_id is None:
            return False
        return any(root_payload.get("internal_timeline_revision_id") == internal_id
                   and any(row.get("shot_id") in shot_ids(root_payload) for row in occurrences.values())
                   for root in roots for root_payload in [payload(root) or {}])
    return False


def _materialization_input(boundary, original, effect, observed_path, effects=None):
    """Accept a rebased physical edge only across one authenticated owner."""
    if original is None:
        return False
    ref, path = effect["ref"], normalized_path(effect["ref"], effect["path"])
    if ref == "parent" and path[-1:] == ["shot_revision_id"]:
        owner_path = path[:-1]
        original_value = location(original[ref]["payload"], path)
        if original_value.get("state") != "present":
            return False
        owner = owner_path[-1].partition(":")[2] if owner_path[-1].startswith("occurrence_id:") else None
        current_value = location(boundary[ref]["payload"], path)
        if owner is None or current_value.get("state") != "present":
            return False
        old_ref = "shot-revision:" + str(original_value["value"])
        current_ref = "shot-revision:" + str(current_value["value"])
        old_owner = _physical_owner(original, old_ref)
        current_owner = _physical_owner(boundary, current_ref)
        return ((old_owner is not None and current_owner is not None
                 and old_owner == current_owner == (owner, old_owner[1]))
                or _coherent_materialization(boundary, effect, effects))
    if not path and ref.startswith(("shot-revision:", "internal-revision:")):
        old_owner = _physical_owner(original, ref)
        current_owner = _physical_owner(boundary, ref)
        return old_owner is not None or current_owner is not None or _coherent_materialization(boundary, effect, effects)
    return _coherent_materialization(boundary, effect, effects)


def _align_materialized_images(result, accepted):
    """Map provider-generated physical ids to the accepted authenticated images."""
    for ref, image in list(result.items()):
        if ref == "parent" or not ref.startswith(("shot-revision:", "internal-revision:")):
            continue
        candidates = [candidate for candidate, known in accepted.items()
                      if candidate.startswith(ref.split(":", 1)[0] + ":")
                      and value_equal(known["payload"], image["payload"])
                      and _physical_owner(result, ref) == _physical_owner(accepted, candidate)]
        if len(candidates) != 1:
            continue
        candidate = candidates[0]
        result[candidate] = copy.deepcopy(accepted[candidate])
        if candidate != ref:
            if ref.startswith("shot-revision:"):
                old_id, new_id = ref.partition(":")[2], candidate.partition(":")[2]
                for row in result["parent"]["payload"].get("occurrences", []):
                    if row.get("shot_revision_id") == old_id:
                        row["shot_revision_id"] = new_id
            else:
                old_id, new_id = ref.partition(":")[2], candidate.partition(":")[2]
                for shot_ref, shot in result.items():
                    if shot_ref.startswith("shot-revision:") and shot["payload"].get("internal_timeline_revision_id") == old_id:
                        shot["payload"]["internal_timeline_revision_id"] = new_id
            result.pop(ref)


def _parent_materialization_reconciles(result, accepted):
    """Recognize a landing parent whose only delta is authenticated shot turnover."""
    before = copy.deepcopy(result["parent"]["payload"])
    after = copy.deepcopy(accepted["parent"]["payload"])
    before_rows = {row.get("occurrence_id"): row for row in before.get("occurrences", [])}
    after_rows = {row.get("occurrence_id"): row for row in after.get("occurrences", [])}
    if set(before_rows) != set(after_rows):
        return False
    changed = False
    for occurrence, row in before_rows.items():
        other = after_rows[occurrence]
        old_ref, new_ref = row.get("shot_revision_id"), other.get("shot_revision_id")
        row.pop("shot_revision_id", None)
        other.pop("shot_revision_id", None)
        if old_ref != new_ref:
            changed = True
            if (_physical_owner(result, "shot-revision:" + str(old_ref)) is None
                    or _physical_owner(accepted, "shot-revision:" + str(new_ref)) is None):
                return False
    return changed and value_equal(before, after)


def _reconcile_materialized_owner_images(result, accepted):
    def owner_token(document, ref):
        image = document.get(ref, {})
        if ref.startswith("shot-revision:"):
            return "shot:" + str(image.get("payload", {}).get("internal_timeline_revision_id"))
        if ref.startswith("internal-revision:"):
            return ref
        return None

    owners = {owner_token(accepted, ref) for ref in accepted
              if ref.startswith(("shot-revision:", "internal-revision:"))}
    for owner in owners - {None}:
        result_refs = {ref for ref in result if owner_token(result, ref) == owner}
        accepted_refs = {ref for ref in accepted if owner_token(accepted, ref) == owner}
        for ref in result_refs - accepted_refs:
                result.pop(ref, None)
        for ref in accepted_refs:
            result[ref] = copy.deepcopy(accepted[ref])


def _occurrence_order_change(record, index):
    """Bind one native collection observation to its sealed patch change."""
    bindings = [binding for binding in record["bindings"]
                if binding.get("key", "").startswith("doc.patch:")
                and binding.get("write_range") == [index, index + 1]]
    require(record.get("command", {}).get("op") == "doc.patch" and len(bindings) == 1,
            "provider occurrence order lacks a unique patch binding")
    binding = bindings[0]
    changes = record["command"]["args"]["changes"]
    ordinal = binding.get("boundary", {}).get("change_ordinal")
    require(type(ordinal) is int and 0 <= ordinal < len(changes)
            and binding.get("key") == "doc.patch:" + str(ordinal)
            and binding.get("physical_ref") == "parent" and binding.get("path") == ["occurrences"]
            and changes[ordinal].get("ref") == "parent"
            and value_equal(binding.get("change"), changes[ordinal])
            and binding["change"].get("op") == "list.move",
            "provider occurrence order differs from its sealed patch change")
    return binding["change"]


def _occurrence_order_observation(boundary, capture, change, identity_scope):
    """Authenticate authored order observations, retaining the exact physical rows."""
    rows = boundary["parent"]["payload"].get("occurrences")
    require(isinstance(rows, list), "provider occurrence order has no physical input")
    physical, authored = {}, []
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get("occurrence_id"), str)
                and row["occurrence_id"] not in physical,
                "provider occurrence order has ambiguous physical membership")
        shot = boundary.get("shot-revision:" + str(row.get("shot_revision_id")), {})
        internal_id = shot.get("internal_timeline_revision_id")
        require(shot.get("shot_id") == row.get("shot_id")
                and shot.get("revision_id") == row.get("shot_revision_id")
                and isinstance(internal_id, str) and "internal-revision:" + internal_id in boundary
                and shot.get("payload", {}).get("internal_timeline_revision_id") == internal_id,
                "provider occurrence order has an unauthenticated physical owner")
        physical[row["occurrence_id"]] = row
        native = {key: copy.deepcopy(value) for key, value in row.items()
                  if key not in {"shot_revision_id", "revision_id"}}
        if sum(other.get("shot_id") == row["shot_id"] for other in rows) > 1:
            require(identity_scope is not None,
                    "provider shared occurrence order lacks an authenticated identity scope")
            native["shot_id"] = _authoring_identity(
                "shot-placement", *identity_scope, row["occurrence_id"], row["shot_id"])
        authored.append(native)
    require(value_equal(capture.get("before"), {"state": "present", "value": authored}),
            "provider occurrence order differs from its sequential input")
    after = capture.get("after", {})
    ordered = after.get("value")
    by_id = {row["occurrence_id"]: row for row in authored}
    require(after.get("state") == "present" and isinstance(ordered, list)
            and len(ordered) == len(rows)
            and all(isinstance(row, dict) and isinstance(row.get("occurrence_id"), str)
                    and row["occurrence_id"] in by_id
                    and value_equal(row, by_id[row["occurrence_id"]]) for row in ordered)
            and len({row["occurrence_id"] for row in ordered}) == len(rows),
            "provider occurrence order is not a row-preserving permutation")
    before_ids = [row["occurrence_id"] for row in rows]
    after_ids = [row["occurrence_id"] for row in ordered]
    identity, anchor = change.get("id"), change.get("after_id")
    require(change.get("order_before") == before_ids and identity in physical
            and value_equal(change.get("before"), {"state": "present", "value": physical[identity]})
            and anchor != identity and (anchor is None or anchor in physical)
            and [key for key in before_ids if key != identity] == [key for key in after_ids if key != identity]
            and (after_ids.index(identity) == 0 if anchor is None else
                 after_ids.index(identity) == after_ids.index(anchor) + 1),
            "provider occurrence order differs from its bound move")
    return {"state": "present", "value": [copy.deepcopy(physical[key]) for key in after_ids]}


def step_output(boundary, step, records, accepted, original=None, authenticated=None, *, identity_scope=None):
    """Project complete authoritative effects solely to authenticate their boundaries."""
    expected = authenticated if authenticated is not None else accepted
    result = copy.deepcopy(boundary)
    order_writes = [(record, index) for ordinal in step["command_ordinals"]
                    for record in [records["commands"][ordinal]]
                    for index, write in enumerate(record["writes"])
                    if write["ref"] == "parent" and write["path"] == ["occurrences"]]
    order_index = 0
    for effect in step["patch"]:
        ref, path = effect["ref"], normalized_path(effect["ref"], effect["path"])
        if ref != "parent" and not path:
            before = {"state": "present", "value": result[ref]["payload"]} if ref in result else {"state": "absent"}
            require(value_equal(before, effect["before"])
                    or _materialization_input(boundary, original, effect, path, step["patch"]),
                    "provider root effect has a different input")
            if effect["op"] == "remove":
                result.pop(ref, None)
            else:
                require(effect["op"] == "set", "provider root effect is not an observed value")
                result[ref] = {**copy.deepcopy(expected.get(ref, accepted.get(ref, {}))),
                               "revision_id": ref.partition(":")[2],
                               "content_digest": digest(effect["value"]), "payload": copy.deepcopy(effect["value"])}
                if ref.startswith("shot-revision:"):
                    result[ref]["internal_timeline_revision_id"] = effect["value"]["internal_timeline_revision_id"]
            continue
        require(ref in result, "provider effect addresses an absent root")
        payload = result[ref]["payload"]
        observed_path = stored_path(payload, ref, path)
        if ref == "parent" and path == ["occurrences"] and effect["op"] == "list.move":
            require(order_index < len(order_writes), "provider occurrence order lacks a collection observation")
            record, index = order_writes[order_index]
            order_index += 1
            change = _occurrence_order_change(record, index)
            require(value_equal(effect, change), "provider occurrence order effect differs from its patch binding")
            state = _occurrence_order_observation(result, record["writes"][index], change, identity_scope)
        elif effect["op"].startswith("list."):
            # List operations are Agent semantics. The recorder supplies the
            # complete resulting collection; Runtime only projects that value.
            observations = [write for ordinal in step["command_ordinals"]
                            for write in records["commands"][ordinal]["writes"]
                            if site(boundary, write["ref"], write["path"]) == (ref, path)]
            require(bool(observations), "provider list effect lacks a full collection observation")
            state = observations[-1]["after"]
        else:
            require(value_equal(location(payload, observed_path), effect["before"])
                    or _materialization_input(boundary, original, effect, observed_path, step["patch"]),
                    "provider effect has a different input value")
            state = {"state": "present", "value": effect["value"]} if effect["op"] == "set" else {"state": "absent"}
        result[ref]["payload"] = project_observation(payload, observed_path, state)
        if ref == "parent" and path[:2] in (["config", "clips"], ["config", "registry"]):
            mirror = path[1]
            if mirror in payload and mirror in result[ref]["payload"].get("config", {}):
                result[ref]["payload"][mirror] = copy.deepcopy(result[ref]["payload"]["config"].get(mirror))
        result[ref]["content_digest"] = digest(result[ref]["payload"])
    if order_index:
        require(order_index == len(order_writes), "provider occurrence order effects omit a collection observation")
    _align_materialized_images(result, expected)
    # Bindings of complete effect images carry the provider's generated revision
    # names. Their payload digest must agree with the projected observations.
    for row in result["parent"]["payload"]["occurrences"]:
        ref = "shot-revision:" + row["shot_revision_id"]
        require(ref in result, "provider occurrence effect has no physical shot image")
        require(result[ref].get("shot_id", row["shot_id"]) == row["shot_id"],
                "provider occurrence effect changes physical shot ownership")
        result[ref]["shot_id"] = row["shot_id"]
    for ref, image in list(result.items()):
        known = expected.get(ref)
        if ref == "parent":
            pins = [binding for ordinal in step["command_ordinals"]
                    for binding in records["commands"][ordinal]["bindings"]
                    if binding.get("key") == "commit.effect" and binding.get("physical_ref") == ref
                    and binding.get("boundary", {}).get("side") == "after"
                    and binding.get("content_digest") == image["content_digest"]]
            if pins:
                require(len({pin["revision_id"] for pin in pins}) == 1, "provider intermediate parent pins disagree")
                image["revision_id"] = pins[0]["revision_id"]
            else:
                reconciled = known is not None and _parent_materialization_reconciles(result, expected)
                require(known is not None and (value_equal(known["payload"], image["payload"])
                                                or reconciled),
                        "provider intermediate parent lacks an effect image")
                result[ref] = copy.deepcopy(known)
                if reconciled:
                    _reconcile_materialized_owner_images(result, expected)
        elif known is not None and value_equal(known["payload"], image["payload"]):
            result[ref] = copy.deepcopy(known)
    return result


def _inverse_stage_write_site(boundary, write):
    """Resolve a staged inverse write, including a root entering the closure."""
    ref, path = write["ref"], write["path"]
    # Native root captures name physical fields. The two parent mirrors can
    # differ between their separately recorded writes within a stage.
    if ref in boundary:
        return ref, path
    if (not path and ref.startswith(("shot-revision:", "internal-revision:"))
            and ref not in boundary):
        return ref, path
    return native_site(boundary, ref, path)


def _inverse_stage_occurrence_collection(boundary, state):
    """Compare authored occurrence rows without hiding an unauthenticated pin."""
    if state["state"] != "present":
        return state
    rows = state["value"]
    require(isinstance(rows, list), "inverse stage occurrence collection is malformed")
    result = []
    seen_occurrences = set()
    seen_shots = set()
    for row in rows:
        require(isinstance(row, dict), "inverse stage occurrence row is malformed")
        occurrence_id = row.get("occurrence_id")
        shot_id = row.get("shot_id")
        shot_revision_id = row.get("shot_revision_id")
        require(isinstance(occurrence_id, str) and occurrence_id not in seen_occurrences
                and isinstance(shot_id, str) and isinstance(shot_revision_id, str),
                "inverse stage occurrence ownership is ambiguous")
        seen_occurrences.add(occurrence_id)
        shot_ref = "shot-revision:" + shot_revision_id
        require(shot_ref not in seen_shots and shot_ref in boundary,
                "inverse stage occurrence has no authenticated physical shot")
        seen_shots.add(shot_ref)
        shot = boundary[shot_ref]
        internal_id = shot.get("internal_timeline_revision_id")
        internal_ref = "internal-revision:" + str(internal_id)
        payload = shot.get("payload")
        require(shot.get("shot_id") == shot_id
                and isinstance(internal_id, str)
                and internal_ref in boundary
                and isinstance(payload, dict)
                and payload.get("internal_timeline_revision_id") == internal_id
                and _physical_owner(boundary, shot_ref) == (occurrence_id, shot_id)
                and _physical_owner(boundary, internal_ref) == (occurrence_id, shot_id),
                "inverse stage occurrence pin differs from its authenticated physical owner")
        authored = copy.deepcopy(row)
        authored.pop("shot_revision_id")
        result.append(authored)
    return {"state": "present", "value": result}


def _inverse_stage_state(boundary, ref, path):
    if ref == "timeline":
        require(not path, "inverse stage timeline capture is not a whole closure")
        return {"state": "present", "value": {
            key: boundary["parent"][key] for key in ("revision_id", "content_digest")}}
    if ref not in boundary:
        return {"state": "absent"}
    state = location(boundary[ref]["payload"], stored_path(boundary[ref]["payload"], ref, path),
                     absent_items=True)
    if ref == "parent" and path == ["occurrences"]:
        return _inverse_stage_occurrence_collection(boundary, state)
    return state


def _inverse_stage_restore_clip_order(boundary, command):
    """Restore a parent clip order proved by a source command's collection selection."""
    recorded = command.get("selections", [])
    require(isinstance(recorded, list) and all(isinstance(selection, dict) for selection in recorded),
            "inverse stage source selections are malformed")
    selections = [selection for selection in recorded
                  if selection.get("key") == "collection.clips"
                  and selection.get("owner") == "parent"]
    if not selections:
        return
    require(len(selections) == 1, "inverse stage source clip order is ambiguous")
    selection = selections[0]
    members, order = selection.get("members"), selection.get("order")
    require(selection.get("query_version") == 1
            and selection.get("policy") == "guard-membership"
            and isinstance(members, list) and isinstance(order, list)
            and all(isinstance(ref, str) for ref in [*members, *order])
            and len(members) == len(set(members))
            and members == order == selection.get("boundaries")
            and all(isinstance(ref, str) and re.fullmatch(r"parent/clip:[^/]+", ref)
                    for ref in members),
            "inverse stage source clip order is malformed")
    payload = boundary["parent"]["payload"]
    config = payload.get("config")
    config_rows = config.get("clips") if isinstance(config, dict) else None
    payload_rows = payload.get("clips")
    rows = config_rows if isinstance(config_rows, list) else payload_rows
    require(isinstance(rows, list), "inverse stage source clip collection is absent")
    if isinstance(config_rows, list) and isinstance(payload_rows, list):
        require(value_equal(config_rows, payload_rows),
                "inverse stage source clip mirrors disagree")
    by_id = {row.get("id"): row for row in rows if isinstance(row, dict)}
    expected_ids = [ref.partition(":")[2] for ref in order]
    require(len(by_id) == len(rows) and set(by_id) == set(expected_ids),
            "inverse stage restored clip membership differs from its source selection")
    restored = [by_id[identity] for identity in expected_ids]
    if isinstance(config_rows, list):
        config["clips"] = restored
    if isinstance(payload_rows, list):
        payload["clips"] = copy.deepcopy(restored)


def _inverse_stage_root(boundary, ref):
    """Observe authored aggregate roots through authenticated physical images."""
    kind, _, identity = ref.partition(":")
    if kind == "occurrence":
        state = location(boundary["parent"]["payload"], ["occurrences", "occurrence_id:" + identity],
                         absent_items=True)
        state = copy.deepcopy(state)
        if state["state"] == "present":
            assert isinstance(state["value"], dict)
            state["value"].pop("shot_revision_id", None)
            state["value"].pop("revision_id", None)
        return state, []
    matches = [(key, image) for key, image in boundary.items()
               if key.startswith("shot-revision:") and image.get("shot_id") == identity]
    require(len(matches) <= 1, "inverse stage shot root is ambiguous")
    if not matches:
        return {"state": "absent"}, []
    physical, shot = matches[0]
    internal = "internal-revision:" + shot["internal_timeline_revision_id"]
    require(internal in boundary and shot["payload"].get("internal_timeline_revision_id")
            == shot["internal_timeline_revision_id"], "inverse stage shot root has no authenticated internal image")
    return {"state": "present", "value": {"payload": copy.deepcopy(shot["payload"]),
            "internal_timeline": copy.deepcopy(boundary[internal]["payload"])}}, [physical, internal]


def _inverse_stage_root_equal(observed, claimed, ref):
    if value_equal(observed, claimed):
        return True
    if ref.startswith("shot:") and observed["state"] == "present":
        authored = copy.deepcopy(observed)
        authored["value"]["payload"].pop("internal_timeline_revision_id", None)
        return value_equal(authored, claimed)
    return False


def _inverse_stage_retire_occurrence_images(native_image, stage_before, writes,
                                           source_entry, source_step, source_commands):
    """Project closure loss from an exact accepted occurrence creation."""
    if source_step is None:
        return
    document = source_entry.get("receipt", {}).get("result", {}).get("canonical_document")
    if document is None:
        return
    accepted_source = images(document)
    source_writes = [capture for ordinal in source_step["command_ordinals"]
                     for capture in source_commands[ordinal]["writes"]]
    for write in writes:
        if (write["path"] or not re.fullmatch(r"occurrence:[^/]+", write["ref"])
                or write["before"]["state"] != "present" or write["after"] != {"state": "absent"}):
            continue
        occurrence = write["ref"].partition(":")[2]
        path = ["occurrences", "occurrence_id:" + occurrence]
        row = location(stage_before["parent"]["payload"], path, absent_items=True)
        require(row["state"] == "present", "inverse retirement has no authenticated occurrence")
        assert isinstance(row["value"], dict)
        shot_ref = "shot-revision:" + row["value"]["shot_revision_id"]
        if shot_ref not in native_image or any(
                item.get("shot_revision_id") == row["value"]["shot_revision_id"]
                for item in native_image["parent"]["payload"].get("occurrences", [])):
            continue
        captures = [capture for capture in source_writes
                    if capture["ref"] == write["ref"] and capture["path"] == []]
        require(len(captures) == 1 and value_equal(captures[0]["after"], write["before"])
                and value_equal(captures[0]["before"], write["after"])
                and value_equal(location(accepted_source["parent"]["payload"], path, absent_items=True), row),
                "inverse retirement differs from its accepted occurrence creation")
        shot = stage_before[shot_ref]
        internal_id = shot["internal_timeline_revision_id"]
        internal_ref = "internal-revision:" + internal_id
        require(shot.get("shot_id") == row["value"]["shot_id"]
                and shot["payload"].get("internal_timeline_revision_id") == internal_id
                and internal_ref in stage_before
                and all(ref in accepted_source and value_equal(stage_before[ref], accepted_source[ref])
                        and value_equal(native_image.get(ref), stage_before[ref])
                        and stage_before[ref]["content_digest"] == digest(stage_before[ref]["payload"])
                        for ref in (shot_ref, internal_ref)),
                "inverse retirement differs from its accepted physical images")
        native_image.pop(shot_ref)
        if not any(image.get("internal_timeline_revision_id") == internal_id
                   or image.get("payload", {}).get("internal_timeline_revision_id") == internal_id
                   for ref, image in native_image.items() if ref.startswith("shot-revision:")):
            native_image.pop(internal_ref)


def _inverse_stage_inherited(source_step, source_commands, source_records, publication):
    """Project partitions of a sealed inverse, retaining its immediate identity.

    History entries come from history_entry, which verifies their acceptance
    and ancestry before exposing these bindings. They are not provider claims.
    """
    bindings = [binding for command in source_commands for binding in command.get("bindings", [])
                if binding.get("key") == "inverse.stage"]
    if not bindings or (len(bindings) == 1 and not any(
            effect["op"] == "remove" and not effect["path"]
            and effect["ref"].startswith(("shot-revision:", "internal-revision:"))
            for effect in source_step["patch"])):
        return None
    if len(bindings) == 1:
        writes = [write for command in source_commands for write in command.get("writes", [])]
        if ((len(writes) != 1 or writes[0]["path"]
                or not re.fullmatch(r"occurrence:[^/]+", writes[0]["ref"]))
                and not any(not write["path"] and re.fullmatch(r"shot:[^/]+", write["ref"])
                            and write["before"]["state"] == "present"
                            and write["after"] == {"state": "absent"} for write in writes)):
            return None
    require(len(source_commands) == 1 and source_commands[0]["command"]["op"] == "timeline.inverse",
            "inherited inverse stages require one authenticated source command")
    command = source_commands[0]
    targets = source_records.get("undo_of")
    require(isinstance(targets, list) and targets and publication not in targets
            and len(set(targets)) == len(targets)
            and command["command"]["args"].get("publications") == targets,
            "inherited inverse stage targets differ from authenticated history")
    native_end = effect_end = 0
    partitions = []
    for binding in bindings:
        boundary = binding.get("boundary", {})
        require(binding.get("ref") == "parent" and binding.get("policy") == "fixed"
                and binding.get("dependencies") == []
                and boundary.get("publication_id") in targets
                and isinstance(boundary.get("step_id"), str) and boundary["step_id"]
                and isinstance(boundary.get("command_ordinals"), list)
                and boundary["command_ordinals"]
                and all(type(ordinal) is int and ordinal >= 0 for ordinal in boundary["command_ordinals"]),
                "inherited inverse stage identity differs from authenticated history")
        native = boundary.get("native_write_range")
        effect = boundary.get("effect_range")
        require(isinstance(native, list) and len(native) == 2
                and all(type(item) is int for item in native)
                and native[0] == native_end < native[1] <= len(command["writes"])
                and isinstance(effect, list) and len(effect) == 2
                and all(type(item) is int for item in effect)
                and effect[0] == effect_end <= effect[1] <= len(source_step["patch"]),
                "inherited inverse ranges are missing, reordered, or overlapping")
        writes = [{**write, "before": write["after"], "after": write["before"]}
                  for write in reversed(command["writes"][native[0]:native[1]])]
        partitions.append({"native_sites": [(write["ref"], write["path"]) for write in writes],
                           "source_writes": writes,
                           "source_effects": source_step["patch"][effect[0]:effect[1]],
                           "effect_sites": [(effect["ref"], effect["path"])
                                            for effect in reversed(source_step["patch"][effect[0]:effect[1]])]})
        native_end, effect_end = native[1], effect[1]
    require(native_end == len(command["writes"]) and effect_end == len(source_step["patch"]),
            "inherited inverse ranges do not cover authenticated history")
    return list(reversed(partitions))


def _inverse_stage_shared_source(entry, step, commands):
    """Recover a retained shared input from its accepted copy effects and pins."""
    bindings = [binding for ordinal in step["command_ordinals"]
                for binding in commands[ordinal]["bindings"]
                if binding.get("key") == "commit.materialization"]
    if not any(len(binding.get("owners", [])) > 1 for binding in bindings):
        return None
    if len(commands) != 1 or commands[0]["command"]["op"] != "occurrence.swap-media":
        return None
    # This representation has one copy boundary. Other stage shapes retain the
    # ordinary turnover checks; a shared owner list alone grants no projection.
    require(len(commands) == 1 and step["command_ordinals"] == [0]
            and len(entry["records"]["steps"]) == 1 and len(bindings) == 2
            and not commands[0].get("derived_writes"),
            "shared inverse source has no unique copy boundary")
    result = entry["receipt"]["result"]
    document = result["canonical_document"]
    require(result["document_digest"] == digest(document), "shared inverse source document digest differs")
    output = images(document)
    source = copy.deepcopy(output)
    roots = [effect for effect in step["patch"] if effect["ref"] != "parent"]
    edges = [effect for effect in step["patch"] if effect["ref"] == "parent"]
    owner = bindings[0].get("owner")
    require(isinstance(owner, str) and re.fullmatch(r"occurrence:[^/]+/shot", owner)
            and len(roots) == len(edges) == 2 and len(step["patch"]) == 4,
            "shared inverse source copy effects are malformed")
    occurrence = owner.removeprefix("occurrence:").removesuffix("/shot")
    owner_path = ["occurrences", "occurrence_id:" + occurrence]
    require([effect["path"] for effect in edges] ==
            [[*owner_path, "shot_id"], [*owner_path, "shot_revision_id"]],
            "shared inverse source copy edges differ from its owner")
    for effect in step["patch"]:
        require(effect["op"] == "set" and effect["ref"] in output
                and value_equal(location(output[effect["ref"]]["payload"], effect["path"]),
                                {"state": "present", "value": effect["value"]}),
                "shared inverse source effect differs from its accepted output")
        if effect["ref"] == "parent":
            require(effect["before"]["state"] == "present", "shared inverse source owner is absent")
            source["parent"]["payload"] = project_observation(
                source["parent"]["payload"], effect["path"], effect["before"])
        else:
            require(not effect["path"] and effect["before"] == {"state": "absent"},
                    "shared inverse source root is not a copy birth")
            source.pop(effect["ref"])
    parent_pins = [pin for pin in commands[0]["bindings"] if pin.get("key") == "commit.effect"
                   and pin.get("physical_ref") == "parent" and pin.get("boundary", {}).get("side") == "before"]
    require(parent_pins and all(pin.get("revision_id") == entry["previous"]["revision_id"]
                               and pin.get("content_digest") == digest(source["parent"]["payload"])
                               for pin in parent_pins),
            "shared inverse source input parent differs from its accepted pin")
    source["parent"]["revision_id"] = entry["previous"]["revision_id"]
    source["parent"]["content_digest"] = digest(source["parent"]["payload"])
    pairs = []
    for binding in bindings:
        old, new = binding.get("physical_ref"), binding.get("successor")
        require(isinstance(old, str) and isinstance(new, str) and old != new
                and old in source and old in output and new in output and new not in source
                and binding.get("ref") == old and binding.get("owner") == owner
                and binding.get("step_id") == step["id"]
                and binding.get("policy") == "fixed" and binding.get("dependencies") == []
                and binding.get("boundary") == {
                    "base_revision_id": result["base_revision_id"],
                    "base_publication_id": result["base_publication_id"],
                    "evaluated_head": entry["previous"], "step_id": step["id"],
                    "command_ordinal": 0, "phase": "input"},
                "shared inverse source materialization attribution differs from history")
        owners = ["occurrence:" + row["occurrence_id"] + "/shot"
                  for row in source["parent"]["payload"]["occurrences"]
                  if old == "shot-revision:" + row["shot_revision_id"]
                  or old == "internal-revision:" + str(source[
                      "shot-revision:" + row["shot_revision_id"]]["internal_timeline_revision_id"])]
        require(binding.get("owners") == owners and owner in owners and len(owners) > 1
                and binding.get("revision_id") == source[old]["revision_id"]
                and binding.get("content_digest") == source[old]["content_digest"]
                and source[old]["content_digest"] == digest(source[old]["payload"]),
                "shared inverse source owner or image pin differs from history")
        sibling = [item for item in bindings if item is not binding]
        require(len(sibling) == 1 and binding.get("edge_before") == sibling[0].get("physical_ref")
                and binding.get("edge_after") == sibling[0].get("successor"),
                "shared inverse source sibling edge differs from history")
        pins = [pin for pin in commands[0]["bindings"] if pin.get("key") == "commit.effect"
                and pin.get("physical_ref") == new and pin.get("boundary", {}).get("side") == "after"]
        require(len(pins) == 1 and pins[0].get("owners") == [owner]
                and pins[0].get("revision_id") == output[new]["revision_id"]
                and pins[0].get("content_digest") == output[new]["content_digest"]
                and output[new]["content_digest"] == digest(output[new]["payload"]),
                "shared inverse source copy pin differs from history")
        pairs.append((old, new))
    shot_pairs = [(old, new) for old, new in pairs if old.startswith("shot-revision:")]
    internal_pairs = [(old, new) for old, new in pairs if old.startswith("internal-revision:")]
    require(len(shot_pairs) == len(internal_pairs) == 1, "shared inverse source copy roots are malformed")
    old_shot, new_shot = shot_pairs[0]
    old_internal, new_internal = internal_pairs[0]
    require([effect["ref"] for effect in roots] == [new_internal, new_shot],
            "shared inverse source copy roots are reordered")
    before_row = location(source["parent"]["payload"], owner_path)["value"]
    after_row = location(output["parent"]["payload"], owner_path)["value"]
    require(isinstance(before_row, dict) and isinstance(after_row, dict),
            "shared inverse source consumer is malformed")
    assert isinstance(before_row, dict) and isinstance(after_row, dict)
    project, timeline = document["project_id"], document["timeline_id"]
    require(before_row["shot_revision_id"] == old_shot.partition(":")[2]
            and after_row["shot_revision_id"] == new_shot.partition(":")[2]
            and source[old_shot]["shot_id"] == before_row["shot_id"]
            and output[new_shot]["shot_id"] == after_row["shot_id"]
            and after_row["shot_id"] == _authoring_identity(
                "shot-placement", project, timeline, occurrence, before_row["shot_id"])
            and source[old_shot]["internal_timeline_revision_id"] == old_internal.partition(":")[2]
            and output[new_shot]["internal_timeline_revision_id"] == new_internal.partition(":")[2],
            "shared inverse source copy differs from its accepted owner edges")
    mapping = {}
    localized = copy.deepcopy(source)
    payload = localized[old_shot]["payload"]
    for item in payload.get("items", []):
        identity = item.get("item_id")
        require(isinstance(identity, str) and identity and identity not in mapping,
                "shared inverse source item identity is ambiguous")
        mapping[identity] = _authoring_identity(
            "shot-item-placement", project, timeline, occurrence, after_row["shot_id"], identity)
    for item in payload.get("items", []):
        item["item_id"] = mapping[item["item_id"]]
        descriptor = item.get("metadata")
        if not isinstance(descriptor, dict):
            descriptor = item
        for field in ("source_item_id", "source_item"):
            if isinstance(descriptor.get(field), str):
                descriptor[field] = mapping.get(descriptor[field], descriptor[field])
    restored = copy.deepcopy(localized)
    mapped_writes = []
    for write in commands[0]["writes"]:
        projected = copy.deepcopy(write)
        if write["ref"] == owner and write["path"][:2] == ["payload", "items"]:
            path = write["path"]
            require(len(path) == 4 and path[2].startswith("item_id:")
                    and path[2].removeprefix("item_id:") in mapping and path[3] == "media_id",
                    "shared inverse source item capture is not a mapped media leaf")
            projected["path"][2] = "item_id:" + mapping[path[2].removeprefix("item_id:")]
        ref, path = native_site(localized, projected["ref"], projected["path"])
        require(ref in (old_shot, old_internal)
                and value_equal(location(localized[ref]["payload"], path), write["before"]),
                "shared inverse source native input differs from history")
        localized[ref]["payload"] = project_observation(localized[ref]["payload"], path, write["after"])
        mapped_writes.append({**projected, "before": write["after"], "after": write["before"]})
    localized[old_shot]["payload"]["internal_timeline_revision_id"] = new_internal.partition(":")[2]
    require(value_equal(localized[old_shot]["payload"], output[new_shot]["payload"])
            and value_equal(localized[old_internal]["payload"], output[new_internal]["payload"]),
            "shared inverse source native captures do not cover its accepted copy")
    inverse_effects = [{**effect, "before": {"state": "present", "value": effect["value"]},
                        "value": effect["before"]["value"]} for effect in edges]
    inverse_effects.extend({"op": "remove", "ref": effect["ref"], "path": [],
                            "before": {"state": "present", "value": effect["value"]}}
                           for effect in reversed(roots))
    return {"source": source, "output": output, "restored": restored, "pairs": pairs,
            "owner_path": owner_path, "writes": list(reversed(mapped_writes)), "effects": inverse_effects}


def _inverse_stage_restore_shared(native_image, before, after, shared):
    """Restore only the accepted consumer; retained sibling images stay sealed."""
    owner_path = shared["owner_path"]
    require(value_equal(location(before["parent"]["payload"], owner_path),
                        location(shared["output"]["parent"]["payload"], owner_path))
            and value_equal(location(after["parent"]["payload"], owner_path),
                            location(shared["source"]["parent"]["payload"], owner_path)),
            "shared inverse consumer differs from its accepted source edges")
    for old, new in shared["pairs"]:
        require(old in before and old in after and new in before and new not in after
                and value_equal(before[old], shared["source"][old])
                and value_equal(after[old], before[old])
                and value_equal(before[new], shared["output"][new]),
                "shared inverse physical images differ from accepted history")
        expected = copy.deepcopy(shared["restored"][old]["payload"])
        if old.startswith("shot-revision:"):
            expected["internal_timeline_revision_id"] = before[new]["internal_timeline_revision_id"]
        require(value_equal(native_image[new]["payload"], expected)
                and value_equal(native_image[old], before[old]),
                "shared inverse native writes change a retained image")
        native_image.pop(new)
    for row in before["parent"]["payload"]["occurrences"]:
        path = ["occurrences", "occurrence_id:" + row["occurrence_id"]]
        if path != owner_path:
            require(value_equal(location(after["parent"]["payload"], path),
                                {"state": "present", "value": row}),
                    "shared inverse changes an untouched consumer")
    native_image["parent"]["payload"] = project_observation(
        native_image["parent"]["payload"], owner_path,
        location(shared["source"]["parent"]["payload"], owner_path))


def _inverse_stage_history(records, history):
    """Return the authenticated source stages named by an inverse record."""
    publications = records.get("undo_of")
    require(isinstance(publications, list) and publications and
            all(isinstance(publication, str) and publication for publication in publications)
            and len(set(publications)) == len(publications),
            "inverse stage history targets are malformed")
    require(isinstance(history, dict), "inverse stage history is unavailable")
    require(set(history) == set(publications), "inverse stage history includes non-source publications")
    selected = records.get("undo_steps")
    if selected is not None:
        require(isinstance(selected, dict) and set(selected) == set(publications),
                "inverse stage selection does not cover its history targets")

    selected_stages = []
    for publication in reversed(publications):
        entry = history.get(publication)
        require(isinstance(entry, dict) and entry.get("publication_id") == publication
                and entry.get("intent") == "recorded"
                and isinstance(entry.get("receipt"), dict)
                and entry["receipt"].get("receipt_id") == publication,
                "inverse stage source publication is not authenticated")
        source_records = entry.get("records")
        require(isinstance(source_records, dict)
                and isinstance(source_records.get("commands"), list)
                and isinstance(source_records.get("steps"), list)
                and source_records["commands"],
                "inverse stage source command history is unavailable")
        assert isinstance(source_records, dict)
        commands = source_records["commands"]
        require([record.get("ordinal") for record in commands] == list(range(len(commands))),
                "inverse stage source command ordinals are unavailable")
        source_steps = source_records["steps"]
        assert isinstance(commands, list) and isinstance(source_steps, list)
        step_by_id = {source_step.get("id"): source_step for source_step in source_steps}
        require(len(step_by_id) == len(source_steps) and all(isinstance(identity, str) and identity
                                                            for identity in step_by_id),
                "inverse stage source steps are malformed")
        requested = (list(step_by_id) if selected is None else selected.get(publication))
        require(isinstance(requested, list) and requested and
                all(isinstance(identity, str) and identity in step_by_id for identity in requested)
                and len(set(requested)) == len(requested),
                "inverse stage selected source steps are unavailable")
        for source_step in reversed(source_steps):
            if source_step["id"] not in requested:
                continue
            ordinals = source_step.get("command_ordinals")
            require(isinstance(ordinals, list) and ordinals
                    and ordinals == list(range(ordinals[0], ordinals[0] + len(ordinals)))
                    and all(type(ordinal) is int and 0 <= ordinal < len(commands) for ordinal in ordinals),
                    "inverse stage source step command boundary is malformed")
            source_commands = [commands[ordinal] for ordinal in ordinals]
            selected_stages.append((publication, entry, source_step, source_commands))

    # Only whole-clip reversals promote literal timing caches to native writes.
    # Leaf anchor edits restore/recompute timing separately as derived writes.
    clip_roots = {write["ref"] for _, _, _, commands in selected_stages
                  for command in commands for write in command.get("writes", [])
                  if write["ref"].startswith("parent/clip:") and not write["path"]}
    timing_sites = {(write["ref"], tuple(write["path"])) for _, _, _, commands in selected_stages
                    for command in commands for write in command.get("derived_writes", [])
                    if write["ref"].startswith("parent/clip:") and write["path"] in (["at"], ["hold"])}
    expected = []
    for publication, entry, source_step, source_commands in selected_stages:
        source_records = entry["records"]
        commands = source_records["commands"]
        ordinals = source_step["command_ordinals"]
        inherited = _inverse_stage_inherited(source_step, source_commands, source_records, publication)
        if inherited is not None:
            expected.extend({"publication_id": publication, "step_id": source_step["id"],
                             "command_ordinals": ordinals, **partition} for partition in inherited)
            continue
        shared = _inverse_stage_shared_source(entry, source_step, commands)
        native_sites = []
        command_boundaries = []
        native_end = 0
        for command in reversed(source_commands):
            command_writes = list(reversed([*command.get("writes", []),
                *(write for write in command.get("derived_writes", [])
                  if write.get("ref") in clip_roots
                  and write.get("path") in (["at"], ["hold"]))]))
            native_sites.extend((write["ref"], write["path"]) for write in command_writes)
            native_end += len(command_writes)
            structural_clip_write = any(
                write["ref"].startswith("parent/clip:") and not write["path"]
                and write["before"].get("state") == "present"
                and write["after"].get("state") == "absent"
                for write in command.get("writes", []))
            if structural_clip_write:
                selections = [selection for selection in command.get("selections", [])
                              if selection.get("key") == "collection.clips"
                              and selection.get("owner") == "parent"]
                require(len(selections) == 1,
                        "inverse stage structural clip write has no unique source order")
                command_boundaries.append({"native_end": native_end,
                                           "selection": copy.deepcopy(selections[0])})
        expected.append({"publication_id": publication, "step_id": source_step["id"],
                         "command_ordinals": ordinals,
                         "native_sites": ([(write["ref"], write["path"]) for write in shared["writes"]]
                                          if shared is not None else native_sites),
                         "command_boundaries": (command_boundaries if shared is None else []),
                         "shared": shared,
                         "empty_native": (not native_sites and not source_step["patch"]
                                          and not any(command.get("writes")
                                                      or command.get("derived_writes")
                                                      for command in source_commands))})
    for stage in expected:
        stage["timing_sites"] = timing_sites
    return expected


def _inverse_stage_ranges(step, records, history=None):
    """Validate the recorder's stage partition without trusting its images."""
    stages = []
    stage_records = []
    for ordinal in step["command_ordinals"]:
        record = records["commands"][ordinal]
        for binding in record["bindings"]:
            if binding.get("key") == "inverse.stage":
                stages.append(binding)
                stage_records.append(record)
    if not stages:
        require(not any(records["commands"][ordinal]["command"]["op"] == "timeline.inverse"
                        for ordinal in step["command_ordinals"]),
                "inverse stage provenance is absent")
        return None

    expected = _inverse_stage_history(records, history)
    require(len(stages) == len(expected),
            "inverse stage provenance does not match authenticated history")

    require(all(records["commands"][ordinal]["command"]["op"] == "timeline.inverse"
                for ordinal in step["command_ordinals"]),
            "inverse stage provenance is attached to a non-inverse command")
    final_ordinal = step["command_ordinals"][-1]
    require(all(record["ordinal"] == final_ordinal for record in stage_records),
            "inverse stage provenance is attached to the wrong command")
    record = records["commands"][final_ordinal]
    previous_native_end = 0
    previous_effect_end = 0
    result = []
    for binding, source_stage in zip(stages, expected):
        boundary = binding.get("boundary")
        require(isinstance(boundary, dict), "inverse stage boundary is absent or malformed")
        step_id = boundary.get("step_id")
        command_ordinals = boundary.get("command_ordinals")
        require(binding.get("ref") == "parent" and binding.get("policy") == "fixed"
                and binding.get("dependencies") == []
                and boundary.get("publication_id") == source_stage["publication_id"]
                and step_id == source_stage["step_id"]
                and command_ordinals == source_stage["command_ordinals"],
                "inverse stage provenance differs from authenticated source history")
        require(isinstance(step_id, str) and step_id
                and isinstance(command_ordinals, list) and command_ordinals
                and all(type(item) is int and item >= 0 for item in command_ordinals)
                and len(set(command_ordinals)) == len(command_ordinals)
                and command_ordinals == sorted(command_ordinals),
                "inverse stage command provenance is malformed")
        native_range = boundary.get("native_write_range")
        effect_range = boundary.get("effect_range")
        require(isinstance(native_range, list) and len(native_range) == 2
                and all(type(item) is int for item in native_range),
                "inverse stage native range is malformed")
        require(isinstance(effect_range, list) and len(effect_range) == 2
                and all(type(item) is int for item in effect_range),
                "inverse stage effect range is malformed")
        native_start, native_end = native_range
        effect_start, effect_end = effect_range
        # A media.admit-only step survives as an authenticated, zero-effect
        # inverse stage; its empty spans are valid only when source history is empty too.
        empty_native_stage = source_stage.get("empty_native", False)
        native_span_valid = (
            native_start == previous_native_end
            and native_end <= len(record["writes"])
            and (native_start == native_end if empty_native_stage else native_start < native_end)
        )
        require(native_end - native_start == len(source_stage["native_sites"])
                and native_span_valid
                and (not empty_native_stage or effect_start == effect_end),
                "inverse stage native ranges are missing, reordered, or overlapping")
        require(effect_start == previous_effect_end and effect_start <= effect_end <= len(step["patch"]),
                "inverse stage effect ranges are missing, reordered, or overlapping")
        native_sites = [(write["ref"], write["path"]) for write in record["writes"][native_start:native_end]]
        effect_sites = [(effect["ref"], effect["path"]) for effect in step["patch"][effect_start:effect_end]]
        if "source_writes" in source_stage:
            require(value_equal(record["writes"][native_start:native_end], source_stage["source_writes"])
                    and effect_sites == source_stage["effect_sites"],
                    "inherited inverse native captures or effects differ from authenticated history")
            for effect, source_effect in zip(step["patch"][effect_start:effect_end],
                                             reversed(source_stage["source_effects"])):
                require(source_effect["op"] in {"set", "remove"} and effect["op"] in {"set", "remove"},
                        "inherited inverse effects are not authenticated observations")
                source_after = ({"state": "present", "value": source_effect["value"]}
                                if source_effect["op"] == "set" else {"state": "absent"})
                after = ({"state": "present", "value": effect["value"]}
                         if effect["op"] == "set" else {"state": "absent"})
                require(value_equal(effect["before"], source_after)
                        and value_equal(after, source_effect["before"]),
                        "inherited inverse effects differ from authenticated source images")
        if source_stage.get("shared") is not None:
            require(value_equal(record["writes"][native_start:native_end], source_stage["shared"]["writes"])
                    and value_equal(step["patch"][effect_start:effect_end], source_stage["shared"]["effects"]),
                    "shared inverse native captures differ from authenticated history")
        # A recorder may observe the exact canonical stage effects directly or
        # retain the source's finer native captures in reverse execution order.
        # Neither representation permits extra sites or mere ancestor overlap.
        require(native_sites == source_stage["native_sites"] or native_sites == effect_sites,
                "inverse stage native write membership differs from its authenticated stage")
        previous_native_end, previous_effect_end = native_end, effect_end
        result.append({"binding": binding, "record": record, "native_range": native_range,
                       "effect_range": effect_range, "source_stage": source_stage})
    require(previous_native_end == len(record["writes"])
            and previous_effect_end == len(step["patch"]),
            "inverse stage ranges do not cover the authenticated inverse")
    return result


def _inverse_stage_timing(native_image, stage_before, stage_after, stage, source_step, source_commands):
    """Authenticate compiler timing separately from authored inverse captures."""
    if source_step is None:
        return
    sources = {}
    for ordinal in source_step["command_ordinals"]:
        for write in source_commands[ordinal].get("derived_writes", []):
            if write["ref"].startswith("parent/clip:") and write["path"] in (["at"], ["hold"]):
                sources.setdefault((write["ref"], tuple(write["path"])), write)
    timing_sites = stage.get("source_stage", {}).get("timing_sites", set(sources))
    require(all((write["ref"], tuple(write["path"])) in timing_sites
                for write in stage["record"].get("derived_writes", [])
                if write["ref"].startswith("parent/clip:") and write["path"] in (["at"], ["hold"])),
            "inverse stage timing is outside its authenticated source history")
    for (clip, cache_path), source in sources.items():
        ref, path = _inverse_stage_write_site(native_image, source)
        observed = _inverse_stage_state(native_image, ref, path)
        after = _inverse_stage_state(stage_after, ref, path)
        if after == {"state": "absent"} and value_equal(observed, after):
            continue
        anchor_ref, anchor_path = native_site(stage_after, clip, ["app", "astrid", "word_anchors"])
        if not _inverse_stage_state(stage_after, anchor_ref, anchor_path).get("value"):
            # With no remaining anchor there is nothing to recompute: recover
            # the exact literal cache authenticated by the source publication.
            require(value_equal(after, source["before"]),
                    "inverse stage timing differs from its authenticated literal cache")
        captures = [write for write in stage["record"].get("derived_writes", [])
                    if write["ref"] == clip and write["path"] == list(cache_path)]
        require((not captures and value_equal(observed, after))
                or len(captures) == 1 and value_equal(captures[0]["before"],
                _inverse_stage_state(stage_before, ref, path))
                and value_equal(captures[0]["after"], after),
                "inverse stage timing differs from its derived capture")
        payload = native_image[ref]["payload"]
        native_image[ref]["payload"] = project_observation(
            payload, stored_path(payload, ref, path), after)
        projected = native_image[ref]["payload"]
        if "clips" in projected and "clips" in projected.get("config", {}):
            projected["clips"] = copy.deepcopy(projected["config"]["clips"])


def _inverse_stage_boundaries(boundary, output, step, records, accepted, original, history=None):
    stages = _inverse_stage_ranges(step, records, history)
    if stages is None:
        return None
    current = boundary
    effect_boundaries = {}
    authenticated_turnovers = []
    effect_bindings = [binding for ordinal in step["command_ordinals"]
                       for binding in records["commands"][ordinal]["bindings"]
                       if binding.get("key") == "commit.effect"]
    for stage in stages:
        effect_start, effect_end = stage["effect_range"]
        stage_before = current
        stage_step = {**step, "patch": step["patch"][effect_start:effect_end]}
        stage_after = step_output(stage_before, stage_step, records, accepted, original=stage_before)
        native_start, native_end = stage["native_range"]
        writes = stage["record"]["writes"][native_start:native_end]
        source_boundary = stage["binding"].get("boundary", {})
        source_entry = (history or {}).get(source_boundary.get("publication_id"), {})
        source_records = source_entry.get("records", {})
        source_commands = source_records.get("commands", [])
        source_steps = source_records.get("steps", [])
        source_step = next((item for item in source_steps
                            if item.get("id") == source_boundary.get("step_id")), None)
        source_bindings = []
        if source_step is not None:
            source_bindings = [binding for ordinal in source_step.get("command_ordinals", [])
                               if isinstance(ordinal, int) and ordinal < len(source_commands)
                               for binding in source_commands[ordinal].get("bindings", [])
                               if binding.get("key") == "commit.materialization"]
        native_image = copy.deepcopy(stage_before)
        inherited_effects = stage["source_stage"].get("source_effects")
        root_checks = []
        native_sites = []
        clip_order_boundaries = stage["source_stage"].get("command_boundaries", [])
        require(all(type(item.get("native_end")) is int and 0 < item["native_end"] <= len(writes)
                    for item in clip_order_boundaries)
                and [item["native_end"] for item in clip_order_boundaries]
                == sorted({item["native_end"] for item in clip_order_boundaries}),
                "inverse stage source clip-order boundaries are malformed")
        clip_order_boundary_index = 0
        # Native captures observe each preceding write (including empty ancestor
        # removals); canonical effects describe the complete stage transition.
        for write_index, write in enumerate(writes):
            while (clip_order_boundary_index < len(clip_order_boundaries)
                   and clip_order_boundaries[clip_order_boundary_index]["native_end"] == write_index):
                _inverse_stage_restore_clip_order(
                    native_image, {"selections": [clip_order_boundaries[
                        clip_order_boundary_index]["selection"]]})
                clip_order_boundary_index += 1
            if not write["path"] and re.fullmatch(r"(?:shot|occurrence):[^/]+", write["ref"]):
                root = write["ref"]
                observed, physical = _inverse_stage_root(native_image, root)
                after, successors = _inverse_stage_root(stage_after, root)
                if root.startswith("occurrence:"):
                    path = ["occurrences", "occurrence_id:" + root.partition(":")[2]]
                    state = location(stage_after["parent"]["payload"], path, absent_items=True)
                    native_image["parent"]["payload"] = project_observation(
                        native_image["parent"]["payload"], path, state)
                else:
                    for ref in physical:
                        if ref.startswith("internal-revision:") and any(
                                image.get("internal_timeline_revision_id") == ref.partition(":")[2]
                                for key, image in native_image.items()
                                if key.startswith("shot-revision:") and key not in physical):
                            continue
                        native_image.pop(ref)
                    for ref in successors:
                        native_image[ref] = copy.deepcopy(stage_after[ref])
                    if (inherited_effects is not None and observed == {"state": "absent"}
                            and after["state"] == write["after"]["state"] == "present"):
                        # The sealed inverse restores the aggregate before its
                        # later child writes. Keep the authenticated physical
                        # pins, but replay from the exact source aggregate.
                        internal = next(ref for ref in successors if ref.startswith("internal-revision:"))
                        native_image[internal]["payload"] = copy.deepcopy(
                            write["after"]["value"]["internal_timeline"])
                        after, _ = _inverse_stage_root(native_image, root)
                root_checks.append((observed, write["before"], root, physical,
                                    after, write["after"], successors))
                continue
            ref, path = _inverse_stage_write_site(native_image, write)
            native_sites.append((ref, path))
            if (inherited_effects is not None and write["ref"].startswith("occurrence:")
                    and "/" not in write["ref"] and write["path"] == ["shot_id"]):
                occurrence_path = ["occurrences", "occurrence_id:" + write["ref"].partition(":")[2]]
                for field in ("shot_id", "shot_revision_id"):
                    captures = [effect for effect in inherited_effects
                                if effect["ref"] == "parent" and effect["path"] == [*occurrence_path, field]]
                    require(len(captures) == 1 and captures[0]["op"] == "set"
                            and value_equal(location(stage_before["parent"]["payload"], [*occurrence_path, field]),
                                            {"state": "present", "value": captures[0]["value"]})
                            and value_equal(location(stage_after["parent"]["payload"], [*occurrence_path, field]),
                                            captures[0]["before"]),
                            "inherited inverse occurrence differs from authenticated source edges")
                    native_image["parent"]["payload"] = project_observation(
                        native_image["parent"]["payload"], [*occurrence_path, field], captures[0]["before"])
                continue
            require(value_equal(_inverse_stage_state(native_image, ref, path), write["before"]),
                    "inverse stage write differs from its sequential input")
            if ref == "timeline":
                assert source_step is not None
                captures = [capture for ordinal in source_step["command_ordinals"]
                            for capture in source_commands[ordinal]["writes"]]
                require(len(writes) == len(captures) == 1
                        and captures[0]["ref"] == "timeline" and captures[0]["path"] == []
                        and value_equal(captures[0]["after"], write["before"])
                        and value_equal(captures[0]["before"], write["after"])
                        and value_equal(_inverse_stage_state(stage_after, ref, path), write["after"]),
                        "inverse stage timeline capture differs from authenticated source endpoints")
                effects = []
                for effect in reversed(source_step["patch"]):
                    require(effect["op"] in {"set", "remove"},
                            "inverse stage timeline source effects are not authenticated observations")
                    restored = {"op": "set" if effect["before"]["state"] == "present" else "remove",
                                "ref": effect["ref"], "path": effect["path"],
                                "before": ({"state": "present", "value": effect["value"]}
                                           if effect["op"] == "set" else {"state": "absent"})}
                    if restored["op"] == "set":
                        restored["value"] = effect["before"]["value"]
                    effects.append(restored)
                require(value_equal(stage_step["patch"], effects),
                        "inverse stage timeline effects differ from authenticated source history")
                # The native whole-closure capture carries an immutable parent
                # pin, not a payload root. The exact reversed source pins bind
                # the complete endpoint projected from this stage's effects.
                native_image = copy.deepcopy(stage_after)
            elif ref == "parent" and path == ["occurrences"]:
                require(write["before"]["state"] == "present",
                        "inverse stage occurrence order has no input collection")
                rows = write["after"].get("value")
                authored = {row["occurrence_id"]: row for row in write["before"]["value"]}
                require(write["after"]["state"] == "present" and isinstance(rows, list)
                        and len(rows) == len(authored)
                        and all(isinstance(row, dict) and isinstance(row.get("occurrence_id"), str)
                                and row["occurrence_id"] in authored
                                and value_equal(row, authored[row["occurrence_id"]]) for row in rows)
                        and len({row["occurrence_id"] for row in rows}) == len(authored),
                        "inverse stage occurrence order is not a row-preserving permutation")
                # The sequential input check authenticated each physical pin.
                # Reorder those exact rows; authored captures cannot supply pins.
                physical = {row["occurrence_id"]: row
                            for row in native_image["parent"]["payload"]["occurrences"]}
                native_image["parent"]["payload"]["occurrences"] = [
                    copy.deepcopy(physical[row["occurrence_id"]]) for row in rows]
            elif not path and ref not in native_image:
                require(ref in stage_after and value_equal(
                    {"state": "present", "value": stage_after[ref]["payload"]}, write["after"]),
                    "inverse stage root differs from its authenticated effect image")
                native_image[ref] = copy.deepcopy(stage_after[ref])
            elif not path and write["after"]["state"] == "absent":
                native_image.pop(ref)
            else:
                payload = native_image[ref]["payload"]
                observed_path = stored_path(payload, ref, path)
                native_image[ref]["payload"] = project_observation(payload, observed_path, write["after"])
                if (write["ref"].startswith("occurrence:") and "/" not in write["ref"]
                        and write["path"] == ["shot_id"] and source_step is not None):
                    fork_commands = [source_commands[ordinal]
                                     for ordinal in source_step["command_ordinals"]
                                     if source_commands[ordinal]["command"]["op"] == "occurrence.fork"]
                    captures = [capture for command in fork_commands for capture in command["writes"]
                                if capture["ref"] == write["ref"] and capture["path"] == write["path"]]
                    if captures:
                        require(len(captures) == 1 and value_equal(captures[0]["after"], write["before"])
                                and value_equal(captures[0]["before"], write["after"]),
                                "inverse fork differs from its authenticated native capture")
                        occurrence_path = ["occurrences", "occurrence_id:" + write["ref"].partition(":")[2]]
                        # The native fork's source alias can predate the physical
                        # source pin. Restore that exact accepted source pair.
                        for field in ("shot_id", "shot_revision_id"):
                            effects = [effect for effect in source_step["patch"]
                                       if effect["ref"] == "parent" and effect["path"] == [*occurrence_path, field]]
                            require(len(effects) == 1 and effects[0]["op"] == "set"
                                    and value_equal(location(stage_before["parent"]["payload"],
                                                             [*occurrence_path, field]),
                                                    {"state": "present", "value": effects[0]["value"]}),
                                    "inverse fork differs from its authenticated source edge")
                            native_image["parent"]["payload"] = project_observation(
                                native_image["parent"]["payload"], [*occurrence_path, field], effects[0]["before"])
                if ref == "parent" and write["ref"].startswith(("parent/clip:", "parent/asset:")):
                    projected = native_image[ref]["payload"]
                    for mirror in (("clips",) if write["ref"].startswith("parent/clip:") else ("registry",)):
                        if mirror in projected and mirror in projected.get("config", {}):
                            projected[mirror] = copy.deepcopy(projected["config"][mirror])
        while (clip_order_boundary_index < len(clip_order_boundaries)
               and clip_order_boundaries[clip_order_boundary_index]["native_end"] == len(writes)):
            _inverse_stage_restore_clip_order(
                native_image, {"selections": [clip_order_boundaries[
                    clip_order_boundary_index]["selection"]]})
            clip_order_boundary_index += 1
        require(clip_order_boundary_index == len(clip_order_boundaries),
                "inverse stage source clip-order boundary was not replayed")
        # A leaf native write can restore authored bytes while the accepted
        # source records an authenticated physical turnover.  In that case,
        # reverse the source materialization edges; never infer a new root or
        # copy an arbitrary stage image.
        shared = stage["source_stage"].get("shared")
        if shared is not None:
            _inverse_stage_restore_shared(native_image, stage_before, stage_after, shared)
            source_bindings = []
        transitions = []
        for binding in source_bindings:
            assert source_step is not None
            source_new = binding.get("physical_ref")
            source_old = binding.get("successor")
            owner = binding.get("owner")
            attribution = binding.get("boundary", {})
            require(binding.get("ref") == source_new
                    and binding.get("step_id") == source_step["id"]
                    and attribution.get("step_id") == source_step["id"]
                    and attribution.get("command_ordinal") in source_step["command_ordinals"]
                    and attribution.get("phase") == "input"
                    and attribution.get("base_revision_id") == source_entry["receipt"]["result"]["base_revision_id"]
                    and attribution.get("base_publication_id") == source_entry["receipt"]["result"]["base_publication_id"]
                    and value_equal(attribution.get("evaluated_head"), source_entry["previous"]),
                    "inverse stage source materialization attribution differs from history")
            require(binding.get("policy") == "fixed"
                    and binding.get("dependencies") == []
                    and isinstance(source_new, str) and isinstance(source_old, str)
                    and source_new.startswith(("shot-revision:", "internal-revision:"))
                    and source_old.startswith(("shot-revision:", "internal-revision:")),
                    "inverse stage source materialization is malformed")
            old, new = source_old, source_new
            require(old != new and old in stage_before and new in stage_after
                    and old not in stage_after and new not in stage_before,
                    "inverse stage source materialization is outside its physical turnover")
            require(isinstance(owner, str) and owner.startswith("occurrence:")
                    and owner.endswith("/shot") and binding.get("owners") == [owner],
                    "inverse stage source materialization owner is malformed")
            occurrence = owner.removeprefix("occurrence:").removesuffix("/shot")
            before_rows = [row for row in stage_before["parent"]["payload"].get("occurrences", [])
                           if row.get("occurrence_id") == occurrence]
            after_rows = [row for row in stage_after["parent"]["payload"].get("occurrences", [])
                          if row.get("occurrence_id") == occurrence]
            require(len(before_rows) == len(after_rows) == 1,
                    "inverse stage materialization owner is absent or ambiguous")
            before_row, after_row = before_rows[0], after_rows[0]
            require(before_row["shot_id"] == after_row["shot_id"]
                    and _physical_owner(stage_before, old) == (occurrence, before_row["shot_id"])
                    and _physical_owner(stage_after, new) == (occurrence, after_row["shot_id"]),
                    "inverse stage materialization changes physical ownership")
            before_shot = "shot-revision:" + str(before_row["shot_revision_id"])
            after_shot = "shot-revision:" + str(after_row["shot_revision_id"])
            before_internal = "internal-revision:" + str(stage_before[before_shot]["internal_timeline_revision_id"])
            after_internal = "internal-revision:" + str(stage_after[after_shot]["internal_timeline_revision_id"])
            if old == before_shot and new == after_shot:
                expected_edges = (before_internal, after_internal)
            elif old == before_internal and new == after_internal:
                expected_edges = (before_shot, after_shot)
            else:
                require(False, "inverse stage materialization differs from its owner edges")
                expected_edges = (None, None)
            require(binding.get("edge_before") == expected_edges[1]
                    and binding.get("edge_after") == expected_edges[0]
                    and binding.get("revision_id") == stage_after[new]["revision_id"]
                    and binding.get("content_digest") == stage_after[new]["content_digest"],
                    "inverse stage source materialization differs from its successor image")
            source_images = [pin for ordinal in source_step["command_ordinals"]
                             for pin in source_commands[ordinal]["bindings"]
                             if pin.get("key") == "commit.effect" and pin.get("physical_ref") == new
                             and pin.get("boundary", {}).get("side") == "before"]
            require(source_images and all(pin.get("revision_id") == binding["revision_id"]
                                          and pin.get("content_digest") == binding["content_digest"]
                                          for pin in source_images),
                    "inverse stage materialization differs from its recorded source image")
            sibling = [item for item in source_bindings
                       if item.get("physical_ref") == binding.get("edge_before")
                       and item.get("successor") == binding.get("edge_after")]
            require(len(sibling) == 1 and sibling[0].get("owner") == owner
                    and sibling[0].get("owners") == [owner]
                    and sibling[0].get("edge_before") == source_new
                    and sibling[0].get("edge_after") == source_old,
                    "inverse stage source materialization has no authenticated sibling edge")
            require((old, new) not in [(item[0], item[1]) for item in transitions],
                    "inverse stage materialization has an ambiguous successor")
            transitions.append((old, new, before_internal, after_internal,
                                before_shot, after_shot))

        shot_turnovers = {(old, new): (before_internal, after_internal)
                          for old, new, before_internal, after_internal, _, _ in transitions
                          if old.startswith("shot-revision:")}
        for old, new, before_internal, after_internal, before_shot, after_shot in transitions:
            image = native_image.pop(old)
            expected = stage_after[new]
            if old.startswith("internal-revision:"):
                require(value_equal(image["payload"], expected["payload"]),
                        "inverse stage materialization changes internal payload")
            else:
                payload = copy.deepcopy(image["payload"])
                require(payload.get("internal_timeline_revision_id") == before_internal.partition(":")[2],
                        "inverse stage materialization has a wrong shot pin")
                payload["internal_timeline_revision_id"] = after_internal.partition(":")[2]
                require(value_equal(payload, expected["payload"]),
                        "inverse stage materialization changes shot payload")
                image["payload"] = payload
                image["internal_timeline_revision_id"] = after_internal.partition(":")[2]
            require(image.get("shot_id") == expected.get("shot_id"),
                    "inverse stage materialization changes physical ownership")
            image["revision_id"] = expected["revision_id"]
            image["content_digest"] = expected["content_digest"]
            require(image["content_digest"] == digest(image["payload"]),
                    "inverse stage materialization has an unauthenticated payload digest")
            native_image[new] = image
        for row in native_image["parent"]["payload"].get("occurrences", []):
            for old, new in shot_turnovers:
                if row.get("shot_revision_id") == old.partition(":")[2]:
                    row["shot_revision_id"] = new.partition(":")[2]
        for observed, before_claim, root, physical, after, after_claim, successors in root_checks:
            before_claim = copy.deepcopy(before_claim)
            after_claim = copy.deepcopy(after_claim)
            if inherited_effects is not None and root.startswith("shot:"):
                # These exact captures were authenticated at source acceptance.
                # Their native pin may precede a canonical physical turnover;
                # both endpoint images are fixed by the exact source effects.
                for claim, image in ((before_claim, observed), (after_claim, after)):
                    if claim["state"] == image["state"] == "present":
                        claim["value"]["payload"]["internal_timeline_revision_id"] = (
                            image["value"]["payload"]["internal_timeline_revision_id"])
            # A later aggregate capture retains the pin from the native source
            # execution. Translate only the exact edge already proved in an
            # earlier inverse stage, preserving every other aggregate byte.
            for claim, refs in ((before_claim, physical), (after_claim, successors)):
                if root.startswith("shot:") and claim["state"] == "present":
                    payload = claim["value"]["payload"]
                    for old, new, old_internal, new_internal, _, _ in authenticated_turnovers:
                        if (new in refs and old.startswith("shot-revision:")
                                and payload.get("internal_timeline_revision_id") == old_internal.partition(":")[2]):
                            payload["internal_timeline_revision_id"] = new_internal.partition(":")[2]
            require(_inverse_stage_root_equal(observed, before_claim, root),
                    "inverse stage root differs from its sequential input")
            require(_inverse_stage_root_equal(after, after_claim, root),
                    "inverse stage root differs from its authenticated effect image")
        authenticated_turnovers.extend(transitions)

        _inverse_stage_retire_occurrence_images(native_image, stage_before, writes,
                                               source_entry, source_step, source_commands)

        if inherited_effects is not None:
            # Reversing a sealed inverse also reopens physical roots that it
            # retired. Its exact effect reversal was checked by stage_ranges;
            # retain the source's immutable pins rather than infer new images.
            for effect in inherited_effects:
                ref = effect["ref"]
                if (effect["op"] != "remove" or effect["path"] or ref in native_image
                        or not ref.startswith(("shot-revision:", "internal-revision:"))):
                    continue
                require(ref in stage_after and value_equal(
                    effect["before"], {"state": "present", "value": stage_after[ref]["payload"]}),
                    "inherited inverse root differs from its authenticated source payload")
                assert source_step is not None
                pins = [pin for ordinal in source_step["command_ordinals"]
                        for pin in source_commands[ordinal]["bindings"]
                        if pin.get("key") == "commit.effect" and pin.get("physical_ref") == ref
                        and pin.get("boundary", {}).get("side") == "before"]
                owners = ["occurrence:" + row["occurrence_id"] + "/shot"
                          for row in stage_after["parent"]["payload"].get("occurrences", [])
                          if ref == "shot-revision:" + row["shot_revision_id"]
                          or ref == "internal-revision:" + str(stage_after.get(
                              "shot-revision:" + row["shot_revision_id"], {}).get("internal_timeline_revision_id"))]
                require(len(pins) == 1 and pins[0].get("revision_id") == stage_after[ref]["revision_id"]
                        and pins[0].get("content_digest") == stage_after[ref]["content_digest"]
                        and pins[0].get("owners") == owners and owners
                        and pins[0].get("policy") == "fixed" and pins[0].get("dependencies") == []
                        and stage_after[ref]["content_digest"] == digest(stage_after[ref]["payload"])
                        and _physical_owner(stage_after, ref) is not None,
                        "inherited inverse root differs from its authenticated source pin")
                native_image[ref] = copy.deepcopy(stage_after[ref])
            # Exact inverse source effects already authenticate both physical
            # endpoints. Align only complete equal payloads with the same owner.
            _align_materialized_images(native_image, stage_after)

        _inverse_stage_timing(native_image, stage_before, stage_after, stage, source_step, source_commands)
        require(value_equal({ref: image["payload"] for ref, image in native_image.items()},
                            {ref: image["payload"] for ref, image in stage_after.items()}),
                "inverse stage native writes do not cover its authenticated effect image")
        for write in writes:
            if not write["path"] and re.fullmatch(r"(?:shot|occurrence):[^/]+", write["ref"]):
                require(value_equal(_inverse_stage_root(native_image, write["ref"])[0],
                                    _inverse_stage_root(stage_after, write["ref"])[0]),
                        "inverse stage roots differ from its authenticated effect image")
        # Each native site belongs to its sequential input. Later writes may
        # remove its alias/owner; compare the resolved physical site, following
        # only the complete source turnovers authenticated above.
        for ref, path in native_sites:
            for old, new, _, _, _, _ in transitions:
                if ref == old:
                    ref = new
            require(value_equal(_inverse_stage_state(native_image, ref, path),
                                _inverse_stage_state(stage_after, ref, path)),
                    "inverse stage writes differ from its authenticated effect image")
        for index in range(effect_start, effect_end):
            effect = step["patch"][index]
            for side, image in (("before", stage_before), ("after", stage_after)):
                if (effect["ref"] in image or (not effect["path"]
                        and effect["ref"].startswith(("shot-revision:", "internal-revision:")))):
                    physical = effect["ref"]
                else:
                    physical, _ = site(image, effect["ref"], effect["path"])
                expected = [binding for binding in effect_bindings
                            if binding.get("effect_ordinal") == index
                            and binding.get("boundary", {}).get("side") == side
                            and binding.get("physical_ref") == physical]
                if physical in image:
                    require(len(expected) == 1,
                            "provider inverse effect bindings do not cover its stage image")
            effect_boundaries[index] = (stage_before, stage_after)
        current = stage_after
    require(value_equal(current, output), "inverse stage images do not reach the authenticated output")
    return effect_boundaries


def _authoring_parent_identity(boundary, identity_scope, manifest):
    """Derive the parent pin from sequential images and retained input pins."""
    project_id, timeline_id = identity_scope
    manifest = copy.deepcopy(manifest or {"media": [], "documents": []})
    for family, prefix, keys, order in (
            ("shots", "shot-revision:", ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest"),
             ("shot_id", "revision_id")),
            ("internal_timelines", "internal-revision:", ("timeline_id", "revision_id", "content_digest"),
             ("timeline_id", "revision_id"))):
        manifest[family] = sorted(({key: image[key] for key in keys} for ref, image in boundary.items()
                                   if ref.startswith(prefix)), key=lambda row: tuple(row[key] for key in order))
    return "authoring-parent-revision-" + digest({
        "project_id": project_id, "timeline_id": timeline_id,
        "parent": boundary["parent"]["payload"], "manifest": manifest,
    }).removeprefix("sha256:")


def _fork_owner_before(boundary, record, occurrence_ref, owner_row, identity_scope=None):
    """Derive the local placement ID from the selected physical source owner."""
    owner_reads = [read for read in record.get("reads", [])
                   if read.get("ref") == occurrence_ref and not read.get("path")]
    source_reads = [read for read in record.get("reads", [])
                    if read.get("ref") == occurrence_ref + "/shot"
                    and read.get("path") == ["shot_id"]]
    if identity_scope is None:
        require(not owner_reads and not source_reads,
                "provider created shot owner lacks an authenticated identity scope")
        return owner_row.get("shot_id")
    require(isinstance(identity_scope, tuple) and len(identity_scope) == 2
            and all(isinstance(value, str) and value for value in identity_scope),
            "provider created shot owner lacks an authenticated identity scope")
    rows = boundary["parent"]["payload"].get("occurrences", [])
    require([row for row in rows if "occurrence:" + row["occurrence_id"] == occurrence_ref] == [owner_row],
            "provider created shot owner is not its selected occurrence")
    source_shot_id = owner_row.get("shot_id")
    source_revision_id = owner_row.get("shot_revision_id")
    source = boundary.get("shot-revision:" + str(source_revision_id), {})
    require(source.get("shot_id") == source_shot_id
            and source.get("revision_id") == source_revision_id
            and isinstance(source.get("payload"), dict)
            and source.get("content_digest") == digest(source["payload"]),
            "provider created shot source differs from its authenticated occurrence")
    project_id, timeline_id = identity_scope
    shared = sum(row.get("shot_id") == source_shot_id for row in rows) > 1
    expected = (source_shot_id if not shared else _authoring_identity(
        "shot-placement", project_id, timeline_id,
        occurrence_ref.partition(":")[2], source_shot_id))
    require(len(owner_reads) == 1 and len(source_reads) == 1,
            "provider created shot owner lacks its authenticated source projection")
    owner_state = owner_reads[0].get("state", {})
    source_state = source_reads[0].get("state", {})
    require(owner_state.get("state") == "present" and isinstance(owner_state.get("value"), dict)
            and source_state == {"state": "present", "value": owner_row.get("shot_id")},
            "provider created shot owner has an unauthenticated source projection")
    projected = owner_state["value"]
    expected_row = {key: value for key, value in owner_row.items()
                    if key not in {"shot_revision_id", "revision_id"}}
    expected_row["shot_id"] = expected
    require(projected == expected_row,
            "provider created shot owner projection differs from its occurrence")
    return expected


def _project_created_child(boundary, record, following, accepted, identity_scope=None, *, same_command=False):
    """Stage an authenticated child allocation for a later or same command.

    Native occurrence creation records authored aggregate roots, while the
    Runtime closure stores their physical shot/internal images. A later
    command in the same step, or a child read in the creating command, must
    see the birth without inheriting its final payload. Build the intermediate
    view and scoped allocation identities from creation writes; check the
    accepted owner edges without borrowing their later payloads.
    """
    created = {item.get("ref"): item for item in record.get("created", [])}
    projected_roots = set()
    future_refs = [read.get("ref") for read in following.get("reads", [])]
    future_refs.extend(binding.get("ref") for binding in following.get("bindings", []))
    future_refs.extend(write.get("ref") for write in following.get("writes", []))

    for created_ref, allocation in created.items():
        if not (isinstance(created_ref, str) and "/" not in created_ref):
            continue
        fork = created_ref.startswith("shot:")
        if not (fork or created_ref.startswith("occurrence:")):
            continue
        shot_id = created_ref.partition(":")[2] if fork else None
        fork_occurrence_writes: list[dict] = []
        owner_row: dict = {}
        if fork:
            if not any(isinstance(ref, str) and ref.startswith("occurrence:") for ref in future_refs):
                continue
            fork_occurrence_writes = [write for write in record.get("writes", [])
                                      if (isinstance(write.get("ref"), str)
                                          and write["ref"].startswith("occurrence:")
                                          and write.get("path") == ["shot_id"]
                                          and write.get("after", {}).get("state") == "present"
                                          and write.get("after", {}).get("value") == shot_id)]
            if not fork_occurrence_writes and any(isinstance(ref, str) and ref.startswith("occurrence:")
                                                  for ref in created):
                continue
            require(len(fork_occurrence_writes) == 1,
                    "provider created shot lacks its authenticated occurrence owner")
            occurrence_ref = fork_occurrence_writes[0]["ref"]
        else:
            occurrence_ref = created_ref
        if not any(ref == occurrence_ref or isinstance(ref, str) and ref.startswith(occurrence_ref + "/")
                   for ref in future_refs):
            continue
        occurrence_write = next((write for write in record.get("writes", [])
                                 if write.get("ref") == occurrence_ref and not write.get("path")), None)
        if fork:
            owner_rows = [row for row in boundary["parent"]["payload"].get("occurrences", [])
                          if row.get("occurrence_id") == occurrence_ref.partition(":")[2]]
            require(len(owner_rows) == 1,
                    "provider created shot owner is not an authenticated occurrence")
            owner_row = owner_rows[0]
            owner_write = fork_occurrence_writes[0]
            owner_before = _fork_owner_before(boundary, record, occurrence_ref, owner_row, identity_scope)
            require(owner_write.get("before") == {"state": "present", "value": owner_before}
                    and owner_write.get("after") == {"state": "present", "value": shot_id},
                    "provider created shot owner differs from its authenticated occurrence")
            occurrence_value = {"shot_id": shot_id}
        else:
            occurrence_value = ((occurrence_write or {}).get("after", {}).get("value"))
            shot_id = occurrence_value.get("shot_id") if isinstance(occurrence_value, dict) else None
            if (allocation.get("kind") != "occurrence" or allocation.get("owner") != "parent"
                    or not isinstance(shot_id, str)):
                require(False, "provider created occurrence root is not an authenticated parent birth")
                continue
            require(occurrence_write is not None
                    and occurrence_write.get("before") == {"state": "absent"}
                    and occurrence_write.get("after", {}).get("state") == "present",
                    "provider created occurrence lacks its absent-to-present root write")
        if not isinstance(shot_id, str):
            require(False, "provider created child has no authenticated shot identity")
            continue
        if fork:
            require(allocation.get("kind") == "shot" and allocation.get("owner") is None,
                    "provider created shot root is not an authenticated fork birth")

        accepted_shot_refs = [ref for ref, image in accepted.items()
                              if ref.startswith("shot-revision:") and image.get("shot_id") == shot_id]
        require(len(accepted_shot_refs) == 1,
                "provider created occurrence has an ambiguous accepted physical shot")
        if len(accepted_shot_refs) != 1:
            require(False, "provider created occurrence has no accepted physical shot")
            continue
        accepted_shot_ref = accepted_shot_refs[0]
        accepted_shot = accepted[accepted_shot_ref]
        accepted_internal_id = accepted_shot.get("internal_timeline_revision_id")
        if not isinstance(accepted_internal_id, str):
            require(False, "provider created occurrence has no accepted physical internal timeline")
            continue
        accepted_internal_ref = "internal-revision:" + str(accepted_internal_id)
        if accepted_internal_ref not in accepted:
            require(False, "provider created occurrence has no accepted physical internal timeline")
            continue
        accepted_internal = accepted[accepted_internal_ref]

        shot_write = next((write for write in record.get("writes", [])
                           if write.get("ref") == "shot:" + shot_id and not write.get("path")), None)
        if not isinstance(shot_write, dict):
            require(False, "provider created occurrence lacks its authored shot birth")
            continue
        require(shot_write.get("before") == {"state": "absent"}
                and shot_write.get("after", {}).get("state") == "present",
                "provider created occurrence lacks its authored shot birth")
        shot_value = shot_write["after"]["value"]
        require(isinstance(shot_value, dict)
                and isinstance(shot_value.get("payload"), dict)
                and isinstance(shot_value.get("internal_timeline"), dict),
                "provider created shot birth is malformed")
        if (not isinstance(shot_value, dict)
                or not isinstance(shot_value.get("payload"), dict)
                or not isinstance(shot_value.get("internal_timeline"), dict)):
            continue
        initial_shot = copy.deepcopy(shot_value["payload"])
        authored_shot = copy.deepcopy(initial_shot)
        initial_internal = copy.deepcopy(shot_value["internal_timeline"])
        if identity_scope is None:
            shot_ref = accepted_shot_ref
            internal_ref = accepted_internal_ref
            internal_id = accepted_internal_id
            shot_revision_id = shot_ref.partition(":")[2]
        else:
            project_id, timeline_id = identity_scope
            require(accepted_internal.get("timeline_id") == timeline_id,
                    "provider created occurrence internal timeline has a foreign owner")
            internal_id = _authoring_identity("authoring-timeline-revision", project_id, timeline_id,
                                              shot_id, initial_internal)
            initial_shot["internal_timeline_revision_id"] = internal_id
            shot_revision_id = _authoring_identity("authoring-shot-revision", project_id, shot_id,
                                                   initial_shot)
            shot_ref = "shot-revision:" + shot_revision_id
            internal_ref = "internal-revision:" + internal_id
        internal_image = copy.deepcopy(accepted_internal)

        # Every physical alias claimed by the next command must still belong
        # to this exact created occurrence. A source pin cannot retarget the
        # child to a foreign or future physical image.
        for binding in following.get("bindings", []):
            ref = binding.get("ref")
            if not (isinstance(ref, str) and (ref == occurrence_ref or ref.startswith(occurrence_ref + "/"))):
                continue
            physical = binding.get("physical_ref")
            if physical is None:
                continue
            require(physical in {"parent", shot_ref, internal_ref},
                    "provider created occurrence source pin is foreign")
            if ref == occurrence_ref + "/source":
                require(physical == internal_ref,
                        "provider created occurrence source pin differs from its child")

        accepted_occurrences = accepted["parent"]["payload"].get("occurrences", [])
        accepted_occurrence = [row for row in accepted_occurrences
                               if row.get("occurrence_id") == occurrence_ref.partition(":")[2]]
        require(len(accepted_occurrence) == 1
                and accepted_occurrence[0].get("shot_id") == shot_id
                and accepted_occurrence[0].get("shot_revision_id") == accepted_shot_ref.partition(":")[2],
                "provider created occurrence has an ambiguous accepted owner")
        # Keep authored creation fields from the earlier native write; only the
        # managed shot revision edge comes from the accepted physical closure.
        intermediate_occurrence = copy.deepcopy(occurrence_value)
        intermediate_occurrence["shot_revision_id"] = shot_revision_id
        if identity_scope is not None:
            accepted_payload = accepted_shot.get("payload")
            require(isinstance(accepted_payload, dict)
                    and {key: value for key, value in accepted_payload.items()
                         if key != "internal_timeline_revision_id"}
                    == {key: value for key, value in authored_shot.items()
                        if key != "internal_timeline_revision_id"},
                    "provider created occurrence accepted shot is not its authored allocation")
            projected_parent = copy.deepcopy(boundary["parent"]["payload"])
            if fork:
                projected_occurrences = projected_parent.get("occurrences", [])
                projected_matches = [row for row in projected_occurrences
                                     if row.get("occurrence_id") == occurrence_ref.partition(":")[2]]
                require(len(projected_matches) == 1,
                        "provider created shot owner is not an authenticated occurrence")
                projected_matches[0].update(intermediate_occurrence)
            else:
                projected_parent.setdefault("occurrences", []).append(intermediate_occurrence)
            parent_pins = [binding for binding in following.get("bindings", [])
                           if binding.get("physical_ref") == "parent"
                           and binding.get("boundary", {}).get("phase") == "input"]
            if same_command:
                require(not parent_pins or all(
                    binding.get("revision_id") == boundary["parent"]["revision_id"]
                    and binding.get("content_digest") == boundary["parent"]["content_digest"]
                    for binding in parent_pins),
                    "provider created occurrence child has a different input parent mapping")
            else:
                require(any(binding.get("content_digest") == digest(projected_parent)
                            for binding in parent_pins),
                        "provider created occurrence lacks an authenticated authoring allocation mapping")
        if fork:
            expected_occurrence = copy.deepcopy(owner_row)
            expected_occurrence["shot_id"] = shot_id
            expected_occurrence["shot_revision_id"] = accepted_shot_ref.partition(":")[2]
            require(all(accepted_occurrence[0].get(key) == value
                        for key, value in expected_occurrence.items()),
                    "provider created shot differs from its accepted owner")
        else:
            require(all(accepted_occurrence[0].get(key) == value
                        for key, value in occurrence_value.items()),
                    "provider created occurrence differs from its accepted owner")

        result_parent = boundary["parent"]
        payload = copy.deepcopy(result_parent["payload"])
        occurrences = payload.setdefault("occurrences", [])
        if fork:
            matches = [row for row in occurrences
                       if row.get("occurrence_id") == occurrence_ref.partition(":")[2]]
            require(len(matches) == 1,
                    "provider created shot owner is not an authenticated occurrence")
            matches[0].update(intermediate_occurrence)
        else:
            require(not any(row.get("occurrence_id") == intermediate_occurrence["occurrence_id"]
                            for row in occurrences),
                    "provider created occurrence is already present at its input boundary")
            occurrences.append(intermediate_occurrence)
        result_parent["payload"] = payload
        result_parent["content_digest"] = digest(payload)

        require(shot_ref not in boundary and internal_ref not in boundary,
                "provider created occurrence physical roots overlap its input boundary")
        result_shot = copy.deepcopy(accepted_shot)
        result_shot["revision_id"] = shot_revision_id
        result_shot["internal_timeline_revision_id"] = internal_id
        result_shot["payload"] = initial_shot
        result_shot["content_digest"] = digest(initial_shot)
        result_internal = copy.deepcopy(internal_image)
        result_internal["revision_id"] = internal_id
        result_internal["payload"] = initial_internal
        result_internal["content_digest"] = digest(initial_internal)
        for binding in following.get("bindings", []):
            if binding.get("ref") == occurrence_ref + "/source":
                require(binding.get("content_digest") == result_internal["content_digest"],
                        "provider created occurrence source digest differs from its birth")
        boundary[shot_ref] = result_shot
        boundary[internal_ref] = result_internal
        projected_roots.add("shot:" + shot_id)
        projected_roots.add(occurrence_ref)
        if fork:
            projected_roots.add(occurrence_ref + "/shot_id")
            source_reads = [read for read in record.get("reads", [])
                            if read.get("ref") == occurrence_ref + "/shot"
                            and read.get("path") == ["shot_id"]]
            source_shot_ref = "shot-revision:" + str(owner_row.get("shot_revision_id"))
            source_shot = boundary.get(source_shot_ref)
            if source_reads and source_shot is not None:
                source_internal_id = source_shot.get("internal_timeline_revision_id")
                require(isinstance(source_internal_id, str),
                        "provider fork source closure lacks its authenticated internal timeline")
                sibling = any(row.get("occurrence_id") != occurrence_ref.partition(":")[2]
                              and row.get("shot_revision_id") == owner_row.get("shot_revision_id")
                              for row in payload.get("occurrences", []))
                retained = source_shot_ref in accepted
                require(not (sibling and not retained),
                        "provider fork source closure differs from its authenticated siblings")
                if not sibling and not retained:
                    boundary.pop(source_shot_ref, None)
                    source_internal_ref = "internal-revision:" + str(source_internal_id)
                    if not any(image.get("internal_timeline_revision_id") == source_internal_id
                               for ref, image in boundary.items()
                               if ref.startswith("shot-revision:")):
                        boundary.pop(source_internal_ref, None)
    return projected_roots


def _following_read_observes(boundary, following, physical_ref):
    for read in following.get("reads", []):
        ref, path = native_site(boundary, read["ref"], read["path"])
        if ref != physical_ref:
            continue
        if not path and "/collection:" in read["ref"]:
            return True
        if not path:
            continue
        observed = location(boundary[ref]["payload"], stored_path(boundary[ref]["payload"], ref, path))
        if value_equal(observed, read.get("state")):
            return True
    return False


_UNKNOWN = "UNKNOWN"
_SAFE_OBSERVATION_DETAIL_KEYS = (
    "verification_phase", "step_ordinal", "command_ordinal",
    "captured_ref_present", "captured_path_present", "native_site_present",
    "physical_digest_present", "physical_digest_hash",
    "creation_exemption", "creation_exemption_outcome",
    "ownership_state", "binding_state", "continuation_state",
)


def _bounded_ordinal(value):
    return value if type(value) is int and 0 <= value <= 1_000_000 else _UNKNOWN


def _safe_digest_hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return _UNKNOWN
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


def _safe_observation_diagnostic(capture, result, ref, path, following, *,
                                 step_ordinal=None, command_ordinal=None,
                                 creation_exemption_applied=False):
    """Return the closed, non-authoritative detail for the 2209 refusal.

    This deliberately receives only the local observation state around the
    existing guard. It never serializes an identifier, path token, payload or
    image. The result is evidence for diagnosis, not an input to authorization.
    """
    bindings = [binding for binding in following.get("bindings", [])
                if isinstance(binding, dict) and binding.get("physical_ref") == ref]
    owned = any(
        isinstance(binding.get("owner"), str) or
        isinstance(binding.get("owners"), list) and bool(binding["owners"])
        for binding in bindings
    )
    continued = any(isinstance(binding.get("successor"), str) for binding in bindings)
    image = result.get(ref)
    physical_digest = image.get("content_digest") if isinstance(image, dict) else None
    detail = {
        "verification_phase": "command_output",
        "step_ordinal": _bounded_ordinal(step_ordinal),
        "command_ordinal": _bounded_ordinal(command_ordinal),
        "captured_ref_present": isinstance(capture, dict) and isinstance(capture.get("ref"), str),
        "captured_path_present": isinstance(capture, dict) and isinstance(capture.get("path"), list),
        "native_site_present": isinstance(ref, str) and isinstance(path, list),
        "physical_digest_present": isinstance(physical_digest, str),
        "physical_digest_hash": _safe_digest_hash(physical_digest),
        "creation_exemption": "created_root_or_projected_site",
        "creation_exemption_outcome": "APPLIED" if creation_exemption_applied else "NOT_APPLIED",
        "ownership_state": "PRESENT" if owned else ("ABSENT" if bindings else _UNKNOWN),
        "binding_state": "PRESENT" if bindings else "ABSENT",
        "continuation_state": "PRESENT" if continued else ("ABSENT" if bindings else _UNKNOWN),
    }
    assert tuple(detail) == _SAFE_OBSERVATION_DETAIL_KEYS
    return detail


def _command_manifest(manifest, record):
    """Project only the dependencies consumed by one authenticated command."""
    result = copy.deepcopy(manifest)
    for dependency in record.get("dependencies", []):
        pin = dependency.get("pin", {})
        if dependency.get("kind") == "media":
            media_id = pin.get("object_id", pin.get("media_id"))
            if media_id is not None:
                media = {row["media_id"]: row for row in result["media"]}
                media[media_id] = {"media_id": media_id, "content_digest": media_id}
                result["media"] = sorted(media.values(), key=lambda row: row["media_id"])
        elif dependency.get("kind") in {"source", "transcript"} and pin not in result["documents"]:
            result["documents"].append(copy.deepcopy(pin))
            result["documents"].sort(
                key=lambda row: (row["document_id"], row["version"], row["content_digest"]))
    return result


def _observation_site(boundary, ref, path):
    """Resolve a recorder capture to its physical field without folding mirrors.

    SDK parent writes can observe both the legacy top-level collection and its
    config mirror in one command. Native clip aliases use the top-level
    collection when it exists; the explicit config path remains independent.
    """
    path = list(path)
    if ref == "parent":
        return ref, path
    if ref.startswith("parent/clip:"):
        payload = boundary["parent"]["payload"]
        root = (["clips"] if isinstance(payload.get("clips"), list)
                else ["config", "clips"])
        identity = ref.removeprefix("parent/clip:")
        return "parent", [*root, "id:" + identity, *path]
    return native_site(boundary, ref, path)


def command_output(boundary, record, following, *, accepted=None, identity_scope=None,
                   manifest=None, previous_manifest=None, step_ordinal=None,
                   command_ordinal=None):
    """Project full recorder observations needed by a subsequent input binding."""
    result = copy.deepcopy(boundary)
    if previous_manifest is not None:
        require(manifest is not None and value_equal(
            manifest, _command_manifest(previous_manifest, record)),
                "provider command manifest differs from its authenticated dependencies")
    projected_roots = (_project_created_child(result, record, following, accepted, identity_scope)
                       if accepted is not None else set())
    created_roots = {item.get("ref") for item in record.get("created", [])
                     if re.fullmatch(r"(?:shot|occurrence):[^/]+", item.get("ref", ""))}
    captures = [*record["writes"], *record["derived_writes"]]
    separate_clip_mirrors = (
        any(capture.get("ref") == "parent" and capture.get("path") == ["clips"]
            for capture in captures)
        and any(capture.get("ref") == "parent" and capture.get("path") == ["config", "clips"]
                for capture in captures)
    )
    derived_mirrors = {}
    clip_mirror_observations = {}
    for index, (capture, is_derived) in enumerate([
            *((capture, False) for capture in record["writes"]),
            *((capture, True) for capture in record["derived_writes"])]):
        capture_site = capture.get("ref", "") + "/" + "/".join(capture.get("path", []))
        if ((capture.get("ref") in created_roots & projected_roots and not capture.get("path"))
                or capture_site in projected_roots):
            # The authored aggregate root was installed above through its
            # physical closure images; it has no direct Runtime image site.
            continue
        clip_capture = (capture.get("ref") == "parent"
                        and capture.get("path") in (["clips"], ["config", "clips"]))
        native_clip_capture = capture.get("ref", "").startswith("parent/clip:")
        ref, path = (_observation_site(result, capture["ref"], capture["path"])
                     if native_clip_capture or (separate_clip_mirrors and clip_capture)
                     else native_site(result, capture["ref"], capture["path"]))
        capture_site = capture.get("ref", "") + "/" + "/".join(capture.get("path", []))
        creation_exemption_applied = (
            capture.get("ref") in created_roots & projected_roots and not capture.get("path")
        ) or capture_site in projected_roots
        require(
            ref in result,
            "provider intermediate command lacks an authenticated physical observation",
            safe_details=_safe_observation_diagnostic(
                capture, result, ref, path, following,
                step_ordinal=step_ordinal, command_ordinal=command_ordinal,
                creation_exemption_applied=creation_exemption_applied,
            ),
        )
        payload = result[ref]["payload"]
        path = stored_path(payload, ref, path)
        observation_site = (ref, tuple(path))
        chains_derived_mirror = (
            not separate_clip_mirrors and is_derived and "cause" in capture
            and ref == "parent" and capture["cause"] == record.get("ordinal")
            and tuple(path) in {("config", "clips"), ("clips",)}
        )
        chains_clip_mirror = (
            separate_clip_mirrors and is_derived and "cause" in capture
            and capture["cause"] == record.get("ordinal") and clip_capture
            and observation_site in clip_mirror_observations
        )
        if chains_clip_mirror:
            expected_before = clip_mirror_observations[observation_site]
        elif chains_derived_mirror and observation_site in derived_mirrors:
            expected_before = derived_mirrors[observation_site]
        else:
            input_payload = boundary.get(ref, result[ref])["payload"] if "cause" in capture else payload
            expected_before = location(input_payload, path, absent_items=True)
        if (ref == "parent" and path == ["occurrences"]
                and record.get("command", {}).get("op") == "doc.patch"):
            require(not is_derived, "provider occurrence order is not an authored patch observation")
            change = _occurrence_order_change(record, index)
            state = _occurrence_order_observation(result, capture, change, identity_scope)
        else:
            require(value_equal(expected_before, capture["before"]),
                    "provider intermediate command has a different input observation")
            state = capture["after"]
        result[ref]["payload"] = project_observation(payload, path, state)
        if separate_clip_mirrors and clip_capture:
            clip_mirror_observations[observation_site] = copy.deepcopy(capture["after"])
        if chains_derived_mirror:
            derived_mirrors[observation_site] = copy.deepcopy(capture["after"])
        if ref == "parent":
            for mirror in ("clips", "registry"):
                projected = result[ref]["payload"]
                if (mirror in projected and mirror in projected.get("config", {})
                        and not ((separate_clip_mirrors or native_clip_capture)
                                 and mirror == "clips")):
                    projected[mirror] = copy.deepcopy(projected["config"][mirror])
        result[ref]["content_digest"] = digest(result[ref]["payload"])
    for ref, image in list(result.items()):
        if ref not in boundary:
            continue
        if image["content_digest"] == boundary[ref]["content_digest"]:
            continue
        pins = [binding for binding in following["bindings"] if binding.get("physical_ref") == ref
                and binding.get("boundary", {}).get("phase") == "input"
                and binding.get("content_digest") == image["content_digest"]]
        if pins:
            require(len({pin["revision_id"] for pin in pins}) == 1,
                    "provider intermediate image differs from recorded command observations")
            require(ref == "parent",
                    "provider intermediate changed payload retains its immutable physical identity")
            image["revision_id"] = pins[0]["revision_id"]
        else:
            aliases = [binding for binding in following["bindings"]
                       if isinstance(binding.get("physical_ref"), str)
                       and binding["physical_ref"].startswith(("shot-revision:", "internal-revision:"))
                       and binding.get("physical_ref") != ref
                       and binding.get("boundary", {}).get("phase") == "input"
                       and binding.get("content_digest") == image["content_digest"]]
            if aliases:
                require(len({binding["physical_ref"] for binding in aliases}) == 1,
                        "provider intermediate image has ambiguous authenticated promotion")
                alias = aliases[0]
                target = alias["physical_ref"]
                require(target.split(":", 1)[0] == ref.split(":", 1)[0]
                        and alias["revision_id"] == target.partition(":")[2],
                        "provider intermediate promotion changes its physical kind or identity")
                require(target not in result,
                        "provider intermediate image promotion overlaps an authenticated root")
                if identity_scope is None:
                    require(False, "provider intermediate promotion lacks an authenticated allocation")
                    continue
                project_id, timeline_id = identity_scope
                target_id = target.partition(":")[2]
                source_id = ref.partition(":")[2]
                if ref.startswith("internal-revision:"):
                    owners = [(owner_ref, owner) for owner_ref, owner in result.items()
                              if owner_ref.startswith("shot-revision:")
                              and owner.get("internal_timeline_revision_id") == source_id]
                    require(len(owners) == 1,
                            "provider intermediate image has an ambiguous physical owner")
                    old_shot_ref, owner = owners[0]
                    shot_id = owner["shot_id"]
                    require(target_id == _authoring_identity(
                        "authoring-timeline-revision", project_id, timeline_id, owner["shot_id"], image["payload"]),
                        "provider intermediate promotion differs from its sequential allocation")
                    payload = owner["payload"]
                    require(payload.get("internal_timeline_revision_id") == source_id,
                            "provider intermediate image owner has a different physical edge")
                    owner["internal_timeline_revision_id"] = target_id
                    payload["internal_timeline_revision_id"] = target_id
                    owner["content_digest"] = digest(payload)
                    successor_shot_id = _authoring_identity(
                        "authoring-shot-revision", project_id, owner["shot_id"], payload)
                    successor_shot_ref = "shot-revision:" + successor_shot_id
                    require(successor_shot_ref not in result,
                            "provider intermediate shot promotion overlaps an authenticated root")
                    owner["revision_id"] = successor_shot_id
                    result[successor_shot_ref] = result.pop(old_shot_ref)
                else:
                    shot_id = image["shot_id"]
                    require(target_id == _authoring_identity(
                        "authoring-shot-revision", project_id, image["shot_id"], image["payload"]),
                        "provider intermediate shot promotion differs from its sequential allocation")
                    old_shot_ref, successor_shot_id = ref, target_id
                parent = result["parent"]["payload"]
                owners = [row for row in parent.get("occurrences", [])
                          if row.get("shot_revision_id") == old_shot_ref.partition(":")[2]]
                require(owners and all(row.get("shot_id") == shot_id for row in owners),
                        "provider intermediate promotion lacks its authenticated parent owner")
                for row in owners:
                    row["shot_revision_id"] = successor_shot_id
                result["parent"]["content_digest"] = digest(parent)
                image["revision_id"] = target_id
                result[target] = result.pop(ref)
                expected_parent = _authoring_parent_identity(result, identity_scope, manifest)
                parent_pins = [binding for binding in following["bindings"]
                               if binding.get("physical_ref") == "parent"
                               and binding.get("boundary", {}).get("phase") == "input"]
                require(parent_pins and all(pin.get("revision_id") == expected_parent
                                           and pin.get("content_digest") == result["parent"]["content_digest"]
                                           for pin in parent_pins),
                        "provider intermediate parent promotion differs from its sequential allocation")
                result["parent"]["revision_id"] = expected_parent
            else:
                require(not ref.startswith(("shot-revision:", "internal-revision:")),
                        "provider intermediate image lacks an authenticated physical promotion")
                require(_following_read_observes(result, following, ref),
                        "provider intermediate image lacks a next-command authenticated read")
    if projected_roots and identity_scope is not None:
        expected_parent = _authoring_parent_identity(result, identity_scope, manifest)
        parent_pins = [binding for binding in following["bindings"]
                       if binding.get("physical_ref") == "parent"
                       and binding.get("boundary", {}).get("phase") == "input"]
        require(parent_pins and all(pin.get("revision_id") == expected_parent
                                   and pin.get("content_digest") == result["parent"]["content_digest"]
                                   for pin in parent_pins),
                "provider created parent differs from its sequential allocation")
        result["parent"]["revision_id"] = expected_parent
    if (previous_manifest is not None and manifest != previous_manifest
            and identity_scope is not None
            and result["parent"]["content_digest"] == boundary["parent"]["content_digest"]):
        expected_parent = _authoring_parent_identity(result, identity_scope, manifest)
        parent_pins = [binding for binding in following["bindings"]
                       if binding.get("physical_ref") == "parent"
                       and binding.get("boundary", {}).get("phase") == "input"]
        require(parent_pins and all(pin.get("revision_id") == expected_parent
                                    and pin.get("content_digest") == result["parent"]["content_digest"]
                                    for pin in parent_pins),
                "provider consumed manifest differs from its sequential parent allocation")
        result["parent"]["revision_id"] = expected_parent
    return result


def _capture_document_images(document):
    validate_commit_value(document, "CanonicalDocument")
    require(isinstance(document, dict)
            and isinstance(document.get("parent_revision"), dict)
            and isinstance(document.get("shot_revisions"), list)
            and isinstance(document.get("internal_timeline_revisions"), list),
            "sequential command boundary document is malformed")
    rows = [document["parent_revision"], *document["shot_revisions"],
            *document["internal_timeline_revisions"]]
    require(all(isinstance(row, dict) and isinstance(row.get("revision_id"), str)
                and isinstance(row.get("payload"), dict)
                and isinstance(row.get("content_digest"), str) for row in rows),
            "sequential command boundary image is malformed")
    try:
        result = images(document)
    except (KeyError, TypeError, ValueError, IndexError) as exc:
        require(False, "sequential command boundary document is malformed")
        raise AssertionError("unreachable") from exc
    require(len(result) == len(rows), "sequential command boundary has duplicate physical images")
    for image in result.values():
        require(isinstance(image, dict) and isinstance(image.get("payload"), dict),
                "sequential command boundary image is malformed")
        require(image.get("content_digest") == digest(image["payload"]),
                "sequential command boundary image digest differs from its payload")
    return result


def _capture_projection_equal(left, right):
    """Compare the immutable image projection used by Runtime authentication.

    ``timeline_id`` is a closure transport annotation on internal images; the
    authenticated payload, revision and content digest are the authoritative
    projection used by the existing step projector.
    """
    def projection(boundary):
        return {ref: {key: value for key, value in image.items() if key != "timeline_id"}
                if ref.startswith("internal-revision:") else image
                for ref, image in boundary.items()}

    return value_equal(projection(left), projection(right))


def _capture_binding_identity(binding):
    boundary = binding.get("boundary", {})
    identity = {key: copy.deepcopy(value) for key, value in binding.items()
                if key not in {"physical_ref", "revision_id", "content_digest", "successor",
                               "edge_before", "edge_after", "boundary", "ref"}}
    for key in ("change", "dependency"):
        if isinstance(identity.get(key), dict):
            identity[key].pop("ref", None)
    physical_ref = binding.get("physical_ref")
    if isinstance(physical_ref, str):
        identity["physical_kind"] = physical_ref.partition(":")[0]
    return canonical_json(identity | {
                                              "boundary": {key: boundary.get(key) for key in (
                                                  "base_revision_id", "base_publication_id", "step_id",
                                                  "command_ordinal", "change_ordinal", "phase", "side")
                                                  if key in boundary},
                                          })


def _capture_source_chain(source):
    """Parse a replay lineage without granting it authority.

    Authority is established by ``validate_sequential_capture`` against the
    actual materialization binding for every node.  This helper only enforces
    the closed JSON shape and returns the complete chain for that check.
    """
    nodes = []
    seen = set()
    while isinstance(source, dict):
        require(set(source) == {"step_id", "source", "owner", "owners"},
                "sequential replay source is malformed")
        require(isinstance(source["step_id"], str) and bool(source["step_id"])
                and isinstance(source["owner"], str) and bool(source["owner"])
                and isinstance(source["owners"], list)
                and all(isinstance(owner, str) and bool(owner) for owner in source["owners"])
                and source["owner"] in source["owners"]
                and len(set(source["owners"])) == len(source["owners"]),
                "sequential replay source owner attribution is malformed")
        token = canonical_json(source)
        require(token not in seen, "sequential replay source is cyclic")
        seen.add(token)
        nodes.append(source)
        source = source["source"]
    require(isinstance(source, str) and bool(source)
            and source.startswith(("shot-revision:", "internal-revision:")),
            "sequential replay source terminal is malformed")
    require(source not in seen, "sequential replay source is cyclic")
    return {"nodes": nodes, "terminal": source}


def sequential_proof_required(prepared, source, continuations=None):
    """Identify the moved-head staged-alias case that cannot use the old ABI."""
    boundary = images(source)
    continuations = continuations or {}
    for record in prepared.get("records", {}).get("commands", []):
        if record.get("ordinal") != 0:
            continue
        for binding in record.get("bindings", []):
            if (binding.get("boundary", {}).get("phase") != "input"
                    or not isinstance(binding.get("physical_ref"), str)
                    or not binding["physical_ref"].startswith(("shot-revision:", "internal-revision:"))):
                continue
            ref = binding.get("ref")
            physical = binding["physical_ref"]
            if physical in boundary or not isinstance(ref, str):
                continue
            seen = set()
            while ref not in boundary and ref in continuations and ref not in seen:
                seen.add(ref)
                successors = continuations[ref]
                if len(successors) != 1:
                    break
                ref = next(iter(successors))
            if ref not in boundary and binding.get("ref", "").startswith(("shot-revision:", "internal-revision:")):
                return True
    return False


def _capture_head(head):
    require(isinstance(head, dict) and set(head) == {"revision_id", "publication_id"}
            and isinstance(head["revision_id"], str) and isinstance(head["publication_id"], str),
            "sequential execution head is malformed")


def _capture_records(records, expected, request):
    """Bind provider records to the prepared candidate without flattening bindings."""
    validate_commit_value(records, "Recorder")
    require(isinstance(records, dict) and isinstance(expected, dict)
            and set(records) == set(expected), "sequential execution records are malformed")
    require(isinstance(records.get("commands"), list) and isinstance(records.get("steps"), list),
            "sequential execution records are incomplete")
    require(len(records["commands"]) == len(request["commands"])
            and len(records["commands"]) == len(expected.get("commands", [])),
            "sequential execution command records are incomplete")
    for ordinal, (record, prepared_record, command) in enumerate(
            zip(records["commands"], expected["commands"], request["commands"])):
        require(isinstance(record, dict) and isinstance(prepared_record, dict)
                and set(record) == set(prepared_record)
                and type(record.get("ordinal")) is int and record["ordinal"] == ordinal
                and value_equal(record.get("command"), prepared_record.get("command"))
                and isinstance(record.get("bindings"), list),
                "sequential command record is malformed")
        for binding in record["bindings"]:
            boundary = binding.get("boundary", {})
            require(isinstance(boundary, dict), "sequential binding boundary is malformed")
            for attribution in (binding, boundary):
                if "command_ordinal" in attribution:
                    require(type(attribution["command_ordinal"]) is int
                            and attribution["command_ordinal"] == ordinal,
                            "sequential binding command ordinal is invalid")
                if "change_ordinal" in attribution:
                    changes = command.get("args", {}).get("changes", [])
                    require(type(attribution["change_ordinal"]) is int
                            and 0 <= attribution["change_ordinal"] < len(changes),
                            "sequential binding change ordinal is invalid")
                if "effect_ordinal" in attribution:
                    step = next((step for step in records["steps"] if ordinal in step["command_ordinals"]), None)
                    require(step is not None and type(attribution["effect_ordinal"]) is int
                            and 0 <= attribution["effect_ordinal"] < len(step["patch"]),
                            "sequential binding effect ordinal is invalid")
            if "write_range" in binding:
                start, end = binding["write_range"]
                require(type(start) is int and type(end) is int
                        and 0 <= start <= end <= len(record["writes"]),
                        "sequential binding write range is invalid")
        for write in record["derived_writes"]:
            require(type(write["cause"]) is int and 0 <= write["cause"] < len(records["commands"]),
                    "sequential derived write cause is invalid")
        for key in set(record) - {"bindings"}:
            require(value_equal(record[key], prepared_record[key]),
                    "sequential command metadata differs from the prepared candidate")
    expected_steps = cast(list, expected.get("steps"))
    require(isinstance(expected_steps, list) and len(records["steps"]) == len(expected_steps),
            "sequential execution step records are incomplete")
    seen_ordinals = []
    for step, prepared_step in zip(records["steps"], expected_steps):
        require(isinstance(step, dict) and isinstance(prepared_step, dict)
                and isinstance(step.get("command_ordinals"), list)
                and all(type(ordinal) is int for ordinal in step["command_ordinals"]),
                "sequential execution step record is malformed")
        for key in ("id", "label", "intent", "tags", "command_ordinals", "reads"):
            if key in prepared_step or key in step:
                require(key in prepared_step and key in step and value_equal(step[key], prepared_step[key]),
                        "sequential execution step metadata differs from the prepared candidate")
        seen_ordinals.extend(step["command_ordinals"])
    require(seen_ordinals == list(range(len(records["commands"]))),
            "sequential execution step records do not partition commands")
    for key in set(records) - {"commands", "steps"}:
        require(value_equal(records[key], expected[key]),
                "sequential execution metadata differs from the prepared candidate")


def _capture_binding_image(document, binding):
    physical = binding.get("physical_ref")
    require(isinstance(physical, str), "sequential physical binding is malformed")
    boundary = _capture_document_images(document)
    image = boundary.get(physical)
    require(image is not None and binding.get("revision_id") == image.get("revision_id")
            and binding.get("content_digest") == image.get("content_digest"),
            "sequential physical binding differs from its captured image")
    return boundary, image


def _capture_owners(document, physical):
    boundary = _capture_document_images(document)
    owners = []
    parent = boundary["parent"]["payload"]
    for row in parent.get("occurrences", []):
        shot_ref = "shot-revision:" + row["shot_revision_id"]
        shot = boundary.get(shot_ref)
        if physical == shot_ref or (shot is not None
                                    and physical == "internal-revision:" + shot["internal_timeline_revision_id"]):
            owners.append("occurrence:" + row["occurrence_id"] + "/shot")
    require(owners, "sequential physical binding has no authenticated owner")
    return owners


def _capture_step(records, step_id):
    matches = [step for step in records["steps"] if step.get("id") == step_id]
    require(len(matches) == 1, "sequential replay source names an unknown step")
    return matches[0]


def validate_sequential_capture(request, prepared, capture, source, base, continuations=None, history=None):
    """Authenticate the private original/landing execution carrier.

    The returned binding pairs are trusted only for this invocation of
    ``validate``.  They never become accepted-history continuations.
    """
    require(isinstance(capture, dict) and set(capture) == {
        "schema_version", "context", "original", "landing", "replay_bindings", "prepared_digest"
    } and type(capture["schema_version"]) is int and capture["schema_version"] == 1,
            "sequential execution capture is malformed")
    require(capture["prepared_digest"] == digest(prepared),
            "sequential execution capture does not bind the prepared commit")
    expected_base = {"revision_id": request["base_revision_id"],
                     "publication_id": request["base_publication_id"]}
    expected_landing = prepared["expected_head"]
    _capture_head(expected_base)
    _capture_head(expected_landing)
    executions = {}
    for side, expected_head, initial in (("original", expected_base, base),
                                         ("landing", expected_landing, source)):
        execution = capture[side]
        require(isinstance(execution, dict) and set(execution) == {"evaluated_head", "commands", "records"},
                "sequential execution has an invalid envelope")
        require(value_equal(execution["evaluated_head"], expected_head)
                and isinstance(execution["commands"], list)
                and isinstance(execution["records"], dict),
                "sequential execution head or records differ from the authenticated invocation")
        records = execution["records"]
        _capture_records(records, prepared["records"], request)
        commands = execution["commands"]
        require(len(commands) == len(records["commands"]),
                "sequential execution command boundaries are incomplete")
        previous = None
        last_output = None
        by_ordinal = {}
        for ordinal, item in enumerate(commands):
            require(isinstance(item, dict) and set(item) == {"boundary", "input", "output"},
                    "sequential command boundary is malformed")
            boundary = item["boundary"]
            require(isinstance(boundary, dict) and set(boundary) == {
                "base_revision_id", "base_publication_id", "evaluated_head", "step_id",
                "command_ordinal", "phase"
            } and boundary["base_revision_id"] == request["base_revision_id"]
                    and boundary["base_publication_id"] == request["base_publication_id"]
                    and value_equal(boundary["evaluated_head"], expected_head)
                    and type(boundary["command_ordinal"]) is int
                    and boundary["command_ordinal"] == ordinal and boundary["phase"] == "input",
                    "sequential command boundary attribution is invalid")
            step = next((step for step in records["steps"] if ordinal in step["command_ordinals"]), None)
            require(step is not None and boundary["step_id"] == step["id"],
                    "sequential command boundary step is invalid")
            current = _capture_document_images(item["input"])
            output = _capture_document_images(item["output"])
            if ordinal == 0:
                require(_capture_projection_equal(current, images(initial)),
                        "sequential original or landing input does not match its authenticated head")
            else:
                require(_capture_projection_equal(current, previous),
                        "sequential command input does not match the preceding command output")
            previous = output
            last_output = item["output"]
            by_ordinal[ordinal] = item
        require(previous is not None, "sequential execution has no command output")
        if side == "landing":
            require(last_output is not None and value_equal(last_output, prepared["canonical_document"]),
                    "landing execution output differs from the prepared document")
        executions[side] = {"by_ordinal": by_ordinal, "records": records}

    original_records = executions["original"]["records"]
    landing_records = executions["landing"]["records"]
    validate_claims(request, original_records)
    validate_claims(request, landing_records)
    original_document = capture["original"]["commands"][-1]["output"]
    original_prepared = {**prepared, "expected_head": expected_base,
                         "canonical_document": original_document,
                         "document_digest": digest(original_document),
                         "records": original_records}
    validate(request, original_prepared, base, base, {}, history,
             sequential={"landing": executions["original"]["by_ordinal"]})

    binding_pairs = {}
    source_to_landing = {}
    landing_to_source = {}
    for ordinal, (original_record, landing_record) in enumerate(zip(
            original_records["commands"], landing_records["commands"])):
        originals = {}
        for binding in original_record.get("bindings", []):
            if "physical_ref" in binding:
                key = _capture_binding_identity(binding)
                require(key not in originals, "sequential source binding is ambiguous")
                originals[key] = binding
        landings = {}
        for binding in landing_record.get("bindings", []):
            if "physical_ref" in binding:
                key = _capture_binding_identity(binding)
                require(key not in landings, "sequential landing binding is ambiguous")
                landings[key] = binding
        require(set(originals) == set(landings),
                "sequential source and landing physical bindings are incomplete")
        used = set()
        for index, binding in enumerate(landing_record.get("bindings", [])):
            if "physical_ref" not in binding:
                continue
            key = _capture_binding_identity(binding)
            original_binding = originals.get(key)
            require(original_binding is not None and key not in used,
                    "sequential landing binding has no unique original correspondence")
            if original_binding is None:
                raise AssertionError("unreachable")
            used.add(key)
            source_physical = original_binding["physical_ref"]
            landing_physical = binding["physical_ref"]
            source_key = canonical_json({"physical_ref": source_physical, "owner": binding.get("owner"),
                                         "owners": binding.get("owners"), "step_id": binding.get("step_id"),
                                         "command_ordinal": ordinal, "change_ordinal": binding.get("change_ordinal"),
                                         "effect_ordinal": binding.get("effect_ordinal"),
                                         "edge_before": original_binding.get("edge_before"),
                                         "edge_after": original_binding.get("edge_after"),
                                         "revision_id": original_binding.get("revision_id"),
                                         "content_digest": original_binding.get("content_digest")})
            landing_key = canonical_json({"physical_ref": landing_physical, "owner": binding.get("owner"),
                                          "owners": binding.get("owners"), "step_id": binding.get("step_id"),
                                          "command_ordinal": ordinal, "change_ordinal": binding.get("change_ordinal"),
                                          "effect_ordinal": binding.get("effect_ordinal"),
                                          "edge_before": binding.get("edge_before"),
                                          "edge_after": binding.get("edge_after"),
                                          "revision_id": binding.get("revision_id"),
                                          "content_digest": binding.get("content_digest")})
            require(source_to_landing.get(source_key, landing_key) == landing_key
                    and landing_to_source.get(landing_key, source_key) == source_key,
                    "sequential source-to-landing correspondence is ambiguous")
            source_to_landing[source_key] = landing_key
            landing_to_source[landing_key] = source_key
            binding_pairs[(ordinal, index)] = {"original": original_binding, "landing": binding,
                                               "source_physical_ref": source_physical}
        require(used == set(originals),
                "sequential source physical bindings were not consumed exactly once")

    replay = capture["replay_bindings"]
    require(isinstance(replay, list), "sequential replay bindings are malformed")
    expected_map = set()
    replay_required = expected_landing != expected_base
    for ordinal, record in enumerate(original_records["commands"]):
        command = request["commands"][ordinal]
        if replay_required and command.get("op") == "doc.patch":
            changes = command.get("args", {}).get("changes")
            require(isinstance(changes, list), "sequential patch changes are malformed")
            expected_map.update((ordinal, "patch", index) for index in range(len(changes)))
        original_reads = [binding for binding in record["bindings"] if binding.get("key") == "commit.read"]
        landing_reads = [binding for binding in landing_records["commands"][ordinal]["bindings"]
                         if binding.get("key") == "commit.read"]
        for binding in original_reads:
            matches = [candidate for candidate in landing_reads
                       if _capture_binding_identity(candidate) == _capture_binding_identity(binding)]
            require(len(matches) == 1, "sequential read binding correspondence is incomplete")
            phase = binding.get("boundary", {}).get("phase")
            if replay_required and binding.get("physical_ref") != matches[0].get("physical_ref"):
                expected_map.add((ordinal, "read", binding.get("ref"),
                                  tuple(binding.get("path", [])), phase))
    seen_map = set()
    for entry in replay:
        require(isinstance(entry, dict), "sequential replay binding is malformed")
        kind = entry.get("kind")
        binding_candidates = []
        command_ordinal = None
        map_key = None
        if kind == "patch":
            require(set(entry) == {"command_ordinal", "kind", "change_ordinal", "source"}
                    and type(entry.get("command_ordinal")) is int
                    and type(entry.get("change_ordinal")) is int
                    and isinstance(entry.get("source"), (dict, str)),
                    "sequential patch replay binding is malformed")
            command_ordinal = entry["command_ordinal"]
            change_ordinal = entry["change_ordinal"]
            require(0 <= command_ordinal < len(request["commands"]),
                    "sequential patch replay binding ordinal is invalid")
            command = request["commands"][command_ordinal]
            changes = command.get("args", {}).get("changes") if command.get("op") == "doc.patch" else None
            require(isinstance(changes, list) and 0 <= change_ordinal < len(changes),
                    "sequential patch replay binding ordinal is invalid")
            map_key = (command_ordinal, "patch", change_ordinal)
            binding_candidates = [binding for binding in original_records["commands"][command_ordinal]["bindings"]
                                  if binding.get("key") == "doc.patch:" + str(change_ordinal)]
        elif kind == "read":
            require(set(entry) == {"command_ordinal", "kind", "ref", "path", "phase", "source"}
                    and type(entry.get("command_ordinal")) is int
                    and isinstance(entry.get("ref"), str)
                    and isinstance(entry.get("path"), list)
                    and all(isinstance(token, str) for token in entry["path"])
                    and entry.get("phase") in {"input", "batch-read"},
                    "sequential read replay binding is malformed")
            command_ordinal = entry["command_ordinal"]
            require(0 <= command_ordinal < len(original_records["commands"]),
                    "sequential read replay binding ordinal is invalid")
            record = original_records["commands"][command_ordinal]
            require(any(isinstance(read, dict) and read.get("ref") == entry["ref"]
                        and read.get("path") == entry["path"]
                        for read in record["bindings"] if read.get("key") == "commit.read"),
                    "sequential read replay binding differs from the recorded read")
            require(entry["phase"] != "batch-read" or command_ordinal == 0,
                    "sequential batch read replay binding is out of order")
            map_key = (command_ordinal, "read", entry["ref"], tuple(entry["path"]), entry["phase"])
            binding_candidates = [binding for binding in record["bindings"]
                                  if binding.get("key") == "commit.read"
                                  and binding.get("ref") == entry["ref"]
                                  and binding.get("path") == entry["path"]
                                  and binding.get("boundary", {}).get("phase") == entry["phase"]]
        else:
            require(False, "sequential replay binding kind is invalid")
            raise AssertionError("unreachable replay binding kind")
        if command_ordinal is None or map_key is None:
            raise AssertionError("unreachable replay binding coordinates")
        require(map_key in expected_map and map_key not in seen_map,
                "sequential replay binding is duplicated or omitted from the authenticated map")
        seen_map.add(map_key)
        require(len(binding_candidates) == 1,
                "sequential replay binding has no unique original record")
        binding = binding_candidates[0]
        landing_candidates = [candidate for candidate in landing_records["commands"][command_ordinal]["bindings"]
                              if _capture_binding_identity(candidate) == _capture_binding_identity(binding)]
        require(len(landing_candidates) == 1,
                "sequential replay binding has no unique landing record")
        landing_binding = landing_candidates[0]
        chain = _capture_source_chain(entry["source"])
        original_input = executions["original"]["by_ordinal"][command_ordinal]["input"]
        landing_input = executions["landing"]["by_ordinal"][command_ordinal]["input"]
        original_images = _capture_document_images(original_input)
        landing_images = _capture_document_images(landing_input)
        terminal = chain["terminal"]
        require(binding.get("physical_ref") in original_images
                and landing_binding.get("physical_ref") in landing_images,
                "sequential replay binding is absent from its authenticated input")
        source_step_ordinals = []
        node_steps = []
        for node_index, node in enumerate(chain["nodes"]):
            step = _capture_step(landing_records, node["step_id"])
            ordinals = step.get("command_ordinals")
            require(isinstance(ordinals, list) and ordinals
                    and all(type(ordinal) is int for ordinal in ordinals)
                    and ordinals == sorted(ordinals)
                    and ordinals == list(range(ordinals[0], ordinals[-1] + 1)),
                    "sequential replay source step ordering is invalid")
            final_ordinal = ordinals[-1]
            require(final_ordinal < command_ordinal
                    and (not source_step_ordinals or final_ordinal < source_step_ordinals[-1]),
                    "sequential replay source step is future or out of order")
            source_step_ordinals.append(final_ordinal)
            step_input = executions["landing"]["by_ordinal"][ordinals[0]]["input"]
            step_output = executions["landing"]["by_ordinal"][final_ordinal]["output"]
            node_steps.append((node, step, step_input, step_output))
            if node_index + 1 < len(chain["nodes"]):
                require(canonical_json(node["source"]) == canonical_json(chain["nodes"][node_index + 1]),
                        "sequential replay source chain skips a recorded step")
        target_landing = landing_binding.get("physical_ref")
        target_original = binding.get("physical_ref")
        for node_index in range(len(node_steps)):
            node, step, step_input, step_output = node_steps[node_index]
            final_ordinal = step["command_ordinals"][-1]
            candidates = [candidate for candidate in original_records["commands"][final_ordinal]["bindings"]
                          if candidate.get("key") == "commit.materialization"
                          and candidate.get("successor") == target_original
                          and candidate.get("owner") == node["owner"]
                          and set(candidate.get("owners", [])) == set(node["owners"])]
            landing_candidates = [candidate for candidate in landing_records["commands"][final_ordinal]["bindings"]
                                  if candidate.get("key") == "commit.materialization"
                                  and candidate.get("successor") == target_landing
                                  and candidate.get("owner") == node["owner"]
                                  and set(candidate.get("owners", [])) == set(node["owners"])]
            require(len(candidates) == 1 and len(landing_candidates) == 1,
                    "sequential replay source lacks a unique authenticated transition")
            original_transition, landing_transition = candidates[0], landing_candidates[0]
            physical = landing_transition.get("physical_ref")
            original_physical = original_transition.get("physical_ref")
            require(isinstance(physical, str) and isinstance(original_physical, str)
                    and physical in _capture_document_images(step_input),
                    "sequential replay source is absent from its source step input")
            owners = _capture_owners(step_input, physical)
            require(node["owner"] in owners and set(node["owners"]) == set(owners),
                    "sequential replay source owner attribution is incomplete")
            original_owners = _capture_owners(
                executions["original"]["by_ordinal"][final_ordinal]["input"], original_physical)
            require(node["owner"] in original_owners and set(node["owners"]) == set(original_owners),
                    "sequential replay source original owner attribution is incomplete")
            _capture_binding_image(executions["landing"]["by_ordinal"][final_ordinal]["input"], landing_transition)
            _capture_binding_image(executions["original"]["by_ordinal"][final_ordinal]["input"], original_transition)
            require(target_landing in _capture_document_images(step_output),
                    "sequential replay source successor is absent from its materialized output")
            require(target_original in _capture_document_images(
                executions["original"]["by_ordinal"][final_ordinal]["output"]),
                    "sequential replay source successor is absent from its original output")
            target_landing = physical
            target_original = original_physical
        require(target_landing == terminal
                and terminal in _capture_document_images(node_steps[-1][2])
                if node_steps else terminal == landing_binding.get("physical_ref"),
                "sequential replay source has an unbound terminal transition")
        if node_steps:
            require(target_original in _capture_document_images(
                executions["original"]["by_ordinal"][node_steps[-1][1]["command_ordinals"][0]]["input"]),
                    "sequential replay source has no authenticated original base image")
        continued, _ = site(images(source), target_original, [], continuations)
        require(continued == target_landing,
                "sequential replay source terminal differs from authenticated history")
    require(seen_map == expected_map,
            "sequential replay map does not cover every authenticated replay input")
    return {"binding_pairs": binding_pairs,
            "original": executions["original"]["by_ordinal"],
            "landing": executions["landing"]["by_ordinal"]}


def validate(request, prepared, source, base=None, continuations=None, history=None, sequential=None):
    """Check request/record correspondence at authenticated immutable boundaries."""
    records = prepared["records"]
    continuations = copy.deepcopy(continuations or {})
    boundary = images(source)
    original = images(base or source)
    if base is not None:
        for read in request.get("reads", []):
            validate_read(images(base), read)
    batch_reads = []
    for read in request.get("reads", []):
        if sequential is not None and "binding_pairs" in sequential:
            _, read = _sequential_assertion(read, [0], sequential, "dependency", "batch-read")
        batch_reads.append(validate_read(boundary, read, continuations))
    validate_claims(request, records)
    accepted = images(prepared["canonical_document"])
    touched = set()
    manifest = copy.deepcopy(source["dependency_manifest"])
    for step_ordinal, step in enumerate(records["steps"]):
        command_inputs = {step["command_ordinals"][0]: boundary}
        input_manifest = copy.deepcopy(manifest)
        command_manifests = {}
        command_input_manifests = {}
        for ordinal in step["command_ordinals"]:
            # Consumed input pins are checked by the request-private port at
            # acceptance. Only earlier commands contribute to this boundary;
            # a following binding cannot allocate a physical identity.
            command_input_manifests[ordinal] = copy.deepcopy(manifest)
            manifest = _command_manifest(manifest, records["commands"][ordinal])
            command_manifests[ordinal] = copy.deepcopy(manifest)
        # Hydrated documents consumed by the first command can rekey the
        # unchanged effect-before parent. Later commands cannot allocate it.
        input_manifest["documents"] = command_manifests[step["command_ordinals"][0]]["documents"]
        input_parent_revision = None
        if input_manifest["documents"] != source["dependency_manifest"]["documents"]:
            input_parent_revision = _authoring_parent_identity(
                boundary, (source["project_id"], source["timeline_id"]), input_manifest)
        for ordinal, next_ordinal in zip(step["command_ordinals"], step["command_ordinals"][1:]):
            command_inputs[next_ordinal] = command_output(
                command_inputs[ordinal], records["commands"][ordinal], records["commands"][next_ordinal],
                accepted=accepted, identity_scope=(source["project_id"], source["timeline_id"]),
                manifest=command_manifests[ordinal],
                previous_manifest=command_input_manifests[ordinal],
                step_ordinal=step_ordinal, command_ordinal=ordinal)
        created_inputs = {}
        for ordinal in step["command_ordinals"]:
            record = records["commands"][ordinal]
            child_refs = [capture.get("ref") for capture in [*record["reads"], *record["bindings"]]
                          if isinstance(capture.get("ref"), str)]
            if not any(_created_occurrence_child(record, ref) for ref in child_refs):
                continue
            staged = copy.deepcopy(command_inputs[ordinal])
            projected = _project_created_child(
                staged, record, record, accepted,
                identity_scope=(source["project_id"], source["timeline_id"]), same_command=True)
            require(all(ref.split("/", 1)[0] in projected
                        for ref in child_refs if _created_occurrence_child(record, ref)),
                    "provider created occurrence child lacks an authenticated staged root")
            created_inputs[ordinal] = staged
        if records["merge_mode"] == "atomic":
            # Resolve aliases only after earlier commands establish their input
            # images; the complete batch union is checked against every step below.
            for ordinal in step["command_ordinals"]:
                record = records["commands"][ordinal]
                command_boundary = command_inputs[ordinal]
                for capture in [*record["writes"], *record["reads"], *record["derived_writes"]]:
                    capture_boundary = (created_inputs[ordinal]
                                        if ordinal in created_inputs
                                        and _created_occurrence_child(record, capture["ref"])
                                        else command_boundary)
                    touched.add(native_site(capture_boundary, capture["ref"], capture["path"])[0])
                touched.update(binding["physical_ref"] for binding in record["bindings"] if "physical_ref" in binding)
        if sequential is not None:
            for ordinal in step["command_ordinals"]:
                captured = sequential["landing"].get(ordinal)
                require(captured is not None
                        and _capture_projection_equal(images(captured["input"]), command_inputs[ordinal]),
                        "provider sequential command input differs from its authenticated projection")
                if captured is None:
                    raise AssertionError("unreachable missing sequential command capture")
                next_ordinal = next((next_value for current, next_value in zip(
                    step["command_ordinals"], step["command_ordinals"][1:]) if current == ordinal), None)
                if next_ordinal is not None:
                    require(_capture_projection_equal(images(captured["output"]), command_inputs[next_ordinal]),
                            "provider sequential command output differs from its next input projection")
        authenticated_output = None
        if sequential is not None:
            last = sequential["landing"].get(step["command_ordinals"][-1])
            if last is not None:
                authenticated_output = images(last["output"])
        output = step_output(boundary, step, records, accepted, original, authenticated_output,
                             identity_scope=(source["project_id"], source["timeline_id"]))
        if sequential is not None:
            last = sequential["landing"].get(step["command_ordinals"][-1])
            require(last is not None and _capture_projection_equal(images(last["output"]), output),
                    "provider sequential command output differs from its authenticated projection")
        effect_boundaries = _inverse_stage_boundaries(boundary, output, step, records, accepted, original, history)
        validate_step(request, records, step, boundary, batch_reads, continuations, command_inputs, sequential,
                      effect_boundaries, created_inputs)
        for ordinal in step["command_ordinals"]:
            record = records["commands"][ordinal]
            command_input = command_inputs[ordinal]
            if record["command"]["op"] == "doc.patch":
                indices = [binding.get("boundary", {}).get("change_ordinal") for binding in record["bindings"]
                           if binding["key"].startswith("doc.patch:")]
                require(indices == list(range(len(record["command"]["args"]["changes"]))),
                        "provider patch bindings do not cover its ordered changes")
            validate_bindings(request, records, prepared["expected_head"], command_input, output, step, ordinal,
                              continuations, original, boundary, effect_boundaries, input_parent_revision,
                              sequential, created_inputs.get(ordinal))
        for ordinal in step["command_ordinals"]:
            for binding in records["commands"][ordinal]["bindings"]:
                if binding.get("key") == "commit.materialization":
                    continuations.setdefault(binding["physical_ref"], set()).add(binding["successor"])
        boundary = output
    for step in records["steps"]:
        for ref in touched:
            require(covers(step["dependencies"], {"kind": "scope", "ref": ref, "path": []}),
                    "provider atomic dependency union omits a touched scope")
    # Materialization can reuse a historical parent revision with these exact
    # bytes. Step bindings still name the projected execution image above;
    # immutable destination provenance is checked separately by the store.
    boundary["parent"]["revision_id"] = accepted["parent"]["revision_id"]
    require(value_equal(boundary, accepted), "provider step effects do not reach the accepted closure")
