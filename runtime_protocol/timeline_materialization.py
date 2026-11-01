"""Read-only join of derived allocations to their original immutable source."""
from __future__ import annotations

import hashlib
import re

from .errors import ValidationError
from .util import canonical_json

_SOURCE = "materialization.source:"
_OWNER = "materialization.owner:"


def has_materialization(prepared):
    return (not isinstance(prepared["id_map"], dict) or any(k != v for k, v in prepared["id_map"].items())
            or any(d["key"].startswith(_SOURCE) for r in prepared["records"]["commands"] for d in r["dependencies"])
            or any(b["key"].startswith(_OWNER) for r in prepared["records"]["commands"] for b in r["bindings"]))


def root_identity(ref):
    # Same closed grammar as Agent's reviewed root_identity/item_identity.
    match = re.fullmatch(r"(shot|occurrence):((?!.*::)[^/]+)", ref) if isinstance(ref, str) else None
    return match.groups() if match and match[2].strip() else None


def item_identity(ref):
    match = re.fullmatch(r"(shot:((?!.*::)[^/]+))/item:((?!.*::)[^/]+)", ref) if isinstance(ref, str) else None
    return (match[1], match[3]) if match and match[2].strip() and match[3].strip() else None


def edges(document):
    rows = document["parent_revision"]["payload"]["occurrences"]
    result = {o["occurrence_id"]: (o["shot_id"], o["shot_revision_id"]) for o in rows}
    if len(result) != len(rows):
        raise ValidationError("ambiguous materialization occurrence")
    return result


def materialization_join(prepared, project, timeline, closure):
    """Return D -> (O, original pin); closure resolves verified private/history inputs.

    This proves provenance and physical edges, never permission to replace rows.
    Legacy identity pairs do not need source inputs. Inverse allocations retain
    their original pin even when the output edge returns to S; callers separately
    authenticate the inverse targets and mutable destination ownership.
    """
    def require(condition):
        if not condition:
            raise ValidationError("incomplete source-bound materialization join")

    def same(left, right):
        return canonical_json(left) == canonical_json(right)

    def scoped(document):
        require((document["project_id"], document["timeline_id"]) == (project, timeline))
        parent = document["parent_revision"]
        require(parent["content_digest"] == "sha256:" + hashlib.sha256(canonical_json(parent["payload"]).encode()).hexdigest())
        return document

    def shot_at(document, edge):
        shots = [s for s in document["shot_revisions"] if (s["shot_id"], s["revision_id"]) == edge]
        require(len(shots) == 1)
        shot = shots[0]
        internals = [i for i in document["internal_timeline_revisions"]
                     if i["revision_id"] == shot["internal_timeline_revision_id"]]
        require(len(internals) == 1 and shot["payload"]["internal_timeline_revision_id"] == internals[0]["revision_id"])
        require(all(i["content_digest"] == "sha256:" + hashlib.sha256(canonical_json(i["payload"]).encode()).hexdigest()
                    for i in (shot, internals[0])))
        items = [i.get("item_id", i.get("id")) for i in shot["payload"].get("items", [])]
        require(all(item_identity("shot:" + shot["shot_id"] + "/item:" + i)
                    for i in items if isinstance(i, str)) and all(isinstance(i, str) for i in items))
        require(len(set(items)) == len(items))
        return shot, internals[0], set(items)

    allocations, expected, owners, raw_items, used_keys = {}, {}, {}, set(), []
    records = prepared["records"]["commands"]

    def item_members(destination, members):
        members = set(members)
        for record in records:
            for write in record["writes"]:
                item = item_identity(write["ref"])
                if item is None or item[0] != "shot:" + destination or write["path"]:
                    continue
                ref, raw = write["ref"], item[1]
                before, after = write["before"], write["after"]
                require((raw in members) == (before["state"] == "present"))
                require(all(state["state"] == "absent" or (isinstance(state.get("value"), dict)
                            and state["value"].get("item_id", state["value"].get("id")) == raw) for state in (before, after)))
                if before["state"] == "absent" and after["state"] == "present" and record["command"]["op"] != "timeline.inverse":
                    require(sum(c == {"ref": ref, "kind": "item", "owner": item[0]} for c in record["created"]) == 1
                            and ref in record["command"].get("created", [])
                            and any(r["ref"] == ref and not r["path"] and r["state"] == {"state": "absent"}
                                    for r in record["reads"]))
                members.discard(raw)
                if after["state"] == "present":
                    members.add(raw)
        return members

    for record in records:
        dependencies = [d for d in record["dependencies"] if d["key"].startswith(_SOURCE)]
        require(len({d["key"] for d in dependencies}) == len(dependencies))
        used = set()
        for dep in dependencies:
            ref = dep["key"][len(_SOURCE):]
            root = root_identity(ref)
            require(root is not None and root[0] == "shot")
            destination, pin = root[1], dep["pin"]
            require(dep["kind"] == "entity" and dep["policy"] == "exact" and isinstance(pin, dict)
                    and set(pin) == {"parent", "source"})
            source, parent = pin["source"], pin["parent"]
            require(isinstance(parent, dict) and set(parent) == {"revision_id", "content_digest"}
                    and all(type(v) is str for v in parent.values()))
            fields = ("shot_id", "revision_id", "content_digest", "internal_timeline_id",
                      "internal_timeline_revision_id", "internal_timeline_content_digest")
            require(isinstance(source, dict) and set(source) == {*fields, "item_id_map"}
                    and all(type(source[k]) is str for k in fields))
            source_ref, items = "shot:" + source["shot_id"], source["item_id_map"]
            require(root_identity(source_ref) is not None and source["shot_id"] != destination and isinstance(items, dict))
            require(all(type(i) is str and type(j) is str and item_identity(source_ref + "/item:" + i)
                        and item_identity(ref + "/item:" + j) for i, j in items.items()))
            require(len(set(items.values())) == len(items))
            owner_key = _OWNER + ref
            bindings = [b for b in record["bindings"] if b["key"] == owner_key]
            require(len(bindings) == 1)
            owner = root_identity(bindings[0]["ref"])
            require(owner is not None and owner[0] == "occurrence")
            pairs = {ref: source_ref, **{ref + "/item:" + j: source_ref + "/item:" + i for i, j in items.items()},
                     owner_key: bindings[0]["ref"]}
            facts = [{"key": k, "ref": v, "policy": "fixed", "dependencies": [dep["key"]]} for k, v in pairs.items()]
            actual = [b for b in record["bindings"] if b["key"] in pairs or dep["key"] in b["dependencies"]]
            require(len(actual) == len(facts) and all(sum(same(b, f) for b in actual) == 1 for f in facts))
            require(all(record["command"].get("bindings", {}).get(k) == v for k, v in pairs.items()))
            used.update(pairs)
            require(not any(c["ref"] in pairs for c in record["created"]))
            require(not any(c in pairs for c in record["command"].get("created", [])))
            allocation = (owner[1], pin)
            if destination in allocations:
                require(same(allocations[destination], allocation))
            else:
                require(owner[1] not in owners and not raw_items.intersection(items.values()))
                allocations[destination], owners[owner[1]] = allocation, destination
                raw_items.update(items.values())
            expected[ref] = destination
            expected.update({ref + "/item:" + j: j for j in items.values()})
            original = scoped(closure(parent["revision_id"]))
            require(same(parent, {k: original["parent_revision"][k] for k in parent}))
            edge = (source["shot_id"], source["revision_id"])
            require(edges(original).get(owner[1]) == edge)
            shot, internal, original_items = shot_at(original, edge)
            require(same({k: source[k] for k in fields}, {
                "shot_id": shot["shot_id"], "revision_id": shot["revision_id"], "content_digest": shot["content_digest"],
                "internal_timeline_id": internal["timeline_id"], "internal_timeline_revision_id": internal["revision_id"],
                "internal_timeline_content_digest": internal["content_digest"]}))
            require(original_items == set(items))
            before = scoped(closure(prepared["expected_head"]["revision_id"]))
            output = scoped(prepared["canonical_document"])
            active, after = edges(before).get(owner[1]), edges(output).get(owner[1])
            inverse = record["command"]["op"] == "timeline.inverse"
            require(active is not None and after is not None and (active == edge or active[0] == destination))
            require(after[0] == destination or (inverse and after == edge))
            _, _, before_members = shot_at(before, active)
            _, _, after_members = shot_at(output, after)
            require(active[0] == destination or before_members == original_items)
            require(after_members == (item_members(destination, before_members if active[0] == destination else items.values())
                                      if after[0] == destination else original_items))
            require(any(r["ref"] == "occurrence:" + owner[1] + "/shot" and r["path"] == ["shot_id"]
                        and same(r["state"], {"state": "present", "value": active[0]}) for r in record["reads"]))
        used_keys.append(used)
    for record, used in zip(records, used_keys):
        require(not any(c["ref"] in expected for c in record["created"]))
        if record["command"]["op"] != "timeline.inverse":
            require(not any(c["kind"] == "item" and item_identity(c["ref"])
                            and item_identity(c["ref"])[1] in raw_items for c in record["created"]))
        for key in [b["key"] for b in record["bindings"]] + list(record["command"].get("bindings", {})):
            member = item_identity(key)
            allocation_ref = member[0] if member else key
            if key.startswith((_SOURCE, _OWNER)) or allocation_ref in expected:
                require(key in used)
    mapping = prepared["id_map"]
    require(isinstance(mapping, dict) and all(type(k) is str and type(v) is str and k and v for k, v in mapping.items()))
    require(mapping == expected if allocations else all(k == v for k, v in mapping.items()))
    return allocations
