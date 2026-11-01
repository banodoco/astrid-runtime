"""Verify main publication facts without replay, rendering, or history writes.

Callers authorize scope and hold the store lock and a consistent transaction.
Installation belongs to the acceptance store, in the transaction that rechecks
these facts. A content revision alone is never a publication identity.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sqlite3

from .errors import ConflictError, RuntimeErrorBase
from .idempotency import EXPIRED
from .timeline_commit_validation import digest
from .util import canonical_json


_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _refuse(reason):
    raise ConflictError("timeline publication history is unavailable", details={
        "status": "refused", "reason": "history_unavailable", "integrity_reason": reason,
    })


def _require(condition, reason):
    if not condition:
        _refuse(reason)


def _json(encoded):
    def invalid(value):
        raise ValueError("non-finite JSON")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    result = json.loads(encoded, parse_constant=invalid, object_pairs_hook=pairs)
    json.dumps(result, allow_nan=False)  # Also reject overflow such as 1e999.
    return result


def _row(connection, query, args):
    row = connection.execute(query, args).fetchone()
    _require(row is not None, "missing_scoped_row")
    return row


def _image(connection, table, revision_id, project_id, **identity):
    # Table names are internal constants, never supplied by the caller.
    row = _row(connection, f"SELECT * FROM {table} WHERE id=?", (revision_id,))
    _require(row["project_id"] == project_id, "revision_project_mismatch")
    _require(all(row[key] == value for key, value in identity.items()), "revision_identity_mismatch")
    payload = _json(row["payload_json"])
    _require(isinstance(payload, dict) and digest(payload) == row["content_digest"], "revision_digest_mismatch")
    return {"revision_id": row["id"], "content_digest": row["content_digest"], "payload": payload, **identity}


def _payload_media(value):
    # Match main's _collect_digest_media; source/content hashes are not CAS
    # identities, and opaque JSON does not declare consumed Document inputs.
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"media_id", "object_id"} and isinstance(child, str):
                bare = child.removeprefix("sha256:")
                if _HEX.fullmatch(bare):
                    found.add("sha256:" + bare)
            found.update(_payload_media(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_payload_media(child))
    return found


def _media(connection, project_id, media_id, read_object):
    _require(isinstance(media_id, str) and media_id.startswith("sha256:") and
             _HEX.fullmatch(media_id[7:]), "invalid_media_identity")
    bare = media_id[7:]
    row = _row(connection, "SELECT size, media_type FROM objects WHERE digest=?", (bare,))
    _row(connection, "SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'", (project_id, bare))
    data = read_object(bare)
    _require(isinstance(data, bytes) and len(data) == row["size"] and
             hashlib.sha256(data).hexdigest() == bare, "media_bytes_mismatch")
    return data, row


def _text_bindings(connection, project_id, shot, read_object):
    for descriptor in shot["payload"].get("text_bindings", []):
        binding = _row(connection, "SELECT * FROM shot_text_bindings WHERE id=? AND project_id=? AND shot_id=?",
                       (descriptor["binding_id"], project_id, shot["shot_id"]))
        head = descriptor["head"]
        _require(type(head) is int and 0 < head <= binding["head_seq"], "text_binding_head_mismatch")
        previous = ""
        pinned = None
        events = connection.execute(
            "SELECT * FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq", (binding["id"],)
        ).fetchall()
        _require(len(events) == binding["head_seq"], "text_binding_ancestry_missing")
        for seq, event in enumerate(events, 1):
            payload = _json(event["payload_json"])
            _require(payload.get("state", "present") in ("present", "absent"), "text_binding_state_mismatch")
            hashed = {"event_id": event["event_id"], "binding_id": binding["id"], "seq": seq,
                      "kind": event["kind"], "payload": payload, "previous_hash": previous}
            _require(event["project_id"] == project_id and event["seq"] == seq and
                     event["previous_hash"] == previous and event["event_hash"] == digest(hashed)[7:],
                     "text_binding_chain_mismatch")
            previous = event["event_hash"]
            if seq == head:
                pinned = payload
        _require(pinned is not None and pinned.get("state", "present") == "present" and pinned["binding_id"] == binding["id"] and
                 pinned["media_id"] == pinned["content_hash"] == descriptor["media_id"] == descriptor["content_hash"],
                 "text_binding_pin_mismatch")
        data, media = _media(connection, project_id, pinned["media_id"], read_object)
        _require(descriptor["byte_size"] == len(data) and descriptor["mime_type"] == media["media_type"],
                 "text_binding_metadata_mismatch")
        _require("text" not in descriptor or descriptor["text"] == data.decode("utf-8"), "text_binding_content_mismatch")
        for field in ("project_id", "shot_id", "kind", "slot", "event_stream_id"):
            _require(field not in descriptor or descriptor[field] == binding[field], "text_binding_identity_mismatch")


def _shot_projection(connection, project_id, shot_id):
    head = _row(connection, "SELECT revision_id FROM shot_revision_heads WHERE shot_id=? AND project_id=?", (shot_id, project_id))
    image = _image(connection, "shot_revisions", head["revision_id"], project_id, shot_id=shot_id)
    payload = image["payload"]
    row = _row(connection, "SELECT * FROM project_shots WHERE id=? AND project_id=?", (shot_id, project_id))
    _require(row["name"] == str(payload.get("name") or shot_id) and
             _json(row["metadata_json"]) == payload.get("metadata", {}) and
             bool(row["archived_at"]) == bool(payload.get("archived", False)), "unaccounted_shot_projection")
    actual = [{"item_id": item["id"], "media_id": item["media_id"].removeprefix("sha256:"),
               "source_frame": item["source_frame"], "metadata": _json(item["metadata_json"])}
              for item in connection.execute("SELECT * FROM shot_items WHERE shot_id=? ORDER BY sort_key, id", (shot_id,))]
    expected = [{"item_id": str(item.get("item_id", item.get("id"))),
                 "media_id": item["media_id"].removeprefix("sha256:"),
                 "source_frame": item.get("source_frame"), "metadata": item.get("metadata", {})}
                for item in payload.get("items", [])]
    _require(actual == expected, "unaccounted_shot_projection")


def _closure(connection, project_id, timeline_id, revision_id, manifest, read_object):
    parent = _image(connection, "parent_composition_revisions", revision_id, project_id, timeline_id=timeline_id)
    parent.pop("timeline_id")
    payload = parent["payload"]
    _require(isinstance(payload["config"], dict) and isinstance(payload["registry"], dict) and
             isinstance(payload["clips"], list) and isinstance(payload["occurrences"], list), "parent_shape_mismatch")
    shots, internals = {}, {}
    occurrence_ids = set()
    rows = connection.execute(
        "SELECT * FROM composition_revision_occurrences WHERE parent_revision_id=? ORDER BY ordinal", (revision_id,)
    ).fetchall()
    _require(len(rows) == len(payload["occurrences"]), "occurrence_rows_mismatch")
    for ordinal, (occurrence, row) in enumerate(zip(payload["occurrences"], rows)):
        _require(occurrence["occurrence_id"] not in occurrence_ids, "duplicate_occurrence")
        occurrence_ids.add(occurrence["occurrence_id"])
        expected = {"parent_revision_id": revision_id, "project_id": project_id, "ordinal": ordinal,
                    **{key: occurrence[key] for key in ("occurrence_id", "shot_id", "shot_revision_id", "duration_ms", "track", "gain")},
                    "muted": int(occurrence["muted"]),
                    **{key + "_json": canonical_json(occurrence[key]) for key in
                       ("placement", "source_offset", "speed", "transform", "provenance")}}
        _require(dict(row) == expected, "occurrence_rows_mismatch")
        shot_id, shot_revision = occurrence["shot_id"], occurrence["shot_revision_id"]
        _row(connection, "SELECT 1 FROM project_shots WHERE id=? AND project_id=?", (shot_id, project_id))
        shot = _image(connection, "shot_revisions", shot_revision, project_id, shot_id=shot_id)
        link = _row(connection, "SELECT internal_timeline_revision_id FROM shot_revisions WHERE id=?", (shot_revision,))[0]
        _require(shot["payload"]["internal_timeline_revision_id"] == link, "internal_link_mismatch")
        shot["internal_timeline_revision_id"] = link
        internal_row = _row(connection, "SELECT timeline_id FROM internal_timeline_revisions WHERE id=?", (link,))
        internal_id = internal_row["timeline_id"]
        scope = connection.execute("SELECT 1 FROM timelines WHERE id=? AND project_id=?", (internal_id, project_id)).fetchone()
        if scope is None and internal_id.startswith("shot:"):
            scope = connection.execute("SELECT 1 FROM project_shots WHERE id=? AND project_id=?", (internal_id[5:], project_id)).fetchone()
        _require(scope is not None, "internal_scope_missing")
        internal = _image(connection, "internal_timeline_revisions", link, project_id, timeline_id=internal_id)
        _text_bindings(connection, project_id, shot, read_object)
        shots[(shot_id, shot_revision)] = shot
        internals[(internal_id, link)] = internal
    shot_images = [shots[key] for key in sorted(shots)]
    internal_images = [internals[key] for key in sorted(internals)]
    # Main's publication manifest has no retained Document snapshots. Only an
    # explicit dependency declares a consumed pin; arbitrary payload keys do not.
    if isinstance(manifest, dict) and manifest.get("documents"):
        _refuse("unretained_document_dependency")
    _require(isinstance(manifest, dict) and set(manifest) == {"shots", "internal_timelines", "media"}, "manifest_missing_or_unsupported")
    expected_manifest = {
        "shots": [{key: image[key] for key in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")} for image in shot_images],
        "internal_timelines": [{key: image[key] for key in ("timeline_id", "revision_id", "content_digest")} for image in internal_images],
        "media": manifest["media"],
    }
    _require(manifest == expected_manifest and isinstance(manifest["media"], list), "manifest_closure_mismatch")
    media_ids = []
    for pin in manifest["media"]:
        _require(set(pin) == {"media_id", "content_digest"} and pin["media_id"] == pin["content_digest"], "manifest_media_mismatch")
        _media(connection, project_id, pin["media_id"], read_object)
        media_ids.append(pin["media_id"])
    _require(media_ids == sorted(set(media_ids)), "manifest_media_order_mismatch")
    required_media = _payload_media(payload)
    for image in shot_images + internal_images:
        required_media.update(_payload_media(image["payload"]))
    _require(required_media.issubset(media_ids), "manifest_media_missing")
    expected_dependencies = []
    for kind, family in (("shot_revision", manifest["shots"]), ("internal_timeline_revision", manifest["internal_timelines"]), ("media", manifest["media"])):
        offset = len(expected_dependencies)
        expected_dependencies.extend((kind, pin.get("revision_id", pin.get("media_id")), pin["content_digest"], offset + index)
                                     for index, pin in enumerate(family))
    actual = connection.execute(
        "SELECT dependency_kind, dependency_id, content_digest, ordinal FROM composition_revision_dependencies WHERE parent_revision_id=? ORDER BY ordinal",
        (revision_id,),
    ).fetchall()
    _require([tuple(row) for row in actual] == expected_dependencies, "dependency_rows_mismatch")
    return {"schema_version": 1, "project_id": project_id, "timeline_id": timeline_id,
            "parent_revision": parent, "shot_revisions": shot_images, "internal_timeline_revisions": internal_images,
            "dependency_manifest": {**copy.deepcopy(manifest), "documents": []}}


def _publication(connection, project_id, timeline_id, event, stream_seq, commands, read_object):
    matches = [command for command in commands if _json(command["event_ids_json"]) == [str(event["id"])]]
    _require(len(matches) == 1, "publication_receipt_pair_missing_or_ambiguous")
    command = matches[0]
    payload = _json(event["payload_json"])
    result = _json(command["result_json"])
    revision_id = payload["new_head"]
    _require(command["txn_id"] and command["primary_stream_id"] == timeline_id and
             command["resulting_stream_seq"] == stream_seq, "receipt_stream_mismatch")
    first, last = command["first_project_seq"], command["last_project_seq"]
    seq = _row(connection, "SELECT next_seq FROM project_sequences WHERE project_id=?", (project_id,))[0]
    _require(type(first) is int and first == last and 0 < first < seq, "receipt_project_sequence_mismatch")
    _require(connection.execute("SELECT COUNT(*) FROM command_idempotency WHERE txn_id=?", (command["txn_id"],)).fetchone()[0] == 1,
             "receipt_identity_ambiguous")
    for name, expected in (("project_id", project_id), ("timeline_id", timeline_id), ("content_digest", payload["content_digest"])):
        _require(payload[name] == result[name] == expected, "publication_result_identity_mismatch")
    _require(result["parent_revision_id"] == revision_id and result["event_id"] == str(event["id"]), "publication_result_event_mismatch")
    _require(isinstance(command["idempotency_key"], str) and command["idempotency_key"] and
             isinstance(command["request_hash"], str) and _HEX.fullmatch(command["request_hash"]), "receipt_request_identity_missing")
    document = _closure(connection, project_id, timeline_id, revision_id, payload["dependency_manifest"], read_object)
    _require(document["parent_revision"]["content_digest"] == payload["content_digest"], "publication_digest_mismatch")
    if EXPIRED in result:
        _require(isinstance(result[EXPIRED], str) and _HEX.fullmatch(result[EXPIRED]) and
                 result["dependency_manifest_sha256"] == digest(payload["dependency_manifest"])[7:], "compacted_publication_proof_missing")
    else:
        _require(result["payload"] == document["parent_revision"]["payload"] and
                 result["dependency_manifest"] == payload["dependency_manifest"] and
                 result["old_head"] == payload["old_head"] and result["new_head"] == revision_id and
                 result["revision_id"] == revision_id, "publication_result_mismatch")
        digests = {"parent": payload["content_digest"]}
        for pin in payload["dependency_manifest"]["shots"] + payload["dependency_manifest"]["internal_timelines"] + payload["dependency_manifest"]["media"]:
            digests[pin.get("revision_id", pin.get("media_id"))] = pin["content_digest"]
        _require(result["content_digests"] == digests, "publication_result_digests_mismatch")
    receipt = {"receipt_id": command["txn_id"], "command_kind": command["command_kind"],
               "idempotency_key": command["idempotency_key"], "request_hash": command["request_hash"],
               "project_id": project_id, "project_seq": [first, last], "event_ids": [str(event["id"])],
               "result": result, "created_at": command["created_at"]}
    entry = {"publication_id": command["txn_id"], "revision_id": revision_id, "previous": None,
             "receipt": receipt, "intent": "legacy_unknown", "records": None,
             "provider_version": None, "compiler_version": None, "publisher": None}
    return entry, document


def _publication_events(connection, project_id, timeline_id):
    events = connection.execute("SELECT * FROM timeline_events WHERE timeline_id=? ORDER BY id", (timeline_id,)).fetchall()
    previous = ""
    publications = []
    for stream_seq, event in enumerate(events, 1):
        payload = _json(event["payload_json"])
        _require(isinstance(payload, dict), "timeline_event_payload_mismatch")
        hashed = {"timeline_id": timeline_id, "kind": event["kind"], "payload": payload,
                  "previous_hash": previous, "created_at": event["created_at"]}
        _require(event["previous_hash"] == previous and event["event_hash"] == digest(hashed)[7:], "timeline_event_chain_mismatch")
        previous = event["event_hash"]
        _require(payload.get("project_id") == project_id, "event_project_mismatch")
        if event["kind"] == "parent.composition.published":
            publications.append((stream_seq, event))
    return events, publications, previous


def _verify(connection, project_id, timeline_id, read_object):
    _row(connection, "SELECT 1 FROM timelines WHERE id=? AND project_id=?", (timeline_id, project_id))
    head = _row(connection, "SELECT * FROM parent_composition_heads WHERE timeline_id=? AND project_id=?", (timeline_id, project_id))
    events, publications, previous = _publication_events(connection, project_id, timeline_id)
    _require(publications, "publication_missing")
    last_seq, latest = publications[-1]
    latest_payload = _json(latest["payload_json"])
    _require(latest_payload["new_head"] == head["revision_id"], "latest_publication_does_not_select_head")
    commands = connection.execute(
        "SELECT * FROM command_idempotency WHERE command_kind='parent_composition.publish' AND aggregate_id=?", (timeline_id,)
    ).fetchall()
    # Main assigns one project sequence to each mutation. Retained stream
    # receipts must agree with event positions as well as publication order.
    stream_receipts = connection.execute(
        "SELECT * FROM command_idempotency WHERE primary_stream_id=? ORDER BY resulting_stream_seq", (timeline_id,)
    ).fetchall()
    prior_project_seq = 0
    for command in stream_receipts:
        position = command["resulting_stream_seq"]
        _require(type(position) is int and 0 < position <= len(events) and
                 _json(command["event_ids_json"]) == [str(events[position - 1]["id"])], "receipt_stream_mismatch")
        first, last = command["first_project_seq"], command["last_project_seq"]
        _require(type(first) is int and first == last and first > prior_project_seq, "receipt_project_sequence_mismatch")
        prior_project_seq = last
    publication_ids = {str(event["id"]) for _, event in publications}
    for command in commands:
        ids = _json(command["event_ids_json"])
        _require(isinstance(ids, list) and len(ids) == 1 and ids[0] in publication_ids, "orphan_publication_receipt")
    entries = []
    current_document = None
    next_payload = None
    for stream_seq, event in reversed(publications):
        payload = _json(event["payload_json"])
        if next_payload is not None:
            _require(next_payload["old_head"] == payload["new_head"], "publication_ancestry_mismatch")
            if not any(_json(command["event_ids_json"]) == [str(event["id"])] for command in commands):
                break  # Earlier provenance is unavailable: explicit baseline boundary.
        entry, document = _publication(connection, project_id, timeline_id, event, stream_seq, commands, read_object)
        if current_document is None:
            current_document = document
        if entries:
            _require(entry["receipt"]["project_seq"][1] < entries[-1]["receipt"]["project_seq"][0], "publication_sequence_order_mismatch")
            entries[-1]["previous"] = {"revision_id": entry["revision_id"], "publication_id": entry["publication_id"]}
        entries.append(entry)
        next_payload = payload
    entries.reverse()
    latest_entry = entries[-1]
    # Legacy document/shot paths can write without a parent publication event.
    # Refuse later scoped ledger mutations even when their authored values match.
    shot_ids = {image["shot_id"] for image in current_document["shot_revisions"]}
    for shot_id in shot_ids:
        _shot_projection(connection, project_id, shot_id)
    internal_ids = {image["timeline_id"] for image in current_document["internal_timeline_revisions"]}
    scope = {timeline_id, "timeline:" + timeline_id, *shot_ids, *internal_ids}
    last_project_seq = latest_entry["receipt"]["project_seq"][1]
    from .timeline_catalog import verify_catalog_tail
    catalog_receipts = verify_catalog_tail(connection, project_id, timeline_id, events, last_seq, last_project_seq, legacy=True)
    for command in connection.execute("SELECT * FROM command_idempotency WHERE last_project_seq > ? OR last_project_seq IS NULL", (last_project_seq,)):
        kind = command["command_kind"]
        if command["txn_id"] in catalog_receipts or kind == "timeline.rename":
            continue
        if kind == "timeline.create" and _json(command["event_ids_json"]) == [str(latest["id"])]:
            continue  # Empty-shell adoption: the create receipt names the publication it installed.
        try:
            result = _json(command["result_json"])
        except (TypeError, ValueError):
            _require(command["aggregate_id"] not in scope, "later_corrupt_scoped_receipt")
            continue
        result_project = result.get("project_id") if isinstance(result, dict) else None
        relevant = command["aggregate_id"] in scope or (
            isinstance(result, dict) and (result.get("timeline_id") in internal_ids | {timeline_id} or result.get("shot_id") in shot_ids)
        )
        _require(not (relevant and (result_project is None or result_project == project_id)), "later_unaccounted_ledger_write")
    return {"head": {"revision_id": head["revision_id"], "publication_id": latest_entry["publication_id"]},
            "canonical_document": current_document, "document_digest": digest(current_document), "entries": entries,
            "witness": {"last_event_id": str(events[-1]["id"]), "event_hash": previous,
                        "stream_seq": len(events), "head_updated_at": head["updated_at"]}}


def verify_baseline(connection, project_id, timeline_id, *, read_object):
    """Return detached, scoped main ledger facts, or refuse without any writes.

    Receipt results retain their stored compacted witness when replay expired;
    this is verification, never reconstruction of a scene-dependent response.
    """
    try:
        return _verify(connection, project_id, timeline_id, read_object)
    except RuntimeErrorBase as exc:
        if isinstance(exc.details, dict) and exc.details.get("reason") == "history_unavailable":
            raise
        _refuse("publication_dependency_unavailable:" + exc.code)
    except (KeyError, TypeError, ValueError, IndexError, sqlite3.Error, OSError) as exc:
        _refuse("missing_or_corrupt_publication_facts:" + type(exc).__name__)


def verify_revision_source(connection, project_id, timeline_id, revision_id, *, read_object):
    """Read an exact main publication closure without installing history or heads."""
    try:
        _row(connection, "SELECT 1 FROM timelines WHERE id=? AND project_id=?", (timeline_id, project_id))
        _, publications, _ = _publication_events(connection, project_id, timeline_id)
        commands = connection.execute(
            "SELECT * FROM command_idempotency WHERE command_kind='parent_composition.publish' AND aggregate_id=?",
            (timeline_id,),
        ).fetchall()
        for stream_seq, event in reversed(publications):
            if _json(event["payload_json"])["new_head"] == revision_id:
                _, document = _publication(connection, project_id, timeline_id, event, stream_seq, commands, read_object)
                return document
        _refuse("source_publication_missing")
    except RuntimeErrorBase as exc:
        if isinstance(exc.details, dict) and exc.details.get("reason") == "history_unavailable":
            raise
        _refuse("publication_dependency_unavailable:" + exc.code)
    except (KeyError, TypeError, ValueError, IndexError, sqlite3.Error, OSError) as exc:
        _refuse("missing_or_corrupt_publication_facts:" + type(exc).__name__)


def baseline_install_plan(connection, facts, *, read_object, existing_head=None):
    """Recheck facts under caller's write transaction; caller inserts the plan.

    The caller must read existing_head from its own edge schema in this same
    transaction, then insert all entries and head before committing. No new
    publication receipt or event is needed for an imported baseline.
    """
    _require(connection.in_transaction, "installation_requires_transaction")
    document = facts["canonical_document"]
    fresh = verify_baseline(connection, document["project_id"], document["timeline_id"], read_object=read_object)
    _require(canonical_json(fresh) == canonical_json(facts), "baseline_compare_failed")
    _require(existing_head is None or existing_head == fresh["head"], "installed_head_mismatch")
    return {"head": fresh["head"], "entries": fresh["entries"], "install": existing_head is None}


def empty_bootstrap_document(project_id, timeline_id, revision_id):
    """Legacy track-less candidate retained for bootstrap adoption."""
    _require(all(isinstance(value, str) and value for value in (project_id, timeline_id, revision_id)), "bootstrap_identity_missing")
    payload = {"config": {"clips": [], "tracks": []}, "registry": {}, "clips": [], "occurrences": []}
    return {"schema_version": 1, "project_id": project_id, "timeline_id": timeline_id,
            "parent_revision": {"revision_id": revision_id, "payload": payload, "content_digest": digest(payload)},
            "shot_revisions": [], "internal_timeline_revisions": [],
            "dependency_manifest": {"shots": [], "internal_timelines": [], "media": [], "documents": []}}


def default_bootstrap_document(project_id, timeline_id, revision_id):
    """Initial editable document for every catalog timeline creator."""
    document = empty_bootstrap_document(project_id, timeline_id, revision_id)
    payload = document["parent_revision"]["payload"]
    payload["config"]["tracks"] = [
        {"id": "V1", "kind": "visual", "label": "V1", "scale": 1, "fit": "contain", "opacity": 1, "blendMode": "normal"},
        {"id": "A1", "kind": "audio", "label": "A1", "scale": 1, "fit": "contain", "opacity": 1, "blendMode": "normal"},
    ]
    document["parent_revision"]["content_digest"] = digest(payload)
    return document


def bootstrap_install_plan(connection, project_id, timeline_id, *, read_object):
    """Verify a real initial empty publication before caller installs its edge.

    Acceptance writes the candidate, main publication event and main receipt in
    this transaction first; a timeline.document.created receipt is insufficient.
    """
    _require(connection.in_transaction, "installation_requires_transaction")
    facts = verify_baseline(connection, project_id, timeline_id, read_object=read_object)
    revision_id = facts["head"]["revision_id"]
    # Existing empty publications remain adoptable; new ones have the exact
    # canonical starter tracks. Arbitrary authored content is still refused.
    expected = (default_bootstrap_document(project_id, timeline_id, revision_id),
                empty_bootstrap_document(project_id, timeline_id, revision_id))
    _require(facts["canonical_document"] in expected and len(facts["entries"]) == 1, "bootstrap_requires_empty_initial_publication")
    event = _row(connection, "SELECT payload_json FROM timeline_events WHERE id=?", (facts["entries"][0]["receipt"]["event_ids"][0],))
    _require(_json(event["payload_json"])["old_head"] is None, "bootstrap_has_previous_head")
    entry = facts["entries"][0]
    entry["intent"] = "bootstrap"
    return {"head": facts["head"], "entries": [entry], "install": True}
