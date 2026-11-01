"""Existing timeline catalog projection and receipt-backed visibility proof."""
from __future__ import annotations

import hashlib
import json

from .errors import NotFoundError
from .idempotency import EXPIRED
from .util import canonical_json


def timeline_resource(connection, timeline_id):
    row = connection.execute("SELECT * FROM timelines WHERE id=?", (timeline_id,)).fetchone()
    if not row: raise NotFoundError("timeline not found")
    shots = [dict(x) for x in connection.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
    refs = [dict(x) for x in connection.execute("SELECT * FROM timeline_references WHERE timeline_id=?", (timeline_id,))]
    head = connection.execute("SELECT revision_id, publication_id FROM parent_composition_heads WHERE timeline_id=? AND project_id=?", (timeline_id, row["project_id"])).fetchone()
    result = {"timeline_id": row["id"], "project_id": row["project_id"], "version": row["version"], "name": row["name"], "head_revision_id": head["revision_id"] if head else None, "archived": bool(row["archived_at"]), "shots": [{"shot_id": x["id"], "start_ms": x["start_ms"], "duration_ms": x["duration_ms"], "reference_ids": json.loads(x["reference_ids_json"])} for x in shots], "references": [{"reference_id": x["id"], "object_id": x["object_id"], **({"role": x["role"]} if x["role"] else {})} for x in refs]}
    result["head_publication_id"] = head["publication_id"] if head else None
    document = connection.execute("SELECT content_json, version FROM project_documents WHERE id=? AND project_id=?", (f"timeline:{timeline_id}", row["project_id"])).fetchone()
    if document:
        content = json.loads(document["content_json"])
        if isinstance(content, dict):
            result.update({"slug": content.get("slug", timeline_id), "config_version": int(document["version"]), "config": content.get("config", {}), "registry": content.get("registry", {})})
    return result


def verify_catalog_tail(connection, project_id, timeline_id, events, start, project_seq, *, legacy=False):
    """Account for visibility events only after the caller verifies the hash chain.

    The retained result (or its expired hash) must describe the same live film
    projection and head. No semantic execution or response replay participates.
    Callers hold the store mutex; acceptance also holds its SQLite transaction.
    """
    from .timeline_commit_baseline import _json, _require

    resource = timeline_resource(connection, timeline_id)
    next_seq = connection.execute("SELECT next_seq FROM project_sequences WHERE project_id=?", (project_id,)).fetchone()
    receipts, version, archived = set(), None, None
    for position, event in enumerate(events[start:], start + 1):
        if event["kind"] == "timeline.renamed":
            continue  # Existing display-only rename policy.
        kind = {"timeline.archived": "timeline.archive", "timeline.recovered": "timeline.recover"}.get(event["kind"])
        _require(kind is not None, "later_unaccounted_timeline_write")
        payload = _json(event["payload_json"])
        _require(isinstance(payload, dict) and set(payload) == {"project_id", "version"}
                 and payload["project_id"] == project_id and type(payload["version"]) is int
                 and payload["version"] > 1, "catalog_event_mismatch")
        rows = connection.execute("SELECT * FROM command_idempotency WHERE primary_stream_id=? AND resulting_stream_seq=?",
                                  (timeline_id, position)).fetchall()
        _require(len(rows) == 1, "catalog_receipt_missing_or_ambiguous")
        receipt = rows[0]
        _require(receipt["command_kind"] == kind and receipt["aggregate_id"] == timeline_id
                 and receipt["txn_id"] and _json(receipt["event_ids_json"]) == [str(event["id"])]
                 and type(receipt["first_project_seq"]) is int
                 and project_seq < receipt["first_project_seq"] == receipt["last_project_seq"]
                 and next_seq is not None and receipt["last_project_seq"] < next_seq[0], "catalog_receipt_scope_mismatch")
        project_seq = receipt["last_project_seq"]
        current_version = payload["version"]
        _require(version is None or current_version == version + 1, "catalog_version_mismatch")
        version, archived = current_version, kind == "timeline.archive"
        bodies = [{"expected_version": version - 1}]
        if kind == "timeline.recover":
            bodies.append({"expected_version": version - 1, "version": version - 1})
        action = kind.split(".")[1]
        _require(receipt["request_hash"] in {
            hashlib.sha256(canonical_json({"timeline_id": timeline_id, "body": body, "action": action}).encode()).hexdigest()
            for body in bodies}, "catalog_request_mismatch")
        result = _json(receipt["result_json"])
        expected = {**resource, "version": version, "archived": archived}
        renamed = any(later["kind"] == "timeline.renamed" for later in events[position:])
        candidates = [expected]
        if legacy:
            # Installing main's proven publication identity does not rewrite
            # earlier catalog receipts, whose publication field was still null.
            candidates.append({**expected, "head_publication_id": None})
        if isinstance(result, dict) and EXPIRED in result:
            # A rename can erase the old name needed to check an expired hash.
            _require(not renamed and result in [{EXPIRED: hashlib.sha256(canonical_json(candidate).encode()).hexdigest()} for candidate in candidates],
                     "catalog_result_mismatch")
        else:
            if renamed and isinstance(result, dict) and isinstance(result.get("name"), str):
                for candidate in candidates:
                    candidate["name"] = result["name"]
            _require(canonical_json(result) in {canonical_json(candidate) for candidate in candidates},
                     "catalog_projection_mismatch")
        receipts.add(receipt["txn_id"])
    if version is not None:
        # Visibility receipts cannot legitimize an earlier raw flat-film write.
        # Canonical commits leave this legacy snapshot/projection unchanged.
        snapshot = connection.execute("SELECT shots_json, references_json FROM timeline_revisions WHERE timeline_id=? ORDER BY version DESC LIMIT 1",
                                      (timeline_id,)).fetchone()
        _require(snapshot is not None and canonical_json(resource["shots"]) == canonical_json(_json(snapshot["shots_json"]))
                 and canonical_json(resource["references"]) == canonical_json(_json(snapshot["references_json"])),
                 "catalog_projection_mismatch")
        _require(resource["project_id"] == project_id and resource["version"] == version
                 and resource["archived"] == archived, "catalog_state_mismatch")
    return receipts
