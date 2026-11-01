"""Projection of accepted, parent-owned unplaced timeline references.

The Agent owns the namespaced parent carrier.  Runtime only derives the
existing timeline reference read model after the normal closure has passed.
"""
from __future__ import annotations

import json
import re

from .util import canonical_json, now

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ReferenceProjectionError(Exception):
    """A fail-closed projection refusal that is safe before persistence."""

    def __init__(self, reason, message=None, *, status=409):
        super().__init__(message or reason)
        self.reason = reason
        self.message = message or reason
        self.status = status


def _refuse(reason, message=None, *, status=409):
    raise ReferenceProjectionError(reason, message, status=status)


def _reference_map(document):
    payload = document["parent_revision"]["payload"]
    config = payload.get("config", {})
    if not isinstance(config, dict):
        _refuse("reference_projection_invalid", "parent config is not an object", status=422)
    app = config.get("app", {})
    if not isinstance(app, dict):
        _refuse("reference_projection_invalid", "parent config app is not an object", status=422)
    astrid = app.get("astrid", {})
    if not isinstance(astrid, dict):
        _refuse("reference_projection_invalid", "parent config astrid is not an object", status=422)
    references = astrid.get("timeline_references", {})
    if not isinstance(references, dict):
        _refuse("reference_projection_invalid", "timeline references are not an object", status=422)
    return references


def _desired(document):
    manifest = document["dependency_manifest"]["media"]
    desired = {}
    for key, value in _reference_map(document).items():
        if (not isinstance(key, str) or not key or not isinstance(value, dict)
                or set(value) != {"version", "reference_id", "role", "media"}
                or type(value["version"]) is not int or value["version"] != 1
                or value["reference_id"] != key or value["role"] != "source"
                or not isinstance(value["media"], dict)
                or set(value["media"]) != {"media_id", "content_digest"}):
            _refuse("reference_projection_invalid", "timeline reference leaf is malformed", status=422)
        media = value["media"]
        if (not isinstance(media["media_id"], str) or not _DIGEST.fullmatch(media["media_id"])
                or media["content_digest"] != media["media_id"]):
            _refuse("reference_projection_invalid", "timeline reference media pin is malformed", status=422)
        if sum(pin == media for pin in manifest) != 1:
            _refuse("reference_projection_out_of_manifest", "timeline reference media is outside accepted custody")
        desired[key] = {"reference_id": key, "object_id": media["media_id"], "role": "source"}
    return desired


def _live_rows(connection, project_id, timeline_id):
    return {
        row["id"]: {"reference_id": row["id"], "object_id": row["object_id"], "role": row["role"]}
        for row in connection.execute(
            "SELECT reference.id, reference.object_id, reference.role "
            "FROM timeline_references reference JOIN timelines timeline "
            "ON timeline.id=reference.timeline_id "
            "WHERE reference.timeline_id=? AND timeline.project_id=?",
            (timeline_id, project_id),
        )
    }


def _global_row(connection, reference_id):
    row = connection.execute(
        "SELECT reference.timeline_id, timeline.project_id, reference.object_id, reference.role "
        "FROM timeline_references reference JOIN timelines timeline "
        "ON timeline.id=reference.timeline_id WHERE reference.id=?",
        (reference_id,),
    ).fetchone()
    if row is None:
        return None
    return {"timeline_id": row["timeline_id"], "project_id": row["project_id"],
            "object_id": row["object_id"], "role": row["role"]}


def _same_row(left, right):
    return left is not None and all(left[key] == right[key] for key in ("reference_id", "object_id", "role"))


def prepare_reference_projection(connection, document, previous_document, *, next_version):
    """Preflight a parent carrier against the previous accepted carrier.

    No database writes occur here.  A previous carrier plus an exact live row
    is the only ownership proof accepted for an occupied identity or removal.
    """
    project_id, timeline_id = document["project_id"], document["timeline_id"]
    if (previous_document["project_id"], previous_document["timeline_id"]) != (project_id, timeline_id):
        _refuse("history_unavailable")
    desired = _desired(document)
    previous = _desired(previous_document)
    if not desired and not previous:
        return None
    live = _live_rows(connection, project_id, timeline_id)

    for reference in desired.values():
        reference_id = reference["reference_id"]
        occupied = _global_row(connection, reference_id)
        if occupied is None:
            continue
        if reference_id not in previous or not _same_row(live.get(reference_id), previous[reference_id]):
            _refuse("reference_projection_occupied", "timeline reference identity is already occupied")
        if (occupied["timeline_id"], occupied["project_id"], occupied["object_id"], occupied["role"]) != (
                timeline_id, project_id, live[reference_id]["object_id"], live[reference_id]["role"]):
            _refuse("reference_projection_occupied", "timeline reference identity is already occupied")

    removed = sorted(set(previous) - set(desired))
    for reference_id in removed:
        current = live.get(reference_id)
        if current is not None and not _same_row(current, previous[reference_id]):
            _refuse("reference_projection_occupied", "timeline reference removal is not owned")

    projected = dict(live)
    for reference_id in removed:
        projected.pop(reference_id, None)
    projected.update(desired)
    references = [projected[key] for key in sorted(projected)]
    return {"project_id": project_id, "timeline_id": timeline_id, "version": next_version,
            "desired": desired, "removed": removed, "previous": previous,
            "references": references}


def apply_reference_projection(connection, projection):
    """Apply a preflighted projection inside the caller's transaction."""
    project_id, timeline_id = projection["project_id"], projection["timeline_id"]
    current = connection.execute(
        "SELECT version FROM timelines WHERE id=? AND project_id=?", (timeline_id, project_id)
    ).fetchone()
    if current is None or int(current["version"]) != projection["version"]:
        _refuse("history_unavailable")

    for reference_id in projection["removed"]:
        previous = projection["previous"][reference_id]
        connection.execute(
            "DELETE FROM timeline_reference_state WHERE id=? AND EXISTS ("
            "SELECT 1 FROM timeline_references reference JOIN timelines timeline "
            "ON timeline.id=reference.timeline_id WHERE reference.id=? "
            "AND reference.timeline_id=? AND timeline.project_id=? "
            "AND reference.object_id=? AND reference.role=?)",
            (reference_id, reference_id, timeline_id, project_id, previous["object_id"], previous["role"]),
        )
        connection.execute(
            "DELETE FROM timeline_references WHERE id=? AND timeline_id=? AND object_id=? AND role=?",
            (reference_id, timeline_id, previous["object_id"], previous["role"]),
        )

    for reference in projection["desired"].values():
        connection.execute(
            "INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET timeline_id=excluded.timeline_id, object_id=excluded.object_id, role=excluded.role",
            (reference["reference_id"], timeline_id, reference["object_id"], reference["role"]),
        )
    shots = [{"shot_id": row["id"], "start_ms": row["start_ms"], "duration_ms": row["duration_ms"],
              "reference_ids": json.loads(row["reference_ids_json"])}
             for row in connection.execute("SELECT * FROM timeline_shots WHERE timeline_id=?", (timeline_id,))]
    connection.execute(
        "INSERT INTO timeline_revisions(timeline_id, version, shots_json, references_json, created_at) VALUES (?, ?, ?, ?, ?)",
        (timeline_id, projection["version"], canonical_json(shots), canonical_json(projection["references"]), now()),
    )
