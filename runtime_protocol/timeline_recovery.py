"""Metadata-only D4 inspection/export; never evaluates an unverified document."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import sqlite3

from .errors import ConflictError, ValidationError
from .util import canonical_json
from . import v33_lifecycle as lifecycle


def _json_row(row):
    return {key: {"base64": base64.b64encode(value).decode()} if isinstance(value, bytes) else value
            for key, value in dict(row).items()}


def inventory(connection, root, project_id, timeline_id, *, reason, backup=None):
    if connection.execute("SELECT 1 FROM timelines WHERE project_id=? AND id=?", (project_id, timeline_id)).fetchone() is None:
        raise ValidationError("recovery timeline is not in the selected project")
    tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    rows = {}
    for table in ("timelines", "timeline_documents", "project_documents", "timeline_revisions", "timeline_events",
                  "parent_composition_revisions", "parent_composition_heads", "shot_revisions", "internal_timeline_revisions",
                  "composition_revision_occurrences", "composition_revision_dependencies", "timeline_commit_history",
                  "timeline_document_input_links", "timeline_document_input_bindings", "timeline_document_input_contents",
                  "generations", "managed_output_associations", "command_idempotency"):
        if table not in tables:
            continue
        columns = {r[1] for r in connection.execute(f'PRAGMA table_info("{table}")')}
        clauses, args = [], []
        if "project_id" in columns:
            clauses.append("project_id=?"); args.append(project_id)
        if "timeline_id" in columns:
            clauses.append("timeline_id=?"); args.append(timeline_id)
        elif table == "timelines":
            clauses.append("id=?"); args.append(timeline_id)
        if not clauses and "parent_revision_id" in columns:
            clauses.append("parent_revision_id IN (SELECT id FROM parent_composition_revisions WHERE project_id=? AND timeline_id=?)")
            args.extend((project_id, timeline_id))
        if not clauses:
            continue
        rows[table] = [_json_row(r) for r in connection.execute(f'SELECT * FROM "{table}" WHERE ' + " AND ".join(clauses), args)]
    media, missing = [], []
    for row in connection.execute("SELECT o.digest, o.size FROM objects o JOIN project_objects p ON p.digest=o.digest WHERE p.project_id=? ORDER BY o.digest", (project_id,)):
        path = Path(root) / "cas" / "sha256" / row[0][:2] / row[0][2:]
        fact = {"digest": row[0], "size": row[1]}
        if not path.is_file() or path.is_symlink() or lifecycle._file_fact(path) != {"size": row[1], "sha256": row[0]}:
            missing.append({**fact, "reason": "missing_or_corrupt_media"})
        else:
            media.append(fact)
    return {"format": "astrid-timeline-recovery/v1", "project_id": project_id, "timeline_id": timeline_id,
            "access": "read_only", "reason": reason, "backup": backup,
            "actions": ["inspect/export original records and verified media", "explicitly re-author/reselect as new work with new keys",
                        "restore the full matching recovery image and prior executable with astrid-runtime upgrade --recover"],
            "rows": rows, "verified_media": media, "unavailable": missing,
            "complete": not missing, "provenance_verified": False, "scope": "original timeline/project records and owned media; provenance is not certified by export",
            "affected_inputs_outbox": "preserved in original records and full local support recovery set; disconnected App outboxes require App inventory"}


def offline_export(root, project_id, timeline_id, *, destination=None):
    """Use an inactive disposable DB copy, including when normal admission fails."""
    from .upgrade import inspect_realm_schema
    root = Path(root).expanduser().resolve()
    inspect_realm_schema(root)  # Unknown layouts remain a refusal, not inferred SQL.
    with lifecycle.sqlite_observation(root) as copy:
        connection = sqlite3.connect(copy / "realm.sqlite3")
        connection.row_factory = sqlite3.Row
        try:
            result = inventory(connection, root, project_id, timeline_id,
                               reason={"code": "unverified_original", "message": "Original records only. Editing/rendering requires verified current proof."})
        finally:
            connection.close()
    if destination is not None:
        destination = Path(destination).expanduser().resolve()
        if destination == root or root in destination.parents or destination in root.parents or destination.exists():
            raise ValidationError("support export requires a new directory outside the realm")
        destination.mkdir(mode=0o700)
        for item in result["verified_media"]:
            source = root / "cas" / "sha256" / item["digest"][:2] / item["digest"][2:]
            target = destination / item["digest"]
            shutil.copyfile(source, target)
            if lifecycle._file_fact(target) != {"size": item["size"], "sha256": item["digest"]}:
                raise ConflictError("media changed during support export; export is incomplete")
        lifecycle.write_record(destination / "inventory.json", result)
    return result
