"""Frozen SQL-only generation backfill primitives used by v33_lifecycle.

Callers must hold the realm fence, durably persist the returned plan before
application, and bind it to a verified recovery set. These functions alone do
not authorize migration or establish startup readiness.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from .errors import ConflictError, ValidationError
from .upgrade import _generation_tag_evidence
from .util import canonical_json


def _digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _witness(row):
    return {key: row[key] for key in ("id", "metadata_json", "version", "updated_at")}


def _source_witness(connection, row):
    """Capture the SQL inputs consulted when deriving a generation's tags."""
    result = {key: row[key] for key in ("project_id", "source_task_id", "type")}
    task_id = row["source_task_id"]
    if not task_id:
        return result
    task = connection.execute(
        "SELECT run_id, expected_effect_json, spec_digest FROM tasks WHERE id=?", (task_id,)
    ).fetchone()
    result["task"] = list(task) if task is not None else None
    if task is None:
        return result
    run = connection.execute(
        "SELECT project_id, spec_digest FROM runs WHERE id=?", (task["run_id"],)
    ).fetchone()
    result["run"] = list(run) if run is not None else None
    result["specs"] = []
    for digest in (task["spec_digest"], run["spec_digest"] if run is not None else None):
        spec = connection.execute("SELECT body_json FROM task_specs WHERE digest=?", (digest,)).fetchone() if digest is not None else None
        result["specs"].append(spec[0] if spec is not None else None)
    binding = connection.execute(
        "SELECT target_kind, target_id FROM execution_bindings WHERE task_id=?", (task_id,)
    ).fetchone()
    result["binding"] = list(binding) if binding is not None else None
    return result


def freeze_generation_plan(connection, *, realm_id, backup_id, schema_fingerprint, applied_at):
    """Build a complete deterministic plan inside a caller-owned transaction.

    The caller persists and fsyncs this plan while maintaining exclusive
    ownership. External evidence, the ledger and CAS are intentionally absent.
    """
    if not connection.in_transaction:
        raise ValidationError("backfill planning requires a transaction")
    if not all(isinstance(x, str) and x for x in (realm_id, backup_id, schema_fingerprint, applied_at)):
        raise ValidationError("backfill plan binding is incomplete")
    if connection.row_factory is not sqlite3.Row:
        raise ValidationError("backfill planning requires sqlite3.Row")
    entries = []
    for row in connection.execute("SELECT * FROM generations ORDER BY id"):
        before = _witness(row)
        after = dict(before)
        try:
            metadata = _generation_tag_evidence(connection, row, version=33, realm_id=realm_id)
            if metadata == json.loads(row["metadata_json"]):
                reason = "already_current"
            else:
                reason = "change"
                after.update(metadata_json=canonical_json(metadata), version=row["version"] + 1, updated_at=applied_at)
        except ValueError as exc:
            reason = str(exc)
        entries.append({"before": before, "after": after, "reason": reason,
                        "source": _source_witness(connection, row)})
    plan = {"algorithm": "generation-tags-sql-v2", "realm_id": realm_id, "backup_id": backup_id,
            "schema_fingerprint": schema_fingerprint, "applied_at": applied_at, "entries": entries}
    return {**plan, "digest": _digest(plan)}


def reconcile_generation_plan(connection, plan, *, verify_only=False):
    """Apply the exact frozen plan or recognize its committed post-state.

    The caller must already have persisted the plan and obtained exclusive realm
    ownership. Mixed/unexpected data, including scope changes, refuses without
    mutation. Completion must be persisted separately before provider startup.
    """
    if connection.in_transaction:
        raise ValidationError("backfill reconciliation requires a fresh transaction")
    if connection.row_factory is not sqlite3.Row:
        raise ValidationError("backfill reconciliation requires sqlite3.Row")
    if not isinstance(plan, dict) or plan.get("algorithm") != "generation-tags-sql-v2":
        raise ValidationError("invalid backfill plan")
    body = {key: value for key, value in plan.items() if key != "digest"}
    if plan.get("digest") != _digest(body):
        raise ValidationError("backfill plan digest mismatch")
    entries = plan.get("entries")
    if not isinstance(entries, list):
        raise ValidationError("invalid backfill entries")
    connection.execute("BEGIN IMMEDIATE")
    try:
        generation_rows = list(connection.execute("SELECT * FROM generations ORDER BY id"))
        rows = [_witness(row) for row in generation_rows]
        pre = [entry["before"] for entry in entries]
        post = [entry["after"] for entry in entries]
        if rows != pre and rows != post:
            raise ConflictError("generation backfill is mixed or changed; recovery is required")
        if [_source_witness(connection, row) for row in generation_rows] != [entry.get("source") for entry in entries]:
            raise ConflictError("generation backfill source evidence changed; recovery is required")
        if rows == post:
            state = "already_applied"
        elif rows == pre:
            if verify_only:
                raise ConflictError("completed backfill does not match its post-state")
            for entry in entries:
                before, after = entry["before"], entry["after"]
                if before == after:
                    continue
                cursor = connection.execute(
                    "UPDATE generations SET metadata_json=?, version=?, updated_at=? "
                    "WHERE id=? AND metadata_json=? AND version=? AND updated_at=?",
                    (after["metadata_json"], after["version"], after["updated_at"], before["id"],
                     before["metadata_json"], before["version"], before["updated_at"]),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("generation changed during frozen backfill")
            state = "applied"
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ConflictError("generation backfill integrity verification failed")
        connection.commit()
        return {"state": state, "plan_digest": plan["digest"], "backup_id": plan["backup_id"]}
    except Exception:
        connection.rollback()
        raise
