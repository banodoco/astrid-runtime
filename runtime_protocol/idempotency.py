"""Bounded replay payloads for the v26 command ledger.

The ledger's key and request hash remain permanent. Large task specs live in
immutable task rows; registration catalogs need a snapshot because capability
rows can be replaced by a later registration in the same runtime epoch.
"""

import base64
import hashlib
import json
import zlib
from datetime import datetime, timedelta, timezone

from .errors import ConflictError
from .util import canonical_json

RESULT_WINDOW_SECONDS = 24 * 60 * 60
EXPIRED = "__runtime_idempotency_result_expired_v1"
COMPACT = "__runtime_compact_result_v1"


class IdempotencyWindowExpired(ConflictError):
    code = "idempotency_window_expired"


def expired_result(result_json):
    return canonical_json({EXPIRED: hashlib.sha256(result_json.encode()).hexdigest()})


def compact_result(kind, result):
    if kind in {"task.claim", "task.create", "attempt.settle", "task.cancel",
                "task.retry", "attempt.fail", "attempt.heartbeat"} and isinstance(result, dict):
        short = dict(result)
        specs = []
        if short.get("task_id") and "spec" in short:
            specs.append(["", "task", short["task_id"], "spec"])
            short.pop("spec")
        task = short.get("task")
        if isinstance(task, dict) and (task.get("task_id") or task.get("id")) and "spec" in task:
            short["task"] = dict(task)
            short["task"].pop("spec")
            specs.append(["task", "task", task.get("task_id") or task["id"], "spec"])
        run = short.get("run")
        if isinstance(run, dict) and run.get("id") and "spec_json" in run:
            short["run"] = dict(run)
            short["run"].pop("spec_json")
            specs.append(["run", "run", run["id"], "spec_json"])
        if specs:
            return canonical_json({COMPACT: "task_spec", "result": short, "specs": specs})
    if kind == "executor.register" and isinstance(result, dict) and "capabilities" in result:
        short = dict(result)
        catalog = short.pop("capabilities")
        # A later registration may replace the current catalog. Keep the
        # exact advertised snapshot, compressed, for in-window retransmits.
        snapshot = base64.b64encode(zlib.compress(canonical_json(catalog).encode(), 9)).decode("ascii")
        return canonical_json({COMPACT: "registration", "result": short, "catalog_zlib": snapshot})
    return canonical_json(result)


def command_result(result_json, *, kind=None, created_at=None, connection=None, window_seconds=RESULT_WINDOW_SECONDS):
    if created_at is not None and kind != "timeline.commit":
        timestamp = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        if timestamp.tzinfo is None or timestamp < datetime.now(timezone.utc) - timedelta(seconds=window_seconds):
            raise IdempotencyWindowExpired("idempotency result is outside its replay window; the command was not executed again")
    value = json.loads(result_json)
    if isinstance(value, dict) and EXPIRED in value:
        raise IdempotencyWindowExpired("idempotency result is outside its replay window; the command was not executed again")
    if isinstance(value, dict) and value.get(COMPACT) == "task_spec":
        result = value["result"]
        from .store import public_task_spec
        for path, source, identity, column in value["specs"]:
            table = "tasks" if source == "task" else "runs"
            columns = {column[1] for column in connection.execute(f"PRAGMA table_info({table})")}
            if "spec_digest" in columns:
                row = connection.execute(
                    f"SELECT s.body_json FROM {table} t LEFT JOIN task_specs s ON s.digest=t.spec_digest WHERE t.id=?",
                    (identity,),
                ).fetchone()
            else:
                row = connection.execute(f"SELECT spec_json FROM {table} WHERE id=?", (identity,)).fetchone()
            if row is None or row[0] is None:
                raise IdempotencyWindowExpired("task or run is unavailable for replay")
            target = result if not path else result[path]
            target[column] = row[0] if column == "spec_json" else public_task_spec(json.loads(row[0]))[0]
        return result
    if isinstance(value, dict) and value.get(COMPACT) == "registration":
        result = value["result"]
        result["capabilities"] = json.loads(zlib.decompress(base64.b64decode(value["catalog_zlib"])))
        return result
    return value
