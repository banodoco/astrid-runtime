"""Shared read-only and fenced authority for disruptive Runtime lifecycle work."""

from __future__ import annotations

import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .errors import ConflictError, RealmAdmissionError, ValidationError
from .catalog import _safe_path
from .sqlite_uri import sqlite_file_uri


def _regular_database(root: str | Path) -> tuple[Path, Path]:
    try:
        root = _safe_path(root, "realm root").resolve()
    except ValueError as exc:
        raise RealmAdmissionError(str(exc)) from exc
    if not root.exists() or not root.is_dir() or root.is_symlink():
        raise RealmAdmissionError("realm root is missing or invalid")
    database = root / "realm.sqlite3"
    try:
        mode = database.lstat().st_mode
    except FileNotFoundError as exc:
        raise RealmAdmissionError("realm database is missing") from exc
    if not stat.S_ISREG(mode) or database.is_symlink():
        raise RealmAdmissionError("realm database must be an ordinary file")
    return root, database


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _expired(value: object, *, observed_at: datetime) -> bool | None:
    if value is None or str(value) == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed <= observed_at
    except (TypeError, ValueError):
        return None


def _age_seconds(value: object, *, observed_at: datetime) -> int | None:
    """Return a stable non-negative age, or None when the timestamp is unknown."""
    if value is None or str(value) == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0, int((observed_at - parsed).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return None


def _blocker_text(blockers: list[dict[str, object]], *, task_count: int) -> tuple[str, str]:
    headline = f"Astrid is busy ({task_count} tasks running). Try again when they finish."
    details = []
    for blocker in blockers:
        age = blocker["age_seconds"]
        age_text = "age unknown" if age is None else f"age {age}s"
        details.append(
            f"{blocker['task_id']} [{blocker['blocker_kind']}; "
            f"{blocker['kind']}; {blocker['state']}; {age_text}]"
        )
    return headline, "\n".join([headline, *details])


def _interruption_report(connection: sqlite3.Connection) -> dict[str, object]:
    """Describe every durable reason a stop/restart/upgrade is unsafe."""
    tables = _tables(connection)
    if not {"tasks", "attempts"}.issubset(tables):
        raise ValidationError(
            "cannot establish runtime interruption safety: task/attempt tables are missing"
        )
    observed_at = datetime.now(timezone.utc)
    task_columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(tasks)")
    }
    if not {"id", "status"}.issubset(task_columns):
        raise ValidationError(
            "cannot establish runtime interruption safety: task identity/status metadata is missing"
        )
    metadata_columns = [column for column in ("id", "status", "capability", "created_at") if column in task_columns]
    task_metadata = {
        str(row["id"]): {
            "kind": str(row["capability"] or "unknown") if "capability" in task_columns else "unknown",
            "state": str(row["status"] or "unknown"),
            "created_at": row["created_at"] if "created_at" in task_columns else None,
        }
        for row in connection.execute(f"SELECT {', '.join(metadata_columns)} FROM tasks")
    }
    active_tasks = [
        {"task_id": row["task_id"], "status": row["status"]}
        for row in connection.execute(
            "SELECT id AS task_id, status FROM tasks WHERE lower(status) IN ('running', 'cancel_requested') ORDER BY id"
        )
    ]
    unreconciled_attempts = []
    for row in connection.execute(
        "SELECT id, task_id, lease_id, lease_expires_at, runtime_epoch "
        "FROM attempts WHERE settled=0 ORDER BY id"
    ):
        unreconciled_attempts.append(
            {
                "attempt_id": str(row[0]),
                "task_id": str(row[1]),
                "lease_id": str(row[2]),
                "lease_expires_at": row[3],
                "lease_expired": _expired(row[3], observed_at=observed_at),
                "runtime_epoch": int(row[4]),
            }
        )
    claimed_bindings = []
    if "execution_bindings" in tables:
        claimed_bindings = [
            {"binding_id": str(row[0]), "task_id": str(row[1]), "status": str(row[2])}
            for row in connection.execute(
                "SELECT binding_id, task_id, status FROM execution_bindings "
                "WHERE status IN ('claimed', 'stale') ORDER BY binding_id"
            )
        ]
    unreleased_reservations = []
    if "reservations" in tables:
        unreleased_reservations = [
            {
                "task_id": str(row[0]), "resource_key": str(row[1]), "lease_token": str(row[2]),
                "executor_id": row[3], "fence": int(row[4]), "lease_expires_at": row[5],
                "lease_expired": _expired(row[5], observed_at=observed_at), "runtime_epoch": int(row[6]),
            }
            for row in connection.execute(
                "SELECT task_id, resource_key, lease_token, executor_id, fence, lease_expires_at, runtime_epoch FROM reservations "
                "WHERE released_at IS NULL ORDER BY task_id, resource_key"
            )
        ]
    blockers = []
    for row in active_tasks:
        task = task_metadata.get(row["task_id"], {})
        category = "cancel_requested_task" if str(row["status"]).lower() == "cancel_requested" else "running_task"
        blockers.append(_normalized_blocker(task, row["task_id"], category, observed_at))
    for row in unreconciled_attempts:
        task = task_metadata.get(row["task_id"], {})
        blockers.append(_normalized_blocker(
            task, row["task_id"], "unsettled_attempt", observed_at,
            attempt_id=row["attempt_id"], lease_id=row["lease_id"],
            lease_expires_at=row["lease_expires_at"], lease_expired=row["lease_expired"],
            runtime_epoch=row["runtime_epoch"],
        ))
    for row in claimed_bindings:
        task = task_metadata.get(row["task_id"], {})
        blockers.append(_normalized_blocker(
            task, row["task_id"], "claimed_or_stale_binding", observed_at,
            binding_id=row["binding_id"], binding_status=row["status"],
        ))
    for row in unreleased_reservations:
        task = task_metadata.get(row["task_id"], {})
        blockers.append(_normalized_blocker(
            task, row["task_id"], "unreleased_reservation", observed_at,
            resource_key=row["resource_key"], lease_token=row["lease_token"],
            executor_id=row["executor_id"], fence=row["fence"],
            lease_expires_at=row["lease_expires_at"], lease_expired=row["lease_expired"],
            runtime_epoch=row["runtime_epoch"],
        ))
    blockers.sort(
        key=lambda row: (
            str(row["task_id"]),
            str(row["blocker_kind"]),
            str(row.get("attempt_id", row.get("binding_id", row.get("resource_key", "")))),
        )
    )
    is_blocked = bool(
        active_tasks
        or unreconciled_attempts
        or claimed_bindings
        or unreleased_reservations
    )
    task_count = len({str(row["task_id"]) for row in blockers})
    headline, message = _blocker_text(blockers, task_count=task_count)
    return {
        "safe": not is_blocked,
        "active_tasks": active_tasks,
        "unreconciled_attempts": unreconciled_attempts,
        "claimed_or_stale_bindings": claimed_bindings,
        "unreleased_reservations": unreleased_reservations,
        "blockers": blockers,
        "task_count": task_count,
        "headline": headline if is_blocked else None,
        "message": message if is_blocked else None,
    }


def _normalized_blocker(
    task: dict[str, object], task_id: str, blocker_kind: str, observed_at: datetime,
    **identifiers: object,
) -> dict[str, object]:
    created_at = task.get("created_at")
    return {
        "task_id": task_id,
        "kind": task.get("kind", "unknown"),
        "state": task.get("state", "unknown"),
        "created_at": created_at,
        "age_seconds": _age_seconds(created_at, observed_at=observed_at),
        "blocker_kind": blocker_kind,
        **identifiers,
    }


def inspect_interruption_state(root: str | Path) -> dict[str, object]:
    """Observe committed lifecycle blockers without changing realm data.

    SQLite may maintain WAL/SHM bookkeeping; this advisory observation never
    authorizes a later stop, which must take a fresh interruption fence.
    """
    _, database = _regular_database(root)
    connection = sqlite3.connect(sqlite_file_uri(database), uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return _interruption_report(connection)
    finally:
        connection.close()


def assert_interruption_safe(root: str | Path) -> dict[str, object]:
    report = inspect_interruption_state(root)
    if not report["safe"]:
        raise ConflictError(
            str(report["message"]),
            details=report,
        )
    return report


@contextmanager
def interruption_fence(
    root: str | Path,
    *,
    timeout_seconds: float = 5.0,
) -> Iterator[dict[str, object]]:
    """Hold SQLite's write fence while a live owner is identity-stopped.

    The initial read-only check gives a side-effect-free refusal path.  The
    immediate transaction then serializes with admission/claim/settlement, so
    no claim can land between the final idle decision and the process signal.
    The transaction is always rolled back because this authority writes no
    lifecycle rows itself.
    """
    assert_interruption_safe(root)
    _, database = _regular_database(root)
    connection = sqlite3.connect(database, timeout=float(timeout_seconds))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        report = _interruption_report(connection)
        if not report["safe"]:
            raise ConflictError(
                str(report["message"]),
                details=report,
            )
        yield report
    finally:
        connection.rollback()
        connection.close()


__all__ = [
    "assert_interruption_safe",
    "inspect_interruption_state",
    "interruption_fence",
]
