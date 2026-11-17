"""Authenticated, read-only subscriptions to durable work and result state."""
from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from datetime import datetime, timezone

from .errors import InvalidRequestError, ValidationError
from .store import _normalize_execution_target, execution_placement_matches
from .util import canonical_json


class TaskWaits:
    def _changes(self):
        # The store binds its condition when it creates the mutation lock.
        # Condition releases *all* recursive acquisitions, including HTTP
        # dispatch's; later instrumentation may wrap that same lock's guard.
        with self.store._mutex:
            return self.store._committed_changes

    def close_task_waits(self):
        self._changes().close()

    @staticmethod
    def _wait_options(body, scope):
        if not isinstance(body, dict) or set(body) - {"cursor", "timeout_seconds"}:
            raise ValidationError("wait accepts only cursor and timeout_seconds")
        seconds = body.get("timeout_seconds", 25)
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or not 0 <= seconds <= 25:
            raise ValidationError("timeout_seconds must be between 0 and 25")
        cursor = body.get("cursor")
        decoded = None
        if cursor is not None:
            try:
                if not isinstance(cursor, str) or len(cursor) > 2048:
                    raise ValueError()
                decoded = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
                if set(decoded) != {"v", "scope", "session", "epoch", "event", "state"} or decoded["v"] != 1 or decoded["scope"] != scope:
                    raise ValueError()
            except (ValueError, TypeError, UnicodeError):
                raise InvalidRequestError("wait cursor is invalid or belongs to another subscription") from None
        return float(seconds), decoded

    def _wait_cursor(self, scope, state, task_id=None):
        if task_id is None:
            sequence = self.store.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        else:
            sequence = self.store.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events WHERE task_id=?", (task_id,)).fetchone()[0]
        value = {"v": 1, "scope": scope, "session": self.runtime_session_id,
                 "epoch": self.store._current_runtime_epoch(), "event": sequence,
                 "state": hashlib.sha256(canonical_json(state).encode()).hexdigest()}
        encoded = base64.urlsafe_b64encode(canonical_json(value).encode()).decode().rstrip("=")
        return value, encoded

    def _wait_deadline(self, task_id=None):
        current = datetime.now(timezone.utc)
        rows = self.store.conn.execute(
            "SELECT * FROM tasks WHERE status IN ('queued', 'running', 'cancel_requested')" +
            (" AND id=?" if task_id else ""), (task_id,) if task_id else (),
        ).fetchall()
        remaining = []
        for row in rows:
            deadlines = [self.store._task_absolute_deadline(row)]
            attempt_deadline = self.store._attempt_runtime_deadline(row) if row["status"] in {"running", "cancel_requested"} else None
            if attempt_deadline is not None:
                deadlines.append(attempt_deadline)
            if row["lease_expires_at"]:
                deadlines.append(datetime.fromisoformat(row["lease_expires_at"]))
            remaining.extend((deadline - current).total_seconds() for deadline in deadlines if deadline > current)
        return min(remaining) if remaining else None

    def _wait_state(self, scope, body, snapshot, *, task_id=None, auth_check=None, work=False):
        seconds, previous = self._wait_options(body, scope)
        expires = time.monotonic() + seconds
        changes = self._changes()
        with changes.condition:
            while True:
                if changes.closed or self.store.conn is None:
                    return {"reason": "shutdown", "runtime_session_id": self.runtime_session_id,
                            "runtime_epoch": self._runtime_state["runtime_epoch"], "cursor": None}
                if auth_check is not None:
                    auth_check()
                # Only an actual hard deadline can cause a write here. The
                # ordinary predicate and empty wait never claim or journal.
                self.reap_task_lifetimes()
                state = snapshot()
                current, cursor = self._wait_cursor(scope, state, task_id)
                changed = previous is None or any(previous[k] != current[k] for k in ("session", "epoch", "state"))
                ready = state["available"] if work else changed
                remaining = expires - time.monotonic()
                if ready or remaining <= 0:
                    return {**state, "reason": "changed" if ready else "timeout", "cursor": cursor,
                            "runtime_session_id": self.runtime_session_id, "runtime_epoch": current["epoch"]}
                deadline = self._wait_deadline(task_id)
                changes.condition.wait(min(remaining, deadline) if deadline is not None else remaining)

    def wait_for_task(self, task_id, body=None, *, auth_check=None):
        def snapshot():
            value = self.store.get_task(task_id)
            task = self._task_resource(value)
            lease = task.get("lease_expires_at")
            return {"task": task, "managed_outputs": self.managed_output_page(task_id),
                    "lease_expired": bool(lease and datetime.fromisoformat(lease) <= datetime.now(timezone.utc))}
        return self._wait_state("task:" + task_id, body or {}, snapshot, task_id=task_id, auth_check=auth_check)

    def wait_for_work(self, body, *, identity=None, auth_check=None):
        from .service import _wire_object, _wire_string, _wire_integer

        body = _wire_object(body, required=("executor_id", "capability_ids", "runtime_epoch"),
                            allowed=("executor_id", "capability_ids", "runtime_epoch", "target", "cursor", "timeout_seconds"))
        executor_id = _wire_string(body, "executor_id")
        capabilities = body["capability_ids"]
        if not isinstance(capabilities, list) or any(not isinstance(c, str) or not c for c in capabilities) or len(set(capabilities)) != len(capabilities):
            raise ValidationError("capability_ids must be a list of unique non-empty strings")
        epoch = _wire_integer(body, "runtime_epoch", positive=True)
        target = _normalize_execution_target(body["target"]) if body.get("target") is not None else None
        placement = self._trusted_execution_placement(identity)
        scope = "work:" + hashlib.sha256(canonical_json({"executor": executor_id, "capabilities": capabilities, "target": target}).encode()).hexdigest()

        def snapshot():
            self._assert_executor_identity(identity, executor_id)
            self._assert_local_claim_admission(executor_id, identity=identity)
            self.store._validate_runtime_epoch(epoch, identity="executor", identity_id=executor_id, required=True)
            # Match the host's capability exclusion rule without a mutating
            # claim just to discover that a head-of-line task is blocked.
            remaining = list(capabilities) or [r[0] for r in self.store.conn.execute(
                "SELECT DISTINCT capability FROM tasks WHERE status='queued'")]
            while remaining:
                row, binding = self._next_claim_candidate(executor_id, remaining, target, placement, identity)
                if row is None:
                    break
                available = row["waiting_reason"] != "provider_state_unknown"
                if available and (binding is not None or (isinstance(identity, dict) and identity.get("qualified_activation") is not None)):
                    available = (binding is not None and placement is not None
                                 and execution_placement_matches(binding["resolved_target"], placement)
                                 and self._placement_recovery_qualification_matches(row["id"], placement)
                                 and (not (self._task_requires_remote_activation(row["id"]) or identity.get("qualified_activation"))
                                      or self._remote_activation_matches(row["id"], identity, placement, require_fresh=True)))
                if available:
                    task = self.store.conn.execute("SELECT * FROM tasks WHERE id=?", (row["id"],)).fetchone()
                    executor = self.store.conn.execute("SELECT * FROM executors WHERE id=?", (executor_id,)).fetchone()
                    capability = self.store.conn.execute("SELECT * FROM capabilities WHERE id=?", (task["capability"],)).fetchone()
                    dependencies = self.store._continuation_rows(task["id"])
                    admitted = not dependencies or self.store.conn.execute("SELECT 1 FROM continuation_admissions WHERE continuation_task_id=?", (task["id"],)).fetchone()
                    reason = self.store._claim_waiting_reason(task, executor, capability, self.store._spec(task))
                    # Superseded resolution needs the ordinary atomic claim
                    # refusal. This read still writes nothing and grants no
                    # worker lease; the claim records its terminal error.
                    available = bool(admitted and reason in {None, "resolution_descriptor_stale"}
                                     and self.store._task_lifetime_failure(task, datetime.now(timezone.utc)) is None)
                if available:
                    return {"available": True, "capability_ids": [row["capability"]]}
                remaining = [cap for cap in remaining if cap != row["capability"]]
            return {"available": False, "capability_ids": []}

        options = {k: body[k] for k in ("cursor", "timeout_seconds") if k in body}
        return self._wait_state(scope, options, snapshot, auth_check=auth_check, work=True)
