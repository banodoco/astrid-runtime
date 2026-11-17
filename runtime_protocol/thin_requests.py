"""Thin admission shares the ordinary create transaction and receipt."""
from __future__ import annotations

import hashlib
import json

from .errors import ConflictError, ValidationError
from .resolution import (ADMISSION_KEY, DESCRIPTOR_KEY, FORMAT, ResolutionUnavailable,
                         bounded, descriptor_digest, resolve)
from .util import canonical_json


def settings_match(store, descriptor):
    reference = descriptor.get("settings_ref")
    if reference is None:
        return True
    row = store.conn.execute("SELECT content_json, version FROM user_app_state WHERE actor_id=? AND key=?",
                             (reference["actor"], reference["key"])).fetchone()
    content, version = (json.loads(row["content_json"]), int(row["version"])) if row else (None, 0)
    digest = "sha256:" + hashlib.sha256(canonical_json(content).encode()).hexdigest()
    return version == reference["version"] and digest == descriptor["settings_digest"]


def binding_matches(store, metadata, executor):
    if not isinstance(metadata, dict) or executor is None:
        return False
    # Resolution is durable data, not a worker lease. A new Runtime boot or
    # another host may execute the same frozen descriptor; claim authority
    # still checks the current executor registration, epoch and ordinary fence.
    # Ignore the executor/Runtime epoch fields in already-admitted LS-7 specs.
    if (metadata.get("source_digest") != executor["source_digest"]
            or metadata.get("source_epoch") != executor["source_epoch"]):
        return False
    return settings_match(store, metadata) and any(descriptor_digest(d) == metadata.get("descriptor_digest")
               for cap in json.loads(executor["capabilities_json"]) if isinstance(cap, dict)
               for d in cap.get(DESCRIPTOR_KEY, []))


def binding_is_stale(store, metadata):
    """Distinguish superseded data from a temporarily unavailable host.

    Retain last-known registrations across restarts and liveness expiry. An
    offline matching host is not evidence that its descriptor changed. Only
    a changed settings snapshot or replacement of every matching descriptor
    invalidates the frozen admission; one unrelated host cannot refuse it.
    """
    if not isinstance(metadata, dict) or not settings_match(store, metadata):
        return True
    return not any(binding_matches(store, metadata, executor)
                   for executor in store.conn.execute("SELECT * FROM executors"))


class ThinRequests:
    def _resolution_descriptor(self, thin, project_id, identity=None):
        matches = []
        for executor in self.store.conn.execute("SELECT * FROM executors ORDER BY id"):
            if int(executor["runtime_epoch"]) != self.store._current_runtime_epoch() or not self.store._executor_live(executor):
                continue
            for cap in json.loads(executor["capabilities_json"]):
                if not isinstance(cap, dict):
                    continue
                for descriptor in cap.get(DESCRIPTOR_KEY, []):
                    digest = descriptor_digest(descriptor)
                    if (descriptor["entry_id"] != thin["entry_id"] or descriptor.get("mode") != thin.get("mode")
                            or descriptor["project_id"] != project_id):
                        continue
                    if thin.get("descriptor_digest") not in (None, digest):
                        continue
                    reference = descriptor.get("settings_ref")
                    if (reference is not None and (not isinstance(identity, dict) or reference["actor"] != identity.get("actor"))) or not settings_match(self.store, descriptor):
                        continue
                    if descriptor["source_digest"] != executor["source_digest"] or descriptor["source_epoch"] != executor["source_epoch"]:
                        continue
                    if not self.store._executor_can_run(executor, descriptor["capability_id"], descriptor["capability_digest"], include_storage=False):
                        continue
                    matches.append((executor, descriptor, digest))
        if not matches or len({m[2] for m in matches}) != 1:
            raise ResolutionUnavailable("entry has no unique live resolution descriptor; use the full path", details={"entry_id": thin["entry_id"]})
        return matches[0]

    def create_thin_task(self, body, *, identity=None, enforce_readiness=False):
        from .service import validate_idempotency_key

        body = bounded(body)
        if set(body) - {"project", "thin_request", "idempotency_key"}:
            raise ValidationError("thin request cannot supply resolved admission or worker authority")
        thin = body["thin_request"]
        if not isinstance(thin, dict) or set(thin) - {"format", "entry_id", "mode", "values", "placement", "descriptor_digest"}:
            raise ResolutionUnavailable("thin request requires unsupported resolution; use the full path")
        if thin.get("format") != FORMAT or not isinstance(thin.get("entry_id"), str) or not thin["entry_id"]:
            raise ResolutionUnavailable("thin request format or entry is unsupported")
        key = body.get("idempotency_key")
        validate_idempotency_key(key)
        project_id = self.store._project(body["project"])["id"] if body.get("project") else None
        original_hash = hashlib.sha256(canonical_json({"actor": identity.get("actor") if identity else None, "envelope": body}).encode()).hexdigest()
        # Replay precedes lookup, readiness and random/default resolution. A
        # lost create response may be recovered even after the host changes.
        found, recorded = self._command_replay_state("task.create", project_id or "unscoped", key, original_hash, with_receipt=False)
        if found:
            return recorded
        # A retired receipt cannot become permission to recreate the command.
        if self.store.conn.execute("SELECT 1 FROM runs WHERE project_id IS ? AND idempotency_key=?", (project_id, key)).fetchone():
            raise ConflictError("thin request replay identity is no longer retained; the task was not created again")
        with self.store._transaction():
            executor, descriptor, digest = self._resolution_descriptor(thin, project_id, identity)
            resolved, values = resolve(descriptor, thin)
            metadata = {"format": FORMAT, "descriptor_digest": digest,
                        "source_digest": executor["source_digest"], "source_epoch": executor["source_epoch"],
                        "settings_digest": descriptor["settings_digest"], "settings_ref": descriptor.get("settings_ref"), "placement_generation": descriptor["placement_generation"],
                        "original_hash": original_hash,
                        "original": thin, "resolved_values": values}
            result = self.create_task({**resolved, "project": project_id, "idempotency_key": key},
                                      enforce_readiness=enforce_readiness, identity=identity, _thin_admission=metadata)
            current = self.store.conn.execute("SELECT * FROM executors WHERE id=?", (executor["id"],)).fetchone()
            if not binding_matches(self.store, metadata, current) or not self.store._executor_live(current):
                raise ResolutionUnavailable("resolution descriptor changed before admission committed")
            # Change the existing receipt's request identity inside the same
            # create transaction. There is no resolution ticket or fourth write.
            self.store.conn.execute("UPDATE command_idempotency SET request_hash=? WHERE command_kind='task.create' AND aggregate_id=? AND idempotency_key=?",
                                    (original_hash, project_id or "unscoped", key))
            return result
