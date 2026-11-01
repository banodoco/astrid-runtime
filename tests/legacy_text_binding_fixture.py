"""Unchanged main text writer methods from 29d0954b6d78a7d7937d81bc36567b6dee7ca976.

Test-only provenance: exercise the actual old writer without reopening an owner
connection or restoring the retired public route.
"""
import hashlib
import uuid

from runtime_protocol.errors import ConflictError, NotFoundError, ValidationError
from runtime_protocol.service import RuntimeService, TEXT_BINDING_MAX_BYTES, _durable_mutation, require_idempotency_key
from runtime_protocol.util import canonical_json, now, sha256_bytes


class LegacyTextWriter(RuntimeService):
    @staticmethod
    def _freeze_text(value):
        if isinstance(value, str):
            value = value.encode("utf-8")
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValidationError("text must be UTF-8 text or bytes", details={"reason": "text"})
        data = bytes(value)
        if len(data) > TEXT_BINDING_MAX_BYTES:
            raise ValidationError("text exceeds 1 MiB", details={"reason": "too_large"})
        try:
            data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValidationError("text is not valid UTF-8", details={"reason": "invalid_utf8"}) from exc
        return data, sha256_bytes(data)

    def _resolve_text_binding(self, project_id, body):
        binding_id = body.get("binding_id")
        if binding_id is not None:
            if any(body.get(key) is not None for key in ("shot_id", "shot_ref", "kind", "slot")):
                raise ValidationError("binding_id cannot be combined with friendly selectors")
            row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=? AND project_id=?", (str(binding_id), project_id)).fetchone()
            if row is None: raise NotFoundError("text binding not found")
            return row
        shot_id = body.get("shot_id") or body.get("shot_ref")
        kind = body.get("kind")
        if not shot_id or not kind: raise ValidationError("shot_id and kind are required")
        self.store.get_project(project_id)
        shot = self.store.conn.execute("SELECT id FROM project_shots WHERE id=? AND project_id=?", (shot_id, project_id)).fetchone()
        if shot is None: raise NotFoundError("shot not found")
        slot = body.get("slot")
        self._text_binding_id(project_id, shot["id"], kind, slot)
        params = [project_id, shot["id"], kind]
        query = "SELECT * FROM shot_text_bindings WHERE project_id=? AND shot_id=? AND kind=?"
        if "slot" in body:
            query += " AND slot IS ?"; params.append(slot)
        rows = self.store.conn.execute(query + " ORDER BY slot IS NOT NULL ASC, slot ASC, id ASC", tuple(params)).fetchall()
        if not rows: raise NotFoundError("text binding not found")
        if len(rows) > 1: raise ConflictError("text binding selector is ambiguous", details={"reason": "ambiguous_selector", "candidates": [str(value["id"]) for value in rows]})
        return rows[0]

    def _record_text_binding_event(self, row, event_kind, payload, *, timestamp):
        prior = self.store.conn.execute("SELECT event_hash FROM shot_text_binding_events WHERE binding_id=? ORDER BY seq DESC LIMIT 1", (row["id"],)).fetchone()
        previous_hash = str(prior[0]) if prior else ""
        seq = int(row["head_seq"]) + 1
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{row['id']}:shot.text_binding:{seq}"))
        event_hash = hashlib.sha256(canonical_json({"event_id": event_id, "binding_id": row["id"], "seq": seq, "kind": event_kind, "payload": payload, "previous_hash": previous_hash}).encode()).hexdigest()
        self.store.conn.execute("INSERT INTO shot_text_binding_events(event_id,binding_id,project_id,seq,kind,payload_json,previous_hash,event_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?)", (event_id, row["id"], row["project_id"], seq, event_kind, canonical_json(payload), previous_hash, event_hash, timestamp))
        return event_id, seq

    def _materialize_text_object(self, project_id, data, digest):
        existing = self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()
        if existing is not None:
            # CAS objects are workspace-global, while ownership is project
            # scoped.  A byte-identical object imported by another path may be
            # reused, but only after independently checking its immutable
            # bytes; then attach the project managed-local relation.
            if not str(existing["media_type"]).startswith("text/") or int(existing["size"]) > TEXT_BINDING_MAX_BYTES:
                raise ValidationError("text media candidate failed integrity", details={"reason": "media_type_not_text", "media_id": "sha256:" + digest})
            try:
                path = self.cas.path_for(digest)
                if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                    raise ValidationError("text media candidate failed integrity", details={"reason": "managed_hash_mismatch", "media_id": "sha256:" + digest})
            except OSError as exc:
                raise ValidationError("text media candidate failed integrity", details={"reason": "managed_file_missing", "media_id": "sha256:" + digest}) from exc
            relation = self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'", (project_id, digest)).fetchone()
            if relation is None:
                self.store.conn.execute("INSERT INTO project_objects(project_id,digest,relation,created_at) VALUES (?,?, 'managed', ?)", (project_id, digest, now()))
            return existing
        path = self.cas.path_for(digest)
        if not path.exists():
            self._begin_cas_publication_journal("shot-text-binding", [{"digest": digest}], project_id=project_id)
            self.cas.put(data, expected_digest=digest)
        stamp = now()
        self.store.conn.execute("INSERT INTO objects(digest,size,media_type,original_name,created_at) VALUES (?,?,?,?,?)", (digest, len(data), "text/plain", digest + ".txt", stamp))
        self.store.conn.execute("INSERT INTO project_objects(project_id,digest,relation,created_at) VALUES (?,?, 'managed', ?)", (project_id, digest, stamp))
        return self.store.conn.execute("SELECT * FROM objects WHERE digest=?", (digest,)).fetchone()

    @_durable_mutation
    def set_project_shot_text_binding(self, project_id, body, *, idempotency_key=None):
        require_idempotency_key(idempotency_key)
        self._require_object_body(body)
        project = self.store.get_project(project_id); project_id = str(project["id"])
        expected = body.get("expected_head")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0: raise ValidationError("expected_head must be a non-negative integer", details={"reason": "expected_head"})
        data, digest = self._freeze_text(body.get("text"))
        if expected == 0:
            if body.get("binding_id") is not None: raise ValidationError("head 0 requires a friendly shot selector", details={"reason": "expected_head"})
            shot_id = body.get("shot_id") or body.get("shot_ref"); kind = body.get("kind"); slot = body.get("slot")
            if not shot_id: raise ValidationError("shot_id is required")
            self._text_binding_id(project_id, shot_id, kind, slot)
            shot = self.store.conn.execute("SELECT id FROM project_shots WHERE id=? AND project_id=?", (shot_id, project_id)).fetchone()
            if shot is None: raise NotFoundError("shot not found")
            binding_id = self._text_binding_id(project_id, shot["id"], kind, slot)
            stream_id = binding_id + ":shot.text_binding"
            row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (binding_id,)).fetchone()
        else:
            row = self._resolve_text_binding(project_id, body); binding_id = str(row["id"]); stream_id = str(row["event_stream_id"])
            if int(row["head_seq"]) != expected: raise ConflictError("text binding head is stale", details={"expected_head": expected, "actual_head": int(row["head_seq"]), "binding_id": binding_id})
        facts = {"project_id": project_id, "binding_id": binding_id, "event_stream_id": stream_id, "expected_head": expected, "desired_content_hash": "sha256:" + digest}
        req_hash = hashlib.sha256(canonical_json({"command_kind": "shot.text_binding.set", **facts}).encode()).hexdigest()
        replay = self._command_replay("shot.text_binding.set", binding_id, idempotency_key, req_hash, project_id=project_id)
        if replay is not None: return replay
        if expected == 0 and row is not None:
            raise ConflictError("text binding head is stale", details={"expected_head": 0, "actual_head": int(row["head_seq"]), "binding_id": binding_id})
        if expected != 0:
            self._text_binding_resource(row)
        if expected == 0:
            desired = self._materialize_text_object(project_id, data, digest)
            stamp = now(); self.store.conn.execute("INSERT INTO shot_text_bindings(id,project_id,shot_id,kind,slot,media_digest,event_stream_id,head_seq,created_at,updated_at) VALUES (?,?,?,?,?,?,?,0,?,?)", (binding_id, project_id, shot_id, kind, slot, digest, stream_id, stamp, stamp))
            row = self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (binding_id,)).fetchone()
            event_id, seq = self._record_text_binding_event(row, "shot.text_binding.created", {"binding_id": binding_id, "media_id": "sha256:" + digest, "content_hash": "sha256:" + digest}, timestamp=stamp)
            self.store.conn.execute("UPDATE shot_text_bindings SET head_seq=1 WHERE id=?", (binding_id,))
        else:
            desired = self._materialize_text_object(project_id, data, digest) if self.store.conn.execute("SELECT 1 FROM objects WHERE digest=? AND EXISTS (SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed')", (digest, project_id, digest)).fetchone() is None else self._verify_text_object(project_id, digest, candidate=True)
            if str(row["media_digest"]) == digest:
                return {"data": self._text_binding_resource(row), "receipt": None}
            stamp = now(); event_id, seq = self._record_text_binding_event(row, "shot.text_binding.rebound", {"binding_id": binding_id, "previous_media_id": "sha256:" + str(row["media_digest"]), "media_id": "sha256:" + digest, "content_hash": "sha256:" + digest}, timestamp=stamp)
            self.store.conn.execute("UPDATE shot_text_bindings SET media_digest=?, head_seq=?, updated_at=? WHERE id=?", (digest, seq, stamp, binding_id))
        result = self._text_binding_resource(self.store.conn.execute("SELECT * FROM shot_text_bindings WHERE id=?", (binding_id,)).fetchone())
        recorded = self._command_record("shot.text_binding.set", binding_id, idempotency_key, req_hash, result, project_id=project_id, event_ids=(event_id,), primary_stream_id=stream_id, resulting_stream_seq=seq)
        return recorded
