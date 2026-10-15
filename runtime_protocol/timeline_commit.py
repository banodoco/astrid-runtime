"""Runtime's durable implementation of CONTRACT-COMMIT's acceptance boundary.

Command execution and the single rebase belong to COMMIT. They are deliberately
not implemented here. Evidence and the final result share the permanent command
ledger and the existing composition publisher's SQLite transaction.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re

from .errors import AuthorizationError, ConflictError, NotFoundError, ValidationError
from .util import canonical_json, now

KIND = "timeline.commit"


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()).hexdigest()


def _object(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValidationError("commit object has missing or unknown fields")


def _string(value):
    if not isinstance(value, str) or not value:
        raise ValidationError("commit identity must be a nonempty string")


def _source(value):
    _object(value, ("via",), ("detail",))
    if value["via"] not in ("cli", "python", "app", "script"):
        raise ValidationError("invalid commit source")
    if "detail" in value:
        _string(value["detail"])


def _publisher(identity, asserted_actor):
    if not isinstance(identity, dict) or not identity.get("actor") or not (
        {"projects:write", "admin"} & set(identity.get("scopes", []))
    ):
        raise AuthorizationError("authenticated projects:write publisher required")
    if asserted_actor is not None:
        _object(asserted_actor, ("kind", "id"))
        if asserted_actor["kind"] not in ("user", "agent", "script"):
            raise ValidationError("invalid asserted actor kind")
        _string(asserted_actor["id"])
        # No alternate actor/delegation model: attribution must name the
        # authenticated actor. Credential metadata is never caller JSON.
        if asserted_actor["id"] != identity["actor"]:
            raise AuthorizationError("asserted actor does not match authenticated publisher")
    return identity["actor"]


def validate_request(request):
    _object(request, ("api_version", "project_id", "timeline_id", "request_id", "session_id",
                      "session_sequence", "base_revision_id", "base_publication_id", "scope",
                      "change", "source", "dry_run"), ("asserted_actor", "label", "reason"))
    for name in ("project_id", "timeline_id", "request_id", "session_id", "base_revision_id"):
        _string(request[name])
    if request["api_version"] != 1 or isinstance(request["api_version"], bool):
        raise ValidationError("unsupported commit api_version")
    if type(request["dry_run"]) is not bool or type(request["session_sequence"]) is not int:
        raise ValidationError("invalid dry_run or session_sequence")
    if request["base_publication_id"] is not None:
        _string(request["base_publication_id"])
    from .service import validate_idempotency_key
    validate_idempotency_key(request["request_id"])
    scope = request["scope"]
    _object(scope, ("target", "complete", "projection_version"),
            ("content", "shot_id", "shot_revision_id", "internal_revision_id"))
    if not isinstance(scope["target"], str) or not re.fullmatch(r"parent|occurrence:.+", scope["target"]):
        raise ValidationError("invalid commit scope")
    complete = scope["complete"]
    if (not isinstance(complete, list) or any(v not in ("clips", "tracks") for v in complete)
            or len(complete) != len(set(complete)) or type(scope["projection_version"]) is not int
            or scope["projection_version"] != 1):
        raise ValidationError("invalid scope completeness or projection version")
    if scope["target"] == "parent" and set(scope) - {"target", "complete", "projection_version"}:
        raise ValidationError("parent scope cannot contain occurrence fields")
    if "content" in scope and scope["content"] not in ("this-occurrence", "shared-shot"):
        raise ValidationError("invalid occurrence content")
    for name in ("shot_id", "shot_revision_id", "internal_revision_id"):
        if name in scope:
            _string(scope[name])
    change = request["change"]
    if isinstance(change, dict) and "commands" in change:
        _object(change, ("commands",))
        if not isinstance(change["commands"], list) or any(not isinstance(v, dict) for v in change["commands"]):
            raise ValidationError("commands must be objects")
    else:
        _object(change, ("document", "adapter"))
        if change["adapter"] not in ("draft", "sheet", "external", "app-save"):
            raise ValidationError("invalid document adapter")
    _source(request["source"])
    if "asserted_actor" in request:
        _object(request["asserted_actor"], ("kind", "id"))
    for name in ("label", "reason"):
        if name in request:
            _string(request[name])
    digest(request)  # Also reject non-JSON/non-finite values before any write.


def result_template(request, request_hash):
    return dict(status="error", request_id=request["request_id"], request_hash=request_hash,
                base_revision_id=request["base_revision_id"], accepted_revision_id=None,
                accepted_publication_id=None, previous_revision_id=None, rebased_onto=None,
                canonical_document=None, projection_version=1, document_digest=None, id_map={},
                change={"changes": [], "commands": [], "direct_writes": [], "consequences": [], "affected": []}, conflicts=[], choices=[],
                provenance=None, evidence=None, schema_report=None, runtime_receipt=None, error=None)


class TimelineCommitAcceptance:
    @staticmethod
    def _commit_aggregate(project_id, timeline_id):
        return canonical_json([project_id, timeline_id])

    def lookup_request(self, project_id, timeline_id, request_id):
        from .service import validate_idempotency_key
        validate_idempotency_key(request_id)
        with self.store._mutex:
            row = self.store.conn.execute(
                "SELECT request_hash, result_json FROM command_idempotency WHERE command_kind=? "
                "AND aggregate_id=? AND idempotency_key=?",
                (KIND, self._commit_aggregate(project_id, timeline_id), request_id),
            ).fetchone()
            if row is None:
                return None
            return {"request_hash": row["request_hash"], "result": json.loads(row["result_json"])["result"]}

    def head(self, project_id, timeline_id):
        with self.store._mutex:
            row = self.store.conn.execute(
                "SELECT revision_id, updated_at FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
                (project_id, timeline_id),
            ).fetchone()
            if not row or row["revision_id"] is None:
                raise NotFoundError("timeline has no committed composition head")
            # Existing publication identity is the immutable parent revision.
            return {"revision_id": row["revision_id"], "publication_id": row["revision_id"], "updated_at": row["updated_at"]}

    def evidence(self, evidence_digest):
        if not isinstance(evidence_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_digest):
            raise ValidationError("invalid evidence digest")
        with self.store._mutex:
            rows = self.store.conn.execute(
                "SELECT result_json FROM command_idempotency WHERE command_kind=? "
                "AND json_extract(result_json, '$.result.runtime_receipt.evidence_digest')=?",
                (KIND, evidence_digest),
            ).fetchall()
            if not rows:
                raise NotFoundError("commit evidence not found")
            value = json.loads(rows[0]["result_json"])["evidence"]
            if digest(value) != evidence_digest:
                raise ConflictError("commit evidence failed digest verification")
            return value

    def revisions(self, project_id, timeline_id, options):
        # Acceptance facts only; HISTORY owns ancestry, restore and list wire behavior.
        with self.store._mutex:
            rows = self.store.conn.execute(
                "SELECT result_json FROM command_idempotency WHERE command_kind=? AND aggregate_id=? ORDER BY rowid DESC",
                (KIND, self._commit_aggregate(project_id, timeline_id)),
            ).fetchall()
            values = [json.loads(row[0])["summary"] for row in rows]
            _object(options, (), ("limit", "before"))
            limit = options.get("limit", 50)
            if type(limit) is not int or limit < 1:
                raise ValidationError("revision limit must be a positive integer")
            values = [v for v in values if v is not None]
            if "before" in options:
                _string(options["before"])
                index = next((i for i, v in enumerate(values) if v["revision_id"] == options["before"]), None)
                if index is None:
                    raise NotFoundError("revision cursor not found")
                values = values[index + 1:]
            return values[:limit]

    def accept(self, request, *, identity):
        """Accept an internal COMMIT result. No HTTP caller can supply this template.

        A single outer transaction includes nested existing publication, evidence,
        final result and request identity. The hook runs only after durable COMMIT.
        """
        from .service import require_idempotency_key
        _object(request, ("project_id", "timeline_id", "request_id", "request_hash", "expected_head_revision_id",
                          "publication", "result", "evidence", "source"),
                ("asserted_actor", "label", "reason", "narration"))
        if "asserted_actor" in request:
            _object(request["asserted_actor"], ("kind", "id"))
        publisher = _publisher(identity, request.get("asserted_actor"))
        _source(request["source"])
        for key in ("project_id", "timeline_id", "expected_head_revision_id"):
            _string(request[key])
        key = require_idempotency_key(request["request_id"])
        if not isinstance(request["request_hash"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", request["request_hash"]):
            raise ValidationError("invalid commit request hash")
        for name in ("label", "reason"):
            if name in request:
                _string(request[name])
        result = copy.deepcopy(request["result"])
        required_result = set(result_template({"request_id": key, "base_revision_id": "base"}, request["request_hash"]))
        _object(result, required_result)
        if (not isinstance(result, dict) or result.get("request_id") != key
                or result.get("request_hash") != request["request_hash"]
                or result.get("status") != ("no_change" if request["publication"] is None else "accepted")
                or any(result.get(k) is not None for k in ("accepted_revision_id", "accepted_publication_id",
                                                           "previous_revision_id", "runtime_receipt", "provenance"))):
            raise ValidationError("acceptance requires an unfilled result matching request identity")
        if (result["error"] is not None or result["schema_report"] is not None
                or type(result["projection_version"]) is not int or result["projection_version"] != 1):
            raise ValidationError("invalid pre-accept result fields")
        _string(result["base_revision_id"])
        _object(result["change"], ("changes", "commands", "direct_writes", "consequences", "affected"))
        if any(not isinstance(v, list) for v in result["change"].values()):
            raise ValidationError("invalid pre-accept changes")
        if (not isinstance(result["id_map"], dict) or any(not isinstance(v, str) or not v for v in result["id_map"].values())
                or not isinstance(result["conflicts"], list) or not isinstance(result["choices"], list)):
            raise ValidationError("invalid pre-accept result containers")
        evidence = copy.deepcopy(request["evidence"])
        _object(evidence, ("commands", "direct_writes", "digests", "toolchain"))
        _object(evidence["digests"], ("before", "after"))
        _object(evidence["toolchain"], ("astrid_sha", "compiler_version"))
        for name in ("commands", "direct_writes"):
            if not isinstance(evidence[name], list) or any(not isinstance(v, dict) for v in evidence[name]):
                raise ValidationError("invalid commit evidence")
        for v in (*evidence["digests"].values(), *evidence["toolchain"].values()):
            _string(v)
        evidence_digest = digest(evidence)
        aggregate = self._commit_aggregate(request["project_id"], request["timeline_id"])
        with self.store._mutex:
            self._assert_mutation_admitted()
            if self.store.conn.in_transaction:
                raise ConflictError("accept must own the durable transaction boundary")
            with self.store._transaction():
                found, saved = self._command_replay_state(KIND, aggregate, key, request["request_hash"], with_receipt=False)
                if found:
                    return self._accept_response(saved["result"], replayed=True)
                project_id, timeline_id = request["project_id"], request["timeline_id"]
                self.store.get_project(project_id)
                head = self.head(project_id, timeline_id)
                if self.store.conn.execute(
                    "SELECT 1 FROM parent_composition_revisions WHERE id=? AND project_id=? AND timeline_id=?",
                    (result["base_revision_id"], project_id, timeline_id),
                ).fetchone() is None:
                    raise NotFoundError("commit base revision not found")
                if head["revision_id"] != request["expected_head_revision_id"]:
                    raise ConflictError("StaleHead", details={"code": "StaleHead", "current_head_revision_id": head["revision_id"]})
                before = self.store.conn.execute("SELECT payload_json, content_digest FROM parent_composition_revisions WHERE id=? AND project_id=? AND timeline_id=?",
                                                 (head["revision_id"], project_id, timeline_id)).fetchone()
                if before is None:
                    raise ConflictError("composition head revision missing")
                before_payload = json.loads(before[0])
                if before["content_digest"] != self._revision_digest(before_payload):
                    raise ConflictError("composition head failed immutable verification")
                publication = request["publication"]
                revision_id = None
                if publication is not None:
                    _object(publication, ("parent_composition", "shot_revisions", "internal_timeline_revisions"))
                    published = self.publish_parent_composition(project_id, timeline_id, {
                        **publication, "project_id": project_id, "timeline_id": timeline_id,
                        "expected_head": head["revision_id"],
                    }, idempotency_key="accept-" + digest([aggregate, key])[7:])
                    revision_id = published["data"]["revision_id"]
                # Semantic document projection/digests belong to COMMIT, not
                # to the storage envelope's immutable content_digest. The two
                # representations need not be equal. Keep its exact document.
                if (not isinstance(result["document_digest"], str)
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", result["document_digest"])
                        or evidence["digests"]["after"] != result["document_digest"]):
                    raise ValidationError("result/evidence document digests do not match")
                # Timeline narration (audio + word timings) has no integrated
                # binding producer. shot_text_bindings is a different record.
                if "narration" in request:
                    raise ValidationError("timeline narration binding producer is not integrated")
                timestamp = now()
                receipt = {"publisher": publisher, "accepted_at": timestamp,
                           "evidence_digest": evidence_digest, "narration_state": None}
                provenance = {"publisher": publisher, "source": request["source"]}
                if "asserted_actor" in request:
                    receipt["asserted_actor"] = request["asserted_actor"]
                    provenance["asserted_actor"] = request["asserted_actor"]
                result.update(accepted_revision_id=revision_id, accepted_publication_id=revision_id,
                              previous_revision_id=head["revision_id"], runtime_receipt=receipt,
                              provenance=provenance, evidence={"digest": evidence_digest})
                summary = None if revision_id is None else dict(
                    revision_id=revision_id, publication_id=revision_id,
                    previous_revision_id=head["revision_id"], previous_publication_id=head["publication_id"],
                    restored_from_revision_id=None, accepted_at=timestamp, source=request["source"],
                    asserted_actor=request.get("asserted_actor"), publisher=publisher,
                    label=request.get("label"), evidence_digest=evidence_digest)
                self._command_record(KIND, aggregate, key, request["request_hash"],
                                     {"result": result, "evidence": evidence, "summary": summary,
                                      "label": request.get("label"), "reason": request.get("reason")},
                                     project_id=project_id, with_receipt=False, created_at=timestamp)
            hook = getattr(self, "_after_timeline_commit", None)
            if hook is not None:
                hook(copy.deepcopy(result))
            return self._accept_response(result)

    @staticmethod
    def _accept_response(result, *, replayed=False):
        return dict(outcome="replayed" if replayed else result["status"],
                    revision_id=result["accepted_revision_id"], publication_id=result["accepted_publication_id"],
                    previous_revision_id=result["previous_revision_id"],
                    previous_publication_id=result["previous_revision_id"], receipt=result["runtime_receipt"], stored_result=result)

    def commit_timeline(self, project_id, timeline_id, request, *, idempotency_key, identity):
        """Single public route; shared COMMIT preparation is a required producer.

        COMMIT supplies prepare_timeline_commit(request, head), returning either
        one AcceptRequest or an uncommitted preview/conflict/refused CommitResult.
        It must be read-only and perform the one shared rebase. No fallback writer.
        """
        validate_request(request)
        _publisher(identity, request.get("asserted_actor"))
        if (request["project_id"], request["timeline_id"], request["request_id"]) != (project_id, timeline_id, idempotency_key):
            raise ValidationError("commit path/header/body identities must match")
        request_hash = digest(request)
        with self.store._mutex:
            self._assert_mutation_admitted()
            if not request["dry_run"]:
                saved = self.lookup_request(project_id, timeline_id, idempotency_key)
                if saved is not None:
                    # Reuse the same ledger conflict and replay path before head.
                    _, wrapper = self._command_replay_state(KIND, self._commit_aggregate(project_id, timeline_id),
                                                            idempotency_key, request_hash, with_receipt=False)
                    return wrapper["result"]
            result = result_template(request, request_hash)
            prepare = getattr(self, "prepare_timeline_commit", None)
            if prepare is None:
                result["error"] = dict(code="runtime_unavailable", message="Shared COMMIT producer is not integrated",
                                       hint="No rebase or publication was attempted", next_action="Retry the original request after COMMIT integration")
                return result
            head = self.head(project_id, timeline_id)
            # A savepoint is always rolled back, even if a faulty producer wrote.
            # accept below owns the only durable transaction; dry runs reserve nothing.
            self.store.conn.execute("SAVEPOINT timeline_commit_prepare")
            try:
                prepared = prepare(copy.deepcopy(request), copy.deepcopy(head))
            finally:
                self.store.conn.execute("ROLLBACK TO timeline_commit_prepare")
                self.store.conn.execute("RELEASE timeline_commit_prepare")
            if not isinstance(prepared, dict):
                raise ValidationError("COMMIT preparation must return an object")
            if "result" not in prepared:
                _object(prepared, set(result_template(request, request_hash)))
                if (any(prepared[k] is not None for k in ("accepted_revision_id", "accepted_publication_id",
                                                           "previous_revision_id", "runtime_receipt"))
                        or prepared.get("base_revision_id") != request["base_revision_id"]
                        or prepared.get("status") not in ("preview", "conflict", "refused", "error")
                        or prepared.get("request_hash") != request_hash or prepared.get("request_id") != idempotency_key
                        or (prepared.get("status") == "preview" and not request["dry_run"])):
                    raise ValidationError("invalid uncommitted COMMIT result")
                return prepared
            if request["dry_run"]:
                raise ValidationError("dry run must return an uncommitted preview or conflict")
            if any(prepared.get(k) != request[k] for k in ("project_id", "timeline_id", "request_id", "source")) or prepared.get("request_hash") != request_hash:
                raise ValidationError("COMMIT preparation changed request identity")
            if (prepared.get("expected_head_revision_id") != head["revision_id"]
                    or not isinstance(prepared.get("result"), dict)
                    or prepared["result"].get("base_revision_id") != request["base_revision_id"]):
                raise ValidationError("COMMIT preparation changed base or prepared head")
            if prepared.get("asserted_actor") != request.get("asserted_actor"):
                raise ValidationError("COMMIT preparation changed asserted actor")
            return self.accept(prepared, identity=identity)["stored_result"]
