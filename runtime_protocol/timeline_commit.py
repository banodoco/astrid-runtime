"""Runtime's durable implementation of CONTRACT-COMMIT's acceptance boundary.

Command execution and the single rebase belong to COMMIT. They are deliberately
not implemented here. Evidence and the final result share the permanent command
ledger and the existing composition publisher's SQLite transaction.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re

from .errors import ForbiddenError, AuthorizationError, ConflictError, NotFoundError, ValidationError
from .util import canonical_json, now

KIND = "timeline.commit"
PROVIDER_INTERFACE_VERSION = 1
PROVIDER_FACTORY = "astrid.sdk.timeline.commit.create_runtime_commit_service"


class RuntimeCommitPort:
    """Request-bound capabilities for the explicitly installed semantic provider.

    Only detached JSON snapshots and scoped callables cross this boundary.
    There is no service, store, connection, or caller-selected authority field.
    """
    __slots__ = ("__lookup", "__head", "__revision", "__revision_closure", "__revisions", "__evidence", "__accept", "__selected_media")

    def __init__(self, *, lookup, head, revision, revision_closure, revisions, evidence, accept, selected_media):
        self.__lookup, self.__head, self.__revision = lookup, head, revision
        self.__revision_closure = revision_closure
        self.__revisions, self.__evidence, self.__accept = revisions, evidence, accept
        self.__selected_media = selected_media

    def lookup_request(self): return self.__lookup()
    def head(self): return self.__head()
    def revision(self, revision_id): return self.__revision(revision_id)
    def revision_closure(self, revision_id): return self.__revision_closure(revision_id)
    def revisions(self, options): return self.__revisions(options)
    def evidence(self, evidence_digest): return self.__evidence(evidence_digest)
    def selected_media(self, selection): return self.__selected_media(selection)
    def accept(self, request): return self.__accept(request)



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


def _media_selection(value, *, require_digest=False):
    fields = ("asset", "generation_id", "variant_id", "object_id")
    _object(value, (*fields, "catalog_digest") if require_digest else fields,
            () if require_digest else ("catalog_digest",))
    for field in fields:
        _string(value[field])
    for field in ("object_id", "catalog_digest"):
        if field in value:
            _string(value[field])
        if field in value and not re.fullmatch(r"sha256:[0-9a-f]{64}", value[field]):
            raise ValidationError("selected media requires canonical sha256 identities")


def _media_metadata(value):
    """Retain authoring JSON, excluding presentation state and transport hints.

    These fields are never consumed as media identity/timing. In particular a
    primary change cannot silently reselect the explicitly named variant.
    """
    excluded = {"viewed_at", "is_viewed", "viewed", "is_primary", "thumbnail",
                "local_path", "object_location", "url", "browser_url", "download_url"}
    if isinstance(value, dict):
        return {k: _media_metadata(v) for k, v in value.items() if k not in excluded}
    if isinstance(value, list):
        return [_media_metadata(v) for v in value]
    return value


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
    def _selected_project_media(self, project_id, selection):
        """Reconstruct one record from managed authority; caller owns the mutex.

        This is also called within acceptance's BEGIN IMMEDIATE, never through
        a cached catalog or a mutable primary-variant lookup. No CAS bytes or
        locations cross the semantic port.
        """
        project = self.store.get_project(project_id)
        if project["id"] != project_id or project["realm_id"] != self.realm["id"]:
            raise AuthorizationError("selected media project is outside the request realm")
        row = self.store.conn.execute(
            "SELECT g.type, g.status, g.source_task_id, g.metadata_json AS generation_metadata, "
            "v.variant_type, v.metadata_json AS variant_metadata, o.media_type, o.size, o.original_name "
            "FROM generations g JOIN generation_variants v ON v.generation_id=g.id "
            "JOIN objects o ON o.digest=v.object_id "
            "JOIN project_objects po ON po.digest=o.digest AND po.project_id=g.project_id AND po.relation='managed' "
            "WHERE g.project_id=? AND g.id=? AND v.id=? AND o.digest=?",
            (project_id, selection["generation_id"], selection["variant_id"], selection["object_id"][7:]),
        ).fetchone()
        if row is None:
            raise NotFoundError("selected media is not a managed project generation/variant/object")
        if row["status"] != "completed":
            raise ConflictError("selected media generation is not completed")
        try:
            generation_metadata = json.loads(row["generation_metadata"])
            variant_metadata = json.loads(row["variant_metadata"])
            if not isinstance(generation_metadata, dict) or not isinstance(variant_metadata, dict):
                raise ValueError("metadata must be objects")
            params = generation_metadata.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("generation params must be an object")
            entry = {"object_id": selection["object_id"], "media_type": row["media_type"],
                     "size": row["size"], "filename": row["original_name"]}
            if (not isinstance(entry["media_type"], str)
                    or not entry["media_type"].startswith(("image/", "video/", "audio/"))
                    or type(entry["size"]) is not int or entry["size"] <= 0):
                raise ValueError("invalid media format or size")
            if entry["filename"] is not None and (not isinstance(entry["filename"], str)
                    or "/" in entry["filename"] or "\\" in entry["filename"]):
                raise ValueError("media filename must not be a location")
            for metadata in (params, variant_metadata):
                for key in ("media_type", "mime_type"):
                    if metadata.get(key) is not None and metadata[key] != entry["media_type"]:
                        raise ValueError("contradictory media format metadata")
                if metadata.get("size") is not None and metadata["size"] != entry["size"]:
                    raise ValueError("contradictory media size metadata")
                for key in ("duration_seconds", "width", "height"):
                    value = metadata.get(key)
                    if value is None:
                        continue
                    if (type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                            or (key != "duration_seconds" and type(value) is not int)):
                        raise ValueError("invalid intrinsic media metadata")
                    if key in entry and entry[key] != value:
                        raise ValueError("contradictory intrinsic media metadata")
                    entry[key] = value
            record = {"realm_id": self.realm["id"], "project_id": project_id,
                      **{k: selection[k] for k in ("asset", "generation_id", "variant_id", "object_id")},
                      "generation": {"type": row["type"], "source_task_id": row["source_task_id"],
                                     "metadata": _media_metadata(generation_metadata)},
                      "variant": {"variant_type": row["variant_type"], "metadata": _media_metadata(variant_metadata)},
                      "entry": entry}
            record["catalog_digest"] = digest(record)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValidationError("invalid selected media metadata") from exc
        if "catalog_digest" in selection and selection["catalog_digest"] != record["catalog_digest"]:
            raise ConflictError("selected media catalog digest changed")
        return record

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
                "SELECT revision_id, publication_id, updated_at FROM parent_composition_heads WHERE project_id=? AND timeline_id=?",
                (project_id, timeline_id),
            ).fetchone()
            if not row or row["revision_id"] is None:
                raise NotFoundError("timeline has no committed composition head")
            if row["publication_id"] is None:
                raise NotFoundError("composition head has no publication receipt")
            return dict(row)

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
        # Keep the existing CommitRevisionSummary contract for the semantic provider.
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
                index = next((i for i, v in enumerate(values) if v["publication_id"] == options["before"]), None)
                if index is None:
                    index = next((i for i, v in enumerate(values) if v["revision_id"] == options["before"]), None)
                if index is None:
                    raise NotFoundError("revision cursor not found")
                values = values[index + 1:]
            return values[:limit]

    def accept(self, request, *, identity, _selected_media=()):
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
            self._assert_commit_authority(identity, request["project_id"])
            if self.store.conn.in_transaction:
                raise ConflictError("accept must own the durable transaction boundary")
            with self.store._transaction():
                found, saved = self._command_replay_state(KIND, aggregate, key, request["request_hash"], with_receipt=False)
                if found:
                    return self._accept_response(saved["result"], saved["previous_publication_id"], replayed=True)
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
                # Replay precedes these dependency checks. BEGIN IMMEDIATE and
                # the same head CAS fence both membership and selected metadata.
                recorded_selections = []
                for command in evidence["commands"]:
                    args = command.get("args")
                    if command.get("op") == "timeline.add" and isinstance(args, dict) and "media" in args:
                        _media_selection(args["media"], require_digest=True)
                        recorded_selections.append(args["media"])
                bound_selections = [{k: selected[k] for k in (
                    "asset", "generation_id", "variant_id", "object_id", "catalog_digest"
                )} for selected in _selected_media]
                if (any(v not in bound_selections for v in recorded_selections)
                        or any(v not in recorded_selections for v in bound_selections)):
                    raise ValidationError("selected media dependencies must match recorded command evidence")
                for selected in _selected_media:
                    current = self._selected_project_media(project_id, selected)
                    if current != selected:
                        raise ConflictError("selected media changed before acceptance")
                before = self.store.conn.execute("SELECT payload_json, content_digest FROM parent_composition_revisions WHERE id=? AND project_id=? AND timeline_id=?",
                                                 (head["revision_id"], project_id, timeline_id)).fetchone()
                if before is None:
                    raise ConflictError("composition head revision missing")
                before_payload = json.loads(before[0])
                if before["content_digest"] != self._revision_digest(before_payload):
                    raise ConflictError("composition head failed immutable verification")
                publication = copy.deepcopy(request["publication"])
                if publication is not None:
                    _object(publication, ("parent_composition", "shot_revisions", "internal_timeline_revisions"))
                candidate = before_payload if publication is None else publication["parent_composition"]
                self._require_writable_composition(before_payload, candidate)
                revision_id = publication_id = None
                if publication is not None:
                    published = self.publish_parent_composition(project_id, timeline_id, {
                        **publication, "project_id": project_id, "timeline_id": timeline_id,
                        "expected_head": head["revision_id"],
                    }, idempotency_key="accept-" + digest([aggregate, key])[7:])
                    revision_id = published["data"]["revision_id"]
                    publication_id = published["receipt"]["receipt_id"]
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
                if publication_id is not None:
                    self.store.conn.execute(
                        "UPDATE parent_composition_publications SET provenance_json=? WHERE publication_id=?",
                        (canonical_json(provenance), publication_id),
                    )
                result.update(accepted_revision_id=revision_id, accepted_publication_id=publication_id,
                              previous_revision_id=head["revision_id"], runtime_receipt=receipt,
                              provenance=provenance, evidence={"digest": evidence_digest})
                summary = None if revision_id is None else dict(
                    revision_id=revision_id, publication_id=publication_id,
                    previous_revision_id=head["revision_id"], previous_publication_id=head["publication_id"],
                    restored_from_revision_id=None, accepted_at=timestamp, source=request["source"],
                    asserted_actor=request.get("asserted_actor"), publisher=publisher,
                    label=request.get("label"), evidence_digest=evidence_digest)
                self._command_record(KIND, aggregate, key, request["request_hash"],
                                     {"result": result, "evidence": evidence, "summary": summary,
                                      "label": request.get("label"), "reason": request.get("reason"),
                                      "previous_publication_id": head["publication_id"]},
                                     project_id=project_id, with_receipt=False, created_at=timestamp)
            hook = getattr(self, "_after_timeline_commit", None)
            if hook is not None:
                hook(copy.deepcopy(result))
            return self._accept_response(result, head["publication_id"])

    @staticmethod
    def _accept_response(result, previous_publication_id, *, replayed=False):
        return dict(outcome="replayed" if replayed else result["status"],
                    revision_id=result["accepted_revision_id"], publication_id=result["accepted_publication_id"],
                    previous_revision_id=result["previous_revision_id"],
                    previous_publication_id=previous_publication_id, receipt=result["runtime_receipt"], stored_result=result)

    def register_timeline_commit_provider(self, provider):
        """Startup-only registration; A's closed launcher choice loads the factory."""
        from .contract_metadata import SCHEMA_DIGEST
        with self.store._mutex:
            if getattr(self, "_timeline_commit_provider", None) is not None or getattr(self, "_timeline_commit_started", False):
                raise ConflictError("timeline commit provider is already fixed for this service")
            if (type(getattr(provider, "interface_version", None)) is not int
                    or provider.interface_version != PROVIDER_INTERFACE_VERSION
                    or getattr(provider, "contract_digest", None) != SCHEMA_DIGEST
                    or not callable(getattr(provider, "commit", None))):
                raise ValidationError("timeline commit provider interface/contract mismatch")
            self._timeline_commit_provider = provider

    def _request_commit_port(self, request, identity):
        # Trusted code is composed in-process; scope is enforced at every call.
        original, principal = copy.deepcopy(request), {k: copy.deepcopy(v) if k != "_paired_session" else v for k, v in identity.items()}
        project, timeline, key = original["project_id"], original["timeline_id"], original["request_id"]
        request_hash = digest(original)
        selections = []
        for command in original["change"].get("commands", []):
            if command.get("op") == "timeline.add" and isinstance(command.get("args"), dict) and "media" in command["args"]:
                selection = command["args"]["media"]
                _media_selection(selection, require_digest=True)
                if selection not in selections:
                    selections.append(copy.deepcopy(selection))
        captured = {}

        def selected_media(selection):
            _media_selection(selection, require_digest=True)
            if selection not in selections:
                raise AuthorizationError("selected media is outside the captured request")
            token = digest(selection)
            with self.store._mutex:
                _publisher(principal, original.get("asserted_actor"))
                # Paired edits remain unavailable under the existing HTTP grant
                # policy; the read cannot become a bypass through a trusted port.
                if principal.get("connector_assertion") or principal.get("_paired_session"):
                    raise AuthorizationError("project grant commit operation is unavailable")
                self._assert_mutation_admitted()
                if token not in captured:
                    captured[token] = self._selected_project_media(project, selection)
                return copy.deepcopy(captured[token])

        def read(call):
            with self.store._mutex:
                return json.loads(canonical_json(call()))

        def revision_closure(revision_id):
            def verified(getter, kind, expected, *, dependency=False):
                details = {"kind": kind, **expected}
                try:
                    value = getter()
                except NotFoundError as exc:
                    if not dependency:
                        raise
                    raise ConflictError("pinned revision dependency is missing", details=details) from exc
                except (ValueError, TypeError) as exc:
                    raise ConflictError("revision payload is invalid JSON", details=details) from exc
                if (not isinstance(value, dict)
                        or any(value.get(k) != v for k, v in expected.items())):
                    raise ConflictError("revision closure identity mismatch", details=details)
                payload = value.get("payload")
                try:
                    actual_digest = self._revision_digest(payload)
                except (ValueError, TypeError) as exc:
                    raise ConflictError("revision payload is invalid JSON", details=details) from exc
                if not isinstance(payload, dict) or actual_digest != value.get("content_digest"):
                    raise ConflictError("revision closure failed digest verification", details={
                        **details, "stored_digest": value.get("content_digest"), "actual_digest": actual_digest,
                    })
                return value

            def scoped():
                parent = verified(
                    lambda: self.get_project_parent_composition_revision(project, timeline, revision_id),
                    "parent", {"project_id": project, "timeline_id": timeline, "revision_id": revision_id},
                )
                occurrences = parent["payload"].get("occurrences")
                if not isinstance(occurrences, list):
                    raise ValidationError("revision closure occurrences must be a list", details={"revision_id": revision_id})
                pins = set()
                for occurrence in occurrences:
                    if (not isinstance(occurrence, dict)
                            or any(not isinstance(occurrence.get(k), str) or not occurrence[k]
                                   for k in ("shot_id", "shot_revision_id"))):
                        raise ValidationError("revision closure occurrence has invalid shot pins", details={"revision_id": revision_id})
                    pins.add((occurrence["shot_id"], occurrence["shot_revision_id"]))
                shots, internals = [], {}
                for shot_id, shot_revision_id in sorted(pins):
                    shot = verified(
                        lambda: self.get_project_shot_revision(project, shot_id, shot_revision_id),
                        "shot", {"project_id": project, "shot_id": shot_id, "revision_id": shot_revision_id},
                        dependency=True,
                    )
                    internal_id = shot.get("internal_timeline_revision_id")
                    if (not isinstance(internal_id, str) or not internal_id
                            or shot["payload"].get("internal_timeline_revision_id") != internal_id):
                        raise ConflictError("pinned shot internal revision identity mismatch", details={"revision_id": shot_revision_id})
                    if internal_id not in internals:
                        # The shot pins a globally unique immutable revision ID.
                        # Resolve its stored timeline identity, never a mutable head.
                        row = self.store.conn.execute(
                            "SELECT timeline_id FROM internal_timeline_revisions WHERE id=? AND project_id=?",
                            (internal_id, project),
                        ).fetchone()
                        if row is None:
                            raise ConflictError("pinned internal timeline dependency is missing", details={
                                "project_id": project, "revision_id": internal_id,
                            })
                        internal_timeline = row["timeline_id"]
                        internal = verified(
                            lambda: self.get_project_timeline_revision(project, internal_timeline, internal_id),
                            "internal_timeline", {"project_id": project, "timeline_id": internal_timeline, "revision_id": internal_id},
                            dependency=True,
                        )
                        internals[internal_id] = {k: internal[k] for k in (
                            "project_id", "timeline_id", "revision_id", "content_digest", "payload",
                        )}
                    shots.append({k: shot[k] for k in (
                        "project_id", "shot_id", "revision_id", "internal_timeline_revision_id", "content_digest", "payload",
                    )})
                return {"parent_revision": parent, "shot_revisions": shots,
                        "internal_timeline_revisions": sorted(internals.values(), key=lambda v: (v["timeline_id"], v["revision_id"]))}

            return read(scoped)

        def evidence(evidence_digest):
            def scoped():
                row = self.store.conn.execute(
                    "SELECT 1 FROM command_idempotency WHERE command_kind=? AND aggregate_id=? "
                    "AND json_extract(result_json, '$.result.runtime_receipt.evidence_digest')=?",
                    (KIND, self._commit_aggregate(project, timeline), evidence_digest),
                ).fetchone()
                if row is None:
                    raise NotFoundError("evidence is outside the request timeline")
                return self.evidence(evidence_digest)
            return read(scoped)

        def accept(prepared):
            if original["dry_run"]:
                raise AuthorizationError("dry-run port cannot accept or reserve a request")
            if not isinstance(prepared, dict):
                raise ValidationError("invalid prepared acceptance")
            if (any(prepared.get(k) != original[k] for k in ("project_id", "timeline_id", "request_id", "source"))
                    or prepared.get("request_hash") != request_hash
                    or any(prepared.get(k) != original.get(k) for k in ("asserted_actor", "label", "reason"))
                    or not isinstance(prepared.get("result"), dict)
                    or prepared["result"].get("base_revision_id") != original["base_revision_id"]):
                raise AuthorizationError("prepared acceptance changed captured request authority or identity")
            # Every declared selection must have been consumed by the semantic
            # provider. Repeated reads/rebase use exactly that detached record.
            dependencies = []
            for selection in selections:
                token = digest(selection)
                if token not in captured:
                    raise ValidationError("selected media must be read before acceptance")
                dependencies.append(copy.deepcopy(captured[token]))
            return copy.deepcopy(self.accept(copy.deepcopy(prepared), identity=principal,
                                             _selected_media=dependencies))

        return RuntimeCommitPort(
            lookup=lambda: read(lambda: self.lookup_request(project, timeline, key)),
            head=lambda: read(lambda: self.head(project, timeline)),
            revision=lambda revision_id: read(lambda: self.get_project_parent_composition_revision(project, timeline, revision_id)),
            revision_closure=revision_closure,
            revisions=lambda options: read(lambda: self.revisions(project, timeline, copy.deepcopy(options))),
            evidence=evidence, accept=accept, selected_media=selected_media,
        )

    def commit_timeline(self, project_id, timeline_id, request, *, idempotency_key, identity):
        """Authenticate/replay, then call the registered Astrid algorithm once.

        D owns apply, compile, rebase and bounded StaleHead retries. No database
        mutex or transaction spans semantic execution. The scoped port alone
        supplies short reads and the authoritative atomic accept primitive.
        """
        validate_request(request)
        _publisher(identity, request.get("asserted_actor"))
        if (request["project_id"], request["timeline_id"], request["request_id"]) != (project_id, timeline_id, idempotency_key):
            raise ValidationError("commit path/header/body identities must match")
        request = copy.deepcopy(request)
        request_hash = digest(request)
        with self.store._mutex:
            self._assert_mutation_admitted()
            self._assert_commit_authority(identity, request["project_id"])
            self._timeline_commit_started = True
            if not request["dry_run"]:
                found, wrapper = self._command_replay_state(KIND, self._commit_aggregate(project_id, timeline_id),
                                                           idempotency_key, request_hash, with_receipt=False)
                if found:
                    return wrapper["result"]
            provider = getattr(self, "_timeline_commit_provider", None)
        result = result_template(request, request_hash)
        if provider is None:
            result["error"] = dict(code="runtime_unavailable", message="Astrid commit provider is not registered",
                                   hint="No semantic commit was attempted", next_action="Retry the original request after provider startup")
            return result
        port = self._request_commit_port(request, identity)
        try:
            prepared = provider.commit(copy.deepcopy(request), port)
        except (AuthorizationError, ForbiddenError):
            raise
        except (ConnectionError, TimeoutError):
            raise  # The transport may have lost an already durable response.
        except Exception:
            result["error"] = dict(code="runtime_unavailable", message="Astrid commit provider failed; outcome may be unknown",
                                   hint="Acceptance may already be durable", next_action="Retry the original request id unchanged")
            return result
        if not isinstance(prepared, dict):
            raise ValidationError("commit provider must return CommitResult")
        _object(prepared, set(result_template(request, request_hash)))
        if (prepared["request_id"] != idempotency_key or prepared["request_hash"] != request_hash
                or prepared["base_revision_id"] != request["base_revision_id"]):
            raise ValidationError("commit provider changed result identity")
        if prepared["status"] in ("accepted", "no_change"):
            if request["dry_run"]:
                raise AuthorizationError("dry-run provider returned acceptance")
            saved = self.lookup_request(project_id, timeline_id, idempotency_key)
            if saved is None or saved["result"] != prepared:
                raise ValidationError("provider reported acceptance without the stored Runtime result")
        elif (prepared["status"] not in ("preview", "conflict", "refused", "error")
              or (prepared["status"] == "preview" and not request["dry_run"])
              or any(prepared[k] is not None for k in ("accepted_revision_id", "accepted_publication_id",
                                                       "previous_revision_id", "runtime_receipt"))):
            raise ValidationError("invalid uncommitted provider result")
        return copy.deepcopy(prepared)
