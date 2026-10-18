"""Runtime's durable implementation of CONTRACT-COMMIT's acceptance boundary.

Command execution and the single rebase belong to COMMIT. They are deliberately
not implemented here. Evidence and the final result share the permanent command
ledger and the existing composition publisher's SQLite transaction.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import re

from .narration import (narration_lines, narration_projection, request_take_refs,
                        validate_take_refs, validate_artifacts, validate_line_take,
                        NarrationTakeRefs, VerifiedNarrationTake)
from .errors import (ForbiddenError, AuthorizationError, ConflictError, NotFoundError, ValidationError,
                     CapabilityUnavailableError)
from .util import canonical_json, now, MANAGED_OUTPUT_ASSOCIATION_KEY

KIND = "timeline.commit"
PROVIDER_INTERFACE_VERSION = 1
PROVIDER_FACTORY = "astrid.sdk.timeline.commit.create_runtime_commit_service"
_LOGGER = logging.getLogger(__name__)


def _record_commit_failure(stage, exc):
    """Best-effort internal diagnosis, containing only fixed vocabulary.

    Never inspect exception text, args, custom class names or instance codes.
    Exact class identity prevents subclasses from supplying diagnostic data.
    Logging failure must not change the existing uncertain public response.
    """
    try:
        exception_class, error_code = "OtherException", None
        for cls, label, code in (
            (ConflictError, "ConflictError", "conflict"),
            (NotFoundError, "NotFoundError", "not_found"),
            (ValidationError, "ValidationError", "validation_error"),
            (CapabilityUnavailableError, "CapabilityUnavailableError", "unavailable"),
            (KeyError, "KeyError", None),
            (TypeError, "TypeError", None),
            (ValueError, "ValueError", None),
            (AttributeError, "AttributeError", None),
            (RuntimeError, "RuntimeError", None),
            (OSError, "OSError", None),
            (FileNotFoundError, "FileNotFoundError", None),
            (PermissionError, "PermissionError", None),
            (ImportError, "ImportError", None),
            (ModuleNotFoundError, "ModuleNotFoundError", None),
        ):
            if type(exc) is cls:
                exception_class, error_code = label, code
                break
        if type(stage) is not str or stage not in ("provider_commit", "preview_scene_validation"):
            stage = "unknown"
        diagnostic = dict(stage=stage, exception_class=exception_class)
        if error_code is not None:
            diagnostic["error_code"] = error_code
        _LOGGER.error("timeline_commit_failure %s", canonical_json(diagnostic))
    except Exception:
        pass  # Diagnosis cannot replace the original failure/uncertainty result.


def validate_timeline_commit_provider(provider):
    """Validate before realm admission as well as at startup-only registration."""
    from .contract_metadata import SCHEMA_DIGEST
    if (type(getattr(provider, "interface_version", None)) is not int
            or provider.interface_version != PROVIDER_INTERFACE_VERSION
            or getattr(provider, "contract_digest", None) != SCHEMA_DIGEST
            or not callable(getattr(provider, "commit", None))
            or (getattr(provider, "provider_id", None) == "astrid-v1"
                and getattr(provider, "requires_scene_evaluation", None) is not True)):
        raise ValidationError("timeline commit provider interface/contract mismatch")


class RuntimeCommitPort:
    """Request-bound capabilities for the explicitly installed semantic provider.

    Detached snapshots, internal immutable captures and scoped callables cross
    this boundary.
    There is no service, store, connection, or caller-selected authority field.
    """
    __slots__ = ("__lookup", "__head", "__revision", "__revision_closure", "__revisions", "__evidence", "__accept", "__selected_media", "__narration_take", "__transcript_source", "__scene_evaluator", "__close", "__validate_scene")

    def __init__(self, *, lookup, head, revision, revision_closure, revisions, evidence, accept, selected_media, narration_take, transcript_source, scene_evaluator=None, close=lambda: None, validate_scene=None):
        self.__lookup, self.__head, self.__revision = lookup, head, revision
        self.__revision_closure = revision_closure
        self.__revisions, self.__evidence, self.__accept = revisions, evidence, accept
        self.__selected_media = selected_media
        self.__narration_take = narration_take
        self.__transcript_source = transcript_source
        self.__scene_evaluator, self.__close = scene_evaluator, close
        self.__validate_scene = validate_scene

    def lookup_request(self): return self.__lookup()
    def head(self): return self.__head()
    def revision(self, revision_id): return self.__revision(revision_id)
    def revision_closure(self, revision_id): return self.__revision_closure(revision_id)
    def revisions(self, options): return self.__revisions(options)
    def evidence(self, evidence_digest): return self.__evidence(evidence_digest)
    def selected_media(self, selection): return self.__selected_media(selection)
    def narration_take(self, refs: NarrationTakeRefs) -> VerifiedNarrationTake:
        return self.__narration_take(refs)
    def resolve_transcript_source(self, request, selection):
        return self.__transcript_source(request, selection)
    def scene_evaluator(self, candidate):
        if self.__scene_evaluator is None:
            raise AuthorizationError("authoring scene owner is unavailable")
        return self.__scene_evaluator(candidate)
    def validate_scene(self, candidate):
        if self.__validate_scene is None:
            raise AuthorizationError("missing scene validation")
        self.__validate_scene({"result": {"canonical_document": candidate}})
    def close(self): self.__close()
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


def _command_leaves(values):
    # Discovery grants no authority to malformed opaque batch args. The
    # semantic runner retains responsibility for their ordinary typed refusal.
    if not isinstance(values, list):
        return
    for command in values:
        if not isinstance(command, dict) or not isinstance(command.get("args"), dict):
            continue
        if command.get("op") == "timeline.batch":
            yield from _command_leaves(command.get("args", {}).get("commands", []))
        else:
            yield command


def _restore_selection(request):
    commands = request["change"].get("commands", [])
    if not any(c.get("op") == "timeline.restore" for c in _command_leaves(commands)):
        return None
    if len(commands) != 1 or commands[0].get("op") != "timeline.restore":
        raise ValidationError("timeline.restore must be the sole command")
    command = commands[0]
    _object(command, ("op", "args"), ("select", "version", "resolved", "expect", "bindings", "created", "authorship"))
    if (command.get("select") is not None or command.get("resolved", []) != []
            or any(command.get(k) is not None for k in ("expect", "bindings", "created", "authorship"))
            or request["scope"] != dict(target="parent", complete=["clips", "tracks"], projection_version=1)):
        raise ValidationError("restore requires an unambiguous complete parent image")
    args = command["args"]
    _object(args, ("revision_id", "content_digest"), ("publication_id",))
    _string(args["revision_id"])
    if not isinstance(args["content_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", args["content_digest"]):
        raise ValidationError("restore requires an exact content digest")
    if args.get("publication_id") is not None:
        _string(args["publication_id"])
    return copy.deepcopy(args)


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
    def get_project_media_selection(self, project_id, *, asset=None, generation_id=None, variant_id=None,
                                    association_id=None, object_id=None, version=None):
        """Read the five-field selection using the commit authority projection.

        HTTP authentication and paired project binding are supplied by the
        existing projects:read route. Caller output identity is checked exactly.
        """
        if not isinstance(project_id, str) or not project_id.strip():
            raise ValidationError("media selection project must be a nonempty string")
        legacy = (asset, generation_id, variant_id)
        output = (association_id, object_id, version)
        with self.store._mutex:
            if all(v is not None for v in output) and all(v is None for v in legacy):
                if (not isinstance(association_id, str) or not association_id.strip()
                        or not isinstance(object_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", object_id)
                        or type(version) is not int or version < 1):
                    raise ValidationError("output selection requires exact association, object and positive version")
                association, variant = self._output_selection_binding(project_id, association_id)
                if association["object_id"] != object_id or association["lifecycle"]["version"] != version:
                    raise ConflictError("captured output object or version changed")
                selection = dict(asset=variant["id"], generation_id=variant["generation_id"],
                                 variant_id=variant["id"], object_id=object_id)
            elif all(isinstance(v, str) and v.strip() for v in legacy) and all(v is None for v in output):
                selection = dict(asset=asset, generation_id=generation_id, variant_id=variant_id)
            else:
                raise ValidationError("exactly one complete media selection selector form is required")
            record = self._selected_project_media(project_id, selection)
            return {key: record[key] for key in (
                "asset", "generation_id", "variant_id", "object_id", "catalog_digest",
            )}

    def _output_selection_binding(self, project_id, association_id):
        """Resolve an exact Runtime-authored binding without reading bytes or writing."""
        if not isinstance(association_id, str) or not association_id.strip():
            raise ValidationError("invalid Runtime output association binding")
        association = self.store.get_managed_output(association_id)
        if association["project_id"] != project_id:
            raise NotFoundError("output association is outside the selected project")
        if (association["durability"] != "durable"
                or association["role"] in {"thumbnail", "manifest", "recoverable_snapshot"}
                or association["lifecycle"]["state"] not in {"available", "promoted"}):
            raise ConflictError("selected output is not an eligible durable creative output")
        variants = self.store.conn.execute(
            "SELECT v.id, v.generation_id, v.object_id, g.project_id FROM generation_variants v "
            "JOIN generations g ON g.id=v.generation_id WHERE "
            "CASE WHEN json_valid(v.metadata_json) THEN json_extract(v.metadata_json, ?) END=?",
            ("$." + MANAGED_OUTPUT_ASSOCIATION_KEY, association_id),
        ).fetchall()
        if not variants:
            raise NotFoundError("output has no authoritative registered variant")
        if len(variants) != 1:
            raise ConflictError("output has ambiguous registered variants")
        variant = variants[0]
        if (variant["project_id"] != project_id or variant["generation_id"] != association["generation_id"]
                or "sha256:" + str(variant["object_id"]) != association["object_id"]):
            raise ConflictError("output association and registered variant identity changed")
        task = self.store.conn.execute("SELECT r.project_id, t.status, t.result_json, t.attempt_id, t.capability FROM tasks t "
                                       "JOIN runs r ON r.id=t.run_id WHERE t.id=?",
                                       (association["task_id"],)).fetchone()
        attempt = self.store.conn.execute("SELECT task_id, settled, executor_id, fence, runtime_epoch, lease_id FROM attempts WHERE id=?",
                                          (association["attempt_id"],)).fetchone()
        try:
            outputs = json.loads(task["result_json"] or "{}").get("outputs", []) if task else []
            matches = [v for v in outputs if isinstance(v, dict)
                       and self.store._generation_publish_output_key(v) == (
                           association["output_port"], association["group_key"],
                           association["variant_key"], association["ordinal"])]
            valid = (len(matches) == 1 and matches[0].get("kind") == "object"
                     and matches[0].get("digest") == association["object_id"]
                     and matches[0].get("size") == association["size"]
                     and matches[0].get("media_type") == association["media_type"]
                     and matches[0].get("role", "output") == association["role"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise ConflictError("selected output settlement identity is malformed") from exc
        if (not task or task["project_id"] != project_id or task["status"] != "completed"
                or not attempt or attempt["task_id"] != association["task_id"] or not attempt["settled"] or not valid):
            raise ConflictError("selected output is not an exact completed settlement")
        provenance = association["provenance"]
        if (task["attempt_id"] != association["attempt_id"] or not attempt["lease_id"]
                or not isinstance(provenance, dict) or any(provenance.get(key) != expected for key, expected in (
                    ("task_id", association["task_id"]), ("attempt_id", association["attempt_id"]),
                    ("capability_id", task["capability"]), ("executor_id", attempt["executor_id"]),
                    ("fence", attempt["fence"]), ("runtime_epoch", attempt["runtime_epoch"]),
                ))):
            raise ConflictError("selected output historical attempt identity changed")
        return association, variant

    def _selected_project_media(self, project_id, selection, _copy_chain=()):
        """Reconstruct one record from managed authority; caller owns the mutex.

        This is also called within acceptance's BEGIN IMMEDIATE, never through
        a cached catalog or a mutable primary-variant lookup. No CAS bytes or
        locations cross the semantic port.
        """
        project = self.store.get_project(project_id)
        if project["id"] != project_id or project["realm_id"] != self.realm["id"]:
            raise AuthorizationError("selected media project is outside the request realm")
        identity = (selection["generation_id"], selection["variant_id"])
        if identity in _copy_chain:
            raise ConflictError("invalid metadata copy lineage")
        row = self.store.conn.execute(
            "SELECT g.type, g.status, g.source_task_id, g.metadata_json AS generation_metadata, "
            "v.variant_type, v.metadata_json AS variant_metadata, o.digest AS object_digest, o.media_type, o.size, o.original_name "
            "FROM generations g JOIN generation_variants v ON v.generation_id=g.id "
            "JOIN objects o ON o.digest=v.object_id "
            "JOIN project_objects po ON po.digest=o.digest AND po.project_id=g.project_id AND po.relation='managed' "
            "WHERE g.project_id=? AND g.id=? AND v.id=? AND (? IS NULL OR o.digest=?)",
            (project_id, selection["generation_id"], selection["variant_id"],
             selection.get("object_id"), selection.get("object_id", "")[7:]),
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
            object_id = "sha256:" + row["object_digest"]
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", object_id):
                raise ValueError("invalid managed object identity")
            entry = {"object_id": object_id, "media_type": row["media_type"],
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
                      **{k: selection[k] for k in ("asset", "generation_id", "variant_id")},
                      "object_id": object_id,
                      "generation": {"type": row["type"], "source_task_id": row["source_task_id"],
                                     "metadata": _media_metadata(generation_metadata)},
                      "variant": {"variant_type": row["variant_type"], "metadata": _media_metadata(variant_metadata)},
                      "entry": entry}
            lineage = generation_metadata.get("runtime_metadata_copy")
            if "runtime_metadata_copy" in generation_metadata or "runtime_metadata_copy" in variant_metadata:
                if (not isinstance(lineage, dict) or set(lineage) != {"realm_id", "project_id", "source"}
                        or lineage != variant_metadata.get("runtime_metadata_copy")
                        or lineage["realm_id"] != self.realm["id"] or lineage["project_id"] != project_id
                        or row["source_task_id"] is not None or MANAGED_OUTPUT_ASSOCIATION_KEY in variant_metadata):
                    raise ConflictError("metadata copy lineage binding changed")
                _media_selection(lineage["source"], require_digest=True)
                original = self._selected_project_media(project_id, lineage["source"], (*_copy_chain, identity))
                if (original["object_id"] != object_id or original["entry"] != entry
                        or original["generation"]["type"] != row["type"]
                        or original["variant"]["variant_type"] != row["variant_type"]):
                    raise ConflictError("metadata copy source identity changed")
                record["variant"]["copy_source"] = original
            if MANAGED_OUTPUT_ASSOCIATION_KEY in variant_metadata:
                association, variant = self._output_selection_binding(
                    project_id, variant_metadata[MANAGED_OUTPUT_ASSOCIATION_KEY])
                if (variant["id"] != selection["variant_id"]
                        or association["size"] != entry["size"] or association["media_type"] != entry["media_type"]):
                    raise ConflictError("selected media output identity changed")
                if entry["media_type"].startswith("video/") and "duration_seconds" not in entry:
                    raise ValueError("selected video output requires intrinsic duration")
                # Include the captured lifecycle version in the existing digest.
                # A later read/retry never silently advances this capture.
                record["variant"]["managed_output"] = {k: association[k] for k in (
                    "association_id", "task_id", "attempt_id", "project_id", "generation_id",
                    "object_id", "output_port", "group_key", "variant_key", "ordinal", "role",
                    "size", "media_type", "filename", "durability", "lifecycle", "provenance",
                )}
            record["catalog_digest"] = digest(record)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValidationError("invalid selected media metadata") from exc
        if "catalog_digest" in selection and selection["catalog_digest"] != record["catalog_digest"]:
            raise ConflictError("selected media catalog digest changed")
        return record

    def _managed_narration_take(self, project_id, refs):
        """Verify one settled take; called under the request mutex/accept fence."""
        validate_take_refs(refs)
        project = self.store.get_project(project_id)
        if project["realm_id"] != self.realm["id"]:
            raise AuthorizationError("narration project is outside the request realm")
        associations, documents, dependencies = [], {}, set()
        for port, ref in refs.items():
            # Check project before reading any auxiliary bytes, even internally.
            selected = self.store.get_managed_output(ref["association_id"])
            if selected["project_id"] != project_id:
                raise AuthorizationError("narration output is outside the request project")
            if not self.store.conn.execute(
                "SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
                (project_id, ref["object_id"][7:]),
            ).fetchone():
                raise ConflictError("narration output has no managed project ownership")
            association, _, data, _ = self._export_source(ref["association_id"])
            if (association["project_id"] != project_id or association["object_id"] != ref["object_id"]
                    or association["output_port"] != port or association["role"] == "recoverable_snapshot"
                    or association["lifecycle"]["state"] not in {"available", "promoted"}):
                raise ConflictError("narration managed output identity/project/lifecycle mismatch")
            task = self.store.conn.execute("SELECT status, result_json FROM tasks WHERE id=?",
                                           (association["task_id"],)).fetchone()
            outputs = json.loads(task["result_json"] or "{}").get("outputs", []) if task else []
            if (task is None or task["status"] != "completed"
                    or not any(v.get("digest") == ref["object_id"]
                               and v.get("output_port", v.get("name")) == port
                               and v.get("size") == association["size"]
                               and v.get("media_type") == association["media_type"] for v in outputs)):
                raise ConflictError("narration output is not a settled task result")
            if "sha256:" + hashlib.sha256(data).hexdigest() != ref["object_id"]:
                raise ConflictError("narration dependency bytes changed")
            self._validate_media_dependencies(project_id, {"media": [ref["object_id"]]})
            dependencies.add(ref["object_id"])
            if association.get("manifest_ref"):
                manifest_ref = association["manifest_ref"]
                self._validate_media_dependencies(project_id, {"media": [manifest_ref]})
                dependencies.add(manifest_ref)
            if port == "speech":
                if not association["media_type"].startswith("audio/"):
                    raise ValidationError("narration speech output must be audio")
                speech = {k: association[k] for k in ("object_id", "size", "media_type")}
            else:
                if association["media_type"] != "application/json":
                    raise ValidationError("narration auxiliary output must be JSON")
                try:
                    documents[port] = json.loads(data)
                except (ValueError, UnicodeError) as exc:
                    raise ValidationError("invalid narration artifact JSON") from exc
            associations.append(association)
        if len({(v["task_id"], v["attempt_id"]) for v in associations}) != 1:
            raise ValidationError("narration refs must identify one settled task attempt")
        manifest, words = documents["speech_manifest"], documents["speech_words"]
        validate_artifacts(refs, manifest, words)
        speech["duration_seconds"] = manifest["duration_seconds"]
        return {"refs": copy.deepcopy(refs), "speech": speech, "manifest": manifest, "words": words,
                "dependency_objects": sorted(dependencies),
                "dependency_digest": digest(sorted(associations, key=lambda v: v["output_port"]))}

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

    def accept(self, request, *, identity, _selected_media=(), _narration_takes=(), _revision_closures=(), _restore_capture=None, _transcript_check=None, _scene_check=None):
        """Accept an internal COMMIT result. No HTTP caller can supply this template.

        A single outer transaction includes nested existing publication, evidence,
        final result and request identity. The hook runs only after durable COMMIT.
        """
        from .service import require_idempotency_key
        _object(request, ("project_id", "timeline_id", "request_id", "request_hash", "expected_head_revision_id",
                          "publication", "result", "evidence", "source"),
                ("asserted_actor", "label", "reason", "narration", "restore"))
        if ("restore" in request) != (_restore_capture is not None):
            raise ValidationError("restore requires the request-bound historical capture")
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
        _object(result, required_result, ("shot_groups",))
        if (not isinstance(result, dict) or result.get("request_id") != key
                or result.get("request_hash") != request["request_hash"]
                or result.get("status") != ("no_change" if request["publication"] is None else "accepted")
                or any(result.get(k) is not None for k in ("accepted_revision_id", "accepted_publication_id",
                                                           "previous_revision_id", "runtime_receipt", "provenance"))):
            raise ValidationError("acceptance requires an unfilled result matching request identity")
        if (result["error"] is not None or result["schema_report"] is not None
                or type(result["projection_version"]) is not int or result["projection_version"] != 1):
            raise ValidationError("invalid pre-accept result fields")
        if "shot_groups" in result:
            if not isinstance(result["shot_groups"], list):
                raise ValidationError("shot_groups result must be an array")
            for group_result in result["shot_groups"]:
                _object(group_result, ("operation_index", "group", "created", "reused", "restored"))
                if type(group_result["operation_index"]) is not int or group_result["operation_index"] < 0:
                    raise ValidationError("invalid group result operation index")
                if group_result["group"] is not None:
                    _object(group_result["group"], ("shotId", "trackId"))
                    for value in group_result["group"].values():
                        _string(value)
                for field in ("created", "reused", "restored"):
                    if not isinstance(group_result[field], list) or any(not isinstance(v, str) or not re.fullmatch(r"(?:parent|occurrence:[^/]+)/clip:[^/]+", v) for v in group_result[field]):
                        raise ValidationError("invalid group result clip identities")
        _string(result["base_revision_id"])
        _object(result["change"], ("changes", "commands", "direct_writes", "consequences", "affected"))
        if any(not isinstance(v, list) for v in result["change"].values()):
            raise ValidationError("invalid pre-accept changes")
        if (not isinstance(result["id_map"], dict) or any(not isinstance(v, str) or not v for v in result["id_map"].values())
                or not isinstance(result["conflicts"], list) or not isinstance(result["choices"], list)):
            raise ValidationError("invalid pre-accept result containers")
        evidence = copy.deepcopy(request["evidence"])
        _object(evidence, ("commands", "direct_writes", "digests", "toolchain"), ("transcripts",))
        if evidence.get("transcripts") and _transcript_check is None:
            raise ValidationError("transcript dependencies require the request-bound capture port")
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
                restore = request.get("restore")
                if restore is not None:
                    if (request["expected_head_revision_id"] != result["base_revision_id"]
                            or (restore["expected_publication_id"] is not None
                                and head["publication_id"] != restore["expected_publication_id"])):
                        raise ConflictError("StaleHead: captured restore publication changed")
                    fresh = self._commit_restore_capture(project_id, timeline_id, restore)
                    if digest(fresh) != digest(_restore_capture):
                        raise ConflictError("historical restore closure changed before acceptance")
                    if digest(request["publication"]) != digest(fresh["publication"]):
                        raise ValidationError("restore publication differs from captured historical image")
                # Replay precedes these dependency checks. BEGIN IMMEDIATE and
                # the same head CAS fence both membership and selected metadata.
                for selection, captured_closure in _revision_closures:
                    if self._commit_revision_closure(project_id, timeline_id, selection) != captured_closure:
                        raise ConflictError("immutable revision dependency changed before acceptance")
                if _transcript_check is not None:
                    _transcript_check(evidence.get("transcripts", {}))
                recorded_selections = []
                for command in _command_leaves(evidence["commands"]):
                    args = command.get("args")
                    if command.get("op") in {"timeline.add", "shot-group.set"} and isinstance(args, dict) and "media" in args:
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
                if _scene_check is not None:
                    _scene_check(request)
                revision_id = publication_id = None
                if publication is not None:
                    published = self.publish_parent_composition(project_id, timeline_id, {
                        **publication, "project_id": project_id, "timeline_id": timeline_id,
                        "expected_head": head["revision_id"],
                        **({"dependency_manifest": {"media": _restore_capture["media"]}} if restore is not None else {}),
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
                # Validate the ACTUAL immutable candidate closure. Any refusal
                # rolls back publication, child projections, head and journal.
                closure = self._commit_revision_closure(project_id, timeline_id,
                                                        revision_id or head["revision_id"])
                projection = narration_projection(closure)
                narration_state = None
                previous_narration = narration_projection(self._commit_revision_closure(
                    project_id, timeline_id, head["revision_id"]))
                if projection["lines"] or previous_narration["lines"] or "narration" in request or _narration_takes:
                    if digest(request.get("narration")) != digest(projection):
                        raise ValidationError("narration projection does not match candidate closure")
                    bound = {digest(v["refs"]): v for v in _narration_takes}
                    for line, authored in narration_lines(closure, require_takes=True):
                        take = bound.get(digest(line["take"]))
                        if take is None:
                            raise ValidationError("candidate narration take was not captured and read")
                        current = self._managed_narration_take(project_id, line["take"])
                        if current != take:
                            raise ConflictError("narration dependency changed before acceptance")
                        validate_line_take(authored, take)
                    narration_state = {"projection": projection, "digest": digest(projection),
                                       "parent_revision_id": revision_id or head["revision_id"]}
                timestamp = now()
                receipt = {"publisher": publisher, "accepted_at": timestamp,
                           "evidence_digest": evidence_digest, "narration_state": narration_state}
                provenance = {"publisher": publisher, "source": request["source"]}
                if "asserted_actor" in request:
                    receipt["asserted_actor"] = request["asserted_actor"]
                    provenance["asserted_actor"] = request["asserted_actor"]
                if publication_id is not None:
                    self.store.conn.execute(
                        "UPDATE parent_composition_publications SET provenance_json=?, restored_from_revision_id=? WHERE publication_id=?",
                        (canonical_json(provenance), restore["revision_id"] if restore is not None else None, publication_id),
                    )
                result.update(accepted_revision_id=revision_id, accepted_publication_id=publication_id,
                              previous_revision_id=head["revision_id"], runtime_receipt=receipt,
                              provenance=provenance, evidence={"digest": evidence_digest})
                summary = None if revision_id is None else dict(
                    revision_id=revision_id, publication_id=publication_id,
                    previous_revision_id=head["revision_id"], previous_publication_id=head["publication_id"],
                    restored_from_revision_id=restore["revision_id"] if restore is not None else None, accepted_at=timestamp, source=request["source"],
                    asserted_actor=request.get("asserted_actor"), publisher=publisher,
                    label=request.get("label"), evidence_digest=evidence_digest)
                if _scene_check is not None:
                    _scene_check(request)
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
        """Startup-only registration of the fixed trusted authoring provider."""
        with self.store._mutex:
            if getattr(self, "_timeline_commit_provider", None) is not None or getattr(self, "_timeline_commit_started", False):
                raise ConflictError("timeline commit provider is already fixed for this service")
            validate_timeline_commit_provider(provider)
            self._timeline_commit_provider = provider

    def _internal_revision_narration_state(self, internal):
        """Read the adopted receipt of this immutable child's origin publication.

        The receipt pins a parent, not a child. Follow the existing immutable
        dependency edge; never select a later acceptance reusing the child.
        A legacy origin cannot acquire narration state through a later edit.
        """
        project, revision = (internal[k] for k in ("project_id", "revision_id"))
        origin = self.store.conn.execute(
            "SELECT p.*, d.content_digest AS dependency_digest FROM parent_composition_publications p "
            "JOIN composition_revision_dependencies d ON d.parent_revision_id=p.revision_id "
            "WHERE p.project_id=? "
            "AND d.dependency_kind='internal_timeline_revision' AND d.dependency_id=? "
            "ORDER BY p.sequence LIMIT 1", (project, revision),
        ).fetchone()
        if origin is None:
            return None
        # A child timeline can differ from its publishing parent timeline.
        timeline = origin["timeline_id"]
        rows = self.store.conn.execute(
            "SELECT idempotency_key, request_hash, result_json FROM command_idempotency "
            "WHERE command_kind=? AND aggregate_id=? "
            "AND (json_extract(result_json, '$.result.accepted_publication_id')=? "
            "OR json_extract(result_json, '$.summary.publication_id')=?)",
            (KIND, self._commit_aggregate(project, timeline), origin["publication_id"],
             origin["publication_id"]),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise ConflictError("ambiguous narration origin receipt")
        try:
            stored = rows[0]
            result = json.loads(stored["result_json"])["result"]
            receipt = result["runtime_receipt"]
            if (result["status"] != "accepted"
                    or result["accepted_publication_id"] != origin["publication_id"]
                    or result["accepted_revision_id"] != origin["revision_id"]
                    or result["request_id"] != stored["idempotency_key"]
                    or result["request_hash"] != stored["request_hash"]
                    or origin["dependency_digest"] != internal["content_digest"]):
                raise ValueError("accepted result identity mismatch")
            if not isinstance(receipt, dict):
                raise ValueError("accepted receipt must be an object")
            state = receipt.get("narration_state")
            if state is None:
                return None
            _object(state, ("projection", "digest", "parent_revision_id"))
            if (state["parent_revision_id"] != origin["revision_id"]
                    or digest(state["projection"]) != state["digest"]):
                raise ValueError("narration receipt pin/digest mismatch")
            closure = self._commit_revision_closure(
                project, timeline, origin["revision_id"],
                _internal_reader=self._get_project_timeline_revision,
            )
            if (not any(all(row[k] == internal[k] for k in (
                    "project_id", "timeline_id", "revision_id", "content_digest", "payload"))
                    for row in closure["internal_timeline_revisions"])
                    or digest(narration_projection(closure)) != state["digest"]):
                raise ValueError("narration receipt does not match pinned closure")
            return copy.deepcopy(state)
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise ConflictError("pinned narration receipt failed verification") from exc

    def _commit_revision_closure(self, project, timeline, revision_id, *, _internal_reader=None):
        internal_reader = _internal_reader or self.get_project_timeline_revision
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

        if isinstance(revision_id, dict) and "timeline_id" in revision_id:
            from .timeline_retention import provenance
            ref = revision_id
            if (set(ref) != {"timeline_id", "parent_revision_id", "publication_id"}
                    or any(not isinstance(v, str) or not v or '/' in v for v in ref.values())
                    or ref["timeline_id"] == timeline):
                raise ValidationError("duplicate source requires distinct timeline and exact revision/publication")
            recorded = provenance(self, timeline)
            expected = dict(timeline_id=ref["timeline_id"], expected_revision_id=ref["parent_revision_id"],
                            expected_publication_id=ref["publication_id"])
            if not recorded or recorded["project_id"] != project or recorded["source"] != expected:
                raise AuthorizationError("duplicate source differs from recorded destination provenance")
            row = self.store.conn.execute(
                "SELECT t.project_id, t.archived_at FROM timelines t JOIN parent_composition_publications p "
                "ON p.timeline_id=t.id AND p.project_id=t.project_id WHERE t.id=? AND p.revision_id=? AND p.publication_id=?",
                (ref["timeline_id"], ref["parent_revision_id"], ref["publication_id"])).fetchone()
            if not row or row["project_id"] != project or row["archived_at"] is not None:
                raise ConflictError("duplicate source exact publication is unavailable")
            return self._commit_revision_closure(project, ref["timeline_id"], ref["parent_revision_id"],
                                                 _internal_reader=_internal_reader)

        if isinstance(revision_id, dict):
            ref = revision_id
            if set(ref) != {"shot_id", "shot_revision_id", "internal_revision_id"} or any(not isinstance(v, str) or not v for v in ref.values()):
                raise ValidationError("exact shot source requires three immutable pins")
            shot = verified(lambda: self.get_project_shot_revision(project, ref["shot_id"], ref["shot_revision_id"]),
                            "shot", {"project_id": project, "shot_id": ref["shot_id"], "revision_id": ref["shot_revision_id"]}, dependency=True)
            if shot.get("internal_timeline_revision_id") != ref["internal_revision_id"] or shot["payload"].get("internal_timeline_revision_id") != ref["internal_revision_id"]:
                raise ConflictError("exact shot source internal revision pin mismatch")
            row = self.store.conn.execute("SELECT timeline_id FROM internal_timeline_revisions WHERE id=? AND project_id=?", (ref["internal_revision_id"], project)).fetchone()
            if row is None:
                raise ConflictError("pinned internal timeline dependency is missing")
            internal = verified(lambda: self.get_project_timeline_revision(project, row["timeline_id"], ref["internal_revision_id"]),
                                "internal_timeline", {"project_id": project, "timeline_id": row["timeline_id"], "revision_id": ref["internal_revision_id"]}, dependency=True)
            return {"shot_revision": {k: shot[k] for k in ("project_id", "shot_id", "revision_id", "internal_timeline_revision_id", "content_digest", "payload")},
                    "internal_timeline_revision": {k: internal[k] for k in ("project_id", "timeline_id", "revision_id", "content_digest", "payload")}}

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
                        lambda: internal_reader(project, internal_timeline, internal_id),
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

        return scoped()


    def _commit_restore_capture(self, project, timeline, selection):
        """Verify the historical ledger with the same authority as direct restore.

        Dependency rows alone cannot authorize manifest-only media. The existing
        revision/event integrity validator proves those rows before we retain
        them, and acceptance repeats this read under its SQLite write fence.
        """
        revision = selection["revision_id"]
        closure = self._commit_revision_closure(project, timeline, revision)
        parent = closure["parent_revision"]
        if (parent["content_digest"] != selection["content_digest"]
                or canonical_json(self._complete_parent_payload(copy.deepcopy(parent["payload"]))) != canonical_json(parent["payload"])):
            raise ConflictError("historical restore digest or canonical image mismatch")
        publication = None
        if selection.get("publication_id") is not None:
            row = self.store.conn.execute(
                "SELECT * FROM parent_composition_publications WHERE project_id=? AND timeline_id=? "
                "AND revision_id=? AND publication_id=?",
                (project, timeline, revision, selection["publication_id"]),
            ).fetchone()
            if row is None:
                raise ConflictError("historical restore publication is unavailable")
            publication = dict(row)
        report = self.store.integrity_report(timeout_seconds=self.store.admission_timeout)
        checks = report.get("checks", {}) if isinstance(report, dict) else {}
        errors = []
        for kind in ("revisions", "event_chain"):
            check = checks.get(kind)
            if (not isinstance(check, dict) or "ok" not in check
                    or not isinstance(check.get("errors"), list)
                    or check.get("reason") == "not_checked"):
                raise ConflictError("historical restore integrity report unavailable")
            errors.extend(error for error in check["errors"] if isinstance(error, dict) and (
                (kind == "revisions" and (str(error.get("identity", "")) == revision
                    or str(error.get("identity", "")).startswith(revision + ":")))
                or (kind == "event_chain" and error.get("timeline_id") == timeline)))
        if errors:
            raise ConflictError("historical restore dependency ledger failed verification", details={"errors": errors})
        dependencies = [dict(row) for row in self.store.conn.execute(
            "SELECT * FROM composition_revision_dependencies WHERE parent_revision_id=? ORDER BY ordinal", (revision,))]
        media = sorted(row["dependency_id"] for row in dependencies if row["dependency_kind"] == "media")
        self._validate_media_dependencies(project, {"media": media})
        return dict(closure=closure, dependencies=dependencies, selected_publication=publication, media=media,
                    publication=dict(parent_composition=copy.deepcopy(parent["payload"]),
                        shot_revisions=[{k: copy.deepcopy(row[k]) for k in (
                            "shot_id", "revision_id", "internal_timeline_revision_id", "content_digest", "payload")}
                            for row in closure["shot_revisions"]],
                        internal_timeline_revisions=[{k: copy.deepcopy(row[k]) for k in (
                            "timeline_id", "revision_id", "content_digest", "payload")}
                            for row in closure["internal_timeline_revisions"]]))


    def _request_commit_port(self, request, identity):
        # Trusted code is composed in-process; scope is enforced at every call.
        original = copy.deepcopy(request)
        # Preserve the live issuer-owned grant; detach ordinary principal data.
        principal = ({k: copy.deepcopy(v) if k != "_paired_session" else v for k, v in identity.items()}
                     if isinstance(identity, dict) else copy.deepcopy(identity))
        project, timeline, key = original["project_id"], original["timeline_id"], original["request_id"]
        request_hash = digest(original)
        restore_selection = _restore_selection(original)
        restore_capture = None
        scene_invocation = None
        def scene_evaluator(candidate):
            nonlocal scene_invocation
            from .authoring_scene import RequestSceneEvaluation
            if scene_invocation is None:
                scene_invocation = RequestSceneEvaluation(self, original, principal)
            return scene_invocation.evaluator(candidate)

        def check_scene(prepared):
            if scene_invocation is None:
                raise AuthorizationError("missing request-scoped scene evaluation")
            scene_invocation.accept(prepared)

        def close_scene():
            if scene_invocation is not None:
                scene_invocation.close()

        selections = []
        for command in _command_leaves(original["change"].get("commands", [])):
            if command.get("op") in {"timeline.add", "shot-group.set"} and isinstance(command.get("args"), dict) and "media" in command["args"]:
                selection = command["args"]["media"]
                _media_selection(selection, require_digest=True)
                if selection not in selections:
                    selections.append(copy.deepcopy(selection))
        captured = {}
        captured_closures = {}
        permitted_revisions = {original["base_revision_id"]}
        if restore_selection is not None:
            permitted_revisions.add(restore_selection["revision_id"])
        def declared(values):
            if not isinstance(values, list):
                return
            for command in values:
                if not isinstance(command, dict) or not isinstance(command.get("args"), dict):
                    continue
                args = command["args"]
                if command.get("op") == "timeline.batch":
                    yield from declared(args.get("commands", []))
                if command.get("op") == "timeline.duplicate":
                    ref = args.get("source")
                    if (not isinstance(ref, dict) or set(ref) != {"timeline_id", "parent_revision_id", "publication_id"}
                            or any(not isinstance(v, str) or not v or '/' in v for v in ref.values())):
                        raise ValidationError("duplicate source requires exact closed pins")
                    bootstrap = self.store.conn.execute(
                        "SELECT previous_revision_id FROM parent_composition_publications "
                        "WHERE project_id=? AND timeline_id=? AND revision_id=? AND publication_id=?",
                        (project, timeline, original["base_revision_id"], original.get("base_publication_id"))).fetchone()
                    if (args.get("bootstrap_revision_id") != original["base_revision_id"]
                            or not bootstrap or bootstrap["previous_revision_id"] is not None):
                        raise AuthorizationError("duplicate requires its exact empty bootstrap publication")
                    yield ref
                if command.get("op") in {"shot.set", "occurrence.set", "occurrence.add"}:
                    for name in ("source", "replacement"):
                        if isinstance(args.get(name), dict):
                            yield args[name]
                if command.get("op") == "timeline.inverse":
                    for write in args.get("writes", []):
                        if isinstance(write, dict) and isinstance(write.get("source"), dict):
                            yield write["source"]
        declared_sources = list(declared(original["change"].get("commands", [])))
        declared_revision_ids = {ref["parent_revision_id"] for ref in declared_sources if "timeline_id" not in ref and isinstance(ref.get("parent_revision_id"), str)}
        declared_shots = {digest(ref): copy.deepcopy(ref) for ref in declared_sources if "parent_revision_id" not in ref or "timeline_id" in ref}
        permitted_revisions.update(declared_revision_ids)
        take_refs = list(request_take_refs(original["change"]))
        captured_takes = {}
        base_takes = None
        transcript_resolver = None
        captured_transcripts = {}
        frozen_transcript_history = None

        def transcript_authority(*scopes):
            _publisher(principal, original.get("asserted_actor"))
            self._assert_commit_authority(principal, project)
            self._assert_mutation_admitted()
            for scope in ("projects:write", *scopes):
                if not {scope, "admin"} & set(principal.get("scopes", [])):
                    raise AuthorizationError("transcript capture requires caller " + scope)
                binding = principal.get("_credential_binding")
                if binding is not None:
                    if self._task_credentials is None:
                        raise AuthorizationError("transcript caller credential issuer is unavailable")
                    self._task_credentials.validate_binding(principal["actor"], binding, scope)

        def transcript_document(document_id):
            transcript_authority("projects:read")
            return copy.deepcopy(self.get_document(project, document_id))

        def transcript_object(object_id):
            transcript_authority("objects:read")
            location = self.object_location(project, object_id)
            metadata, stream = self.open_object(object_id)
            with stream:
                raw = stream.read()
            if (location["object_id"] != object_id or location["digest"] != object_id
                    or location["size"] != len(raw) or int(metadata["size"]) != len(raw)
                    or "sha256:" + hashlib.sha256(raw).hexdigest() != object_id):
                raise ConflictError("transcript project CAS dependency changed")
            return dict(status=200, data=raw)

        def transcript_history():
            # Only ancestors of the exact accepted base can authorize an old
            # inverse dependency. An unrelated commit/journal is not a grant.
            rows = self.store.conn.execute(
                "SELECT result_json FROM command_idempotency WHERE command_kind=? AND aggregate_id=?",
                (KIND, self._commit_aggregate(project, timeline))).fetchall()
            by_revision = {}
            for row in rows:
                wrapper = json.loads(row["result_json"])
                result = wrapper["result"]
                if result.get("accepted_revision_id"):
                    by_revision[result["accepted_revision_id"]] = wrapper
            history, seen = [], set()
            revision = original["base_revision_id"]
            while revision is not None:
                if revision in seen:
                    raise ConflictError("cyclic accepted transcript history")
                seen.add(revision)
                publication = self.store.conn.execute(
                    "SELECT publication_id, previous_revision_id FROM parent_composition_publications "
                    "WHERE project_id=? AND timeline_id=? AND revision_id=?",
                    (project, timeline, revision)).fetchone()
                if publication is None:
                    raise ConflictError("accepted transcript ancestry is missing")
                wrapper = by_revision.get(revision)
                if wrapper is not None:
                    result, evidence = wrapper["result"], wrapper["evidence"]
                    if (result["accepted_publication_id"] != publication["publication_id"]
                            or result["previous_revision_id"] != publication["previous_revision_id"]
                            or digest(evidence) != result["runtime_receipt"]["evidence_digest"]):
                        raise ConflictError("accepted transcript history failed verification")
                    history.append(evidence.get("transcripts", {}))
                revision = publication["previous_revision_id"]
            return history

        def transcript_source(request, selection):
            nonlocal transcript_resolver, frozen_transcript_history
            from astrid.sdk.timeline.transcripts import TranscriptSourceSelection
            from astrid.sdk.timeline.source_hydration import _runtime_transcript_resolver
            if digest(request) != request_hash or not isinstance(selection, TranscriptSourceSelection):
                raise AuthorizationError("transcript capture changed request identity")
            with self.store._mutex:
                transcript_authority("objects:read")
                if transcript_resolver is None:
                    closure = revision_closure(original["base_revision_id"])
                    frozen_transcript_history = transcript_history()
                    transcript_resolver = _runtime_transcript_resolver(original, closure, frozen_transcript_history,
                        document_reader=transcript_document, object_reader=transcript_object)
                if selection.key not in captured_transcripts:
                    capture = transcript_resolver.resolve_transcript_source(original, selection)
                    captured_transcripts[selection.key] = capture
                return captured_transcripts[selection.key]

        def check_transcripts(entries):
            leaves = list(_command_leaves(original["change"].get("commands", [])))
            if not (captured_transcripts or entries or any(
                    c.get("op") in {"transcript.bind", "transcript.reference"}
                    or c.get("op") == "timeline.inverse" and "transcript" in canonical_json(c)
                    for c in leaves)):
                return
            from astrid.sdk.timeline.transcripts import request_selections, inverse_selections
            declared = {**request_selections(original, original["change"].get("commands", [])),
                        **inverse_selections(project, original["change"].get("commands", []))}
            if not declared.keys() <= captured_transcripts.keys():
                raise ValidationError("declared transcript sources must be captured before acceptance")
            expected = {key: capture.entry() for key, capture in captured_transcripts.items()}
            if entries != expected:
                raise ValidationError("transcript evidence differs from request-bound captures")
            if captured_transcripts:
                transcript_authority("objects:read")
                if transcript_history() != frozen_transcript_history:
                    raise ConflictError("accepted transcript history changed before acceptance")
                for capture in captured_transcripts.values():
                    fresh = transcript_resolver.resolve_transcript_source(original, capture.selection)
                    if fresh != capture:
                        raise ConflictError("transcript source changed before acceptance")

        def narration_take(refs):
            nonlocal base_takes
            validate_take_refs(refs)
            with self.store._mutex:
                _publisher(principal, original.get("asserted_actor"))
                self._assert_commit_authority(principal, project)
                self._assert_mutation_admitted()
                if refs not in take_refs:
                    if base_takes is None:
                        closure = self._commit_revision_closure(project, timeline, original["base_revision_id"])
                        base_takes = [line["take"] for line, _ in narration_lines(closure)]
                    historical_takes = ([line["take"] for line, _ in narration_lines(restore_capture["closure"])]
                                        if restore_capture is not None else [])
                    if refs not in base_takes and refs not in historical_takes:
                        raise AuthorizationError("narration take is outside captured request and pinned base")
                token = digest(refs)
                if token not in captured_takes:
                    captured_takes[token] = self._managed_narration_take(project, refs)
                return copy.deepcopy(captured_takes[token])

        def selected_media(selection):
            _media_selection(selection, require_digest=True)
            if selection not in selections:
                raise AuthorizationError("selected media is outside the captured request")
            token = digest(selection)
            with self.store._mutex:
                _publisher(principal, original.get("asserted_actor"))
                self._assert_commit_authority(principal, project)
                self._assert_mutation_admitted()
                if token not in captured:
                    captured[token] = self._selected_project_media(project, selection)
                return copy.deepcopy(captured[token])

        def read(call):
            with self.store._mutex:
                return json.loads(canonical_json(call()))

        def revision_closure(revision_id):
            def scoped():
                nonlocal restore_capture
                _publisher(principal, original.get("asserted_actor"))
                self._assert_commit_authority(principal, project)
                token = digest(revision_id) if isinstance(revision_id, dict) else revision_id
                allowed = (token in declared_shots and declared_shots[token] == revision_id) if isinstance(revision_id, dict) else revision_id in permitted_revisions
                if not allowed:
                    raise AuthorizationError("revision closure is outside captured request and observed heads")
                if restore_selection is not None and revision_id == restore_selection["revision_id"]:
                    fresh = self._commit_restore_capture(project, timeline, restore_selection)
                    if restore_capture is not None and digest(restore_capture) != digest(fresh):
                        raise ConflictError("historical restore closure changed during request")
                    restore_capture = copy.deepcopy(fresh)
                    closure = fresh["closure"]
                else:
                    closure = self._commit_revision_closure(project, timeline, revision_id)
                if token in captured_closures and captured_closures[token][1] != closure:
                    raise ConflictError("immutable revision dependency changed during request")
                captured_closures[token] = (copy.deepcopy(revision_id), copy.deepcopy(closure))
                return closure
            return read(scoped)

        def head():
            def scoped():
                value = self.head(project, timeline)
                permitted_revisions.add(value["revision_id"])
                return value
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
            if restore_selection is not None:
                marker = {**restore_selection, "expected_publication_id": original["base_publication_id"]}
                if (prepared.get("restore") != marker or restore_capture is None
                        or prepared.get("expected_head_revision_id") != original["base_revision_id"]):
                    raise ValidationError("restore marker must match captured command, head and historical read")
            elif "restore" in prepared:
                raise ValidationError("restore marker requires the sole captured restore command")
            # Every declared selection must have been consumed by the semantic
            # provider. Repeated reads/rebase use exactly that detached record.
            dependencies = []
            for selection in selections:
                token = digest(selection)
                if token not in captured:
                    raise ValidationError("selected media must be read before acceptance")
                dependencies.append(copy.deepcopy(captured[token]))
            if not (declared_revision_ids | declared_shots.keys()) <= captured_closures.keys():
                raise ValidationError("declared immutable sources must be read before acceptance")
            accepted = copy.deepcopy(self.accept(copy.deepcopy(prepared), identity=principal,
                                             _selected_media=dependencies,
                                             _narration_takes=copy.deepcopy(list(captured_takes.values())),
                                             _revision_closures=copy.deepcopy(list(captured_closures.values())),
                                             _restore_capture=copy.deepcopy(restore_capture),
                                             _transcript_check=check_transcripts,
                                             _scene_check=check_scene if getattr(getattr(self, "_timeline_commit_provider", None),
                                                 "requires_scene_evaluation", False) or scene_invocation is not None else None))
            accepted_revision = accepted["stored_result"].get("accepted_revision_id")
            if accepted_revision:
                permitted_revisions.add(accepted_revision)
            return accepted

        def revisions(options):
            if restore_selection is None:
                return read(lambda: self.revisions(project, timeline, copy.deepcopy(options)))
            def scoped():
                _publisher(principal, original.get("asserted_actor"))
                self._assert_commit_authority(principal, project)
                _object(options, (), ("limit", "before"))
                limit = options.get("limit", 50)
                if type(limit) is not int or limit < 1:
                    raise ValidationError("revision limit must be a positive integer")
                rows = [dict(row) for row in self.store.conn.execute(
                    "SELECT revision_id, publication_id FROM parent_composition_publications "
                    "WHERE project_id=? AND timeline_id=? ORDER BY sequence DESC", (project, timeline))]
                if "before" in options:
                    _string(options["before"])
                    index = next((i for i, row in enumerate(rows) if row["publication_id"] == options["before"]), None)
                    if index is None:
                        raise NotFoundError("restore publication cursor not found")
                    rows = rows[index + 1:]
                return rows[:limit]
            return read(scoped)

        return RuntimeCommitPort(
            lookup=lambda: read(lambda: self.lookup_request(project, timeline, key)),
            head=head,
            revision=lambda revision_id: read(lambda: self.get_project_parent_composition_revision(project, timeline, revision_id)),
            revision_closure=revision_closure,
            revisions=revisions,
            evidence=evidence, accept=accept, selected_media=selected_media, narration_take=narration_take,
            transcript_source=transcript_source, scene_evaluator=scene_evaluator, close=close_scene, validate_scene=check_scene,
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
        stage = "provider_commit"
        try:
            prepared = provider.commit(copy.deepcopy(request), port)
            if (getattr(provider, "requires_scene_evaluation", False) and isinstance(prepared, dict)
                    and prepared.get("status") == "preview"):
                stage = "preview_scene_validation"
                port.validate_scene(prepared["canonical_document"])
        except (AuthorizationError, ForbiddenError):
            raise
        except (ConnectionError, TimeoutError):
            raise  # The transport may have lost an already durable response.
        except Exception as exc:
            _record_commit_failure(stage, exc)
            result["error"] = dict(code="runtime_unavailable", message="Astrid commit provider failed; outcome may be unknown",
                                   hint="Acceptance may already be durable", next_action="Retry the original request id unchanged")
            return result
        finally:
            port.close()
        if not isinstance(prepared, dict):
            raise ValidationError("commit provider must return CommitResult")
        _object(prepared, set(result_template(request, request_hash)), ("shot_groups",))
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
