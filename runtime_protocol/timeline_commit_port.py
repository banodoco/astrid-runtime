"""Request-scoped adapters for the installed timeline command provider.

Semantic execution belongs to Agent; durable acceptance and retry exclusion
belong to the commit store and coordinator. No renderer participates here.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
from urllib.parse import quote

from .errors import AuthorizationError, ConflictError, NotFoundError, RuntimeErrorBase, ValidationError
from .timeline_commit_validation import detached, digest
from .util import canonical_json


class CommitUnavailable(RuntimeErrorBase):
    code = "not_ready"
    status = 503

    def __init__(self):
        super().__init__("Timeline commit outcome unavailable; retry the exact request",
                         details={"reason": "runtime_unavailable"})


TEXT_MEDIA_TYPE = "text/plain; charset=utf-8"
TEXT_MAX_BYTES = 1_048_576
_OBJECT_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
# The authority-only guard has no authored reads, selections or writes. Agent
# may capture these defaults, but no nonempty claim grants producer authority.
_PRODUCER_GUARD_RECORD_METADATA = {
    "intent": {}, "resolved": [], "reads": [], "selections": [],
    "bindings": {}, "created": [], "expect": {}, "authorship": {},
}


def _producer_guard_matches(recorded, original):
    from .timeline_commit_producer import value_equal
    added = recorded.keys() - original.keys()
    if any(key not in _PRODUCER_GUARD_RECORD_METADATA
           or not value_equal(recorded[key], _PRODUCER_GUARD_RECORD_METADATA[key]) for key in added):
        return False
    # Preserve the typed guard envelope and pin, including integer fences.
    return canonical_json({key: value for key, value in recorded.items() if key not in added}) == canonical_json(original)


def validate_provider(provider):
    from .timeline_commit_provider import validate_timeline_commit_provider
    validate_timeline_commit_provider(provider)


def route_path(project_id, timeline_id, suffix="commit"):
    return f"/v1/projects/{quote(project_id, safe='')}/timelines/{quote(timeline_id, safe='')}/{suffix}"


def validate_request(request):
    from .timeline_commit_validation import validate_commit_value
    validate_commit_value(request, "CommitRequest")
    restores = [item for item in command_leaves(request["commands"]) if item.get("op") == "timeline.restore"]
    if restores and (len(request["commands"]) != 1 or request["commands"][0] is not restores[0]):
        raise ValidationError("timeline.restore must be the sole command")


def command_leaves(commands):
    for command in commands:
        if command.get("op") == "timeline.batch":
            nested = command.get("args", {}).get("commands", [])
            if not isinstance(nested, list) or not all(isinstance(item, dict) for item in nested):
                raise ValidationError("invalid command batch")
            yield from command_leaves(nested)
        else:
            yield command


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def refused(reason, message, *, current=None, diagnostic_reason=None):
    from .timeline_commit import CommitRejected
    error = CommitRejected({"http_status": 409, "code": "conflict", "message": message,
                            "details": {"status": "refused", "reason": reason,
                                        "base": None, "current": current, "conflicts": []}})
    if diagnostic_reason is not None:
        error.__dict__["_diagnostic_reason"] = diagnostic_reason
    return error


def public_failure(failure):
    error = RuntimeErrorBase(failure["message"], details=copy.deepcopy(failure["details"]))
    error.code = failure["code"]
    error.status = failure["http_status"]
    return error


class RequestCommitPort:
    def __init__(self, service, commit_store, context, authorize):
        self.__service = service
        self.__store = commit_store
        self.__context = detached(context)
        self.__authorize = authorize
        self.__closed = False
        self.__closures = {}
        self.__source_closures = {}
        self.__source_refs = {}
        self.__shots = {}
        self.__media = {}
        self.__raw_media = {}
        self.__takes = {}
        self.__texts = {}
        self.__documents = {}
        self.__document_objects = {}
        self.__producers = {}
        self.__history_pins = []
        self.__preview = None
        self.__sequential_capture = None
        self.__request = self.__context["request"]
        self.__project = self.__request["project_id"]
        self.__timeline = self.__request["timeline_id"]
        self.__observed = {}
        self.__ancestry = {}
        self.__ancestry_identity = None
        self.__declared = list(objects(self.__request["commands"]))
        adapter = self.__context["invocation"]["operation"] == "restoreProjectParentCompositionRevision"
        if adapter or self.__request["commands"][0].get("op") == "timeline.restore":
            def prepare_restore():
                args = self.__request["commands"][0]["args"]
                self._restore_integrity(args["revision_id"])
                try:
                    source = self.__store.revision_closure(self.__project, self.__timeline, args["revision_id"])
                except NotFoundError as exc:
                    raise refused("dependency_unavailable", "restore source dependency is missing") from exc
                content_digest = source["parent_revision"]["content_digest"]
                if adapter:
                    args["content_digest"] = content_digest
                elif args["content_digest"] != content_digest:
                    raise refused("dependency_unavailable", "restore source content digest disagrees with immutable revision")
                self.__closures[args["revision_id"]] = copy.deepcopy(source)
                self.__declared = list(objects(self.__request["commands"])) + list(objects(source))
            self._read(prepare_restore)

    def _restore_integrity(self, revision_id):
        # Preserve main's bounded preflight before semantic execution. Accepted
        # retries are resolved by the coordinator before constructing this port.
        report = self.__service.store.integrity_report(timeout_seconds=self.__service.store.admission_timeout)
        checks = report.get("checks", {}) if isinstance(report, dict) else {}
        errors = []
        complete = isinstance(checks, dict)
        for name in ("revisions", "event_chain"):
            check = checks.get(name) if isinstance(checks, dict) else None
            if (not isinstance(check, dict) or type(check.get("ok")) is not bool
                    or not isinstance(check.get("errors"), list) or check.get("reason") == "not_checked"
                    or (not check["ok"] and not check["errors"])):
                complete = False
                continue
            for error in check["errors"]:
                if isinstance(error, dict) and (
                        (name == "revisions" and (str(error.get("identity", "")) == revision_id
                         or str(error.get("identity", "")).startswith(revision_id + ":")))
                        or (name == "event_chain" and error.get("timeline_id") == self.__timeline)):
                    errors.append(error)
        if not complete:
            errors.append({"reason": "integrity_report_unavailable"})
        if errors:
            raise ConflictError("historical parent composition dependency closure failed immutable verification",
                                details={"status": "refused", "reason": "dependency_unavailable",
                                         "revision_id": revision_id, "errors": errors})

    def _provider_context(self):
        return copy.deepcopy(self.__context)

    def capture_sequential_execution(self, capture: dict) -> None:
        """Retain one private, request-bound sequential execution proof.

        This is deliberately not part of ``PreparedCommit``.  Agent calls it
        immediately before each candidate preview/accept, so the port owns the
        custody boundary and can discard the proof after that attempt.
        """
        if self.__closed:
            raise AuthorizationError("timeline commit port is closed")
        # A new candidate attempt always supersedes any prior proof, including
        # when the replacement itself is rejected as malformed.
        self.__sequential_capture = None
        capture = detached(capture)
        if not isinstance(capture, dict):
            raise ValidationError("sequential execution capture is invalid")
        expected = {"schema_version", "context", "original", "landing",
                    "replay_bindings", "prepared_digest"}
        if set(capture) != expected or type(capture["schema_version"]) is not int or capture["schema_version"] != 1:
            raise ValidationError("sequential execution capture has an invalid shape")
        if canonical_json(capture["context"]) != canonical_json(self.__context):
            raise refused("invocation_mismatch", "sequential execution capture belongs to another request")
        if not isinstance(capture["original"], dict) or not isinstance(capture["landing"], dict):
            raise ValidationError("sequential execution capture executions are invalid")
        if not isinstance(capture["replay_bindings"], list) or not isinstance(capture["prepared_digest"], str):
            raise ValidationError("sequential execution capture is incomplete")
        # Detach before retaining: the provider cannot mutate a proof after it
        # has crossed the private port boundary.
        self.__sequential_capture = capture

    def close(self):
        self.__closed = True
        self.__sequential_capture = None
        self.__ancestry.clear()
        self.__ancestry_identity = None

    def _read(self, call):
        if self.__closed:
            raise AuthorizationError("timeline commit port is closed")
        try:
            with self.__service.store._mutex:
                self.__authorize()
                with self.__store.history_read_scope():
                    identity = self.__store._history_read_identity
                    if identity != self.__ancestry_identity:
                        self.__ancestry.clear()
                        self.__ancestry_identity = identity
                    return copy.deepcopy(call())
        except BaseException:
            self.__ancestry.clear()
            self.__ancestry_identity = None
            raise

    def head(self):
        def read():
            pin = self.__store.head(self.__project, self.__timeline)
            self.__observed[pin["publication_id"]] = copy.deepcopy(pin)
            return pin
        return self._read(read)

    def _ancestor(self, publication_id):
        # Retain only reachability, never caller-owned entries. Every lookup
        # still authenticates its target inside the live history read scope.
        roots = []
        if publication_id in self.__ancestry:
            roots.append({"publication_id": publication_id, "revision_id": self.__ancestry[publication_id]})
        roots += list(self.__observed.values()) + [{
            "revision_id": self.__request["base_revision_id"],
            "publication_id": self.__request["base_publication_id"],
        }]
        for root in roots:
            current, seen = root, {}
            while current and current["publication_id"] not in seen:
                entry = self.__store._history_entry_view(self.__project, self.__timeline, current["publication_id"])
                if entry["revision_id"] != current["revision_id"]:
                    raise refused("history_unavailable", "publication/revision pins disagree",
                                  diagnostic_reason="port_ancestor_pin_mismatch")
                seen[current["publication_id"]] = current["revision_id"]
                if current["publication_id"] == publication_id:
                    from .timeline_commit_inputs import reachable_document_input_pins
                    pins = reachable_document_input_pins(self.__store.conn, self.__project, self.__timeline,
                                                         publication_ids=[publication_id])
                    self.__history_pins.extend(pin for pin in pins if pin not in self.__history_pins)
                    self.__ancestry.update(seen)
                    return entry
                current = entry["previous"]
        raise refused("history_unavailable", "publication is outside request ancestry",
                      diagnostic_reason="port_ancestor_outside_request")

    def history_entry(self, publication_id):
        return self._read(lambda: self._ancestor(publication_id))

    def history(self, through, after_publication_id=None, cursor=None, limit=100):
        def read():
            if self._ancestor(through["publication_id"])["revision_id"] != through["revision_id"]:
                raise refused("history_unavailable", "history bounds disagree",
                              diagnostic_reason="port_history_bounds_mismatch")
            return self.__store._history_view(self.__project, self.__timeline, through,
                                        after_publication_id=after_publication_id, cursor=cursor, limit=limit)
        return self._read(read)

    def revision_closure(self, revision_id):
        if isinstance(revision_id, dict):
            return self.source_revision_closure(revision_id)

        def read():
            if revision_id in self.__closures:
                return self.__closures[revision_id]
            allowed = {self.__request["base_revision_id"]}
            allowed.update(pin["revision_id"] for pin in self.__observed.values())
            # Reachability belongs to this live read identity. Reauthenticate
            # its exact target rather than walking every ancestor again for
            # each historical closure in a provider's history page.
            publication = next((publication for publication, revision in self.__ancestry.items()
                                if revision == revision_id), None)
            if publication is not None:
                self._ancestor(publication)
                allowed.add(revision_id)
            if revision_id not in allowed:
                allowed.update(item["revision_id"] for item in self.__declared
                               if "revision_id" in item and "content_digest" in item)
            if revision_id not in allowed:
                current = self.head()
                cursor = current
                while cursor:
                    entry = self._ancestor(cursor["publication_id"])
                    allowed.add(entry["revision_id"])
                    cursor = entry["previous"]
            if revision_id not in allowed:
                raise refused("history_unavailable", "revision is outside request ancestry or declared source",
                              diagnostic_reason="port_revision_outside_ancestry")
            # The original base pair must itself be a proven accepted edge.
            if revision_id == self.__request["base_revision_id"]:
                entry = self._ancestor(self.__request["base_publication_id"])
                if entry["revision_id"] != revision_id:
                    raise refused("history_unavailable", "base pins disagree",
                                  diagnostic_reason="port_base_pins_mismatch")
            value = self.__store.revision_closure(self.__project, self.__timeline, revision_id)
            self.__closures[revision_id] = copy.deepcopy(value)
            self.__declared.extend(objects(value))
            return value
        return self._read(read)

    def source_revision_closure(self, source_ref):
        """Capture one exact, authenticated source-timeline closure.

        Source authority is request-private.  It does not change the
        destination scope used by ordinary ``revision_closure`` or grant a
        provider a general project read capability.
        """
        if (not isinstance(source_ref, dict)
                or set(source_ref) != {"project_id", "timeline_id", "revision_id",
                                       "publication_id", "content_digest"}
                or any(not isinstance(source_ref[key], str) or not source_ref[key]
                       for key in source_ref)):
            raise ValidationError("source reference requires project, timeline, revision, publication, and digest")
        ref = copy.deepcopy(source_ref)
        key = canonical_json(ref)

        def read():
            if ref["project_id"] != self.__project:
                raise refused("dependency_unavailable", "source project is outside the destination project")
            if ref["timeline_id"] == self.__timeline:
                raise refused("dependency_unavailable", "source timeline must differ from the destination timeline")
            # Reuse the authenticated request identity and the service's
            # canonical realm/membership check for the source scope.  The
            # callback is not a caller-supplied source grant.
            self.__service._timeline_authorize(
                ref["project_id"], ref["timeline_id"], self.__authorize,
                mutation=False,
            )()
            if key in self.__source_closures:
                return self.__source_closures[key]
            value = self.__store.source_revision_closure(
                ref["project_id"], ref["timeline_id"], ref["revision_id"],
                ref["publication_id"], ref["content_digest"],
            )
            if (value["project_id"], value["timeline_id"],
                    value["parent_revision"]["revision_id"],
                    value["parent_revision"]["content_digest"]) != (
                        ref["project_id"], ref["timeline_id"], ref["revision_id"],
                        ref["content_digest"]):
                raise refused("dependency_unavailable", "source closure identity changed")
            self.__source_closures[key] = copy.deepcopy(value)
            self.__source_refs[key] = copy.deepcopy(ref)
            self.__declared.extend(objects(value))
            return value
        return self._read(read)

    def shot_closure(self, shot_id, revision_id):
        def read():
            if (shot_id, revision_id) in self.__shots:
                return self.__shots[(shot_id, revision_id)]
            declared = any(item.get("shot_id") == shot_id and
                           item.get("revision_id", item.get("shot_revision_id")) == revision_id
                           for item in self.__declared)
            pinned = any(any(shot["shot_id"] == shot_id and shot["revision_id"] == revision_id
                             for shot in closure["shot_revisions"]) for closure in self.__closures.values())
            if not declared and not pinned:
                raise refused("dependency_unavailable", "source shot requires an exact declared pin")
            value = self.__store.shot_closure(self.__project, shot_id, revision_id)
            self.__shots[(shot_id, revision_id)] = copy.deepcopy(value)
            self.__declared.extend(objects(value))
            return value
        return self._read(read)

    def selected_media(self, selection):
        def read():
            if selection not in self.__declared:
                raise refused("dependency_unavailable", "media selection was not declared")
            value = MediaReads(self.__service).selected(self.__project, selection)
            self.__media[canonical_json(selection)] = (copy.deepcopy(selection), value)
            return value
        return self._read(read)

    def raw_media_info(self, pin):
        """Capture one explicitly declared managed raw-media descriptor.

        This is intentionally separate from both base-only media reads and the
        managed five-field selection. The memo belongs to this request only.
        """
        def read():
            if (not isinstance(pin, dict) or set(pin) != {"media_id", "content_digest"}
                    or not isinstance(pin["media_id"], str) or not _OBJECT_ID.fullmatch(pin["media_id"])
                    or pin["content_digest"] != pin["media_id"]):
                raise ValidationError("raw media info requires one exact media pin")
            if pin not in self.__declared:
                raise refused("dependency_unavailable", "raw media info requires an exact declared pin")
            key = canonical_json(pin)
            if key in self.__raw_media:
                return self.__raw_media[key][1]
            value = MediaReads(self.__service).raw_media_info(self.__project, pin)
            self.__raw_media[key] = (copy.deepcopy(pin), value)
            return value
        return self._read(read)

    def text_selection(self, selection):
        def read():
            if selection not in self.__declared:
                raise refused("dependency_unavailable", "text selection was not declared")
            value = MediaReads(self.__service).text(self.__project, selection)
            self.__texts[canonical_json(selection)] = (copy.deepcopy(selection), value)
            return value
        return self._read(read)

    def narration_take(self, refs):
        def read():
            if refs not in self.__declared:
                raise refused("dependency_unavailable", "narration take was not declared")
            value = MediaReads(self.__service).narration(self.__project, refs)
            self.__takes[canonical_json(refs)] = (copy.deepcopy(refs), value)
            return value
        return self._read(read)

    def _document(self, pin, transcript):
        from .timeline_commit_inputs import (
            PROJECT_PACK_KIND,
            PROJECT_PACK_SCHEMA,
            capture_document_input,
        )
        def read():
            reachable = [item for closure in self.__closures.values()
                         for item in closure["dependency_manifest"]["documents"]]
            reachable.extend(item for closure in self.__source_closures.values()
                             for item in closure["dependency_manifest"]["documents"])
            reachable.extend(item for closure in self.__shots.values() for item in closure["documents"])
            reachable.extend(self.__history_pins)
            if pin not in self.__declared and pin not in reachable:
                raise refused("dependency_unavailable", "document input was not declared")
            if transcript:
                kind, schema = "media.transcript", "media.transcript/v1"
            else:
                kind = _source_kind(self.__service.store.conn, self.__project, pin, pin in reachable)
                if kind is None:
                    raise refused("dependency_unavailable", "source input requires a registered config or project pack kind")
                schema = PROJECT_PACK_SCHEMA if kind == PROJECT_PACK_KIND else None
            capture = capture_document_input(self.__service.store.conn, self.__project, pin,
                                             reachable_pins=reachable, expected_kind=kind, expected_schema=schema)
            self.__documents[canonical_json(pin)] = capture
            return {"pin": capture.pin, "document": capture.document}
        return self._read(read)

    def transcript_source(self, pin):
        return self._document(pin, True)

    def config_source(self, pin):
        return self._document(pin, False)

    def document_object(self, pin, object_id):
        def read():
            capture = self.__documents.get(canonical_json(pin))
            descriptor, data, identity = _pack_object(self.__service, self.__project, capture, object_id)
            key = (canonical_json(pin), object_id)
            captured = (descriptor, data, identity)
            if key in self.__document_objects and self.__document_objects[key] != captured:
                raise refused("dependency_unavailable", "captured project pack object changed")
            self.__document_objects[key] = captured
            return {**descriptor, "bytes_base64": base64.b64encode(data).decode("ascii")}
        return self._read(read)

    def producer_attempt(self, pin):
        from .timeline_commit_producer import ProducerReads, request_pin, validate_pin
        from .timeline_commit_producer_checkpoint import check_producer_consumption
        validate_pin(pin)
        def read():
            if request_pin(self.__request) != pin:
                raise refused("producer_dependency_unavailable", "producer pin was not declared")
            captured = ProducerReads(self.__service).capture(self.__context, pin)
            # Exact ledger retries precede this port; a new key must refuse
            # consumption before the provider tries to replay stale edit guards.
            check_producer_consumption(self.__service.store, pin["task_id"])
            key = canonical_json(pin)
            if key in self.__producers and self.__producers[key] != captured:
                raise refused("producer_attempt_mismatch", "captured producer authority changed")
            self.__producers[key] = captured
            return {"pin": captured["pin"]}
        return self._read(read)

    def _producer_captures(self, prepared):
        from .timeline_commit_producer import ProducerReads, request_pin, value_equal
        def read():
            pin = request_pin(self.__request)
            expected = [] if pin is None else [canonical_json(pin)]
            records = [dependency for record in prepared["records"]["commands"]
                       for dependency in record["dependencies"]
                       if dependency.get("key", "").startswith("producer_attempt:")
                       or (dependency.get("kind") == "authority"
                           and "task_id" in dependency.get("pin", {}))]
            wanted = [] if pin is None else [{"key": "producer_attempt:" + pin["task_id"],
                                             "kind": "authority", "policy": "exact", "pin": pin}]
            if sorted(self.__producers) != expected or canonical_json(records) != canonical_json(wanted):
                raise refused("producer_dependency_unavailable", "producer capture and authority records disagree")
            if pin is not None:
                guard = prepared["records"]["commands"][0]
                if (not _producer_guard_matches(guard["command"], self.__request["commands"][0])
                        or canonical_json(guard["dependencies"]) != canonical_json(wanted)
                        or any(guard[field] for field in ("writes", "reads", "selections", "bindings",
                                                        "created", "derived_writes"))
                        or not value_equal([record["command"] for record in prepared["records"]["commands"][1:]],
                                           self.__request["commands"][1:])
                        or prepared["records"]["undo_of"] or prepared["records"]["restored_from"] is not None):
                    raise refused("producer_dependency_unavailable", "producer authority requires its guard record")
            for captured in self.__producers.values():
                current = ProducerReads(self.__service).capture(self.__context, captured["pin"])
                if current != captured:
                    raise refused("producer_attempt_mismatch", "captured producer authority changed")
            return list(self.__producers.values())
        return self._read(read)

    def validate(self, prepared):
        from .timeline_commit_inputs import read_pack_snapshot_object, validate_captured_document_inputs
        if self.__closed:
            raise AuthorizationError("timeline commit port is closed")
        self.__authorize()
        self._validate_producer_consumption(prepared)
        for revision, captured in self.__closures.items():
            if self.__store.revision_closure(self.__project, self.__timeline, revision) != captured:
                raise refused("dependency_unavailable", "captured revision changed")
        for key, captured in self.__source_closures.items():
            ref = self.__source_refs[key]
            self.__service._timeline_authorize(
                ref["project_id"], ref["timeline_id"], self.__authorize,
                mutation=False,
            )()
            if self.__store.source_revision_closure(
                    ref["project_id"], ref["timeline_id"], ref["revision_id"],
                    ref["publication_id"], ref["content_digest"]) != captured:
                raise refused("dependency_unavailable", "captured source revision changed")
        for (shot, revision), captured in self.__shots.items():
            if self.__store.shot_closure(self.__project, shot, revision) != captured:
                raise refused("dependency_unavailable", "captured shot changed")
        reads = MediaReads(self.__service)
        for selection, captured in self.__media.values():
            if reads.selected(self.__project, selection) != captured:
                raise refused("dependency_unavailable", "captured media changed")
        manifest = prepared["canonical_document"]["dependency_manifest"]
        raw_manifest = {canonical_json(item) for item in manifest["media"]}
        for pin, captured in self.__raw_media.values():
            if canonical_json(pin) not in raw_manifest:
                raise refused("dependency_unavailable", "captured raw media pin is not in the candidate manifest")
            if captured.get("object_id") != pin["media_id"]:
                raise refused("dependency_unavailable", "captured raw media identity changed")
            if reads.raw_media_info(self.__project, pin) != captured:
                raise refused("dependency_unavailable", "captured raw media changed")
        for selection, captured in self.__texts.values():
            if reads.text(self.__project, selection) != captured:
                raise refused("dependency_unavailable", "captured text changed")
        for refs, captured in self.__takes.values():
            if reads.narration(self.__project, refs) != captured:
                raise refused("dependency_unavailable", "captured narration changed")
        authorized_media = {item["media_id"] for closure in self.__closures.values()
                            for item in closure["dependency_manifest"]["media"]}
        authorized_media.update(item["media_id"] for closure in self.__shots.values() for item in closure["media"])
        authorized_media.update(value["selection"]["object_id"] for _, value in self.__media.values())
        authorized_media.update(value["object_id"] for _, value in self.__raw_media.values())
        authorized_media.update(value["object_id"] for _, value in self.__texts.values())
        authorized_media.update(item for _, value in self.__takes.values() for item in value["dependency_objects"])
        if any(item["media_id"] not in authorized_media for item in manifest["media"]):
            raise refused("dependency_unavailable", "candidate media was not captured through this port")
        media_pins = {canonical_json(item) for closure in self.__closures.values()
                      for item in closure["dependency_manifest"]["media"]}
        media_pins.update(canonical_json(item) for closure in self.__source_closures.values()
                          for item in closure["dependency_manifest"]["media"])
        media_pins.update(canonical_json(item) for closure in self.__shots.values() for item in closure["media"])
        for captures in (self.__media, self.__raw_media, self.__texts):
            media_pins.update(canonical_json(pin) for pin, _ in captures.values())
        for record in prepared["records"]["commands"]:
            for dependency in record["dependencies"]:
                pin, kind = dependency["pin"], dependency["kind"]
                if kind == "media":
                    media_id = pin.get("object_id", pin.get("media_id"))
                    if (canonical_json(pin) not in media_pins
                            or canonical_json({"media_id": media_id, "content_digest": media_id}) not in raw_manifest):
                        raise refused("dependency_unavailable", "recorded media pin was not captured in the candidate manifest")
                elif kind in {"source", "transcript"}:
                    capture = self.__documents.get(canonical_json(pin))
                    if capture is None or pin not in manifest["documents"]:
                        raise refused("dependency_unavailable", "recorded document pin was not captured in the candidate manifest")
                    expected = "transcript" if capture.document["kind"] == "media.transcript" else "source"
                    if kind != expected:
                        raise refused("dependency_unavailable", "recorded document kind differs from its capture")
        pins = manifest["documents"]
        if sorted(map(canonical_json, pins)) != sorted(self.__documents):
            raise refused("dependency_unavailable", "candidate document pins differ from captured inputs")
        recorded = [dep["pin"] for record in prepared["records"]["commands"]
                    for dep in record["dependencies"] if dep["kind"] in {"transcript", "source"}
                    and {"document_id", "version", "content_digest"} <= dep["pin"].keys()]
        if any(pin not in recorded for pin in pins):
            raise refused("dependency_unavailable", "document input lacks a recorded dependency")
        validate_captured_document_inputs(self.__service.store.conn, self.__documents.values())
        for descriptor, data, identity in self.__document_objects.values():
            current = read_pack_snapshot_object(
                self.__service.store.conn, self.__service.cas, self.__project, descriptor,
                max_bytes=self.__service.max_object_bytes,
            )
            if current != (data, identity):
                raise refused("dependency_unavailable", "captured project pack object changed")
        return self._materializations(prepared)

    def _materializations(self, prepared):
        from .timeline_materialization import materialization_join

        def captured(revision):
            if revision not in self.__closures:
                raise refused("dependency_unavailable", "materialization requires a private parent capture")
            return self.__closures[revision]

        allocations = materialization_join(prepared, self.__project, self.__timeline, captured)
        if allocations:
            for record in prepared["records"]["commands"]:
                if record["command"]["op"] == "timeline.inverse" or not any(
                        d["key"].startswith("materialization.source:") for d in record["dependencies"]):
                    continue
                ordinal = record["ordinal"]
                commands = self.__request["commands"]
                if (type(ordinal) is not int or not 0 <= ordinal < len(commands)
                        or canonical_json(commands[ordinal].get("bindings")) != canonical_json(record["command"].get("bindings"))):
                    raise ValidationError("materialization bindings differ from sealed request")
        return allocations

    def _validate_producer_consumption(self, prepared):
        from .timeline_commit_producer_checkpoint import check_producer_consumption
        for capture in self._producer_captures(prepared):
            check_producer_consumption(self.__service.store, capture["pin"]["task_id"])

    def persist(self, prepared, publication_id, revision_id):
        from .timeline_commit_inputs import DocumentInputLink, persist_document_input_links
        links = []
        for ordinal, pin in enumerate(prepared["canonical_document"]["dependency_manifest"]["documents"]):
            capture = self.__documents[canonical_json(pin)]
            kind = "transcript" if capture.document["kind"] == "media.transcript" else "source"
            links.append(DocumentInputLink(capture, kind, ordinal))
        persist_document_input_links(self.__service.store.conn, project_id=self.__project,
                                     timeline_id=self.__timeline, publication_id=publication_id,
                                     revision_id=revision_id, links=links)
        from .timeline_commit_producer_checkpoint import persist_producer_checkpoint
        persist_producer_checkpoint(self.__store, self.__context, self._producer_captures(prepared),
                                    publication_id, revision_id)

    def _prepared(self, prepared):
        if self.__closed:
            raise AuthorizationError("timeline commit port is closed")
        prepared = detached(prepared)
        self._materializations(prepared)
        if prepared["expected_head"] not in self.__observed.values():
            raise refused("history_unavailable", "candidate head was not observed through this port",
                          diagnostic_reason="port_candidate_head_unobserved")
        restore = any(item.get("op") == "timeline.restore" for item in self.__request["commands"])
        if restore and prepared["records"]["restored_from"] != self.__request["commands"][0]["args"]:
            raise ValidationError("restore recorder must preserve the exact historical source pins")
        base = {"revision_id": self.__request["base_revision_id"],
                "publication_id": self.__request["base_publication_id"]}
        if restore and prepared["expected_head"] != base:
            raise refused("stale_head", "restore head pair changed", current=prepared["expected_head"])
        return prepared

    def preview(self, prepared):
        try:
            if not self.__request.get("dry_run", False):
                raise refused("preview_requires_dry_run", "preview requires dry_run")
            prepared = self._prepared(prepared)
            result = self.__store.preview(self.__context, prepared, authorize=self.__authorize, inputs=self)
            self.__preview = copy.deepcopy(result)
            return copy.deepcopy(result)
        finally:
            self.__sequential_capture = None

    def accept(self, prepared):
        from .timeline_commit_execution import current_commit_timing
        timing = current_commit_timing()
        if timing is None:
            return self._accept(prepared)
        with timing.stage("port_store_accept"):
            return self._accept(prepared)

    def _accept(self, prepared):
        from .timeline_commit import StaleHead
        try:
            if self.__request.get("dry_run", False):
                raise refused("dry_run_accept", "dry run cannot accept")
            prepared = self._prepared(prepared)
            return self.__store.accept(self.__context, prepared, authorize=self.__authorize, inputs=self)
        except StaleHead as exc:
            if any(item.get("op") == "timeline.restore" for item in self.__request["commands"]):
                raise refused("stale_head", "restore head pair changed", current=exc.current_head) from exc
            raise
        finally:
            self.__sequential_capture = None

    def _validate_sequential_execution(self, prepared, source, base, continuations, history):
        capture = self.__sequential_capture
        self.__sequential_capture = None
        if capture is None:
            return None
        from .timeline_commit_auth import validate_sequential_capture
        proof = validate_sequential_capture(
            self.__request, prepared, capture, source, base, continuations, history,
        )
        proof["retained_capture"] = capture
        return proof

    def verify_outcome(self, outcome):
        if isinstance(outcome, dict) and outcome.get("receipt", True) is None and outcome != self.__preview:
            raise ValidationError("provider preview differs from validated candidate")


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


def _source_kind(conn, project_id, pin, retained):
    from .timeline_commit_inputs import PROJECT_PACK_KIND, TRANSCRIPT_KIND
    row = None
    if retained:
        row = conn.execute(
            "SELECT kind FROM timeline_document_input_bindings WHERE project_id=? AND document_id=? "
            "AND document_version=? AND content_digest=?",
            (project_id, pin["document_id"], pin["version"], pin["content_digest"]),
        ).fetchone()
    if row is None:
        row = conn.execute("SELECT kind FROM project_documents WHERE project_id=? AND id=?",
                           (project_id, pin["document_id"])).fetchone()
    if row is None:
        return None
    if not (row["kind"].endswith(".config") or row["kind"] in {PROJECT_PACK_KIND, TRANSCRIPT_KIND}):
        raise refused("dependency_unavailable", "source input requires a registered config or project pack kind")
    return row["kind"]


def _linked_pins(conn, project_id):
    return [{"document_id": row[0], "version": int(row[1]), "content_digest": row[2]} for row in conn.execute(
        "SELECT DISTINCT document_id, document_version, content_digest FROM timeline_document_input_links "
        "WHERE project_id=?", (project_id,)).fetchall()]


def read_project_source_document(service, project_id, pin):
    """Read one exact retained config or project pack Document for a public caller.

    Same authorized closure and custody checks as ``read_project_pack_object``;
    the result is the VerifiedDocument the commit port's ``config_source`` returns.
    """
    from .timeline_commit_inputs import PROJECT_PACK_KIND, PROJECT_PACK_SCHEMA, capture_document_input
    from .timeline_commit_validation import validate_commit_value
    validate_commit_value(pin, "DocumentPin")
    conn = service.store.conn
    reachable = _linked_pins(conn, project_id)
    kind = _source_kind(conn, project_id, pin, pin in reachable)
    capture = capture_document_input(conn, project_id, pin, reachable_pins=reachable, expected_kind=kind,
                                     expected_schema=PROJECT_PACK_SCHEMA if kind == PROJECT_PACK_KIND else None)
    return {"pin": capture.pin, "document": capture.document}


def _pack_object(service, project_id, capture, object_id):
    from .timeline_commit_inputs import PROJECT_PACK_KIND, pack_snapshot_objects, read_pack_snapshot_object
    if capture is None or capture.document["kind"] != PROJECT_PACK_KIND:
        raise refused("dependency_unavailable", "object read requires a captured project pack document")
    descriptors = [value for value in pack_snapshot_objects(capture.document["content"])
                   if value["object_id"] == object_id]
    if not descriptors:
        raise refused("dependency_unavailable", "object is outside the captured project pack document")
    data, identity = read_pack_snapshot_object(
        service.store.conn, service.cas, project_id, descriptors[0], max_bytes=service.max_object_bytes,
    )
    return descriptors[0], data, identity


def read_project_pack_object(service, project_id, pin, object_id):
    """Read one exact retained pack object for a public caller.

    The authorized closure is every document pin linked by an accepted
    timeline record in this project, so a pin survives a live V2, removal and
    restart exactly as it does for a commit request. Nothing is written.
    """
    from .timeline_commit_inputs import PROJECT_PACK_KIND, PROJECT_PACK_SCHEMA, capture_document_input
    from .timeline_commit_validation import validate_commit_value
    validate_commit_value(pin, "DocumentPin")
    validate_commit_value(object_id, "Digest")
    conn = service.store.conn
    reachable = _linked_pins(conn, project_id)
    capture = capture_document_input(conn, project_id, pin, reachable_pins=reachable,
                                     expected_kind=PROJECT_PACK_KIND, expected_schema=PROJECT_PACK_SCHEMA)
    descriptor, data, _ = _pack_object(service, project_id, capture, object_id)
    return {**descriptor, "bytes_base64": base64.b64encode(data).decode("ascii")}


def verify_text_object(conn, cas, project_id, selection):
    return _verify_text_object(conn, cas, project_id, selection, TEXT_MEDIA_TYPE)


def verify_retained_text_object(conn, cas, binding, selection):
    """Reuse main's exact text/plain descriptor from this binding's present history."""
    from .service import RuntimeService

    events = RuntimeService._text_binding_events(conn, binding)
    expected = {"binding_id": binding["id"], "project_id": binding["project_id"],
                "shot_id": binding["shot_id"], "kind": binding["kind"], "slot": binding["slot"],
                "media_id": selection.get("object_id"), "content_hash": selection.get("digest"),
                "byte_size": selection.get("size"), "mime_type": selection.get("media_type")}
    for event in events:
        payload = json.loads(event["payload_json"])
        # Original main events omit scope/size/MIME; those remain in the binding
        # identity and immutable object metadata, checked below.
        if (payload.get("state", "present") == "present"
                and all(payload.get(key) == expected[key] for key in ("binding_id", "media_id", "content_hash"))
                and all(payload[key] == value for key, value in expected.items() if key in payload)):
            return _verify_text_object(conn, cas, binding["project_id"], selection, "text/plain")
    raise ConflictError("legacy text descriptor is outside this binding's retained present history")


def _verify_text_object(conn, cas, project_id, selection, media_type):
    if (not isinstance(selection, dict) or set(selection) != {"object_id", "digest", "size", "media_type"}
            or not all(isinstance(selection[k], str) and _OBJECT_ID.match(selection[k]) for k in ("object_id", "digest"))
            or selection["object_id"] != selection["digest"]
            or type(selection["size"]) is not int or not 0 <= selection["size"] <= TEXT_MAX_BYTES
            or selection["media_type"] != media_type):
        raise ValidationError(f"text selection requires object_id == digest, size within 1 MiB and {media_type}")
    bare = selection["digest"][7:]
    row = conn.execute("SELECT o.size, o.media_type FROM objects o JOIN project_objects p ON p.digest=o.digest "
                       "WHERE p.project_id=? AND p.relation='managed' AND o.digest=?", (project_id, bare)).fetchone()
    if row is None:
        raise NotFoundError("selected text is not a managed project object")
    if row["size"] != selection["size"] or row["media_type"] != selection["media_type"]:
        raise ConflictError("selected text size or media type changed")
    data = cas.read(bare)
    if len(data) != row["size"]:
        raise ConflictError("selected text bytes changed")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("selected text is not valid UTF-8") from exc
    return {**selection, "utf8": True}


class MediaReads:
    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.realm = service.realm
        self.cas = service.cas

    def selection(self, project_id, *, asset=None, generation_id=None, variant_id=None,
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

    @staticmethod
    def _variant_matches(association, metadata):
        if {"output_port", "group_key", "variant_key", "ordinal"} <= metadata.keys():
            return all(metadata[key] == association[key] for key in ("output_port", "group_key", "variant_key", "ordinal"))
        return (metadata.get("source_task_id") == association["task_id"]
                and metadata.get("output_name") == association["output_port"]
                and metadata.get("output_ordinal") == association["ordinal"])

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
            "SELECT v.id, v.generation_id, v.object_id, v.metadata_json, g.project_id FROM generation_variants v "
            "JOIN generations g ON g.id=v.generation_id WHERE g.project_id=? AND v.generation_id=? AND v.object_id=?",
            (project_id, association["generation_id"], association["object_id"][7:]),
        ).fetchall()
        variants = [row for row in variants if self._variant_matches(association, json.loads(row["metadata_json"]))]
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
            associations = self.store.conn.execute(
                "SELECT association_id FROM managed_output_associations WHERE project_id=? AND generation_id=? AND object_digest=?",
                (project_id, selection["generation_id"], row["object_digest"]),
            ).fetchall()
            matched = [self.store.get_managed_output(item["association_id"]) for item in associations]
            matched = [item for item in matched if self._variant_matches(item, variant_metadata)]
            if associations and len(matched) != 1:
                raise ConflictError("selected variant has no unique exact managed output binding")
            if matched:
                association, variant = self._output_selection_binding(project_id, matched[0]["association_id"])
                if (variant["id"] != selection["variant_id"]
                        or association["size"] != entry["size"] or association["media_type"] != entry["media_type"]):
                    raise ConflictError("selected media output identity changed")
                record["variant"]["managed_output"] = {key: association[key] for key in (
                    "association_id", "task_id", "attempt_id", "project_id", "generation_id", "object_id",
                    "output_port", "group_key", "variant_key", "ordinal", "role", "size", "media_type",
                    "filename", "durability", "lifecycle", "provenance",
                )}
            if entry["media_type"].startswith(("video/", "audio/")) and "duration_seconds" not in entry:
                raise ValueError("selected audio/video requires intrinsic duration")
            # A selected command input is authoritative only while its exact
            # managed object bytes still match the catalog size and digest.
            # Keep this scoped to consumed selections; the acceptance closure
            # remains responsible for its existing manifest checks.
            self.service._verify_child_object_bytes(
                row["object_digest"], row["size"], label="selected media CAS object",
            )
            record["catalog_digest"] = digest(record)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValidationError("invalid selected media metadata") from exc
        if "catalog_digest" in selection and selection["catalog_digest"] != record["catalog_digest"]:
            raise ConflictError("selected media catalog digest changed")
        return record

    def selected(self, project_id, selection):
        from .timeline_commit_validation import validate_commit_value
        validate_commit_value(selection, "MediaSelection")
        if not isinstance(selection, dict) or set(selection) != {"asset", "generation_id", "variant_id", "object_id", "catalog_digest"}:
            raise ValidationError("selected media requires all five exact identity fields")
        record = self._selected_project_media(project_id, selection)
        return {"selection": {key: record[key] for key in selection},
                **{key: record["entry"][key] for key in ("media_type", "size", "duration_seconds", "width", "height") if key in record["entry"]}}

    def raw_media_info(self, project_id, pin):
        """Verify one managed raw object through one opened CAS descriptor."""
        if (not isinstance(pin, dict) or set(pin) != {"media_id", "content_digest"}
                or not isinstance(pin["media_id"], str) or not _OBJECT_ID.fullmatch(pin["media_id"])
                or pin["content_digest"] != pin["media_id"]):
            raise ValidationError("raw media info requires one exact media pin")
        project = self.store.get_project(project_id)
        if project["id"] != project_id or project["realm_id"] != self.realm["id"]:
            raise AuthorizationError("raw media info project is outside the request realm")
        bare = pin["media_id"][7:]
        row = self.store.conn.execute(
            "SELECT o.digest, o.size, o.media_type FROM objects o "
            "JOIN project_objects p ON p.digest=o.digest "
            "WHERE p.project_id=? AND p.relation='managed' AND o.digest=?",
            (project_id, bare),
        ).fetchone()
        if row is None:
            raise NotFoundError("raw media is not a managed project object")
        with self.cas.open(bare) as stream:
            self.service._verify_open_file(
                stream.fileno(), bare, row["size"], label="raw media CAS object",
            )
        return {"object_id": pin["media_id"], "media_type": row["media_type"], "size": row["size"]}

    def text(self, project_id, selection):
        """Exact UTF-8 text read; retention is the manifest media pin, as for selected media."""
        return verify_text_object(self.store.conn, self.cas, project_id, selection)

    def narration(self, project_id, refs):
        from .timeline_commit_validation import validate_commit_value
        validate_commit_value(refs, "NarrationTakeRefs")
        if not isinstance(refs, dict) or set(refs) != {"speech", "speech_words", "speech_manifest"}:
            raise ValidationError("narration requires the exact three managed refs")
        associations, documents, dependencies = [], {}, set()
        speech = None
        for port, ref in refs.items():
            if (not isinstance(ref, dict) or set(ref) != {"association_id", "object_id", "version"}
                    or type(ref["version"]) is not int or ref["version"] < 1
                    or not isinstance(ref["object_id"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", ref["object_id"])):
                raise ValidationError("invalid managed narration ref")
            association = self.store.get_managed_output(ref["association_id"])
            if association["project_id"] != project_id:
                raise NotFoundError("narration input is outside the selected project")
            if (association["object_id"] != ref["object_id"] or association["lifecycle"]["version"] != ref["version"]
                    or association["output_port"] != port or association["durability"] != "durable"
                    or association["lifecycle"]["state"] not in {"available", "promoted"}):
                raise ConflictError("narration managed output identity changed")
            task = self.store.conn.execute(
                "SELECT t.status, t.result_json, t.attempt_id, t.capability, r.project_id FROM tasks t "
                "JOIN runs r ON r.id=t.run_id WHERE t.id=?", (association["task_id"],),
            ).fetchone()
            attempt = self.store.conn.execute("SELECT * FROM attempts WHERE id=?", (association["attempt_id"],)).fetchone()
            outputs = json.loads(task["result_json"] or "{}").get("outputs", []) if task else []
            matches = [item for item in outputs if self.store._generation_publish_output_key(item) == (
                association["output_port"], association["group_key"], association["variant_key"], association["ordinal"])]
            if (not task or task["status"] != "completed" or task["project_id"] != project_id
                    or task["attempt_id"] != association["attempt_id"] or not attempt or not attempt["settled"]
                    or attempt["task_id"] != association["task_id"] or len(matches) != 1
                    or any(matches[0].get(key) != expected for key, expected in (
                        ("kind", "object"), ("digest", ref["object_id"]),
                        ("size", association["size"]), ("media_type", association["media_type"])))):
                raise ConflictError("narration is not an exact settled task result")
            if any(association["provenance"].get(key) != expected for key, expected in (
                    ("task_id", association["task_id"]), ("attempt_id", association["attempt_id"]),
                    ("capability_id", task["capability"]), ("executor_id", attempt["executor_id"]),
                    ("fence", attempt["fence"]), ("runtime_epoch", attempt["runtime_epoch"]))):
                raise ConflictError("narration attempt provenance changed")
            owned = self.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
                                            (project_id, ref["object_id"][7:])).fetchone()
            if owned is None:
                raise ConflictError("narration object lacks current managed ownership")
            data = self.cas.read(ref["object_id"][7:])
            if "sha256:" + hashlib.sha256(data).hexdigest() != ref["object_id"] or len(data) != association["size"]:
                raise ConflictError("narration object bytes changed")
            dependencies.add(ref["object_id"])
            if association.get("manifest_ref") not in (None, refs["speech_manifest"]["object_id"]):
                raise ConflictError("narration manifest linkage disagrees with the declared take")
            if port == "speech":
                if not association["media_type"].startswith("audio/"):
                    raise ValidationError("narration speech must be audio")
                speech = {key: association[key] for key in ("object_id", "size", "media_type")}
            else:
                if association["media_type"] != "application/json":
                    raise ValidationError("narration auxiliary output must be JSON")
                documents[port] = detached(json.loads(data))
            associations.append(association)
        if len({(item["task_id"], item["attempt_id"]) for item in associations}) != 1:
            raise ValidationError("narration refs must name one settled attempt")
        manifest, words = documents["speech_manifest"], documents["speech_words"]
        validate_narration_artifacts(refs, manifest, words)
        speech["duration_seconds"] = manifest["duration_seconds"]
        return {"refs": copy.deepcopy(refs), "speech": speech, "manifest": manifest, "words": words,
                "dependency_objects": sorted(dependencies),
                "dependency_digest": digest(sorted(associations, key=lambda item: item["output_port"]))}


def validate_narration_artifacts(refs, manifest, words):
    audio = refs['speech']['object_id'][7:]
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1 or not isinstance(manifest.get('text'), str)
            or not manifest['text'] or not isinstance(manifest.get('settings'), dict)
            or manifest.get('text_sha256') != hashlib.sha256(manifest['text'].encode()).hexdigest()
            or manifest.get('audio_sha256') != audio):
        raise ValidationError('narration manifest identity mismatch')
    duration = manifest.get('duration_seconds')
    if (type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0
            or not isinstance(words, dict) or type(words.get('schema_version')) is not int
            or words['schema_version'] != 1 or words.get('audio_sha256') != audio
            or type(words.get('duration_seconds')) not in (int, float)
            or words['duration_seconds'] != duration
            or not isinstance(words.get('words'), list) or not words['words']):
        raise ValidationError('narration word/audio duration mismatch')
    previous = 0
    for row in words['words']:
        if (not isinstance(row, dict) or not isinstance(row.get('word'), str) or not row['word']
                or any(type(row.get(k)) not in (int, float) or not math.isfinite(row[k])
                       for k in ('start_s', 'end_s'))
                or not previous <= row['start_s'] < row['end_s'] <= duration):
            raise ValidationError('invalid narration word timing')
        previous = row['end_s']


