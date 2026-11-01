"""Settled producer authority, captured only through a requesting commit port."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from typing import TypedDict

from .cas import IO_CHUNK_BYTES
from .errors import RuntimeErrorBase, ValidationError
from .timeline_commit_port import command_leaves, refused


class ProducerAdmittedTarget(TypedDict):
    project_id: str
    timeline_id: str
    base_revision_id: str
    base_publication_id: str


class ProducerAttemptPin(TypedDict):
    task_id: str
    attempt_id: str
    executor_id: str
    fence: int
    runtime_epoch: int
    admitted_target: ProducerAdmittedTarget
    proposal_digest: str


class VerifiedProducerAttempt(TypedDict):
    pin: ProducerAttemptPin


_TARGET = {"project_id", "timeline_id", "base_revision_id", "base_publication_id"}
_PRODUCER = {"task_id", "attempt_id", "executor_id", "fence", "runtime_epoch"}
_PIN = _PRODUCER | {"admitted_target", "proposal_digest"}


def validate_pin(pin):
    if (not isinstance(pin, dict) or set(pin) != _PIN
            or any(not isinstance(pin.get(key), str) or not pin[key].strip()
                   for key in ("task_id", "attempt_id", "executor_id"))
            or any(type(pin.get(key)) is not int or pin[key] <= 0 for key in ("fence", "runtime_epoch"))
            or not isinstance(pin.get("proposal_digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin["proposal_digest"])):
        raise ValidationError("invalid producer attempt pin")
    target = pin["admitted_target"]
    if (not isinstance(target, dict) or set(target) != _TARGET
            or any(not isinstance(value, str) or not value.strip() for value in target.values())):
        raise ValidationError("invalid producer admitted target")
    try:
        json.dumps(pin, ensure_ascii=False).encode("utf-8")
    except UnicodeError as exc:
        raise ValidationError("invalid producer attempt pin Unicode") from exc


def value_equal(left, right):
    """JSON recipe equality: numeric value, distinct booleans, exact structure."""
    if type(left) in (int, float) and type(right) in (int, float):
        return (type(left) is int or math.isfinite(left)) and (type(right) is int or math.isfinite(right)) and left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(value_equal(value, right[key]) for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(value_equal(a, b) for a, b in zip(left, right))
    return left == right


def request_pin(request):
    commands = request["commands"]
    leaves = list(command_leaves(commands))
    guards = [item for item in leaves if item.get("op") == "producer.guard"]
    if not guards:
        return None
    guard = commands[0]
    if (len(guards) != 1 or guards[0] is not guard
            or set(guard) != {"schema_version", "op", "version", "select", "args"}
            or type(guard.get("schema_version")) is not int or guard["schema_version"] != 1
            or guard.get("version") != "1" or guard.get("select") is not None
            or not isinstance(guard.get("args"), dict) or set(guard["args"]) != {"pin"}
            or len(commands) < 2
            or any(item.get("op") in {"timeline.restore", "timeline.inverse"} for item in leaves)):
        raise refused("producer_attempt_mismatch", "producer guard must precede only the proposed commands")
    pin = guard["args"]["pin"]
    validate_pin(pin)
    return pin


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite JSON number")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    # Also rejects escaped unpaired surrogates, overflowed floats, and surrogates in keys.
    json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value


def _mismatch():
    return refused("producer_attempt_mismatch", "settled producer authority changed")


def _unavailable():
    return refused("producer_dependency_unavailable", "settled producer dependency is unavailable")


def _current_attempt(task, attempt):
    return (task["attempt_id"] == attempt["id"] and attempt["task_id"] == task["id"]
            and task["executor_id"] == attempt["executor_id"]
            and all(type(task[column]) is int and type(attempt[key]) is int
                    and task[column] == attempt[key] and attempt[key] > 0
                    for key, column in (("fence", "lease_fence"), ("runtime_epoch", "runtime_epoch"))))


class ProducerReads:
    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.conn = service.store.conn

    def _output(self, task, attempt, project, output, *, read_bytes=False):
        matches = [item for item in self.store.list_managed_outputs(task["id"])
                   if item["attempt_id"] == attempt["id"]
                   and self.store._generation_publish_output_key(output) == (
                       item["output_port"], item["group_key"], item["variant_key"], item["ordinal"])]
        if len(matches) != 1:
            raise _unavailable()
        association = matches[0]
        if (association["project_id"] != project or output.get("kind") != "object"
                or association["object_id"] != output.get("digest")
                or type(output.get("size")) is not int or association["size"] != output["size"]
                or association["media_type"] != output.get("media_type")
                or association["role"] != output.get("role", "output")
                or association["durability"] != "durable"
                or association["lifecycle"]["state"] not in {"available", "promoted"}
                or any(type(association["provenance"].get(key)) is not int
                       for key in ("fence", "runtime_epoch"))
                or any(association["provenance"].get(key) != value for key, value in (
                    ("task_id", task["id"]), ("attempt_id", attempt["id"]),
                    ("executor_id", attempt["executor_id"]), ("fence", attempt["fence"]),
                    ("runtime_epoch", attempt["runtime_epoch"]), ("capability_id", task["capability"])))):
            raise _unavailable()
        digest = association["object_id"][7:]
        obj = self.conn.execute("SELECT size, media_type FROM objects WHERE digest=?", (digest,)).fetchone()
        if (not obj or obj["size"] != output["size"] or obj["media_type"] != output["media_type"]
                or not self.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
                                         (project, digest)).fetchone()):
            raise _unavailable()
        if read_bytes and output["size"] > self.service.max_object_bytes:
            raise _unavailable()
        chunks = [] if read_bytes else None
        size, hasher = 0, hashlib.sha256()
        with self.service.cas.open(digest) as stream:
            while chunk := stream.read(IO_CHUNK_BYTES):
                size += len(chunk)
                if size > output["size"]:
                    raise _mismatch()
                hasher.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
        if size != output["size"] or hasher.hexdigest() != digest:
            raise _mismatch()
        return b"".join(chunks) if chunks is not None else None, association

    def _continuation(self, task, spec, project):
        deps = spec.get("runtime_dependencies", {})
        rows = self.store._continuation_rows(task["id"])
        admission = self.conn.execute("SELECT * FROM continuation_admissions WHERE continuation_task_id=?",
                                      (task["id"],)).fetchone()
        assembler = task["capability"] == "rendering.assemble_timeline"
        if not rows and not admission and not deps.get("edges") and not assembler:
            return None
        if (not rows or not admission or (assembler and len(rows) != 2)
                or deps.get("aggregation", {}).get("kind") != "ordered_cas_inputs"
                or [item["task_id"] for item in rows] != [edge["from_task_id"] for edge in deps["edges"]]
                or [item["ordinal"] for item in rows] != list(range(len(rows)))):
            raise _unavailable()
        children, inputs, captures, visuals = [], [], [], []
        for row in rows:
            child = self.conn.execute("SELECT t.*, r.project_id FROM tasks t JOIN runs r ON r.id=t.run_id WHERE t.id=?",
                                      (row["task_id"],)).fetchone()
            attempt = self.conn.execute("SELECT * FROM attempts WHERE id=?", (child["attempt_id"],)).fetchone()
            if (child["project_id"] != project or child["status"] != "completed" or not attempt
                    or not _current_attempt(child, attempt) or attempt["settled"] != 1):
                raise _unavailable()
            outputs = json.loads(child["result_json"])["outputs"]
            for output in outputs:
                if output["digest"] not in inputs:
                    inputs.append(output["digest"])
            selected = outputs
            if assembler:
                selected = [output for output in outputs if output.get("role") in {"primary", "primary_visual"}
                            and output.get("is_primary") is not False
                            and output.get("metadata", {}).get("status") != "superseded"]
                if len(selected) != 1 or not selected[0].get("media_type", "").startswith("video/"):
                    raise _unavailable()
                visuals.append(selected[0]["digest"])
            for output in selected:
                _, association = self._output(child, attempt, project, output)
                captures.append(association)
            children.append({"task_id": child["id"], "ordinal": row["ordinal"], "outputs": outputs})
        snapshot = {"children": children, "input_object_ids": inputs}
        stored = self.store._spec(task)
        if (json.loads(admission["dependency_snapshot_json"]) != snapshot
                or deps.get("resolved_children") != children or stored.get("input_object_ids") != inputs):
            raise _mismatch()
        order = deps["aggregation"].get("order", deps["aggregation"].get("object_ids", inputs))
        if assembler and order != visuals:
            raise _mismatch()
        return {"admission": dict(admission), "snapshot": snapshot, "associations": captures}

    def capture(self, context, pin):
        validate_pin(pin)
        request = context["request"]
        target = pin["admitted_target"]
        if target != {key: request[key] for key in _TARGET}:
            raise _unavailable()
        try:
            task = self.conn.execute("SELECT t.*, r.project_id FROM tasks t JOIN runs r ON r.id=t.run_id WHERE t.id=?",
                                     (pin["task_id"],)).fetchone()
            attempt = self.conn.execute("SELECT * FROM attempts WHERE id=?", (pin["attempt_id"],)).fetchone()
            if (not task or task["project_id"] != request["project_id"] or not attempt
                    or attempt["task_id"] != task["id"]):
                raise _unavailable()
            if (task["status"] != "completed" or not _current_attempt(task, attempt) or attempt["settled"] != 1
                    or any(task[column] != pin[key] or attempt[key] != pin[key] for key, column in (
                        ("executor_id", "executor_id"), ("fence", "lease_fence"), ("runtime_epoch", "runtime_epoch")))):
                raise _mismatch()
            stored = self.store._spec(task)
            spec = stored["spec"]
            publication = spec["runtime_dependencies"]["publication"]
            if publication["admitted_target"] != target:
                raise _unavailable()
            declared = spec.get("outputs", {}).get("authoring_proposal")
            if (not isinstance(declared, dict) or declared.get("type") != "file"
                    or declared.get("artifact_type") != "timeline/authoring-proposal"
                    or (publication.get("render") is not None and not isinstance(publication["render"], dict))):
                raise _unavailable()
            outputs = json.loads(task["result_json"])["outputs"]
            matches = [item for item in outputs if item.get("name") == "authoring_proposal"]
            if (len(matches) != 1 or matches[0].get("media_type") != "application/json"
                    or matches[0].get("output_port", matches[0].get("name")) != "authoring_proposal"):
                raise _unavailable()
            output = matches[0]
            raw, association = self._output(task, attempt, request["project_id"], output, read_bytes=True)
            proposal = _strict_json(raw)
            if (not isinstance(proposal, dict) or set(proposal) != {
                    "schema_version", "producer", "admitted_target", "commands", "rationale", "proposal_digest"}
                    or type(proposal["schema_version"]) is not int or proposal["schema_version"] != 1
                    or not isinstance(proposal["producer"], dict) or set(proposal["producer"]) != _PRODUCER
                    or not isinstance(proposal["commands"], list) or not proposal["commands"]
                    or not isinstance(proposal["rationale"], str)):
                raise _mismatch()
            derived = {**proposal["producer"], "admitted_target": proposal["admitted_target"],
                       "proposal_digest": proposal["proposal_digest"]}
            validate_pin(derived)
            unsigned = {key: value for key, value in proposal.items() if key != "proposal_digest"}
            encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            if (derived != pin or "sha256:" + hashlib.sha256(encoded).hexdigest() != pin["proposal_digest"]
                    or request_pin(request) != pin
                    or not value_equal(request["commands"][1:], proposal["commands"])
                    or not value_equal(request.get("rationale"), proposal["rationale"])):
                raise _mismatch()
            continuation = self._continuation(task, spec, request["project_id"])
            run = self.conn.execute("SELECT * FROM runs WHERE id=?", (task["run_id"],)).fetchone()
            return copy.deepcopy({"pin": pin, "proposal": proposal, "render_intent": publication.get("render"),
                "artifact": {"descriptor": output, "association": association},
                "identity": {**{key: context[key] for key in ("realm_id", "publisher", "idempotency_key", "request_hash")},
                             "project_id": request["project_id"], "timeline_id": request["timeline_id"]},
                "authority": {"task": dict(task), "attempt": dict(attempt), "run": dict(run), "spec": stored,
                              "continuation": continuation}})
        except (KeyError, TypeError, ValueError, UnicodeError, OSError, RecursionError, RuntimeErrorBase) as exc:
            raise _unavailable() from exc
