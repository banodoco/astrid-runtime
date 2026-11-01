"""Owner-local execution exclusion; the command ledger is the only journal."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import sys
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps

from .errors import ProtocolError, RuntimeErrorBase
from .timeline_commit_store import detached, reject, request_identity, scope

_REQUEST_ID_RE = re.compile(r"^[a-f0-9]{32}$")
_PUBLIC_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")
_MAX_EXCEPTION_CLASSES = 8
_MAX_FRAMES = 32
_MAX_DIAGNOSTIC_BYTES = 4096
_MAX_METADATA_BYTES = 128
_SAFE_CLASS_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.(?:[A-Za-z_][A-Za-z0-9_]*|<locals>))*$"
)
_SAFE_FILENAME_RE = re.compile(r"^(?:[A-Za-z0-9_.-]+|<[^<>\r\n]{1,64}>)$")
_SAFE_REASON_RE = re.compile(r"^(?:[a-z_]+|catchall:[A-Za-z0-9_.<>:-]{1,256})$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$")
_PUBLIC_REQUEST_ID = ContextVar("timeline_public_request_id", default=None)
_IDEMPOTENCY_KEY = ContextVar("timeline_idempotency_key", default=None)
_COMMIT_TIMING = ContextVar("timeline_commit_timing", default=None)
_LOGGER = logging.getLogger(__name__)
_TIMING_FIELDS = (
    "handler",
    "service_admission",
    "initial_replay_lookup",
    "provider_commit",
    "port_store_accept",
    "close",
    "durable_reconciliation",
    "wire_response",
    "total",
)
_MAX_TIMING_MS = 24 * 60 * 60 * 1000


def _new_request_id():
    """Create the private Runtime correlation value for one commit request."""
    return secrets.token_hex(16)


def _validated_request_id(value):
    if type(value) is str and _REQUEST_ID_RE.fullmatch(value):
        return value
    return _new_request_id()


def _metadata_digest(value):
    if not isinstance(value, str):
        return "sha256:invalid"
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _public_request_id_hash(value):
    """Return a bounded, one-way correlation value for the HTTP request id."""
    if not isinstance(value, str) or not _PUBLIC_REQUEST_ID_RE.fullmatch(value):
        return None
    return "sha256:" + hashlib.sha256(value.encode("ascii")).hexdigest()


def _idempotency_key_hash(value):
    """Return the helper-compatible hash for one accepted header value."""
    if not isinstance(value, str) or not _IDEMPOTENCY_KEY_RE.fullmatch(value):
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextmanager
def public_request_id_scope(value):
    token = _PUBLIC_REQUEST_ID.set(value)
    try:
        yield
    finally:
        _PUBLIC_REQUEST_ID.reset(token)


@contextmanager
def idempotency_key_scope(value):
    token = _IDEMPOTENCY_KEY.set(value)
    try:
        yield
    finally:
        _IDEMPOTENCY_KEY.reset(token)


def current_public_request_id():
    return _PUBLIC_REQUEST_ID.get()


def current_idempotency_key():
    return _IDEMPOTENCY_KEY.get()


@dataclass
class CommitTiming:
    """Request-local, source-only timing data for one timeline commit.

    This is deliberately kept out of the commit context and response envelope:
    timings must never affect request identity, replay, or durable receipts.
    The fixed field set and millisecond cap keep the debug record bounded.
    """

    request_id: str | None = None
    stages: dict = field(default_factory=dict)
    _started: dict = field(default_factory=dict)
    outcome: str = "unknown"
    emitted: bool = False

    def set_request_id(self, request_id):
        if request_id is not None:
            self.request_id = _validated_request_id(request_id)

    def begin(self, name):
        if name in _TIMING_FIELDS:
            self._started[name] = time.monotonic_ns()

    def end(self, name):
        started = self._started.pop(name, None)
        if started is None:
            return
        elapsed = max(0, time.monotonic_ns() - started)
        self.stages[name] = min(_MAX_TIMING_MS, int(round(elapsed / 1_000_000)))

    @contextmanager
    def stage(self, name):
        self.begin(name)
        try:
            yield
        finally:
            self.end(name)

    def mark_outcome(self, result):
        if self.outcome == "replay":
            return
        if isinstance(result, dict):
            if result.get("receipt") is not None:
                self.outcome = result.get("data", {}).get("status", "accepted")
            elif result.get("details", {}).get("status") in {"conflict", "refused", "invalid"}:
                self.outcome = result["details"]["status"]

    def mark_replay(self, result):
        self.mark_outcome(result)
        self.outcome = "replay"

    def finish(self):
        for name in tuple(self._started):
            self.end(name)
        values = {name: int(self.stages.get(name, 0)) for name in _TIMING_FIELDS}
        values["total"] = min(_MAX_TIMING_MS, max(values["total"], values["handler"]))
        return values

    def emit(self):
        if self.emitted:
            return
        self.emitted = True
        payload = {
            "event": "timeline_commit_timing",
            "request_id": _validated_request_id(self.request_id),
            "outcome": self.outcome,
            "timings_ms": self.finish(),
        }
        public_hash = _public_request_id_hash(current_public_request_id())
        if public_hash is not None:
            payload["public_request_id_hash"] = public_hash
        key_hash = _idempotency_key_hash(current_idempotency_key())
        if key_hash is not None:
            payload["idempotency_key_sha256"] = key_hash
        # Successful timing records are DEBUG-only: operators can opt in for a
        # bounded sample without turning every commit into an info log.
        line = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        if len((line + "\n").encode("utf-8")) <= _MAX_DIAGNOSTIC_BYTES:
            _LOGGER.debug("runtime.timeline_commit.timing %s", line)


def current_commit_timing():
    return _COMMIT_TIMING.get()


def start_commit_timing(request_id=None):
    timing = CommitTiming(request_id=request_id)
    timing.begin("total")
    return timing, _COMMIT_TIMING.set(timing)


def finish_commit_timing(timing, token):
    try:
        timing.emit()
    finally:
        _COMMIT_TIMING.reset(token)


def timed_timeline_commit(function):
    """Keep direct service callers observable without changing the contract."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        timing = current_commit_timing()
        token = None
        if timing is None:
            timing, token = start_commit_timing()
        try:
            result = function(*args, **kwargs)
            timing.mark_outcome(result)
            return result
        except BaseException:
            timing.outcome = "failure"
            raise
        finally:
            if token is not None:
                finish_commit_timing(timing, token)
    return wrapped


def _safe_metadata(value, pattern):
    if not isinstance(value, str):
        return "sha256:invalid"
    try:
        if (len(value.encode("utf-8", "surrogatepass")) <= _MAX_METADATA_BYTES
                and pattern.fullmatch(value)):
            return value
    except (UnicodeError, TypeError):
        pass
    return _metadata_digest(value)


def _exception_class(kind):
    try:
        module = _safe_metadata(kind.__module__, _SAFE_CLASS_RE)
        qualname = _safe_metadata(kind.__qualname__, _SAFE_CLASS_RE)
    except BaseException:  # noqa: BLE001 - diagnostics cannot affect the result
        return "sha256:invalid"
    return f"{module}.{qualname}"


def _exception_class_chain(error):
    classes = []
    seen = set()
    current = error
    while current is not None and id(current) not in seen and len(classes) < _MAX_EXCEPTION_CLASSES:
        seen.add(id(current))
        classes.append(_exception_class(type(current)))
        try:
            current = current.__cause__ or current.__context__
        except BaseException:  # noqa: BLE001 - diagnostics cannot affect the result
            break
    return classes


def _exception_frames(error):
    frames = []
    seen = set()
    current = error
    while current is not None and id(current) not in seen and len(frames) < _MAX_FRAMES:
        seen.add(id(current))
        try:
            traceback = current.__traceback__
        except BaseException:  # noqa: BLE001 - diagnostics cannot affect the result
            traceback = None
        while traceback is not None and len(frames) < _MAX_FRAMES:
            try:
                code = traceback.tb_frame.f_code
                filename = _safe_metadata(code.co_filename, _SAFE_FILENAME_RE)
                function = _safe_metadata(code.co_name, _SAFE_CLASS_RE)
                lineno = traceback.tb_lineno
                if type(lineno) is not int or not 0 <= lineno <= 1_000_000_000:
                    lineno = 0
                frames.append(f"{filename}:{lineno}:{function}")
                traceback = traceback.tb_next
            except BaseException:  # noqa: BLE001 - diagnostics cannot affect the result
                frames.append("sha256:invalid:0:sha256:invalid")
                break
        try:
            current = current.__cause__ or current.__context__
        except BaseException:  # noqa: BLE001 - diagnostics cannot affect the result
            break
    return frames


def _diagnostic_line(payload):
    def fits(value):
        return len((value + "\n").encode("utf-8")) <= _MAX_DIAGNOSTIC_BYTES

    line = "runtime.timeline_commit.error " + json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    if fits(line):
        return line
    compact = dict(payload)
    compact["exception_class_chain"] = [_metadata_digest(json.dumps(
        payload["exception_class_chain"], separators=(",", ":")
    ))]
    compact["frames"] = [_metadata_digest(json.dumps(
        payload["frames"], separators=(",", ":")
    ))]
    line = "runtime.timeline_commit.error " + json.dumps(
        compact, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    if fits(line):
        return line
    compact["exception_class_chain"] = []
    compact["frames"] = []
    return "runtime.timeline_commit.error " + json.dumps(
        compact, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


def _diagnostic_reason(error, reason):
    if reason is None:
        if error is None:
            return "catchall:unknown"
        return "catchall:" + _exception_class(type(error))
    if isinstance(reason, str) and _SAFE_REASON_RE.fullmatch(reason):
        return reason
    return "catchall:invalid"


def _emit_redacted_diagnostic(request_id, error=None, *, reason=None, public_request_id=None,
                              idempotency_key=None):
    """Write one bounded, source-only diagnostic without inspecting exception data."""
    try:
        payload = {
            "event": "timeline_commit_error",
            "request_id": _validated_request_id(request_id),
            "reason": _diagnostic_reason(error, reason),
            "exception_class_chain": _exception_class_chain(error),
            "frames": _exception_frames(error),
        }
        public_hash = _public_request_id_hash(
            public_request_id if public_request_id is not None else _PUBLIC_REQUEST_ID.get()
        )
        if public_hash is not None:
            payload["public_request_id_hash"] = public_hash
        key_hash = _idempotency_key_hash(
            idempotency_key if idempotency_key is not None else _IDEMPOTENCY_KEY.get()
        )
        if key_hash is not None:
            payload["idempotency_key_sha256"] = key_hash
        sys.stderr.write(_diagnostic_line(payload) + "\n")
    except BaseException:  # noqa: BLE001, S110 - diagnostics cannot affect the result
        # Diagnostics must never replace the original commit outcome.
        pass


_HISTORY_MESSAGE_TAGS = {
    "publication/revision pins disagree": "port_ancestor_pin_mismatch",
    "publication is outside request ancestry": "port_ancestor_outside_request",
    "history bounds disagree": "port_history_bounds_mismatch",
    "revision is outside request ancestry or declared source": "port_revision_outside_ancestry",
    "base pins disagree": "port_base_pins_mismatch",
    "candidate head was not observed through this port": "port_candidate_head_unobserved",
}

_HISTORY_SOURCE_TAGS = frozenset({
    "history_baseline_publication_dependency",
    "history_baseline_corrupt_publication_facts",
    "history_baseline_source_publication_missing",
    "history_baseline_unretained_document_dependency",
    "provider_history_guard",
    "history_provider_or_store_guard",
    "port_ancestor_pin_mismatch",
    "port_ancestor_outside_request",
    "port_history_bounds_mismatch",
    "port_revision_outside_ancestry",
    "port_base_pins_mismatch",
    "port_candidate_head_unobserved",
    "store_membership_missing",
    "store_head_missing",
    "store_head_revision_mismatch",
    "store_head_canonical_mismatch",
    "store_head_catalog_corrupt",
    "store_archived_scope_missing",
    "store_history_entry_missing",
    "store_history_ledger_mismatch",
    "store_history_bound_revision_mismatch",
    "store_history_bound_order_invalid",
    "store_history_chain_break",
    "store_history_through_mismatch",
    "store_revision_scope_missing",
    "store_revision_missing",
    "store_revision_dependency_missing",
    "store_shot_input_closure_ambiguous",
    "store_shot_parent_missing",
    "store_occurrence_rows_mismatch",
    "store_occurrence_row_mismatch",
    "store_dependency_rows_mismatch",
    "store_shot_revision_scope_missing",
    "store_history_ancestry_cycle",
    "store_history_base_outside_ancestry",
    "store_inverse_stage_targets_unavailable",
    "store_request_base_mismatch",
    "store_adopt_existing_head",
    "store_adopt_nonempty_scope",
    "store_adopt_existing_parent",
    "store_adopt_legacy_shell_mismatch",
    "store_adopt_prior_publication",
    "store_bootstrap_unpublished_head",
    "store_reference_projection_prepare_history",
    "store_reference_projection_apply_history",
})


def _history_diagnostic_reason(failure, *, source_reason=None):
    """Map an intentional history refusal to a bounded private source tag."""
    if not isinstance(failure, dict):
        return None
    details = failure.get("details")
    if not isinstance(details, dict) or details.get("reason") != "history_unavailable":
        return None
    if source_reason is not None:
        return source_reason if source_reason in _HISTORY_SOURCE_TAGS else None
    integrity_reason = details.get("integrity_reason")
    if isinstance(integrity_reason, str):
        if integrity_reason.startswith("publication_dependency_unavailable:"):
            return "history_baseline_publication_dependency"
        if integrity_reason.startswith("missing_or_corrupt_publication_facts:"):
            return "history_baseline_corrupt_publication_facts"
        if integrity_reason == "source_publication_missing":
            return "history_baseline_source_publication_missing"
        if integrity_reason == "unretained_document_dependency":
            return "history_baseline_unretained_document_dependency"
    message = failure.get("message")
    if message in _HISTORY_MESSAGE_TAGS:
        return _HISTORY_MESSAGE_TAGS[message]
    return "history_provider_or_store_guard"


class CommitOutcomeUnknown(RuntimeErrorBase):
    code = "not_ready"
    status = 503

    def __init__(self):
        super().__init__("Timeline commit outcome unavailable; retry the exact request",
                         details={"reason": "runtime_unavailable"})


@dataclass
class _Entry:
    request_hash: str
    users: int = 0
    lock: object = field(default_factory=threading.Lock)


class CommitExecutionCoordinator:
    def __init__(self, commit_store):
        self.commit_store = commit_store
        self._guard = threading.Lock()
        self._entries = {}

    @contextmanager
    def _execution(self, context):
        key = (scope(context), context["idempotency_key"])
        with self._guard:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry(context["request_hash"])
            mismatch = entry.request_hash != context["request_hash"]
            if not mismatch:
                entry.users += 1
        if mismatch:
            # A changed request may have entered after the original accepted.
            # The durable winner takes precedence over this transient hash.
            yield False
            return
        try:
            with entry.lock:
                yield True
        finally:
            with self._guard:
                entry.users -= 1
                if entry.users == 0:
                    del self._entries[key]

    def _lookup(self, context, authorize, *, diagnostic_request_id=None, public_request_id=None,
                idempotency_key=None):
        from .errors import AuthorizationError, ForbiddenError
        from .timeline_commit import CommitRejected

        try:
            return self.commit_store.lookup(context, authorize=authorize)
        except (CommitRejected, AuthorizationError, ForbiddenError):
            raise
        except Exception as exc:
            _emit_redacted_diagnostic(
                diagnostic_request_id, exc, public_request_id=public_request_id,
                idempotency_key=idempotency_key,
            )
            raise CommitOutcomeUnknown() from exc

    def execute(self, context, provider, port_factory, *, authorize, diagnostic_request_id=None,
                public_request_id=None, idempotency_key=None):
        timing = current_commit_timing()
        token = None
        if timing is None:
            timing, token = start_commit_timing(diagnostic_request_id)
        with self.commit_store.verification_scope():
            try:
                result = self._execute(context, provider, port_factory, authorize=authorize,
                                       diagnostic_request_id=diagnostic_request_id,
                                       public_request_id=public_request_id,
                                       idempotency_key=idempotency_key)
                timing.mark_outcome(result)
                return result
            except BaseException:
                timing.outcome = "failure"
                raise
            finally:
                if token is not None:
                    finish_commit_timing(timing, token)

    def _execute(self, context, provider, port_factory, *, authorize, diagnostic_request_id=None,
                 public_request_id=None, idempotency_key=None):
        context = detached(context)
        if request_identity(context) != context["request_hash"]:
            reject("invocation_mismatch", status=422)
        # There is intentionally no optimistic dependency/head read here. Even
        # callers with an earlier cache miss repeat this lookup after waiting.
        with self._execution(context) as acquired:
            timing = current_commit_timing()
            if timing is not None:
                timing.begin("initial_replay_lookup")
            try:
                replay = self._lookup(context, authorize, diagnostic_request_id=diagnostic_request_id,
                                      public_request_id=public_request_id,
                                      idempotency_key=idempotency_key)
            finally:
                if timing is not None:
                    timing.end("initial_replay_lookup")
            if replay is not None:
                if timing is not None:
                    timing.mark_replay(replay)
                return replay
            if not acquired:
                reject("idempotency_mismatch")
            outcome = error = port = None
            try:
                if timing is not None:
                    timing.begin("provider_commit")
                try:
                    port = port_factory(detached(context))
                    provider_context = detached(port._provider_context()) if hasattr(port, "_provider_context") else detached(context)
                    if any(provider_context[k] != context[k] for k in ("invocation", "idempotency_key", "request_hash", "realm_id", "publisher")):
                        raise ProtocolError("request port changed invocation identity")
                    try:
                        outcome = detached(provider.commit(provider_context, port))
                    except BaseException as exc:
                        if _is_unattributed_history_refusal(exc):
                            exc.__dict__["_diagnostic_reason"] = "provider_history_guard"
                        raise
                    if hasattr(port, "verify_outcome"):
                        port.verify_outcome(outcome)
                finally:
                    if timing is not None:
                        timing.end("provider_commit")
            except BaseException as exc:
                error = exc
            finally:
                if port is not None:
                    if timing is not None:
                        timing.begin("close")
                    try:
                        port.close()
                    except BaseException as exc:
                        if error is None:
                            error = exc
                    finally:
                        if timing is not None:
                            timing.end("close")
            # No provider completion, including a close/hook exception, can
            # supersede a committed winner. A failed read is an unknown outcome.
            if timing is not None:
                timing.begin("durable_reconciliation")
            try:
                replay = self._lookup(context, authorize, diagnostic_request_id=diagnostic_request_id,
                                      public_request_id=public_request_id,
                                      idempotency_key=idempotency_key)
            finally:
                if timing is not None:
                    timing.end("durable_reconciliation")
            if replay is not None:
                return replay
            if error is not None:
                raise error
            if not isinstance(outcome, dict):
                raise ProtocolError("provider returned no commit outcome")
            if "receipt" in outcome:
                if outcome["receipt"] is not None:
                    raise ProtocolError("provider claimed acceptance without a durable receipt")
                if outcome.get("data", {}).get("status") != "preview" or not context["request"].get("dry_run", False):
                    raise ProtocolError("provider returned an invalid preview")
            elif outcome.get("details", {}).get("status") not in {"conflict", "refused", "invalid"}:
                raise ProtocolError("provider returned an invalid commit failure")
            else:
                self.commit_store.clear_replay_memo()
            return outcome


def _is_unattributed_history_refusal(error):
    """Recognize a provider-owned history refusal without inspecting its text."""
    if getattr(error, "_diagnostic_reason", None) is not None:
        return False
    failure = getattr(error, "failure", None)
    details = failure.get("details") if isinstance(failure, dict) else getattr(error, "details", None)
    return isinstance(details, dict) and details.get("reason") == "history_unavailable"


def _is_history_failure(failure):
    details = failure.get("details") if isinstance(failure, dict) else None
    return isinstance(details, dict) and details.get("reason") == "history_unavailable"
