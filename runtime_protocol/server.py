from __future__ import annotations

import json
import math
import re
import socket
import sys
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .errors import RuntimeErrorBase, AuthorizationError, BodyTooLargeError, ConflictError, ForbiddenError, NotFoundError, ProtocolError, InvalidRequestError, RetiredRouteError
from .service import reject_retired_timeline_writer, validate_idempotency_key
from .cas import IO_CHUNK_BYTES


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_non_finite_json(value):
    raise ValueError(f"non-finite JSON value {value!r}")


def _validate_finite_json(value):
    """Reject overflowed JSON numbers after the decoder has produced them."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON value {value!r}")
        return
    if isinstance(value, list):
        for child in value:
            _validate_finite_json(child)
        return
    if isinstance(value, dict):
        for child in value.values():
            _validate_finite_json(child)


DOCUMENT_PIN = ("document_id", "version", "content_digest")
# Verified reads under /v1/projects/{project_id}/: path tail -> (exact query
# field sets, Runtime method, error message for any other query shape).
VERIFIED_READS = {
    ("media-selection",): (
        ({"asset", "generation_id", "variant_id"}, {"association_id", "object_id", "version"}),
        "get_project_media_selection", "exactly one complete media selection selector form is required"),
    ("media-selection", "verified"): (
        ({"asset", "generation_id", "variant_id", "object_id", "catalog_digest"},),
        "get_project_verified_media", "all five exact media selection fields are required"),
    ("document-inputs", "verified"): (
        ({*DOCUMENT_PIN},), "get_project_verified_document", "all three exact document pin fields are required"),
    ("document-objects", "verified"): (
        ({*DOCUMENT_PIN, "object_id"},), "get_project_verified_document_object", "all four exact document object fields are required"),
}


class RuntimeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    # The default TCPServer backlog is only five. A cold runtime receives a
    # burst of executor/client requests during launch, and an overflow resets
    # otherwise valid loopback connections before the handler can return the
    # durable idempotent replay. Keep a bounded backlog sized for the local
    # control-plane fan-in.
    request_queue_size = 64
    accepting_authenticated_requests = True

    def __init__(self, *args, **kwargs):
        self._maintenance_lock = threading.Lock()
        self._maintenance_thread = None
        self._maintenance_error = None
        super().__init__(*args, **kwargs)

    def service_actions(self):
        # serve_forever already polls every 0.5s, including when no clients or
        # workers are connected. Reuse the same fenced reaper as reads/claims.
        # SQLite may wait on an external writer or the shared store mutex;
        # neither wait may occupy the accept loop. Admit only one reaper.
        runtime = getattr(self, "runtime", None)
        if (runtime is None or not self.accepting_authenticated_requests
                or not self._maintenance_lock.acquire(blocking=False)):
            return
        try:
            error, self._maintenance_error = self._maintenance_error, None
            if error is not None:
                raise error
            self._maintenance_thread = threading.Thread(
                target=self._reap_task_lifetimes, args=(runtime,),
                name="astrid-runtime-lifetime-reaper", daemon=True,
            )
            self._maintenance_thread.start()
        except BaseException:
            self._maintenance_thread = None
            self._maintenance_lock.release()
            raise

    def _reap_task_lifetimes(self, runtime):
        try:
            runtime.reap_task_lifetimes()
        except RuntimeErrorBase:
            # Admission loss already revokes daemon readiness. Keep the
            # listener alive so its existing failure response remains usable.
            pass
        except BaseException as exc:
            # Preserve unexpected failures on the serving thread's next poll.
            self._maintenance_error = exc
        finally:
            self._maintenance_lock.release()

    def server_close(self):
        self.accepting_authenticated_requests = False
        super().server_close()
        # RuntimeDaemon closes its store after the listener. Drain the one
        # admitted reaper before that connection can be closed or replaced.
        if self._maintenance_thread is not None:
            self._maintenance_thread.join()

    def server_bind(self):
        if sys.platform == "win32":
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        # HTTPServer.server_bind() performs a reverse-DNS lookup after binding
        # but before it publishes server_port. Runtime listeners are loopback
        # only and publish their numeric endpoint, so retain TCPServer's bind
        # semantics while deriving the inherited metadata from that address.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class RuntimeHandler(BaseHTTPRequestHandler):
    server_version = "AstridRuntime/0.1"
    # Bound abandoned request bodies and clients that stop consuming responses.
    timeout = 30
    MAX_BODY_BYTES = 64 * 1024 * 1024
    TIMELINE_BODY_BYTES = 1024 * 1024
    REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")

    def log_message(self, *_):
        return

    def handle_one_request(self):
        # BaseHTTPRequestHandler reuses this instance for keep-alive requests;
        # the public id is stable only for the request currently being parsed.
        self._runtime_request_id = None
        return super().handle_one_request()

    def _request_id(self):
        current = getattr(self, "_runtime_request_id", None)
        if current:
            return current
        supplied = self.headers.get("X-Request-ID", "")
        value = supplied if self.REQUEST_ID_RE.fullmatch(supplied) else uuid.uuid4().hex
        self._runtime_request_id = value
        return value

    @property
    def runtime(self):
        return self.server.runtime  # type: ignore[attr-defined]

    def _identity(self, scope):
        if self.path.split("?", 1)[0] == "/v1/health":
            return {"actor": "health", "scopes": ["health"]}
        if not getattr(self.server, "accepting_authenticated_requests", True):
            raise AuthorizationError("runtime is not accepting authenticated requests")
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            raise AuthorizationError("bearer credential required")
        return self.server.credentials.require(value[7:], scope)  # type: ignore[attr-defined]

    def _header_values(self, name):
        if hasattr(self.headers, "get_all"):
            return self.headers.get_all(name, [])
        value = self.headers.get(name)
        return [] if value is None else [value]

    def _content_length(self, limit=None):
        """Strict framing, bounded decimal parsing, before touching the body."""
        values = self._header_values("Content-Length")
        value = values[0].strip() if len(values) == 1 else ""
        if not re.fullmatch(r"[0-9]{1,20}", value):
            raise ProtocolError("one Content-Length header is required and must be a non-negative decimal integer")
        length = int(value, 10)
        maximum = self.MAX_BODY_BYTES if limit is None else limit
        if length > maximum:
            raise BodyTooLargeError(f"request body exceeds {maximum} byte limit")
        return length

    def _binary_chunks(self):
        # Rejections/cancellations never leave unread framing on a reusable connection.
        self.close_connection = True
        encodings = self._header_values("Content-Encoding")
        if encodings and (len(encodings) != 1 or encodings[0].strip().lower() != "identity"):
            raise ProtocolError("binary Content-Encoding must be one identity value")
        if self._header_values("Trailer"):
            raise ProtocolError("chunk trailers are unsupported")
        maximum = self.runtime.max_object_bytes
        transfer = self._header_values("Transfer-Encoding")
        if transfer:
            if len(transfer) != 1 or transfer[0].strip().lower() != "chunked" or self._header_values("Content-Length"):
                raise ProtocolError("binary request requires either Content-Length or chunked Transfer-Encoding")
            total = 0
            while True:
                line = self.rfile.readline(8193)
                # Chunk extensions follow the token/quoted-string grammar;
                # arbitrary text after a semicolon is not valid framing.
                token = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
                quoted = rb'"(?:[\x09\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\x09\x20-\x7e\x80-\xff])*"'
                extension = rb"[ \t]*;[ \t]*" + token + rb"(?:[ \t]*=[ \t]*(?:" + token + rb"|" + quoted + rb"))?"
                if len(line) > 8192 or not re.fullmatch(rb"[0-9a-fA-F]{1,16}(?:" + extension + rb")*\r\n", line):
                    raise ProtocolError("malformed or incomplete chunk header")
                size = int(line.split(b";", 1)[0].strip(), 16)
                if size == 0:
                    if self.rfile.readline(8193) != b"\r\n":
                        raise ProtocolError("chunk trailers are unsupported or incomplete")
                    return
                total += size
                if total > maximum:
                    raise BodyTooLargeError(f"request body exceeds {maximum} byte limit")
                remaining = size
                while remaining:
                    chunk = self.rfile.read(min(remaining, IO_CHUNK_BYTES))
                    if not chunk:
                        raise ProtocolError("request body contains an incomplete chunk")
                    remaining -= len(chunk)
                    yield chunk
                if self.rfile.read(2) != b"\r\n":
                    raise ProtocolError("malformed or incomplete chunk terminator")
        else:
            remaining = self._content_length(maximum)
            while remaining:
                chunk = self.rfile.read(min(remaining, IO_CHUNK_BYTES))
                if not chunk:
                    raise ProtocolError("request body is shorter than Content-Length")
                remaining -= len(chunk)
                yield chunk

    def _read_raw_body(self, limit=None):
        if self._header_values("Transfer-Encoding"):
            raise ProtocolError("JSON requests require Content-Length without Transfer-Encoding")
        length = self._content_length(limit)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ProtocolError("request body is shorter than Content-Length")
        return raw

    def _prefetch_body(self, limit=None):
        """Read a declared request body before the store mutex is taken.

        A client that is still sending its body must not hold the lock every
        other database route waits on. A framing error is kept and raised
        only if the route reads the body, as it was before.
        """
        if not hasattr(self, "headers") or not (self._header_values("Content-Length") or self._header_values("Transfer-Encoding")):
            return
        try:
            self._prefetched_body = self._read_raw_body(limit)
        except RuntimeErrorBase as exc:
            self._prefetched_body = exc

    def _raw_body(self, limit=None):
        prefetched = getattr(self, "_prefetched_body", None)
        if isinstance(prefetched, RuntimeErrorBase):
            raise prefetched
        if prefetched is not None:
            return prefetched
        return self._read_raw_body(limit)

    def _body(self):
        raw = self._raw_body()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("request body must be valid JSON") from exc

    def _strict_json_body(self, label):
        """Parse an authoring request without normalizing its original body."""
        raw = self._raw_body(self.TIMELINE_BODY_BYTES)
        try:
            body = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_non_finite_json,
            ) if raw else {}
            _validate_finite_json(body)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProtocolError(f"{label} must be finite JSON without duplicate fields") from exc
        if not isinstance(body, dict):
            raise InvalidRequestError(f"{label} must be a JSON object")
        return body

    def _commit_body(self):
        return self._strict_json_body("commit request")

    def _restore_body(self):
        return self._strict_json_body("restore request")

    def _project_mutation_body(self):
        body = self._body()
        if not isinstance(body, dict):
            raise InvalidRequestError("request body must be a JSON object")
        return body

    def _timeline_options(self):
        body = self._body()
        if not isinstance(body, dict):
            raise InvalidRequestError("timeline options must be a JSON object")
        return body

    def _idempotency_key(self):
        key = self.headers.get("Idempotency-Key")
        if not key:
            raise ProtocolError("Idempotency-Key header is required")
        try:
            return validate_idempotency_key(key)
        except InvalidRequestError as exc:
            raise ProtocolError(str(exc)) from exc

    def _commit_idempotency_key(self):
        values = self._header_values("Idempotency-Key")
        if len(values) != 1:
            raise ProtocolError("one Idempotency-Key header is required")
        try:
            return validate_idempotency_key(values[0])
        except InvalidRequestError as exc:
            raise ProtocolError(str(exc)) from exc

    def _authorize_timeline_commit(self, publisher):
        identity = self._identity("projects:write")
        if identity.get("actor") != publisher:
            raise AuthorizationError("authenticated publisher changed during commit")
        return identity

    def _authorize_timeline_read(self, publisher):
        identity = self._identity("projects:read")
        if identity.get("actor") != publisher:
            raise AuthorizationError("authenticated publisher changed during timeline read")
        return identity

    @staticmethod
    def _timeline_path(project_id, timeline_id, suffix):
        return (
            f"/v1/projects/{quote(project_id, safe='')}/timelines/"
            f"{quote(timeline_id, safe='')}/{suffix}"
        )

    def _timeline_commit(self, project_id, timeline_id, path):
        if urlsplit(self.path).query:
            raise ProtocolError("timeline commit does not accept a query string")
        identity = self._identity("projects:write")
        body = self._commit_body()
        if body.get("project_id") != project_id or body.get("timeline_id") != timeline_id:
            raise ConflictError("commit project/timeline identity does not match the route")
        key = self._commit_idempotency_key()
        commit = getattr(self.runtime, "commit_timeline", None)
        if not callable(commit):
            from .timeline_commit_execution import (
                _emit_redacted_diagnostic,
                _new_request_id,
            )
            from .timeline_commit_provider import TimelineCommitUnavailable
            public_request_id = self._request_id()
            _emit_redacted_diagnostic(
                _new_request_id(), reason="timeline_commit_unavailable",
                public_request_id=public_request_id,
                idempotency_key=key,
            )
            raise TimelineCommitUnavailable()
        publisher = identity["actor"]

        def authorize():
            return self._authorize_timeline_commit(publisher)

        from .timeline_commit_execution import (
            idempotency_key_scope,
            public_request_id_scope,
        )
        with public_request_id_scope(self._request_id()), idempotency_key_scope(key):
            return self._send(200, commit(
                project_id,
                timeline_id,
                body,
                idempotency_key=key,
                publisher=publisher,
                invocation_path=self._timeline_path(project_id, timeline_id, "commit"),
                authorize=authorize,
            ))

    def _send(self, status, payload=None, *, headers=None, body=None, error=None, receipt=None, idempotency_key=None):
        if getattr(self, "_defer_response", False):
            self._pending_response = (status, payload, {
                "headers": headers, "body": body, "error": error,
                "receipt": receipt, "idempotency_key": idempotency_key,
            })
            return
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", self._request_id())
        for key, value in (headers or {}).items():
            self.send_header(key, str(value))
        if body is None:
            encoded = json.dumps(error if error is not None else payload, sort_keys=True).encode()
            self.send_header("Content-Type", "application/json")
        else:
            encoded = body
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)

    def _send_file(self, status, stream, start, length, headers):
        if getattr(self, "_defer_response", False):
            self._pending_file_response = (status, stream, start, length, headers)
            return
        try:
            self.send_response(status)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Request-ID", self._request_id())
            for key, value in headers.items():
                self.send_header(key, str(value))
            self.send_header("Content-Length", str(length))
            self.end_headers()
            self._response_started = True
            if self.command != "HEAD":
                stream.seek(start)
                remaining = length
                while remaining:
                    chunk = stream.read(min(remaining, IO_CHUNK_BYTES))
                    if not chunk:
                        self.close_connection = True
                        return
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        finally:
            stream.close()

    def _is_binary_io(self):
        if not hasattr(self, "path"):
            return False
        path = [unquote(x) for x in urlsplit(self.path).path.split("/") if x]
        if path == ["v1", "objects"] and self.command == "POST":
            return True
        if len(path) == 3 and path[:2] == ["v1", "objects"] and self.command in ("GET", "HEAD"):
            return True
        if (self.command == "GET" and len(path) == 6 and path[:2] == ["v1", "projects"]
                and path[3] == "objects" and path[5] == "location"):
            return True
        return (self.command == "POST" and len(path) == 4 and path[:2] == ["v1", "projects"]
                and path[3] in ("objects", "media-imports"))

    def _is_timeline_commit(self):
        path = [unquote(x) for x in urlsplit(getattr(self, "path", "")).path.split("/") if x]
        if getattr(self, "command", None) != "POST" or path[:2] != ["v1", "projects"]:
            return False
        commit = len(path) == 6 and path[3] == "timelines" and path[5] == "commit"
        restore = (
            len(path) == 8 and path[3] == "timelines"
            and path[5] == "composition-revisions" and path[7] == "restore"
        )
        return commit or restore

    def _error(self, exc):
        commits = getattr(self.runtime, "_timeline_commit_store", None)
        if commits is not None:
            commits.clear_replay_memo()
        if isinstance(exc, RuntimeErrorBase):
            payload = exc.as_dict()
            payload["request_id"] = self._request_id()
            self._send(exc.status, error=payload)
        else:
            request_id = self._request_id()
            # The client sees only the request id; the log keeps the cause.
            route = urlsplit(getattr(self, "path", "")).path
            print(f"Runtime internal error (request {request_id}, {getattr(self, 'command', '?')} {route}):\n"
                  + "".join(traceback.format_exception(exc)), file=sys.stderr, flush=True)
            self._send(500, error={"code": "internal_error", "message": "internal runtime error", "request_id": request_id})

    def _is_owner_identity_probe(self):
        """Select a read-only snapshot; route authentication is unchanged."""
        return (getattr(self, "command", None) == "GET"
                and urlsplit(getattr(self, "path", "")).path in {"/v1/health", "/v1/realm"}
                and getattr(self, "headers", {}).get("X-Astrid-Owner-Identity") == "1")

    def _require_update_context(self):
        raise AuthorizationError("updates require the trusted browser door")

    def _update_route(self):
        self.close_connection = True
        self._require_update_context()
        expected = {"/v1/update": "POST", "/v1/update/status": "GET"}
        if self.path not in expected or self.command != expected[self.path]:
            raise ProtocolError("exact update path and method required; no parameters")
        if any(self._header_values(name) for name in ("Transfer-Encoding", "Content-Encoding", "Trailer")):
            raise ProtocolError("update requests do not accept encoded or ambiguous framing")
        lengths = self._header_values("Content-Length")
        if (self.command == "POST" or lengths) and (len(lengths) != 1 or lengths[0] != "0"):
            raise ProtocolError("update requests require zero body bytes")
        from astrid_runtime.update import update_admission
        admission = update_admission(self.server.daemon_runtime)
        if self.command == "GET":
            return self._send(200, admission.status())
        return self._send(202, admission.request())

    def _route(self):
        path = [unquote(x) for x in urlsplit(self.path).path.split("/") if x]
        method = self.command
        if method == "POST" and len(path) == 5 and path[:3] == ["v1", "control", "tasks"] and path[4] == "abandon":
            identity = self._identity("admin")
            if identity.get("actor") != "owner":
                raise ForbiddenError("task abandon requires the Runtime owner actor")
            return self._send(200, self.runtime.abandon_task(path[3], self._body(),
                idempotency_key=self._idempotency_key(), identity=identity))
        if path == ["v1", "health"]:
            health = dict(self.runtime.health(identity_probe=True) if self._is_owner_identity_probe()
                          else self.runtime.health())
            # RuntimeService is also exercised without an owning daemon in
            # low-level protocol fixtures. Such a response has no startup
            # identity; real owner listeners replace this with the snapshot.
            health["identity"] = None
            daemon = getattr(self.server, "daemon_runtime", None)
            if daemon is not None:
                # Startup identity belongs to one owner instance. Read only
                # the defensive snapshot captured by RuntimeDaemon.start();
                # health must never recapture install records or checkouts.
                health["runtime_instance_id"] = getattr(
                    daemon, "startup_identity_instance_id", None
                )
                health["identity"] = getattr(daemon, "startup_identity", None)
                health["services"] = daemon.service_status()
            return self._send(200, health)
        if path == ["v1", "credentials"] and method == "POST":
            self._identity("credentials:provision")
            body = self._body()
            actor = str(body.get("actor_id") or "")
            token = str(body.get("credential") or "")
            scope = str(body.get("scope") or "")
            if not actor or not token or scope != "astrid":
                raise ProtocolError("actor_id, credential, and astrid scope are required")
            from .daemon import WORKER_ACTOR
            if actor == WORKER_ACTOR:
                raise ConflictError("the shared Worker actor requires exact owner credential control")
            from .door import PRODUCT_SCOPES
            scopes = list(PRODUCT_SCOPES)
            self.server.credentials.provision_static(actor, token, scopes)  # type: ignore[attr-defined]
            return self._send(201, {"actor_id": actor, "scope": scope})
        if path == ["v1", "handshake"] and method == "POST":
            identity = self._identity("handshake")
            body = self._body()
            body["authenticated_actor"] = identity["actor"]
            body["authenticated_scopes"] = identity.get("scopes", [])
            value = self.runtime.handshake(body)
            return self._send(200, value)
        if path == ["v1", "handshake"] and method == "GET":
            identity = self._identity("handshake")
            return self._send(200, self.runtime.handshake({"authenticated_actor": identity["actor"], "authenticated_scopes": identity.get("scopes", []), "requested_scopes": []}))
        if path == ["v1", "realm"] and method == "GET":
            self._identity("projects:read")
            owner_probe = self._is_owner_identity_probe()
            resource = dict(self.runtime.realm_resource(identity_probe=True)
                            if owner_probe else self.runtime.realm_resource())
            daemon = getattr(self.server, "daemon_runtime", None)
            if owner_probe and daemon is not None:
                resource["runtime_instance_id"] = getattr(daemon, "startup_identity_instance_id", None)
            return self._send(200, resource)
        if path == ["v1", "doctor"] and method == "GET":
            self._identity("admin")
            return self._send(200, self.runtime.doctor())
        if path == ["v1", "diagnostics"] and method == "GET":
            self._identity("projects:read")
            from astrid_runtime.diagnostics import diagnostics_report
            from astrid_runtime.paths import RuntimePaths
            paths = RuntimePaths.current(data_root=self.runtime.support_root.parent if self.runtime.support_root else None)
            support = self.runtime.doctor()
            report = diagnostics_report(paths, support)
            return self._send(200, {"report": report})
        if path == ["v1", "realm", "tombstone"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.tombstone(self._body()))
        if path == ["v1", "realm", "recover"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.recover_realm(self._body()))
        if path == ["v1", "realm", "purge"] and method == "POST":
            self._identity("admin")
            return self._send(200, self.runtime.purge(self._body()))
        if path == ["v1", "export"] and method == "GET":
            self._identity("admin")
            return self._send(200, self.runtime.export_structured())
        if path == ["v1", "backup"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("destination"):
                raise ProtocolError("destination is required")
            return self._send(201, self.runtime.backup(body["destination"]))
        if path == ["v1", "restore"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("backup") or not body.get("destination"):
                raise ProtocolError("backup and destination are required")
            return self._send(201, self.runtime.restore(body["backup"], body["destination"]))
        if path == ["v1", "replace"] and method == "POST":
            self._identity("admin")
            body = self._body()
            if not body.get("candidate"):
                raise ProtocolError("candidate is required")
            retain_superseded = body.get("retain_superseded", False)
            if not isinstance(retain_superseded, bool):
                raise ProtocolError("retain_superseded must be a boolean")
            daemon = getattr(self.server, "daemon_runtime", None)
            if daemon is None:
                raise ProtocolError("replacement is unavailable outside the owning daemon")
            return self._send(200, daemon.activate_candidate(body["candidate"], retain_superseded=retain_superseded))
        if len(path) == 3 and path[:2] == ["v1", "preferences"] and method in ("GET", "PUT"):
            identity = self._identity("projects:read" if method == "GET" else "projects:write")
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if set(query) - {"project_id"} or len(query.get("project_id", [])) > 1:
                raise ProtocolError("preferences accept only one optional project_id selector")
            project_id = query.get("project_id", [None])[0]
            if method == "GET":
                return self._send(200, self.runtime.get_preferences(path[2], project_id, identity=identity))
            body = self._project_mutation_body()
            if set(body) != {"content", "expected_version"}:
                raise ProtocolError("preferences require only content and expected_version")
            return self._send(200, self.runtime.update_preferences(path[2], body["content"], body["expected_version"], self._idempotency_key(), project_id, identity=identity))
        if len(path) == 4 and path[:3] == ["v1", "app-state", "user"] and method in ("GET", "PUT"):
            identity = self._identity("projects:read" if method == "GET" else "projects:write")
            if urlsplit(self.path).query:
                raise ProtocolError("app-state accepts no query parameters")
            if method == "GET":
                return self._send(200, self.runtime.get_app_state(path[3], identity=identity))
            body = self._project_mutation_body()
            if set(body) != {"content", "expected_version"}:
                raise ProtocolError("app-state requires only content and expected_version")
            return self._send(200, self.runtime.update_app_state(path[3], body["content"], body["expected_version"], self._idempotency_key(), identity=identity))
        if path == ["v1", "projects", "selection"] and method in ("GET", "PUT"):
            identity = self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                return self._send(200, self.runtime.current_project(identity["actor"]))
            body = self._project_mutation_body()
            if not isinstance(body, dict) or not body.get("project"):
                raise ProtocolError("project is required")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            value = self.runtime.select_project(identity["actor"], body["project"], scope=body.get("scope", "workspace"), idempotency_key=key)
            project_id = value["project"]["project_id"]
            aggregate_id = f"{identity['actor']}:{value['scope']}"
            return self._send(200, {"data": value, "receipt": self.runtime.committed_receipt("project.select", aggregate_id, key, project_id=project_id)})
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "commit" and method == "POST":
            return self._timeline_commit(path[2], path[4], path)
        if len(path) == 4 and path[:2] == ["v1", "projects"] and path[3] == "timelines":
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "POST":
                body = self._project_mutation_body()
                if set(body) - {"timeline_id", "name"}:
                    raise InvalidRequestError("timeline creation accepts only timeline_id and name")
                if "name" in body and not isinstance(body["name"], str):
                    raise InvalidRequestError("timeline name must be a string")
                key = self.headers.get("Idempotency-Key")
                if not key:
                    raise ProtocolError("Idempotency-Key header is required")
                return self._send(201, self.runtime.create_timeline(path[2], body.get("timeline_id", ""), name=body.get("name"), idempotency_key=key))
            if method == "GET":
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.list_timelines(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if len(path) == 5 and path[:2] == ["v1", "projects"] and path[3] == "timelines":
            if path[4] == "import" and method == "POST":
                self._identity("projects:write")
                return self._send(201, self.runtime.import_timeline(path[2], self._project_mutation_body(), idempotency_key=self._idempotency_key()))
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                return self._send(200, self.runtime.get_project_timeline(path[2], path[4]))
            if method == "PATCH":
                return self._send(200, self.runtime.rename_timeline(path[2], path[4], self._project_mutation_body(), idempotency_key=self._idempotency_key()))
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "commits" and method == "GET":
            identity = self._identity("projects:read")
            publisher = identity["actor"]
            def authorize():
                return self._authorize_timeline_read(publisher)

            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            return self._send(200, self.runtime.list_timeline_commits(
                path[2], path[4], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0],
                authorize=authorize,
            ))
        route = VERIFIED_READS.get(tuple(path[3:]))
        if path[:2] == ["v1", "projects"] and route is not None and method == "GET":
            forms, read, message = route
            document = path[3] in ("document-inputs", "document-objects")
            identity = self._identity("projects:read")
            publisher = identity["actor"]
            def authorize():
                return self._authorize_timeline_read(publisher)

            raw_query = urlsplit(self.path).query
            try:
                if re.search(r"%(?![0-9a-fA-F]{2})", raw_query):
                    raise ValueError("invalid percent encoding")
                query = parse_qs(raw_query, keep_blank_values=True, strict_parsing=True, errors="strict")
            except (ValueError, UnicodeError) as exc:
                raise ProtocolError("invalid media selection query encoding") from exc
            if set(query) not in forms or any(len(values) != 1 or not values[0].strip() for values in query.values()):
                raise ProtocolError(message)
            if "version" in query:
                if not re.fullmatch(r"[1-9][0-9]*", query["version"][0]):
                    raise ProtocolError("document version must be a positive integer" if document
                                        else "output version must be a positive integer")
                query["version"] = [int(query["version"][0])]
            selector = {key: values[0] for key, values in query.items()}
            if document:
                pin = {key: selector[key] for key in DOCUMENT_PIN}
                args = (pin, selector["object_id"]) if path[3] == "document-objects" else (pin,)
            else:
                args = (selector,)
            return self._send(200, getattr(self.runtime, read)(path[2], *args, authorize=authorize))
        if len(path) == 4 and path[:2] == ["v1", "projects"] and path[3] == "timeline-documents" and method == "POST":
            self._identity("projects:write")
            self.runtime._require_timeline_command()
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "composition-revisions" and method == "POST":
            self._identity("projects:write")
            # Retire at the HTTP boundary so no compatibility dispatch can
            # reach a Runtime publication implementation.
            reject_retired_timeline_writer()
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "composition-revisions" and method == "GET":
            self._identity("projects:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.list_project_parent_composition_revisions(
                path[2], path[4], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0],
            ))
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "inspect" and method == "POST":
            self._identity("projects:read")
            return self._send(200, self.runtime.inspect_timeline(path[2], path[4], self._timeline_options()))
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "views" and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.create_timeline_view(path[2], path[4], self._timeline_options(), idempotency_key=self._idempotency_key()))
        if len(path) == 6 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "replace-parent-media" and method == "POST":
            self._identity("projects:write")
            self.runtime._require_timeline_command()
        if len(path) == 7 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "composition-revisions" and method == "GET":
            self._identity("projects:read")
            return self._send(200, self.runtime.get_project_parent_composition_revision(path[2], path[4], path[6]))
        if len(path) == 8 and path[:2] == ["v1", "projects"] and path[3] == "timelines" and path[5] == "composition-revisions" and path[7] == "restore" and method == "POST":
            identity = self._identity("projects:write")
            body = self._restore_body()
            restore = self.runtime.restore_project_parent_composition_revision

            def authorize():
                current = self._identity("projects:write")
                if current.get("actor") != identity.get("actor"):
                    raise AuthorizationError("authenticated publisher changed during restore")
                return current

            from .timeline_commit_execution import public_request_id_scope
            with public_request_id_scope(self._request_id()):
                return self._send(200, restore(
                    path[2], path[4], path[6], body,
                    idempotency_key=self._commit_idempotency_key(),
                    publisher=identity["actor"],
                    invocation_path=self._timeline_path(
                        path[2], path[4],
                        f"composition-revisions/{quote(path[6], safe='')}/restore",
                    ),
                    authorize=authorize,
                ))
        if len(path) == 7 and path[:2] == ["v1", "projects"] and path[5] == "revisions" and method == "GET":
            self._identity("projects:read")
            if path[3] == "shots":
                return self._send(200, self.runtime.get_project_shot_revision(path[2], path[4], path[6]))
            if path[3] == "timelines":
                return self._send(200, self.runtime.get_project_timeline_revision(path[2], path[4], path[6]))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("shots", "references") and method == "POST":
            self._identity("projects:write")
            body = self._body()
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(201, self.runtime.create_shot(path[2], body, idempotency_key=key) if path[3] == "shots" else self.runtime.create_reference(path[2], body, idempotency_key=key))
        if len(path) == 3 and path[:2] == ["v1", "timelines"] and method == "PATCH":
            self._identity("projects:write"); self.runtime._require_timeline_command()
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] == "replace-clip" and method == "POST":
            self._identity("projects:write")
            self.runtime._require_timeline_command()
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("history", "diff") and method == "GET":
            self._identity("projects:read")
            query = parse_qs(urlsplit(self.path).query)
            if path[3] == "history":
                return self._send(200, self.runtime.list_timeline_history(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
            if "from_version" not in query or "to_version" not in query:
                raise ProtocolError("from_version and to_version are required")
            return self._send(200, self.runtime.diff_timeline(path[2], query["from_version"][0], query["to_version"][0]))
        if len(path) == 4 and path[:2] == ["v1", "timelines"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            body = self._body()
            if path[3] == "archive":
                return self._send(200, self.runtime.archive_timeline(path[2], body, idempotency_key=self._idempotency_key()))
            return self._send(200, self.runtime.recover_timeline(path[2], body, idempotency_key=self._idempotency_key()))
        if len(path) == 3 and path[:2] == ["v1", "shots"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_shot(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "shots"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_shot(path[2], self._body(), idempotency_key=self.headers.get("Idempotency-Key")))
        if len(path) == 4 and path[:2] == ["v1", "shots"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(200, self.runtime.archive_shot(path[2], self._body(), idempotency_key=key) if path[3] == "archive" else self.runtime.recover_shot(path[2], self._body(), idempotency_key=key))
        if len(path) == 3 and path[:2] == ["v1", "references"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_reference(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "references"] and method == "PATCH":
            self._identity("projects:write"); return self._send(200, self.runtime.update_reference(path[2], self._body(), idempotency_key=self.headers.get("Idempotency-Key")))
        if len(path) == 4 and path[:2] == ["v1", "references"] and path[3] in ("archive", "recover") and method == "POST":
            self._identity("projects:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(200, self.runtime.archive_reference(path[2], self._body(), idempotency_key=key) if path[3] == "archive" else self.runtime.recover_reference(path[2], self._body(), idempotency_key=key))
        if path == ["v1", "projects"]:
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.list_projects(cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
            if method == "POST":
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key:
                    raise ProtocolError("Idempotency-Key header is required")
                value = self.runtime.create_project(body, idempotency_key=key)
                resource = self.runtime._project_resource(value)
                return self._send(201, {"data": resource, "receipt": self.runtime.committed_receipt("project.create", value["id"], key, project_id=value["id"])})
        if len(path) >= 3 and path[:2] == ["v1", "projects"]:
            selector = path[2]
            if len(path) == 3:
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    return self._send(200, self.runtime._project_resource(self.runtime.get_project(selector)))
                if method == "PATCH":
                    key = self.headers.get("Idempotency-Key")
                    if not key:
                        raise ProtocolError("Idempotency-Key header is required")
                    value = self.runtime.update_project(selector, self._body(), idempotency_key=key)
                    return self._send(200, self.runtime._project_resource(value))
            if len(path) == 4 and path[3] == "documents":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_documents(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0], kind=query.get("kind", [None])[0]))
                if method == "POST":
                    body = self._body()
                    if isinstance(body, dict) and (
                        "timeline_id" in body
                        or str(body.get("document_id", "")).startswith("timeline:")
                        or body.get("kind") == "timeline.composition"
                    ):
                        self.runtime._require_timeline_command()
                    return self._send(201, self.runtime.create_document(selector, body, idempotency_key=self._idempotency_key()))
            if len(path) == 5 and path[3] == "documents" and method in ("GET", "PATCH"):
                self._identity("projects:read" if method == "GET" else "projects:write")
                if path[4].startswith("timeline:"):
                    raise RetiredRouteError(
                        "timeline-document reads and CAS writes are retired; use inspectTimeline and canonical publication",
                        details={"replacement": "POST /v1/projects/{project_id}/timelines/{timeline_id}/inspect"},
                    )
                if method == "GET": return self._send(200, self.runtime.get_document(selector, path[4]))
                body = self._body()
                if isinstance(body, dict) and "timeline_id" in body:
                    self.runtime._require_timeline_command()
                return self._send(200, self.runtime.update_document(selector, path[4], body, idempotency_key=self._idempotency_key()))
            if len(path) == 4 and path[3] == "media-imports" and method == "POST":
                identity = self._identity("projects:write")
                key = self._idempotency_key()
                with self.runtime.stage_object(self._binary_chunks(), expected_digest=self.headers.get("X-Expected-Digest")) as data:
                    result = self.runtime.import_media(
                        selector,
                        data,
                        media_type=self.headers.get("Content-Type", "application/octet-stream"),
                        original_name=self.headers.get("X-Original-Name"),
                        expected_digest=self.headers.get("X-Expected-Digest"),
                        actor_id=identity["actor"],
                        width=self.headers.get("X-Media-Width"),
                        height=self.headers.get("X-Media-Height"),
                        duration_seconds=self.headers.get("X-Media-Duration-Seconds"),
                        idempotency_key=key,
                    )
                return self._send(201, result)
            if len(path) == 5 and path[3] == "media-imports" and method == "GET":
                self._identity("projects:read")
                return self._send(200, self.runtime.get_media_import(selector, path[4]))
            if len(path) == 4 and path[3] == "generations":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                    filters = {name: query[name][0] for name in ("kind", "model", "target", "tag") if name in query}
                    return self._send(200, self.runtime.list_generations(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0], **filters))
                if method == "POST": return self._send(201, self.runtime.create_generation(selector, self._body(), idempotency_key=self._idempotency_key()))
            if len(path) == 4 and path[3] == "objects":
                # Project association is control-plane mutation.  A worker may
                # publish unscoped CAS bytes, but cannot attach arbitrary bytes
                # to a project without the user-scoped project authority.
                self._identity("objects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    filter_query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                    filters = {name: filter_query[name][0] for name in ("kind", "model", "target", "tag") if name in filter_query}
                    # Keep legacy blank cursor/limit handling; blank filters are invalid.
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_project_objects(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0], **filters))
                if method == "POST":
                    key = self._idempotency_key()
                    with self.runtime.stage_object(self._binary_chunks(), expected_digest=self.headers.get("X-Expected-Digest")) as data:
                        result = self.runtime.ingest(selector, data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Original-Name"), expected_digest=self.headers.get("X-Expected-Digest"), idempotency_key=key)
                    return self._send(201, result)
            if len(path) == 6 and path[3] == "objects" and path[5] == "location" and method == "GET":
                self._identity("objects:read")
                return self._send(200, self.runtime.object_location(selector, path[4]))
            if len(path) == 4 and path[3] in ("tasks", "runs") and method == "GET":
                self._identity("tasks:read")
                query = parse_qs(urlsplit(self.path).query)
                filters = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                task_query = {key: filters[key][0] for key in ("kind", "order") if key in filters}
                value = self.runtime.list_project_tasks(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0], **task_query) if path[3] == "tasks" else self.runtime.list_project_runs(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0])
                return self._send(200, value)
            if len(path) == 4 and path[3] in ("shots", "references") and method == "GET":
                self._identity("projects:read")
                query = parse_qs(urlsplit(self.path).query)
                include_archived = query.get("include_archived", ["false"])[0].lower() == "true"
                value = self.runtime.list_project_shots(selector, cursor=query.get("cursor", [None])[0], include_archived=include_archived, limit=query.get("limit", [50])[0]) if path[3] == "shots" else self.runtime.list_project_references(selector, cursor=query.get("cursor", [None])[0], include_archived=include_archived, limit=query.get("limit", [50])[0])
                return self._send(200, value)
            if len(path) == 4 and path[3] == "shot-text-bindings":
                self._identity("projects:read" if method == "GET" else "projects:write")
                query = parse_qs(urlsplit(self.path).query)
                if method == "GET":
                    return self._send(200, self.runtime.list_project_shot_text_bindings(selector, shot_id=query.get("shot_id", [None])[0], kind=query.get("kind", [None])[0], slot=query.get("slot", [None])[0]))
                if method == "POST":
                    return self._send(200, self.runtime.set_project_shot_text_binding(selector, self._project_mutation_body(), idempotency_key=self._idempotency_key()))
            if len(path) == 5 and path[3] == "shot-text-bindings":
                self._identity("projects:read" if method == "GET" else "projects:write")
                if method == "GET":
                    return self._send(200, self.runtime.get_project_shot_text_binding(selector, path[4]))
                if method == "POST":
                    body = self._project_mutation_body(); body["binding_id"] = path[4]
                    return self._send(200, self.runtime.set_project_shot_text_binding(selector, body, idempotency_key=self._idempotency_key()))
            if len(path) == 6 and path[3] == "shot-text-bindings" and path[5] == "rebind" and method == "POST":
                self._identity("projects:write")
                body = self._project_mutation_body(); body["binding_id"] = path[4]
                return self._send(200, self.runtime.rebind_project_shot_text_binding(selector, body, idempotency_key=self._idempotency_key()))
            if len(path) >= 5 and path[3] in ("shots", "references"):
                kind, resource_id = path[3], path[4]
                self._identity("projects:read" if method == "GET" else "projects:write")
                key = self.headers.get("Idempotency-Key")
                if method == "PATCH" and path[5:] == []:
                    body = self._project_mutation_body()
                    if not key:
                        raise ProtocolError("Idempotency-Key header is required")
                    key = self._idempotency_key()
                    value = self.runtime.update_project_shot(selector, resource_id, body, idempotency_key=key) if kind == "shots" else self.runtime.update_project_reference(selector, resource_id, body, idempotency_key=key)
                    return self._send(200, value)
                if method == "POST" and path[5:] in (["archive"], ["recover"]):
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    value = self.runtime.update_project_shot(selector, resource_id, body, idempotency_key=key, archived=path[5:] == ["archive"]) if kind == "shots" else self.runtime.update_project_reference(selector, resource_id, body, idempotency_key=key, archived=path[5:] == ["archive"])
                    return self._send(200, value)
                if method == "GET" and not path[5:]:
                    return self._send(200, self.runtime.get_project_shot(selector, resource_id) if kind == "shots" else self.runtime.get_project_reference(selector, resource_id))
                if kind == "shots" and path[5:] == ["items"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.add_shot_item(selector, resource_id, body, idempotency_key=key))
                if kind == "shots" and path[5:] == ["promote-candidate"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.promote_project_shot_candidate(selector, resource_id, body, idempotency_key=key))
                if kind == "shots" and len(path) == 7 and path[5] == "items" and method == "DELETE":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.remove_shot_item(selector, resource_id, path[6], body, idempotency_key=key))
                if kind == "shots" and path[5:] == ["reorder"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.reorder_shot_items(selector, resource_id, body, idempotency_key=key))
                if kind == "references" and path[5:] == ["associations"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.associate_reference(selector, resource_id, body, idempotency_key=key))
                if kind == "references" and path[5:] == ["primary"] and method == "POST":
                    body = self._project_mutation_body()
                    if not key: raise ProtocolError("Idempotency-Key header is required")
                    return self._send(200, self.runtime.set_primary_reference(selector, resource_id, body.get("association_id"), body, idempotency_key=key))
            if len(path) == 4 and path[3] in ("shots", "references") and method == "POST":
                self._identity("projects:write")
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key:
                    raise ProtocolError("Idempotency-Key header is required")
                value = self.runtime.create_project_shot(selector, body, idempotency_key=key) if path[3] == "shots" else self.runtime.create_project_reference(selector, body, idempotency_key=key)
                return self._send(201, value)
            if len(path) == 4 and path[3] == "reference-links" and method == "POST":
                self._identity("projects:write")
                body = self._project_mutation_body()
                key = self.headers.get("Idempotency-Key")
                if not key: raise ProtocolError("Idempotency-Key header is required")
                return self._send(200, self.runtime.link_references(selector, body, idempotency_key=key))
            if len(path) == 4 and path[3] == "media-relations":
                self._identity("objects:read" if method == "GET" else "objects:write")
                if method == "GET":
                    query = parse_qs(urlsplit(self.path).query)
                    return self._send(200, self.runtime.list_media_relations(selector, cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
                if method == "POST": return self._send(201, self.runtime.create_media_relation(selector, self._body(), idempotency_key=self._idempotency_key()))
            if len(path) == 5 and path[3:] == ["thumbnails", "source-frame"]:
                query = parse_qs(urlsplit(self.path).query)
                if method == "GET":
                    self._identity("objects:read")
                    if not query.get("source_object_id") or not query.get("source_time_seconds"):
                        raise ProtocolError("source_object_id and source_time_seconds query parameters are required")
                    try:
                        recipe_version = int(query.get("recipe_version", ["1"])[0])
                        source_time = float(query["source_time_seconds"][0])
                    except (TypeError, ValueError) as exc:
                        raise ProtocolError("source-frame thumbnail query parameters are invalid") from exc
                    return self._send(200, self.runtime.get_source_frame_thumbnail(
                        selector, source_object_id=query["source_object_id"][0],
                        source_time_seconds=source_time, recipe_version=recipe_version,
                    ))
                if method == "POST":
                    self._identity("objects:write")
                    return self._send(200, self.runtime.ensure_source_frame_thumbnail(
                        selector, self._body(), idempotency_key=self._idempotency_key(),
                    ))
        if path == ["v1", "objects"] and method == "POST":
            identity = self._identity("objects:write")
            key = self._idempotency_key()
            upload_binding = None
            raw_binding = self.headers.get("X-Output-Binding")
            if raw_binding:
                try:
                    upload_binding = json.loads(raw_binding)
                except (TypeError, ValueError) as exc:
                    raise ProtocolError("X-Output-Binding must contain valid JSON") from exc
            with self.runtime.stage_object(self._binary_chunks(), expected_digest=self.headers.get("X-Expected-Digest")) as data:
                value = self.runtime.ingest_object(data, media_type=self.headers.get("Content-Type", "application/octet-stream"), original_name=self.headers.get("X-Filename"), expected_digest=self.headers.get("X-Expected-Digest"), idempotency_key=key, identity=identity, upload_binding=upload_binding)
            return self._send(201, value)
        if len(path) == 3 and path[:2] == ["v1", "objects"] and method in ("GET", "HEAD"):
            self._identity("objects:read")
            metadata, stream = self.runtime.open_object(path[2])
            try:
                total = int(metadata["size"])
                start, end = 0, total - 1
                digest = path[2].removeprefix("sha256:")
                etag_value = "sha256:" + digest
                etag = f'"{etag_value}"'
                range_header = self.headers.get("Range")
                if self.headers.get("If-Range") not in (None, etag):
                    range_header = None
                status = 200
                if range_header:
                    match = re.fullmatch(r"bytes=([0-9]{0,20})-([0-9]{0,20})", range_header)
                    try:
                        if not match:
                            raise ValueError
                        left, right = match.groups()
                        if not left:
                            suffix_length = int(right)
                            if suffix_length <= 0:
                                raise ValueError
                            start = max(0, total - suffix_length)
                        else:
                            start = int(left)
                            end = min(int(right), total - 1) if right else total - 1
                        if start >= total or end < start:
                            raise ValueError
                        status = 206
                    except ValueError:
                        return self._send(416, {"code": "invalid_range", "message": "invalid byte range"},
                            headers={"Content-Range": f"bytes */{total}", "Accept-Ranges": "bytes"})
                headers = {"Content-Type": metadata["media_type"], "ETag": etag,
                           "Accept-Ranges": "bytes", "X-Content-Digest": etag_value}
                if status == 206:
                    headers["Content-Range"] = f"bytes {start}-{end}/{total}"
                self._send_file(status, stream, start, max(0, end - start + 1), headers)
                stream = None  # The deferred response or sender owns the open file.
                return
            finally:
                if stream is not None:
                    stream.close()
        if path == ["v1", "tasks"] and method == "POST":
            self._identity("tasks:write")
            body = self._project_mutation_body()
            body["idempotency_key"] = self.headers.get("Idempotency-Key")
            if not body["idempotency_key"]:
                raise ProtocolError("Idempotency-Key header is required")
            # Admission authority lives here, inside the owner process.  The
            # readiness check and row creation share the store transaction;
            # a client precheck can never race an unavailable registration.
            value = self.runtime.create_task(body, enforce_readiness=True)
            resource = self.runtime._task_resource(value)
            project_id = value["run"].get("project_id") or "unscoped"
            return self._send(201, {"data": resource, "receipt": self.runtime.committed_receipt("task.create", project_id, body.get("idempotency_key"), project_id=project_id)})
        if path == ["v1", "delegated-tasks"] and method == "POST":
            identity = self._identity("worker:execute")
            key = self._idempotency_key()
            value = self.runtime.admit_delegated_child(self._project_mutation_body(), idempotency_key=key, identity=identity)
            resource = self.runtime._task_resource(value)
            project_id = value["run"].get("project_id") or "unscoped"
            return self._send(201, {"data": resource, "receipt": self.runtime.committed_receipt("task.create", project_id, key, project_id=project_id)})
        if len(path) == 4 and path[:2] == ["v1", "tasks"] and path[3] == "claim-delegated-child" and method == "POST":
            identity = self._identity("worker:execute")
            return self._send(200, self.runtime.claim_delegated_child(
                path[2], self._body(), idempotency_key=self._idempotency_key(), identity=identity,
            ))
        if path == ["v1", "tasks", "claim"] and method == "POST":
            identity = self._identity("worker:execute")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            result = self.runtime.claim_next(self._body(), idempotency_key=key, identity=identity)
            if result is None:
                return self._send(204, body=b"")
            return self._send(200, result)
        if len(path) == 3 and path[:2] == ["v1", "tasks"]:
            task_id = path[2]
            if method == "GET":
                self._identity("tasks:read")
                value = self.runtime.task(task_id)
                return self._send(200, self.runtime._task_resource(value))
        if len(path) == 4 and path[:2] == ["v1", "tasks"] and path[3] == "managed-outputs" and method == "GET":
            self._identity("tasks:read")
            return self._send(200, self.runtime.managed_output_page(path[2]))
        if len(path) == 3 and path[:2] == ["v1", "managed-outputs"]:
            if method == "GET":
                self._identity("tasks:read")
                return self._send(200, self.runtime.managed_output(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "managed-outputs"]:
            association_id, action = path[2:]
            if action == "adopt" and method == "POST":
                self._identity("tasks:write")
                return self._send(200, self.runtime.adopt_managed_output(association_id, self._project_mutation_body(), idempotency_key=self._idempotency_key()))
            if action == "export" and method == "POST":
                self._identity("tasks:write")
                return self._send(200, self.runtime.export_managed_output(association_id, self._project_mutation_body(), idempotency_key=self._idempotency_key()))
            if action == "lifecycle" and method == "POST":
                self._identity("tasks:write")
                return self._send(200, self.runtime.update_managed_output_lifecycle(association_id, self._project_mutation_body(), idempotency_key=self._idempotency_key()))
        if len(path) == 4 and path[:2] == ["v1", "tasks"]:
            task_id, action = path[2:]
            if method == "POST" and action == "remote-credential":
                identity = self._identity("admin")
                if identity.get("actor") != "owner":
                    raise AuthorizationError("resident remote credential control requires the daemon owner")
                daemon = getattr(self.server, "daemon_runtime", None)
                if daemon is None:
                    raise ConflictError("resident credential owner is unavailable")
                return self._send(200, daemon.remote_credential_control(task_id, self._project_mutation_body(), identity=identity))
            if method == "POST" and action == "remote-activation":
                identity = self._identity("admin")
                qualification = self._project_mutation_body()
                return self._send(200, self.runtime.record_remote_activation(
                    task_id, qualification, identity=identity
                ))
            if method == "POST" and action == "placement-recovery":
                identity = self._identity("admin")
                key = self._idempotency_key()
                value = self.runtime.recover_task_placement(
                    task_id, self._body(), idempotency_key=key, identity=identity
                )
                return self._send(200, value)
            if method == "POST" and action == "cancel":
                body = self._body()
                fenced = isinstance(body, dict) and bool(set(body) & {
                    "attempt_id", "lease_id", "fence", "runtime_epoch", "outputs", "result", "stop_observed"})
                identity = self._identity("worker:execute" if fenced else "tasks:write")
                key = self._idempotency_key()
                value = self.runtime.cancel_task_canonical(task_id, body, idempotency_key=key, identity=identity)
                task = self.runtime.store.get_task(task_id)
                return self._send(200, value)
            self._identity("tasks:write")
            if method == "POST" and action == "retry":
                key = self._idempotency_key()
                value = self.runtime.retry_task(task_id, self._body(), idempotency_key=key)
                task = self.runtime.store.get_task(task_id)
                return self._send(200, value)
            if method == "GET" and action == "events":
                task = self.runtime.store.get_task(task_id)
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.events_page(task["run"]["id"], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if len(path) == 5 and path[:2] == ["v1", "tasks"] and path[3:] == ["remote-activation", "revoke"] and method == "POST":
            identity = self._identity("admin")
            body = self._project_mutation_body()
            if set(body) != {"activation_id"} or not isinstance(body["activation_id"], str) or not body["activation_id"]:
                raise ProtocolError("activation_id is the only accepted revocation field")
            self.runtime.revoke_remote_activation(path[2], body["activation_id"], identity=identity)
            return self._send(204, body=b"")
        if len(path) == 4 and path[:2] == ["v1", "attempts"] and method == "POST":
            identity = self._identity("worker:execute")
            action = path[3]
            if action == "recoverable-snapshots":
                key = self._idempotency_key()
                return self._send(200, self.runtime.publish_recoverable_snapshot(path[2], self._project_mutation_body(), idempotency_key=key, identity=identity))
            if action == "child-authority":
                return self._send(200, self.runtime.issue_child_authority(path[2], self._project_mutation_body(), identity=identity))
            if action == "prepare-reboot":
                body = self._project_mutation_body()
                # generated clients intentionally do not duplicate it in the
                # JSON body, so bind it at the HTTP boundary before invoking
                # the service.
                body["attempt_id"] = path[2]
                return self._send(200, self.runtime.prepare_reboot(body, identity=identity))
            if action == "checkpoint": return self._send(201, self.runtime.checkpoint_attempt(path[2], self._body(), identity=identity))
            if action == "publish-timeline-render":
                self.runtime._require_timeline_command()
            if action == "settle":
                key = self._idempotency_key()
                value = self.runtime.settle_attempt(path[2], self._body(), idempotency_key=key, identity=identity)
                return self._send(200, value)
            if action == "heartbeat":
                key = self._idempotency_key()
                value = self.runtime.heartbeat_attempt(path[2], self._body(), idempotency_key=key, identity=identity)
                return self._send(200, value)
            if action == "fail":
                key = self._idempotency_key()
                value = self.runtime.fail_attempt(path[2], self._body(), idempotency_key=key, identity=identity)
                return self._send(200, value)
        if path == ["v1", "recovery", "reboot"] and method == "POST":
            identity = self._identity("worker:execute")
            return self._send(200, self.runtime.request_reboot(self._body(), identity=identity))
        if path == ["v1", "recovery", "resume"] and method == "POST":
            identity = self._identity("worker:execute")
            return self._send(200, self.runtime.resume_attempt(self._body(), identity=identity))
        if len(path) == 3 and path[:2] == ["v1", "generations"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_generation(path[2]))
        if len(path) == 5 and path[:2] == ["v1", "generations"] and path[3] == "variants" and path[4] == "viewed" and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.mark_generation_variants_viewed(path[2], idempotency_key=self._idempotency_key()))
        if len(path) == 4 and path[:2] == ["v1", "generations"] and path[3] == "variants":
            self._identity("projects:read" if method == "GET" else "projects:write")
            if method == "GET":
                query = parse_qs(urlsplit(self.path).query)
                return self._send(200, self.runtime.list_variants(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
            if method == "POST": return self._send(201, self.runtime.create_variant(path[2], self._body(), idempotency_key=self._idempotency_key()))
        if len(path) == 3 and path[:2] == ["v1", "variants"] and method == "GET":
            self._identity("projects:read"); return self._send(200, self.runtime.get_variant(path[2]))
        if len(path) == 4 and path[:2] == ["v1", "variants"] and path[3] == "thumbnail" and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.attach_variant_thumbnail(path[2], self._body(), idempotency_key=self._idempotency_key()))
        if len(path) == 4 and path[:2] == ["v1", "variants"] and path[3] == "viewed" and method == "POST":
            self._identity("projects:write")
            return self._send(200, self.runtime.mark_variant_viewed(path[2], idempotency_key=self._idempotency_key()))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] == "events" and method == "GET":
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.events_page(path[2], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if len(path) == 4 and path[:2] == ["v1", "runs"] and path[3] in ("cancel", "retry") and method == "POST":
            self._identity("tasks:write")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            body = self._body()
            if path[3] == "cancel":
                return self._send(200, self.runtime.cancel_run(path[2], body, idempotency_key=key))
            return self._send(200, self.runtime.retry_run(path[2], body, idempotency_key=key))
        if path == ["v1", "events"] and method == "GET":
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.events_page(query.get("aggregate_id", [None])[0], cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0], from_=query.get("from", [None])[0]))
        if path == ["v1", "capabilities"] and method == "GET":
            # Capability discovery is part of task admission, not worker
            # control. Astrid's scoped product actor must be able to resolve
            # a capability digest before creating a task, while registration
            # and execution remain restricted to worker scopes.
            self._identity("tasks:read")
            query = parse_qs(urlsplit(self.path).query)
            return self._send(200, self.runtime.list_capabilities(cursor=query.get("cursor", [None])[0], limit=query.get("limit", [50])[0]))
        if path == ["v1", "capabilities"] and method == "POST":
            self._identity("worker:register")
            return self._send(201, self.runtime.register_capability(self._body()))
        if path == ["v1", "executors"] and method == "POST":
            identity = self._identity("worker:register")
            key = self.headers.get("Idempotency-Key")
            if not key:
                raise ProtocolError("Idempotency-Key header is required")
            return self._send(201, self.runtime.register_executor(self._body(), idempotency_key=key, identity=identity))
        if len(path) == 3 and path[:2] == ["v1", "executors"] and method == "GET":
            identity = self._identity("admin")
            if identity.get("actor") != "owner":
                raise AuthorizationError("exact executor observation requires the Runtime owner")
            return self._send(200, self.runtime.executor_observation(path[2], identity=identity))
        if len(path) == 3 and path[:2] == ["v1", "runs"] and method == "GET":
            self._identity("tasks:read")
            return self._send(200, self.runtime.run(path[2]))
        raise NotFoundError("route not found")

    def _is_local_worker_control(self):
        path = urlsplit(getattr(self, "path", "")).path
        method = getattr(self, "command", None)
        return (method == "POST" and path in {
            "/v1/control/local-worker/start", "/v1/control/local-worker/relinquish",
        }) or (method == "GET" and path == "/v1/control/local-worker/generation")

    def _is_task_settlement_control(self):
        path = [unquote(x) for x in urlsplit(getattr(self, "path", "")).path.split("/") if x]
        return (getattr(self, "command", None) == "GET" and len(path) == 5
                and path[:3] == ["v1", "control", "tasks"] and path[4] == "settlement")

    def _task_settlement_control(self):
        identity = self._identity("admin")
        if identity.get("actor") != "owner":
            raise ForbiddenError("task settlement requires the Runtime owner actor")
        daemon = getattr(self.server, "daemon_runtime", None)
        if daemon is None:
            raise ConflictError("task settlement requires daemon ownership")
        task_id = unquote(urlsplit(self.path).path.split("/")[4])
        return self._send(200, daemon.task_settlement(task_id, identity=identity))

    def _is_remote_credential_control(self):
        path = [unquote(x) for x in urlsplit(getattr(self, "path", "")).path.split("/") if x]
        return getattr(self, "command", None) == "POST" and len(path) == 4 and path[:2] == ["v1", "tasks"] and path[3] == "remote-credential"

    def _local_worker_control(self):
        identity = self._identity("admin")
        if identity.get("actor") != "owner":
            raise ForbiddenError("local worker launch requires the Runtime owner actor")
        daemon = getattr(self.server, "daemon_runtime", None)
        if daemon is None:
            raise ConflictError("local worker launch requires daemon ownership")
        if self.command == "GET":
            return self._send(200, daemon.local_worker_generation(identity=identity))
        body = self._body()
        if urlsplit(self.path).path.endswith("/relinquish"):
            if (not isinstance(body, dict) or not {"executor_incarnation", "evidence_digest"} <= set(body)
                    or set(body) - {"executor_incarnation", "evidence_digest", "expected_task_ids"}
                    or ("expected_task_ids" in body and body["expected_task_ids"] is None)):
                raise ProtocolError("exact local Worker generation fields are required")
            return self._send(200, daemon.relinquish_local_worker(
                body["executor_incarnation"], body["evidence_digest"], identity=identity,
                expected_task_ids=body.get("expected_task_ids"),
            ))
        if not isinstance(body, dict) or set(body) != {"profile_id", "expected_workspace_uuid"}:
            raise ProtocolError("profile_id and expected_workspace_uuid are the only accepted launch fields")
        return self._send(200, daemon.start_local_worker(body["profile_id"], body["expected_workspace_uuid"]))

    def _dispatch(self):
        """Serialize handlers that share the daemon's SQLite connection.

        ``ThreadingHTTPServer`` creates one handler thread per request, while
        this runtime intentionally owns one SQLite connection.  The service
        has finer-grained locks around many mutations, but read paths and
        multi-step handlers also touch the connection; the HTTP boundary must
        therefore serialize the service portion of the route. Response socket
        writes happen afterwards: an unread client must not hold the database
        lock and stall every other request, including health checks.
        """
        timing = token = None
        wire_started = False
        if self._is_timeline_commit():
            from .timeline_commit_execution import start_commit_timing
            timing, token = start_commit_timing()
            timing.begin("handler")
        try:
            self._pending_response = None
            self._pending_file_response = None
            self._prefetched_body = None
            self._defer_response = True
            try:
                if urlsplit(getattr(self, "path", "")).path.startswith("/v1/update"):
                    # Admission and network preparation never hold the shared SQLite writer.
                    self._update_route()
                elif self._is_task_settlement_control():
                    self._task_settlement_control()
                elif self._is_local_worker_control():
                    # Process preparation and OS observation are deliberately
                    # outside the SQLite mutex. Credential authentication and
                    # publication use CredentialStore's short internal lock.
                    self._local_worker_control()
                elif self._is_owner_identity_probe():
                    # Boundary identity probes use independent read-only
                    # snapshots while a lifecycle fence blocks the writer.
                    # Ordinary health/realm reads retain writer serialization.
                    self._route()
                elif getattr(self, "command", None) == "GET" and urlsplit(getattr(self, "path", "")).path == "/v1/diagnostics":
                    # Support diagnostics performs independent owner-boundary
                    # probes; it must not hold the serialized SQLite section.
                    self._route()
                elif self._is_remote_credential_control() or self._is_binary_io() or self._is_timeline_commit():
                    # Both routes own short store sections. Transfer, hashing,
                    # and daemon actor ownership must stay outside this lock.
                    if self._is_timeline_commit():
                        self._prefetch_body(self.TIMELINE_BODY_BYTES)
                    self._route()
                else:
                    self._prefetch_body()
                    with self.runtime.store._mutex:
                        self._route()
            finally:
                self._defer_response = False
            if self._pending_response is not None:
                status, payload, kwargs = self._pending_response
                self._pending_response = None
                if timing is not None:
                    timing.begin("wire_response")
                    wire_started = True
                try:
                    self._send(status, payload, **kwargs)
                finally:
                    if timing is not None:
                        timing.end("wire_response")
                        wire_started = False
            if self._pending_file_response is not None:
                pending = self._pending_file_response
                self._pending_file_response = None
                self._send_file(*pending)
        except (ConnectionError, TimeoutError):
            if timing is not None:
                timing.outcome = "failure"
                if wire_started:
                    timing.end("wire_response")
            self.close_connection = True
        except Exception as exc:
            if timing is not None:
                timing.outcome = "failure"
                timing.begin("wire_response")
                wire_started = True
            if getattr(self, "_response_started", False):
                self.close_connection = True
            else:
                try:
                    self._error(exc)
                finally:
                    if timing is not None:
                        timing.end("wire_response")
                        wire_started = False
        finally:
            pending = getattr(self, "_pending_file_response", None)
            if pending is not None:
                pending[1].close()
                self._pending_file_response = None
            if timing is not None:
                if wire_started:
                    timing.end("wire_response")
                timing.end("handler")
                from .timeline_commit_execution import finish_commit_timing
                finish_commit_timing(timing, token)

    def do_GET(self):
        self._dispatch()

    def do_HEAD(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    def do_PATCH(self):
        self._dispatch()

    def do_PUT(self):
        self.do_PATCH()

    def do_DELETE(self):
        self._dispatch()
