"""The hosted page's door: a second loopback listener for the browser.

The product runs from https://astrid.haus; the person's Runtime and files stay
on their computer. The door is how that page reaches them: a listener on
127.0.0.1:17340 that answers only the configured hosted origin, with the CORS
and Private Network Access headers a browser needs, in front of the same
handlers as the Runtime's own listener (``RuntimeHandler._dispatch``).

Authority is the product credential, never the Origin. The door holds the
scoped product credential (the ``astrid`` profile's ``astrid.json``), and every
request authenticates through ``CredentialStore.require`` exactly as a client
presenting that bearer would. The Origin only admits a browser request. The
trust model is the product credential's own: anything on this computer that
can send the hosted Origin to the loopback port acts as the product.

Listening is not readiness. Until the product credential is provisioned, and
again once shutdown begins or the realm's readiness is revoked, every Runtime
route answers 503 ``runtime_unavailable``, which the page reads as "not
running". A credential that names anything but the scoped product identity is
503 ``runtime_identity_mismatch``.

Chat is a separate local service. It tells the running Runtime where it is the
way the Runtime itself publishes discovery.json: one owner-only file,
``<support>/chat.json`` = ``{"endpoint": "http://127.0.0.1:PORT", "token": "..."}``,
read on every chat request. The door forwards ``/api/astrid/acp/*`` there with
the chat service's own credential, the bridge protocol version and the hosted
local-media-only policy. No file, or nothing answering at its endpoint, is 503
``acp_unavailable``, which the page shows as a calm line.
"""

from __future__ import annotations

import errno
import http.client
import json
import os as process_os
from .dirfd import filesystem as os
import re
import selectors
import socket
import stat

from runtime_protocol import platform
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .auth import CredentialStore
from .errors import AuthorizationError, BodyTooLargeError, ConflictError
from .server import RuntimeHTTPServer, RuntimeHandler

DEFAULT_DOOR_PORT = 17340
DEFAULT_HOSTED_ORIGIN = "https://astrid.haus"

PRODUCT_SCOPES = ("handshake", "objects:read", "objects:write", "projects:read", "projects:write", "tasks:read", "tasks:write")
# The daemon owner and the shared Worker are never the product, whatever their scopes.
NON_PRODUCT_ACTORS = frozenset({"owner", "astrid-pack-host"})

# What a browser may send and read. Credentials, cookies and Runtime-internal
# headers (X-Output-Binding, X-Request-ID, If-Range) never cross the door.
REQUEST_HEADERS = frozenset({
    "accept", "content-type", "content-length", "range", "if-match", "if-none-match", "idempotency-key",
    "x-filename", "x-original-name", "x-expected-digest", "x-media-width", "x-media-height",
    "x-media-duration-seconds",
})
RESPONSE_HEADERS = ("content-type", "content-length", "content-range", "accept-ranges", "etag", "last-modified")
# Body framing is the Runtime's to judge (it refuses non-identity binary encodings and trailers).
_FRAMING_HEADERS = frozenset({"transfer-encoding", "content-encoding", "trailer"})

JSON_MAX_BYTES = 1024 * 1024
ACP_MAX_BYTES = 128 * 1024
# Idle, not wall clock: a flowing media stream is never capped.
IDLE_TIMEOUT_SECONDS = 60.0
ACP_IDLE_TIMEOUT_SECONDS = 300.0
PREFLIGHT_MAX_AGE_SECONDS = 300
ACP_PROTOCOL_HEADER = "X-Astrid-Bridge-Version"
ACP_PROTOCOL_VERSION = "v1"
ACP_LOCAL_MEDIA_ONLY_HEADER = "X-Astrid-Local-Media-Only"
IMMUTABLE_OBJECT_CACHE_CONTROL = "private, max-age=31536000, immutable"
# A refused request's body is read and dropped up to this size, so the client sees the refusal and not a reset.
_DRAIN_LIMIT_BYTES = 2 * 1024 * 1024
_STREAM_CHUNK_BYTES = 64 * 1024


class DoorPortTaken(ConflictError):
    code = "door_port_taken"


class _Refusal(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def _is_acp_prompt(method: str, path: str, body: bytes | None) -> bool:
    """Only prompt completion waits may outlive the ordinary chat timeout."""
    if method != "POST":
        return False
    path = urlsplit(path).path
    if re.fullmatch(r"/acp/projects/[^/]+/chat/prompt", path):
        return True
    if not re.fullmatch(r"/acp/[^/]+/rpc", path):
        return False
    try:
        request = json.loads(body or b"")
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(request, dict) and request.get("method") == "session/prompt"


def _wait_for_prompt_response(upstream: socket.socket, browser: socket.socket) -> bool:
    """Wait for completion or disconnect, without imposing an execution deadline.

    Closing the door shuts down the tracked upstream socket and wakes this wait.
    A vanished browser releases only its HTTP connection; it never cancels work.
    """
    with selectors.DefaultSelector() as selector:
        selector.register(upstream, selectors.EVENT_READ)
        selector.register(browser, selectors.EVENT_READ)
        while True:
            readable = {key.fileobj for key, _ in selector.select()}
            if browser in readable:
                if not browser.recv(1, socket.MSG_PEEK):
                    return False
                # Extra/pipelined request bytes aren't part of this response.
                # Avoid spinning; this handler closes the connection as usual.
                selector.unregister(browser)
            if upstream in readable:
                return True


def exact_https_origin(value: str) -> str:
    """``value`` if it is an exact HTTPS origin (scheme, lowercase host, optional port), else ValueError."""
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"hosted origin must be an exact HTTPS origin, got {value!r}") from exc
    host = parts.hostname or ""
    canonical = f"https://{host}" + (f":{port}" if port not in (None, 443) else "")
    if parts.scheme != "https" or not host or parts.username or parts.password or value != canonical:
        raise ValueError(f"hosted origin must be an exact HTTPS origin such as {DEFAULT_HOSTED_ORIGIN}, got {value!r}")
    return value


@dataclass(frozen=True)
class DoorConfig:
    origin: str
    credential_file: Path
    port: int = DEFAULT_DOOR_PORT
    audit_log: Path | None = None
    idle_timeout: float = IDLE_TIMEOUT_SECONDS
    acp_idle_timeout: float = ACP_IDLE_TIMEOUT_SECONDS

    def __post_init__(self):
        exact_https_origin(self.origin)
        if not isinstance(self.port, int) or not 0 <= self.port <= 65535:
            raise ValueError("door port must be an integer from 0 to 65535")
        if not Path(self.credential_file).is_absolute():
            raise ValueError("door credential file must be absolute")


# ---------------------------------------------------------------------------
# The route table: the hosted page's calls, one method set and one exact path
# shape each, nothing a wildcard.

_DENIED = (
    re.compile(r"^/v1/(doctor|backup|restore|export)(?:/|$)"),
    re.compile(r"^/v1/realm/(?:tombstone|recover|purge|replace)(?:/|$)"),
    re.compile(r"^/v1/(?:tasks/claim|attempts/|recovery/|executors(?:/|$))"),
)
# A decoded segment holds only unreserved characters and ':' (ids such as
# `timeline:x` or `sha256:...` arrive as `%3A`). Dynamic ids match what the
# Runtime issues.
_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9._~:-]+")
_ID_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~:-]{0,255}")
_CONNECTION_SEGMENT = re.compile(r"[A-Za-z0-9_-]{1,128}")
_ENCODED_SEGMENT = re.compile(r"(?:[^%]|%[0-9A-Fa-f]{2})*")
_RESERVED_ACP = frozenset({"health", "connect", "projects", "models", "model", "agents", "astrid"})
_MAX_PATH_LENGTH = 4096


def _entry(methods: str, template: str) -> tuple[frozenset[str], tuple[str, ...]]:
    """``:`` stands for a dynamic id segment, ``:conn`` for an ACP connection id."""
    return frozenset(methods.split(",")), tuple(template.split("/")[1:])


WORKSPACE_ROUTES = (
    _entry("GET", "/v1/health"),
    _entry("POST", "/v1/handshake"),
    _entry("GET", "/v1/realm"),
    _entry("GET,PUT", "/v1/app-state/user/:"),
    _entry("GET,POST", "/v1/projects"),
    _entry("PUT", "/v1/projects/selection"),
    _entry("GET,PATCH", "/v1/projects/:"),
    _entry("GET", "/v1/projects/:/timelines"),
    _entry("POST", "/v1/projects/:/timelines/import"),
    _entry("GET,PATCH", "/v1/projects/:/timelines/:"),
    _entry("GET", "/v1/projects/:/timelines/:/revisions/:"),
    _entry("GET,POST", "/v1/projects/:/timelines/:/composition-revisions"),
    _entry("GET", "/v1/projects/:/timelines/:/composition-revisions/:"),
    _entry("POST", "/v1/projects/:/timelines/:/composition-revisions/:/restore"),
    _entry("POST", "/v1/projects/:/timelines/:/inspect"),
    _entry("GET", "/v1/projects/:/shots/:/revisions/:"),
    _entry("GET,POST", "/v1/projects/:/documents"),
    _entry("GET,PATCH", "/v1/projects/:/documents/:"),
    _entry("GET,POST", "/v1/projects/:/thumbnails/source-frame"),
    _entry("GET", "/v1/projects/:/objects"),
    _entry("POST", "/v1/projects/:/objects"),
    _entry("GET", "/v1/projects/:/objects/:/location"),
    _entry("POST", "/v1/projects/:/media-imports"),
    _entry("GET", "/v1/projects/:/media-imports/:"),
    _entry("GET,HEAD", "/v1/objects/:"),
    _entry("POST", "/v1/tasks"),
    _entry("GET", "/v1/tasks/:"),
    _entry("POST", "/v1/tasks/:/cancel"),
    _entry("POST", "/v1/tasks/:/retry"),
    _entry("GET", "/v1/projects/:/tasks"),
    _entry("GET", "/v1/tasks/:/managed-outputs"),
    _entry("GET", "/v1/managed-outputs/:"),
    _entry("POST", "/v1/managed-outputs/:/export"),
    _entry("GET", "/v1/events"),
    _entry("GET", "/v1/projects/:/generations"),
    _entry("GET", "/v1/generations/:"),
    _entry("GET", "/v1/generations/:/variants"),
    _entry("POST", "/v1/generations/:/variants/viewed"),
    _entry("POST", "/v1/variants/:/viewed"),
)
# The capability catalog is read-only for the product, and only under /api/astrid.
ASTRID_ONLY_ROUTES = (_entry("GET", "/v1/capabilities"),)
ACP_ROUTES = (
    _entry("GET", "/acp/health"),
    _entry("GET", "/acp/models"),
    _entry("GET", "/acp/agents"),
    _entry("POST", "/acp/connect"),
    # Astrid's own agent: the app pastes an OpenRouter key here; only the local chat service sees it.
    _entry("POST", "/acp/astrid/api-key"),
    _entry("GET", "/acp/:conn/models"),
    _entry("POST", "/acp/:conn/rpc"),
    _entry("POST", "/acp/:conn/cancel"),
    _entry("POST", "/acp/:conn/reconnect"),
    _entry("GET", "/acp/:conn/events"),
    _entry("DELETE", "/acp/:conn"),
    _entry("GET,PATCH", "/acp/projects/:/chat"),
    _entry("POST", "/acp/projects/:/chat/sessions"),
    _entry("GET", "/acp/projects/:/chat/unassigned"),
    _entry("POST", "/acp/projects/:/chat/associate"),
    _entry("PATCH", "/acp/projects/:/chat/draft"),
    _entry("PATCH", "/acp/projects/:/chat/main"),
    _entry("POST", "/acp/projects/:/chat/prompt"),
)


@dataclass(frozen=True)
class DoorRoute:
    """``service`` is ``runtime``, ``astrid`` (both the Runtime) or ``acp``; ``path`` is canonical, with the raw query."""

    service: str
    path: str

    @property
    def bare_path(self) -> str:
        return self.path.split("?", 1)[0]


def _segment_matches(expected: str, actual: str) -> bool:
    if expected == ":":
        return bool(_ID_SEGMENT.fullmatch(actual))
    if expected == ":conn":
        return bool(_CONNECTION_SEGMENT.fullmatch(actual)) and actual not in _RESERVED_ACP
    return expected == actual


def _find(table, method: str, segments: list[str]) -> bool:
    # Exact routes reserve their path even for methods they don't allow, so a
    # parameterized route can't reinterpret a reserved word as an id.
    exact = next((methods for methods, template in table
                  if len(template) == len(segments) and ":" not in template
                  and template == tuple(segments)), None)
    if exact is not None:
        return method in exact
    return any(
        method in methods and len(template) == len(segments)
        and all(_segment_matches(expected, actual) for expected, actual in zip(template, segments))
        for methods, template in table
    )


def _canonical(path: str) -> tuple[list[str], str] | None:
    """Percent-decode the path exactly once into segments, or refuse it.

    What is judged is what is dispatched: the Runtime decodes each segment once
    more, which is the identity on a segment that passed ``_SAFE_SEGMENT``.
    """
    if not path or len(path) > _MAX_PATH_LENGTH or not path.startswith("/"):
        return None
    # Printable ASCII only, and no fragments, backslashes or embedded URLs.
    if not re.fullmatch(r"[\x21-\x7e]+", path) or "#" in path or "\\" in path or "://" in path:
        return None
    pathname, _, query = path.partition("?")
    segments = []
    for raw in pathname[1:].split("/"):
        if not _ENCODED_SEGMENT.fullmatch(raw):
            return None
        try:
            decoded = unquote(raw, errors="strict")
        except UnicodeDecodeError:
            return None
        # Refuses empty segments, '.'/'..' (also encoded), encoded '/', '\\', '?',
        # '#', control characters and a '%' left after decoding (double encoding).
        if not _SAFE_SEGMENT.fullmatch(decoded) or decoded in (".", ".."):
            return None
        segments.append(decoded)
    return segments, query


def classify(path: str, method: str) -> DoorRoute | None:
    """The route for a browser request, or None when the door does not serve it."""
    canonical = _canonical(path)
    if canonical is None:
        return None
    segments, query = canonical
    method = method.upper()
    if len(segments) < 3 or segments[0] != "api" or segments[1] not in ("runtime", "astrid"):
        return None
    service, upstream = segments[1], segments[2:]
    upstream_path = "/" + "/".join(upstream)
    with_query = upstream_path + (f"?{query}" if query else "")
    # Compose (/api/astrid/generation/compose) is the local app's own route and is never served here.
    if service == "astrid" and upstream[0] == "acp":
        return DoorRoute("acp", with_query) if _find(ACP_ROUTES, method, upstream) else None
    if any(pattern.search(upstream_path) for pattern in _DENIED):
        return None
    if _find(WORKSPACE_ROUTES, method, upstream) or (service == "astrid" and _find(ASTRID_ONLY_ROUTES, method, upstream)):
        return DoorRoute(service, with_query)
    return None


def _is_binary_upload(route: DoorRoute, method: str) -> bool:
    return method == "POST" and bool(re.search(r"/(objects|media-imports)$", route.bare_path))


_DIGEST_OBJECT_PATH = re.compile(r"/v1/objects/(?:sha256:)?[0-9a-f]{64}")


def object_cache_control(method: str, route: DoorRoute | None, status: int) -> str:
    """Digest-addressed object bytes never change; every other response is no-store."""
    if (route is not None and route.service != "acp" and method in ("GET", "HEAD")
            and _DIGEST_OBJECT_PATH.fullmatch(route.bare_path) and status in (200, 206, 304)):
        return IMMUTABLE_OBJECT_CACHE_CONTROL
    return "no-store"


# ---------------------------------------------------------------------------
# What the door reads from disk: the product credential and the chat service


CHAT_FILE_NAME = "chat.json"
_LOOPBACK_URL = re.compile(r"http://127\.0\.0\.1:([0-9]{1,5})")


_MAX_LOCAL_FILE_BYTES = 64 * 1024


def _owner_only_json(path: Path) -> dict | None:
    """A JSON object from a regular file only this user can read or write, or None.

    The file is opened once without following a symlink, and that open file is
    what is checked and read (bounded), so it cannot be swapped in between.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or not platform.is_owner_only(descriptor)
                or metadata.st_size > _MAX_LOCAL_FILE_BYTES):
            return None
        raw = b""
        while len(raw) <= _MAX_LOCAL_FILE_BYTES:
            chunk = os.read(descriptor, _MAX_LOCAL_FILE_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) > _MAX_LOCAL_FILE_BYTES:
            return None
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    finally:
        os.close(descriptor)
    return value if isinstance(value, dict) else None


def chat_endpoint(path: Path) -> tuple[int, str] | None:
    """The chat service's loopback port and credential from its file, or None."""
    value = _owner_only_json(path)
    if value is None:
        return None
    match = _LOOPBACK_URL.fullmatch(value.get("endpoint")) if isinstance(value.get("endpoint"), str) else None
    token = value.get("token")
    if not match or not 1 <= int(match.group(1)) <= 65535 or not isinstance(token, str) or not token:
        return None
    return int(match.group(1)), token


# ---------------------------------------------------------------------------
# The listener


class _CountingWriter:
    """The response stream, counting body bytes for the audit line."""

    def __init__(self, raw):
        self.raw, self.counting, self.count = raw, False, 0

    def write(self, data):
        written = self.raw.write(data)
        if self.counting:
            self.count += len(data)
        return written

    def flush(self):
        return self.raw.flush()

    def close(self):
        return self.raw.close()

    @property
    def closed(self):
        return self.raw.closed


class DoorHTTPServer(RuntimeHTTPServer):
    def __init__(self, config: DoorConfig, *, runtime, daemon_runtime, credentials: CredentialStore, chat_file: Path):
        self.door = config
        self.runtime = runtime
        self.daemon_runtime = daemon_runtime
        self.credentials = credentials
        self.chat_file = Path(chat_file)
        self.audit_lock = threading.Lock()
        # Chat connections forwarded right now, so closing the listener also closes them.
        self._upstreams: set[socket.socket] = set()
        self._upstreams_lock = threading.Lock()
        self._closed = False
        super().__init__(("127.0.0.1", config.port), DoorHandler)

    def track_upstream(self, upstream: socket.socket) -> bool:
        """Registers a forwarded chat connection; False once the listener has closed."""
        with self._upstreams_lock:
            if self._closed:
                return False
            self._upstreams.add(upstream)
            return True

    def untrack_upstream(self, upstream: socket.socket) -> None:
        with self._upstreams_lock:
            self._upstreams.discard(upstream)

    def server_close(self):
        with self._upstreams_lock:
            self._closed = True
            upstreams, self._upstreams = self._upstreams, set()
        for upstream in upstreams:
            # Shutdown, not close: it wakes a handler blocked reading from it.
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        super().server_close()


def open_door(config: DoorConfig, *, runtime, daemon_runtime, credentials: CredentialStore, chat_file: Path) -> DoorHTTPServer:
    """Bind the door, or raise ``DoorPortTaken`` naming whatever holds its port."""
    try:
        return DoorHTTPServer(config, runtime=runtime, daemon_runtime=daemon_runtime, credentials=credentials, chat_file=chat_file)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            raise DoorPortTaken(describe_port_holder(config.port, config.origin)) from exc
        raise


def _printable(value) -> str:
    """Terminal-safe, bounded text from another local process."""
    return re.sub(r"[^\x20-\x7e]", "?", str(value or ""))[:80]


def _probe(port: int, origin: str, path: str) -> tuple[int, dict | None] | None:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", path, headers={"Host": f"127.0.0.1:{port}", "Origin": origin})
        response = connection.getresponse()
        raw = response.read(16384)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            body = None
        return response.status, body if isinstance(body, dict) else None
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def describe_port_holder(port: int, origin: str) -> str:
    """One sentence for a taken door port, asking the holder who it is the way the hosted page would.

    The page only ever looks on the well-known port, so the advice is to stop the holder, never to use another port.
    """
    stop_runtime = "stop that one first (astrid-runtime down)"
    health = _probe(port, origin, "/api/runtime/v1/health")
    if health is not None:
        status, body = health
        if status == 200 and body is not None and body.get("protocol") == "workspace.v1":
            realm = _probe(port, origin, "/api/runtime/v1/realm")
            if realm is not None and realm[0] == 200 and realm[1] is not None and isinstance(realm[1].get("realm_id"), str):
                name = _printable(realm[1]["realm_id"])
                if realm[1].get("display_name"):
                    name = f'"{_printable(realm[1]["display_name"])}" ({name})'
                return f"port {port} is already served by another Astrid Runtime for realm {name}; {stop_runtime}"
            return f"port {port} is already served by another Astrid Runtime; {stop_runtime}"
        if body is not None and body.get("error") in ("runtime_unavailable", "runtime_identity_mismatch"):
            return f"port {port} is already served by another Astrid Runtime that is not ready; {stop_runtime}"
        if status == 403 and body is not None and body.get("error") == "hosted_origin_required":
            return f"port {port} is already served by another Astrid Runtime for a different hosted origin; {stop_runtime}"
    return f"port {port} is already in use by a program that is not an Astrid Runtime; stop it, then start Astrid again"


class DoorHandler(RuntimeHandler):
    """The browser's side of ``RuntimeHandler``: admission, CORS and the header allowlists around ``_dispatch``."""

    def setup(self):
        self.timeout = self.server.door.idle_timeout
        super().setup()
        self.wfile = _CountingWriter(self.wfile)
        self._door_cors = False
        self._door_route = None
        self._door_token = None
        self._door_status = None
        self._door_cache_control = "no-store"
        self._door_extra = []
        self._door_audit_path = None
        self._door_origin = None
        self._body_consumed = False

    # -- admission ---------------------------------------------------------

    def _single(self, name):
        values = self._header_values(name)
        return values[0] if len(values) == 1 else None

    def _door(self):
        self._door_origin = self._single("Origin")
        try:
            self._admit()
        except _Refusal as refusal:
            self._refuse(refusal.status, refusal.code)
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        finally:
            self._audit()

    def _admit(self):
        door = self.server.door
        method = self.command
        route = classify(self.path, method)
        self._door_audit_path = (route.path if route else self.path).split("?", 1)[0]
        # Host is exact (a DNS-rebinding guard), and Origin is judged before the route, so a
        # foreign page learns nothing about which paths exist. Only Origin counts: media
        # elements send it in CORS mode, and a Referer is never accepted in its place.
        if self._single("Host") != f"127.0.0.1:{self.server.server_port}":
            raise _Refusal(403, "invalid_host")
        if self._door_origin != door.origin:
            raise _Refusal(403, "hosted_origin_required")
        self._door_cors = True
        if method == "OPTIONS":
            return self._preflight()
        # The page reads a refusal from its own origin, so a missing route is a 404 and not an opaque network error.
        if route is None:
            raise _Refusal(404, "route_not_allowed")
        if self._header_values("Authorization") or self._header_values("Cookie"):
            raise _Refusal(403, "browser_credentials_forbidden")
        declared = self._header_values("Content-Length")
        if len(declared) > 1 or (declared and not re.fullmatch(r"[0-9]{1,20}", declared[0].strip())):
            raise _Refusal(400, "invalid_request")
        limit = ACP_MAX_BYTES if route.service == "acp" else self.runtime.max_object_bytes if _is_binary_upload(route, method) else JSON_MAX_BYTES
        if declared and int(declared[0]) > limit:
            raise _Refusal(413, "payload_too_large")
        self._door_route = route
        # Chat is behind the same authority and readiness as every other route.
        self._door_token = self._product_token()
        if route.service == "acp":
            return self._forward_acp(route)
        self.path = route.path
        for name in {key.lower() for key in self.headers.keys()}:
            if name not in REQUEST_HEADERS and name not in _FRAMING_HEADERS:
                del self.headers[name]
        self._dispatch()

    def _preflight(self):
        # The requested route, method and headers are all judged before the 204. An ACP route
        # passes with no chat registered, so the request itself reads `acp_unavailable`.
        requested_method = self._single("Access-Control-Request-Method") or ""
        if classify(self.path, requested_method) is None:
            raise _Refusal(404, "route_not_allowed")
        if self._header_values("Authorization") or self._header_values("Cookie"):
            raise _Refusal(403, "browser_credentials_forbidden")
        # A browser sends the list once; anything else is not read as an empty list.
        listed = self._header_values("Access-Control-Request-Headers")
        if len(listed) > 1:
            raise _Refusal(403, "header_not_allowed")
        requested = [name.strip().lower() for name in (listed[0] if listed else "").split(",") if name.strip()]
        if any(name not in REQUEST_HEADERS for name in requested):
            raise _Refusal(403, "header_not_allowed")
        self._door_extra = [
            ("Access-Control-Allow-Methods", requested_method),
            ("Access-Control-Allow-Headers", ", ".join(requested)),
            # Chrome's Private Network Access preflight; Local Network Access itself is a user permission.
            ("Access-Control-Allow-Private-Network", "true"),
            ("Access-Control-Max-Age", str(PREFLIGHT_MAX_AGE_SECONDS)),
        ]
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _product_token(self) -> str:
        """The product credential, once the Runtime is ready to be used through it."""
        if not self.server.accepting_authenticated_requests or not getattr(self.runtime, "_verified", False):
            raise _Refusal(503, "runtime_unavailable")
        credential = _owner_only_json(Path(self.server.door.credential_file))
        token = credential.get("token") if credential else None
        actor = credential.get("actor_id") if credential else None
        if not isinstance(token, str) or not token or not isinstance(actor, str) or not actor:
            raise _Refusal(503, "runtime_unavailable")
        try:
            identity = self.server.credentials.require(token, "handshake")
        except AuthorizationError:
            raise _Refusal(503, "runtime_unavailable") from None
        if (identity.get("actor") != actor or actor in NON_PRODUCT_ACTORS
                or tuple(sorted(identity.get("scopes", []))) != PRODUCT_SCOPES):
            raise _Refusal(503, "runtime_identity_mismatch")
        return token

    def _identity(self, scope):
        if self.path.split("?", 1)[0] == "/v1/health":
            return {"actor": "health", "scopes": ["health"]}
        if not self.server.accepting_authenticated_requests:
            raise AuthorizationError("runtime is not accepting authenticated requests")
        return self.server.credentials.require(self._door_token, scope)

    # -- responses ---------------------------------------------------------

    def _send(self, status, payload=None, *, headers=None, body=None, error=None, receipt=None, idempotency_key=None):
        # The hosted App uses this door health response to show install-manager
        # guidance. Keep this browser-facing marker out of Runtime's canonical
        # health contract so the Runtime schema digest remains stable.
        if (
            status == 200
            and self.command == "GET"
            and self.path.split("?", 1)[0] == "/v1/health"
            and isinstance(payload, dict)
            and process_os.environ.get("ASTRID_INSTALL_MANAGED_BY") == "pinokio"
        ):
            payload = {**payload, "install": {"managed_by": "pinokio"}}
        return super()._send(
            status,
            payload,
            headers=headers,
            body=body,
            error=error,
            receipt=receipt,
            idempotency_key=idempotency_key,
        )

    def _refuse(self, status: int, code: str):
        if getattr(self, "_response_started", False):
            self.close_connection = True
            return
        self._drain()
        body = json.dumps({"error": code}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _drain(self):
        """Read a small unread request body so the refusal is seen, not a reset."""
        values = self._header_values("Content-Length")
        if self._body_consumed or len(values) != 1 or not values[0].strip().isdigit():
            return
        remaining = int(values[0])
        if remaining > _DRAIN_LIMIT_BYTES:
            self.close_connection = True
            return
        try:
            while remaining:
                chunk = self.rfile.read(min(remaining, _STREAM_CHUNK_BYTES))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            self.close_connection = True

    def _error(self, exc):
        if isinstance(exc, BodyTooLargeError):
            self.close_connection = True
            return self._send(413, error={"error": "payload_too_large"})
        return super()._error(exc)

    def send_response(self, code, message=None):
        self._door_status = code
        self._door_cache_control = object_cache_control(self.command, self._door_route, code)
        super().send_response(code, message)

    def send_header(self, keyword, value):
        name = keyword.lower()
        if name == "cache-control":
            value = self._door_cache_control
        elif name not in RESPONSE_HEADERS and name != "date":
            return
        super().send_header(keyword, value)

    def end_headers(self):
        if self._door_cors:
            super().send_header("Access-Control-Allow-Origin", self.server.door.origin)
            super().send_header("Vary", "Origin")
            super().send_header("Access-Control-Expose-Headers", ", ".join(RESPONSE_HEADERS))
        for keyword, value in self._door_extra:
            super().send_header(keyword, value)
        super().end_headers()
        self.wfile.counting = True

    def _audit(self):
        path = self.server.door.audit_log
        if path is None or self._door_status is None:
            return
        entry = {
            "at": datetime.now(timezone.utc).isoformat(), "method": self.command, "path": self._door_audit_path,
            "origin": self._door_origin, "status": self._door_status, "response_bytes": self.wfile.count,
        }
        line = (json.dumps(entry, sort_keys=True) + "\n").encode()
        with self.server.audit_lock:
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, line)
            finally:
                os.close(descriptor)

    # -- chat --------------------------------------------------------------

    def _forward_acp(self, route: DoorRoute):
        """Forward to the registered chat endpoint, streaming its answer back as it comes."""
        door = self.server.door
        chat = chat_endpoint(self.server.chat_file)
        if chat is None:
            raise _Refusal(503, "acp_unavailable")
        port, token = chat
        if self._header_values("Transfer-Encoding"):
            raise _Refusal(400, "invalid_request")
        declared = self._header_values("Content-Length")
        body = None
        if declared:
            length = int(declared[0])
            body = self.rfile.read(length)
            self._body_consumed = True
            if len(body) != length:
                raise _Refusal(400, "incomplete_request")
        headers = {name: value for name, value in self.headers.items() if name.lower() in REQUEST_HEADERS and name.lower() != "content-length"}
        headers.update({
            "Authorization": f"Bearer {token}",
            ACP_PROTOCOL_HEADER: ACP_PROTOCOL_VERSION,
            # Calls through the door always select the hosted, local-media-only policy.
            ACP_LOCAL_MEDIA_ONLY_HEADER: "1",
        })
        # Connection establishment, writes, and response transfer stay bounded.
        # A prompt has no completion deadline: progress travels on another request.
        self.connection.settimeout(door.acp_idle_timeout)
        upstream = http.client.HTTPConnection("127.0.0.1", port, timeout=door.acp_idle_timeout)
        tracked = None
        try:
            try:
                upstream.connect()
                tracked = upstream.sock
                if not self.server.track_upstream(tracked):
                    raise _Refusal(503, "acp_unavailable")
                upstream.request(self.command, route.path[len("/acp"):] or "/", body=body, headers=headers)
                if _is_acp_prompt(self.command, route.path, body):
                    if not _wait_for_prompt_response(tracked, self.connection):
                        self.close_connection = True
                        return
                response = upstream.getresponse()
            except (socket.timeout, TimeoutError):
                raise _Refusal(504, "upstream_timeout") from None
            except (OSError, http.client.HTTPException):
                raise _Refusal(503, "acp_unavailable") from None
            # An upstream redirect never moves a browser request anywhere else.
            if 300 <= response.status < 400 and response.status != 304:
                raise _Refusal(502, "upstream_redirect_forbidden")
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() in RESPONSE_HEADERS:
                    self.send_header(name, value)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self._response_started = True
            if self.command == "HEAD":
                return
            try:
                while True:
                    chunk = response.read1(_STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (OSError, http.client.HTTPException):
                # Either side went away mid-stream: the browser sees a cut connection, never a second status.
                self.close_connection = True
        finally:
            if tracked is not None:
                self.server.untrack_upstream(tracked)
            upstream.close()

    def do_OPTIONS(self):
        self._door()

    def do_GET(self):
        self._door()

    def do_HEAD(self):
        self._door()

    def do_POST(self):
        self._door()

    def do_PATCH(self):
        self._door()

    def do_PUT(self):
        self._door()

    def do_DELETE(self):
        self._door()
