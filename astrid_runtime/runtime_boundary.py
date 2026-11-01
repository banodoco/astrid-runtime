"""Concrete local boundary for the neutral workspace runtime.

The bootstrap package deliberately does not import the runtime implementation.
This module is the small adapter that turns an editable source profile into a
real loopback daemon process and a generated-client-shaped connection.
"""

from __future__ import annotations

import errno
import json
import uuid
from runtime_protocol.dirfd import filesystem as os
from runtime_protocol import platform
from runtime_protocol import cancellation
from pathlib import Path
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Mapping
from urllib.parse import urlsplit

from .bootstrap import BootstrapCustodyUncertain, BootstrapError, SourceProfile
from .loopback_http import urlopen_loopback
from .custody_broker import (
    ACTIVE_CAPABILITY_NAME,
    NativeProcessCustody,
    NATIVE_CAPABILITY_VERSION,
    CustodyError,
    AuthenticatedCleanupActor,
    RoleCustodyAuthority,
    RoleBoundCustodyBroker,
    close_authority_scope,
    custody_wrapper_argv,
    default_process_identity,
    publish_active_capability,
    load_sealed_capability,
    signal_audit_token,
    signal_sealed_capability,
)


PROTOCOL_VERSION = "workspace.v1"
WIRE_PROTOCOL = PROTOCOL_VERSION
SCHEMA_VERSION = "workspace-schema-v1"
WAIT_SECONDS = 10.0
ADMISSION_TIMEOUT_ENV = "ASTRID_RUNTIME_ADMISSION_TIMEOUT_SECONDS"
DEFAULT_ADMISSION_TIMEOUT_SECONDS = 120.0
STARTUP_WAIT_MARGIN_SECONDS = 5.0
SERVICE_OWNER_STOP_GRACE_SECONDS = 20.0


def _authoring_profile(source: SourceProfile) -> str:
    """Resolve the trusted provider profile for either Runtime launch route."""
    profile = {"astrid": "astrid"}.get(source.profile)
    if profile is None:
        raise BootstrapError(
            "Source profile has no supported Runtime authoring profile: "
            f"{source.profile!r}"
        )
    return profile


def _admission_timeout_from_environment() -> float:
    """Read the bounded startup integrity budget from the install environment."""
    raw = os.environ.get(ADMISSION_TIMEOUT_ENV)
    if raw in (None, ""):
        return DEFAULT_ADMISSION_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise BootstrapError(f"{ADMISSION_TIMEOUT_ENV} must be a finite positive number.") from exc
    if not (value > 0 and value != float("inf") and value == value):
        raise BootstrapError(f"{ADMISSION_TIMEOUT_ENV} must be a finite positive number.")
    return value


class RuntimeCustodyLaunchUncertain(BootstrapError):
    """Retain a created child even when admission/publication failed."""

    def __init__(self, message: str, *, process: subprocess.Popen[str], broker: RoleBoundCustodyBroker):
        super().__init__(message)
        self.process = process
        self.broker = broker


class RuntimeConnection:
    """Generated-client compatible connection plus bootstrap-only provisioning."""

    def __init__(self, endpoint: str, credential: str, bootstrap_credential: str | None = None):
        self.endpoint = endpoint.rstrip("/")
        self.credential = credential
        self.bootstrap_credential = bootstrap_credential
        self._client = None

    def _generated(self):
        if self._client is None:
            raise RuntimeError("generated client is unavailable")
        return self._client

    def __getattr__(self, name):
        return getattr(self._generated(), name)

    def _request(self, method: str, path: str, body: Mapping[str, Any], token: str):
        encoded = json.dumps(dict(body), separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.endpoint + path,
            data=encoded,
            method=method,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            },
        )
        try:
            with urlopen_loopback(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8"))
            except Exception:
                detail = {"message": str(exc)}
            raise BootstrapError(f"Runtime credential provisioning failed: {detail}") from exc

    def provision_actor(self, *, scope: str, actor_id: str, credential: str):
        # On reconnect the one-time bootstrap credential is gone. The actor
        # credential is already durable, so provisioning is intentionally a
        # no-op in that case.
        if self.bootstrap_credential:
            value = self._request(
                "POST",
                "/v1/credentials",
                {
                    "actor_id": actor_id,
                    "credential": credential,
                    "scope": scope,
                },
                self.bootstrap_credential,
            )
            if value.get("scope") != scope:
                raise BootstrapError("Runtime returned an unexpected credential scope.")
        return {"scope": scope, "actor_id": actor_id}

    def select_realm(self, *, actor_id: str, realm_id: str):
        # Realm selection is represented durably by the neutral catalog. The
        # runtime has one realm per process in Stage 1, so no extra API call is
        # needed here; retaining this method keeps the generated seam explicit.
        return {"actor_id": actor_id, "realm_id": realm_id}

    def handshake(self, **kwargs):
        # The generated client uses the canonical handshake signature while the
        # bootstrap protocol passes version keywords. Bridge both shapes.
        requested = [
            "projects:read", "projects:write", "objects:read", "objects:write",
            "tasks:read", "tasks:write",
        ]
        return self._generated().handshake("astrid-local", "0.1.0", requested)


class LocalRuntimeBoundary:
    """Launch and supervise a loopback daemon from an editable source profile."""

    # Health is a loopback request, but the daemon may be briefly busy while
    # finishing startup or serving another control-plane request.  Keep this
    # bounded without making a normal, healthy runtime look stale.
    HEALTH_TIMEOUT_SECONDS = 5.0

    def __init__(self, *, wait_seconds: float | None = None):
        self.admission_timeout_seconds = _admission_timeout_from_environment()
        requested_wait = WAIT_SECONDS if wait_seconds is None else float(wait_seconds)
        if requested_wait <= 0 or requested_wait != requested_wait or requested_wait == float("inf"):
            raise BootstrapError("wait_seconds must be a finite positive number.")
        self.wait_seconds = max(requested_wait, self.admission_timeout_seconds + STARTUP_WAIT_MARGIN_SECONDS)
        self._process: subprocess.Popen[str] | None = None
        self._source: SourceProfile | None = None
        self._realm_root: Path | None = None
        self._support_root: Path | None = None
        self._realm_id: str | None = None
        self._display_name = "Astrid Workspace"
        self._bootstrap_credential: str | None = None
        self._detached_pid: int | None = None
        self._door: tuple[Any, Path] | None = None
        # Where this start's own lines begin in runtime.log, so a startup failure is reported by its cause.
        self._log_offset = 0

    @staticmethod
    def _validate_source(source: SourceProfile) -> None:
        """Validate only the explicitly configured product source.

        The runtime and generated client are installed dependencies.  A
        checkout path is provenance for the editable source profile, never an
        import or launch fallback for the neutral runtime.
        """
        runtime_checkout = Path(source.runtime_checkout).expanduser()
        if not runtime_checkout.is_absolute():
            raise BootstrapError("Source profile must provide an absolute pinned runtime_checkout.")
        LocalRuntimeBoundary._validate_path(runtime_checkout, "runtime checkout")
        source_checkout = Path(source.source_checkout).expanduser()
        LocalRuntimeBoundary._validate_path(source_checkout, "source checkout")
        if source_checkout.is_symlink():
            raise BootstrapError("Source checkout from the editable profile must not be a symlink.")
        source_checkout = source_checkout.resolve()
        if not source_checkout.exists():
            raise BootstrapError(f"Source checkout from the editable profile does not exist: {source_checkout}")
        if source.worker_profile:
            worker_profile = Path(source.worker_profile).expanduser()
            LocalRuntimeBoundary._validate_path(worker_profile, "worker profile")
            if worker_profile.is_symlink() or not worker_profile.is_file():
                raise BootstrapError(f"Configured worker profile is unavailable: {worker_profile}")
        if source.runtime_environment:
            environment = Path(source.runtime_environment).expanduser()
            LocalRuntimeBoundary._validate_path(environment, "runtime environment")
            if not environment.is_dir():
                raise BootstrapError(f"Configured runtime environment does not exist: {environment}")

    @staticmethod
    def _validate_path(path: Path, label: str) -> Path:
        """Reject operator-controlled path aliases before resolving them."""
        target = Path(path).expanduser()
        if not target.is_absolute():
            raise BootstrapError(f"{label} must be absolute")
        current = Path(target.anchor)
        for component in target.parts[1:]:
            current /= component
            # /var and /tmp are protected macOS compatibility aliases; all
            # support-relative components below them are still checked.
            if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
                raise BootstrapError(f"{label} must not traverse a symlink")
        return target

    def configure_source(self, source: SourceProfile) -> None:
        self._source = source

    def configure_door(self, door, credential_file: Path) -> None:
        """Open the hosted page's browser door (``DoorSettings``, or None) in every daemon this boundary starts."""
        self._door = None if door is None else (door, Path(credential_file))

    @staticmethod
    def _token_file(support_root: Path, token: str) -> Path:
        LocalRuntimeBoundary._validate_path(support_root, "runtime support root")
        platform.private_directory(support_root)
        fd, name = platform.private_temporary(support_root, ".bootstrap-token-")
        path = Path(name)
        platform.owner_only(path)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        return path

    def _argv(self, source: SourceProfile, *, realm_id: str, realm_root: Path, support_root: Path, display_name: str, owner_lock: Path, token_file: Path) -> list[str]:
        self._validate_source(source)
        if source.runtime_command:
            argv = list(source.runtime_command)
        else:
            python = sys.executable
            if source.runtime_environment:
                candidate = platform.venv_python(Path(source.runtime_environment).expanduser().resolve())
                if not candidate.is_file() or not os.access(candidate, os.X_OK):
                    raise BootstrapError(
                        "Configured runtime environment is missing its installed Python: "
                        f"{candidate}"
                    )
                python = str(candidate)
            authoring_profile = _authoring_profile(source)
            argv = [python, "-X", "utf8", "-m", "runtime_protocol", "start", "--authoring-profile", authoring_profile]
        replacements = {
            "{realm_id}": realm_id,
            "{realm_root}": str(realm_root),
            "{support_root}": str(support_root),
            "{display_name}": display_name,
            "{owner_lock}": str(owner_lock),
            "{bootstrap_token_file}": str(token_file),
        }
        argv = [replacements.get(part, part) for part in argv]
        if not any("--root" == part for part in argv):
            argv += ["--root", str(realm_root)]
        if not any("--support-root" == part for part in argv):
            argv += ["--support-root", str(support_root)]
        if not any("--display-name" == part for part in argv):
            argv += ["--display-name", display_name]
        if not any("--realm-id" == part for part in argv):
            argv += ["--realm-id", realm_id]
        if not any("--owner-lock" == part for part in argv):
            argv += ["--owner-lock", str(owner_lock)]
        if not any("--bootstrap-token-file" == part for part in argv):
            argv += ["--bootstrap-token-file", str(token_file)]
        if not any("--admission-timeout" == part for part in argv):
            argv += ["--admission-timeout", str(self.admission_timeout_seconds)]
        if source.worker_profile and "--worker-profile" not in argv:
            argv += ["--worker-profile", str(Path(source.worker_profile).expanduser().resolve())]
        if source.service_declaration:
            argv += ["--service-declaration", source.service_declaration,
                "--service-python", python, "--service-source-checkout", source.source_checkout]
        argv += ["--runtime-checkout", source.runtime_checkout, "--agent-checkout", source.source_checkout]
        argv += ["--log-file", str(self._log_path(support_root))]
        if self._door is not None and "--door-origin" not in argv:
            door, credential_file = self._door
            argv += ["--door-origin", door.origin, "--door-port", str(door.port), "--door-credential-file", str(credential_file)]
        return argv

    def create(self, *, realm_id: str, realm_root: Path, display_name: str, source_profile: SourceProfile) -> Mapping[str, Any]:
        """Explicitly provision one fresh realm before launching its daemon.

        Ordinary ``start`` remains an open/admission operation and therefore
        refuses a missing or invalid realm.  This separate subprocess invokes
        the Runtime's canonical creation command, keeping schema, identity,
        and ownership inside Runtime rather than recreating them in the
        neutral launcher.
        """
        realm_root = self._validate_path(Path(realm_root), "realm root").resolve()
        if realm_root.exists() or realm_root.is_symlink():
            raise BootstrapError("fresh realm creation requires a new root")
        self._validate_source(source_profile)
        if source_profile.runtime_command:
            raise BootstrapError("explicit realm creation requires the pinned runtime environment")
        python = sys.executable
        if source_profile.runtime_environment:
            candidate = platform.venv_python(Path(source_profile.runtime_environment).expanduser().resolve())
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                raise BootstrapError(
                    "Configured runtime environment is missing its installed Python: "
                    f"{candidate}"
                )
            python = str(candidate)
        environment = None
        if sys.platform == "win32":
            from runtime_protocol.windows_handoff import python_executable

            # The Windows venv redirector starts a second process.  Invoke the
            # actual interpreter directly so the creation command has the same
            # selected-venv identity and custody boundary as daemon startup.
            executable = python_executable(python)
            environment = dict(os.environ)
            environment.pop("__PYVENV_LAUNCHER__", None)
            if executable != python:
                environment["__PYVENV_LAUNCHER__"] = str(python)
            python = executable
        argv = [
            python, "-X", "utf8", "-m", "runtime_protocol", "create",
            "--root", str(realm_root),
            "--display-name", display_name,
            "--realm-id", realm_id,
        ]
        try:
            result = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                env=environment,
            )
        except OSError as exc:
            raise BootstrapError("Runtime realm creation could not start.") from exc
        output = result.stdout.strip()
        errors = (getattr(result, "stderr", "") or "").strip()
        if result.returncode != 0:
            diagnostic = "\n".join(value for value in (output, errors) if value)
            raise BootstrapError(
                "Runtime realm creation failed: " + (diagnostic or "no diagnostic")
            )
        try:
            created = json.loads(output)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            diagnostic = "\n".join(value for value in (output, errors) if value)
            diagnostic = diagnostic if len(diagnostic) <= 4096 else diagnostic[:4096] + "... [truncated]"
            raise BootstrapError(
                "Runtime realm creation returned invalid metadata: " + repr(diagnostic)
            ) from exc
        if not isinstance(created, Mapping):
            raise BootstrapError("Runtime realm creation returned invalid metadata.")
        return created

    def inspect(self, *, realm_root: Path) -> Mapping[str, Any]:
        """Run Runtime's bounded doctor without opening or starting authority."""
        root = self._validate_path(Path(realm_root), "realm root")
        if root.is_symlink() or not root.is_dir():
            raise BootstrapError(f"realm root is unavailable: {root}")
        result = subprocess.run(
            [
                sys.executable, "-X", "utf8", "-m", "runtime_protocol", "doctor",
                "--root", str(root), "--json",
                "--admission-timeout", str(self.admission_timeout_seconds),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        try:
            report = json.loads(result.stdout.strip())
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BootstrapError("Runtime realm inspection returned invalid metadata.") from exc
        if not isinstance(report, Mapping):
            raise BootstrapError("Runtime realm inspection returned invalid metadata.")
        return report

    def _spawn_runtime(self, argv: list[str], *, support_root: Path, stdout):
        """Publish exact child custody before any admission wait can fail."""
        environment = dict(os.environ)
        # The former installer transaction binding is never propagated to a
        # daemon, even when inherited from an older launcher environment.
        environment.pop("ASTRID_INSTALLER_OPERATION_ID", None)
        if sys.platform != "darwin":
            if sys.platform == "win32":
                from runtime_protocol.windows_handoff import python_executable

                # Keep discovery and custody on the interpreter's PID, rather
                # than the venv redirector that waits for it on Windows.
                executable = python_executable(argv[0])
                environment.pop("__PYVENV_LAUNCHER__", None)
                if executable != argv[0]:
                    environment["__PYVENV_LAUNCHER__"] = str(argv[0])
                argv = [executable, *argv[1:]]
            process = platform.spawn_tree(argv, detached=True, stdout=stdout,
                stderr=subprocess.STDOUT, text=True, close_fds=True,
                env=environment)
            process._runtime_stop_grace = SERVICE_OWNER_STOP_GRACE_SECONDS if "--service-declaration" in argv else 5.0
            process._runtime_boundary_sole_reaper = True
            self._process = process
            return process, None
        run_id = uuid.uuid4().hex
        ledger_root = support_root / "runtime-custody" / run_id
        ledger_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        scope = support_root / "runtime-custody-scopes" / run_id
        scope.mkdir(mode=0o700, parents=True)
        broker = RoleBoundCustodyBroker(
            role="runtime_owner",
            identity_provider=default_process_identity,
            ledger_root=ledger_root,
            timeout=min(10.0, self.admission_timeout_seconds),
            authority_scope_root=scope,
            authority_journal=scope / "retained-authority.jsonl",
            retain_post_exec_connection=True,
        )
        environment.update(broker.child_environment(argv, start_new_session=True))
        try:
            process = subprocess.Popen(
                custody_wrapper_argv(argv[0]), stdout=stdout,
                stderr=subprocess.STDOUT, text=True, env=environment,
                start_new_session=False, close_fds=True,
            )
        except BaseException:
            broker.abort_before_spawn()
            raise
        # This object is the sole reaper; adopted owners cannot use this fact.
        process._runtime_boundary_owner = self
        process._runtime_stop_grace = SERVICE_OWNER_STOP_GRACE_SECONDS if "--service-declaration" in argv else 5.0
        process._runtime_boundary_sole_reaper = True
        process._runtime_custody_broker = broker
        self._process = process
        try:
            broker.wait_until_sealed()
        except CustodyError as exc:
            raise RuntimeCustodyLaunchUncertain(
                "Runtime child exists but custody admission is uncertain.",
                process=process, broker=broker,
            ) from exc
        return process, broker

    def start(self, *, realm_id: str, realm_root: Path, owner_lock: Path, source_profile: SourceProfile) -> Mapping[str, Any]:
        if self._process and self._process.poll() is None:
            raise BootstrapError("runtime boundary already owns a live daemon")
        realm_root = self._validate_path(Path(realm_root), "realm root")
        owner_lock = self._validate_path(Path(owner_lock), "owner lock")
        support_root = self._validate_path(owner_lock.parent, "runtime support root")
        self._validate_source(source_profile)
        # Resolve only after the lexical fence.  No source profile field can
        # replace these neutral authority paths.
        realm_root = realm_root.resolve()
        support_root = support_root.resolve()
        owner_lock = owner_lock.resolve()
        bootstrap_token = os.urandom(32).hex()
        token_file = self._token_file(support_root, bootstrap_token)
        argv = self._argv(source_profile, realm_id=realm_id, realm_root=realm_root, support_root=support_root, display_name=self._display_name, owner_lock=owner_lock, token_file=token_file)
        log_path = self._log_path(support_root)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        platform.owner_only(log_path.parent)
        # The daemon owns its rotating stream; no inherited file descriptor
        # holds a log open across a Windows rename.
        self._log_offset = log_path.stat().st_size if log_path.exists() else 0
        try:
            # Do not derive imports from either checkout.  The selected
            # runtime_environment is an installed environment and the child
            # inherits the host's already-configured environment unchanged.
            # Preserve the daemon's structured startup failure on the existing
            # operator log boundary; successful stdout is only its one-line
            # launch record.
            self._process, broker = self._spawn_runtime(argv, support_root=support_root, stdout=subprocess.DEVNULL)
        except Exception:
            token_file.unlink(missing_ok=True)
            raise
        self._source, self._realm_root, self._support_root, self._realm_id = source_profile, realm_root, support_root, realm_id
        self._bootstrap_credential = bootstrap_token
        try:
            endpoint = self._wait_endpoint(support_root, self._process)
            discovery = self._read_discovery(support_root)
            identity = default_process_identity(self._process.pid)
            if identity is None:
                raise BootstrapError("Ready Runtime child disappeared before custody publication.")
            if platform.process_birth_matches(str(discovery.get("process_birth_id") or ""), str(identity.get("birth_id") or "")) is not True:
                raise BootstrapError("Ready Runtime birth identity differs from discovery.")
            if broker is None:
                custody = NativeProcessCustody(support_root, identity)
                custody.publish()
                self._process._runtime_native_custody = custody
            else:
                broker.bind_ready_token(expected_pid=self._process.pid, expected_identity=identity)
                publish_active_capability(support_root / ACTIVE_CAPABILITY_NAME, broker)
        except Exception:
            self._terminate(self._process)
            token_file.unlink(missing_ok=True)
            self._bootstrap_credential = None
            raise
        return {
            "endpoint": endpoint,
            "pid": self._process.pid,
            "process_birth_id": discovery.get("process_birth_id") or self.process_birth_identity(self._process.pid),
            "runtime_instance_id": discovery.get("runtime_instance_id", ""),
            "coordinator_epoch": discovery.get("coordinator_epoch"),
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "capability_digest": source_profile.capability_digest,
            # These are paths and public metadata only; the scoped worker
            # secret remains in the runtime-owned 0600 file.
            "worker_credential_file": discovery.get("worker_credential_file"),
            "worker_credential_pending": bool(discovery.get("worker_credential_pending")),
            "worker_actor": discovery.get("worker_actor"),
            "worker_scopes": discovery.get("worker_scopes", ()),
            "door_endpoint": discovery.get("door_endpoint"),
            "door_origin": discovery.get("door_origin"),
        }

    def _read_discovery(self, support_root: Path) -> dict[str, Any]:
        return self._read_discovery_file(self._validate_path(Path(support_root) / "discovery.json", "runtime discovery"))

    @classmethod
    def _read_discovery_file(cls, path: Path) -> dict[str, Any]:
        if platform.sys.platform == "win32":
            try:
                value = json.loads(platform.read_private_file(path).decode("utf-8"))
            except FileNotFoundError:
                return {}
            except OSError as exc:
                raise BootstrapError(f"Runtime discovery access refused: {exc}") from exc
            return value if isinstance(value, dict) else {}
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return {}
                chunks = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                value = json.loads(b"".join(chunks).decode("utf-8"))
            finally:
                os.close(fd)
            return value if isinstance(value, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
            return {}

    @staticmethod
    def process_birth_identity(pid: int) -> str | None:
        """Return the shared native process start marker."""
        try:
            identity = default_process_identity(int(pid))
            return None if identity is None else str(identity["birth_id"])
        except CustodyError as exc:
            raise BootstrapError("Runtime process identity remains uncertain.") from exc

    @staticmethod
    def _log_path(support_root: Path) -> Path:
        # Preserve the established macOS background log location.
        return support_root / "runtime.log" if sys.platform == "darwin" else platform.log_dir() / "runtime.log"

    @staticmethod
    def _startup_failure(log_path: Path, offset: int) -> str | None:
        """The daemon's own structured startup error, from what it logged after ``offset``."""
        try:
            with log_path.open("rb") as handle:
                size = log_path.stat().st_size
                handle.seek(max(offset if offset <= size else 0, size - 65536))
                lines = handle.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return None
        for line in reversed(lines):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            error = value.get("error") if isinstance(value, dict) and value.get("ok") is False else None
            if isinstance(error, dict) and isinstance(error.get("message"), str):
                return error["message"]
        return None

    def _wait_endpoint(self, support_root: Path, process: subprocess.Popen[str]) -> str:
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            cancellation.check()
            if process.poll() is not None:
                cause = self._startup_failure(self._log_path(support_root), self._log_offset)
                raise BootstrapError(
                    f"Runtime daemon exited during startup: {cause} (see {self._log_path(support_root)})." if cause
                    else f"Runtime daemon exited during startup (see {self._log_path(support_root)})."
                )
            discovery = self._read_discovery(support_root)
            # A support root may still advertise a healthy incumbent while a
            # replacement candidate is starting.  Never adopt that endpoint:
            # doing so lets the candidate's rollback clear the incumbent's
            # discovery and owner marker.  The daemon publishes its own PID
            # atomically only after realm admission succeeds.
            try:
                advertised_pid = int(discovery.get("pid", 0))
            except (TypeError, ValueError):
                advertised_pid = 0
            if advertised_pid and advertised_pid != process.pid:
                cancellation.pause(0.05) if cancellation.active() else time.sleep(0.05)
                continue
            endpoint = str(discovery.get("endpoint", ""))
            if endpoint and self._http_health(endpoint):
                cancellation.check()
                return endpoint
            cancellation.pause(0.05) if cancellation.active() else time.sleep(0.05)
        self._terminate(process)
        raise BootstrapError("Runtime daemon did not become healthy before the bounded startup deadline.")

    @staticmethod
    def _http_status(endpoint: str) -> str | None:
        value = LocalRuntimeBoundary._http_health_payload(endpoint)
        return value.get("status") if value else None

    @staticmethod
    def _http_health_payload(endpoint: str) -> dict[str, Any] | None:
        try:
            parsed = urlsplit(str(endpoint))
            if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")
                    or parsed.port is None or not (1 <= parsed.port <= 65535)):
                return None
        except ValueError:
            return None
        # Identity observation must remain reachable under the lifecycle write fence.
        request = urllib.request.Request(
            str(endpoint).rstrip("/") + "/v1/health",
            headers={"Accept": "application/json", "X-Astrid-Owner-Identity": "1"},
        )
        try:
            def read(timeout):
                with urlopen_loopback(request, timeout=timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            value = cancellation.retry_timeouts(read, LocalRuntimeBoundary.HEALTH_TIMEOUT_SECONDS)
            if isinstance(value, dict) and value.get("protocol") == WIRE_PROTOCOL:
                status = value.get("status")
                if status in ("ok", "degraded"):
                    return value
            return None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _http_health(endpoint: str) -> bool:
        return LocalRuntimeBoundary._http_status(endpoint) == "ok"

    def connect(self, *, endpoint: str, credential: str, timeout_seconds: float | None = None) -> RuntimeConnection:
        try:
            parsed = urlsplit(str(endpoint))
            if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")
                    or parsed.port is None or not (1 <= parsed.port <= 65535)):
                raise ValueError
        except ValueError as exc:
            raise BootstrapError("runtime endpoint must be an HTTP loopback authority") from exc
        try:
            from astrid_runtime_client import WorkspaceClient
        except ImportError as exc:
            raise BootstrapError("The installed generated workspace client is unavailable; install astrid-runtime-client.") from exc
        connection = RuntimeConnection(endpoint, credential, self._bootstrap_credential)
        # Upgrade integrity verification can legitimately exceed the generated
        # client's ordinary request timeout. Keep its explicit bounded budget
        # local to that connection; other bootstrap requests retain the default.
        options = {} if timeout_seconds is None else {"timeout": timeout_seconds}
        connection._client = WorkspaceClient(endpoint, credential, **options)
        return connection

    def health(self, *, endpoint: str, pid: int, instance_id: str) -> bool:
        health = self._http_health_payload(endpoint)
        return bool(
            self.is_pid_alive(pid)
            and health
            and health.get("status") == "ok"
            and health.get("runtime_instance_id") == instance_id
        )

    def owner_startup_identity(self, *, endpoint: str, instance_id: str) -> Mapping[str, Any] | None:
        """Return canonical health so the caller can validate its owner binding."""
        return self._http_health_payload(endpoint)

    def endpoint_metadata(self, *, endpoint: str, credential_file: Path) -> Mapping[str, Any]:
        """Read endpoint instance and authenticated realm identity without mutation."""
        health = self._http_health_payload(endpoint)
        if not health:
            return {}
        try:
            credential_path = self._validate_path(Path(credential_file), "runtime credential")
            if platform.sys.platform == "win32":
                raw = platform.read_private_file(credential_path)
            else:
                fd = os.open(credential_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        return {}
                    raw = bytearray()
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        raw.extend(chunk)
                finally:
                    os.close(fd)
            token = bytes(raw).decode("utf-8").strip()
            if not token:
                return {}
            request = urllib.request.Request(
                str(endpoint).rstrip("/") + "/v1/realm",
                headers={"Accept": "application/json", "Authorization": f"Bearer {token}",
                         "X-Astrid-Owner-Identity": "1"},
            )
            with urlopen_loopback(request, timeout=self.HEALTH_TIMEOUT_SECONDS) as response:
                realm = json.loads(response.read().decode("utf-8"))
            if not isinstance(realm, Mapping) or not realm.get("realm_id"):
                return {}
            # Older supported Runtime releases authenticated `/v1/realm` but
            # did not include the optional instance id on that resource. The
            # health snapshot still binds the endpoint to the observed owner;
            # when realm supplies its own instance id, require it to agree.
            realm_instance_id = realm.get("runtime_instance_id")
            if (realm_instance_id is not None
                    and (health.get("runtime_instance_id") is None
                         or str(realm_instance_id) != str(health["runtime_instance_id"]))):
                return {}
            return {**health, "realm_id": str(realm["realm_id"])}
        except (BootstrapError, OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            if platform.sys.platform == "win32" and isinstance(exc, OSError) and not isinstance(exc, FileNotFoundError):
                raise BootstrapError(f"Runtime credential access refused: {exc}") from exc
            return {}

    def validate_owner(
        self, *, endpoint: str, pid: int, instance_id: str, owner_lock: Path,
        process_birth_id: str | None = None, expected_realm_id: str | None = None,
        expected_realm_root: Path | None = None,
    ) -> bool:
        if not self.is_pid_alive(pid):
            return False
        try:
            path = self._validate_path(Path(owner_lock), "owner lock")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    return False
                chunks = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                marker = json.loads(b"".join(chunks).decode("utf-8"))
            finally:
                os.close(fd)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError):
            return False
        if not isinstance(marker, dict):
            return False
        if str(marker.get("pid")) != str(pid) or str(marker.get("runtime_instance_id")) != instance_id:
            return False
        if expected_realm_id is not None and str(marker.get("realm_id")) != str(expected_realm_id):
            return False
        if expected_realm_root is not None:
            try:
                expected_root = self._validate_path(Path(expected_realm_root), "expected realm root").resolve()
                marker_root = self._validate_path(Path(str(marker.get("realm_root") or "")), "owner realm root").resolve()
            except (BootstrapError, OSError):
                return False
            if marker_root != expected_root:
                return False
        expected_birth = process_birth_id or marker.get("process_birth_id")
        if not expected_birth:
            return False
        actual_birth = self.process_birth_identity(pid)
        health = self._http_health_payload(endpoint)
        if not health or health.get("runtime_instance_id") != instance_id:
            return False
        if actual_birth is None:
            # Restricted clients may be able to prove that a PID exists but
            # not inspect its birth marker. Require the daemon itself to
            # attest the durable runtime instance over its loopback health
            # endpoint; health alone is never an identity proof.
            pass
        elif platform.process_birth_matches(str(expected_birth), actual_birth) is not True:
            return False
        # A degraded runtime can still be the correct owner. Keep health
        # admission separate so database failures are not called PID conflicts.
        return True

    @staticmethod
    def is_pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            return default_process_identity(pid) is not None
        except CustodyError:
            # Unknown observation protects the incumbent; it never grants signal authority.
            return True

    @staticmethod
    def _terminate(process: subprocess.Popen[str]):
        primary = sys.exc_info()[1]
        broker = getattr(process, "_runtime_custody_broker", None)
        grace = getattr(process, "_runtime_stop_grace", 5.0)
        try:
            if sys.platform != "darwin":
                platform.stop_tree(process, grace=grace)
                return
            if not getattr(process, "_runtime_boundary_sole_reaper", False):
                raise CustodyError("Runtime child has no authoritative sole-reaper ownership")
            if process.poll() is not None:
                return
            if not isinstance(broker, RoleBoundCustodyBroker):
                raise CustodyError("Runtime child has no registered kernel custody")
            close_channel = getattr(broker, "close_post_exec_channel", None)
            if close_channel is not None:
                close_channel()
            deadline = time.monotonic() + grace + 2.0
            broker.set_cleanup_deadline(deadline)
            if broker.authority_scope_root is not None:
                close_authority_scope(broker.authority_scope_root, deadline=deadline)
            signal_owned = broker.signal_failed_admission if broker.error is not None else broker.signal
            for signum, timeout in ((platform.TERM, grace), (platform.KILL, 2.0)):
                if process.poll() is not None:
                    return
                try:
                    signal_owned(signum, expected_pid=process.pid)
                except CustodyError:
                    # Only the retained, reaped direct-child handle proves this exit race.
                    if process.poll() is not None:
                        return
                    raise
                try:
                    process.wait(timeout=timeout)
                    return
                except subprocess.TimeoutExpired:
                    continue
            raise CustodyError("Runtime child remains alive after bounded kernel-custody cleanup")
        except (CustodyError, OSError) as exc:
            failure = BootstrapError(f"Runtime cleanup remains uncertain: {exc}")
            process._runtime_cleanup_error = failure
            if primary is not None:
                raise primary.with_traceback(primary.__traceback__) from failure
            raise failure from exc

    def stop(self, **_kwargs):
        process = self._process
        if process is not None:
            anchor = getattr(process, "_runtime_owner_released_anchor", None)
            if anchor is not None and process.poll() is None:
                broker = self._process._runtime_custody_broker
                ack = self._commit_owner_transition(
                    broker.role_authority, kind="claim", actor=broker.cleanup_actor,
                    generation=broker.role_authority.reference()["generation"],
                    owner_epoch=broker.owner_epoch, sealed=anchor,
                )
                broker.custody_generation = ack["generation"]
                del process._runtime_owner_released_anchor
            self._terminate(process)
            self._process = None
        self._bootstrap_credential = None
        return {"children_stopped": True}

    def _commit_owner_transition(self, authority: RoleCustodyAuthority, *, kind: str,
                                 actor: AuthenticatedCleanupActor, generation: int,
                                 owner_epoch: str, sealed: Mapping[str, object] | None = None) -> dict[str, object]:
        identifier = uuid.uuid4().hex
        intent = authority._runtime_intent(kind=kind, actor=actor, generation=generation,
                                           transition_id=identifier, owner_epoch=owner_epoch, sealed=sealed)
        error = None
        for _ in range(2):
            try:
                if kind == "relinquish":
                    authority.relinquish(actor=actor, generation=generation,
                                         transition_id=identifier, owner_epoch=owner_epoch)
                else:
                    authority.claim(actor=actor, generation=generation, transition_id=identifier,
                                    sealed=sealed, owner_epoch=owner_epoch, identity_provider=default_process_identity)
                ack = authority.committed(identifier, intent)
                if ack is not None:
                    return ack
            except (CustodyError, OSError) as exc:
                error = exc
        try:
            ack = authority.committed(identifier, intent)
        except (CustodyError, OSError) as exc:
            failure = BootstrapCustodyUncertain(
                f"Runtime {kind} commit unknown; transition {identifier}; support state preserved, cleanup unresolved.", controller=self)
            failure.transition_id = identifier
            failure.replay_intent = dict(intent)
            self._custody_transition_uncertain = failure
            raise failure from exc
        if ack is not None:
            return ack
        raise BootstrapError(f"Runtime {kind} not committed; transition {identifier}: {error}") from error

    def release_owner_custody(self) -> Mapping[str, Any]:
        process = self._process
        native = getattr(process, "_runtime_native_custody", None)
        if native is not None:
            return native.release()
        broker = getattr(process, "_runtime_custody_broker", None)
        if process is None or not isinstance(broker, RoleBoundCustodyBroker):
            raise BootstrapError("Runtime release lacks its retained launch controller.")
        anchor = broker.role_authority.reference()
        ack = self._commit_owner_transition(broker.role_authority, kind="relinquish", actor=broker.cleanup_actor,
                                            generation=broker.custody_generation, owner_epoch=broker.owner_epoch)
        # Only a reread durable ACK advances our local generation. The retained
        # Popen remains available for an explicit same-controller rollback.
        broker.custody_generation = ack["generation"]
        process._runtime_owner_released_anchor = anchor
        return ack

    def stop_owner(self, **kwargs) -> Mapping[str, Any]:
        """Stop an adopted owner using the same birth/lock fences as restart."""
        return self.restart(**kwargs, start_after_stop=False)

    def prepare_restart(self, *, source_profile: SourceProfile, realm_id: str, realm_root: Path, support_root: Path, pid: int) -> None:
        """Adopt a detached daemon for an operator restart.

        ``astrid-runtime up`` intentionally leaves the daemon in its own
        process group, so a later CLI invocation has no ``Popen`` handle.  The
        support lock/discovery record is the only durable hand-off; adopting
        it here lets restart terminate exactly that owner and relaunch the
        same realm without opening its database in the launcher.
        """
        self._source = source_profile
        self._realm_id = str(realm_id)
        self._realm_root = self._validate_path(Path(realm_root), "realm root").resolve()
        self._support_root = self._validate_path(Path(support_root), "runtime support root").resolve()
        self._detached_pid = int(pid)

    def restart(self, **kwargs) -> Mapping[str, Any]:
        if not self._source or not self._realm_root or not self._support_root or not self._realm_id:
            raise BootstrapError("No runtime process is available to restart.")
        source, root, support, realm_id = self._source, self._realm_root, self._support_root, self._realm_id
        shutdown_grace = SERVICE_OWNER_STOP_GRACE_SECONDS if getattr(source, "service_declaration", None) else 5.0
        start_after_stop = bool(kwargs.get("start_after_stop", True))
        require_health = bool(kwargs.get("require_health", True))
        endpoint = str(kwargs.get("endpoint", ""))
        expected_pid = int(kwargs.get("pid", 0))
        expected_instance = str(kwargs.get("instance_id", ""))
        expected_birth = str(kwargs.get("process_birth_id", ""))
        expected_realm = str(kwargs.get("realm_id", realm_id))
        owner_lock = self._validate_path(Path(kwargs.get("owner_lock", support / "instance.lock")), "owner lock").resolve()
        discovery_path = self._validate_path(Path(kwargs.get("discovery_path", support / "discovery.json")), "runtime discovery").resolve()
        exit_evidence = None
        native_record = self._read_discovery_file(support / ACTIVE_CAPABILITY_NAME)
        native_owner = native_record.get("version") == NATIVE_CAPABILITY_VERSION

        def validate_before_signal(*, require_health: bool = True) -> None:
            """Re-read every fence immediately before the first signal."""
            if expected_pid <= 0 or not endpoint or not expected_instance or not expected_birth:
                raise BootstrapError("Runtime restart refused: discovery identity is incomplete.")
            if expected_pid == os.getpid():
                raise BootstrapError("Runtime restart refused: owner PID is the current operator process.")
            try:
                discovery = self._read_discovery_file(discovery_path)
                fd = os.open(owner_lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise OSError("owner lock is not a regular file")
                    marker = json.loads(os.read(fd, 1024 * 1024).decode("utf-8"))
                finally:
                    os.close(fd)
            except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise BootstrapError("Runtime restart refused: owner discovery or lock is unavailable.") from exc
            try:
                expected_root = self._validate_path(root, "expected realm root").resolve()
                discovery_root = self._validate_path(
                    Path(str(discovery.get("realm_root") or "")), "discovery realm root"
                ).resolve()
                marker_root = self._validate_path(
                    Path(str(marker.get("realm_root") or "")), "owner realm root"
                ).resolve()
            except (BootstrapError, OSError) as exc:
                raise BootstrapError("Runtime restart refused: realm-root identity is invalid.") from exc
            health = self._http_health_payload(endpoint)
            endpoint_identity = self.endpoint_metadata(
                endpoint=endpoint,
                credential_file=support / "credentials" / "owner.token",
            )
            checks = (
                str(discovery.get("pid")) == str(expected_pid),
                str(discovery.get("endpoint")) == endpoint,
                str(discovery.get("runtime_instance_id")) == expected_instance,
                str(discovery.get("process_birth_id")) == expected_birth,
                str(discovery.get("active_realm")) == expected_realm,
                discovery_root == expected_root,
                str(marker.get("pid")) == str(expected_pid),
                str(marker.get("runtime_instance_id")) == expected_instance,
                str(marker.get("process_birth_id")) == expected_birth,
                str(marker.get("realm_id")) == expected_realm,
                marker_root == expected_root,
                self.is_pid_alive(expected_pid),
                platform.process_birth_matches(expected_birth, self.process_birth_identity(expected_pid) or "") is True,
                bool(health and health.get("runtime_instance_id") == expected_instance),
                bool(endpoint_identity and endpoint_identity.get("runtime_instance_id") == expected_instance),
                bool(endpoint_identity and endpoint_identity.get("realm_id") == expected_realm),
                (bool(health and health.get("status") == "ok") if require_health else True),
            )
            if not all(checks):
                raise BootstrapError("Runtime restart refused: owner identity changed or is stale.")
            # A group kill is only safe for the daemon's own session leader.
            try:
                if not native_owner and platform.process_group(expected_pid) != expected_pid:
                    raise BootstrapError("Runtime restart refused: owner is not its own process-group leader.")
            except OSError as exc:
                raise BootstrapError("Runtime restart refused: owner process disappeared.") from exc

        def validate_escalation_target() -> None:
            # TERM deliberately revokes readiness and removes discovery while
            # the same daemon may still be draining. Those absent surfaces do
            # not replace custody: the signal below still verifies the sealed
            # target and current authenticated actor/generation under its guard.
            observed = default_process_identity(expected_pid)
            if observed is None or any(observed.get(k) != v for k, v in
                                       {"pid": expected_pid, "birth_id": expected_birth, "uid": platform.current_user()}.items()):
                raise BootstrapError("Runtime escalation refused: selected incarnation changed or disappeared.")
            try:
                if not native_owner and platform.process_group(expected_pid) != expected_pid:
                    raise BootstrapError("Runtime escalation refused: selected owner session changed.")
                def read_optional_identity_file(path):
                    try:
                        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    except FileNotFoundError:
                        return None
                    try:
                        if not stat.S_ISREG(os.fstat(fd).st_mode):
                            raise OSError("owner identity file is not regular")
                        value = json.loads(os.read(fd, 1024 * 1024).decode("utf-8"))
                        if not isinstance(value, dict):
                            raise ValueError("owner identity metadata is not an object")
                        return value
                    finally:
                        os.close(fd)
                discovery = read_optional_identity_file(discovery_path)
                marker = read_optional_identity_file(owner_lock)
                for metadata, realm_key in ((discovery, "active_realm"), (marker, "realm_id")):
                    if metadata is None:
                        continue
                    if (not isinstance(metadata, dict)
                            or any(str(metadata.get(k)) != str(v) for k, v in {
                                "pid": expected_pid, "process_birth_id": expected_birth,
                                "runtime_instance_id": expected_instance, realm_key: expected_realm}.items())
                            or self._validate_path(Path(str(metadata.get("realm_root") or "")), "owner realm root").resolve() != root.resolve()
                            or (realm_key == "active_realm" and metadata.get("endpoint") != endpoint)):
                        raise BootstrapError("Runtime escalation refused: conflicting replacement metadata.")
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise BootstrapError("Runtime escalation refused: identity metadata is unreadable.") from exc
            health = self._http_health_payload(endpoint)
            endpoint_identity = self.endpoint_metadata(endpoint=endpoint, credential_file=support / "credentials" / "owner.token")
            if ((health and health.get("runtime_instance_id") != expected_instance)
                    or (endpoint_identity and (endpoint_identity.get("runtime_instance_id") != expected_instance
                                               or endpoint_identity.get("realm_id") != expected_realm))):
                raise BootstrapError("Runtime escalation refused: endpoint belongs to a replacement.")

        # A stopped owner must still pass the birth/lock identity fence.  The
        # operator upgrade path may explicitly disable only the health check
        # here so an unhealthy daemon can be stopped without signaling a
        # reused PID or unrelated process group.
        validate_before_signal(require_health=require_health)
        if not self._process and getattr(self, "_detached_pid", None):
            detached = int(self._detached_pid)
            if detached != expected_pid:
                raise BootstrapError("Runtime restart refused: adopted owner PID changed.")
            validate_before_signal(require_health=require_health)
            identity = {"pid": detached, "birth_id": expected_birth, "uid": platform.current_user()}
            if native_owner:
                custody = NativeProcessCustody(support, identity)
                custody.signal(platform.TERM, validate=lambda: validate_before_signal(require_health=require_health))
                deadline = time.monotonic() + shutdown_grace
                while self.is_pid_alive(detached) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self.is_pid_alive(detached):
                    custody.signal(platform.KILL, validate=validate_escalation_target)
                deadline = time.monotonic() + 2.0
                while self.is_pid_alive(detached) and time.monotonic() < deadline:
                    time.sleep(0.05)
                if self.is_pid_alive(detached):
                    raise BootstrapError("Runtime native cleanup remains uncertain after bounded wait.")
                self._detached_pid = None
                if not start_after_stop:
                    return {"state": "stopped", "realm_id": realm_id}
                return self.start(realm_id=realm_id, realm_root=root, owner_lock=owner_lock, source_profile=source)
            loaded = load_sealed_capability(support / ACTIVE_CAPABILITY_NAME, expected_identity=identity)
            sealed = loaded["reference"]["role_custody"]
            authority = RoleCustodyAuthority(Path(str(sealed["scope_root"])), "runtime_owner")
            actor = AuthenticatedCleanupActor.current()
            claimed = self._commit_owner_transition(authority, kind="claim", actor=actor,
                                                    generation=authority.reference()["generation"],
                                                    owner_epoch=loaded["owner_epoch"], sealed=sealed)
            attempted = False

            def deliver(words, signum):
                nonlocal attempted
                attempted = True
                signal_audit_token(words, signum)

            def selected_owner_absent():
                observed = default_process_identity(detached)
                return observed is None or any(observed.get(k) != identity[k] for k in identity)

            try:
                validate_before_signal(require_health=require_health)
                signal_sealed_capability(
                    support / ACTIVE_CAPABILITY_NAME,
                    expected_identity=identity, signum=platform.TERM,
                    actor=actor, generation=claimed["generation"], signal_provider=deliver,
                )
                deadline = time.monotonic() + shutdown_grace
                while time.monotonic() < deadline and self.is_pid_alive(detached):
                    time.sleep(0.05)
                if self.is_pid_alive(detached):
                    validate_escalation_target()
                    signal_sealed_capability(
                        support / ACTIVE_CAPABILITY_NAME, expected_identity=identity, signum=platform.KILL,
                        actor=actor, generation=claimed["generation"], signal_provider=deliver,
                    )
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline and self.is_pid_alive(detached):
                    time.sleep(0.05)
                if not selected_owner_absent():
                    raise BootstrapError("Runtime detached cleanup remains uncertain after bounded wait.")
            except Exception as exc:
                absent = False
                if attempted:
                    try:
                        absent = selected_owner_absent()
                    except CustodyError:
                        pass
                if not absent:
                    try:
                        self._commit_owner_transition(authority, kind="relinquish", actor=actor,
                                                      generation=claimed["generation"], owner_epoch=loaded["owner_epoch"])
                    except Exception as release_error:
                        failure = BootstrapCustodyUncertain("Runtime cleanup/release remains uncertain; support state preserved, cleanup unresolved.", controller=self)
                        self._custody_transition_uncertain = failure
                        raise failure from release_error
                    raise BootstrapError(f"Runtime detached cleanup uncertain; claim relinquished; signal attempted={attempted}: {exc}") from exc
            # This operator is not the daemon's parent. Its observation is
            # useful public stop evidence, never a retained wait/reap claim.
            exit_evidence = "nonchild_absence_observed"
            self._detached_pid = None
        else:
            process = self._process
            if process is None or process.pid != expected_pid:
                raise BootstrapError("Runtime restart refused: owned process handle changed.")
            validate_before_signal()
            self.stop()  # Reclaim an explicit release before retained-child cleanup.
        if not start_after_stop:
            self._bootstrap_credential = None
            return {"status": "stopped", "realm_id": realm_id, "pid": expected_pid,
                    **({"exit_evidence": exit_evidence} if exit_evidence else {})}
        return self.start(realm_id=realm_id, realm_root=root, owner_lock=support / "instance.lock", source_profile=source)


class ForegroundRuntimeBoundary(LocalRuntimeBoundary):
    """Run the daemon in this process so a service manager supervises its owner."""
    def __init__(self):
        super().__init__()
        self.daemon = None
        self._custody = None
        self._log_directory = None

    def start(self, *, realm_id, realm_root, owner_lock, source_profile):
        from runtime_protocol.daemon import RuntimeDaemon
        from runtime_protocol.door import DoorConfig
        from runtime_protocol.local_worker_composition import load_local_worker_composition
        from runtime_protocol.services import load_service_configuration

        cancellation.check()
        if self.daemon is not None:
            raise BootstrapError("foreground Runtime already owns a daemon")
        self._validate_source(source_profile)
        if source_profile.runtime_command:
            raise BootstrapError("run requires the installed Runtime, rather than a custom runtime_command")
        if (source_profile.runtime_environment
                and Path(source_profile.runtime_environment).resolve() != Path(sys.prefix).resolve()):
            raise BootstrapError("run must execute inside the selected runtime_environment")
        authoring_profile = _authoring_profile(source_profile)
        root = self._validate_path(Path(realm_root), "realm root").resolve()
        support = self._validate_path(Path(owner_lock).parent, "runtime support root").resolve()
        token = os.urandom(32).hex()
        token_file = self._token_file(support, token)
        try:
            door = None
            if self._door is not None:
                settings, credential = self._door
                door = DoorConfig(origin=settings.origin, port=settings.port, credential_file=credential)
            composition = None
            if source_profile.worker_profile:
                composition = load_local_worker_composition(source_profile.worker_profile,
                    workspace_uuid=realm_id, realm_root=root, support_root=support,
                    runtime_instance_id="pending-startup")
            services = load_service_configuration(getattr(source_profile, "service_declaration", None),
                python=sys.executable, source_checkout=getattr(source_profile, "source_checkout", ""))
            daemon = RuntimeDaemon(root, support_root=support, display_name=self._display_name,
                realm_id=realm_id, owner_lock=owner_lock, bootstrap_token_file=token_file,
                runtime_checkout=getattr(source_profile, "runtime_checkout", None),
                agent_checkout=getattr(source_profile, "source_checkout", None),
                admission_timeout=self.admission_timeout_seconds,
                local_worker_profiles=composition.profiles if composition else None,
                local_worker_preparer=composition.preparer if composition else None,
                local_worker_inspector=composition.inspector if composition else None, door=door,
                _local_worker_composition=composition,
                _local_worker_composition_required=bool(source_profile.worker_profile),
                services=services, log_directory=self._log_directory, authoring_profile=authoring_profile)
            self.daemon = daemon
            cancellation.check()
            daemon.start()
            cancellation.check()
            identity = default_process_identity(os.getpid())
            if identity is None:
                raise BootstrapError("foreground Runtime process identity is unavailable")
            self._custody = NativeProcessCustody(support, identity)
            self._custody.publish()
            self._bootstrap_credential = token
            return {**self._read_discovery(support), "protocol_version": PROTOCOL_VERSION,
                "schema_version": SCHEMA_VERSION, "capability_digest": source_profile.capability_digest}
        except BaseException:
            with cancellation.cleanup_scope():
                self.stop()
            raise
        finally:
            token_file.unlink(missing_ok=True)

    def release_owner_custody(self):
        if self._custody is None:
            raise BootstrapError("foreground Runtime has no native custody")
        return self._custody.release()

    def check_running(self):
        if self.daemon is None:
            raise BootstrapError("Runtime is already running in another process; stop it before using run")
        daemon = self.daemon
        threads = [(daemon.thread, "Runtime listener")]
        if daemon.door is not None:
            threads.append((daemon.door_thread, "browser door"))
        for thread, name in threads:
            if thread is None or not thread.is_alive():
                raise BootstrapError(f"{name} stopped unexpectedly")
        if daemon.service is None or not daemon.service._verified:
            raise BootstrapError("Runtime readiness was revoked")

    def stop(self, **kwargs):
        daemon = self.daemon
        if daemon is not None:
            daemon.stop()
            self.daemon = None
            self._custody = None
        self._bootstrap_credential = None
        return {"children_stopped": True}
