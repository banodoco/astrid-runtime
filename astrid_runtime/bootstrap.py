"""T2 neutral one-realm launch/reconnect lifecycle.

The boundary protocol is intentionally tiny. A real generated workspace
client can implement it; tests use a fake. Runtime ownership stays behind
that boundary and legacy roots are always rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import errno
import hashlib
import json
import re
from runtime_protocol.dirfd import filesystem as os
from pathlib import Path
import secrets
import shutil
import stat
import time
from contextlib import contextmanager, nullcontext
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlsplit
import uuid

from .io import atomic_write_json, owner_only, read_json, remove_file
from runtime_protocol import platform as runtime_platform
from runtime_protocol import cancellation
from runtime_protocol import process_control
from runtime_protocol.errors import ConflictError
from .paths import INSTALL_RECORD_OWNER, RuntimePaths, _install_record_path
from .refusal import refusal_from
from runtime_protocol.lifecycle import interruption_fence, inspect_interruption_state
from .identity import (
    IDENTITY_REFUSAL_MESSAGE,
    StartupIdentityError,
    normalize_startup_identity,
    requested_startup_identity,
    validate_live_owner_identity,
)


PROTOCOL_VERSION = "workspace.v1"
SCHEMA_VERSION = "workspace-schema-v1"
RUNTIME_VERSION = PROTOCOL_VERSION
IMPORTER_VERSION = "t5"
CATALOG_VERSION = 1
DISCOVERY_VERSION = 1
PINOKIO_STOP_HANDOFF_VERSION = 1
PINOKIO_STOP_BINDING_KEYS = frozenset({
    "program_root", "data_root", "realm_id", "realm_root", "owner_version_root",
    "owner_version_name", "owner_release", "runtime_checkout", "source_checkout",
    "runtime_environment", "service_declaration", "source_profile_sha256",
    "install_marker_sha256", "owner_version_sha256", "profile_sha256",
    "owner_identity_sha256", "service_declaration_sha256",
})
WORKER_ACTOR = "astrid-pack-host"
WORKER_SCOPES = (
    "handshake",
    "worker:register",
    "worker:execute",
    "projects:read",
    "tasks:read",
    "objects:read",
    "objects:write",
)
LEGACY_NEXT_ACTION = (
    "Legacy realm roots are unsupported; preserve {legacy_root} and "
    "provision a fresh canonical realm before launching."
)
RECONFIGURE_NEXT_ACTION = (
    "Restart the runtime with a compatible source profile: "
    "astrid-runtime restart --profile astrid"
)
MULTI_REALM_NEXT_ACTION = (
    "Stage 1 supports one realm only; use the Stage 2 multi-realm workflow."
)


class BootstrapError(RuntimeError):
    """A deterministic, user-actionable bootstrap failure."""

    def __init__(self, message: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.details = dict(details) if isinstance(details, Mapping) else None


class BootstrapCustodyUncertain(BootstrapError):
    """Keep an in-process controller reference; never claim it survives CLI exit."""

    def __init__(self, message: str, *, controller: object):
        super().__init__(message)
        self.controller = controller


class LegacyRootCollisionError(BootstrapError):
    pass


class DuplicateOwnerError(BootstrapError):
    pass


class CompatibilityError(BootstrapError):
    pass


def _pinokio_stop_refusal(message: str, *, code: str = "stop_unproven") -> BootstrapError:
    """Mark only new Pinokio handoff admissions as safe C1 refusals."""
    return BootstrapError(message, details={"safe": False, "code": code})


class UnsupportedRealmError(BootstrapError):
    pass


class RuntimeBoundary(Protocol):
    """Generated-client/runtime seam used by bootstrap.

    Implementations may launch or connect to a daemon, but must keep database
    and object-store ownership inside that daemon.
    """

    def create(self, *, realm_id: str, realm_root: Path, display_name: str,
               source_profile: "SourceProfile") -> Mapping[str, Any]: ...

    def inspect(self, *, realm_root: Path) -> Mapping[str, Any]: ...

    def start(self, *, realm_id: str, realm_root: Path, owner_lock: Path,
              source_profile: "SourceProfile") -> Mapping[str, Any]: ...

    def connect(self, *, endpoint: str, credential: str, timeout_seconds: float | None = None) -> Any: ...

    def health(self, *, endpoint: str, pid: int, instance_id: str) -> bool: ...

    def owner_startup_identity(self, *, endpoint: str, instance_id: str) -> Mapping[str, Any] | None: ...

    def endpoint_metadata(self, *, endpoint: str, credential_file: Path) -> Mapping[str, Any]: ...

    def validate_owner(self, *, endpoint: str, pid: int, instance_id: str,
                       owner_lock: Path, process_birth_id: str | None = None,
                       expected_realm_id: str | None = None,
                       expected_realm_root: Path | None = None) -> bool: ...

    def stop_owner(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def release_owner_custody(self) -> Mapping[str, Any]: ...

    def is_pid_alive(self, pid: int) -> bool: ...


@dataclass(frozen=True)
class SourceProfile:
    profile: str
    runtime_checkout: str
    source_checkout: str
    runtime_environment: str | None = None
    worker_profile: str | None = None
    runtime_command: tuple[str, ...] = ()
    protocol_version: str = PROTOCOL_VERSION
    schema_version: str = SCHEMA_VERSION
    capability_digest: str = ""
    source_digest: str = ""
    lock_digest: str = ""
    service_declaration: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], *, expected_profile: str = "astrid") -> "SourceProfile":
        if not isinstance(value, Mapping):
            raise BootstrapError("Source profile manifest must contain an object.")
        allowed = {
            "profile", "runtime_checkout", "source_checkout", "runtime_environment",
            "worker_profile",
            "runtime_command", "protocol_version", "schema_version", "capability_digest",
            "source_digest", "lock_digest", "service_declaration",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise BootstrapError(
                "Source profile cannot override runtime authority: "
                + ", ".join(unknown)
            )
        profile = str(value.get("profile", ""))
        if profile != expected_profile:
            raise BootstrapError(f"Source profile must be {expected_profile!r}, got {profile!r}.")
        if "runtime_checkout" not in value:
            raise BootstrapError(
                "Source profile is incomplete; configure the pinned runtime_checkout "
                "in the editable source manifest."
            )
        runtime_checkout = str(value.get("runtime_checkout", ""))
        if not runtime_checkout or not Path(runtime_checkout).expanduser().is_absolute():
            raise BootstrapError("Source profile runtime_checkout must be an explicit absolute pinned checkout path.")
        source_checkout = str(value.get("source_checkout", ""))
        if not source_checkout:
            raise BootstrapError(
                "Source profile is incomplete; configure source_checkout "
                "in the editable source manifest."
            )
        command = value.get("runtime_command", ())
        if isinstance(command, str):
            command = (command,)
        if not isinstance(command, Sequence):
            raise BootstrapError("Source profile runtime_command must be an argv array.")
        if tuple(command):
            raise BootstrapError(
                "Source profile runtime_command is not an authority; configure only the pinned runtime_checkout."
            )
        declaration = value.get("service_declaration")
        if declaration is not None and (not isinstance(declaration, str) or not declaration
                or not Path(declaration).expanduser().is_absolute()):
            raise BootstrapError("Source profile service_declaration must be an absolute path.")
        return cls(
            profile=profile,
            runtime_checkout=runtime_checkout,
            source_checkout=source_checkout,
            runtime_environment=(str(value["runtime_environment"]) if value.get("runtime_environment") else None),
            worker_profile=(str(value["worker_profile"]) if value.get("worker_profile") else None),
            runtime_command=tuple(str(part) for part in command),
            protocol_version=str(value.get("protocol_version", PROTOCOL_VERSION)),
            schema_version=str(value.get("schema_version", SCHEMA_VERSION)),
            capability_digest=str(value.get("capability_digest", "")),
            source_digest=str(value.get("source_digest", "")),
            lock_digest=str(value.get("lock_digest", "")),
            service_declaration=declaration,
        )

    @classmethod
    def load(cls, path: Path | str, *, expected_profile: str = "astrid") -> "SourceProfile":
        target = Path(path).expanduser()
        if not target.is_absolute() or _has_symlink_component(target):
            raise BootstrapError(f"Source profile manifest must be absolute and symlink-free: {target}")
        try:
            raw = _read_json_regular(target)
        except (FileNotFoundError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BootstrapError(f"Source profile manifest is missing or invalid: {target}") from exc
        if raw is None:
            raise BootstrapError(f"Source profile manifest is missing or invalid: {target}")
        return cls.from_mapping(raw, expected_profile=expected_profile)

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "runtime_checkout": self.runtime_checkout,
            "source_checkout": self.source_checkout,
            "runtime_environment": self.runtime_environment,
            "worker_profile": self.worker_profile,
            "runtime_command": list(self.runtime_command),
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "capability_digest": self.capability_digest,
            "source_digest": self.source_digest,
            "lock_digest": self.lock_digest,
            **({"service_declaration": self.service_declaration} if self.service_declaration is not None else {}),
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class RestoreSelection:
    """Existing installer paths that identify a realm during restore replay."""

    journal_path: Path
    selection_path: Path


@dataclass(frozen=True)
class DoorSettings:
    """The hosted page's browser door that a started daemon opens (``runtime_protocol.door``)."""

    origin: str
    port: int


@dataclass(frozen=True)
class BootstrapConfig:
    profile: str = "astrid"
    display_name: str = "Astrid Workspace"
    source_profile: SourceProfile | None = None
    source_manifest: Path | None = None
    protocol_version: str = PROTOCOL_VERSION
    schema_version: str = SCHEMA_VERSION
    capability_digest: str = ""
    legacy_roots: tuple[Path, ...] = ()
    door: DoorSettings | None = None

    def resolve_source_profile(self, paths: RuntimePaths) -> SourceProfile:
        if self.source_profile is not None:
            return self.source_profile
        manifest = self.source_manifest or (paths.source_profiles_dir / f"{self.profile}.json")
        return SourceProfile.load(manifest, expected_profile=self.profile)


@dataclass(frozen=True)
class BootstrapResult:
    status: str
    realm_id: str
    display_name: str
    endpoint: str
    actor_id: str
    source_profile: str
    diagnostics: tuple[str, ...] = ()
    discovery_path: Path | None = field(default=None, compare=False)
    # The handoff exposes only the owner-only credential *path*.  The secret
    # itself never crosses the launcher stdout boundary.
    credential_file: Path | None = field(default=None, compare=False)
    # The launcher hands the Astrid pack host a separate scoped credential;
    # the user-facing Astrid credential remains the value above.
    worker_credential_file: Path | None = field(default=None, compare=False)
    worker_actor: str | None = field(default=None, compare=False)
    worker_scopes: tuple[str, ...] = field(default=(), compare=False)
    source_checkout: str | None = field(default=None, compare=False)
    # The browser door of the running daemon, when it has one: the page to open and where it listens.
    door_origin: str | None = field(default=None, compare=False)
    door_endpoint: str | None = field(default=None, compare=False)
    runtime_instance_id: str | None = field(default=None, compare=False)

    @property
    def ready(self) -> bool:
        return self.status in {"started", "reconnected", "restarted"}


def _default_legacy_roots(paths: RuntimePaths) -> tuple[Path, ...]:
    # These are collision signals only; no legacy state is read.
    # ~/.astrid also holds supported credentials and compute profiles.
    return (
        paths.home / ".astrid",
        paths.home / "Astrid" / "projects",
        paths.home / "Documents" / "Astrid" / "projects",
    )


def _legacy_collision(paths: RuntimePaths, configured: tuple[Path, ...]) -> Path | None:
    for root in (*configured, *_default_legacy_roots(paths)):
        root = Path(root).expanduser()
        # lexists is intentional: a dangling legacy symlink is still a
        # collision and must not be bypassed by a stale/empty catalog.
        if root == paths.home / ".astrid" and root not in configured and root.is_dir() and not root.is_symlink():
            # Inspect names only, never open legacy databases or credential files.
            markers = (
                "astrid.sqlite3", "workspace.sqlite3", "realm.sqlite3",
                "projects", "runtime", "realms",
            )
            if any(os.path.lexists(str(root / marker)) for marker in markers):
                return root
        elif os.path.lexists(str(root)):
            return root
    return None


def _read_json_regular(path: Path) -> Any:
    if runtime_platform.sys.platform == "win32" and path.name in {"astrid.json", "discovery.json"}:
        return json.loads(runtime_platform.read_private_file(path).decode("utf-8"))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        return json.loads(bytes(data).decode("utf-8"))
    finally:
        os.close(fd)


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        # macOS exposes the temporary directory through the protected
        # ``/var`` (and sometimes ``/tmp``) compatibility symlink.  Those
        # fixed system aliases are not operator-controlled support paths;
        # continue checking every component below them.
        if current.is_symlink() and current not in {Path("/var"), Path("/tmp")}:
            return True
    return False


def _validate_source_profile(source: SourceProfile, *, expected_profile: str = "astrid") -> None:
    """Reject source metadata that attempts to become runtime authority."""
    if not isinstance(source, SourceProfile) or source.profile != expected_profile:
        raise BootstrapError(f"Source profile must be {expected_profile!r}.")
    checkout = str(source.runtime_checkout or "")
    checkout_path = Path(checkout).expanduser()
    source_path = Path(str(source.source_checkout or "")).expanduser()
    if not checkout or not checkout_path.is_absolute() or _has_symlink_component(checkout_path):
        raise BootstrapError("Source profile runtime_checkout must be an explicit absolute pinned checkout path.")
    if not source_path.is_absolute() or _has_symlink_component(source_path):
        raise BootstrapError("Source profile source_checkout must be an absolute symlink-free provenance path.")
    if source.worker_profile:
        worker_profile = Path(source.worker_profile).expanduser()
        if not worker_profile.is_absolute() or _has_symlink_component(worker_profile) or worker_profile.is_symlink():
            raise BootstrapError("Source profile worker_profile must be an absolute symlink-free path.")
        if not worker_profile.is_file():
            raise BootstrapError(f"Source profile worker_profile does not exist: {worker_profile}")
    if source.runtime_command:
        raise BootstrapError("Source profile runtime_command is not permitted; runtime launch is fixed by the installed runtime.")
    if source.protocol_version != PROTOCOL_VERSION or source.schema_version != SCHEMA_VERSION:
        raise CompatibilityError("Source profile protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION)


def _validate_loopback_endpoint(endpoint: str) -> str:
    """Accept only the runtime's local HTTP authority."""
    try:
        parsed = urlsplit(str(endpoint))
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise BootstrapError("Runtime discovery endpoint is invalid or not loopback-only.") from exc
    if (parsed.scheme != "http" or parsed.username or parsed.password
            or host not in {"127.0.0.1", "localhost", "::1"}
            or port is None or not (1 <= int(port) <= 65535)
            or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise BootstrapError("Runtime discovery endpoint must be an HTTP loopback authority.")
    return str(endpoint).rstrip("/")


def _worker_handoff(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the non-secret pack-host credential handoff.

    The token itself stays in the owner-only file.  Discovery carries only
    its path and the exact scope declaration so a launcher can activate one
    host without promoting the Astrid user credential or an owner token.
    Older fake boundaries may omit the optional fields; real runtime launch
    always supplies them.
    """
    if not isinstance(value, Mapping) or not value.get("worker_credential_file"):
        return {}
    raw_path = value.get("worker_credential_file")
    if not isinstance(raw_path, str) or not raw_path:
        raise BootstrapError("Runtime worker credential handoff is invalid; " + RECONFIGURE_NEXT_ACTION)
    path = Path(raw_path).expanduser()
    pending = bool(value.get("worker_credential_pending"))
    if (not path.is_absolute() or _has_symlink_component(path)
            or path.is_symlink() or (not pending and not path.is_file())):
        raise BootstrapError("Runtime worker credential handoff is unsafe; " + RECONFIGURE_NEXT_ACTION)
    if not pending:
        try:
            if not runtime_platform.is_owner_only(path if runtime_platform.sys.platform == "win32" else path.stat()):
                raise BootstrapError("Runtime worker credential file must be owner-only; " + RECONFIGURE_NEXT_ACTION)
        except OSError as exc:
            raise BootstrapError("Runtime worker credential handoff is unavailable; " + RECONFIGURE_NEXT_ACTION) from exc
    actor = str(value.get("worker_actor") or "")
    scopes = tuple(str(scope) for scope in (value.get("worker_scopes") or ()))
    if actor != WORKER_ACTOR or scopes != WORKER_SCOPES:
        raise CompatibilityError("Runtime worker credential scopes are incompatible. " + RECONFIGURE_NEXT_ACTION)
    return {
        "worker_credential_file": path,
        "worker_credential_pending": pending,
        "worker_actor": actor,
        "worker_scopes": scopes,
    }


def _validate_support_paths(paths: RuntimePaths) -> None:
    """Validate the fixed support composition before reading or writing it."""
    directories = (
        paths.home, paths.app_support, paths.runtime_support,
        paths.credentials_dir, paths.runtime_support / "credentials", paths.realms_dir,
        paths.source_profiles_dir,
    )
    files = (
        paths.catalog_path, paths.discovery_path,
        paths.instance_lock_path, paths.bootstrap_lock_path, paths.process_control_path,
        paths.runtime_support / "credentials" / "owner.token",
        paths.runtime_support / "credentials" / "owner.json",
        paths.runtime_support / "credentials" / "astrid-pack-host.token",
        paths.runtime_support / "credentials" / "astrid-pack-host.json",
    )
    for item in (*directories, *files):
        target = Path(item).expanduser()
        # The fixed home path may itself be reached through a platform alias
        # (for example /var -> /private/var).  Validate all support-relative
        # components, including the leaf, while preserving that OS alias.
        try:
            relative = target.relative_to(Path(paths.home).expanduser())
        except ValueError:
            relative = target
        support_symlink = False
        cursor = Path(paths.home).expanduser() if target.is_relative_to(Path(paths.home).expanduser()) else Path(target.anchor)
        for component in relative.parts:
            if component in (".", ""):
                continue
            cursor /= component
            if cursor.is_symlink():
                support_symlink = True
                break
        if not target.is_absolute() or support_symlink:
            raise BootstrapError(f"Neutral support path must be absolute and symlink-free: {target}")
    for directory in directories:
        if os.path.lexists(str(directory)) and (directory.is_symlink() or not directory.is_dir()):
            raise BootstrapError(f"Neutral support directory is not a regular directory: {directory}")
    for path in files:
        if os.path.lexists(str(path)) and (path.is_symlink() or not path.is_file()):
            raise BootstrapError(f"Neutral support file is not a regular file: {path}")


def _read_support_json(path: Path) -> dict[str, Any] | None:
    """Read a support JSON file without following a symlink."""
    try:
        value = _read_json_regular(path)
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        detail = f": {exc}" if runtime_platform.sys.platform == "win32" else ""
        raise BootstrapError(f"Neutral support file is missing, malformed, or unsafe: {path}{detail}") from exc
    if not isinstance(value, Mapping):
        raise BootstrapError(f"Neutral support file must contain an object: {path}")
    return dict(value)


def _new_realm_id() -> str:
    return uuid.uuid4().hex


def _read_catalog(paths: RuntimePaths) -> dict[str, Any]:
    catalog = _read_support_json(paths.catalog_path)
    if catalog is None:
        return {"version": CATALOG_VERSION, "selected_realm_id": None, "realms": [], "source_profiles": {}}
    return _validate_catalog(catalog)


def _validate_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one already-read catalog snapshot and return its document."""
    catalog = dict(catalog)
    if catalog.get("version") != CATALOG_VERSION:
        raise BootstrapError("Neutral realm catalog version is unsupported; run astrid-runtime doctor.")
    if not isinstance(catalog.get("realms", []), list):
        raise BootstrapError("Neutral realm catalog is invalid; recover or remove catalog.json.")
    if not isinstance(catalog.get("source_profiles", {}), Mapping):
        raise BootstrapError("Neutral realm catalog source profiles are invalid; run astrid-runtime doctor.")
    for profile_name, manifest in catalog.get("source_profiles", {}).items():
        try:
            if str(profile_name) != "astrid":
                raise BootstrapError("Neutral realm catalog contains an unsupported source profile.")
            SourceProfile.from_mapping(manifest, expected_profile=str(profile_name))
        except BootstrapError:
            raise
        except (TypeError, ValueError) as exc:
            raise BootstrapError("Neutral realm catalog source profile is invalid; run astrid-runtime doctor.") from exc
    if len(catalog["realms"]) > 1:
        raise UnsupportedRealmError(MULTI_REALM_NEXT_ACTION)
    seen: set[str] = set()
    for realm in catalog["realms"]:
        if not isinstance(realm, Mapping):
            raise BootstrapError("Neutral realm catalog contains an invalid realm entry; run astrid-runtime doctor.")
        realm_id = str(realm.get("realm_id") or "")
        data_root = Path(str(realm.get("data_root") or "")).expanduser()
        if (not realm_id or realm_id in seen or any(char in realm_id for char in "/\\")
                or not data_root.is_absolute() or _has_symlink_component(data_root)
                or data_root.is_symlink() or (data_root.exists() and not data_root.is_dir())):
            raise BootstrapError("Neutral realm catalog contains an unsafe realm root; run astrid-runtime doctor.")
        if not str(realm.get("display_name") or ""):
            raise BootstrapError("Neutral realm catalog contains an unnamed realm; run astrid-runtime doctor.")
        seen.add(realm_id)
    selected = catalog.get("selected_realm_id")
    if selected is not None and str(selected) not in seen:
        raise BootstrapError("Catalog selected realm is inconsistent; run astrid-runtime doctor.")
    return catalog


def _selected_realm(catalog: dict[str, Any]) -> dict[str, Any] | None:
    realms = catalog.get("realms", [])
    if len(realms) > 1:
        raise UnsupportedRealmError(MULTI_REALM_NEXT_ACTION)
    if not realms:
        return None
    selected = catalog.get("selected_realm_id")
    if selected is None:
        return None
    realm = realms[0]
    if selected and str(selected) != str(realm.get("realm_id")):
        raise BootstrapError("Catalog selected realm is inconsistent; run astrid-runtime doctor.")
    return realm


def _credential(paths: RuntimePaths) -> tuple[str, str]:
    if runtime_platform.sys.platform == "win32":
        runtime_platform.private_directory(paths.credentials_dir)
    else:
        paths.credentials_dir.mkdir(parents=True, exist_ok=True)
        owner_only(paths.credentials_dir, directory=True)
    path = paths.credentials_dir / "astrid.json"
    current = _read_support_json(path)
    if current and current.get("scope") == "astrid" and isinstance(current.get("token"), str):
        token = current["token"]
        if len(token) == 64:
            return str(current.get("actor_id") or _actor_id(token)), token
    token = secrets.token_hex(32)
    actor_id = _actor_id(token)
    atomic_write_json(path, {"version": 1, "scope": "astrid", "actor_id": actor_id, "token": token})
    return actor_id, token


def _actor_id(token: str) -> str:
    return "astrid-" + hashlib.sha256(token.encode()).hexdigest()[:24]


def _compatible(discovery: Mapping[str, Any], config: BootstrapConfig, source: SourceProfile) -> None:
    if discovery.get("protocol_version") != config.protocol_version or discovery.get("schema_version") != config.schema_version:
        raise CompatibilityError(
            "Runtime protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION
        )
    if config.capability_digest and discovery.get("capability_digest") not in {None, "", config.capability_digest}:
        raise CompatibilityError("Runtime capability digest is incompatible. " + RECONFIGURE_NEXT_ACTION)
    if source.protocol_version != config.protocol_version or source.schema_version != config.schema_version:
        raise CompatibilityError("Source profile protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION)


def _pid_alive(boundary: RuntimeBoundary | None, pid: Any) -> bool:
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return False
    if pid_int <= 0:
        return False
    if boundary is not None:
        # The selected boundary owns this observation. An unknown result
        # must not authorize cleanup through a different fallback probe.
        return bool(boundary.is_pid_alive(pid_int))
    try:
        return runtime_platform.process_identity(pid_int) is not None
    except PermissionError:
        return True
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return False
        raise BootstrapError("Runtime liveness observation remains uncertain.") from exc


def _owner_may_be_alive(boundary: RuntimeBoundary, record: Mapping[str, Any]) -> bool:
    """Only proven absence or a different birth permits stale-record cleanup."""
    pid = record.get("pid")
    if not _pid_alive(boundary, pid):
        return False
    observe = getattr(boundary, "process_birth_identity", None)
    expected = record.get("process_birth_id")
    if not callable(observe) or not expected:
        return True
    actual = observe(int(pid))
    return actual is None or runtime_platform.process_birth_matches(str(expected), actual) is not False


def _reclaim_stale_owner_locked(paths: RuntimePaths, boundary: RuntimeBoundary) -> bool:
    """Reclaim only stale advertisements under the launcher mutex; never signal.

    Check both records before removing either: a missing/stale discovery must
    not hide a live owner in instance.lock. Recheck snapshots so replacement
    advertisements cannot be removed by an older cleanup attempt.
    """
    records = [(path, _read_support_json(path))
               for path in (paths.discovery_path, paths.instance_lock_path)]
    present = [(path, record) for path, record in records if record is not None]
    if not present or any(_owner_may_be_alive(boundary, record) for _, record in present):
        return False
    if any(_read_support_json(path) != record for path, record in records):
        raise BootstrapError("Runtime owner changed during stale-owner cleanup.")
    for path, _ in present:
        remove_file(path)
    return True


def _canonical_realm_root(value: str | Path, *, allow_missing: bool = False) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute() or _has_symlink_component(raw) or raw.is_symlink():
        raise BootstrapError("Realm-root identity must be absolute and symlink-free.")
    normalized = Path(os.path.abspath(raw))
    if normalized != raw:
        raise BootstrapError("Realm-root identity must be canonical.")
    resolved = raw.resolve()
    if not resolved.is_dir() and not (allow_missing and not resolved.exists()):
        raise BootstrapError("Realm-root identity is unavailable.")
    return resolved




def _lock_matches(
    paths: RuntimePaths, pid: int, instance_id: str, realm_id: str,
    process_birth_id: str | None = None, realm_root: Path | None = None,
) -> bool:
    marker = _read_support_json(paths.instance_lock_path)
    root_matches = True
    if realm_root is not None:
        try:
            root_matches = _canonical_realm_root(str(marker.get("realm_root") or "")) == realm_root if marker else False
        except BootstrapError:
            root_matches = False
    return bool(
        marker
        and str(marker.get("pid")) == str(pid)
        and str(marker.get("runtime_instance_id")) == instance_id
        and str(marker.get("realm_id")) == realm_id
        and (process_birth_id is None or str(marker.get("process_birth_id")) == process_birth_id)
        and root_matches
    )


@contextmanager
def _bootstrap_mutex(paths: RuntimePaths):
    """Serialize launchers so two clean launches cannot both start a daemon."""
    if runtime_platform.sys.platform == "win32":
        runtime_platform.private_directory(paths.runtime_support)
    else:
        paths.runtime_support.mkdir(parents=True, exist_ok=True)
        owner_only(paths.runtime_support, directory=True)
    handle = paths.bootstrap_lock_path.open("a+")
    locked = False
    try:
        if runtime_platform.sys.platform == "win32":
            runtime_platform.owner_only(handle.fileno())
        else:
            owner_only(paths.bootstrap_lock_path)
        runtime_platform.lock_file(handle.fileno())
        locked = True
        cancellation.check()
        yield
    finally:
        try:
            if locked:
                runtime_platform.unlock_file(handle.fileno())
        except OSError:
            pass
        handle.close()


def _provision_connection(connection: Any, actor_id: str, token: str, realm_id: str) -> None:
    """Call only generated-client-shaped methods; never inspect runtime state."""
    provision = getattr(connection, "provision_actor", None)
    if provision is not None:
        result = cancellation.wait_for(provision, scope="astrid", actor_id=actor_id, credential=token)
        if isinstance(result, Mapping) and result.get("scope") not in (None, "astrid"):
            raise BootstrapError("Runtime refused the Astrid-scoped credential.")
    select = getattr(connection, "select_realm", None)
    if select is not None:
        cancellation.wait_for(select, actor_id=actor_id, realm_id=realm_id)
    handshake = getattr(connection, "handshake", None)
    if handshake is not None:
        cancellation.wait_for(handshake, protocol_version=PROTOCOL_VERSION, schema_version=SCHEMA_VERSION)


def _rollback_failed_bootstrap(paths: RuntimePaths, boundary: RuntimeBoundary, *, realm_root: Path, new_realm: bool, credential_before: bytes | None, catalog_before: bytes | None = None, source_before: bytes | None = None, source_profile: str = "astrid", candidate_pid: int | None = None, completed_stop_marker: Mapping[str, Any] | None = None) -> None:
    """Return neutral support state to its pre-launch shape after a failed handoff."""
    # Rollback is allowed to remove only metadata emitted by this candidate.
    # A concurrent/previous owner may still be serving even when its support
    # advertisement is being repaired; deleting that owner's discovery here
    # strands a healthy daemon and causes every following caller to start a
    # duplicate candidate.  Capture the candidate PID before ``stop`` clears
    # the boundary handle, then fence each support file by its owner marker.
    candidate = getattr(boundary, "_process", None)
    candidate_pid = candidate_pid if candidate_pid is not None else getattr(candidate, "pid", None)
    try:
        candidate_publications = {
            path: _read_support_json(path)
            for path in (paths.discovery_path, paths.instance_lock_path)
        }
    except Exception:
        candidate_publications = None
    stop = getattr(boundary, "stop", None)
    cleanup_result = None
    if callable(stop):
        try:
            with cancellation.cleanup_scope():
                cleanup_result = stop()
        except Exception as exc:
            # Removing any support/credential/catalog/realm state here would
            # strand the owner whose cleanup just failed. Keep its controller
            # and every original file, even on a partial-start failure.
            raise BootstrapCustodyUncertain("Runtime rollback cleanup remains uncertain; support state retained.", controller=boundary) from exc
    for path in (paths.discovery_path, paths.instance_lock_path):
        try:
            current = _read_support_json(path)
            expected = candidate_publications.get(path) if candidate_publications is not None else object()
            if (candidate_pid is not None and candidate_publications is not None
                    and current is not None and current == expected):
                try:
                    owned = int(current.get("pid", 0)) == int(candidate_pid)
                except (TypeError, ValueError):
                    owned = False
                if owned:
                    remove_file(path)
        except Exception:
            pass
    credential = paths.credentials_dir / "astrid.json"
    try:
        if credential_before is None:
            remove_file(credential)
        else:
            credential.write_bytes(credential_before)
            owner_only(credential)
    except OSError:
        pass
    catalog = paths.catalog_path
    catalog_restored = False
    try:
        if catalog_before is None:
            remove_file(catalog)
        else:
            catalog.write_bytes(catalog_before)
            owner_only(catalog)
        catalog_restored = ((not catalog.exists()) if catalog_before is None
                            else catalog.read_bytes() == catalog_before)
    except OSError:
        pass
    source_manifest = paths.source_profiles_dir / f"{source_profile}.json"
    source_restored = False
    try:
        if source_before is None:
            remove_file(source_manifest)
        else:
            source_manifest.write_bytes(source_before)
            owner_only(source_manifest)
        source_restored = ((not source_manifest.exists()) if source_before is None
                           else source_manifest.read_bytes() == source_before)
    except OSError:
        pass
    # A failed first launch owns this newly allocated root.  Constrain the
    # cleanup to the exact lexical child selected by the neutral realm path;
    # never follow a symlink or remove an existing realm on reconnect.
    if new_realm and realm_root.is_dir() and not realm_root.is_symlink():
        try:
            realm_root.relative_to(paths.realms_dir)
        except ValueError:
            return
        try:
            shutil.rmtree(realm_root)
        except OSError:
            pass
    if (completed_stop_marker is not None
            and isinstance(cleanup_result, Mapping)
            and cleanup_result.get("children_stopped") is True
            and catalog_restored and source_restored):
        _reattest_aborted_launch_stop(
            paths, boundary, completed_stop_marker, realm_root=realm_root,
        )


def _reattest_aborted_launch_stop(
    paths: RuntimePaths, boundary: RuntimeBoundary,
    marker: Mapping[str, Any], *, realm_root: Path,
) -> bool:
    """Restore a consumed Stop lifetime only after C1 proves this launch aborted."""
    try:
        owner = _validate_completed_stop_marker(marker)
        if (_read_support_json(paths.discovery_path) is not None
                or _read_support_json(paths.instance_lock_path) is not None):
            return False
        if not realm_root.is_dir() or realm_root.is_symlink():
            return False
        _require_owner_absent(
            boundary, int(owner["pid"]), str(owner["process_birth_id"]),
            context="while re-attesting an aborted launch",
        )
        catalog = _read_catalog(paths)
        realm = _selected_realm(catalog)
        if realm is None or _canonical_realm_root(str(realm.get("data_root") or "")) != realm_root:
            return False
        binding = _pinokio_stop_binding(paths, realm)
        if binding is None or dict(marker["completed_stop"]["binding"]) != binding:
            return False
        with interruption_fence(realm_root) as report:
            if not report.get("safe", False):
                return False
            if (_read_support_json(paths.discovery_path) is not None
                    or _read_support_json(paths.instance_lock_path) is not None):
                return False
            _require_owner_absent(
                boundary, int(owner["pid"]), str(owner["process_birth_id"]),
                context="inside the aborted-launch fence",
            )
            current_binding = _pinokio_stop_binding(paths, realm)
            if current_binding != binding or current_binding != marker["completed_stop"]["binding"]:
                return False
            atomic_write_json(paths.instance_lock_path, dict(marker))
        return True
    except Exception:
        # Re-attestation is optional recovery evidence. Any unknown state keeps
        # the old marker consumed and leaves the original launch error intact.
        return False


def bootstrap(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    config: BootstrapConfig | None = None,
) -> BootstrapResult:
    """Perform ``astrid-runtime up`` for the one current-Mac realm."""
    config = config or BootstrapConfig()
    _validate_support_paths(paths)
    # The launcher signals the daemon it starts, so it follows the same
    # process-control setting as the daemon, fixed before anything is spawned.
    process_control.configure_from(paths.runtime_support)
    # Collision detection is deliberately before the mutex/support directory:
    # a legacy checkout must never cause even neutral launch state to be
    # created, and the user must be directed to fresh canonical provisioning.
    if config.profile != "astrid":
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    collision = _legacy_collision(paths, config.legacy_roots)
    if collision is not None:
        raise LegacyRootCollisionError(LEGACY_NEXT_ACTION.format(legacy_root=collision))
    if _selected_realm(_read_catalog(paths)) is None:
        raise BootstrapError(
            "No workspace is configured; run astrid-runtime workspace create or workspace attach."
        )
    config.resolve_source_profile(paths)
    with _bootstrap_mutex(paths):
        return _bootstrap_locked(paths, boundary, config)


def _commit_bootstrap_metadata(paths: RuntimePaths, source: SourceProfile, catalog: Mapping[str, Any], discovery: Mapping[str, Any]) -> None:
    """Commit catalog, source provenance, and ephemeral discovery in order."""
    atomic_write_json(paths.catalog_path, dict(catalog))
    atomic_write_json(paths.source_profiles_dir / f"{source.profile}.json", source.as_dict())
    atomic_write_json(paths.discovery_path, dict(discovery))


def _commit_source_profile_metadata(paths: RuntimePaths, source: SourceProfile, catalog: Mapping[str, Any]) -> None:
    """Persist an explicitly selected source profile without rewriting discovery."""
    catalog_before = paths.catalog_path.read_bytes() if paths.catalog_path.is_file() and not paths.catalog_path.is_symlink() else None
    source_path = paths.source_profiles_dir / f"{source.profile}.json"
    source_before = source_path.read_bytes() if source_path.is_file() and not source_path.is_symlink() else None
    if catalog_before is not None and source_before is not None:
        try:
            if json.loads(catalog_before) == dict(catalog) and json.loads(source_before) == source.as_dict():
                return
        except (ValueError, UnicodeDecodeError):
            pass
    try:
        atomic_write_json(paths.catalog_path, dict(catalog))
        atomic_write_json(source_path, source.as_dict())
    except Exception:
        try:
            if catalog_before is None:
                remove_file(paths.catalog_path)
            else:
                paths.catalog_path.write_bytes(catalog_before)
                owner_only(paths.catalog_path)
            if source_before is None:
                remove_file(source_path)
            else:
                source_path.write_bytes(source_before)
                owner_only(source_path)
        except OSError:
            pass
        raise


def _capture_requested_identity(source: SourceProfile) -> dict[str, Any]:
    try:
        return requested_startup_identity(source)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise BootstrapError("Requested Runtime identity could not be verified.") from exc


def _validated_matching_owner_identity(
    owner_health: Any,
    *,
    instance_id: str,
    requested_identity: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        observed = validate_live_owner_identity(owner_health, instance_id=instance_id)
        requested = normalize_startup_identity(requested_identity)
    except (StartupIdentityError, OSError, RuntimeError, TypeError, ValueError):
        raise BootstrapError(IDENTITY_REFUSAL_MESSAGE, details={"code": "identity_mismatch"}) from None
    if observed != requested:
        raise BootstrapError(IDENTITY_REFUSAL_MESSAGE, details={"code": "identity_mismatch"})
    return observed


def _bootstrap_locked(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig) -> BootstrapResult:
    if config.profile != "astrid":
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    source = config.resolve_source_profile(paths)
    _validate_source_profile(source, expected_profile=config.profile)
    requested_identity = _capture_requested_identity(source)
    collision = _legacy_collision(paths, config.legacy_roots)
    if collision is not None:
        raise LegacyRootCollisionError(LEGACY_NEXT_ACTION.format(legacy_root=collision))

    paths.ensure_support_dirs()
    catalog = _read_catalog(paths)
    catalog_before = paths.catalog_path.read_bytes() if paths.catalog_path.is_file() and not paths.catalog_path.is_symlink() else None
    realm = _selected_realm(catalog)
    if realm is None:
        raise BootstrapError("No workspace is configured; explicit create or attach is required before up.")
    completed_stop_before_launch = _revoke_completed_stop_before_launch(paths, boundary, realm)

    def rollback_failed(**kwargs) -> None:
        _rollback_failed_bootstrap(
            paths, boundary, completed_stop_marker=completed_stop_before_launch,
            **kwargs,
        )
    new_realm = False
    diagnostics: list[str] = []

    marker = _read_support_json(paths.instance_lock_path)
    if marker is None or marker.get("state") is None:
        _reclaim_stale_owner_locked(paths, boundary)
    discovery = _read_support_json(paths.discovery_path)
    if discovery is not None and discovery.get("active_realm"):
        _compatible(discovery, config, source)
        pid = discovery.get("pid")
        endpoint = str(discovery.get("endpoint", ""))
        instance_id = str(discovery.get("runtime_instance_id", ""))
        if _owner_may_be_alive(boundary, discovery):
            if not endpoint or not instance_id:
                raise DuplicateOwnerError(
                    "A runtime owner is active but its discovery record is incomplete; "
                    "stop that owner, then run astrid-runtime restart --profile astrid."
                )
            endpoint = _validate_loopback_endpoint(endpoint)
            try:
                selected_root = _canonical_realm_root(str(realm.get("data_root") or "")) if realm else None
                discovered_root = _canonical_realm_root(str(discovery.get("realm_root") or ""))
            except BootstrapError:
                selected_root = discovered_root = None
            valid_owner = boundary.validate_owner(
                endpoint=endpoint, pid=int(pid), instance_id=instance_id,
                owner_lock=paths.instance_lock_path,
                process_birth_id=str(discovery.get("process_birth_id") or ""),
                expected_realm_id=str(discovery["active_realm"]),
                expected_realm_root=selected_root,
            )
            if not valid_owner or selected_root is None or discovered_root != selected_root or not discovery.get("process_birth_id") or not _lock_matches(paths, int(pid), instance_id, str(discovery["active_realm"]), str(discovery.get("process_birth_id")), selected_root):
                raise DuplicateOwnerError(
                    "A different runtime owner is active for the selected realm; "
                    "stop it before retrying astrid-runtime up --profile astrid."
                )
            if not boundary.health(endpoint=endpoint, pid=int(pid), instance_id=instance_id):
                raise BootstrapError("The selected runtime owner is unhealthy; next action: " + RECONFIGURE_NEXT_ACTION)
            _validated_matching_owner_identity(
                boundary.owner_startup_identity(endpoint=endpoint, instance_id=instance_id),
                instance_id=instance_id, requested_identity=requested_identity,
            )
            if realm is None or str(realm.get("realm_id")) != str(discovery["active_realm"]):
                raise BootstrapError("Discovery does not match the selected catalog realm; run astrid-runtime doctor.")
            configure = getattr(boundary, "configure_source", None)
            if configure is not None:
                configure(source)
            actor_id, token = _credential(paths)
            connection = boundary.connect(endpoint=endpoint, credential=token)
            realm_id = str(discovery["active_realm"])
            _provision_connection(connection, actor_id, token, realm_id)
            realm["source_profile"] = source.profile
            catalog["source_profiles"][source.profile] = source.as_dict()
            _commit_source_profile_metadata(paths, source, catalog)
            diagnostics.append("runtime checkout differences are provenance only")
            if config.door is not None and discovery.get("door_origin") != config.door.origin:
                diagnostics.append(
                    f"the running Runtime's browser door serves {discovery.get('door_origin') or 'no hosted page'}; "
                    f"restart it to serve {config.door.origin}"
                )
            worker = _worker_handoff(discovery)
            _restore_admitted_live_lock(paths)
            return BootstrapResult(
                "reconnected", realm_id,
                str(realm.get("display_name", "Astrid Workspace")) if realm else "Astrid Workspace",
                endpoint, actor_id, source.profile, tuple(diagnostics),
                paths.discovery_path, paths.credentials_dir / "astrid.json",
                worker.get("worker_credential_file"), worker.get("worker_actor"),
                worker.get("worker_scopes", ()), source.source_checkout,
                discovery.get("door_origin"), discovery.get("door_endpoint"),
                discovery.get("runtime_instance_id"),
            )
        marker = _read_support_json(paths.instance_lock_path)
        if marker is not None and _owner_may_be_alive(boundary, marker):
            raise DuplicateOwnerError("A live runtime owner lock protects the stale discovery.")
        # A dead advertisement is ephemeral support state.  Remove it before
        # starting so a crash cannot be mistaken for a live owner.
        remove_file(paths.discovery_path)

    # A daemon may have advertised successfully but crashed before its
    # ephemeral discovery write (or discovery may have been manually removed).
    # Never start a second owner while the durable instance lock still points
    # at a live process.
    marker = _read_support_json(paths.instance_lock_path)
    if marker and _owner_may_be_alive(boundary, marker):
        raise DuplicateOwnerError(
            "A different runtime owner is active for the selected realm; "
            "stop it before retrying astrid-runtime up --profile astrid."
        )

    realm_id = str(realm["realm_id"])
    realm_root = _canonical_realm_root(str(realm["data_root"]))
    configure = getattr(boundary, "configure_source", None)
    if configure is not None:
        configure(source)
    configure_door = getattr(boundary, "configure_door", None)
    if configure_door is not None:
        # The door acts with the product credential this launcher provisions below.
        configure_door(config.door, paths.credentials_dir / "astrid.json")
    # ``realm`` was synthesized above only when the catalog was empty. Keep
    # this explicit ownership bit so rollback can remove only a fresh root.
    credential_path = paths.credentials_dir / "astrid.json"
    credential_before = runtime_platform.read_private_file(credential_path) if credential_path.is_file() and not credential_path.is_symlink() else None
    source_manifest_path = paths.source_profiles_dir / f"{source.profile}.json"
    source_before = source_manifest_path.read_bytes() if source_manifest_path.is_file() and not source_manifest_path.is_symlink() else None
    try:
        handle = boundary.start(
            realm_id=realm_id,
            realm_root=realm_root,
            owner_lock=paths.instance_lock_path,
            source_profile=source,
        )
    except Exception:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile)
        raise
    try:
        endpoint = str(handle["endpoint"])
        pid = int(handle["pid"])
        instance_id = str(handle["runtime_instance_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raw_candidate_pid = handle.get("pid") if isinstance(handle, Mapping) else None
        try:
            candidate_pid = int(raw_candidate_pid) if raw_candidate_pid is not None else None
        except (TypeError, ValueError):
            candidate_pid = None
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=candidate_pid)
        raise BootstrapError("Runtime start returned incomplete owner metadata.") from exc
    process_birth_id = str(handle.get("process_birth_id") or handle.get("birth_id") or "")
    if not process_birth_id:
        birth_fn = getattr(boundary, "process_birth_identity", None)
        if birth_fn is not None:
            process_birth_id = str(birth_fn(pid) or "")
    # Test/fake boundaries may not expose an OS process marker.  Keep a
    # synthetic marker in their hand-off while real boundaries always use the
    # kernel/ps birth identity above.
    if not process_birth_id:
        process_birth_id = f"synthetic:{instance_id}:{pid}"
    try:
        endpoint = _validate_loopback_endpoint(endpoint)
    except Exception:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    try:
        healthy = bool(boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id))
    except Exception:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    if not healthy:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise BootstrapError("Runtime started but failed health check; next action: " + RECONFIGURE_NEXT_ACTION)
    try:
        owner_identity = _validated_matching_owner_identity(
            boundary.owner_startup_identity(endpoint=endpoint, instance_id=instance_id),
            instance_id=instance_id, requested_identity=requested_identity,
        )
    except BootstrapError:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    worker = _worker_handoff(handle)
    # The marker contains ownership metadata only and never a credential.
    try:
        atomic_write_json(paths.instance_lock_path, {"pid": pid, "process_birth_id": process_birth_id, "runtime_instance_id": instance_id, "realm_id": realm_id, "realm_root": str(realm_root)})
        actor_id, token = _credential(paths)
        connection = boundary.connect(endpoint=endpoint, credential=token)
        _provision_connection(connection, actor_id, token, realm_id)
    except Exception:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    realm["source_profile"] = source.profile
    catalog["source_profiles"][source.profile] = source.as_dict()
    # Keep the editable source profile at the neutral support boundary after a
    # successful launch. ``up`` may have received a one-shot manifest from a
    # product launcher, and later operator reconnect/restart commands must be
    # able to resolve the same composition without requiring that temporary
    # path or a second manual setup step. This is composition metadata only;
    # it is not a runtime/database authority and is written only after the
    # daemon, credential handoff, activation, and catalog commit succeeded.
    discovery_value = {
        "version": DISCOVERY_VERSION,
        "endpoint": endpoint,
        "pid": pid,
        "process_birth_id": process_birth_id,
        "runtime_instance_id": instance_id,
        "identity": owner_identity,
        "active_realm": realm_id,
        "realm_root": str(realm_root),
        "coordinator_epoch": handle.get("coordinator_epoch"),
        "protocol_version": handle.get("protocol_version", source.protocol_version),
        "schema_version": handle.get("schema_version", source.schema_version),
        "capability_digest": handle.get("capability_digest", source.capability_digest),
        "credential_file": str(paths.credentials_dir / "astrid.json"),
        "worker_credential_file": str(handle.get("worker_credential_file") or ""),
        "worker_credential_pending": bool(handle.get("worker_credential_pending")),
        "worker_actor": str(handle.get("worker_actor") or ""),
        "worker_scopes": list(handle.get("worker_scopes") or ()),
        "advertised_at": time.time(),
        **({"door_endpoint": handle["door_endpoint"], "door_origin": handle["door_origin"]} if handle.get("door_endpoint") else {}),
    }
    try:
        _commit_bootstrap_metadata(paths, source, catalog, discovery_value)
    except Exception:
        rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    release = getattr(boundary, "release_owner_custody", None)
    if callable(release):
        # The concrete public CLI boundary always implements this hook. Legacy
        # injected fake boundaries can omit it; they launch no real owner.
        try:
            release()
        except BootstrapCustodyUncertain:
            # A durable release may have committed. Never signal at the old
            # generation or roll back advertised metadata on an unknown ACK.
            raise
        except Exception:
            rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
            raise
    return BootstrapResult(
        "started", realm_id, str(realm["display_name"]), endpoint, actor_id,
        source.profile, tuple(diagnostics), paths.discovery_path,
        paths.credentials_dir / "astrid.json",
        worker.get("worker_credential_file"), worker.get("worker_actor"),
        worker.get("worker_scopes", ()), source.source_checkout,
        handle.get("door_origin") if handle.get("door_endpoint") else None, handle.get("door_endpoint"),
        instance_id,
    )


def connect(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig | None = None) -> BootstrapResult:
    """Connect without creating a realm or starting authority."""
    config = config or BootstrapConfig()
    _validate_support_paths(paths)
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    discovery = _read_support_json(paths.discovery_path)
    if realm is None or not discovery:
        raise BootstrapError("No healthy selected runtime. Next action: astrid-runtime up --profile astrid")
    source = config.resolve_source_profile(paths)
    _compatible(discovery, config, source)
    requested_identity = _capture_requested_identity(source)
    try:
        pid = int(discovery["pid"])
        endpoint = _validate_loopback_endpoint(str(discovery["endpoint"]))
        instance_id = str(discovery["runtime_instance_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("Runtime discovery is incomplete; run astrid-runtime restart --profile astrid.") from exc
    if not _pid_alive(boundary, pid) or not boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id=instance_id, owner_lock=paths.instance_lock_path):
        raise BootstrapError("Runtime discovery is stale or owned by another process; run astrid-runtime up --profile astrid.")
    if not boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id):
        raise BootstrapError("The selected runtime is unhealthy; run astrid-runtime restart --profile astrid.")
    _validated_matching_owner_identity(
        boundary.owner_startup_identity(endpoint=endpoint, instance_id=instance_id),
        instance_id=instance_id, requested_identity=requested_identity,
    )
    if str(realm.get("realm_id")) != str(discovery.get("active_realm")):
        raise BootstrapError("Discovery does not match the selected catalog realm; run astrid-runtime doctor.")
    actor_id, token = _credential(paths)
    connection = boundary.connect(endpoint=endpoint, credential=token)
    _provision_connection(connection, actor_id, token, str(realm["realm_id"]))
    worker = _worker_handoff(discovery)
    return BootstrapResult(
        "reconnected", str(realm["realm_id"]),
        str(realm.get("display_name", "Astrid Workspace")), endpoint, actor_id,
        source.profile, (), paths.discovery_path,
        paths.credentials_dir / "astrid.json",
        worker.get("worker_credential_file"), worker.get("worker_actor"),
        worker.get("worker_scopes", ()), source.source_checkout,
        discovery.get("door_origin"), discovery.get("door_endpoint"),
        discovery.get("runtime_instance_id"),
    )


def _owner_record_matches(
    value: Mapping[str, Any] | None, *, pid: int, instance_id: str,
    process_birth_id: str, realm_id: str, realm_root: Path,
) -> bool:
    if not value:
        return False
    try:
        recorded_root = _canonical_realm_root(str(value.get("realm_root") or ""))
    except BootstrapError:
        return False
    return bool(
        str(value.get("pid")) == str(pid)
        and str(value.get("runtime_instance_id")) == instance_id
        and str(value.get("process_birth_id")) == process_birth_id
        and str(value.get("active_realm") or value.get("realm_id")) == realm_id
        and recorded_root == realm_root
    )


def _private_handoff_bytes(path: Path) -> bytes:
    """Read an owner-owned, canonical regular file used to bind Pinokio state."""
    target = Path(path).expanduser()
    if (not target.is_absolute() or _has_symlink_component(target)
            or target.is_symlink() or not target.is_file()):
        raise BootstrapError(f"Pinokio stop binding is missing or unsafe: {target}")
    try:
        if runtime_platform.sys.platform == "win32":
            raw = runtime_platform.read_private_file(target)
        else:
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                metadata = os.fstat(fd)
                if (not stat.S_ISREG(metadata.st_mode)
                        or not runtime_platform.is_current_user(metadata)):
                    raise BootstrapError(f"Pinokio stop binding is not an owner-owned regular file: {target}")
                chunks = bytearray()
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.extend(chunk)
                raw = bytes(chunks)
            finally:
                os.close(fd)
    except BootstrapError:
        raise
    except OSError as exc:
        raise BootstrapError(f"Pinokio stop binding is unavailable: {target}") from exc
    return raw


def _private_handoff_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _private_handoff_bytes(path)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"Pinokio stop binding is malformed: {path}") from exc
    if not isinstance(value, dict):
        raise BootstrapError(f"Pinokio stop binding must be an object: {path}")
    return raw, value


def _canonical_handoff_path(value: Any, *, label: str, directory: bool | None = None) -> Path:
    if not isinstance(value, str) or not value:
        raise BootstrapError(f"Pinokio stop binding has no {label}.")
    raw = Path(value).expanduser()
    if not raw.is_absolute() or _has_symlink_component(raw) or raw.is_symlink():
        raise BootstrapError(f"Pinokio stop binding {label} is not absolute and symlink-free.")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise BootstrapError(f"Pinokio stop binding {label} is unavailable.") from exc
    if resolved != raw:
        raise BootstrapError(f"Pinokio stop binding {label} is not canonical.")
    if directory is True and not resolved.is_dir():
        raise BootstrapError(f"Pinokio stop binding {label} is not a directory.")
    if directory is False and not resolved.is_file():
        raise BootstrapError(f"Pinokio stop binding {label} is not a regular file.")
    return resolved


def _pinokio_stop_binding(
    paths: RuntimePaths, realm: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Derive selected Pinokio identity from Runtime-owned profile/catalog data.

    No caller-supplied path or ambient managed-by flag can create this binding.
    A service-backed profile is treated as Pinokio only when its selected
    Version, profile, install marker, and per-user selection record agree.
    """
    catalog = _read_catalog(paths)
    profiles = catalog.get("source_profiles", {})
    raw_profile = profiles.get("astrid") if isinstance(profiles, Mapping) else None
    managed_by_env = os.environ.get("ASTRID_INSTALL_MANAGED_BY") == "pinokio"
    selection_path = _install_record_path(Path(paths.home))
    selected = None
    selection_error = None
    if os.path.lexists(str(selection_path)):
        try:
            _selection_raw, selected = _private_handoff_json(selection_path)
        except BootstrapError as exc:
            selection_error = exc
    selected_pinokio = bool(isinstance(selected, Mapping)
                            and selected.get("owner") == INSTALL_RECORD_OWNER
                            and selected.get("managed_by") == "pinokio")
    selected_for_data = False
    if selected_pinokio:
        try:
            selected_for_data = (
                _canonical_handoff_path(selected.get("data_root"), label="selection data root", directory=True)
                == paths.app_support
            )
        except BootstrapError:
            selected_for_data = False

    source = None
    source_error = None
    if isinstance(raw_profile, Mapping):
        try:
            source = SourceProfile.from_mapping(raw_profile, expected_profile="astrid")
        except BootstrapError as exc:
            source_error = exc
    owner_pinokio = False
    owner_version_error = None
    if source is not None and source.runtime_environment:
        try:
            candidate_environment = _canonical_handoff_path(
                source.runtime_environment, label="runtime environment", directory=True,
            )
            candidate_version_root = _canonical_handoff_path(
                str(candidate_environment.parent), label="owner Version root", directory=True,
            )
            _owner_version_raw, owner_version_probe = _private_handoff_json(
                candidate_version_root / "version.json",
            )
            owner_identity_probe = owner_version_probe.get("identity")
            owner_pinokio = (isinstance(owner_identity_probe, Mapping)
                             and owner_identity_probe.get("managed_by") == "pinokio")
        except BootstrapError as exc:
            owner_version_error = exc
    candidate_pinokio = managed_by_env or selected_for_data or owner_pinokio
    if not candidate_pinokio:
        # Service-backed source profiles can belong to other Runtime users;
        # only selected records for this data root or a Pinokio Version prove
        # that this Runtime is part of a Pinokio installation.
        return None
    if source_error is not None:
        raise source_error
    if source is None:
        raise BootstrapError("Runtime Pinokio stop binding is missing the selected source profile.")
    if selection_error is not None:
        raise selection_error
    if not selected_for_data:
        raise BootstrapError("Runtime Pinokio stop binding has no selected install record for this data root.")
    if not source.service_declaration:
        raise BootstrapError("Runtime Pinokio stop binding has no selected service declaration.")
    if owner_version_error is not None and not owner_pinokio:
        # Selected Pinokio metadata remains sufficient to make malformed or
        # missing Version composition a fail-closed refusal.
        raise owner_version_error
    if not source.runtime_environment:
        raise BootstrapError("Runtime Pinokio stop binding has no selected interpreter environment.")

    environment = _canonical_handoff_path(
        source.runtime_environment, label="runtime environment", directory=True,
    )
    owner_version_root = _canonical_handoff_path(
        str(environment.parent), label="Version root", directory=True,
    )
    program_root = _canonical_handoff_path(
        str(owner_version_root.parent.parent), label="program root", directory=True,
    )
    if owner_version_root.parent != program_root / "versions":
        raise BootstrapError("Runtime Pinokio owner Version is outside the selected program root.")
    runtime_checkout = _canonical_handoff_path(
        source.runtime_checkout, label="Runtime checkout", directory=True,
    )
    source_checkout = _canonical_handoff_path(
        source.source_checkout, label="Agent checkout", directory=True,
    )
    declaration = _canonical_handoff_path(
        source.service_declaration, label="service declaration", directory=False,
    )

    current_path = program_root / "current"
    current_raw = _private_handoff_bytes(current_path)
    version_name = current_raw.decode("utf-8").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version_name):
        raise BootstrapError("Runtime Pinokio stop binding has an invalid selected Version pointer.")
    selected_version_root = _canonical_handoff_path(
        str(program_root / "versions" / version_name), label="selected Version root", directory=True,
    )

    _marker_raw, install_marker = _private_handoff_json(program_root / "install.json")
    expected_root = _canonical_realm_root(str(realm.get("data_root") or ""))
    realm_id = str(realm.get("realm_id") or "")
    if (selected.get("owner") != INSTALL_RECORD_OWNER
            or selected.get("managed_by") != "pinokio"
            or _canonical_handoff_path(selected.get("program_root"), label="selection program root", directory=True) != program_root
            or _canonical_handoff_path(selected.get("data_root"), label="selection data root", directory=True) != paths.app_support
            or str(selected.get("realm_id") or "") != realm_id
            or _canonical_handoff_path(selected.get("realm_root"), label="selection realm root", directory=True) != expected_root):
        raise BootstrapError("Runtime Pinokio stop binding conflicts with the selected install record.")
    if (install_marker.get("owner") != INSTALL_RECORD_OWNER
            or install_marker.get("managed_by") != "pinokio"
            or _canonical_handoff_path(install_marker.get("data_root"), label="install marker data root", directory=True) != paths.app_support):
        raise BootstrapError("Runtime Pinokio stop binding conflicts with the program install marker.")

    def read_version(root: Path, *, label: str) -> tuple[bytes, dict[str, Any], dict[str, Any], bytes, Path]:
        version_raw, version = _private_handoff_json(root / "version.json")
        if _canonical_handoff_path(version.get("root"), label=f"{label} root", directory=True) != root:
            raise BootstrapError(f"Runtime Pinokio stop binding has a conflicting {label} record.")
        identity = version.get("identity")
        if (not isinstance(identity, Mapping) or identity.get("managed_by") != "pinokio"
                or type(identity.get("release")) is not int or identity["release"] < 0):
            raise BootstrapError(f"Runtime Pinokio stop binding has no Pinokio {label} identity.")
        profile_path = _canonical_handoff_path(version.get("profile"), label=f"{label} profile", directory=False)
        profile_raw, profile = _private_handoff_json(profile_path)
        if profile.get("profile") != "astrid":
            raise BootstrapError(f"Runtime Pinokio stop binding has a non-Astrid {label} profile.")
        return version_raw, version, dict(identity), profile_raw, profile_path

    owner_version_raw, owner_version, owner_identity, profile_raw, owner_profile_path = read_version(
        owner_version_root, label="owner Version",
    )
    _selected_version_raw, selected_version, selected_identity, _selected_profile_raw, selected_profile_path = read_version(
        selected_version_root, label="selected Version",
    )
    if selected.get("identity") != selected_identity:
        raise BootstrapError("Runtime Pinokio stop binding conflicts with the selected Version identity.")
    raw_python = owner_version.get("python")
    python_path = Path(raw_python).expanduser() if isinstance(raw_python, str) else Path()
    if (not python_path.is_absolute() or _has_symlink_component(python_path.parent)
            or python_path.parent.resolve() not in {environment / "bin", environment / "Scripts"}
            or not python_path.is_file()):
        raise BootstrapError("Runtime Pinokio stop binding interpreter escapes its environment.")
    raw_selected_python = selected_version.get("python")
    selected_python = Path(raw_selected_python).expanduser() if isinstance(raw_selected_python, str) else Path()
    if (not selected_python.is_absolute() or _has_symlink_component(selected_python.parent)
            or not selected_python.is_file()):
        raise BootstrapError("Runtime Pinokio selected interpreter is missing or unsafe.")
    selected_environment = selected_python.parent.parent
    if not selected_environment.is_dir():
        raise BootstrapError("Runtime Pinokio selected interpreter environment is unavailable.")
    _, version_profile = _private_handoff_json(owner_profile_path)
    _, selected_profile = _private_handoff_json(selected_profile_path)
    if selected_profile.get("runtime_environment") != str(selected_environment):
        raise BootstrapError("Runtime Pinokio selected profile differs from its interpreter environment.")
    for key, expected in (("runtime_checkout", str(runtime_checkout)),
                          ("source_checkout", str(source_checkout)),
                          ("runtime_environment", str(environment)),
                          ("service_declaration", str(declaration))):
        if version_profile.get(key) != expected:
            raise BootstrapError("Runtime Pinokio stop binding differs from the selected Version profile.")
    if version_profile.get("source_digest", "") != source.source_digest:
        raise BootstrapError("Runtime Pinokio stop binding source digest differs from the selected Version profile.")
    declaration_raw = _private_handoff_bytes(declaration)
    release = owner_identity["release"]

    def digest(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()
    stable_marker = {key: install_marker.get(key) for key in ("owner", "managed_by", "data_root")}
    return {
        "program_root": str(program_root),
        "data_root": str(paths.app_support),
        "realm_id": realm_id,
        "realm_root": str(expected_root),
        "owner_version_root": str(owner_version_root),
        "owner_version_name": owner_version_root.name,
        "owner_release": release,
        "runtime_checkout": str(runtime_checkout),
        "source_checkout": str(source_checkout),
        "runtime_environment": str(environment),
        "service_declaration": str(declaration),
        "source_profile_sha256": source.digest,
        "install_marker_sha256": digest(json.dumps(stable_marker, sort_keys=True).encode("utf-8")),
        "owner_version_sha256": digest(owner_version_raw),
        "profile_sha256": digest(profile_raw),
        "owner_identity_sha256": digest(json.dumps(owner_identity, sort_keys=True).encode("utf-8")),
        "service_declaration_sha256": digest(declaration_raw),
    }


def _durable_remove(path: Path) -> None:
    """Remove one authority marker and persist its directory entry update."""
    try:
        path.unlink()
    except FileNotFoundError:
        return
    runtime_platform.fsync_directory(path.parent)


def _require_owner_absent(boundary: RuntimeBoundary, pid: int, birth: str, *, context: str) -> None:
    try:
        if _pid_alive(boundary, pid):
            raise BootstrapError(f"Runtime Pinokio stopped owner is still present {context}.")
        observe_birth = getattr(boundary, "process_birth_identity", None)
        if callable(observe_birth):
            observed_birth = observe_birth(pid)
            if observed_birth is not None:
                raise BootstrapError(f"Runtime Pinokio stopped owner identity changed {context}.")
    except BootstrapError:
        raise
    except Exception as exc:
        raise BootstrapError(f"Runtime Pinokio owner absence is unknown {context}.") from exc


def _completed_stop_record(
    paths: RuntimePaths, marker: Mapping[str, Any] | None,
    binding: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(marker, Mapping) or marker.get("state") != "completed_stop":
        return None
    owner = _validate_completed_stop_marker(marker)
    receipt = marker["completed_stop"]
    if binding is None or dict(receipt["binding"]) != dict(binding):
        # A changed selection must permanently retire this lifetime; otherwise
        # a later filesystem revert could make old evidence useful again.
        _durable_remove(paths.instance_lock_path)
        raise BootstrapError("Runtime Pinokio completed-stop binding changed; refusing interruption.")
    if str(owner.get("data_root") or "") != str(paths.app_support):
        _durable_remove(paths.instance_lock_path)
        raise BootstrapError("Runtime Pinokio completed-stop data root changed; refusing interruption.")
    return {**owner, "binding": dict(binding)}


def _validate_completed_stop_marker(marker: Mapping[str, Any]) -> dict[str, Any]:
    receipt = marker.get("completed_stop")
    if (set(marker) != {"pid", "process_birth_id", "runtime_instance_id", "realm_id",
                        "realm_root", "data_root", "state", "completed_stop"}
            or not isinstance(receipt, Mapping)
            or set(receipt) != {"version", "binding"}
            or type(receipt.get("version")) is not int
            or receipt.get("version") != PINOKIO_STOP_HANDOFF_VERSION
            or not isinstance(receipt.get("binding"), Mapping)
            or set(receipt["binding"]) != PINOKIO_STOP_BINDING_KEYS):
        raise BootstrapError("Runtime Pinokio completed-stop marker is malformed; refusing interruption.")
    owner = dict(marker)
    pid = owner.get("pid")
    birth = owner.get("process_birth_id")
    instance = owner.get("runtime_instance_id")
    realm_id = owner.get("realm_id")
    realm_root_raw = owner.get("realm_root")
    data_root = owner.get("data_root")
    if (type(pid) is not int or pid <= 0
            or any(not isinstance(value, str) or not value
                   for value in (birth, instance, realm_id, realm_root_raw, data_root))):
        raise BootstrapError("Runtime Pinokio completed-stop owner identity is malformed.")
    try:
        realm_root = _canonical_realm_root(realm_root_raw)
        _canonical_handoff_path(data_root, label="completed-stop data root", directory=True)
    except BootstrapError as exc:
        raise BootstrapError("Runtime Pinokio completed-stop owner identity is malformed.") from exc
    if not _owner_record_matches(owner, pid=pid, instance_id=instance,
                                 process_birth_id=birth, realm_id=realm_id,
                                 realm_root=realm_root):
        raise BootstrapError("Runtime Pinokio completed-stop owner identity is malformed.")
    _validate_binding_fields(receipt["binding"])
    return owner


def _validate_binding_fields(binding: Mapping[str, Any]) -> None:
    for key, value in binding.items():
        if key.endswith("_sha256"):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise BootstrapError("Runtime Pinokio completed-stop binding digest is malformed.")
        elif key.endswith("_release"):
            if type(value) is not int or value < 0:
                raise BootstrapError("Runtime Pinokio completed-stop binding release is malformed.")
        elif not isinstance(value, str) or not value:
            raise BootstrapError("Runtime Pinokio completed-stop binding field is malformed.")


def _validate_stopping_marker(marker: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the Runtime-written intent form of instance.lock.

    C1 writes it inside the final fence, before the first signal. It is
    evidence only that C1 admitted and was stopping this exact owner; it is
    never live health or discovery.
    """
    intent = marker.get("stopping")
    if (set(marker) != {"pid", "process_birth_id", "runtime_instance_id", "realm_id",
                        "realm_root", "data_root", "state", "stopping"}
            or marker.get("state") != "stopping"
            or not isinstance(intent, Mapping)
            or set(intent) != {"version", "binding"}
            or type(intent.get("version")) is not int
            or intent.get("version") != PINOKIO_STOP_HANDOFF_VERSION):
        raise BootstrapError("Runtime owner stopping marker is malformed; refusing interruption.")
    binding = intent.get("binding")
    if binding is not None:
        if not isinstance(binding, Mapping) or set(binding) != PINOKIO_STOP_BINDING_KEYS:
            raise BootstrapError("Runtime owner stopping marker is malformed; refusing interruption.")
        _validate_binding_fields(binding)
    owner = dict(marker)
    pid = owner.get("pid")
    if (type(pid) is not int or pid <= 0
            or any(not isinstance(owner.get(key), str) or not owner[key]
                   for key in ("process_birth_id", "runtime_instance_id", "realm_id",
                               "realm_root", "data_root"))):
        raise BootstrapError("Runtime owner stopping marker identity is malformed.")
    try:
        _canonical_realm_root(owner["realm_root"])
    except BootstrapError as exc:
        raise BootstrapError("Runtime owner stopping marker identity is malformed.") from exc
    return owner


def _revoke_completed_stop_before_launch(
    paths: RuntimePaths, boundary: RuntimeBoundary, realm: Mapping[str, Any],
) -> dict[str, Any] | None:
    marker = _read_support_json(paths.instance_lock_path)
    if marker is None:
        return None
    if marker.get("state") is None:
        return None
    if marker.get("state") == "stopping":
        # Intent evidence is revoked like a completed stop, but only on
        # positive absence; every other outcome leaves the bytes unchanged.
        # The single exception is a published owner that is still alive and
        # matches the intent exactly: a stop refused before its first signal
        # leaves that owner untouched, so launch reconnects to it instead.
        conflict = "Runtime owner stopping marker conflicts with a published owner; launch refused."
        owner = _validate_stopping_marker(marker)
        if str(owner.get("data_root")) != str(paths.app_support):
            raise BootstrapError(conflict)
        discovery = _read_support_json(paths.discovery_path)
        if discovery is not None:
            try:
                published = _validate_published_stop_owner(
                    paths, boundary, realm,
                    _canonical_realm_root(str(realm.get("data_root") or "")),
                    discovery, marker,
                )
            except BootstrapError as exc:
                raise BootstrapError(conflict) from exc
            if published is None:
                raise BootstrapError(conflict)
            # The lock keeps its stopping form here; the reconnect path in
            # bootstrap restores the live form once the owner is revalidated.
            return None
        _require_owner_absent(
            boundary, int(owner["pid"]), str(owner["process_birth_id"]),
            context="before launch",
        )
        _durable_remove(paths.instance_lock_path)
        return None
    if marker.get("state") != "completed_stop":
        raise BootstrapError("Runtime owner lock has an unknown state; launch refused.")
    try:
        owner = _validate_completed_stop_marker(marker)
    except (KeyError, TypeError, ValueError, BootstrapError):
        _durable_remove(paths.instance_lock_path)
        raise BootstrapError("Runtime Pinokio completed-stop marker is malformed; launch refused.")
    if str(owner.get("data_root") or "") != str(paths.app_support):
        _durable_remove(paths.instance_lock_path)
        raise BootstrapError("Runtime Pinokio completed-stop data root changed; launch refused.")
    discovery = _read_support_json(paths.discovery_path)
    if discovery is not None:
        _durable_remove(paths.instance_lock_path)
        raise _pinokio_stop_refusal("Runtime Pinokio completed-stop marker conflicts with a published owner.")
    try:
        _require_owner_absent(
            boundary, int(owner["pid"]), str(owner["process_birth_id"]),
            context="before launch",
        )
    except BootstrapError as exc:
        _durable_remove(paths.instance_lock_path)
        raise _pinokio_stop_refusal(str(exc)) from exc
    # This is intentionally before boundary.start. Only a later C1 cleanup
    # that proves this attempt ended before publication can re-attest it.
    _durable_remove(paths.instance_lock_path)
    return dict(marker)


def _restore_admitted_live_lock(paths: RuntimePaths) -> None:
    """Return a stopping intent, admitted for reconnect, to the live lock form."""
    marker = _read_support_json(paths.instance_lock_path)
    if marker is None or marker.get("state") != "stopping":
        return
    owner = _validate_stopping_marker(marker)
    atomic_write_json(paths.instance_lock_path, {
        key: owner[key] for key in (
            "pid", "process_birth_id", "runtime_instance_id", "realm_id", "realm_root",
        )
    })


@contextmanager
def _downstream_stop_errors():
    """Keep post-admission failure details from looking like lifecycle refusal."""
    try:
        yield
    except ConflictError as exc:
        error = _raise_conflict(exc)
        details = {"cause_details": dict(error.details)} if error.details else None
        raise BootstrapError(str(error), details=details) from exc
    except BootstrapError as exc:
        if not exc.details:
            raise
        raise BootstrapError(
            str(exc), details={"cause_details": dict(exc.details)},
        ) from exc
    except Exception as exc:
        inherited = getattr(exc, "details", None)
        if not isinstance(inherited, Mapping) or not inherited:
            raise
        raise BootstrapError(
            str(exc), details={"cause_details": dict(inherited)},
        ) from exc


def _fenced_stop_and_manager(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, realm_id: str, realm_root: Path,
    discovery: Mapping[str, Any] | None, marker: Mapping[str, Any] | None,
    owner: tuple[int, str, str, str] | None, stop_manager=None,
    stop_foreground=None, validate_stop=None, stale_owner_identity=None,
    allow_missing_realm: bool = False,
    completed_stop_binding: Mapping[str, Any] | None = None,
    retained_completed_stop: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Stop an admitted owner and its manager while the caller holds the mutex."""
    try:
        fence = (nullcontext({"safe": True, "realm_absent": True})
                 if allow_missing_realm else interruption_fence(realm_root))
        with fence as final_report:
            try:
                final_discovery = _read_support_json(paths.discovery_path)
                final_marker = _read_support_json(paths.instance_lock_path)
            except Exception:
                raise
            if final_discovery != discovery:
                raise BootstrapError("Runtime discovery changed before stop; refusing interruption.")
            if final_marker != marker:
                raise BootstrapError("Runtime owner lock changed before stop; refusing interruption.")
            if validate_stop is not None:
                validate_stop()
            if stale_owner_identity is not None:
                stale_pid, stale_birth = stale_owner_identity
                try:
                    if _pid_alive(boundary, stale_pid):
                        raise BootstrapError(
                            "Runtime interruption refused: stale owner process is present at the final fence."
                        )
                    observe_birth = getattr(boundary, "process_birth_identity", None)
                    if callable(observe_birth):
                        observed_birth = observe_birth(stale_pid)
                        if observed_birth is not None:
                            raise BootstrapError(
                                "Runtime interruption refused: stale owner process identity changed at the final fence."
                            )
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError(
                        "Runtime interruption refused: owner absence could not be re-established at the final fence."
                    ) from exc
            stopped = None
            # Everything after fence admission is downstream. A controller or
            # manager may fail after acting, so its details cannot represent
            # an initial lifecycle refusal.
            with _downstream_stop_errors():
                if owner is not None:
                    pid, birth, instance_id, endpoint = owner
                    stop_owner = getattr(boundary, "stop_owner", None)
                    if not callable(stop_owner):
                        raise BootstrapError("Runtime boundary lacks the birth-checked stop handoff.")
                    # Durable Runtime-written intent, before the first signal:
                    # if the controller dies after TERM, a retry can prove
                    # this exact owner was being stopped by C1.
                    intent = {
                        "pid": int(pid), "process_birth_id": str(birth),
                        "runtime_instance_id": str(instance_id),
                        "realm_id": str(realm_id), "realm_root": str(realm_root),
                        "data_root": str(paths.app_support), "state": "stopping",
                        "stopping": {
                            "version": PINOKIO_STOP_HANDOFF_VERSION,
                            "binding": (dict(completed_stop_binding)
                                        if completed_stop_binding is not None else None),
                        },
                    }
                    if final_marker != intent:
                        atomic_write_json(paths.instance_lock_path, intent)
                    marker = intent
                    # First destructive operation: Runtime's existing validated stop.
                    stopped = stop_owner(
                        endpoint=endpoint, pid=pid, instance_id=instance_id,
                        process_birth_id=birth, realm_id=realm_id,
                        owner_lock=paths.instance_lock_path,
                        discovery_path=paths.discovery_path, require_health=False,
                    )
                    if completed_stop_binding is not None:
                        _require_owner_absent(
                            boundary, pid, birth, context="after Runtime stop",
                        )
                elif stop_foreground is not None:
                    stopped = stop_foreground()
                # The stopped owner can remove its own advertisements. A new
                # identity must never be covered by the old owner's authority,
                # even if it appears before the manager callback rather than
                # after it. Preserve the replacement and forbid manager or
                # cleanup work; a later retry must pass C1 again.
                for path, expected in ((paths.discovery_path, discovery),
                                       (paths.instance_lock_path, marker)):
                    observed = _read_support_json(path)
                    if observed is not None and observed != expected:
                        raise BootstrapError(
                            "Runtime owner changed before manager stop; refusing interruption."
                        )
                # Revalidate the recovery context after all publications have
                # been checked, immediately before invoking the manager callback.
                # In the missing-realm case this is the serialized absence check
                # that substitutes for the SQLite fence.
                if validate_stop is not None:
                    validate_stop()
                if stale_owner_identity is not None:
                    stale_pid, stale_birth = stale_owner_identity
                    try:
                        if _pid_alive(boundary, stale_pid):
                            raise BootstrapError(
                                "Runtime interruption refused: stale owner process is present immediately before manager stop."
                            )
                        observe_birth = getattr(boundary, "process_birth_identity", None)
                        if callable(observe_birth):
                            observed_birth = observe_birth(stale_pid)
                            if observed_birth is not None:
                                raise BootstrapError(
                                    "Runtime interruption refused: stale owner identity changed immediately before manager stop."
                                )
                    except BootstrapError:
                        raise
                    except Exception as exc:
                        raise BootstrapError(
                            "Runtime interruption refused: owner absence could not be re-established immediately before manager stop."
                        ) from exc
                if stop_manager is not None:
                    stop_manager()
    except ConflictError as exc:
        raise _raise_conflict(exc) from exc
    except BootstrapError:
        raise
    except Exception as exc:
        inherited = getattr(exc, "details", None)
        details = dict(inherited) if isinstance(inherited, Mapping) else None
        raise BootstrapError(str(exc), details=details) from exc

    # Cleanup is after the manager has synchronously stopped and after the
    # SQLite fence released. Preserve any replacement identity.
    with _downstream_stop_errors():
        current_discovery = _read_support_json(paths.discovery_path)
        current_marker = _read_support_json(paths.instance_lock_path)
        if owner is not None:
            pid, birth, instance_id, _endpoint = owner
            if current_discovery is not None and not _owner_record_matches(
                current_discovery, pid=pid, instance_id=instance_id,
                process_birth_id=birth, realm_id=realm_id, realm_root=realm_root,
            ):
                raise BootstrapError("Runtime owner changed during stop; refusing discovery cleanup.")
            if current_marker is not None and not _owner_record_matches(
                current_marker, pid=pid, instance_id=instance_id,
                process_birth_id=birth, realm_id=realm_id, realm_root=realm_root,
            ):
                raise BootstrapError("Runtime owner changed during stop; refusing owner-lock cleanup.")
        else:
            # For absent/stale publications, never unlink a record that was
            # replaced while the manager callback ran. Equality is used here
            # because no live-owner stop authority was established.
            if current_discovery is not None and current_discovery != discovery:
                raise BootstrapError("Runtime discovery changed during stop; refusing cleanup.")
            if current_marker is not None and current_marker != marker:
                raise BootstrapError("Runtime owner lock changed during stop; refusing cleanup.")
        if current_discovery is not None:
            remove_file(paths.discovery_path)
        if owner is not None and completed_stop_binding is not None:
            if marker is None:
                raise BootstrapError("Runtime completed-stop publication lacks the stopped owner marker.")
            owner_record = {
                "pid": int(owner[0]),
                "process_birth_id": str(owner[1]),
                "runtime_instance_id": str(owner[2]),
                "realm_id": str(realm_id),
                "realm_root": str(realm_root),
                "data_root": str(paths.app_support),
            }
            _require_owner_absent(
                boundary, int(owner[0]), str(owner[1]), context="before receipt publication",
            )
            atomic_write_json(paths.instance_lock_path, {
                **owner_record,
                "state": "completed_stop",
                "completed_stop": {
                    "version": PINOKIO_STOP_HANDOFF_VERSION,
                    "binding": dict(completed_stop_binding),
                },
            })
        elif retained_completed_stop is not None:
            # A fresh Runtime process may repeat canonical down after the
            # session owner already exited. Keep the same marker until a new
            # launch attempt invalidates this owner lifetime.
            observed = _read_support_json(paths.instance_lock_path)
            if observed != marker:
                raise BootstrapError("Runtime completed-stop marker changed during retry; refusing cleanup.")
            if marker is not None and marker.get("state") == "stopping":
                _require_owner_absent(
                    boundary, int(marker["pid"]), str(marker["process_birth_id"]),
                    context="before receipt publication",
                )
                atomic_write_json(paths.instance_lock_path, {
                    **{key: marker[key] for key in (
                        "pid", "process_birth_id", "runtime_instance_id", "realm_id",
                        "realm_root", "data_root")},
                    "state": "completed_stop",
                    "completed_stop": {
                        "version": PINOKIO_STOP_HANDOFF_VERSION,
                        "binding": dict(retained_completed_stop["binding"]),
                    },
                })
        elif current_marker is not None:
            remove_file(paths.instance_lock_path)
    return {"status": "stopped", "realm_id": realm_id,
            "runtime": stopped, "interruption": final_report}


def _restore_json_snapshot(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read exact regular-file bytes without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BootstrapError(f"Restore metadata is missing or unsafe: {path}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"not a regular file: {path}")
        chunks = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.extend(chunk)
    finally:
        os.close(fd)
    raw = bytes(chunks)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"Restore metadata is malformed: {path}") from exc
    if not isinstance(value, Mapping):
        raise BootstrapError(f"Restore metadata must contain an object: {path}")
    return raw, dict(value)


def _canonical_metadata_path(value: Path, *, label: str) -> Path:
    path = Path(value).expanduser()
    if (not path.is_absolute() or _has_symlink_component(path) or path.is_symlink()
            or Path(os.path.abspath(path)) != path):
        raise BootstrapError(f"Restore {label} path must be absolute, canonical and symlink-free.")
    return path


def _restore_realm_absent(path: Path) -> bool:
    """Prove only a missing leaf realm, never an unreadable path, is absent."""
    path = _canonical_metadata_path(Path(path), label="realm root")
    parent = path.parent
    try:
        parent_info = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise BootstrapError("Restore realm parent is unavailable or unsafe.") from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise BootstrapError("Restore realm parent is not a regular directory.")
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise BootstrapError("Restore realm availability could not be established.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BootstrapError("Restore realm root is unsafe or not a directory.")
    return False


def _restore_selection_snapshot(
    paths: RuntimePaths, selection: RestoreSelection,
) -> dict[str, Any]:
    """Derive a recovery realm only from agreeing existing installer metadata."""
    journal_path = _canonical_metadata_path(Path(selection.journal_path), label="journal")
    selection_path = _canonical_metadata_path(Path(selection.selection_path), label="selection")
    if journal_path.name != "update-transaction.json":
        raise BootstrapError("Restore journal path is not the installation update transaction.")
    install_root = journal_path.parent
    if not install_root.is_dir():
        raise BootstrapError("Restore installation root is unavailable.")
    journal_bytes, journal = _restore_json_snapshot(journal_path)
    selection_bytes, selected = _restore_json_snapshot(selection_path)
    if (journal.get("format") != "astrid-install-update/v1"
            or journal.get("step") != "recovering"
            or journal.get("transaction_kind") not in (None, "migration")):
        raise BootstrapError("Restore selection requires a pending migration recovery journal.")
    if (not isinstance(journal.get("operation_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", journal["operation_id"])):
        raise BootstrapError("Restore journal operation identity is malformed.")

    backup = journal.get("backup")
    if not isinstance(backup, Mapping) or backup.get("kind") not in ("clone", "runtime"):
        raise BootstrapError("Restore journal does not name a supported retained backup.")
    backup_root = _canonical_metadata_path(Path(str(backup.get("root") or "")), label="backup")
    expected_backups = _canonical_metadata_path(install_root / "backups", label="backup directory")
    if backup_root.parent != expected_backups or not backup_root.is_dir():
        raise BootstrapError("Restore backup is outside this installation's retained backups.")
    backup_catalog_path = backup_root / "support" / "runtime" / "catalog.json"
    backup_catalog_path = _canonical_metadata_path(backup_catalog_path, label="retained catalog")
    backup_catalog_bytes, backup_catalog_value = _restore_json_snapshot(backup_catalog_path)

    owner = str(selected.get("owner") or "")
    raw_program_root = str(selected.get("program_root") or "")
    raw_data_root = str(selected.get("data_root") or "")
    realm_id = str(selected.get("realm_id") or "")
    raw_realm_root = str(selected.get("realm_root") or "")
    if owner != INSTALL_RECORD_OWNER:
        raise BootstrapError("Restore install selection has an unsupported owner.")
    program_root = _canonical_metadata_path(Path(raw_program_root), label="program root")
    data_root = _canonical_metadata_path(Path(raw_data_root), label="data root")
    realm_root = _canonical_realm_root(
        _canonical_metadata_path(Path(raw_realm_root), label="realm root"), allow_missing=True)
    journal_data = _canonical_metadata_path(Path(str(journal.get("data_root") or "")), label="journal data root")
    journal_realm = journal.get("realm")
    if not isinstance(journal_realm, Mapping):
        raise BootstrapError("Restore journal does not identify its selected realm.")
    journal_realm_root = _canonical_realm_root(_canonical_metadata_path(
        Path(str(journal_realm.get("realm_root") or "")), label="journal realm root"), allow_missing=True)
    if (program_root != install_root or data_root != journal_data
            or str(journal_realm.get("realm_id") or "") != realm_id
            or journal_realm_root != realm_root
            or not realm_id or any(char in realm_id for char in "/\\")
            or not isinstance(journal_realm.get("realm_id"), str)
            or not isinstance(selected.get("realm_id"), str)):
        raise BootstrapError("Restore journal and install selection disagree on installation or realm identity.")

    retained = _validate_catalog(backup_catalog_value)
    retained_realm = _selected_realm(retained)
    retained_root = _canonical_realm_root(_canonical_metadata_path(
        Path(str(retained_realm.get("data_root") or "")), label="retained realm root"), allow_missing=True) if retained_realm else None
    if (retained_realm is None or not isinstance(retained.get("selected_realm_id"), str)
            or not isinstance(retained_realm.get("realm_id"), str)
            or retained.get("selected_realm_id") != realm_id
            or str(retained_realm.get("realm_id") or "") != realm_id
            or retained_root != realm_root):
        raise BootstrapError("Retained backup catalog conflicts with the install selection.")

    live_catalog_bytes = None
    live_catalog = None
    if os.path.lexists(str(paths.catalog_path)):
        live_catalog_bytes, live_catalog = _restore_json_snapshot(paths.catalog_path)
        parsed_live = _validate_catalog(live_catalog)
        live_realm = _selected_realm(parsed_live)
        live_root = _canonical_realm_root(_canonical_metadata_path(
            Path(str(live_realm.get("data_root") or "")), label="current realm root"), allow_missing=True) if live_realm else None
        if (live_realm is None
                or not isinstance(parsed_live.get("selected_realm_id"), str)
                or not isinstance(live_realm.get("realm_id"), str)
                or str(parsed_live.get("selected_realm_id") or "") != realm_id
                or str(live_realm.get("realm_id") or "") != realm_id
                or live_root != realm_root):
            raise BootstrapError("Current Runtime catalog conflicts with the retained restore selection.")

    realm_absent = _restore_realm_absent(realm_root)
    return {
        "journal_path": journal_path, "selection_path": selection_path,
        "journal_bytes": journal_bytes, "selection_bytes": selection_bytes,
        "backup_catalog_path": backup_catalog_path,
        "backup_catalog_bytes": backup_catalog_bytes,
        "catalog": retained, "live_catalog_bytes": live_catalog_bytes,
        "program_root": program_root, "realm_id": realm_id,
        "realm_root": realm_root, "data_root": data_root,
        "realm_absent": realm_absent,
    }


def _validate_restore_snapshot(paths: RuntimePaths, selection: RestoreSelection,
                               snapshot: Mapping[str, Any]) -> None:
    current = _restore_selection_snapshot(paths, selection)
    for key in ("journal_bytes", "selection_bytes", "backup_catalog_bytes", "live_catalog_bytes",
                "program_root", "realm_id", "realm_root", "realm_absent"):
        if current.get(key) != snapshot.get(key):
            raise BootstrapError("Restore metadata changed during Runtime interruption; refusing recovery.")
    _inspect_restore_realm(current)


def _selected_restore_snapshot(paths: RuntimePaths, selection: RestoreSelection) -> dict[str, Any]:
    snapshot = _restore_selection_snapshot(paths, selection)
    if Path(snapshot["data_root"]) != paths.app_support:
        raise BootstrapError("Restore selection does not belong to this Runtime data root.")
    _inspect_restore_realm(snapshot)
    return snapshot


def _require_restore_publications_absent(
    paths: RuntimePaths, *, expected_completed_marker: Mapping[str, Any] | None = None,
) -> None:
    discovery = _read_support_json(paths.discovery_path)
    marker = _read_support_json(paths.instance_lock_path)
    if discovery is not None:
        raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")
    if marker is None and expected_completed_marker is None:
        return
    if (marker is not None and expected_completed_marker is not None
            and marker == expected_completed_marker
            and marker.get("state") == "completed_stop"):
        return
    if marker is not None:
        raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")
    raise BootstrapError("Restore recovery owner marker changed during admission.")


def _inspect_restore_realm(snapshot: Mapping[str, Any]) -> None:
    if snapshot.get("realm_absent") is True:
        if not _restore_realm_absent(Path(snapshot["realm_root"])):
            raise BootstrapError("Restore realm reappeared during recovery admission.")
        return
    from runtime_protocol.upgrade import inspect_canonical_schema

    try:
        inspect_canonical_schema(
            Path(snapshot["realm_root"]), expected_realm_id=str(snapshot["realm_id"]),
        )
    except Exception as exc:
        raise BootstrapError("Restore selection does not match the readable Runtime realm identity.") from exc


def _interrupt_owner_locked(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    stop_foreground=None, restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Admit, fence, stop and clean the selected Runtime owner."""
    _validate_support_paths(paths)
    if restore_selection is not None:
        snapshot = _selected_restore_snapshot(paths, restore_selection)
        marker = _read_support_json(paths.instance_lock_path)
        if (marker is not None and marker.get("state") == "completed_stop"
                and _read_support_json(paths.discovery_path) is not None):
            _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal("Runtime completed-stop marker conflicts with an active discovery.")
        retained_completed_stop = None
        if marker is not None:
            if marker.get("state") != "completed_stop":
                raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")
            try:
                retained_completed_stop = _validate_completed_stop_marker(marker)
            except BootstrapError as exc:
                _durable_remove(paths.instance_lock_path)
                raise _pinokio_stop_refusal(str(exc)) from exc
            binding = marker["completed_stop"]["binding"]
            if (retained_completed_stop.get("data_root") != str(snapshot["data_root"])
                    or retained_completed_stop.get("realm_id") != str(snapshot["realm_id"])
                    or _canonical_realm_root(str(retained_completed_stop.get("realm_root") or ""))
                    != Path(snapshot["realm_root"])
                    or binding.get("data_root") != str(snapshot["data_root"])
                    or binding.get("realm_id") != str(snapshot["realm_id"])
                    or binding.get("realm_root") != str(snapshot["realm_root"])
                    or binding.get("program_root") != str(snapshot["program_root"])):
                _durable_remove(paths.instance_lock_path)
                raise _pinokio_stop_refusal("Runtime completed-stop marker conflicts with restore selection.")
            try:
                _require_owner_absent(
                    boundary, int(retained_completed_stop["pid"]),
                    str(retained_completed_stop["process_birth_id"]),
                    context="during restore admission",
                )
            except BootstrapError as exc:
                _durable_remove(paths.instance_lock_path)
                raise _pinokio_stop_refusal(str(exc)) from exc
        _require_restore_publications_absent(
            paths, expected_completed_marker=marker,
        )
        realm_absent = bool(snapshot["realm_absent"])

        def validate_restore() -> None:
            _validate_restore_snapshot(paths, restore_selection, snapshot)
            _require_restore_publications_absent(paths, expected_completed_marker=marker)
            if retained_completed_stop is not None:
                _require_owner_absent(
                    boundary, int(retained_completed_stop["pid"]),
                    str(retained_completed_stop["process_birth_id"]),
                    context="immediately before restore manager stop",
                )

        result = _fenced_stop_and_manager(
            paths, boundary, realm_id=str(snapshot["realm_id"]),
            realm_root=Path(snapshot["realm_root"]), discovery=None, marker=marker,
            owner=None, stop_manager=stop_manager, stop_foreground=stop_foreground,
            validate_stop=validate_restore, allow_missing_realm=realm_absent,
            retained_completed_stop=retained_completed_stop,
        )
        with _downstream_stop_errors():
            validate_restore()
            if snapshot["live_catalog_bytes"] is None:
                atomic_write_json(paths.catalog_path, snapshot["catalog"])
            if retained_completed_stop is not None:
                _durable_remove(paths.instance_lock_path)
        return {"status": "stopped", "realm_id": snapshot["realm_id"],
                "idle": result["interruption"],
                "catalog_restored": snapshot["live_catalog_bytes"] is None}

    realm, realm_root = _selected_stop_realm(paths)
    discovery = _read_support_json(paths.discovery_path)
    marker = _read_support_json(paths.instance_lock_path)
    if marker is not None and marker.get("state") == "completed_stop" and discovery is not None:
        _durable_remove(paths.instance_lock_path)
        raise _pinokio_stop_refusal("Runtime completed-stop marker conflicts with an active discovery.")
    try:
        pinokio_binding = _pinokio_stop_binding(paths, realm)
    except BootstrapError as exc:
        if discovery is not None:
            # A staged candidate Runtime can own a temporary live process
            # before its Version pointer commits. Its ordinary exact-owner C1
            # stop remains valid, but it cannot mint stopped-install evidence.
            pinokio_binding = None
        else:
            if marker is not None and marker.get("state") == "completed_stop":
                _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal(str(exc)) from exc
    owner = None
    stale_owner_identity = None
    retained_completed_stop = None
    reused_owner = False
    if discovery is None and marker is not None and marker.get("state") == "completed_stop":
        if pinokio_binding is None:
            _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal("Runtime completed-stop marker has no selected Pinokio installation.")
        try:
            retained_completed_stop = _completed_stop_record(paths, marker, pinokio_binding)
        except BootstrapError as exc:
            _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal(str(exc)) from exc
        try:
            stale_pid = int(retained_completed_stop["pid"])
            stale_birth = str(retained_completed_stop["process_birth_id"])
            stale_instance = str(retained_completed_stop["runtime_instance_id"])
            if _pid_alive(boundary, stale_pid):
                _durable_remove(paths.instance_lock_path)
                raise _pinokio_stop_refusal("Runtime Pinokio completed-stop owner is present; refusing interruption.")
            observe_birth = getattr(boundary, "process_birth_identity", None)
            if callable(observe_birth):
                observed_birth = observe_birth(stale_pid)
                if observed_birth is not None:
                    _durable_remove(paths.instance_lock_path)
                    raise _pinokio_stop_refusal(
                        "Runtime Pinokio completed-stop owner identity changed; refusing interruption."
                    )
            if (str(retained_completed_stop.get("realm_id")) != str(realm.get("realm_id"))
                    or _canonical_realm_root(str(retained_completed_stop.get("realm_root") or "")) != realm_root
                    or not stale_birth or not stale_instance):
                _durable_remove(paths.instance_lock_path)
                raise _pinokio_stop_refusal("Runtime Pinokio completed-stop owner no longer matches the selected realm.")
        except BootstrapError:
            _durable_remove(paths.instance_lock_path)
            raise
        except Exception as exc:
            _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal(
                "Runtime Pinokio completed-stop owner absence could not be established."
            ) from exc
    elif discovery is None and marker is not None and marker.get("state") == "stopping":
        # Runtime's own intent: admitted only on positive OS absence of that
        # exact pid and birth. A present, reused or unknown process refuses
        # with the lock bytes unchanged.
        stopping = _validate_stopping_marker(marker)
        if (stopping["data_root"] != str(paths.app_support)
                or stopping["realm_id"] != str(realm.get("realm_id"))
                or _canonical_realm_root(stopping["realm_root"]) != realm_root):
            raise BootstrapError("Runtime interruption refused: owner stopping marker does not match the selected realm.")
        _require_owner_absent(
            boundary, stopping["pid"], stopping["process_birth_id"],
            context="at stopping-marker admission",
        )
        stale_owner_identity = (stopping["pid"], stopping["process_birth_id"])
        recorded_binding = stopping["stopping"]["binding"]
        if pinokio_binding is not None:
            if recorded_binding is None or dict(recorded_binding) != pinokio_binding:
                _durable_remove(paths.instance_lock_path)
                raise _pinokio_stop_refusal("Runtime Pinokio stopping-marker binding changed; refusing interruption.")
            retained_completed_stop = {**stopping, "binding": dict(recorded_binding)}
    elif discovery is None and marker is not None:
        raise BootstrapError("Runtime interruption refused: owner lock has no matching discovery.")
    elif discovery is None and marker is None and pinokio_binding is not None:
        raise _pinokio_stop_refusal("Runtime Pinokio interruption refused: no owner or completed-stop evidence.")
    if discovery is not None:
        # A proven different birth identifies a reused PID. Keep both matching
        # publications until the lifecycle fence and manager callback succeed.
        stale_pid, stale_birth, stale_instance, _endpoint = _recorded_owner_identity(
            discovery, realm_id=str(realm["realm_id"]), realm_root=realm_root,
        )
        observe_birth = getattr(boundary, "process_birth_identity", None)
        alive = _pid_alive(boundary, stale_pid)
        actual_birth = observe_birth(stale_pid) if callable(observe_birth) and alive else None
        if (_read_support_json(paths.discovery_path) != discovery
                or _read_support_json(paths.instance_lock_path) != marker):
            raise BootstrapError("Runtime owner changed during stale-owner cleanup.")
        reused_owner = (marker is not None and marker.get("state") is None
                        and _owner_record_matches(marker, pid=stale_pid, instance_id=stale_instance,
                                                  process_birth_id=stale_birth,
                                                  realm_id=str(realm["realm_id"]), realm_root=realm_root)
                        and actual_birth is not None
                        and runtime_platform.process_birth_matches(stale_birth, actual_birth) is False)
        if not reused_owner:
            owner = _validate_published_stop_owner(
                paths, boundary, realm, realm_root, discovery, marker, observed_alive=alive,
            )
            if owner is None:
                stale_owner_identity = (stale_pid, stale_birth)
    elif (marker is not None and retained_completed_stop is None
          and stale_owner_identity is None):
        raise BootstrapError("Runtime interruption refused: owner lock identity is incomplete.")

    if owner is not None:
        _validate_stop_endpoint(paths, boundary, owner=owner,
                                realm_id=str(realm["realm_id"]), realm_root=realm_root)
        prepare_restart = getattr(boundary, "prepare_restart", None)
        if callable(prepare_restart):
            source_profiles = _read_catalog(paths).get("source_profiles", {})
            source_manifest = source_profiles.get("astrid") if isinstance(source_profiles, Mapping) else None
            source = (SourceProfile.from_mapping(source_manifest, expected_profile="astrid")
                      if isinstance(source_manifest, Mapping)
                      else BootstrapConfig().resolve_source_profile(paths))
            prepare_restart(
                source_profile=source, realm_id=str(realm["realm_id"]),
                realm_root=realm_root, support_root=paths.runtime_support,
                pid=int(owner[0]),
            )
    elif stop_foreground is not None and not callable(stop_foreground):
        raise TypeError("stop_foreground must be a zero-argument callback")

    def validate_stop_context() -> None:
        if reused_owner:
            if (_read_support_json(paths.discovery_path) != discovery
                    or _read_support_json(paths.instance_lock_path) != marker):
                raise BootstrapError("Runtime owner changed during stale-owner cleanup.")
            observed = boundary.process_birth_identity(stale_pid)
            if (not _pid_alive(boundary, stale_pid) or observed is None
                    or runtime_platform.process_birth_matches(stale_birth, observed) is not False):
                raise BootstrapError("Runtime reused process identity changed during stale-owner cleanup.")
        if pinokio_binding is None:
            return
        try:
            current_binding = _pinokio_stop_binding(paths, realm)
        except BootstrapError as exc:
            raise _pinokio_stop_refusal(str(exc)) from exc
        if current_binding != pinokio_binding:
            if retained_completed_stop is not None:
                _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal("Runtime Pinokio stop binding changed before manager stop.")
        if retained_completed_stop is None:
            return
        if _read_support_json(paths.instance_lock_path) != marker:
            raise BootstrapError("Runtime completed-stop marker changed before manager stop.")
        try:
            _require_owner_absent(
                boundary, int(retained_completed_stop["pid"]),
                str(retained_completed_stop["process_birth_id"]),
                context="immediately before manager stop",
            )
        except BootstrapError as exc:
            _durable_remove(paths.instance_lock_path)
            raise _pinokio_stop_refusal(str(exc)) from exc

    result = _fenced_stop_and_manager(
        paths, boundary, realm_id=str(realm["realm_id"]), realm_root=realm_root,
        discovery=discovery, marker=marker, owner=owner, stop_manager=stop_manager,
        stop_foreground=stop_foreground if owner is None else None,
        stale_owner_identity=stale_owner_identity,
        completed_stop_binding=pinokio_binding if owner is not None else None,
        retained_completed_stop=retained_completed_stop,
        validate_stop=validate_stop_context if pinokio_binding is not None or reused_owner else None,
    )
    return {"status": "stopped", "realm_id": str(realm["realm_id"]),
            "idle": result["interruption"]}


def _interrupt_owner(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    stop_foreground=None, restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Serialize owner validation, the lifecycle fence and manager callback."""
    _preflight_owner_interruption(paths, restore_selection=restore_selection)
    with _bootstrap_mutex(paths):
        return _interrupt_owner_locked(
            paths, boundary, stop_manager=stop_manager,
            stop_foreground=stop_foreground, restore_selection=restore_selection,
        )


def _preflight_owner_interruption(
    paths: RuntimePaths, *, restore_selection: RestoreSelection | None = None,
) -> None:
    """Refuse known busy state before acquiring launcher sidecars."""
    _validate_support_paths(paths)
    discovery = _read_support_json(paths.discovery_path)
    marker = _read_support_json(paths.instance_lock_path)
    if restore_selection is not None:
        _require_restore_publications_absent(paths, expected_completed_marker=marker)
    elif discovery is None and marker is not None:
        if marker.get("state") not in ("completed_stop", "stopping"):
            raise BootstrapError("Runtime interruption refused: owner lock has no matching discovery.")
    elif discovery is not None and marker is None:
        raise BootstrapError("Runtime interruption refused: owner lock does not match discovery.")
    elif discovery is None and marker is None and restore_selection is None:
        # No publication is a valid idle-stop state. The selected realm still
        # has to be readable and clear before sidecar serialization begins.
        realm, _root = _selected_stop_realm(paths)
        try:
            pinokio_binding = _pinokio_stop_binding(paths, realm)
        except BootstrapError as exc:
            raise _pinokio_stop_refusal(str(exc)) from exc
        if pinokio_binding is not None:
            raise _pinokio_stop_refusal("Runtime Pinokio interruption refused: no owner or completed-stop evidence.")
    if restore_selection is None:
        preflight_stop(paths)
    else:
        preflight_stop(paths, restore_selection=restore_selection)


def down(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    stop_foreground=None, restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Stop the selected owner, then its manager, under one lifecycle fence."""
    if stop_manager is not None and not callable(stop_manager):
        raise TypeError("stop_manager must be a zero-argument callback")
    if stop_foreground is not None and not callable(stop_foreground):
        raise TypeError("stop_foreground must be a zero-argument callback")
    if restore_selection is not None and not isinstance(restore_selection, RestoreSelection):
        raise TypeError("restore_selection must be a RestoreSelection")
    return _interrupt_owner(paths, boundary, stop_manager=stop_manager,
                            stop_foreground=stop_foreground,
                            restore_selection=restore_selection)


def _selected_stop_realm(paths: RuntimePaths) -> tuple[dict[str, Any], Path]:
    catalog = _read_catalog(paths)
    realm = _selected_realm(catalog)
    if realm is None:
        raise BootstrapError("No selected Runtime realm is available for a safe stop.")
    root = _canonical_realm_root(str(realm.get("data_root") or ""))
    return realm, root


def _raise_conflict(exc: ConflictError) -> BootstrapError:
    message, details = refusal_from(exc)
    return BootstrapError(message, details=details)


def preflight_stop(
    paths: RuntimePaths, *, restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Read-only selected-realm interruption check for installer callers."""
    _validate_support_paths(paths)
    if restore_selection is not None and not isinstance(restore_selection, RestoreSelection):
        raise TypeError("restore_selection must be a RestoreSelection")
    if restore_selection is not None:
        snapshot = _selected_restore_snapshot(paths, restore_selection)
        marker = _read_support_json(paths.instance_lock_path)
        _require_restore_publications_absent(paths, expected_completed_marker=marker)
        realm_root = Path(snapshot["realm_root"])
        if snapshot["realm_absent"]:
            return {"safe": True, "realm_absent": True}
    else:
        _realm, realm_root = _selected_stop_realm(paths)
    try:
        report = inspect_interruption_state(realm_root)
        if not report.get("safe", False):
            message, details = refusal_from(BootstrapError(
                "Runtime interruption refused while work is active or unreconciled.",
                details=report,
            ))
            raise BootstrapError(message, details=details)
        return report
    except BootstrapError:
        raise
    except ConflictError as exc:
        raise _raise_conflict(exc) from exc
    except Exception as exc:
        raise BootstrapError(str(exc)) from exc


def _recorded_owner_identity(
    value: Mapping[str, Any], *, realm_id: str, realm_root: Path,
) -> tuple[int, str, str, str]:
    try:
        pid = int(value["pid"])
        birth = str(value["process_birth_id"])
        instance = str(value["runtime_instance_id"])
        endpoint = _validate_loopback_endpoint(str(value["endpoint"]))
        observed_realm = str(value.get("active_realm") or value.get("realm_id") or "")
        observed_root = _canonical_realm_root(str(value.get("realm_root") or ""))
    except (KeyError, TypeError, ValueError, BootstrapError) as exc:
        raise BootstrapError("Runtime interruption refused: discovery or owner identity is incomplete.") from exc
    if pid <= 0 or not birth or not instance or observed_realm != realm_id or observed_root != realm_root:
        raise BootstrapError("Runtime interruption refused: discovery realm root does not match the selected workspace.")
    return pid, birth, instance, endpoint


def _validate_stop_endpoint(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, owner: tuple[int, str, str, str],
    realm_id: str, realm_root: Path,
) -> Mapping[str, Any]:
    """Validate the process/lock handoff and authenticated published endpoint."""
    pid, birth, instance_id, endpoint = owner
    validate = getattr(boundary, "validate_owner", None)
    if not callable(validate) or not validate(
        endpoint=endpoint, pid=pid, instance_id=instance_id,
        owner_lock=paths.instance_lock_path, process_birth_id=birth,
        expected_realm_id=realm_id, expected_realm_root=realm_root,
    ):
        raise BootstrapError("Runtime interruption refused: owner endpoint or process identity failed validation.")
    endpoint_metadata = getattr(boundary, "endpoint_metadata", None)
    if not callable(endpoint_metadata):
        raise BootstrapError("Runtime interruption refused: boundary cannot verify the selected endpoint.")
    identity = endpoint_metadata(
        endpoint=endpoint,
        credential_file=paths.runtime_support / "credentials" / "owner.token",
    )
    if (not identity
            or str(identity.get("runtime_instance_id") or "") != instance_id
            or str(identity.get("realm_id") or "") != realm_id):
        raise BootstrapError("Runtime interruption refused: endpoint identity does not match the selected owner.")
    return identity


def _validate_published_stop_owner(
    paths: RuntimePaths, boundary: RuntimeBoundary | None, realm: Mapping[str, Any],
    realm_root: Path, discovery: Mapping[str, Any], marker: Mapping[str, Any] | None,
    *, observed_alive: bool | None = None,
) -> tuple[int, str, str, str] | None:
    realm_id = str(realm.get("realm_id") or "")
    if marker is not None and marker.get("state") == "stopping":
        _validate_stopping_marker(marker)
    elif marker is not None and marker.get("state") is not None:
        raise BootstrapError("Runtime interruption refused: owner lock has an unknown state.")
    pid, birth, instance_id, endpoint = _recorded_owner_identity(
        discovery, realm_id=realm_id, realm_root=realm_root,
    )
    if (marker is None or str(marker.get("realm_id") or "") != realm_id
            or not _owner_record_matches(
        marker, pid=pid, instance_id=instance_id, process_birth_id=birth,
        realm_id=realm_id, realm_root=realm_root,
    )):
        raise BootstrapError("Runtime interruption refused: owner lock changed or does not match discovery.")
    alive = _pid_alive(boundary, pid) if observed_alive is None else observed_alive
    if not alive:
        try:
            if boundary is None:
                # _pid_alive used the platform identity API and returned only
                # after a successful absence observation.
                return None
            if not callable(getattr(boundary, "process_birth_identity", None)):
                # A boundary-provided liveness check is itself an observation
                # of the selected process identity. False is positive absence;
                # uncertainty must be raised by the boundary, not collapsed.
                return None
            if boundary.process_birth_identity(pid) is None:
                return None
        except Exception as exc:
            raise BootstrapError("Runtime interruption refused: owner absence could not be established.") from exc
        raise BootstrapError("Runtime interruption refused: owner process identity changed.")
    return pid, birth, instance_id, endpoint


def restart(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig | None = None) -> BootstrapResult:
    """Stop under the shared lifecycle fence, then explicitly start again."""
    config = config or BootstrapConfig()
    _validate_support_paths(paths)
    _preflight_owner_interruption(paths)
    with _bootstrap_mutex(paths):
        _interrupt_owner_locked(paths, boundary)
        result = _bootstrap_locked(paths, boundary, config)
    return replace(result, status="restarted")


def _doctor_observation(paths: RuntimePaths, boundary: RuntimeBoundary | None = None) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Read-only support-state diagnostics.  This function creates no files."""
    catalog = discovery = None
    report: dict[str, Any] = {
        "healthy": True,
        "catalog_path": str(paths.catalog_path),
        "discovery_path": str(paths.discovery_path),
        "catalog_present": catalog is not None,
        "discovery_present": discovery is not None,
        "issues": [],
    }
    try:
        _validate_support_paths(paths)
        catalog = _read_support_json(paths.catalog_path)
        discovery = _read_support_json(paths.discovery_path)
    except BootstrapError as exc:
        catalog = discovery = None
        report["healthy"] = False
        report["issues"].append(str(exc))
    report["catalog_present"] = catalog is not None
    report["discovery_present"] = discovery is not None
    if catalog is None:
        report["healthy"] = False
        report["issues"].append("catalog_missing")
    else:
        try:
            realm = _selected_realm(catalog)
            report["realm_id"] = realm.get("realm_id") if realm else None
            if realm and not Path(str(realm.get("data_root", ""))).exists():
                report["healthy"] = False
                report["issues"].append("realm_root_missing")
        except BootstrapError as exc:
            report["healthy"] = False
            report["issues"].append(str(exc))
    try:
        report["process_control"] = process_control.read_setting(paths.runtime_support)
    except ConflictError as exc:
        report["healthy"] = False
        report["issues"].append(str(exc))
    # Probed live in this process, evaluated for the configured mode.
    report["process_signalling"] = runtime_platform.process_control_probe(mode=report.get("process_control"))
    if discovery is not None:
        # Process visibility is diagnostic only: clients can be in another PID
        # namespace. Lifecycle operations retain their stricter process fences.
        try:
            report["pid_alive"] = bool(_pid_alive(boundary, discovery.get("pid")))
        except (BootstrapError, OSError):
            report["pid_alive"] = None
        if report["pid_alive"] is not True:
            report["notes"] = ["pid_not_visible"]
        if boundary:
            try:
                metadata = boundary.endpoint_metadata(
                    endpoint=_validate_loopback_endpoint(str(discovery.get("endpoint", ""))),
                    credential_file=paths.runtime_support / "credentials" / "owner.token",
                )
            except Exception:
                metadata = {}
            if not metadata:
                report["healthy"] = False
                report["issues"].append(
                    "stale_discovery" if report["pid_alive"] is False else "runtime_unhealthy"
                )
            elif (not discovery.get("runtime_instance_id") or not report.get("realm_id")
                    or metadata.get("runtime_instance_id") != discovery["runtime_instance_id"]
                    or metadata.get("realm_id") != discovery.get("active_realm")
                    or metadata.get("realm_id") != report["realm_id"]):
                report["healthy"] = False
                report["issues"].append("discovery_identity")
            elif metadata.get("status") != "ok":
                report["healthy"] = False
                report["issues"].append("runtime_unhealthy")
        elif report["pid_alive"] is not True:
            report["healthy"] = False
            report["issues"].append("stale_discovery")
    return report, dict(discovery) if discovery is not None else None


def doctor(paths: RuntimePaths, boundary: RuntimeBoundary | None = None) -> dict[str, Any]:
    """Read-only support-state diagnostics. This function creates no files."""
    return _doctor_observation(paths, boundary)[0]
