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
from contextlib import ExitStack, contextmanager, nullcontext
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlsplit
import uuid

from .io import atomic_write_json, owner_only, read_json, remove_file
from runtime_protocol import platform as runtime_platform
from runtime_protocol import cancellation
from runtime_protocol import process_control
from runtime_protocol.errors import ConflictError
from .paths import RuntimePaths
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
    # These are collision signals only; no directory is scanned and no legacy
    # state is read.  Callers can provide the exact historical root explicitly.
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
        if os.path.lexists(str(root)) and (root.is_dir() or root.is_file() or root.is_symlink()):
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


def _canonical_recovery_realm_root(value: str | Path) -> Path:
    """Validate a journal-bound realm path while permitting its restore gap."""
    return _canonical_realm_root(value, allow_missing=True)


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


def _rollback_failed_bootstrap(paths: RuntimePaths, boundary: RuntimeBoundary, *, realm_root: Path, new_realm: bool, credential_before: bytes | None, catalog_before: bytes | None = None, source_before: bytes | None = None, source_profile: str = "astrid", candidate_pid: int | None = None) -> None:
    """Return neutral support state to its pre-launch shape after a failed handoff."""
    # Rollback is allowed to remove only metadata emitted by this candidate.
    # A concurrent/previous owner may still be serving even when its support
    # advertisement is being repaired; deleting that owner's discovery here
    # strands a healthy daemon and causes every following caller to start a
    # duplicate candidate.  Capture the candidate PID before ``stop`` clears
    # the boundary handle, then fence each support file by its owner marker.
    candidate = getattr(boundary, "_process", None)
    candidate_pid = candidate_pid if candidate_pid is not None else getattr(candidate, "pid", None)
    stop = getattr(boundary, "stop", None)
    if callable(stop):
        try:
            with cancellation.cleanup_scope():
                stop()
        except Exception as exc:
            # Removing any support/credential/catalog/realm state here would
            # strand the owner whose cleanup just failed. Keep its controller
            # and every original file, even on a partial-start failure.
            raise BootstrapCustodyUncertain("Runtime rollback cleanup remains uncertain; support state retained.", controller=boundary) from exc
    for path in (paths.discovery_path, paths.instance_lock_path):
        try:
            current = _read_support_json(path)
            if candidate_pid is not None and current is not None:
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
    try:
        if catalog_before is None:
            remove_file(catalog)
        else:
            catalog.write_bytes(catalog_before)
            owner_only(catalog)
    except OSError:
        pass
    source_manifest = paths.source_profiles_dir / f"{source_profile}.json"
    try:
        if source_before is None:
            remove_file(source_manifest)
        else:
            source_manifest.write_bytes(source_before)
            owner_only(source_manifest)
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


def _require_matching_owner_identity(
    *,
    instance_id: str,
    requested_identity: Mapping[str, Any],
    owner_health: Any,
) -> None:
    _validated_matching_owner_identity(
        owner_health, instance_id=instance_id, requested_identity=requested_identity,
    )


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
        raise BootstrapError(IDENTITY_REFUSAL_MESSAGE) from None
    if observed != requested:
        raise BootstrapError(IDENTITY_REFUSAL_MESSAGE)
    return observed


def _owner_health(boundary: RuntimeBoundary, *, endpoint: str, instance_id: str) -> Any:
    read_identity = getattr(boundary, "owner_startup_identity", None)
    if not callable(read_identity):
        return None
    return read_identity(endpoint=endpoint, instance_id=instance_id)


def _bootstrap_locked(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig) -> BootstrapResult:
    if config.profile != "astrid":
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    source = config.resolve_source_profile(paths)
    installer_operation_id = os.environ.get("ASTRID_INSTALLER_OPERATION_ID")
    if installer_operation_id is not None and re.fullmatch(r"[0-9a-f]{32}", installer_operation_id) is None:
        raise BootstrapError("ASTRID_INSTALLER_OPERATION_ID must be 32 lowercase hexadecimal characters.")
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
    new_realm = False
    diagnostics: list[str] = []

    discovery = _read_support_json(paths.discovery_path)
    if discovery is not None and discovery.get("active_realm"):
        _compatible(discovery, config, source)
        pid = discovery.get("pid")
        endpoint = str(discovery.get("endpoint", ""))
        instance_id = str(discovery.get("runtime_instance_id", ""))
        if _pid_alive(boundary, pid):
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
            owner_health = _owner_health(boundary, endpoint=endpoint, instance_id=instance_id)
            if owner_health is not None:
                _require_matching_owner_identity(
                    instance_id=instance_id,
                    requested_identity=requested_identity, owner_health=owner_health,
                )
            if not boundary.health(endpoint=endpoint, pid=int(pid), instance_id=instance_id):
                raise BootstrapError("The selected runtime owner is unhealthy; next action: " + RECONFIGURE_NEXT_ACTION)
            if owner_health is None:
                _require_matching_owner_identity(
                    instance_id=instance_id,
                    requested_identity=requested_identity, owner_health=None,
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
        # A dead advertisement is ephemeral support state.  Remove it before
        # starting so a crash cannot be mistaken for a live owner.
        remove_file(paths.discovery_path)

    # A daemon may have advertised successfully but crashed before its
    # ephemeral discovery write (or discovery may have been manually removed).
    # Never start a second owner while the durable instance lock still points
    # at a live process.
    marker = _read_support_json(paths.instance_lock_path)
    if marker and _pid_alive(boundary, marker.get("pid")):
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
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile)
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
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=candidate_pid)
        raise BootstrapError("Runtime start returned incomplete owner metadata.") from exc
    captured_operation_id = handle.get("installer_operation_id")
    if captured_operation_id != installer_operation_id:
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise BootstrapError("Runtime launch operation binding was not captured by the owner.")
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
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    try:
        healthy = bool(boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id))
    except Exception:
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    if not healthy:
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise BootstrapError("Runtime started but failed health check; next action: " + RECONFIGURE_NEXT_ACTION)
    owner_health = _owner_health(boundary, endpoint=endpoint, instance_id=instance_id)
    try:
        owner_identity = _validated_matching_owner_identity(
            owner_health, instance_id=instance_id, requested_identity=requested_identity,
        )
    except BootstrapError:
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
        raise
    worker = _worker_handoff(handle)
    # The marker contains ownership metadata only and never a credential.
    try:
        atomic_write_json(paths.instance_lock_path, {"pid": pid, "process_birth_id": process_birth_id, "runtime_instance_id": instance_id, "realm_id": realm_id, "realm_root": str(realm_root), **({"installer_operation_id": captured_operation_id} if captured_operation_id is not None else {})})
        actor_id, token = _credential(paths)
        connection = boundary.connect(endpoint=endpoint, credential=token)
        _provision_connection(connection, actor_id, token, realm_id)
    except Exception:
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
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
        **({"installer_operation_id": captured_operation_id} if captured_operation_id is not None else {}),
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
        _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
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
            _rollback_failed_bootstrap(paths, boundary, realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
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
    owner_health = _owner_health(boundary, endpoint=endpoint, instance_id=instance_id)
    if owner_health is not None:
        _require_matching_owner_identity(
            instance_id=instance_id,
            requested_identity=requested_identity, owner_health=owner_health,
        )
    if not boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id):
        raise BootstrapError("The selected runtime is unhealthy; run astrid-runtime restart --profile astrid.")
    if owner_health is None:
        _require_matching_owner_identity(
            instance_id=instance_id,
            requested_identity=requested_identity, owner_health=None,
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


def _fenced_stop_and_manager(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, realm_id: str, realm_root: Path,
    discovery: Mapping[str, Any] | None, marker: Mapping[str, Any] | None,
    owner: tuple[int, str, str, str] | None, stop_manager=None,
    validate_stop=None, stop_foreground=None, record_stop_authority=None,
    remember_stop=None, missing_recovery_realm: bool = False,
) -> dict[str, Any]:
    """Stop an admitted owner and its manager while the caller holds the mutex.

    Receipt/recovery callbacks only adapt existing installer admission; the
    fence, owner handoff, replacement checks and cleanup are shared with down.
    """
    stop_completed = False
    try:
        lifecycle_fence = (
            nullcontext({"safe": None, "recovery_restore_in_progress": True})
            if missing_recovery_realm else interruption_fence(realm_root)
        )
        with lifecycle_fence as final_report:
            try:
                final_discovery = _read_support_json(paths.discovery_path)
                final_marker = _read_support_json(paths.instance_lock_path)
            except Exception:
                _discard_installer_stop_receipt(boundary)
                raise
            if final_discovery != discovery:
                _discard_installer_stop_receipt(boundary)
                raise BootstrapError("Runtime discovery changed before stop; refusing interruption.")
            if final_marker != marker:
                _discard_installer_stop_receipt(boundary)
                raise BootstrapError("Runtime owner lock changed before stop; refusing interruption.")
            if validate_stop is not None:
                validate_stop()
            stopped = None
            if owner is not None:
                pid, birth, instance_id, endpoint = owner
                stop_owner = getattr(boundary, "stop_owner", None)
                if not callable(stop_owner):
                    raise BootstrapError("Runtime boundary lacks the birth-checked stop handoff.")
                if record_stop_authority is not None:
                    record_stop_authority({
                        "support_root": str(paths.runtime_support.resolve()),
                        "realm_id": realm_id,
                        "realm_root": str(realm_root),
                        "pid": int(pid), "process_birth_id": str(birth),
                        "runtime_instance_id": str(instance_id),
                        "endpoint": str(endpoint),
                    })
                # First destructive operation: Runtime's existing validated stop.
                stopped = stop_owner(
                    endpoint=endpoint, pid=pid, instance_id=instance_id,
                    process_birth_id=birth, realm_id=realm_id,
                    owner_lock=paths.instance_lock_path,
                    discovery_path=paths.discovery_path, require_health=False,
                )
            elif stop_foreground is not None:
                stopped = stop_foreground()
            # The stopped owner can remove its own advertisements. A new
            # identity must never be covered by the old owner's authority,
            # even if it appears before the manager callback rather than
            # after it. Preserve the replacement and forbid rollback.
            for path, expected in ((paths.discovery_path, discovery),
                                   (paths.instance_lock_path, marker)):
                try:
                    observed = _read_support_json(path)
                except Exception:
                    _discard_installer_stop_receipt(boundary)
                    raise
                if observed is not None and observed != expected:
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError(
                        "Runtime owner changed before manager stop; refusing interruption.",
                        details={"stop_authority_lost": True},
                    )
            stop_completed = True
            if remember_stop is not None:
                remember_stop()
            if stop_manager is not None:
                stop_manager()
    except ConflictError as exc:
        error = _raise_conflict(exc)
        if stop_completed:
            details = dict(error.details or {})
            details["stop_completed"] = True
            error = BootstrapError(str(error), details=details)
        raise error from exc
    except BootstrapError as exc:
        if stop_completed:
            details = dict(exc.details or {})
            details["stop_completed"] = True
            raise BootstrapError(str(exc), details=details) from exc
        raise
    except Exception as exc:
        inherited = getattr(exc, "details", None)
        details = dict(inherited) if isinstance(inherited, Mapping) else {}
        if stop_completed:
            details["stop_completed"] = True
        raise BootstrapError(str(exc), details=details or None) from exc

    # Cleanup is after the manager has synchronously stopped and after the
    # SQLite fence released. Preserve any replacement identity.
    try:
        current_discovery = _read_support_json(paths.discovery_path)
        current_marker = _read_support_json(paths.instance_lock_path)
    except Exception:
        _discard_installer_stop_receipt(boundary)
        raise
    if owner is not None:
        pid, birth, instance_id, _endpoint = owner
        if current_discovery is not None and not _owner_record_matches(
            current_discovery, pid=pid, instance_id=instance_id,
            process_birth_id=birth, realm_id=realm_id, realm_root=realm_root,
        ):
            _discard_installer_stop_receipt(boundary)
            raise BootstrapError("Runtime owner changed during stop; refusing discovery cleanup.")
        if current_marker is not None and not _owner_record_matches(
            current_marker, pid=pid, instance_id=instance_id,
            process_birth_id=birth, realm_id=realm_id, realm_root=realm_root,
        ):
            _discard_installer_stop_receipt(boundary)
            raise BootstrapError("Runtime owner changed during stop; refusing owner-lock cleanup.")
    else:
        # For absent/stale publications, never unlink a record that was
        # replaced while the manager callback ran. Equality is used here
        # because no live-owner stop authority was established.
        if current_discovery is not None and current_discovery != discovery:
            _discard_installer_stop_receipt(boundary)
            raise BootstrapError("Runtime discovery changed during stop; refusing cleanup.")
        if current_marker is not None and current_marker != marker:
            _discard_installer_stop_receipt(boundary)
            raise BootstrapError("Runtime owner lock changed during stop; refusing cleanup.")
    if current_discovery is not None:
        remove_file(paths.discovery_path)
    if current_marker is not None:
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
    if owner != "haus.astrid.runtime":
        raise BootstrapError("Restore install selection has an unsupported owner.")
    program_root = _canonical_metadata_path(Path(raw_program_root), label="program root")
    data_root = _canonical_metadata_path(Path(raw_data_root), label="data root")
    realm_root = _canonical_realm_root(
        _canonical_metadata_path(Path(raw_realm_root), label="realm root"))
    journal_data = _canonical_metadata_path(Path(str(journal.get("data_root") or "")), label="journal data root")
    journal_realm = journal.get("realm")
    if not isinstance(journal_realm, Mapping):
        raise BootstrapError("Restore journal does not identify its selected realm.")
    journal_realm_root = _canonical_metadata_path(
        Path(str(journal_realm.get("realm_root") or "")), label="journal realm root")
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
        Path(str(retained_realm.get("data_root") or "")), label="retained realm root")) if retained_realm else None
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
            Path(str(live_realm.get("data_root") or "")), label="current realm root")) if live_realm else None
        if (live_realm is None
                or not isinstance(parsed_live.get("selected_realm_id"), str)
                or not isinstance(live_realm.get("realm_id"), str)
                or str(parsed_live.get("selected_realm_id") or "") != realm_id
                or str(live_realm.get("realm_id") or "") != realm_id
                or live_root != realm_root):
            raise BootstrapError("Current Runtime catalog conflicts with the retained restore selection.")

    return {
        "journal_path": journal_path, "selection_path": selection_path,
        "journal_bytes": journal_bytes, "selection_bytes": selection_bytes,
        "backup_catalog_path": backup_catalog_path,
        "backup_catalog_bytes": backup_catalog_bytes,
        "catalog": retained, "live_catalog_bytes": live_catalog_bytes,
        "realm_id": realm_id, "realm_root": realm_root, "data_root": data_root,
    }


def _validate_restore_snapshot(paths: RuntimePaths, selection: RestoreSelection,
                               snapshot: Mapping[str, Any]) -> None:
    current = _restore_selection_snapshot(paths, selection)
    for key in ("journal_bytes", "selection_bytes", "backup_catalog_bytes", "live_catalog_bytes",
                "realm_id", "realm_root"):
        if current.get(key) != snapshot.get(key):
            raise BootstrapError("Restore metadata changed during Runtime interruption; refusing recovery.")
    _inspect_restore_realm(current)


def _selected_restore_snapshot(paths: RuntimePaths, selection: RestoreSelection) -> dict[str, Any]:
    snapshot = _restore_selection_snapshot(paths, selection)
    if Path(snapshot["data_root"]) != paths.app_support:
        raise BootstrapError("Restore selection does not belong to this Runtime data root.")
    _inspect_restore_realm(snapshot)
    return snapshot


def _require_restore_publications_absent(paths: RuntimePaths) -> None:
    if (_read_support_json(paths.discovery_path) is not None
            or _read_support_json(paths.instance_lock_path) is not None):
        raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")


def _inspect_restore_realm(snapshot: Mapping[str, Any]) -> None:
    from runtime_protocol.upgrade import inspect_canonical_schema

    try:
        inspect_canonical_schema(
            Path(snapshot["realm_root"]), expected_realm_id=str(snapshot["realm_id"]),
        )
    except Exception as exc:
        raise BootstrapError("Restore selection does not match the readable Runtime realm identity.") from exc


def _interrupt_owner_locked(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Identity-stop the owner while the caller holds the launcher mutex."""
    _validate_support_paths(paths)
    if restore_selection is not None:
        snapshot = _selected_restore_snapshot(paths, restore_selection)
        _require_restore_publications_absent(paths)

        def validate_restore() -> None:
            _validate_restore_snapshot(paths, restore_selection, snapshot)
            _require_restore_publications_absent(paths)

        # The pending selection identifies a readable realm, but gives no
        # authority to bypass the ordinary final lifecycle fence.
        result = _fenced_stop_and_manager(
            paths, boundary, realm_id=str(snapshot["realm_id"]),
            realm_root=Path(snapshot["realm_root"]), discovery=None, marker=None,
            owner=None, stop_manager=stop_manager, validate_stop=validate_restore,
        )
        # The same launcher mutex still serializes publication. Revalidate
        # every source and the no-owner state before atomically repairing K2's
        # catalog with Runtime's existing writer.
        validate_restore()
        if snapshot["live_catalog_bytes"] is None:
            atomic_write_json(paths.catalog_path, snapshot["catalog"])
        return {"status": "stopped", "realm_id": snapshot["realm_id"],
                "idle": result["interruption"],
                "catalog_restored": snapshot["live_catalog_bytes"] is None}

    discovery = _read_support_json(paths.discovery_path)
    if not discovery:
        raise BootstrapError("No runtime owner is available to interrupt.")
    realm_id = str(discovery.get("active_realm") or "")
    selected = _selected_realm(_read_catalog(paths))
    if selected is None or not realm_id or str(selected.get("realm_id")) != realm_id:
        raise BootstrapError("Runtime interruption refused: discovery does not match the selected workspace.")
    realm_root = _canonical_realm_root(str(selected["data_root"]))
    discovery_root = _canonical_realm_root(str(discovery.get("realm_root") or ""))
    if discovery_root != realm_root:
        raise BootstrapError("Runtime interruption refused: discovery realm root does not match the selected workspace.")
    marker = _read_support_json(paths.instance_lock_path)
    if marker is None or str(marker.get("realm_id") or "") != realm_id:
        raise BootstrapError("Runtime interruption refused: owner lock does not match discovery.")
    owner = _recorded_owner_identity(discovery, realm_id=realm_id, realm_root=realm_root)
    pid, birth, instance_id, _endpoint = owner
    # Test boundaries without kernel identity can model the hand-off.
    modeled_boundary = getattr(boundary, "process_birth_identity", None) is None
    if not _pid_alive(boundary, pid) and not modeled_boundary:
        raise BootstrapError("Runtime interruption refused: owner is stale or discovery identity is incomplete.")
    if not _owner_record_matches(
        marker, pid=pid, instance_id=instance_id, process_birth_id=birth,
        realm_id=realm_id, realm_root=realm_root,
    ):
        raise BootstrapError("Runtime interruption refused: owner lock does not match discovery.")
    _validate_stop_endpoint(paths, boundary, owner=owner, realm_id=realm_id, realm_root=realm_root)
    result = _fenced_stop_and_manager(
        paths, boundary, realm_id=realm_id, realm_root=realm_root,
        discovery=discovery, marker=marker, owner=owner, stop_manager=stop_manager,
    )
    return {"status": "stopped", "realm_id": realm_id, "idle": result["interruption"]}


def _interrupt_owner(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Serialize owner validation, fencing, signal, and cleanup."""
    _preflight_owner_interruption(paths, restore_selection=restore_selection)
    with _bootstrap_mutex(paths):
        return _interrupt_owner_locked(paths, boundary, stop_manager=stop_manager,
                                       restore_selection=restore_selection)


def _preflight_owner_interruption(
    paths: RuntimePaths, *, restore_selection: RestoreSelection | None = None,
) -> None:
    """Refuse known busy state before acquiring/creating launcher sidecars."""
    _validate_support_paths(paths)
    if restore_selection is not None:
        snapshot = _selected_restore_snapshot(paths, restore_selection)
        _require_restore_publications_absent(paths)
        report = inspect_interruption_state(Path(snapshot["realm_root"]))
        if not report.get("safe", False):
            refusal = BootstrapError(
                "Runtime interruption refused while work is active or unreconciled.",
                details=report,
            )
            message, details = refusal_from(refusal)
            raise BootstrapError(message, details=details)
        return
    if _read_support_json(paths.discovery_path) is None:
        raise BootstrapError("No runtime owner is available to interrupt.")
    preflight_stop(paths)


def down(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Stop the selected owner only when all durable work is reconciled."""
    if stop_manager is not None and not callable(stop_manager):
        raise TypeError("stop_manager must be a zero-argument callback")
    if restore_selection is not None and not isinstance(restore_selection, RestoreSelection):
        raise TypeError("restore_selection must be a RestoreSelection")
    return _interrupt_owner(paths, boundary, stop_manager=stop_manager,
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
        _require_restore_publications_absent(paths)
        realm_root = Path(snapshot["realm_root"])
    else:
        _realm, realm_root = _selected_stop_realm(paths)
    try:
        report = inspect_interruption_state(realm_root)
        if not report.get("safe", False):
            refusal = BootstrapError(
                "Runtime interruption refused while work is active or unreconciled.",
                details=report,
            )
            message, details = refusal_from(refusal)
            raise BootstrapError(message, details=details)
        return report
    except BootstrapError:
        raise
    except ConflictError as exc:
        raise _raise_conflict(exc) from exc
    except Exception as exc:
        # An unreadable or malformed realm is never evidence that it is idle.
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
        raise BootstrapError("Runtime interruption refused: discovery does not match the selected workspace.")
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
    paths: RuntimePaths, boundary: RuntimeBoundary, realm: Mapping[str, Any], realm_root: Path,
    discovery: Mapping[str, Any], marker: Mapping[str, Any] | None,
    *, recovery_operation_id: str | None = None,
    recovery_launch_identity: Mapping[str, Any] | None = None,
    require_live: bool = False,
) -> tuple[int, str, str, str] | None:
    realm_id = str(realm.get("realm_id") or "")
    pid, birth, instance_id, endpoint = _recorded_owner_identity(
        discovery, realm_id=realm_id, realm_root=realm_root,
    )
    if marker is not None and not _owner_record_matches(
        marker, pid=pid, instance_id=instance_id, process_birth_id=birth,
        realm_id=realm_id, realm_root=realm_root,
    ):
        raise BootstrapError("Runtime interruption refused: owner lock changed or does not match discovery.")
    alive = _pid_alive(boundary, pid)
    if not alive and callable(getattr(boundary, "process_birth_identity", None)):
        # A missing process incarnation is positive absence only when the OS
        # identity lookup itself completed and returned no identity.
        try:
            absent = boundary.process_birth_identity(pid) is None
        except Exception as exc:
            raise BootstrapError("Runtime interruption refused: owner absence could not be established.") from exc
        if absent:
            if require_live:
                raise BootstrapError("Runtime recovery refused: transaction-bound replacement is absent.")
            return None
        raise BootstrapError("Runtime interruption refused: owner process identity changed.")
    if not alive and getattr(boundary, "process_birth_identity", None) is None:
        raise BootstrapError("Runtime interruption refused: modeled owner is not live.")
    identity = _validate_stop_endpoint(
        paths, boundary, owner=(pid, birth, instance_id, endpoint),
        realm_id=realm_id, realm_root=realm_root,
    )
    if recovery_operation_id is not None:
        if (discovery.get("installer_operation_id") != recovery_operation_id
                or marker is None or marker.get("installer_operation_id") != recovery_operation_id
                or identity.get("installer_operation_id") != recovery_operation_id):
            raise BootstrapError("Runtime recovery refused: owner launch binding does not match the pending operation.")
        if recovery_launch_identity is None:
            raise BootstrapError("Runtime recovery refused: authorized launch identity is unavailable.")
        try:
            requested_identity = normalize_startup_identity(recovery_launch_identity)
            _validated_matching_owner_identity(
                identity, instance_id=instance_id, requested_identity=requested_identity,
            )
        except (BootstrapError, StartupIdentityError, TypeError, ValueError) as exc:
            raise BootstrapError("Runtime recovery refused: owner is outside the authorized launch identity.") from exc
    return pid, birth, instance_id, endpoint


def _recorded_foreground_matches_receipt(
    recorded: Mapping[str, Any], receipt: Any, *, paths: RuntimePaths,
    realm: Mapping[str, Any], realm_root: Path, boundary: RuntimeBoundary,
) -> bool:
    """Recognize only the exact foreground incarnation stopped by this controller.

    Older service records contain only PID and birth id. Those fields are
    sufficient to compare with a private receipt already bound to this support
    root and selected realm; they are never sufficient to create a receipt or
    authorize a signal on their own.
    """
    if not isinstance(receipt, Mapping):
        return False
    try:
        pid = int(recorded["pid"])
        birth = str(recorded["birth_id"])
        normalized_receipt = _canonical_stop_evidence(receipt, paths=paths)
        receipt_pid = normalized_receipt["pid"]
        receipt_birth = normalized_receipt["process_birth_id"]
        if recorded.get("realm_id") not in (None, "", str(realm["realm_id"])):
            return False
        recorded_root = recorded.get("realm_root")
        if recorded_root not in (None, "") and _canonical_realm_root(str(recorded_root)) != realm_root:
            return False
    except (KeyError, TypeError, ValueError, BootstrapError):
        return False
    if (pid <= 0 or not birth or pid != receipt_pid or birth != receipt_birth
            or normalized_receipt["realm_id"] != str(realm["realm_id"])
            or normalized_receipt["realm_root"] != realm_root):
        return False
    try:
        absent = boundary.process_birth_identity(pid) is None
    except Exception as exc:
        _discard_installer_stop_receipt(boundary)
        raise BootstrapError("Runtime interruption refused: prior foreground absence could not be established.") from exc
    if not absent:
        _discard_installer_stop_receipt(boundary)
    return absent


def _canonical_stop_evidence(value: Mapping[str, Any], *, paths: RuntimePaths) -> dict[str, Any]:
    """Normalize persisted and in-memory stop identities before exact comparison."""
    if not isinstance(value, Mapping):
        raise BootstrapError("Runtime stop authority is malformed.")
    try:
        raw_pid = value["pid"]
        if isinstance(raw_pid, bool) or not isinstance(raw_pid, int):
            raise ValueError("PID must be an integer")
        pid = raw_pid
        birth = value["process_birth_id"]
        support = value["support_root"]
        realm_id = value["realm_id"]
        realm_root = value["realm_root"]
        instance = value.get("runtime_instance_id")
        endpoint = value.get("endpoint")
        if (pid <= 0 or not isinstance(birth, str) or not birth
                or not isinstance(realm_id, str) or not realm_id
                or not isinstance(support, (str, Path))
                or not isinstance(realm_root, (str, Path))):
            raise ValueError("incomplete stop identity")
        support_path = Path(support).expanduser()
        if (not support_path.is_absolute() or _has_symlink_component(support_path)
                or Path(os.path.abspath(support_path)) != support_path):
            raise ValueError("noncanonical support path")
        support_path = support_path.resolve()
        realm_path = _canonical_recovery_realm_root(realm_root)
        if instance is not None and (not isinstance(instance, str) or not instance):
            raise ValueError("invalid runtime instance")
        if endpoint is not None:
            if not isinstance(endpoint, str) or not endpoint:
                raise ValueError("invalid endpoint")
            endpoint = _validate_loopback_endpoint(endpoint)
    except (KeyError, TypeError, ValueError, OSError, RuntimeError, BootstrapError) as exc:
        raise BootstrapError("Runtime stop authority is malformed or noncanonical.") from exc
    if support_path != paths.runtime_support.resolve():
        raise BootstrapError("Runtime stop authority belongs to another support root.")
    return {"pid": pid, "process_birth_id": birth, "support_root": support_path,
            "realm_id": realm_id, "realm_root": realm_path,
            "runtime_instance_id": instance, "endpoint": endpoint}


def _preflight_recovery_refusal(paths: RuntimePaths) -> None:
    """Preserve the existing busy blocker when a recovery journal lacks authority."""
    _validate_support_paths(paths)
    catalog = _read_catalog(paths)
    if _selected_realm(catalog) is not None:
        preflight_stop(paths)


def _publication_matches_receipt(value: Mapping[str, Any], receipt: Mapping[str, Any], *, paths: RuntimePaths, realm: Mapping[str, Any], realm_root: Path) -> bool:
    """Return whether an advertisement is the exact incarnation in a receipt."""
    try:
        raw_pid = value["pid"]
        if isinstance(raw_pid, bool) or not isinstance(raw_pid, int):
            return False
        pid = raw_pid
        birth = value.get("process_birth_id")
        instance = value.get("runtime_instance_id")
        observed_realm = str(value.get("active_realm") or value.get("realm_id") or "")
        observed_root = _canonical_realm_root(str(value.get("realm_root") or ""))
        normalized = _canonical_stop_evidence(receipt, paths=paths)
    except (KeyError, TypeError, ValueError, BootstrapError):
        return False
    return (
        pid == normalized["pid"]
        and birth == normalized["process_birth_id"]
        and (not instance or (normalized["runtime_instance_id"] is not None
                              and instance == normalized["runtime_instance_id"]))
        and (not value.get("endpoint") or (
            normalized["endpoint"] is not None
            and value.get("endpoint") == normalized["endpoint"]
        ))
        and observed_realm == str(realm.get("realm_id"))
        and observed_root == realm_root
        and normalized["realm_id"] == str(realm.get("realm_id"))
        and normalized["realm_root"] == realm_root
    )


def _discard_installer_stop_receipt(boundary: RuntimeBoundary) -> None:
    """Revoke receipt authority while retaining identity for foreground reconciliation."""
    try:
        if isinstance(getattr(boundary, "_installer_stop_receipt", None), Mapping):
            boundary._installer_stop_receipt_invalidated = True
    except AttributeError:
        pass


def _invalidate_stale_stop_receipt(paths: RuntimePaths, boundary: RuntimeBoundary) -> None:
    """Forget prior stop evidence as soon as a nonmatching publication is observed."""
    receipt = getattr(boundary, "_installer_stop_receipt", None)
    if not isinstance(receipt, Mapping):
        return
    try:
        _validate_support_paths(paths)
        realm, realm_root = _selected_stop_realm(paths)
        normalized = _canonical_stop_evidence(receipt, paths=paths)
        publications = (
            _read_support_json(paths.discovery_path),
            _read_support_json(paths.instance_lock_path),
        )
        if (normalized["realm_id"] != str(realm.get("realm_id"))
                or normalized["realm_root"] != realm_root):
            _discard_installer_stop_receipt(boundary)
            return
        absent = boundary.process_birth_identity(normalized["pid"]) is None
        if not absent or any(
            publication is not None and not _publication_matches_receipt(
                        publication, receipt, paths=paths, realm=realm, realm_root=realm_root,
            )
            for publication in publications
        ):
            _discard_installer_stop_receipt(boundary)
    except Exception:
        # Any uncertain support/context/publication observation irrevocably
        # revokes authority, even if that publication later disappears. The
        # caller still performs its normal validation to report the refusal.
        _discard_installer_stop_receipt(boundary)


@contextmanager
def _stop_receipt_validation(boundary: RuntimeBoundary):
    """Revoke retained authority if stop admission cannot validate its context."""
    try:
        yield
    except Exception:
        _discard_installer_stop_receipt(boundary)
        raise


def _remember_completed_stop(
    boundary: RuntimeBoundary, *, paths: RuntimePaths, realm: Mapping[str, Any],
    realm_root: Path, evidence: Mapping[str, Any] | None,
) -> None:
    if evidence is None:
        return
    try:
        pid = int(evidence["pid"])
        birth = str(evidence.get("process_birth_id") or evidence.get("birth_id") or "")
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("Runtime interruption refused: stopped owner identity is incomplete.") from exc
    if pid <= 0 or not birth:
        raise BootstrapError("Runtime interruption refused: stopped owner identity is incomplete.")
    boundary._installer_stop_receipt = {
        "support_root": paths.runtime_support.resolve(),
        "realm_id": str(realm["realm_id"]), "realm_root": realm_root,
        "pid": pid, "process_birth_id": birth,
        "runtime_instance_id": evidence.get("runtime_instance_id"),
        **({"endpoint": evidence["endpoint"]} if evidence.get("endpoint") else {}),
    }
    try:
        delattr(boundary, "_installer_stop_receipt_invalidated")
    except AttributeError:
        pass


def installer_stop(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    *,
    stop_manager,
    recorded_foreground: Mapping[str, Any] | None = None,
    recovery_owner: Mapping[str, Any] | None = None,
    recovery_realm: Mapping[str, Any] | None = None,
    recovery_operation_id: str | None = None,
    recovery_launch_identity: Mapping[str, Any] | None = None,
    allow_restore_in_progress: bool = False,
    record_stop_authority=None,
) -> dict[str, Any]:
    """Stop the selected Runtime owner and then its manager under one fence.

    The manager callback is deliberately zero-argument and runs while both
    launcher serialization and the realm's SQLite interruption fence remain
    held. It must only synchronously stop/disable the external manager.
    """
    if not callable(stop_manager):
        raise TypeError("stop_manager must be a zero-argument callback")
    if record_stop_authority is not None and not callable(record_stop_authority):
        raise TypeError("record_stop_authority must be callable")
    recovery_mode = recovery_owner is not None or recovery_realm is not None or allow_restore_in_progress
    if recovery_mode and (not isinstance(recovery_owner, Mapping)
                          or not isinstance(recovery_realm, Mapping)):
        _preflight_recovery_refusal(paths)
        raise BootstrapError("Runtime recovery stop requires the journal-bound owner and realm identity.")
    if recovery_operation_id is not None and (
        not isinstance(recovery_operation_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", recovery_operation_id) is None
    ):
        if recovery_mode:
            _preflight_recovery_refusal(paths)
        raise BootstrapError("Runtime recovery operation binding is malformed.")
    if recovery_launch_identity is not None:
        if not isinstance(recovery_launch_identity, Mapping):
            raise BootstrapError("Runtime recovery launch identity is malformed.")
        try:
            recovery_launch_identity = normalize_startup_identity(recovery_launch_identity)
        except (StartupIdentityError, TypeError, ValueError) as exc:
            raise BootstrapError("Runtime recovery launch identity is malformed.") from exc
    if recovery_mode:
        try:
            recovery_owner = _canonical_stop_evidence(recovery_owner, paths=paths)
            matches_realm = (
                str(recovery_realm.get("realm_id") or "") == recovery_owner["realm_id"]
                and _canonical_recovery_realm_root(str(recovery_realm.get("realm_root") or ""))
                == recovery_owner["realm_root"]
            )
        except BootstrapError:
            _preflight_recovery_refusal(paths)
            raise
        if not matches_realm:
            _preflight_recovery_refusal(paths)
            raise BootstrapError("Runtime recovery owner authority does not match the journal realm.")
    with ExitStack() as locks:
        # Guard admission separately from the actual stop/manager callback:
        # a failed callback must retain a genuinely completed-stop receipt.
        with _stop_receipt_validation(boundary):
            _validate_support_paths(paths)
            # Forget stale same-controller evidence before any preflight refusal can
            # return. This is in-memory only; no support or workspace files are changed.
            _invalidate_stale_stop_receipt(paths, boundary)
            # Avoid creating/acquiring the launcher mutex for a known busy realm. The
            # final SQLite fence below repeats this observation under serialization.
            missing_recovery_realm = False
            if recovery_mode:
                try:
                    recovery_realm_id = str(recovery_realm.get("realm_id") or "")
                    recovery_root = _canonical_recovery_realm_root(str(recovery_realm.get("realm_root") or ""))
                    if not recovery_realm_id:
                        raise BootstrapError("Runtime recovery realm identity is incomplete.")
                    catalog = _read_catalog(paths)
                    catalog_realm = _selected_realm(catalog)
                    if catalog_realm is None:
                        if catalog.get("realms"):
                            raise BootstrapError("Runtime recovery catalog has an unselected realm.")
                        if not allow_restore_in_progress:
                            raise BootstrapError("Runtime recovery has no selected realm.")
                        realm = {"realm_id": recovery_realm_id, "data_root": str(recovery_root)}
                        realm_root = recovery_root
                        if realm_root.exists():
                            from runtime_protocol.upgrade import inspect_canonical_schema
                            inspect_canonical_schema(realm_root, expected_realm_id=recovery_realm_id)
                            missing_recovery_realm = False
                        else:
                            missing_recovery_realm = True
                    else:
                        realm, realm_root = catalog_realm, _canonical_recovery_realm_root(str(catalog_realm.get("data_root") or ""))
                        if (str(realm.get("realm_id") or "") != recovery_realm_id
                                or realm_root != recovery_root):
                            raise BootstrapError("Runtime recovery journal does not match the selected realm.")
                        missing_recovery_realm = not realm_root.exists()
                    if missing_recovery_realm and not allow_restore_in_progress:
                        raise BootstrapError("Runtime recovery realm is absent outside a restore transaction.")
                    expected_support = paths.runtime_support.resolve()
                    if (str(recovery_owner.get("support_root") or "") != str(expected_support)
                            or str(recovery_owner.get("realm_id") or "") != recovery_realm_id
                            or _canonical_recovery_realm_root(str(recovery_owner.get("realm_root") or "")) != recovery_root):
                        raise BootstrapError("Runtime recovery owner authority does not match the journal realm.")
                    if missing_recovery_realm:
                        if realm_root.exists() or realm_root.is_symlink():
                            raise BootstrapError("Runtime recovery realm root is unavailable or unsafe.")
                    elif catalog_realm is not None:
                        preflight_stop(paths)
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError(f"Runtime recovery identity validation failed: {exc}") from exc
            else:
                preflight_stop(paths)
            locks.enter_context(_bootstrap_mutex(paths))
            _validate_support_paths(paths)
            if not recovery_mode:
                realm, realm_root = _selected_stop_realm(paths)
            else:
                # The journal is only context. Re-read the selected realm after
                # launcher serialization so a catalog replacement cannot be
                # hidden by the pre-lock observation.
                try:
                    locked_catalog = _read_catalog(paths)
                    locked_realm = _selected_realm(locked_catalog)
                    if locked_realm is None:
                        if locked_catalog.get("realms") or not allow_restore_in_progress:
                            raise BootstrapError("Runtime recovery catalog changed before stop admission.")
                        locked_root = _canonical_recovery_realm_root(str(recovery_realm["realm_root"]))
                    else:
                        locked_root = _canonical_recovery_realm_root(str(locked_realm.get("data_root") or ""))
                        if (str(locked_realm.get("realm_id") or "") != str(recovery_realm["realm_id"])
                                or locked_root != _canonical_recovery_realm_root(str(recovery_realm["realm_root"]))):
                            raise BootstrapError("Runtime recovery catalog changed before stop admission.")
                    if locked_root.exists():
                        from runtime_protocol.upgrade import inspect_canonical_schema
                        inspect_canonical_schema(locked_root, expected_realm_id=str(recovery_realm["realm_id"]))
                    if locked_root.exists() == missing_recovery_realm:
                        raise BootstrapError("Runtime recovery realm changed before stop admission.")
                    realm_root = locked_root
                    if locked_realm is not None:
                        realm = locked_realm
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError("Runtime recovery realm could not be revalidated under launcher lock.") from exc
            discovery = _read_support_json(paths.discovery_path)
            marker = _read_support_json(paths.instance_lock_path)
            exact_retained = False
            if recovery_mode:
                exact_retained = bool(recovery_owner.get("runtime_instance_id")) and all(
                    published is None or _publication_matches_receipt(
                        published, recovery_owner, paths=paths, realm=realm, realm_root=realm_root,
                    ) for published in (discovery, marker)
                )
                has_publication = discovery is not None or marker is not None
                if has_publication and not exact_retained:
                    bound_replacement = bool(
                        recovery_operation_id
                        and recovery_launch_identity is not None
                        and recovery_owner.get("runtime_instance_id")
                        and isinstance(discovery, Mapping) and isinstance(marker, Mapping)
                        and discovery.get("installer_operation_id") == recovery_operation_id
                        and marker.get("installer_operation_id") == recovery_operation_id
                        and str(discovery.get("runtime_instance_id") or "")
                        and str(discovery.get("runtime_instance_id")) != str(recovery_owner.get("runtime_instance_id") or "")
                    )
                    if not bound_replacement:
                        raise BootstrapError(
                            "Runtime recovery refused: a replacement owner publication is present."
                        )
            receipt = getattr(boundary, "_installer_stop_receipt", None)
            retired_foreground_evidence = None
            if isinstance(receipt, Mapping) and any(
                published is not None and not _publication_matches_receipt(
                    published, receipt, paths=paths, realm=realm, realm_root=realm_root,
                )
                for published in (discovery, marker)
            ):
                # Keep the local copy only long enough to reconcile the old
                # foreground record while validating/stopping this newly
                # published owner. If that handoff does not complete, a later
                # missing-publication retry cannot fall back to the older receipt.
                _discard_installer_stop_receipt(boundary)
            if recorded_foreground is not None and _recorded_foreground_matches_receipt(
                recorded_foreground, receipt, paths=paths, realm=realm,
                realm_root=realm_root, boundary=boundary,
            ):
                # A completed stop can leave old foreground metadata in the
                # service record. Retire that evidence only after re-observing
                # absence of the exact incarnation. Any current publication is
                # then validated independently below.
                retired_foreground_evidence = _canonical_stop_evidence(receipt, paths=paths)
                recorded_foreground = None
            owner = None
            if discovery is not None:
                try:
                    exact_publication = recovery_mode and _publication_matches_receipt(
                        discovery, recovery_owner, paths=paths, realm=realm, realm_root=realm_root,
                    )
                    owner = _validate_published_stop_owner(
                        paths, boundary, realm, realm_root, discovery, marker,
                        recovery_operation_id=(recovery_operation_id if recovery_mode and not exact_publication else None),
                        recovery_launch_identity=(recovery_launch_identity if recovery_mode and not exact_publication else None),
                        require_live=bool(recovery_mode and not exact_publication),
                    )
                except BootstrapError:
                    if isinstance(receipt, Mapping) and _publication_matches_receipt(
                        discovery, receipt, paths=paths, realm=realm, realm_root=realm_root,
                    ):
                        _discard_installer_stop_receipt(boundary)
                    raise
            elif marker is not None:
                # A lock without discovery is not kill authority. It can only be
                # treated as absent after proving the recorded incarnation is gone.
                try:
                    pid = int(marker["pid"])
                    birth = str(marker["process_birth_id"])
                    instance = str(marker["runtime_instance_id"])
                    marker_realm = str(marker["realm_id"])
                    marker_root = _canonical_realm_root(str(marker["realm_root"]))
                except (KeyError, TypeError, ValueError, BootstrapError) as exc:
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError("Runtime interruption refused: owner lock identity is incomplete.") from exc
                if (pid <= 0 or not birth or not instance or marker_realm != str(realm.get("realm_id"))
                        or marker_root != realm_root):
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError("Runtime interruption refused: owner lock does not match the selected workspace.")
                recorded_match = False
                if recorded_foreground is not None:
                    try:
                        recorded_match = (
                            int(recorded_foreground.get("pid", -1)) == pid
                            and str(recorded_foreground.get("birth_id") or "") == birth
                            and str(recorded_foreground.get("realm_id") or realm.get("realm_id")) == marker_realm
                            and _canonical_realm_root(str(recorded_foreground.get("realm_root") or marker_root)) == marker_root
                        )
                    except (TypeError, ValueError, BootstrapError):
                        recorded_match = False
                if callable(getattr(boundary, "process_birth_identity", None)) and not recorded_match:
                    if _pid_alive(boundary, pid):
                        _discard_installer_stop_receipt(boundary)
                        raise BootstrapError("Runtime interruption refused: live lock owner has no matching discovery.")
                    try:
                        if boundary.process_birth_identity(pid) is not None:
                            _discard_installer_stop_receipt(boundary)
                            raise BootstrapError("Runtime interruption refused: live lock owner has no matching discovery.")
                    except BootstrapError:
                        raise
                    except Exception as exc:
                        _discard_installer_stop_receipt(boundary)
                        raise BootstrapError("Runtime interruption refused: owner absence could not be established.") from exc
                elif _pid_alive(boundary, pid) and not recorded_match:
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError("Runtime interruption refused: live lock owner has no matching discovery.")
            if recovery_mode and recorded_foreground is not None:
                try:
                    foreground_pid = int(recorded_foreground["pid"])
                    foreground_birth = str(recorded_foreground["birth_id"])
                    foreground_realm = str(recorded_foreground.get("realm_id") or realm["realm_id"])
                    foreground_root = _canonical_recovery_realm_root(
                        str(recorded_foreground.get("realm_root") or realm_root)
                    )
                    if foreground_realm != str(recovery_realm["realm_id"]) or foreground_root != realm_root:
                        raise BootstrapError("Runtime recovery refused: recorded foreground belongs to another realm.")
                    matches_admitted = bool(
                        owner is not None and foreground_pid == owner[0] and foreground_birth == owner[1]
                    )
                    matches_retained = (
                        foreground_pid == recovery_owner["pid"]
                        and foreground_birth == recovery_owner["process_birth_id"]
                    )
                    if matches_admitted:
                        pass
                    elif not matches_retained:
                        raise BootstrapError("Runtime recovery refused: recorded foreground does not match the admitted or retained owner.")
                    else:
                        # A service record for the prior stopped owner may
                        # remain while a transaction-bound replacement is live.
                        # Retire it only after final-fence absence is repeated.
                        if boundary.process_birth_identity(foreground_pid) is None:
                            retired_foreground_evidence = recovery_owner
                            recorded_foreground = None
                        elif owner is not None:
                            raise BootstrapError("Runtime recovery refused: prior foreground child is still present.")
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError("Runtime recovery refused: foreground identity or absence could not be established.") from exc
            # A retained service child accompanying publication must name that
            # exact owner. This prevents a stop for one realm being used as cover
            # for a different child recorded by the installer.
            if owner is not None and recorded_foreground is not None and not recovery_mode:
                owner_pid, owner_birth, _owner_instance, _owner_endpoint = owner
                try:
                    foreground_pid = int(recorded_foreground["pid"])
                    foreground_birth = str(recorded_foreground["birth_id"])
                    # Legacy service records contain only PID/birth. The selected
                    # catalog realm supplies missing context; explicit context is
                    # still compared and rejected when it points elsewhere.
                    foreground_realm = str(recorded_foreground.get("realm_id") or realm.get("realm_id") or "")
                    foreground_root = _canonical_realm_root(
                        str(recorded_foreground.get("realm_root") or realm_root)
                    )
                except (KeyError, TypeError, ValueError, BootstrapError) as exc:
                    raise BootstrapError("Runtime interruption refused: recorded foreground identity is incomplete.") from exc
                if (foreground_pid != owner_pid or foreground_birth != owner_birth
                        or foreground_realm != str(realm.get("realm_id")) or foreground_root != realm_root):
                    raise BootstrapError("Runtime interruption refused: recorded foreground child does not match the selected owner.")

            # When there is no live published owner, a recorded child is accepted
            # only by a boundary method which checks the retained OS child/custody.
            foreground = None
            if owner is None and recorded_foreground is not None:
                foreground = getattr(boundary, "stop_recorded_foreground", None)
                if not callable(foreground):
                    raise BootstrapError("Runtime interruption refused: foreground child has no validated custody handoff.")
                if str(recorded_foreground.get("realm_id") or realm.get("realm_id")) != str(realm.get("realm_id")):
                    raise BootstrapError("Runtime interruption refused: foreground child belongs to another realm.")
                if recorded_foreground.get("realm_root") and _canonical_realm_root(str(recorded_foreground["realm_root"])) != realm_root:
                    raise BootstrapError("Runtime interruption refused: foreground child belongs to another realm root.")

            absence_evidence = None
            absence_is_receipt = False
            if recovery_mode and owner is None and foreground is None:
                # Empty and exact retained stale publications share one absence
                # proof. A nonmatching publication was either rejected above or
                # proved as a live bound owner; it cannot become stale authority.
                try:
                    absence_evidence = recovery_owner
                    owner_pid = absence_evidence["pid"]
                    if boundary.process_birth_identity(owner_pid) is not None:
                        raise BootstrapError("Runtime interruption refused: retained owner process is still present.")
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError("Runtime interruption refused: retained owner absence is not established.") from exc
                if missing_recovery_realm and (realm_root.exists() or realm_root.is_symlink()):
                    raise BootstrapError("Runtime recovery realm changed before the stop fence.")
            elif owner is None and discovery is None and marker is None and recorded_foreground is None:
                # Missing advertisements alone do not establish an absent process.
                # In particular, an OS manager may still hold an unpublished owner.
                # A retry in this same controller can retain positive evidence from
                # its completed handoff. Revalidate that exact process's absence;
                # the receipt cannot authorize a signal or survive a new process.
                if (not isinstance(receipt, Mapping)
                        or getattr(boundary, "_installer_stop_receipt_invalidated", False)):
                    raise BootstrapError("Runtime interruption refused: no owner identity or retained child proves a safe stop.")
                try:
                    absence_evidence = _canonical_stop_evidence(receipt, paths=paths)
                    if (absence_evidence["realm_id"] != str(realm["realm_id"])
                            or absence_evidence["realm_root"] != realm_root):
                        raise BootstrapError("Runtime interruption refused: retained stop receipt belongs to another realm.")
                    absent = boundary.process_birth_identity(absence_evidence["pid"]) is None
                except Exception as exc:
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError("Runtime interruption refused: prior owner absence could not be established.") from exc
                if not absent:
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError("Runtime interruption refused: prior owner process identity is no longer absent.")
                absence_is_receipt = True
            if missing_recovery_realm and (discovery is not None or marker is not None or recorded_foreground is not None):
                raise BootstrapError("Runtime interruption refused: realm is absent while an owner publication remains.")

        def validate_compatibility_stop():
            if owner is not None and recovery_mode and discovery is not None:
                try:
                    exact_retained = _publication_matches_receipt(
                        discovery, recovery_owner, paths=paths,
                        realm=realm, realm_root=realm_root,
                    )
                    final_owner = _validate_published_stop_owner(
                        paths, boundary, realm, realm_root, discovery, marker,
                        recovery_operation_id=(None if exact_retained else recovery_operation_id),
                        recovery_launch_identity=(None if exact_retained else recovery_launch_identity),
                        require_live=True,
                    )
                except BootstrapError:
                    _discard_installer_stop_receipt(boundary)
                    raise
                if final_owner != owner:
                    raise BootstrapError("Runtime recovery owner changed before the final stop fence.")
            if missing_recovery_realm:
                if realm_root.exists() or realm_root.is_symlink():
                    raise BootstrapError("Runtime recovery realm changed before the final stop fence.")
            if absence_evidence is not None:
                if absence_is_receipt and getattr(boundary, "_installer_stop_receipt_invalidated", False):
                    _discard_installer_stop_receipt(boundary)
                    raise BootstrapError("Runtime interruption refused: prior stop receipt was invalidated by a replacement publication.")
                try:
                    if boundary.process_birth_identity(absence_evidence["pid"]) is not None:
                        _discard_installer_stop_receipt(boundary)
                        message = ("prior owner identity changed under the final fence."
                                   if absence_is_receipt else "retained owner process is still present.")
                        raise BootstrapError("Runtime interruption refused: " + message)
                except BootstrapError:
                    raise
                except Exception as exc:
                    _discard_installer_stop_receipt(boundary)
                    message = ("prior owner absence could not be established under the final fence."
                               if absence_is_receipt else "retained owner absence is not established.")
                    raise BootstrapError("Runtime interruption refused: " + message) from exc
            if retired_foreground_evidence is not None:
                try:
                    if boundary.process_birth_identity(retired_foreground_evidence["pid"]) is not None:
                        raise BootstrapError("Runtime recovery refused: retired foreground identity is no longer absent.")
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError("Runtime recovery refused: retired foreground absence could not be revalidated.") from exc
            if (recovery_mode or absence_evidence is not None
                    or retired_foreground_evidence is not None):
                # Re-read after every owner, foreground and absence
                # observation. Exact retained remnants stay unchanged;
                # empty publications stay empty.
                try:
                    if (_read_support_json(paths.discovery_path) != discovery
                            or _read_support_json(paths.instance_lock_path) != marker):
                        raise BootstrapError("Runtime recovery refused: owner publications changed during absence validation.")
                except BootstrapError:
                    raise
                except Exception as exc:
                    raise BootstrapError("Runtime recovery publications could not be revalidated.") from exc

        def stop_compatibility_foreground():
            def persist_custody_authority() -> None:
                if record_stop_authority is None:
                    return
                try:
                    foreground_pid = int(recorded_foreground["pid"])
                    foreground_birth = str(recorded_foreground["birth_id"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise BootstrapError("Runtime foreground identity is incomplete.") from exc
                record_stop_authority({
                    "support_root": str(paths.runtime_support.resolve()),
                    "realm_id": str(realm["realm_id"]), "realm_root": str(realm_root),
                    "pid": foreground_pid, "process_birth_id": foreground_birth,
                    **({"runtime_instance_id": str(recorded_foreground["runtime_instance_id"])}
                       if recorded_foreground.get("runtime_instance_id") else {}),
                })
            return foreground(
                recorded_foreground=recorded_foreground,
                realm_id=str(realm["realm_id"]), realm_root=realm_root,
                **({"record_custody_authority": persist_custody_authority}
                   if record_stop_authority is not None else {}),
            )

        def remember_compatibility_stop():
            _remember_completed_stop(
                boundary, paths=paths, realm=realm, realm_root=realm_root,
                evidence=(discovery or marker) if owner is not None
                else (discovery or marker or recorded_foreground),
            )

        result = _fenced_stop_and_manager(
            paths, boundary, realm_id=str(realm["realm_id"]), realm_root=realm_root,
            discovery=discovery, marker=marker, owner=owner,
            stop_manager=stop_manager, validate_stop=validate_compatibility_stop,
            stop_foreground=stop_compatibility_foreground if foreground is not None else None,
            record_stop_authority=record_stop_authority,
            remember_stop=remember_compatibility_stop,
            missing_recovery_realm=missing_recovery_realm,
        )
        evidence = discovery or marker or recorded_foreground
        if evidence is not None and getattr(boundary, "_installer_stop_receipt", None) is None:
            _remember_completed_stop(
                boundary, paths=paths, realm=realm, realm_root=realm_root,
                evidence=evidence,
            )
        return result


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
        report["pid_alive"] = bool(_pid_alive(boundary, discovery.get("pid")))
        if not report["pid_alive"]:
            report["healthy"] = False
            report["issues"].append("stale_discovery")
        elif boundary:
            try:
                owner_ok = bool(boundary.validate_owner(endpoint=str(discovery.get("endpoint", "")), pid=int(discovery["pid"]), instance_id=str(discovery.get("runtime_instance_id", "")), owner_lock=paths.instance_lock_path, process_birth_id=str(discovery.get("process_birth_id") or "")))
            except Exception:
                owner_ok = False
            if not owner_ok:
                report["healthy"] = False
                report["issues"].append("discovery_identity")
            elif not boundary.health(endpoint=str(discovery.get("endpoint", "")), pid=int(discovery["pid"]), instance_id=str(discovery.get("runtime_instance_id", ""))):
                report["healthy"] = False
                report["issues"].append("runtime_unhealthy")
    return report, dict(discovery) if discovery is not None else None


def doctor(paths: RuntimePaths, boundary: RuntimeBoundary | None = None) -> dict[str, Any]:
    """Read-only support-state diagnostics. This function creates no files."""
    return _doctor_observation(paths, boundary)[0]
