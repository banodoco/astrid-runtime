"""T2 neutral one-realm launch/reconnect lifecycle.

The boundary protocol is intentionally tiny. A real generated workspace
client can implement it; tests use a fake. Runtime ownership stays behind
that boundary and legacy roots are always rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from functools import wraps
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
from .owner_diagnostics import (
    instrument,
    observation,
    outcome,
    owner_phase,
    phase_instrument,
    predicate_chain,
    unavailable,
)
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


@predicate_chain(
    "support_json_read", "support_json_decode", "support_json_parse", "support_json_open", "support_json_regular"
)
def _read_json_regular(path: Path) -> Any:
    if runtime_platform.sys.platform == "win32" and path.name in {"astrid.json", "discovery.json"}:
        with observation("support_json_read"):
            raw = runtime_platform.read_private_file(path)
        with observation("support_json_decode", malformed=(UnicodeDecodeError,)):
            decoded = raw.decode("utf-8")
        with observation("support_json_parse", malformed=(json.JSONDecodeError,)):
            return json.loads(decoded)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with observation("support_json_open", malformed=(FileNotFoundError,)):
        fd = os.open(path, flags)
    try:
        if not outcome("support_json_regular", stat.S_ISREG(os.fstat(fd).st_mode)):
            raise OSError(f"not a regular file: {path}")
        data = bytearray()
        while True:
            with observation("support_json_read"):
                chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        with observation("support_json_decode", malformed=(UnicodeDecodeError,)):
            decoded = bytes(data).decode("utf-8")
        with observation("support_json_parse", malformed=(json.JSONDecodeError,)):
            return json.loads(decoded)
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


@predicate_chain(
    "source_profile_type",
    "source_profile_name",
    "source_runtime_present",
    "source_runtime_absolute",
    "source_runtime_no_symlink",
    "source_checkout_absolute",
    "source_checkout_no_symlink",
    "source_worker_absolute",
    "source_worker_no_symlink",
    "source_worker_leaf_no_symlink",
    "source_worker_file",
    "source_runtime_command_absent",
    "source_protocol",
    "source_schema",
)
def _validate_source_profile(source: SourceProfile, *, expected_profile: str = "astrid") -> None:
    """Reject source metadata that attempts to become runtime authority."""
    if not outcome(
        "source_profile_type",
        isinstance(source, SourceProfile),
    ) or not outcome("source_profile_name", source.profile == expected_profile):
        raise BootstrapError(f"Source profile must be {expected_profile!r}.")
    checkout = str(source.runtime_checkout or "")
    checkout_path = Path(checkout).expanduser()
    source_path = Path(str(source.source_checkout or "")).expanduser()
    if (
        not outcome(
            "source_runtime_present",
            checkout,
        )
        or not outcome(
            "source_runtime_absolute",
            checkout_path.is_absolute(),
        )
        or not outcome("source_runtime_no_symlink", not _has_symlink_component(checkout_path))
    ):
        raise BootstrapError("Source profile runtime_checkout must be an explicit absolute pinned checkout path.")
    if not outcome(
        "source_checkout_absolute",
        source_path.is_absolute(),
    ) or not outcome("source_checkout_no_symlink", not _has_symlink_component(source_path)):
        raise BootstrapError("Source profile source_checkout must be an absolute symlink-free provenance path.")
    if source.worker_profile:
        worker_profile = Path(source.worker_profile).expanduser()
        if (
            not outcome(
                "source_worker_absolute",
                worker_profile.is_absolute(),
            )
            or not outcome(
                "source_worker_no_symlink",
                not _has_symlink_component(worker_profile),
            )
            or not outcome("source_worker_leaf_no_symlink", not worker_profile.is_symlink())
        ):
            raise BootstrapError("Source profile worker_profile must be an absolute symlink-free path.")
        if not outcome("source_worker_file", worker_profile.is_file()):
            raise BootstrapError(f"Source profile worker_profile does not exist: {worker_profile}")
    if not outcome("source_runtime_command_absent", not source.runtime_command):
        raise BootstrapError("Source profile runtime_command is not permitted; runtime launch is fixed by the installed runtime.")
    if not outcome(
        "source_protocol",
        source.protocol_version == PROTOCOL_VERSION,
    ) or not outcome("source_schema", source.schema_version == SCHEMA_VERSION):
        raise CompatibilityError("Source profile protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION)


@predicate_chain(
    "loopback_parse",
    "loopback_scheme",
    "loopback_no_username",
    "loopback_no_password",
    "loopback_host",
    "loopback_port_present",
    "loopback_port_range",
    "loopback_path",
    "loopback_no_query",
    "loopback_no_fragment",
)
def _validate_loopback_endpoint(endpoint: str) -> str:
    """Accept only the runtime's local HTTP authority."""
    try:
        with observation("loopback_parse", malformed=(ValueError,)):
            parsed = urlsplit(str(endpoint))
            host = parsed.hostname
            port = parsed.port
    except ValueError as exc:
        raise BootstrapError("Runtime discovery endpoint is invalid or not loopback-only.") from exc
    if (
        not outcome(
            "loopback_scheme",
            parsed.scheme == "http",
        )
        or not outcome(
            "loopback_no_username",
            not parsed.username,
        )
        or not outcome(
            "loopback_no_password",
            not parsed.password,
        )
        or not outcome(
            "loopback_host",
            host in {"127.0.0.1", "localhost", "::1"},
        )
        or not outcome(
            "loopback_port_present",
            port is not None,
        )
        or not outcome(
            "loopback_port_range",
            1 <= int(port) <= 65535,
        )
        or not outcome(
            "loopback_path",
            parsed.path in ("", "/"),
        )
        or not outcome("loopback_no_query", not parsed.query)
        or not outcome("loopback_no_fragment", not parsed.fragment)
    ):
        raise BootstrapError("Runtime discovery endpoint must be an HTTP loopback authority.")
    return str(endpoint).rstrip("/")


@predicate_chain(
    "worker_handoff_object",
    "worker_credential_present",
    "worker_credential_string",
    "worker_credential_nonempty",
    "worker_path_absolute",
    "worker_path_no_symlink",
    "worker_leaf_no_symlink",
    "worker_file_available",
    "worker_file_owner_only",
    "worker_actor_matches",
    "worker_scopes_match",
)
def _worker_handoff(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate the non-secret pack-host credential handoff.

    The token itself stays in the owner-only file.  Discovery carries only
    its path and the exact scope declaration so a launcher can activate one
    host without promoting the Astrid user credential or an owner token.
    Older fake boundaries may omit the optional fields; real runtime launch
    always supplies them.
    """
    if not outcome("worker_handoff_object", not (not isinstance(value, Mapping))) or not outcome(
        "worker_credential_present", not (not value.get("worker_credential_file"))
    ):
        return {}
    raw_path = value.get("worker_credential_file")
    if not outcome("worker_credential_string", not (not isinstance(raw_path, str))) or not outcome(
        "worker_credential_nonempty", not (not raw_path)
    ):
        raise BootstrapError("Runtime worker credential handoff is invalid; " + RECONFIGURE_NEXT_ACTION)
    path = Path(raw_path).expanduser()
    pending = bool(value.get("worker_credential_pending"))
    if (
        not outcome("worker_path_absolute", not (not path.is_absolute()))
        or not outcome("worker_path_no_symlink", not (_has_symlink_component(path)))
        or not outcome("worker_leaf_no_symlink", not (path.is_symlink()))
        or not outcome("worker_file_available", not (not pending and not path.is_file()))
    ):
        raise BootstrapError("Runtime worker credential handoff is unsafe; " + RECONFIGURE_NEXT_ACTION)
    if not pending:
        try:
            if not outcome(
                "worker_file_owner_only",
                not (
                    not runtime_platform.is_owner_only(
                        path if runtime_platform.sys.platform == "win32" else path.stat()
                    )
                ),
            ):
                raise BootstrapError("Runtime worker credential file must be owner-only; " + RECONFIGURE_NEXT_ACTION)
        except OSError as exc:
            raise BootstrapError("Runtime worker credential handoff is unavailable; " + RECONFIGURE_NEXT_ACTION) from exc
    actor = str(value.get("worker_actor") or "")
    scopes = tuple(str(scope) for scope in (value.get("worker_scopes") or ()))
    if not outcome("worker_actor_matches", not (actor != WORKER_ACTOR)) or not outcome(
        "worker_scopes_match", not (scopes != WORKER_SCOPES)
    ):
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
            if not outcome("support_component_safe", not cursor.is_symlink()):
                support_symlink = True
                break
        if not outcome(
            "support_path_absolute", target.is_absolute(), blocked=("support_path_no_symlink",)
        ) or not outcome("support_path_no_symlink", not support_symlink):
            raise BootstrapError(f"Neutral support path must be absolute and symlink-free: {target}")
    for directory in directories:
        if outcome(
            "support_directory_present",
            os.path.lexists(str(directory)),
            blocked=("support_directory_no_symlink", "support_directory_regular"),
        ) and (
            not outcome(
                "support_directory_no_symlink", not directory.is_symlink(), blocked=("support_directory_regular",)
            )
            or not outcome("support_directory_regular", directory.is_dir())
        ):
            raise BootstrapError(f"Neutral support directory is not a regular directory: {directory}")
    for path in files:
        if outcome(
            "support_file_present",
            os.path.lexists(str(path)),
            blocked=("support_file_no_symlink", "support_file_regular"),
        ) and (
            not outcome("support_file_no_symlink", not path.is_symlink(), blocked=("support_file_regular",))
            or not outcome("support_file_regular", path.is_file())
        ):
            raise BootstrapError(f"Neutral support file is not a regular file: {path}")


def _read_support_json(path: Path) -> dict[str, Any] | None:
    """Read a support JSON file without following a symlink."""
    try:
        value = _read_json_regular(path)
    except FileNotFoundError:
        outcome("support_json_present", False)
        return None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        detail = f": {exc}" if runtime_platform.sys.platform == "win32" else ""
        raise BootstrapError(f"Neutral support file is missing, malformed, or unsafe: {path}{detail}") from exc
    outcome("support_json_present", True)
    if not outcome("support_json_object", isinstance(value, Mapping)):
        raise BootstrapError(f"Neutral support file must contain an object: {path}")
    return dict(value)


def _new_realm_id() -> str:
    return uuid.uuid4().hex


def _read_catalog(paths: RuntimePaths) -> dict[str, Any]:
    catalog = _read_support_json(paths.catalog_path)
    if catalog is None:
        return {"version": CATALOG_VERSION, "selected_realm_id": None, "realms": [], "source_profiles": {}}
    return _validate_catalog(catalog)


@predicate_chain(
    "catalog_version",
    "catalog_realms_list",
    "catalog_profiles_object",
    "catalog_profile_supported",
    "catalog_one_realm",
    "catalog_realm_object",
    "catalog_realm_id_present",
    "catalog_realm_id_unique",
    "catalog_realm_id_safe",
    "catalog_root_absolute",
    "catalog_root_no_symlink",
    "catalog_root_leaf_no_symlink",
    "catalog_root_directory",
    "catalog_realm_named",
    "catalog_selection_matches",
)
def _validate_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one already-read catalog snapshot and return its document."""
    catalog = dict(catalog)
    if not outcome("catalog_version", not (catalog.get("version") != CATALOG_VERSION)):
        raise BootstrapError("Neutral realm catalog version is unsupported; run astrid-runtime doctor.")
    if not outcome("catalog_realms_list", not (not isinstance(catalog.get("realms", []), list))):
        raise BootstrapError("Neutral realm catalog is invalid; recover or remove catalog.json.")
    if not outcome("catalog_profiles_object", not (not isinstance(catalog.get("source_profiles", {}), Mapping))):
        raise BootstrapError("Neutral realm catalog source profiles are invalid; run astrid-runtime doctor.")
    for profile_name, manifest in catalog.get("source_profiles", {}).items():
        try:
            if not outcome("catalog_profile_supported", not (str(profile_name) != "astrid")):
                raise BootstrapError("Neutral realm catalog contains an unsupported source profile.")
            SourceProfile.from_mapping(manifest, expected_profile=str(profile_name))
        except BootstrapError:
            raise
        except (TypeError, ValueError) as exc:
            raise BootstrapError("Neutral realm catalog source profile is invalid; run astrid-runtime doctor.") from exc
    if not outcome("catalog_one_realm", not (len(catalog["realms"]) > 1)):
        raise UnsupportedRealmError(MULTI_REALM_NEXT_ACTION)
    seen: set[str] = set()
    for realm in catalog["realms"]:
        if not outcome("catalog_realm_object", not (not isinstance(realm, Mapping))):
            raise BootstrapError("Neutral realm catalog contains an invalid realm entry; run astrid-runtime doctor.")
        realm_id = str(realm.get("realm_id") or "")
        data_root = Path(str(realm.get("data_root") or "")).expanduser()
        if (
            not outcome("catalog_realm_id_present", not (not realm_id))
            or not outcome("catalog_realm_id_unique", not (realm_id in seen))
            or not outcome("catalog_realm_id_safe", not (any(char in realm_id for char in "/\\")))
            or not outcome("catalog_root_absolute", not (not data_root.is_absolute()))
            or not outcome("catalog_root_no_symlink", not (_has_symlink_component(data_root)))
            or not outcome("catalog_root_leaf_no_symlink", not (data_root.is_symlink()))
            or not outcome("catalog_root_directory", not (data_root.exists() and not data_root.is_dir()))
        ):
            raise BootstrapError("Neutral realm catalog contains an unsafe realm root; run astrid-runtime doctor.")
        if not outcome("catalog_realm_named", not (not str(realm.get("display_name") or ""))):
            raise BootstrapError("Neutral realm catalog contains an unnamed realm; run astrid-runtime doctor.")
        seen.add(realm_id)
    selected = catalog.get("selected_realm_id")
    if not outcome("catalog_selection_matches", not (selected is not None and str(selected) not in seen)):
        raise BootstrapError("Catalog selected realm is inconsistent; run astrid-runtime doctor.")
    return catalog


def _selected_realm(catalog: dict[str, Any]) -> dict[str, Any] | None:
    realms = catalog.get("realms", [])
    if not outcome("selected_one_realm", len(realms) <= 1):
        raise UnsupportedRealmError(MULTI_REALM_NEXT_ACTION)
    if not outcome("selected_realms_present", bool(realms), blocked=("selected_id_present", "selected_realm_matches")):
        return None
    selected = catalog.get("selected_realm_id")
    if not outcome("selected_id_present", selected is not None, blocked=("selected_realm_matches",)):
        return None
    realm = realms[0]
    if not outcome("selected_realm_matches", not (selected and str(selected) != str(realm.get("realm_id")))):
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


def _observe_validation(name):
    """Report the outcome of an existing validator without reading its inputs."""
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                result = function(*args, **kwargs)
            except BootstrapError:
                outcome(name, False)
                raise
            except Exception:
                outcome(name, None, error=True)
                raise
            outcome(name, True)
            return result
        return wrapped
    return decorate


@_observe_validation("compatibility")
@predicate_chain(
    "compatibility_protocol",
    "compatibility_schema",
    "compatibility_capability",
    "compatibility_source_protocol",
    "compatibility_source_schema",
)
def _compatible(discovery: Mapping[str, Any], config: BootstrapConfig, source: SourceProfile) -> None:
    if not outcome(
        "compatibility_protocol",
        discovery.get("protocol_version") == config.protocol_version,
    ) or not outcome("compatibility_schema", discovery.get("schema_version") == config.schema_version):
        raise CompatibilityError(
            "Runtime protocol/schema is incompatible. " + RECONFIGURE_NEXT_ACTION
        )
    if not outcome(
        "compatibility_capability",
        not (
            config.capability_digest and discovery.get("capability_digest") not in {None, "", config.capability_digest}
        ),
    ):
        raise CompatibilityError("Runtime capability digest is incompatible. " + RECONFIGURE_NEXT_ACTION)
    if not outcome(
        "compatibility_source_protocol",
        source.protocol_version == config.protocol_version,
    ) or not outcome("compatibility_source_schema", source.schema_version == config.schema_version):
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


def _realm_owner_present(root: Path) -> bool:
    """Observe the lifetime lock independently of the caller's PID namespace."""
    try:
        fd = os.open(root / "owner.lock", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise BootstrapError("Runtime realm ownership could not be established.") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise BootstrapError("Runtime realm owner lock is not a regular file.")
        try:
            runtime_platform.lock_file(fd, blocking=False)
        except BlockingIOError:
            return True
        except OSError as exc:
            raise BootstrapError("Runtime realm ownership could not be established.") from exc
        runtime_platform.unlock_file(fd)
        return False
    finally:
        os.close(fd)


@instrument
def _owner_may_be_alive(boundary: RuntimeBoundary, record: Mapping[str, Any]) -> bool:
    """Only proven absence or a different birth permits stale-record cleanup."""
    if outcome("liveness_realm_root", bool(record.get("realm_root"))) and outcome("liveness_realm_lock", _realm_owner_present(
        _canonical_realm_root(str(record["realm_root"]))
    )):
        return True
    pid = record.get("pid")
    with observation("liveness_pid_read"):
        alive = _pid_alive(boundary, pid)
    if not outcome(
        "liveness_pid_alive",
        alive,
        blocked=(
            "liveness_observer_callable",
            "liveness_birth_expected",
            "liveness_birth_read",
            "liveness_birth_observed",
            "liveness_birth_compatible",
        ),
    ):
        return False
    observe = getattr(boundary, "process_birth_identity", None)
    expected = record.get("process_birth_id")
    if not outcome(
        "liveness_observer_callable",
        callable(observe),
        blocked=(
            "liveness_birth_expected",
            "liveness_birth_read",
            "liveness_birth_observed",
            "liveness_birth_compatible",
        ),
    ) or not outcome(
        "liveness_birth_expected",
        bool(expected),
        blocked=(
            "liveness_birth_read",
            "liveness_birth_observed",
            "liveness_birth_compatible",
        ),
    ):
        return True
    with observation("liveness_birth_read"):
        actual = observe(int(pid))
    return (
        not outcome(
            "liveness_birth_observed",
            actual is not None,
            blocked=("liveness_birth_compatible",),
        )
        or outcome(
            "liveness_birth_compatible",
            runtime_platform.process_birth_matches(str(expected), actual),
        )
        is not False
    )


@phase_instrument
def _reclaim_stale_owner_locked(paths: RuntimePaths, boundary: RuntimeBoundary) -> bool:
    """Reclaim only stale advertisements under the launcher mutex; never signal.

    Check both records before removing either: a missing/stale discovery must
    not hide a live owner in instance.lock. Recheck snapshots so replacement
    advertisements cannot be removed by an older cleanup attempt.
    """
    records = [(path, _read_support_json(path))
               for path in (paths.discovery_path, paths.instance_lock_path)]
    present = [(path, record) for path, record in records if record is not None]
    if not outcome("reclaim_records_present", bool(present), blocked=("reclaim_no_live_owner",)) or not outcome(
        "reclaim_no_live_owner",
        not any((_owner_may_be_alive(boundary, record) for _, record in present)),
    ):
        return False
    if not outcome(
        "reclaim_snapshots_unchanged",
        not any((_read_support_json(path) != record for path, record in records)),
    ):
        raise BootstrapError("Runtime owner changed during stale-owner cleanup.")
    expected = dict(records)
    for path, _ in present:
        if not outcome(
            "reclaim_fresh_absence",
            not any((_owner_may_be_alive(boundary, record) for record in expected.values() if record is not None)),
        ):
            raise BootstrapError("Runtime owner appeared during stale-owner cleanup.")
        if not outcome(
            "reclaim_fresh_snapshots",
            all(_read_support_json(candidate) == record for candidate, record in expected.items()),
        ):
            raise BootstrapError("Runtime owner changed during stale-owner cleanup.")
        remove_file(path)
        expected[path] = None
    return True


@predicate_chain(
    "realm_path_absolute",
    "realm_path_no_symlink",
    "realm_leaf_no_symlink",
    "realm_path_canonical",
    "realm_path_available",
)
def _canonical_realm_root(value: str | Path, *, allow_missing: bool = False) -> Path:
    raw = Path(value).expanduser()
    if (
        not outcome("realm_path_absolute", not (not raw.is_absolute()))
        or not outcome("realm_path_no_symlink", not (_has_symlink_component(raw)))
        or not outcome("realm_leaf_no_symlink", not (raw.is_symlink()))
    ):
        raise BootstrapError("Realm-root identity must be absolute and symlink-free.")
    normalized = Path(os.path.abspath(raw))
    if not outcome("realm_path_canonical", not (normalized != raw)):
        raise BootstrapError("Realm-root identity must be canonical.")
    resolved = raw.resolve()
    if not outcome(
        "realm_path_available", not (not resolved.is_dir() and not (allow_missing and not resolved.exists()))
    ):
        raise BootstrapError("Realm-root identity is unavailable.")
    return resolved


@predicate_chain(
    "lock_match_read",
    "lock_match_root",
    "lock_match_present",
    "lock_match_pid",
    "lock_match_instance",
    "lock_match_realm",
    "lock_match_birth",
)
def _lock_matches(
    paths: RuntimePaths, pid: int, instance_id: str, realm_id: str,
    process_birth_id: str | None = None, realm_root: Path | None = None,
) -> bool:
    with observation("lock_match_read"):
        marker = _read_support_json(paths.instance_lock_path)
    root_matches = True
    if realm_root is not None:
        try:
            root_matches = _canonical_realm_root(str(marker.get("realm_root") or "")) == realm_root if marker else False
        except BootstrapError:
            root_matches = False
        outcome("lock_match_root", root_matches)
    return bool(
        outcome("lock_match_present", bool(marker))
        and outcome("lock_match_pid", str(marker.get("pid")) == str(pid))
        and outcome("lock_match_instance", str(marker.get("runtime_instance_id")) == instance_id)
        and outcome("lock_match_realm", str(marker.get("realm_id")) == realm_id)
        and outcome(
            "lock_match_birth",
            process_birth_id is None or str(marker.get("process_birth_id")) == process_birth_id,
        )
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


def _provision_connection(connection: Any, actor_id: str, token: str, realm_id: str, *, validate_owner=None) -> None:
    """Call only generated-client-shaped methods; never inspect runtime state."""
    provision = getattr(connection, "provision_actor", None)
    if provision is not None:
        if validate_owner is not None:
            validate_owner()
        result = cancellation.wait_for(provision, scope="astrid", actor_id=actor_id, credential=token)
        if isinstance(result, Mapping) and result.get("scope") not in (None, "astrid"):
            raise BootstrapError("Runtime refused the Astrid-scoped credential.")
    select = getattr(connection, "select_realm", None)
    if select is not None:
        if validate_owner is not None:
            validate_owner()
        cancellation.wait_for(select, actor_id=actor_id, realm_id=realm_id)
    handshake = getattr(connection, "handshake", None)
    if handshake is not None:
        if validate_owner is not None:
            validate_owner()
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

    def validate_rollback_absence() -> None:
        if not outcome("rollback_realm_owner_absent", not _realm_owner_present(realm_root)):
            raise BootstrapError("Runtime rollback refuses a live realm owner.")
        for path in (paths.discovery_path, paths.instance_lock_path):
            current = _read_support_json(path)
            expected = candidate_publications.get(path) if candidate_publications is not None else object()
            if not outcome("rollback_publication_unchanged", current is None or current == expected):
                raise BootstrapError("Runtime rollback refuses replacement publications.")
            if current is not None and not outcome(
                "rollback_candidate_matches",
                candidate_pid is not None and str(current.get("pid")) == str(candidate_pid),
            ):
                raise BootstrapError("Runtime rollback refuses another owner's metadata.")

    try:
        validate_rollback_absence()
    except BootstrapError:
        return  # Preserve the original launch failure and the incumbent's state.
    owner_present = _realm_owner_present(realm_root)
    for path in (paths.discovery_path, paths.instance_lock_path):
        try:
            current = _read_support_json(path)
            expected = candidate_publications.get(path) if candidate_publications is not None else object()
            if (not owner_present and candidate_pid is not None and candidate_publications is not None
                    and current is not None and current == expected):
                try:
                    owned = int(current.get("pid", 0)) == int(candidate_pid)
                except (TypeError, ValueError):
                    owned = False
                if outcome("rollback_candidate_matches", owned):
                    validate_rollback_absence()
                    remove_file(path)
        except Exception:
            pass
    credential = paths.credentials_dir / "astrid.json"
    try:
        validate_rollback_absence()
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
        validate_rollback_absence()
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
        validate_rollback_absence()
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
            validate_rollback_absence()
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


@phase_instrument
@predicate_chain(
    "reattest_discovery_absent",
    "reattest_marker_absent",
    "reattest_realm_directory",
    "reattest_realm_no_symlink",
    "reattest_catalog_parse",
    "reattest_realm_parse",
    "reattest_realm_selected",
    "reattest_realm_root",
    "reattest_binding_parse",
    "reattest_binding_present",
    "reattest_binding_matches",
    "reattest_fence_safe",
    "recovery_reattest_publications_absent",
    "reattest_current_binding_parse",
    "recovery_reattest_binding",
)
def _reattest_aborted_launch_stop(
    paths: RuntimePaths, boundary: RuntimeBoundary,
    marker: Mapping[str, Any], *, realm_root: Path,
) -> bool:
    """Restore a consumed Stop lifetime only after C1 proves this launch aborted."""
    try:
        owner = _validate_completed_stop_marker(marker)
        if not outcome(
            "reattest_discovery_absent",
            _read_support_json(paths.discovery_path) is None,
        ) or not outcome(
            "reattest_marker_absent",
            _read_support_json(paths.instance_lock_path) is None,
        ):
            return False
        if not outcome(
            "reattest_realm_directory",
            realm_root.is_dir(),
        ) or not outcome("reattest_realm_no_symlink", not realm_root.is_symlink()):
            return False
        _require_owner_absent(
            boundary, int(owner["pid"]), str(owner["process_birth_id"]),
            context="while re-attesting an aborted launch",
        )
        with observation("reattest_catalog_parse", malformed=(BootstrapError, TypeError, ValueError)):
            catalog = _read_catalog(paths)
        with observation("reattest_realm_parse", malformed=(BootstrapError, TypeError, ValueError)):
            realm = _selected_realm(catalog)
        if not outcome(
            "reattest_realm_selected",
            realm is not None,
        ) or not outcome(
            "reattest_realm_root",
            _canonical_realm_root(str(realm.get("data_root") or "")) == realm_root,
        ):
            return False
        with observation("reattest_binding_parse", malformed=(BootstrapError, TypeError, ValueError)):
            binding = _pinokio_stop_binding(paths, realm)
        if not outcome(
            "reattest_binding_present",
            binding is not None,
        ) or not outcome(
            "reattest_binding_matches",
            dict(marker["completed_stop"]["binding"]) == binding,
        ):
            return False
        with interruption_fence(realm_root) as report:
            if not outcome("reattest_fence_safe", report.get("safe", False)):
                return False
            if not outcome("recovery_reattest_publications_absent", _read_support_json(paths.discovery_path) is None
                    and _read_support_json(paths.instance_lock_path) is None):
                return False
            _require_owner_absent(
                boundary, int(owner["pid"]), str(owner["process_birth_id"]),
                context="inside the aborted-launch fence",
            )
            with observation(
                "reattest_current_binding_parse",
                malformed=(BootstrapError, TypeError, ValueError),
            ):
                current_binding = _pinokio_stop_binding(paths, realm)
            if not outcome(
                "recovery_reattest_binding",
                outcome("reattest_binding_unchanged", current_binding == binding)
                and outcome("reattest_marker_binding_matches", current_binding == marker["completed_stop"]["binding"]),
            ):
                return False
            if not outcome(
                "reattest_final_discovery_absent", _read_support_json(paths.discovery_path) is None
            ) or not outcome("reattest_final_marker_absent", _read_support_json(paths.instance_lock_path) is None):
                return False
            atomic_write_json(paths.instance_lock_path, dict(marker))
        return True
    except Exception:
        # Re-attestation is optional recovery evidence. Any unknown state keeps
        # the old marker consumed and leaves the original launch error intact.
        return False


@phase_instrument
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
    if not outcome("discovery_profile_supported", config.profile == "astrid"):
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    collision = _legacy_collision(paths, config.legacy_roots)
    if not outcome("discovery_legacy_absent", collision is None):
        raise LegacyRootCollisionError(LEGACY_NEXT_ACTION.format(legacy_root=collision))
    if _selected_realm(_read_catalog(paths)) is None:
        raise BootstrapError(
            "No workspace is configured; run astrid-runtime workspace create or workspace attach."
        )
    config.resolve_source_profile(paths)
    with _bootstrap_mutex(paths):
        return _bootstrap_locked(paths, boundary, config)


def _commit_bootstrap_metadata(paths: RuntimePaths, source: SourceProfile, catalog: Mapping[str, Any], discovery: Mapping[str, Any], *, validate_owner=None) -> None:
    """Commit catalog, source provenance, and ephemeral discovery in order."""
    if validate_owner is not None:
        validate_owner()
    atomic_write_json(paths.catalog_path, dict(catalog))
    if validate_owner is not None:
        validate_owner()
    atomic_write_json(paths.source_profiles_dir / f"{source.profile}.json", source.as_dict())
    marker = _read_support_json(paths.instance_lock_path)
    if marker is None or not _owner_record_matches(
        marker, pid=int(discovery["pid"]), instance_id=str(discovery["runtime_instance_id"]),
        process_birth_id=str(discovery["process_birth_id"]),
        realm_id=str(discovery["active_realm"]), realm_root=Path(str(discovery["realm_root"])),
    ):
        raise BootstrapError("Runtime owner changed before discovery publication.")
    # Keep the owner's public advertisement with its existing identity marker.
    # No bearer bytes are stored here. Up can repair a lost ephemeral file only
    # after revalidating this exact owner through the ordinary boundary.
    if validate_owner is not None:
        validate_owner()
    atomic_write_json(paths.instance_lock_path, {**marker, "discovery": dict(discovery)})
    if validate_owner is not None:
        validate_owner()
    atomic_write_json(paths.discovery_path, dict(discovery))


def _commit_source_profile_metadata(paths: RuntimePaths, source: SourceProfile, catalog: Mapping[str, Any], *, validate_owner=None) -> None:
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
        if validate_owner is not None:
            validate_owner()
        atomic_write_json(paths.catalog_path, dict(catalog))
        if validate_owner is not None:
            validate_owner()
        atomic_write_json(source_path, source.as_dict())
    except Exception:
        try:
            if validate_owner is not None:
                validate_owner()
            if catalog_before is None:
                remove_file(paths.catalog_path)
            else:
                paths.catalog_path.write_bytes(catalog_before)
                owner_only(paths.catalog_path)
            if validate_owner is not None:
                validate_owner()
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
        with observation("requested_identity_capture", malformed=(TypeError, ValueError)):
            return requested_startup_identity(source)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise BootstrapError("Requested Runtime identity could not be verified.") from exc


def _owner_identity_health(boundary: RuntimeBoundary, **kwargs):
    with observation("startup_identity_read"):
        return boundary.owner_startup_identity(**kwargs)


@_observe_validation("startup_identity")
@predicate_chain(
    "startup_owner_identity_parse",
    "startup_requested_identity_parse",
    "startup_identity_matches",
)
def _validated_matching_owner_identity(
    owner_health: Any,
    *,
    instance_id: str,
    requested_identity: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        with observation(
            "startup_owner_identity_parse",
            malformed=(StartupIdentityError, TypeError, ValueError),
        ):
            observed = validate_live_owner_identity(owner_health, instance_id=instance_id)
        with observation(
            "startup_requested_identity_parse",
            malformed=(StartupIdentityError, TypeError, ValueError),
        ):
            requested = normalize_startup_identity(requested_identity)
    except (StartupIdentityError, OSError, RuntimeError, TypeError, ValueError):
        raise BootstrapError(IDENTITY_REFUSAL_MESSAGE, details={"code": "identity_mismatch"}) from None
    if not outcome("startup_identity_matches", observed == requested):
        raise BootstrapError(IDENTITY_REFUSAL_MESSAGE, details={"code": "identity_mismatch"})
    return observed


@phase_instrument
def _bootstrap_locked(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig) -> BootstrapResult:
    with observation("admission_upgrade_journal_read", malformed=(BootstrapError, TypeError, ValueError)):
        upgrade_journal = _read_support_json(paths.runtime_support / "upgrade-journal.json")
    if (
        outcome("upgrade_journal_present", bool(upgrade_journal))
        and outcome("upgrade_journal_operation", upgrade_journal.get("operation") == "astrid-runtime-upgrade/v1")
        and not outcome(
            "upgrade_journal_terminal", upgrade_journal.get("state") in {"complete", "rolled_back", "failed"}
        )
        and not outcome(
            "upgrade_journal_operator_matches",
            os.environ.get("ASTRID_V33_OPERATOR_OPERATION") == upgrade_journal.get("operation_id"),
        )
    ):
        raise BootstrapError("An upgrade is incomplete; use astrid-runtime upgrade --recover before starting this installation.")
    if not outcome("discovery_profile_supported", config.profile == "astrid"):
        raise BootstrapError("Stage 1 supports only the astrid profile.")
    with observation("admission_source_read", malformed=(BootstrapError, TypeError, ValueError)):
        source = config.resolve_source_profile(paths)
    _validate_source_profile(source, expected_profile=config.profile)
    requested_identity = _capture_requested_identity(source)
    collision = _legacy_collision(paths, config.legacy_roots)
    if not outcome("discovery_legacy_absent", collision is None):
        raise LegacyRootCollisionError(LEGACY_NEXT_ACTION.format(legacy_root=collision))

    paths.ensure_support_dirs()
    with observation("admission_catalog_read", malformed=(BootstrapError, TypeError, ValueError)):
        catalog = _read_catalog(paths)
    catalog_before = paths.catalog_path.read_bytes() if paths.catalog_path.is_file() and not paths.catalog_path.is_symlink() else None
    with observation("admission_realm_read", malformed=(BootstrapError, TypeError, ValueError)):
        realm = _selected_realm(catalog)
    if not outcome("discovery_realm_present", realm is not None):
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
    if (marker is not None and marker.get("state") is None
            and _read_support_json(paths.discovery_path) is None
            and isinstance(marker.get("discovery"), Mapping)):
        with owner_phase("recovery"):
            recovery = marker["discovery"]
            realm_root = _canonical_realm_root(str(realm["data_root"]))
            pid, birth, instance_id, endpoint = _recorded_owner_identity(
                recovery,
                realm_id=str(realm["realm_id"]),
                realm_root=realm_root,
            )
            if _owner_may_be_alive(boundary, marker):
                _compatible(recovery, config, source)
                if (
                    not outcome(
                        "recovery_lock_matches",
                        _lock_matches(
                            paths,
                            pid,
                            instance_id,
                            str(realm["realm_id"]),
                            birth,
                            realm_root,
                        ),
                        blocked=("recovery_owner_valid", "recovery_health"),
                    )
                    or not outcome(
                        "recovery_owner_valid",
                        boundary.validate_owner(
                            endpoint=endpoint,
                            pid=pid,
                            instance_id=instance_id,
                            owner_lock=paths.instance_lock_path,
                            process_birth_id=birth,
                            expected_realm_id=str(realm["realm_id"]),
                            expected_realm_root=realm_root,
                        ),
                        blocked=("recovery_health",),
                    )
                    or not outcome(
                        "recovery_health",
                        boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id),
                    )
                ):
                    raise DuplicateOwnerError("Runtime discovery recovery refused: live owner identity is unverified.")
                _validated_matching_owner_identity(
                    _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                    instance_id=instance_id,
                    requested_identity=requested_identity,
                )
                _validate_stop_endpoint(
                    paths,
                    boundary,
                    owner=(pid, birth, instance_id, endpoint),
                    realm_id=str(realm["realm_id"]),
                    realm_root=realm_root,
                )
                if not outcome(
                    "recovery_marker_unchanged",
                    _read_support_json(paths.instance_lock_path) == marker,
                    blocked=("recovery_discovery_absent",),
                ) or not outcome(
                    "recovery_discovery_absent",
                    _read_support_json(paths.discovery_path) is None,
                ):
                    raise BootstrapError("Runtime owner changed during discovery recovery.")
                _validate_stop_endpoint(
                    paths,
                    boundary,
                    owner=(pid, birth, instance_id, endpoint),
                    realm_id=str(realm["realm_id"]),
                    realm_root=realm_root,
                )
                _validated_matching_owner_identity(
                    _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                    instance_id=instance_id,
                    requested_identity=requested_identity,
                )
                if not outcome(
                    "recovery_marker_unchanged",
                    _read_support_json(paths.instance_lock_path) == marker,
                    blocked=("recovery_discovery_absent",),
                ) or not outcome(
                    "recovery_discovery_absent",
                    _read_support_json(paths.discovery_path) is None,
                ):
                    raise BootstrapError("Runtime owner changed during discovery recovery.")
                atomic_write_json(paths.discovery_path, dict(recovery))
    if marker is None or marker.get("state") is None:
        _reclaim_stale_owner_locked(paths, boundary)
    discovery = _read_support_json(paths.discovery_path)
    if discovery is not None and discovery.get("active_realm"):
        _compatible(discovery, config, source)
        pid = discovery.get("pid")
        endpoint = str(discovery.get("endpoint", ""))
        instance_id = str(discovery.get("runtime_instance_id", ""))
        if outcome(
            "discovery_owner_alive",
            _owner_may_be_alive(boundary, discovery),
            blocked=(
                "discovery_endpoint_present",
                "discovery_instance_present",
                "discovery_owner_valid",
                "discovery_health",
                "startup_identity",
                "discovery_selected_realm",
            ),
        ):
            if not outcome(
                "discovery_endpoint_present",
                bool(endpoint),
                blocked=("discovery_instance_present",),
            ) or not outcome("discovery_instance_present", bool(instance_id)):
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
            with observation("discovery_owner_read", malformed=(BootstrapError, TypeError, ValueError)):
                valid_owner = boundary.validate_owner(
                    endpoint=endpoint,
                    pid=int(pid),
                    instance_id=instance_id,
                    owner_lock=paths.instance_lock_path,
                    process_birth_id=str(discovery.get("process_birth_id") or ""),
                    expected_realm_id=str(discovery["active_realm"]),
                    expected_realm_root=selected_root,
                )
            if (
                not outcome(
                    "discovery_owner_valid",
                    valid_owner,
                    blocked=(
                        "discovery_root_present",
                        "discovery_root_matches",
                        "discovery_birth_present",
                        "discovery_lock_matches",
                    ),
                )
                or not outcome(
                    "discovery_root_present",
                    selected_root is not None,
                    blocked=(
                        "discovery_root_matches",
                        "discovery_birth_present",
                        "discovery_lock_matches",
                    ),
                )
                or not outcome(
                    "discovery_root_matches",
                    discovered_root == selected_root,
                    blocked=("discovery_birth_present", "discovery_lock_matches"),
                )
                or not outcome(
                    "discovery_birth_present",
                    bool(discovery.get("process_birth_id")),
                    blocked=("discovery_lock_matches",),
                )
                or not outcome(
                    "discovery_lock_matches",
                    _lock_matches(
                        paths,
                        int(pid),
                        instance_id,
                        str(discovery["active_realm"]),
                        str(discovery.get("process_birth_id")),
                        selected_root,
                    ),
                )
            ):
                raise DuplicateOwnerError(
                    "A different runtime owner is active for the selected realm; "
                    "stop it before retrying astrid-runtime up --profile astrid."
                )
            if not outcome("discovery_health", boundary.health(endpoint=endpoint, pid=int(pid), instance_id=instance_id)):
                raise BootstrapError("The selected runtime owner is unhealthy; next action: " + RECONFIGURE_NEXT_ACTION)
            _validated_matching_owner_identity(
                _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                instance_id=instance_id,
                requested_identity=requested_identity,
            )
            if not outcome("discovery_selected_realm", realm is not None and str(realm.get("realm_id")) == str(discovery["active_realm"])):
                raise BootstrapError("Discovery does not match the selected catalog realm; run astrid-runtime doctor.")

            @predicate_chain(
                "reconnect_discovery_unchanged",
                "reconnect_owner_alive",
                "reconnect_owner_valid",
                "reconnect_lock_matches",
                "reconnect_health",
                "reconnect_realm_present",
                "reconnect_realm_matches",
            )
            def validate_reconnect_owner() -> None:
                # Re-run the strict admission checks at each owner-authorized
                # mutation. The diagnostic stream is never used as a fence.
                if (
                    not outcome(
                        "reconnect_discovery_unchanged",
                        _read_support_json(paths.discovery_path) == discovery,
                    )
                    or not outcome(
                        "reconnect_owner_alive",
                        _owner_may_be_alive(boundary, discovery),
                    )
                    or not outcome(
                        "reconnect_owner_valid",
                        boundary.validate_owner(
                            endpoint=endpoint,
                            pid=int(pid),
                            instance_id=instance_id,
                            owner_lock=paths.instance_lock_path,
                            process_birth_id=str(discovery.get("process_birth_id") or ""),
                            expected_realm_id=str(discovery["active_realm"]),
                            expected_realm_root=selected_root,
                        ),
                    )
                    or not outcome(
                        "reconnect_lock_matches",
                        _lock_matches(
                            paths,
                            int(pid),
                            instance_id,
                            str(discovery["active_realm"]),
                            str(discovery.get("process_birth_id")),
                            selected_root,
                        ),
                    )
                    or not outcome(
                        "reconnect_health",
                        boundary.health(endpoint=endpoint, pid=int(pid), instance_id=instance_id),
                    )
                ):
                    raise DuplicateOwnerError("Runtime owner changed during reconnect; refusing mutation.")
                _validated_matching_owner_identity(
                    _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                    instance_id=instance_id,
                    requested_identity=requested_identity,
                )
                current_realm = _selected_realm(_read_catalog(paths))
                if not outcome(
                    "reconnect_realm_present",
                    current_realm is not None,
                ) or not outcome(
                    "reconnect_realm_matches",
                    str(current_realm.get("realm_id")) == str(discovery["active_realm"]),
                ):
                    raise BootstrapError("Runtime selected realm changed during reconnect; refusing mutation.")
                if not outcome(
                    "reconnect_final_discovery", _read_support_json(paths.discovery_path) == discovery
                ) or not outcome("reconnect_final_marker", _read_support_json(paths.instance_lock_path) == marker):
                    raise DuplicateOwnerError("Runtime owner changed during reconnect; refusing mutation.")

            configure = getattr(boundary, "configure_source", None)
            if configure is not None:
                validate_reconnect_owner()
                configure(source)
            validate_reconnect_owner()
            actor_id, token = _credential(paths)
            validate_reconnect_owner()
            connection = boundary.connect(endpoint=endpoint, credential=token)
            realm_id = str(discovery["active_realm"])
            _provision_connection(connection, actor_id, token, realm_id, validate_owner=validate_reconnect_owner)
            realm["source_profile"] = source.profile
            catalog["source_profiles"][source.profile] = source.as_dict()
            _commit_source_profile_metadata(paths, source, catalog, validate_owner=validate_reconnect_owner)
            diagnostics.append("runtime checkout differences are provenance only")
            if config.door is not None and discovery.get("door_origin") != config.door.origin:
                diagnostics.append(
                    f"the running Runtime's browser door serves {discovery.get('door_origin') or 'no hosted page'}; "
                    f"restart it to serve {config.door.origin}"
                )
            worker = _worker_handoff(discovery)
            validate_reconnect_owner()
            _restore_admitted_live_lock(paths, validate_owner=validate_reconnect_owner)
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
        if (
            not outcome(
                "stale_discovery_unchanged",
                _read_support_json(paths.discovery_path) == discovery,
            )
            or not outcome(
                "stale_marker_unchanged",
                _read_support_json(paths.instance_lock_path) == marker,
            )
            or not outcome("stale_owner_absent", not _owner_may_be_alive(boundary, discovery))
            or (
                marker is not None and not outcome("stale_lock_owner_absent", not _owner_may_be_alive(boundary, marker))
            )
        ):
            raise BootstrapError("Runtime owner changed before stale discovery removal.")
        if not outcome(
            "stale_final_discovery_unchanged", _read_support_json(paths.discovery_path) == discovery
        ) or not outcome("stale_final_marker_unchanged", _read_support_json(paths.instance_lock_path) == marker):
            raise BootstrapError("Runtime owner changed before stale discovery removal.")
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

    with owner_phase("startup"):
        realm_id = str(realm["realm_id"])
        realm_root = _canonical_realm_root(str(realm["data_root"]))
        launch_publications = {
            path: _read_support_json(path) for path in (paths.discovery_path, paths.instance_lock_path)
        }

        def validate_launch_absence() -> None:
            for path, expected in launch_publications.items():
                if not outcome("launch_publication_unchanged", _read_support_json(path) == expected):
                    raise DuplicateOwnerError("Runtime owner appeared before launch; refusing mutation.")
                if expected is not None and not outcome(
                    "launch_record_owner_absent",
                    not _owner_may_be_alive(boundary, expected),
                ):
                    raise DuplicateOwnerError("Runtime owner appeared before launch; refusing mutation.")
            if not outcome("launch_realm_owner_absent", not _realm_owner_present(realm_root)):
                raise DuplicateOwnerError("Runtime realm owner appeared before launch; refusing mutation.")
            if not outcome(
                "launch_final_publications",
                all(_read_support_json(path) == expected for path, expected in launch_publications.items()),
            ):
                raise DuplicateOwnerError("Runtime owner appeared before launch; refusing mutation.")

        configure = getattr(boundary, "configure_source", None)
        if configure is not None:
            validate_launch_absence()
            configure(source)
        configure_door = getattr(boundary, "configure_door", None)
        if configure_door is not None:
            # The door acts with the product credential this launcher provisions below.
            validate_launch_absence()
            configure_door(config.door, paths.credentials_dir / "astrid.json")
        # ``realm`` was synthesized above only when the catalog was empty. Keep
        # this explicit ownership bit so rollback can remove only a fresh root.
        credential_path = paths.credentials_dir / "astrid.json"
        credential_before = (
            runtime_platform.read_private_file(credential_path)
            if credential_path.is_file() and not credential_path.is_symlink()
            else None
        )
        source_manifest_path = paths.source_profiles_dir / f"{source.profile}.json"
        source_before = (
            source_manifest_path.read_bytes()
            if source_manifest_path.is_file() and not source_manifest_path.is_symlink()
            else None
        )
        try:
            validate_launch_absence()
            handle = boundary.start(
                realm_id=realm_id,
                realm_root=realm_root,
                owner_lock=paths.instance_lock_path,
                source_profile=source,
            )
        except Exception:
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
            )
            raise
        try:
            with observation("startup_endpoint_parse", malformed=(KeyError, TypeError, ValueError)):
                endpoint = str(handle["endpoint"])
            with observation("startup_pid_parse", malformed=(KeyError, TypeError, ValueError)):
                pid = int(handle["pid"])
            with observation("startup_instance_parse", malformed=(KeyError, TypeError, ValueError)):
                instance_id = str(handle["runtime_instance_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raw_candidate_pid = handle.get("pid") if isinstance(handle, Mapping) else None
            try:
                candidate_pid = int(raw_candidate_pid) if raw_candidate_pid is not None else None
            except (TypeError, ValueError):
                candidate_pid = None
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
                candidate_pid=candidate_pid,
            )
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
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
                candidate_pid=pid,
            )
            raise
        try:
            with observation("startup_health_read"):
                healthy = bool(boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id))
            outcome("startup_health", healthy)
        except Exception:
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
                candidate_pid=pid,
            )
            raise
        if not healthy:
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
                candidate_pid=pid,
            )
            raise BootstrapError("Runtime started but failed health check; next action: " + RECONFIGURE_NEXT_ACTION)
        try:
            owner_identity = _validated_matching_owner_identity(
                _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                instance_id=instance_id,
                requested_identity=requested_identity,
            )
        except BootstrapError:
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
                candidate_pid=pid,
            )
            raise
        worker = _worker_handoff(handle)

        @predicate_chain(
            "startup_publication_matches",
            "startup_realm_present",
            "startup_realm_matches",
            "startup_root_matches",
        )
        def validate_candidate_publications() -> None:
            for path in (paths.discovery_path, paths.instance_lock_path):
                publication = _read_support_json(path)
                if publication is not None and not outcome(
                    "startup_publication_matches",
                    _owner_record_matches(
                        publication,
                        pid=pid,
                        instance_id=instance_id,
                        process_birth_id=process_birth_id,
                        realm_id=realm_id,
                        realm_root=realm_root,
                    ),
                ):
                    raise BootstrapError("Runtime owner changed during startup; refusing mutation.")
            current_realm = _selected_realm(_read_catalog(paths))
            if (
                not outcome(
                    "startup_realm_present",
                    current_realm is not None,
                )
                or not outcome(
                    "startup_realm_matches",
                    str(current_realm.get("realm_id")) == realm_id,
                )
                or not outcome(
                    "startup_root_matches",
                    _canonical_realm_root(str(current_realm.get("data_root") or "")) == realm_root,
                )
            ):
                raise BootstrapError("Runtime selected realm changed during startup; refusing mutation.")

        @predicate_chain("startup_owner_valid", "startup_health")
        def validate_started_owner() -> None:
            validate_candidate_publications()
            if not outcome(
                "startup_owner_valid",
                boundary.validate_owner(
                    endpoint=endpoint,
                    pid=pid,
                    instance_id=instance_id,
                    owner_lock=paths.instance_lock_path,
                    process_birth_id=process_birth_id,
                    expected_realm_id=realm_id,
                    expected_realm_root=realm_root,
                ),
            ) or not outcome(
                "startup_health",
                boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id),
            ):
                raise BootstrapError("Runtime owner changed during startup; refusing mutation.")
            _validated_matching_owner_identity(
                _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                instance_id=instance_id,
                requested_identity=requested_identity,
            )
            validate_candidate_publications()

        # The first lock publication precedes the lock-based strict check, so
        # recheck the already admitted health and startup identity at that boundary.
        try:
            validate_candidate_publications()
            if not outcome("startup_pid_alive", _pid_alive(boundary, pid)):
                raise BootstrapError("Runtime owner changed during startup; refusing mutation.")
            observe_birth = getattr(boundary, "process_birth_identity", None)
            if callable(observe_birth):
                actual_birth = observe_birth(pid)
                if not outcome(
                    "startup_birth_matches",
                    runtime_platform.process_birth_matches(process_birth_id, actual_birth) is True,
                ):
                    raise BootstrapError("Runtime owner changed during startup; refusing mutation.")
            if not outcome(
                "startup_health",
                boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id),
            ):
                raise BootstrapError("Runtime owner changed during startup; refusing mutation.")
            _validated_matching_owner_identity(
                _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
                instance_id=instance_id,
                requested_identity=requested_identity,
            )
            validate_candidate_publications()
            atomic_write_json(
                paths.instance_lock_path,
                {
                    "pid": pid,
                    "process_birth_id": process_birth_id,
                    "runtime_instance_id": instance_id,
                    "realm_id": realm_id,
                    "realm_root": str(realm_root),
                },
            )
            validate_started_owner()
            actor_id, token = _credential(paths)
            validate_started_owner()
            connection = boundary.connect(endpoint=endpoint, credential=token)
            _provision_connection(
                connection,
                actor_id,
                token,
                realm_id,
                validate_owner=validate_started_owner,
            )
        except Exception:
            rollback_failed(
                realm_root=realm_root,
                new_realm=new_realm,
                credential_before=credential_before,
                catalog_before=catalog_before,
                source_before=source_before,
                source_profile=source.profile,
                candidate_pid=pid,
            )
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
            **(
                {
                    "door_endpoint": handle["door_endpoint"],
                    "door_origin": handle["door_origin"],
                }
                if handle.get("door_endpoint")
                else {}
            ),
        }
        try:
            _commit_bootstrap_metadata(
                paths,
                source,
                catalog,
                discovery_value,
                validate_owner=validate_started_owner,
            )
        except Exception:
            rollback_failed(realm_root=realm_root, new_realm=new_realm, credential_before=credential_before, catalog_before=catalog_before, source_before=source_before, source_profile=source.profile, candidate_pid=pid)
            raise
        release = getattr(boundary, "release_owner_custody", None)
        if callable(release):
            # The concrete public CLI boundary always implements this hook. Legacy
            # injected fake boundaries can omit it; they launch no real owner.
            try:
                validate_started_owner()
                release()
            except BootstrapCustodyUncertain:
                # A durable release may have committed. Never signal at the old
                # generation or roll back advertised metadata on an unknown ACK.
                raise
            except Exception:
                rollback_failed(
                    realm_root=realm_root,
                    new_realm=new_realm,
                    credential_before=credential_before,
                    catalog_before=catalog_before,
                    source_before=source_before,
                    source_profile=source.profile,
                    candidate_pid=pid,
                )
                raise
        return BootstrapResult(
            "started",
            realm_id,
            str(realm["display_name"]),
            endpoint,
            actor_id,
            source.profile,
            tuple(diagnostics),
            paths.discovery_path,
            paths.credentials_dir / "astrid.json",
            worker.get("worker_credential_file"),
            worker.get("worker_actor"),
            worker.get("worker_scopes", ()),
            source.source_checkout,
            handle.get("door_origin") if handle.get("door_endpoint") else None,
            handle.get("door_endpoint"),
            instance_id,
        )


@phase_instrument
@predicate_chain(
    "connect_realm_present",
    "connect_discovery_present",
    "connect_pid_parse",
    "connect_endpoint_parse",
    "connect_instance_parse",
    "connect_pid_alive",
    "connect_owner_valid",
    "connect_health",
    "startup_identity_read",
    "startup_identity",
    "connect_selected_realm",
)
def connect(paths: RuntimePaths, boundary: RuntimeBoundary, config: BootstrapConfig | None = None) -> BootstrapResult:
    """Connect without creating a realm or starting authority."""
    config = config or BootstrapConfig()
    _validate_support_paths(paths)
    with observation("admission_catalog_read", malformed=(BootstrapError, TypeError, ValueError)):
        catalog = _read_catalog(paths)
    with observation("admission_realm_read", malformed=(BootstrapError, TypeError, ValueError)):
        realm = _selected_realm(catalog)
    discovery = _read_support_json(paths.discovery_path)
    if not outcome(
        "connect_realm_present",
        realm is not None,
    ) or not outcome("connect_discovery_present", bool(discovery)):
        raise BootstrapError("No healthy selected runtime. Next action: astrid-runtime up --profile astrid")
    with observation("admission_source_read", malformed=(BootstrapError, TypeError, ValueError)):
        source = config.resolve_source_profile(paths)
    _compatible(discovery, config, source)
    requested_identity = _capture_requested_identity(source)
    try:
        with observation("connect_pid_parse", malformed=(KeyError, TypeError, ValueError)):
            pid = int(discovery["pid"])
        with observation(
            "connect_endpoint_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            endpoint = _validate_loopback_endpoint(str(discovery["endpoint"]))
        with observation("connect_instance_parse", malformed=(KeyError, TypeError, ValueError)):
            instance_id = str(discovery["runtime_instance_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("Runtime discovery is incomplete; run astrid-runtime restart --profile astrid.") from exc
    if not outcome("connect_pid_alive", _pid_alive(boundary, pid)):
        unavailable("connect_owner_valid", depends_on="connect_pid_alive")
        raise BootstrapError("Runtime discovery is stale or owned by another process; run astrid-runtime up --profile astrid.")
    if not outcome("connect_owner_valid", boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id=instance_id, owner_lock=paths.instance_lock_path)):
        raise BootstrapError("Runtime discovery is stale or owned by another process; run astrid-runtime up --profile astrid.")
    if not outcome("connect_health", boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id)):
        raise BootstrapError("The selected runtime is unhealthy; run astrid-runtime restart --profile astrid.")
    _validated_matching_owner_identity(
        _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
        instance_id=instance_id,
        requested_identity=requested_identity,
    )
    if not outcome("connect_selected_realm", str(realm.get("realm_id")) == str(discovery.get("active_realm"))):
        raise BootstrapError("Discovery does not match the selected catalog realm; run astrid-runtime doctor.")

    @predicate_chain(
        "connect_discovery_unchanged",
        "connect_pid_alive",
        "connect_owner_valid",
        "connect_health",
        "connect_realm_present",
        "connect_selected_realm",
    )
    def validate_connect_owner() -> None:
        if (
            not outcome(
                "connect_discovery_unchanged",
                _read_support_json(paths.discovery_path) == discovery,
            )
            or not outcome(
                "connect_pid_alive",
                _pid_alive(boundary, pid),
            )
            or not outcome(
                "connect_owner_valid",
                boundary.validate_owner(
                    endpoint=endpoint,
                    pid=pid,
                    instance_id=instance_id,
                    owner_lock=paths.instance_lock_path,
                ),
            )
            or not outcome(
                "connect_health",
                boundary.health(endpoint=endpoint, pid=pid, instance_id=instance_id),
            )
        ):
            raise BootstrapError("Runtime owner changed during connection; refusing mutation.")
        _validated_matching_owner_identity(
            _owner_identity_health(boundary, endpoint=endpoint, instance_id=instance_id),
            instance_id=instance_id,
            requested_identity=requested_identity,
        )
        current_realm = _selected_realm(_read_catalog(paths))
        if not outcome(
            "connect_realm_present",
            current_realm is not None,
        ) or not outcome(
            "connect_selected_realm",
            str(current_realm.get("realm_id")) == str(discovery.get("active_realm")),
        ):
            raise BootstrapError("Runtime selected realm changed during connection; refusing mutation.")
        if not outcome("connect_final_discovery", _read_support_json(paths.discovery_path) == discovery):
            raise BootstrapError("Runtime owner changed during connection; refusing mutation.")

    validate_connect_owner()
    actor_id, token = _credential(paths)
    validate_connect_owner()
    connection = boundary.connect(endpoint=endpoint, credential=token)
    _provision_connection(connection, actor_id, token, str(realm["realm_id"]), validate_owner=validate_connect_owner)
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


@instrument
@predicate_chain(
    "owner_record_present",
    "owner_record_root_readable",
    "owner_record_pid",
    "owner_record_instance",
    "owner_record_birth",
    "owner_record_realm",
    "owner_record_root",
)
def _owner_record_matches(
    value: Mapping[str, Any] | None, *, pid: int, instance_id: str,
    process_birth_id: str, realm_id: str, realm_root: Path,
) -> bool:
    if not outcome("owner_record_present", bool(value)):
        return False
    try:
        recorded_root = _canonical_realm_root(str(value.get("realm_root") or ""))
        outcome("owner_record_root_readable", True)
    except BootstrapError:
        outcome("owner_record_root_readable", False)
        return False
    return bool(
        outcome("owner_record_pid", str(value.get("pid")) == str(pid))
        and outcome("owner_record_instance", str(value.get("runtime_instance_id")) == instance_id)
        and outcome("owner_record_birth", str(value.get("process_birth_id")) == process_birth_id)
        and outcome("owner_record_realm", str(value.get("active_realm") or value.get("realm_id")) == realm_id)
        and outcome("owner_record_root", recorded_root == realm_root)
    )


@predicate_chain(
    "handoff_path_absolute",
    "handoff_path_no_symlink",
    "handoff_leaf_no_symlink",
    "handoff_file_present",
    "handoff_file_regular",
    "handoff_file_owned",
)
def _private_handoff_bytes(path: Path) -> bytes:
    """Read an owner-owned, canonical regular file used to bind Pinokio state."""
    target = Path(path).expanduser()
    if (
        not outcome("handoff_path_absolute", not (not target.is_absolute()))
        or not outcome("handoff_path_no_symlink", not (_has_symlink_component(target)))
        or not outcome("handoff_leaf_no_symlink", not (target.is_symlink()))
        or not outcome("handoff_file_present", not (not target.is_file()))
    ):
        raise BootstrapError(f"Pinokio stop binding is missing or unsafe: {target}")
    try:
        if runtime_platform.sys.platform == "win32":
            raw = runtime_platform.read_private_file(target)
        else:
            fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                metadata = os.fstat(fd)
                if not outcome("handoff_file_regular", not (not stat.S_ISREG(metadata.st_mode))) or not outcome(
                    "handoff_file_owned", not (not runtime_platform.is_current_user(metadata))
                ):
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


@predicate_chain("handoff_json_parse", "handoff_json_object")
def _private_handoff_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _private_handoff_bytes(path)
    try:
        with observation("handoff_json_parse", malformed=(UnicodeDecodeError, json.JSONDecodeError)):
            value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"Pinokio stop binding is malformed: {path}") from exc
    if not outcome("handoff_json_object", not (not isinstance(value, dict))):
        raise BootstrapError(f"Pinokio stop binding must be an object: {path}")
    return raw, value


@predicate_chain(
    "handoff_value_string",
    "handoff_value_present",
    "handoff_value_absolute",
    "handoff_value_no_symlink",
    "handoff_value_leaf_no_symlink",
    "handoff_value_canonical",
)
def _canonical_handoff_path(value: Any, *, label: str, directory: bool | None = None) -> Path:
    if not outcome("handoff_value_string", not (not isinstance(value, str))) or not outcome(
        "handoff_value_present", not (not value)
    ):
        raise BootstrapError(f"Pinokio stop binding has no {label}.")
    raw = Path(value).expanduser()
    if (
        not outcome("handoff_value_absolute", not (not raw.is_absolute()))
        or not outcome("handoff_value_no_symlink", not (_has_symlink_component(raw)))
        or not outcome("handoff_value_leaf_no_symlink", not (raw.is_symlink()))
    ):
        raise BootstrapError(f"Pinokio stop binding {label} is not absolute and symlink-free.")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise BootstrapError(f"Pinokio stop binding {label} is unavailable.") from exc
    if not outcome("handoff_value_canonical", not (resolved != raw)):
        raise BootstrapError(f"Pinokio stop binding {label} is not canonical.")
    if directory is True and not outcome("handoff_value_directory", resolved.is_dir()):
        raise BootstrapError(f"Pinokio stop binding {label} is not a directory.")
    if directory is False and not outcome("handoff_value_regular", resolved.is_file()):
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
    with observation("binding_catalog_parse", malformed=(BootstrapError, TypeError, ValueError)):
        catalog = _read_catalog(paths)
    profiles = catalog.get("source_profiles", {})
    raw_profile = profiles.get("astrid") if isinstance(profiles, Mapping) else None
    managed_by_env = outcome("binding_environment_pinokio", os.environ.get("ASTRID_INSTALL_MANAGED_BY") == "pinokio")
    selection_path = _install_record_path(Path(paths.home))
    selected = None
    selection_error = None
    if outcome("binding_selection_present", os.path.lexists(str(selection_path))):
        try:
            with observation(
                "binding_selection_raw_selected_parse",
                malformed=(BootstrapError, TypeError, ValueError),
            ):
                _selection_raw, selected = _private_handoff_json(selection_path)
        except BootstrapError as exc:
            selection_error = exc
    selected_pinokio = bool(
        outcome(
            "binding_selection_object",
            isinstance(selected, Mapping),
            blocked=("binding_selection_owner", "binding_selection_managed"),
        )
        and outcome(
            "binding_selection_owner",
            selected.get("owner") == INSTALL_RECORD_OWNER,
            blocked=("binding_selection_managed",),
        )
        and outcome("binding_selection_managed", selected.get("managed_by") == "pinokio")
    )
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
    if outcome("binding_raw_profile_object", isinstance(raw_profile, Mapping)):
        try:
            source = SourceProfile.from_mapping(raw_profile, expected_profile="astrid")
        except BootstrapError as exc:
            source_error = exc
    owner_pinokio = False
    owner_version_error = None
    if source is not None and source.runtime_environment:
        try:
            with observation(
                "binding_candidate_environment_parse",
                malformed=(BootstrapError, TypeError, ValueError),
            ):
                candidate_environment = _canonical_handoff_path(
                    source.runtime_environment,
                    label="runtime environment",
                    directory=True,
                )
            with observation(
                "binding_candidate_version_root_parse",
                malformed=(BootstrapError, TypeError, ValueError),
            ):
                candidate_version_root = _canonical_handoff_path(
                    str(candidate_environment.parent),
                    label="owner Version root",
                    directory=True,
                )
            with observation(
                "binding_owner_version_raw_owner_version_probe_parse",
                malformed=(BootstrapError, TypeError, ValueError),
            ):
                _owner_version_raw, owner_version_probe = _private_handoff_json(
                    candidate_version_root / "version.json",
                )
            owner_identity_probe = owner_version_probe.get("identity")
            owner_pinokio = outcome(
                "binding_probe_identity_object",
                isinstance(owner_identity_probe, Mapping),
                blocked=("binding_probe_management",),
            ) and outcome("binding_probe_management", owner_identity_probe.get("managed_by") == "pinokio")
        except BootstrapError as exc:
            owner_version_error = exc
    candidate_pinokio = outcome("binding_candidate_pinokio", managed_by_env or selected_for_data or owner_pinokio)
    if not candidate_pinokio:
        # Service-backed source profiles can belong to other Runtime users;
        # only selected records for this data root or a Pinokio Version prove
        # that this Runtime is part of a Pinokio installation.
        return None
    if not outcome("binding_profile_readable", source_error is None):
        raise source_error
    if not outcome("binding_profile_present", source is not None):
        raise BootstrapError("Runtime Pinokio stop binding is missing the selected source profile.")
    if not outcome("binding_selection_readable", selection_error is None):
        raise selection_error
    if not outcome("binding_selection_matches_data", selected_for_data):
        raise BootstrapError("Runtime Pinokio stop binding has no selected install record for this data root.")
    if not outcome("binding_service_present", source.service_declaration):
        raise BootstrapError("Runtime Pinokio stop binding has no selected service declaration.")
    if not outcome(
        "binding_owner_version_readable",
        not (owner_version_error is not None and (not owner_pinokio)),
    ):
        # Selected Pinokio metadata remains sufficient to make malformed or
        # missing Version composition a fail-closed refusal.
        raise owner_version_error
    if not outcome("binding_environment_present", source.runtime_environment):
        raise BootstrapError("Runtime Pinokio stop binding has no selected interpreter environment.")

    with observation("binding_environment_parse", malformed=(BootstrapError, TypeError, ValueError)):
        environment = _canonical_handoff_path(
            source.runtime_environment,
            label="runtime environment",
            directory=True,
        )
    with observation(
        "binding_owner_version_root_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        owner_version_root = _canonical_handoff_path(
            str(environment.parent),
            label="Version root",
            directory=True,
        )
    with observation("binding_program_root_parse", malformed=(BootstrapError, TypeError, ValueError)):
        program_root = _canonical_handoff_path(
            str(owner_version_root.parent.parent),
            label="program root",
            directory=True,
        )
    if not outcome(
        "binding_owner_version_parent",
        owner_version_root.parent == program_root / "versions",
    ):
        raise BootstrapError("Runtime Pinokio owner Version is outside the selected program root.")
    with observation(
        "binding_runtime_checkout_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        runtime_checkout = _canonical_handoff_path(
            source.runtime_checkout,
            label="Runtime checkout",
            directory=True,
        )
    with observation(
        "binding_source_checkout_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        source_checkout = _canonical_handoff_path(
            source.source_checkout,
            label="Agent checkout",
            directory=True,
        )
    with observation("binding_declaration_parse", malformed=(BootstrapError, TypeError, ValueError)):
        declaration = _canonical_handoff_path(
            source.service_declaration,
            label="service declaration",
            directory=False,
        )

    current_path = program_root / "current"
    with observation("binding_current_raw_parse", malformed=(BootstrapError, TypeError, ValueError)):
        current_raw = _private_handoff_bytes(current_path)
    version_name = current_raw.decode("utf-8").strip()
    if not outcome(
        "binding_current_version_format",
        re.fullmatch("[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version_name),
    ):
        raise BootstrapError("Runtime Pinokio stop binding has an invalid selected Version pointer.")
    with observation(
        "binding_selected_version_root_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        selected_version_root = _canonical_handoff_path(
            str(program_root / "versions" / version_name),
            label="selected Version root",
            directory=True,
        )

    with observation(
        "binding_marker_raw_install_marker_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        _marker_raw, install_marker = _private_handoff_json(program_root / "install.json")
    with observation("binding_expected_root_parse", malformed=(BootstrapError, TypeError, ValueError)):
        expected_root = _canonical_realm_root(str(realm.get("data_root") or ""))
    realm_id = str(realm.get("realm_id") or "")
    if (
        not outcome(
            "binding_selection_owner",
            selected.get("owner") == INSTALL_RECORD_OWNER,
            blocked=(
                "binding_selection_managed",
                "binding_selection_program",
                "binding_selection_data",
                "binding_selection_realm",
                "binding_selection_root",
            ),
        )
        or not outcome(
            "binding_selection_managed",
            selected.get("managed_by") == "pinokio",
            blocked=(
                "binding_selection_program",
                "binding_selection_data",
                "binding_selection_realm",
                "binding_selection_root",
            ),
        )
        or not outcome(
            "binding_selection_program",
            _canonical_handoff_path(
                selected.get("program_root"),
                label="selection program root",
                directory=True,
            )
            == program_root,
            blocked=(
                "binding_selection_data",
                "binding_selection_realm",
                "binding_selection_root",
            ),
        )
        or not outcome(
            "binding_selection_data",
            _canonical_handoff_path(selected.get("data_root"), label="selection data root", directory=True)
            == paths.app_support,
            blocked=("binding_selection_realm", "binding_selection_root"),
        )
        or not outcome(
            "binding_selection_realm",
            str(selected.get("realm_id") or "") == realm_id,
            blocked=("binding_selection_root",),
        )
        or not outcome(
            "binding_selection_root",
            _canonical_handoff_path(selected.get("realm_root"), label="selection realm root", directory=True)
            == expected_root,
        )
    ):
        raise BootstrapError("Runtime Pinokio stop binding conflicts with the selected install record.")
    if (
        not outcome(
            "binding_install_owner",
            install_marker.get("owner") == INSTALL_RECORD_OWNER,
            blocked=("binding_install_managed", "binding_install_data"),
        )
        or not outcome(
            "binding_install_managed",
            install_marker.get("managed_by") == "pinokio",
            blocked=("binding_install_data",),
        )
        or not outcome(
            "binding_install_data",
            _canonical_handoff_path(
                install_marker.get("data_root"),
                label="install marker data root",
                directory=True,
            )
            == paths.app_support,
        )
    ):
        raise BootstrapError("Runtime Pinokio stop binding conflicts with the program install marker.")

    def read_version(root: Path, *, label: str) -> tuple[bytes, dict[str, Any], dict[str, Any], bytes, Path]:
        with observation(
            "binding_version_raw_version_parse",
            malformed=(BootstrapError, TypeError, ValueError),
        ):
            version_raw, version = _private_handoff_json(root / "version.json")
        if not outcome(
            "binding_version_root",
            _canonical_handoff_path(version.get("root"), label=f"{label} root", directory=True) == root,
        ):
            raise BootstrapError(f"Runtime Pinokio stop binding has a conflicting {label} record.")
        identity = version.get("identity")
        if (
            not outcome(
                "binding_version_identity_object",
                isinstance(identity, Mapping),
                blocked=(
                    "binding_version_management",
                    "binding_version_release_integer",
                    "binding_version_release_nonnegative",
                ),
            )
            or not outcome(
                "binding_version_management",
                identity.get("managed_by") == "pinokio",
                blocked=(
                    "binding_version_release_integer",
                    "binding_version_release_nonnegative",
                ),
            )
            or not outcome(
                "binding_version_release_integer",
                type(identity.get("release")) is int,
                blocked=("binding_version_release_nonnegative",),
            )
            or not outcome("binding_version_release_nonnegative", identity["release"] >= 0)
        ):
            raise BootstrapError(f"Runtime Pinokio stop binding has no Pinokio {label} identity.")
        with observation(
            "binding_profile_path_parse",
            malformed=(BootstrapError, TypeError, ValueError),
        ):
            profile_path = _canonical_handoff_path(version.get("profile"), label=f"{label} profile", directory=False)
        with observation(
            "binding_profile_raw_profile_parse",
            malformed=(BootstrapError, TypeError, ValueError),
        ):
            profile_raw, profile = _private_handoff_json(profile_path)
        if not outcome("binding_version_profile", profile.get("profile") == "astrid"):
            raise BootstrapError(f"Runtime Pinokio stop binding has a non-Astrid {label} profile.")
        return version_raw, version, dict(identity), profile_raw, profile_path

    owner_version_raw, owner_version, owner_identity, profile_raw, owner_profile_path = read_version(
        owner_version_root, label="owner Version",
    )
    _selected_version_raw, selected_version, selected_identity, _selected_profile_raw, selected_profile_path = read_version(
        selected_version_root, label="selected Version",
    )
    if not outcome("binding_selected_identity", selected.get("identity") == selected_identity):
        raise BootstrapError("Runtime Pinokio stop binding conflicts with the selected Version identity.")
    raw_python = owner_version.get("python")
    python_path = Path(raw_python).expanduser() if isinstance(raw_python, str) else Path()
    if (
        not outcome(
            "binding_python_absolute",
            python_path.is_absolute(),
            blocked=(
                "binding_python_parent_no_symlink",
                "binding_python_environment",
                "binding_python_file",
            ),
        )
        or not outcome(
            "binding_python_parent_no_symlink",
            not _has_symlink_component(python_path.parent),
            blocked=("binding_python_environment", "binding_python_file"),
        )
        or not outcome(
            "binding_python_environment",
            python_path.parent.resolve() in {environment / "bin", environment / "Scripts"},
            blocked=("binding_python_file",),
        )
        or not outcome("binding_python_file", python_path.is_file())
    ):
        raise BootstrapError("Runtime Pinokio stop binding interpreter escapes its environment.")
    raw_selected_python = selected_version.get("python")
    selected_python = Path(raw_selected_python).expanduser() if isinstance(raw_selected_python, str) else Path()
    if (
        not outcome(
            "binding_selected_python_absolute",
            selected_python.is_absolute(),
            blocked=(
                "binding_selected_python_no_symlink",
                "binding_selected_python_file",
            ),
        )
        or not outcome(
            "binding_selected_python_no_symlink",
            not _has_symlink_component(selected_python.parent),
            blocked=("binding_selected_python_file",),
        )
        or not outcome("binding_selected_python_file", selected_python.is_file())
    ):
        raise BootstrapError("Runtime Pinokio selected interpreter is missing or unsafe.")
    selected_environment = selected_python.parent.parent
    if not outcome("binding_selected_environment_directory", selected_environment.is_dir()):
        raise BootstrapError("Runtime Pinokio selected interpreter environment is unavailable.")
    with observation(
        "binding__version_profile_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        _, version_profile = _private_handoff_json(owner_profile_path)
    with observation(
        "binding__selected_profile_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        _, selected_profile = _private_handoff_json(selected_profile_path)
    if not outcome(
        "binding_selected_profile_environment",
        selected_profile.get("runtime_environment") == str(selected_environment),
    ):
        raise BootstrapError("Runtime Pinokio selected profile differs from its interpreter environment.")
    for key, expected in (("runtime_checkout", str(runtime_checkout)),
                          ("source_checkout", str(source_checkout)),
                          ("runtime_environment", str(environment)),
                          ("service_declaration", str(declaration))):
        if not outcome("binding_version_profile_" + key, version_profile.get(key) == expected):
            raise BootstrapError("Runtime Pinokio stop binding differs from the selected Version profile.")
    if not outcome(
        "binding_version_source_digest",
        version_profile.get("source_digest", "") == source.source_digest,
    ):
        raise BootstrapError("Runtime Pinokio stop binding source digest differs from the selected Version profile.")
    with observation(
        "binding_declaration_raw_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
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


def _retire_owner_marker(paths: RuntimePaths, marker: Mapping[str, Any] | None) -> None:
    observed = _read_support_json(paths.instance_lock_path)
    if observed is None:
        return
    if not outcome("retire_marker_unchanged", observed == marker):
        raise BootstrapError("Runtime owner marker changed before retirement.")
    _durable_remove(paths.instance_lock_path)


@predicate_chain("owner_absent_pid", "owner_absent_birth_read", "owner_absent_birth")
def _require_owner_absent(boundary: RuntimeBoundary, pid: int, birth: str, *, context: str) -> None:
    try:
        if not outcome("owner_absent_pid", not _pid_alive(boundary, pid)):
            raise BootstrapError(f"Runtime Pinokio stopped owner is still present {context}.")
        observe_birth = getattr(boundary, "process_birth_identity", None)
        if callable(observe_birth):
            with observation("owner_absent_birth_read"):
                observed_birth = observe_birth(pid)
            if not outcome("owner_absent_birth", observed_birth is None):
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
    if not outcome(
        "completed_binding_present",
        binding is not None,
        blocked=("completed_binding_matches",),
    ) or not outcome("completed_binding_matches", dict(receipt["binding"]) == dict(binding)):
        # A changed selection must permanently retire this lifetime; otherwise
        # a later filesystem revert could make old evidence useful again.
        _retire_owner_marker(paths, marker)
        raise BootstrapError("Runtime Pinokio completed-stop binding changed; refusing interruption.")
    if not outcome(
        "completed_data_matches",
        str(owner.get("data_root") or "") == str(paths.app_support),
    ):
        _retire_owner_marker(paths, marker)
        raise BootstrapError("Runtime Pinokio completed-stop data root changed; refusing interruption.")
    return {**owner, "binding": dict(binding)}


@_observe_validation("completed_stop_marker")
@predicate_chain(
    "completed_marker_fields",
    "completed_receipt_object",
    "completed_receipt_fields",
    "completed_version_integer",
    "completed_version_supported",
    "completed_binding_object",
    "completed_binding_keys",
    "completed_pid_integer",
    "completed_pid_positive",
    "completed_birth_string",
    "completed_instance_string",
    "completed_realm_string",
    "completed_root_string",
    "completed_data_string",
    "completed_owner_strings",
    "completed_root_parse",
    "completed_realm_root_parse",
    "completed_data_parse",
    "completed_owner_matches",
)
def _validate_completed_stop_marker(marker: Mapping[str, Any]) -> dict[str, Any]:
    receipt = marker.get("completed_stop")
    if (
        not outcome(
            "completed_marker_fields",
            set(marker)
            == {
                "pid",
                "process_birth_id",
                "runtime_instance_id",
                "realm_id",
                "realm_root",
                "data_root",
                "state",
                "completed_stop",
            },
        )
        or not outcome(
            "completed_receipt_object",
            isinstance(receipt, Mapping),
        )
        or not outcome(
            "completed_receipt_fields",
            set(receipt) == {"version", "binding"},
        )
        or not outcome(
            "completed_version_integer",
            type(receipt.get("version")) is int,
        )
        or not outcome(
            "completed_version_supported",
            receipt.get("version") == PINOKIO_STOP_HANDOFF_VERSION,
        )
        or not outcome(
            "completed_binding_object",
            isinstance(receipt.get("binding"), Mapping),
        )
        or not outcome(
            "completed_binding_keys",
            set(receipt["binding"]) == PINOKIO_STOP_BINDING_KEYS,
        )
    ):
        raise BootstrapError("Runtime Pinokio completed-stop marker is malformed; refusing interruption.")
    owner = dict(marker)
    pid = owner.get("pid")
    birth = owner.get("process_birth_id")
    instance = owner.get("runtime_instance_id")
    realm_id = owner.get("realm_id")
    realm_root_raw = owner.get("realm_root")
    data_root = owner.get("data_root")
    if (
        not outcome(
            "completed_pid_integer",
            type(pid) is int,
        )
        or not outcome("completed_pid_positive", pid > 0)
        or not outcome(
            "completed_owner_strings",
            not any(
                (
                    not outcome(
                        "completed_" + key + "_string",
                        isinstance(value, str) and bool(value),
                    )
                    for key, value in (
                        ("birth", birth),
                        ("instance", instance),
                        ("realm", realm_id),
                        ("root", realm_root_raw),
                        ("data", data_root),
                    )
                )
            ),
        )
    ):
        raise BootstrapError("Runtime Pinokio completed-stop owner identity is malformed.")
    try:
        with observation("completed_root_parse", malformed=(BootstrapError,)):
            with observation(
                "completed_realm_root_parse",
                malformed=(BootstrapError, TypeError, ValueError),
            ):
                realm_root = _canonical_realm_root(realm_root_raw)
        with observation("completed_data_parse", malformed=(BootstrapError,)):
            _canonical_handoff_path(data_root, label="completed-stop data root", directory=True)
    except BootstrapError as exc:
        raise BootstrapError("Runtime Pinokio completed-stop owner identity is malformed.") from exc
    if not outcome(
        "completed_owner_matches",
        _owner_record_matches(
            owner,
            pid=pid,
            instance_id=instance,
            process_birth_id=birth,
            realm_id=realm_id,
            realm_root=realm_root,
        ),
    ):
        raise BootstrapError("Runtime Pinokio completed-stop owner identity is malformed.")
    _validate_binding_fields(receipt["binding"])
    return owner


@_observe_validation("binding_fields")
def _validate_binding_fields(binding: Mapping[str, Any]) -> None:
    for key, value in binding.items():
        if key.endswith("_sha256"):
            if not outcome("binding_" + key + "_string", isinstance(value, str)) or not outcome(
                "binding_" + key + "_digest", bool(re.fullmatch(r"[0-9a-f]{64}", value))
            ):
                raise BootstrapError("Runtime Pinokio completed-stop binding digest is malformed.")
        elif key.endswith("_release"):
            if not outcome("binding_" + key + "_integer", type(value) is int) or not outcome(
                "binding_" + key + "_nonnegative", value >= 0
            ):
                raise BootstrapError("Runtime Pinokio completed-stop binding release is malformed.")
        elif not outcome("binding_" + key + "_string", isinstance(value, str) and bool(value)):
            raise BootstrapError("Runtime Pinokio completed-stop binding field is malformed.")


@_observe_validation("stopping_marker")
@predicate_chain(
    "stopping_marker_fields",
    "stopping_marker_state",
    "stopping_discovery_object",
    "stopping_intent_object",
    "stopping_intent_fields",
    "stopping_version_integer",
    "stopping_version_supported",
    "stopping_binding_object",
    "stopping_binding_keys",
    "stopping_pid_integer",
    "stopping_pid_positive",
    "stopping_process_birth_id_string",
    "stopping_runtime_instance_id_string",
    "stopping_realm_id_string",
    "stopping_realm_root_string",
    "stopping_data_root_string",
    "stopping_owner_strings",
    "stopping_root_parse",
)
def _validate_stopping_marker(marker: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the Runtime-written intent form of instance.lock.

    C1 writes it inside the final fence, before the first signal. It is
    evidence only that C1 admitted and was stopping this exact owner; it is
    never live health or discovery.
    """
    intent = marker.get("stopping")
    required = {"pid", "process_birth_id", "runtime_instance_id", "realm_id",
                "realm_root", "data_root", "state", "stopping"}
    if (
        not outcome(
            "stopping_marker_fields",
            set(marker) in (required, required | {"discovery"}),
        )
        or not outcome(
            "stopping_marker_state",
            marker.get("state") == "stopping",
        )
        or not outcome(
            "stopping_discovery_object",
            not ("discovery" in marker and (not isinstance(marker["discovery"], Mapping))),
        )
        or not outcome(
            "stopping_intent_object",
            isinstance(intent, Mapping),
        )
        or not outcome(
            "stopping_intent_fields",
            set(intent) == {"version", "binding"},
        )
        or not outcome(
            "stopping_version_integer",
            type(intent.get("version")) is int,
        )
        or not outcome(
            "stopping_version_supported",
            intent.get("version") == PINOKIO_STOP_HANDOFF_VERSION,
        )
    ):
        raise BootstrapError("Runtime owner stopping marker is malformed; refusing interruption.")
    binding = intent.get("binding")
    if binding is not None:
        if not outcome(
            "stopping_binding_object",
            isinstance(binding, Mapping),
        ) or not outcome("stopping_binding_keys", set(binding) == PINOKIO_STOP_BINDING_KEYS):
            raise BootstrapError("Runtime owner stopping marker is malformed; refusing interruption.")
        _validate_binding_fields(binding)
    owner = dict(marker)
    pid = owner.get("pid")
    if (
        not outcome(
            "stopping_pid_integer",
            type(pid) is int,
        )
        or not outcome("stopping_pid_positive", pid > 0)
        or not outcome(
            "stopping_owner_strings",
            not any(
                (
                    not outcome(
                        "stopping_" + key + "_string",
                        isinstance(owner.get(key), str) and bool(owner[key]),
                    )
                    for key in (
                        "process_birth_id",
                        "runtime_instance_id",
                        "realm_id",
                        "realm_root",
                        "data_root",
                    )
                )
            ),
        )
    ):
        raise BootstrapError("Runtime owner stopping marker identity is malformed.")
    try:
        with observation("stopping_root_parse", malformed=(BootstrapError,)):
            _canonical_realm_root(owner["realm_root"])
    except BootstrapError as exc:
        raise BootstrapError("Runtime owner stopping marker identity is malformed.") from exc
    return owner


def _revoke_completed_stop_before_launch(
    paths: RuntimePaths, boundary: RuntimeBoundary, realm: Mapping[str, Any],
) -> dict[str, Any] | None:
    marker = _read_support_json(paths.instance_lock_path)
    if not outcome("launch_marker_present", marker is not None):
        return None
    if outcome("launch_marker_live", marker.get("state") is None):
        return None
    if outcome("launch_marker_stopping", marker.get("state") == "stopping"):
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
        _retire_owner_marker(paths, marker)
        return None
    if not outcome("launch_marker_completed", marker.get("state") == "completed_stop"):
        raise BootstrapError("Runtime owner lock has an unknown state; launch refused.")
    try:
        owner = _validate_completed_stop_marker(marker)
    except (KeyError, TypeError, ValueError, BootstrapError):
        _retire_owner_marker(paths, marker)
        raise BootstrapError("Runtime Pinokio completed-stop marker is malformed; launch refused.")
    if not outcome(
        "completed_data_matches",
        str(owner.get("data_root") or "") == str(paths.app_support),
    ):
        _retire_owner_marker(paths, marker)
        raise BootstrapError("Runtime Pinokio completed-stop data root changed; launch refused.")
    discovery = _read_support_json(paths.discovery_path)
    if discovery is not None:
        _retire_owner_marker(paths, marker)
        raise _pinokio_stop_refusal("Runtime Pinokio completed-stop marker conflicts with a published owner.")
    try:
        _require_owner_absent(
            boundary, int(owner["pid"]), str(owner["process_birth_id"]),
            context="before launch",
        )
    except BootstrapError as exc:
        _retire_owner_marker(paths, marker)
        raise _pinokio_stop_refusal(str(exc)) from exc
    # This is intentionally before boundary.start. Only a later C1 cleanup
    # that proves this attempt ended before publication can re-attest it.
    _retire_owner_marker(paths, marker)
    return dict(marker)


def _restore_admitted_live_lock(paths: RuntimePaths, *, validate_owner=None) -> None:
    """Return a stopping intent, admitted for reconnect, to the live lock form."""
    marker = _read_support_json(paths.instance_lock_path)
    if marker is None or marker.get("state") != "stopping":
        return
    owner = _validate_stopping_marker(marker)
    live = {
        key: owner[key] for key in (
            "pid", "process_birth_id", "runtime_instance_id", "realm_id", "realm_root",
        )
    }
    if "discovery" in owner:
        live["discovery"] = owner["discovery"]
    if validate_owner is not None:
        validate_owner()
    if not outcome(
        "restore_live_marker_unchanged",
        _read_support_json(paths.instance_lock_path) == marker,
    ):
        raise BootstrapError("Runtime owner changed before live-lock restoration.")
    atomic_write_json(paths.instance_lock_path, live)


@contextmanager
def _downstream_stop_errors():
    """Keep post-admission failure details from looking like lifecycle refusal."""
    try:
        yield
    except ConflictError as exc:
        outcome("stop_downstream", None, error=True)
        error = _raise_conflict(exc)
        details = {"cause_details": dict(error.details)} if error.details else None
        raise BootstrapError(str(error), details=details) from exc
    except BootstrapError as exc:
        outcome("stop_downstream", None, error=True)
        if not exc.details:
            raise
        raise BootstrapError(
            str(exc), details={"cause_details": dict(exc.details)},
        ) from exc
    except Exception as exc:
        outcome("stop_downstream", None, error=True)
        inherited = getattr(exc, "details", None)
        if not isinstance(inherited, Mapping) or not inherited:
            raise
        raise BootstrapError(
            str(exc), details={"cause_details": dict(inherited)},
        ) from exc


@phase_instrument
def _fenced_stop_and_manager(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    *,
    realm_id: str,
    realm_root: Path,
    discovery: Mapping[str, Any] | None,
    marker: Mapping[str, Any] | None,
    owner: tuple[int, str, str, str] | None,
    stop_manager=None,
    stop_foreground=None,
    validate_stop=None,
    stale_owner_identity=None,
    allow_missing_realm: bool = False,
    completed_stop_binding: Mapping[str, Any] | None = None,
    retained_completed_stop: Mapping[str, Any] | None = None,
    validate_cleanup_context=None,
) -> dict[str, Any]:
    """Stop an admitted owner and its manager while the caller holds the mutex."""
    try:
        fence = (nullcontext({"safe": True, "realm_absent": True})
                 if allow_missing_realm else interruption_fence(realm_root))
        with fence as final_report:
            if not outcome(
                "stop_realm_owner_absent",
                not (owner is None and (not allow_missing_realm) and _realm_owner_present(realm_root)),
            ):
                raise BootstrapError(
                    "Runtime interruption refused: the realm owner is still active; "
                    "run astrid-runtime up --profile astrid to recover discovery."
                )
            try:
                final_discovery = _read_support_json(paths.discovery_path)
                final_marker = _read_support_json(paths.instance_lock_path)
            except Exception:
                raise
            if not outcome("stop_discovery_unchanged", final_discovery == discovery):
                raise BootstrapError("Runtime discovery changed before stop; refusing interruption.")
            if not outcome("stop_marker_unchanged", final_marker == marker):
                raise BootstrapError("Runtime owner lock changed before stop; refusing interruption.")
            if validate_stop is not None:
                validate_stop()
            if stale_owner_identity is not None:
                stale_pid, stale_birth = stale_owner_identity
                try:
                    if not outcome("stop_stale_pid_absent", not _pid_alive(boundary, stale_pid)):
                        raise BootstrapError(
                            "Runtime interruption refused: stale owner process is present at the final fence."
                        )
                    observe_birth = getattr(boundary, "process_birth_identity", None)
                    if callable(observe_birth):
                        observed_birth = observe_birth(stale_pid)
                        if not outcome("stop_stale_birth_absent", observed_birth is None):
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
                    if not outcome("stop_owner_callable", callable(stop_owner)):
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
                    # Preserve the owner's recovery snapshot across a refused stop.
                    if final_marker is not None and "discovery" in final_marker:
                        intent["discovery"] = final_marker["discovery"]
                    if final_marker != intent:
                        _validate_stop_endpoint(
                            paths, boundary, owner=owner, realm_id=realm_id,
                            realm_root=realm_root,
                        )
                        if validate_stop is not None:
                            validate_stop()
                        if not outcome(
                            "stop_intent_discovery_unchanged",
                            _read_support_json(paths.discovery_path) == discovery,
                            blocked=("stop_intent_marker_unchanged",),
                        ) or not outcome(
                            "stop_intent_marker_unchanged",
                            _read_support_json(paths.instance_lock_path) == final_marker,
                        ):
                            raise BootstrapError("Runtime owner changed before stop intent publication.")
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
                    if not outcome(
                        "stop_manager_publication_matches",
                        not (observed is not None and observed != expected),
                    ):
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
                        if not outcome(
                            "manager_stale_pid_absent",
                            not _pid_alive(boundary, stale_pid),
                        ):
                            raise BootstrapError(
                                "Runtime interruption refused: stale owner process is present immediately before manager stop."
                            )
                        observe_birth = getattr(boundary, "process_birth_identity", None)
                        if callable(observe_birth):
                            observed_birth = observe_birth(stale_pid)
                            if not outcome("manager_stale_birth_absent", observed_birth is None):
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
                    for path, expected in (
                        (paths.discovery_path, discovery),
                        (paths.instance_lock_path, marker),
                    ):
                        observed = _read_support_json(path)
                        if not outcome(
                            "stop_manager_publication_matches",
                            observed is None or observed == expected,
                        ):
                            raise BootstrapError("Runtime owner changed immediately before manager stop.")
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
            if not outcome(
                "stop_cleanup_discovery_matches",
                not (
                    current_discovery is not None
                    and (
                        not _owner_record_matches(
                            current_discovery,
                            pid=pid,
                            instance_id=instance_id,
                            process_birth_id=birth,
                            realm_id=realm_id,
                            realm_root=realm_root,
                        )
                    )
                ),
            ):
                raise BootstrapError("Runtime owner changed during stop; refusing discovery cleanup.")
            if not outcome(
                "stop_cleanup_marker_matches",
                not (
                    current_marker is not None
                    and (
                        not _owner_record_matches(
                            current_marker,
                            pid=pid,
                            instance_id=instance_id,
                            process_birth_id=birth,
                            realm_id=realm_id,
                            realm_root=realm_root,
                        )
                    )
                ),
            ):
                raise BootstrapError("Runtime owner changed during stop; refusing owner-lock cleanup.")
        else:
            # For absent/stale publications, never unlink a record that was
            # replaced while the manager callback ran. Equality is used here
            # because no live-owner stop authority was established.
            if not outcome(
                "stop_cleanup_discovery_unchanged",
                not (current_discovery is not None and current_discovery != discovery),
            ):
                raise BootstrapError("Runtime discovery changed during stop; refusing cleanup.")
            if not outcome(
                "stop_cleanup_marker_unchanged",
                not (current_marker is not None and current_marker != marker),
            ):
                raise BootstrapError("Runtime owner lock changed during stop; refusing cleanup.")

        def validate_cleanup() -> None:
            if owner is not None:
                _require_owner_absent(
                    boundary,
                    int(owner[0]),
                    str(owner[1]),
                    context="before stop cleanup",
                )
            elif stale_owner_identity is not None:
                _require_owner_absent(
                    boundary,
                    int(stale_owner_identity[0]),
                    str(stale_owner_identity[1]),
                    context="before stale-owner cleanup",
                )
            cleanup_context = validate_cleanup_context or validate_stop
            if cleanup_context is not None:
                cleanup_context()
            if completed_stop_binding is not None:
                current_binding = _pinokio_stop_binding(paths, {"realm_id": realm_id, "data_root": str(realm_root)})
                if not outcome(
                    "stop_cleanup_binding_matches",
                    current_binding == completed_stop_binding,
                ):
                    raise BootstrapError("Runtime stop binding changed before cleanup.")
            if not outcome(
                "stop_cleanup_discovery_unchanged",
                _read_support_json(paths.discovery_path) == current_discovery,
                blocked=("stop_cleanup_marker_unchanged",),
            ) or not outcome(
                "stop_cleanup_marker_unchanged",
                _read_support_json(paths.instance_lock_path) == current_marker,
            ):
                raise BootstrapError("Runtime owner changed before stop cleanup.")

        if current_discovery is not None:
            validate_cleanup()
            remove_file(paths.discovery_path)
            current_discovery = None
        if owner is not None and completed_stop_binding is not None:
            if not outcome("stop_completed_marker_present", marker is not None):
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
            validate_cleanup()
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
            if not outcome("stop_retained_marker_unchanged", observed == marker):
                raise BootstrapError("Runtime completed-stop marker changed during retry; refusing cleanup.")
            if marker is not None and marker.get("state") == "stopping":
                _require_owner_absent(
                    boundary, int(marker["pid"]), str(marker["process_birth_id"]),
                    context="before receipt publication",
                )
                validate_cleanup()
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
            validate_cleanup()
            remove_file(paths.instance_lock_path)
    return {"status": "stopped", "realm_id": realm_id,
            "runtime": stopped, "interruption": final_report}


@predicate_chain("restore_file_regular", "restore_json_parse", "restore_json_object")
def _restore_json_snapshot(path: Path) -> tuple[bytes, dict[str, Any]]:
    """Read exact regular-file bytes without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BootstrapError(f"Restore metadata is missing or unsafe: {path}") from exc
    try:
        if not outcome("restore_file_regular", not (not stat.S_ISREG(os.fstat(fd).st_mode))):
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
        with observation("restore_json_parse", malformed=(UnicodeDecodeError, json.JSONDecodeError)):
            value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"Restore metadata is malformed: {path}") from exc
    if not outcome("restore_json_object", not (not isinstance(value, Mapping))):
        raise BootstrapError(f"Restore metadata must contain an object: {path}")
    return raw, dict(value)


@predicate_chain(
    "restore_path_absolute", "restore_path_no_symlink", "restore_leaf_no_symlink", "restore_path_canonical"
)
def _canonical_metadata_path(value: Path, *, label: str) -> Path:
    path = Path(value).expanduser()
    if (
        not outcome("restore_path_absolute", not (not path.is_absolute()))
        or not outcome("restore_path_no_symlink", not (_has_symlink_component(path)))
        or not outcome("restore_leaf_no_symlink", not (path.is_symlink()))
        or not outcome("restore_path_canonical", not (Path(os.path.abspath(path)) != path))
    ):
        raise BootstrapError(f"Restore {label} path must be absolute, canonical and symlink-free.")
    return path


@predicate_chain("restore_parent_directory", "restore_root_no_symlink", "restore_root_directory")
def _restore_realm_absent(path: Path) -> bool:
    """Prove only a missing leaf realm, never an unreadable path, is absent."""
    path = _canonical_metadata_path(Path(path), label="realm root")
    parent = path.parent
    try:
        parent_info = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise BootstrapError("Restore realm parent is unavailable or unsafe.") from exc
    if not outcome("restore_parent_directory", not (not stat.S_ISDIR(parent_info.st_mode))):
        raise BootstrapError("Restore realm parent is not a regular directory.")
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise BootstrapError("Restore realm availability could not be established.") from exc
    if not outcome("restore_root_no_symlink", not (stat.S_ISLNK(info.st_mode))) or not outcome(
        "restore_root_directory", not (not stat.S_ISDIR(info.st_mode))
    ):
        raise BootstrapError("Restore realm root is unsafe or not a directory.")
    return False


@predicate_chain(
    "restore_journal_path_parse",
    "restore_selection_path_parse",
    "restore_journal_name",
    "restore_install_directory",
    "restore_journal_bytes_journal_parse",
    "restore_selection_bytes_selected_parse",
    "restore_journal_format",
    "restore_journal_step",
    "restore_journal_kind",
    "restore_operation_string",
    "restore_operation_format",
    "restore_backup_object",
    "restore_backup_kind",
    "restore_backup_root_parse",
    "restore_expected_backups_parse",
    "restore_backup_parent",
    "restore_backup_directory",
    "restore_backup_catalog_path_parse",
    "restore_backup_catalog_bytes_backup_catalog_value_parse",
    "restore_selection_owner",
    "restore_program_root_parse",
    "restore_data_root_parse",
    "restore_realm_root_parse",
    "restore_journal_data_parse",
    "restore_journal_realm_object",
    "restore_journal_realm_root_parse",
    "restore_program_root",
    "restore_data_root",
    "restore_realm_id",
    "restore_realm_root",
    "restore_realm_nonempty",
    "restore_realm_safe",
    "restore_journal_realm_string",
    "restore_selection_realm_string",
    "restore_retained_parse",
    "restore_retained_realm_parse",
    "restore_retained_realm_present",
    "restore_retained_selection_string",
    "restore_retained_realm_string",
    "restore_retained_selection_matches",
    "restore_retained_realm_matches",
    "restore_retained_root_matches",
    "restore_live_catalog_bytes_live_catalog_parse",
    "restore_parsed_live_parse",
    "restore_live_realm_parse",
    "restore_live_realm_present",
    "restore_live_selection_string",
    "restore_live_realm_string",
    "restore_live_selection_matches",
    "restore_live_realm_matches",
    "restore_live_root_matches",
)
def _restore_selection_snapshot(
    paths: RuntimePaths, selection: RestoreSelection,
) -> dict[str, Any]:
    """Derive a recovery realm only from agreeing existing installer metadata."""
    with observation("restore_journal_path_parse", malformed=(BootstrapError, TypeError, ValueError)):
        journal_path = _canonical_metadata_path(Path(selection.journal_path), label="journal")
    with observation(
        "restore_selection_path_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        selection_path = _canonical_metadata_path(Path(selection.selection_path), label="selection")
    if not outcome("restore_journal_name", journal_path.name == "update-transaction.json"):
        raise BootstrapError("Restore journal path is not the installation update transaction.")
    install_root = journal_path.parent
    if not outcome("restore_install_directory", install_root.is_dir()):
        raise BootstrapError("Restore installation root is unavailable.")
    with observation(
        "restore_journal_bytes_journal_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        journal_bytes, journal = _restore_json_snapshot(journal_path)
    with observation(
        "restore_selection_bytes_selected_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        selection_bytes, selected = _restore_json_snapshot(selection_path)
    if (
        not outcome(
            "restore_journal_format",
            journal.get("format") == "astrid-install-update/v1",
        )
        or not outcome(
            "restore_journal_step",
            journal.get("step") == "recovering",
        )
        or not outcome(
            "restore_journal_kind",
            journal.get("transaction_kind") in (None, "migration"),
        )
    ):
        raise BootstrapError("Restore selection requires a pending migration recovery journal.")
    if not outcome(
        "restore_operation_string",
        isinstance(journal.get("operation_id"), str),
    ) or not outcome(
        "restore_operation_format",
        re.fullmatch("[0-9a-f]{32}", journal["operation_id"]),
    ):
        raise BootstrapError("Restore journal operation identity is malformed.")

    backup = journal.get("backup")
    if not outcome(
        "restore_backup_object",
        isinstance(backup, Mapping),
    ) or not outcome("restore_backup_kind", backup.get("kind") in ("clone", "runtime")):
        raise BootstrapError("Restore journal does not name a supported retained backup.")
    with observation("restore_backup_root_parse", malformed=(BootstrapError, TypeError, ValueError)):
        backup_root = _canonical_metadata_path(Path(str(backup.get("root") or "")), label="backup")
    with observation(
        "restore_expected_backups_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        expected_backups = _canonical_metadata_path(install_root / "backups", label="backup directory")
    if not outcome(
        "restore_backup_parent",
        backup_root.parent == expected_backups,
    ) or not outcome("restore_backup_directory", backup_root.is_dir()):
        raise BootstrapError("Restore backup is outside this installation's retained backups.")
    backup_catalog_path = backup_root / "support" / "runtime" / "catalog.json"
    with observation(
        "restore_backup_catalog_path_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        backup_catalog_path = _canonical_metadata_path(backup_catalog_path, label="retained catalog")
    with observation(
        "restore_backup_catalog_bytes_backup_catalog_value_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        backup_catalog_bytes, backup_catalog_value = _restore_json_snapshot(backup_catalog_path)

    owner = str(selected.get("owner") or "")
    raw_program_root = str(selected.get("program_root") or "")
    raw_data_root = str(selected.get("data_root") or "")
    realm_id = str(selected.get("realm_id") or "")
    raw_realm_root = str(selected.get("realm_root") or "")
    if not outcome("restore_selection_owner", owner == INSTALL_RECORD_OWNER):
        raise BootstrapError("Restore install selection has an unsupported owner.")
    with observation("restore_program_root_parse", malformed=(BootstrapError, TypeError, ValueError)):
        program_root = _canonical_metadata_path(Path(raw_program_root), label="program root")
    with observation("restore_data_root_parse", malformed=(BootstrapError, TypeError, ValueError)):
        data_root = _canonical_metadata_path(Path(raw_data_root), label="data root")
    with observation("restore_realm_root_parse", malformed=(BootstrapError, TypeError, ValueError)):
        realm_root = _canonical_realm_root(
            _canonical_metadata_path(Path(raw_realm_root), label="realm root"),
            allow_missing=True,
        )
    with observation("restore_journal_data_parse", malformed=(BootstrapError, TypeError, ValueError)):
        journal_data = _canonical_metadata_path(Path(str(journal.get("data_root") or "")), label="journal data root")
    journal_realm = journal.get("realm")
    if not outcome("restore_journal_realm_object", isinstance(journal_realm, Mapping)):
        raise BootstrapError("Restore journal does not identify its selected realm.")
    with observation(
        "restore_journal_realm_root_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        journal_realm_root = _canonical_realm_root(
            _canonical_metadata_path(
                Path(str(journal_realm.get("realm_root") or "")),
                label="journal realm root",
            ),
            allow_missing=True,
        )
    if (
        not outcome(
            "restore_program_root",
            program_root == install_root,
        )
        or not outcome(
            "restore_data_root",
            data_root == journal_data,
        )
        or not outcome(
            "restore_realm_id",
            str(journal_realm.get("realm_id") or "") == realm_id,
        )
        or not outcome(
            "restore_realm_root",
            journal_realm_root == realm_root,
        )
        or not outcome(
            "restore_realm_nonempty",
            realm_id,
        )
        or not outcome(
            "restore_realm_safe",
            not any((char in realm_id for char in "/\\")),
        )
        or not outcome(
            "restore_journal_realm_string",
            isinstance(journal_realm.get("realm_id"), str),
        )
        or not outcome("restore_selection_realm_string", isinstance(selected.get("realm_id"), str))
    ):
        raise BootstrapError("Restore journal and install selection disagree on installation or realm identity.")

    with observation("restore_retained_parse", malformed=(BootstrapError, TypeError, ValueError)):
        retained = _validate_catalog(backup_catalog_value)
    with observation(
        "restore_retained_realm_parse",
        malformed=(BootstrapError, TypeError, ValueError),
    ):
        retained_realm = _selected_realm(retained)
    retained_root = _canonical_realm_root(_canonical_metadata_path(
        Path(str(retained_realm.get("data_root") or "")), label="retained realm root"), allow_missing=True) if retained_realm else None
    if (
        not outcome(
            "restore_retained_realm_present",
            retained_realm is not None,
        )
        or not outcome(
            "restore_retained_selection_string",
            isinstance(retained.get("selected_realm_id"), str),
        )
        or not outcome(
            "restore_retained_realm_string",
            isinstance(retained_realm.get("realm_id"), str),
        )
        or not outcome(
            "restore_retained_selection_matches",
            retained.get("selected_realm_id") == realm_id,
        )
        or not outcome(
            "restore_retained_realm_matches",
            str(retained_realm.get("realm_id") or "") == realm_id,
        )
        or not outcome("restore_retained_root_matches", retained_root == realm_root)
    ):
        raise BootstrapError("Retained backup catalog conflicts with the install selection.")

    live_catalog_bytes = None
    live_catalog = None
    if os.path.lexists(str(paths.catalog_path)):
        with observation(
            "restore_live_catalog_bytes_live_catalog_parse",
            malformed=(BootstrapError, TypeError, ValueError),
        ):
            live_catalog_bytes, live_catalog = _restore_json_snapshot(paths.catalog_path)
        with observation(
            "restore_parsed_live_parse",
            malformed=(BootstrapError, TypeError, ValueError),
        ):
            parsed_live = _validate_catalog(live_catalog)
        with observation(
            "restore_live_realm_parse",
            malformed=(BootstrapError, TypeError, ValueError),
        ):
            live_realm = _selected_realm(parsed_live)
        live_root = _canonical_realm_root(_canonical_metadata_path(
            Path(str(live_realm.get("data_root") or "")), label="current realm root"), allow_missing=True) if live_realm else None
        if (
            not outcome(
                "restore_live_realm_present",
                live_realm is not None,
            )
            or not outcome(
                "restore_live_selection_string",
                isinstance(parsed_live.get("selected_realm_id"), str),
            )
            or not outcome(
                "restore_live_realm_string",
                isinstance(live_realm.get("realm_id"), str),
            )
            or not outcome(
                "restore_live_selection_matches",
                str(parsed_live.get("selected_realm_id") or "") == realm_id,
            )
            or not outcome(
                "restore_live_realm_matches",
                str(live_realm.get("realm_id") or "") == realm_id,
            )
            or not outcome("restore_live_root_matches", live_root == realm_root)
        ):
            raise BootstrapError("Current Runtime catalog conflicts with the retained restore selection.")

    with observation("restore_realm_absence_read"):
        realm_absent = _restore_realm_absent(realm_root)
    outcome("restore_realm_absent", realm_absent)
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
        if not outcome("restore_snapshot_" + key, current.get(key) == snapshot.get(key)):
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
    if not outcome("restore_discovery_absent", discovery is None):
        raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")
    if outcome("restore_marker_absent", marker is None and expected_completed_marker is None):
        return
    if (
        outcome("restore_marker_present", marker is not None)
        and outcome("restore_expected_marker_present", expected_completed_marker is not None)
        and outcome("restore_marker_unchanged", marker == expected_completed_marker)
        and outcome("restore_marker_completed", marker.get("state") == "completed_stop")
    ):
        return
    if marker is not None:
        raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")
    raise BootstrapError("Restore recovery owner marker changed during admission.")


def _inspect_restore_realm(snapshot: Mapping[str, Any]) -> None:
    if snapshot.get("realm_absent") is True:
        if not outcome(
            "restore_realm_still_absent",
            _restore_realm_absent(Path(snapshot["realm_root"])),
        ):
            raise BootstrapError("Restore realm reappeared during recovery admission.")
        return
    from runtime_protocol.upgrade import inspect_canonical_schema

    try:
        with observation("restore_realm_schema", malformed=(ValueError,)):
            inspect_canonical_schema(
                Path(snapshot["realm_root"]),
                expected_realm_id=str(snapshot["realm_id"]),
            )
    except Exception as exc:
        raise BootstrapError("Restore selection does not match the readable Runtime realm identity.") from exc


@phase_instrument
def _interrupt_owner_locked(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, stop_manager=None,
    stop_foreground=None, restore_selection: RestoreSelection | None = None,
) -> dict[str, Any]:
    """Admit, fence, stop and clean the selected Runtime owner."""
    _validate_support_paths(paths)
    if restore_selection is not None:
        with owner_phase("recovery"):
            snapshot = _selected_restore_snapshot(paths, restore_selection)
            marker = _read_support_json(paths.instance_lock_path)
            if (
                marker is not None
                and marker.get("state") == "completed_stop"
                and _read_support_json(paths.discovery_path) is not None
            ):
                _retire_owner_marker(paths, marker)
                raise _pinokio_stop_refusal("Runtime completed-stop marker conflicts with an active discovery.")
            retained_completed_stop = None
            if marker is not None:
                if not outcome("restore_marker_completed", marker.get("state") == "completed_stop"):
                    raise BootstrapError("Restore recovery refuses while Runtime owner publications are present.")
                try:
                    retained_completed_stop = _validate_completed_stop_marker(marker)
                except BootstrapError as exc:
                    _retire_owner_marker(paths, marker)
                    raise _pinokio_stop_refusal(str(exc)) from exc
                binding = marker["completed_stop"]["binding"]
                if (
                    not outcome(
                        "restore_marker_data",
                        retained_completed_stop.get("data_root") == str(snapshot["data_root"]),
                        blocked=(
                            "restore_marker_realm",
                            "restore_marker_root",
                            "restore_binding_data",
                            "restore_binding_realm",
                            "restore_binding_root",
                            "restore_binding_program",
                        ),
                    )
                    or not outcome(
                        "restore_marker_realm",
                        retained_completed_stop.get("realm_id") == str(snapshot["realm_id"]),
                        blocked=(
                            "restore_marker_root",
                            "restore_binding_data",
                            "restore_binding_realm",
                            "restore_binding_root",
                            "restore_binding_program",
                        ),
                    )
                    or not outcome(
                        "restore_marker_root",
                        _canonical_realm_root(str(retained_completed_stop.get("realm_root") or ""))
                        == Path(snapshot["realm_root"]),
                        blocked=(
                            "restore_binding_data",
                            "restore_binding_realm",
                            "restore_binding_root",
                            "restore_binding_program",
                        ),
                    )
                    or not outcome(
                        "restore_binding_data",
                        binding.get("data_root") == str(snapshot["data_root"]),
                        blocked=(
                            "restore_binding_realm",
                            "restore_binding_root",
                            "restore_binding_program",
                        ),
                    )
                    or not outcome(
                        "restore_binding_realm",
                        binding.get("realm_id") == str(snapshot["realm_id"]),
                        blocked=("restore_binding_root", "restore_binding_program"),
                    )
                    or not outcome(
                        "restore_binding_root",
                        binding.get("realm_root") == str(snapshot["realm_root"]),
                        blocked=("restore_binding_program",),
                    )
                    or not outcome(
                        "restore_binding_program",
                        binding.get("program_root") == str(snapshot["program_root"]),
                    )
                ):
                    _retire_owner_marker(paths, marker)
                    raise _pinokio_stop_refusal("Runtime completed-stop marker conflicts with restore selection.")
                try:
                    _require_owner_absent(
                        boundary,
                        int(retained_completed_stop["pid"]),
                        str(retained_completed_stop["process_birth_id"]),
                        context="during restore admission",
                    )
                except BootstrapError as exc:
                    _retire_owner_marker(paths, marker)
                    raise _pinokio_stop_refusal(str(exc)) from exc
            _require_restore_publications_absent(
                paths,
                expected_completed_marker=marker,
            )
            realm_absent = bool(snapshot["realm_absent"])

            def validate_restore() -> None:
                _validate_restore_snapshot(paths, restore_selection, snapshot)
                _require_restore_publications_absent(paths, expected_completed_marker=marker)
                if retained_completed_stop is not None:
                    _require_owner_absent(
                        boundary,
                        int(retained_completed_stop["pid"]),
                        str(retained_completed_stop["process_birth_id"]),
                        context="immediately before restore manager stop",
                    )

            result = _fenced_stop_and_manager(
                paths,
                boundary,
                realm_id=str(snapshot["realm_id"]),
                realm_root=Path(snapshot["realm_root"]),
                discovery=None,
                marker=marker,
                owner=None,
                stop_manager=stop_manager,
                stop_foreground=stop_foreground,
                validate_stop=validate_restore,
                allow_missing_realm=realm_absent,
                retained_completed_stop=retained_completed_stop,
            )
            with _downstream_stop_errors():
                validate_restore()
                if snapshot["live_catalog_bytes"] is None:
                    atomic_write_json(paths.catalog_path, snapshot["catalog"])
                if retained_completed_stop is not None:
                    expected = dict(snapshot)
                    if snapshot["live_catalog_bytes"] is None:
                        expected["live_catalog_bytes"] = paths.catalog_path.read_bytes()
                    _validate_restore_snapshot(paths, restore_selection, expected)
                    _require_restore_publications_absent(paths, expected_completed_marker=marker)
                    _require_owner_absent(
                        boundary,
                        int(retained_completed_stop["pid"]),
                        str(retained_completed_stop["process_birth_id"]),
                        context="before restore marker consumption",
                    )
                    _retire_owner_marker(paths, marker)
            return {
                "status": "stopped",
                "realm_id": snapshot["realm_id"],
                "idle": result["interruption"],
                "catalog_restored": snapshot["live_catalog_bytes"] is None,
            }

    realm, realm_root = _selected_stop_realm(paths)
    discovery = _read_support_json(paths.discovery_path)
    marker = _read_support_json(paths.instance_lock_path)
    if marker is not None and marker.get("state") == "completed_stop" and discovery is not None:
        _retire_owner_marker(paths, marker)
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
                _retire_owner_marker(paths, marker)
            raise _pinokio_stop_refusal(str(exc)) from exc
    owner = None
    stale_owner_identity = None
    retained_completed_stop = None
    reused_owner = False
    if discovery is None and marker is not None and marker.get("state") == "completed_stop":
        if not outcome("completed_binding_selected", pinokio_binding is not None):
            _retire_owner_marker(paths, marker)
            raise _pinokio_stop_refusal("Runtime completed-stop marker has no selected Pinokio installation.")
        try:
            retained_completed_stop = _completed_stop_record(paths, marker, pinokio_binding)
        except BootstrapError as exc:
            _retire_owner_marker(paths, marker)
            raise _pinokio_stop_refusal(str(exc)) from exc
        try:
            stale_pid = int(retained_completed_stop["pid"])
            stale_birth = str(retained_completed_stop["process_birth_id"])
            stale_instance = str(retained_completed_stop["runtime_instance_id"])
            if not outcome("completed_pid_absent", not _pid_alive(boundary, stale_pid)):
                _retire_owner_marker(paths, marker)
                raise _pinokio_stop_refusal("Runtime Pinokio completed-stop owner is present; refusing interruption.")
            observe_birth = getattr(boundary, "process_birth_identity", None)
            if callable(observe_birth):
                with observation("stop_observed_birth_read", malformed=(BootstrapError, TypeError, ValueError)):
                    observed_birth = observe_birth(stale_pid)
                if not outcome("completed_birth_absent", observed_birth is None):
                    _retire_owner_marker(paths, marker)
                    raise _pinokio_stop_refusal(
                        "Runtime Pinokio completed-stop owner identity changed; refusing interruption."
                    )
            if (
                not outcome(
                    "completed_realm_matches",
                    str(retained_completed_stop.get("realm_id")) == str(realm.get("realm_id")),
                    blocked=(
                        "completed_root_matches",
                        "completed_birth_present",
                        "completed_instance_present",
                    ),
                )
                or not outcome(
                    "completed_root_matches",
                    _canonical_realm_root(str(retained_completed_stop.get("realm_root") or "")) == realm_root,
                    blocked=("completed_birth_present", "completed_instance_present"),
                )
                or not outcome(
                    "completed_birth_present",
                    stale_birth,
                    blocked=("completed_instance_present",),
                )
                or not outcome("completed_instance_present", stale_instance)
            ):
                _retire_owner_marker(paths, marker)
                raise _pinokio_stop_refusal("Runtime Pinokio completed-stop owner no longer matches the selected realm.")
        except BootstrapError:
            _retire_owner_marker(paths, marker)
            raise
        except Exception as exc:
            _retire_owner_marker(paths, marker)
            raise _pinokio_stop_refusal(
                "Runtime Pinokio completed-stop owner absence could not be established."
            ) from exc
    elif discovery is None and marker is not None and marker.get("state") == "stopping":
        # Runtime's own intent: admitted only on positive OS absence of that
        # exact pid and birth. A present, reused or unknown process refuses
        # with the lock bytes unchanged.
        stopping = _validate_stopping_marker(marker)
        if (
            not outcome(
                "stopping_data_matches",
                stopping["data_root"] == str(paths.app_support),
                blocked=("stopping_realm_matches", "stopping_root_matches"),
            )
            or not outcome(
                "stopping_realm_matches",
                stopping["realm_id"] == str(realm.get("realm_id")),
                blocked=("stopping_root_matches",),
            )
            or not outcome(
                "stopping_root_matches",
                _canonical_realm_root(stopping["realm_root"]) == realm_root,
            )
        ):
            raise BootstrapError("Runtime interruption refused: owner stopping marker does not match the selected realm.")
        _require_owner_absent(
            boundary, stopping["pid"], stopping["process_birth_id"],
            context="at stopping-marker admission",
        )
        stale_owner_identity = (stopping["pid"], stopping["process_birth_id"])
        recorded_binding = stopping["stopping"]["binding"]
        if pinokio_binding is not None:
            if not outcome(
                "stopping_binding_present",
                recorded_binding is not None,
                blocked=("stopping_binding_matches",),
            ) or not outcome("stopping_binding_matches", dict(recorded_binding) == pinokio_binding):
                _retire_owner_marker(paths, marker)
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
        with observation("stop_alive_read", malformed=(BootstrapError, TypeError, ValueError)):
            alive = _pid_alive(boundary, stale_pid)
        with observation("stop_actual_birth_read", malformed=(BootstrapError, TypeError, ValueError)):
            actual_birth = observe_birth(stale_pid) if callable(observe_birth) and alive else None
        if not outcome(
            "stale_discovery_unchanged",
            _read_support_json(paths.discovery_path) == discovery,
            blocked=("stale_marker_unchanged",),
        ) or not outcome(
            "stale_marker_unchanged",
            _read_support_json(paths.instance_lock_path) == marker,
        ):
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

    def validate_stop_context(*, allow_removed_discovery=False) -> None:
        if reused_owner:
            if not outcome(
                "reused_discovery_unchanged",
                (
                    _read_support_json(paths.discovery_path) in (None, discovery)
                    if allow_removed_discovery
                    else _read_support_json(paths.discovery_path) == discovery
                ),
                blocked=("reused_marker_unchanged",),
            ) or not outcome(
                "reused_marker_unchanged",
                _read_support_json(paths.instance_lock_path) == marker,
            ):
                raise BootstrapError("Runtime owner changed during stale-owner cleanup.")
            with observation("stop_observed_read", malformed=(BootstrapError, TypeError, ValueError)):
                observed = boundary.process_birth_identity(stale_pid)
            if (
                not outcome(
                    "reused_pid_alive",
                    _pid_alive(boundary, stale_pid),
                    blocked=("reused_birth_observed", "reused_birth_different"),
                )
                or not outcome(
                    "reused_birth_observed",
                    observed is not None,
                    blocked=("reused_birth_different",),
                )
                or not outcome(
                    "reused_birth_different",
                    runtime_platform.process_birth_matches(stale_birth, observed) is False,
                )
            ):
                raise BootstrapError("Runtime reused process identity changed during stale-owner cleanup.")
        if pinokio_binding is None:
            return
        try:
            current_binding = _pinokio_stop_binding(paths, realm)
        except BootstrapError as exc:
            raise _pinokio_stop_refusal(str(exc)) from exc
        if not outcome("stop_binding_unchanged", current_binding == pinokio_binding):
            if retained_completed_stop is not None:
                _retire_owner_marker(paths, marker)
            raise _pinokio_stop_refusal("Runtime Pinokio stop binding changed before manager stop.")
        if retained_completed_stop is None:
            return
        if not outcome(
            "completed_marker_unchanged",
            _read_support_json(paths.instance_lock_path) == marker,
        ):
            raise BootstrapError("Runtime completed-stop marker changed before manager stop.")
        try:
            _require_owner_absent(
                boundary, int(retained_completed_stop["pid"]),
                str(retained_completed_stop["process_birth_id"]),
                context="immediately before manager stop",
            )
        except BootstrapError as exc:
            _retire_owner_marker(paths, marker)
            raise _pinokio_stop_refusal(str(exc)) from exc

    result = _fenced_stop_and_manager(
        paths,
        boundary,
        realm_id=str(realm["realm_id"]),
        realm_root=realm_root,
        discovery=discovery,
        marker=marker,
        owner=owner,
        stop_manager=stop_manager,
        stop_foreground=stop_foreground if owner is None else None,
        validate_cleanup_context=(
            (lambda: validate_stop_context(allow_removed_discovery=True))
            if pinokio_binding is not None or reused_owner
            else None
        ),
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
            _realm, realm_root = _selected_stop_realm(paths)
            active = _realm_owner_present(realm_root)
            raise BootstrapError(
                "Runtime interruption refused: owner lock has no matching discovery. "
                + ("The realm owner is still active. " if active else "")
                + "Run astrid-runtime up --profile astrid to recover discovery.",
                details={"safe": False, "owner_active": active},
            )
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


@instrument
@predicate_chain(
    "recorded_pid_parse",
    "recorded_birth_parse",
    "recorded_instance_parse",
    "recorded_endpoint_parse",
    "recorded_observed_realm_parse",
    "recorded_observed_root_parse",
    "recorded_identity_readable",
    "recorded_pid_positive",
    "recorded_birth_present",
    "recorded_instance_present",
    "recorded_realm_matches",
    "recorded_root_matches",
)
def _recorded_owner_identity(
    value: Mapping[str, Any], *, realm_id: str, realm_root: Path,
) -> tuple[int, str, str, str]:
    try:
        with observation(
            "recorded_pid_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            pid = int(value["pid"])
        with observation(
            "recorded_birth_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            birth = str(value["process_birth_id"])
        with observation(
            "recorded_instance_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            instance = str(value["runtime_instance_id"])
        with observation(
            "recorded_endpoint_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            endpoint = _validate_loopback_endpoint(str(value["endpoint"]))
        with observation(
            "recorded_observed_realm_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            observed_realm = str(value.get("active_realm") or value.get("realm_id") or "")
        with observation(
            "recorded_observed_root_parse",
            malformed=(KeyError, TypeError, ValueError, BootstrapError),
        ):
            observed_root = _canonical_realm_root(str(value.get("realm_root") or ""))
        outcome("recorded_identity_readable", True)
    except (KeyError, TypeError, ValueError, BootstrapError) as exc:
        outcome("recorded_identity_readable", False)
        raise BootstrapError("Runtime interruption refused: discovery or owner identity is incomplete.") from exc
    if (
        not outcome(
            "recorded_pid_positive",
            pid > 0,
        )
        or not outcome(
            "recorded_birth_present",
            bool(birth),
        )
        or not outcome(
            "recorded_instance_present",
            bool(instance),
        )
        or not outcome(
            "recorded_realm_matches",
            observed_realm == realm_id,
        )
        or not outcome("recorded_root_matches", observed_root == realm_root)
    ):
        raise BootstrapError("Runtime interruption refused: discovery realm root does not match the selected workspace.")
    return pid, birth, instance, endpoint


@instrument
@predicate_chain(
    "owner_validator_callable",
    "owner_valid",
    "metadata_callable",
    "endpoint_metadata",
    "endpoint_instance",
    "endpoint_realm",
)
def _validate_stop_endpoint(
    paths: RuntimePaths, boundary: RuntimeBoundary, *, owner: tuple[int, str, str, str],
    realm_id: str, realm_root: Path,
) -> Mapping[str, Any]:
    """Validate the process/lock handoff and authenticated published endpoint."""
    pid, birth, instance_id, endpoint = owner
    validate = getattr(boundary, "validate_owner", None)
    if not outcome("owner_validator_callable", callable(validate), blocked=("owner_valid",)) or not outcome(
        "owner_valid",
        bool(
            validate(
                endpoint=endpoint,
                pid=pid,
                instance_id=instance_id,
                owner_lock=paths.instance_lock_path,
                process_birth_id=birth,
                expected_realm_id=realm_id,
                expected_realm_root=realm_root,
            )
        ),
    ):
        raise BootstrapError("Runtime interruption refused: owner endpoint or process identity failed validation.")
    endpoint_metadata = getattr(boundary, "endpoint_metadata", None)
    if not outcome("metadata_callable", callable(endpoint_metadata)):
        raise BootstrapError("Runtime interruption refused: boundary cannot verify the selected endpoint.")
    identity = endpoint_metadata(
        endpoint=endpoint,
        credential_file=paths.runtime_support / "credentials" / "owner.token",
    )
    if (
        not outcome(
            "endpoint_metadata",
            bool(identity),
            blocked=("endpoint_instance", "endpoint_realm"),
        )
        or not outcome(
            "endpoint_instance",
            str(identity.get("runtime_instance_id") or "") == instance_id,
            blocked=("endpoint_realm",),
        )
        or not outcome("endpoint_realm", str(identity.get("realm_id") or "") == realm_id)
    ):
        raise BootstrapError("Runtime interruption refused: endpoint identity does not match the selected owner.")
    return identity


@instrument
@predicate_chain(
    "published_marker_state",
    "recorded_identity_readable",
    "published_marker_present",
    "published_marker_realm",
    "published_marker_matches",
    "published_pid_alive",
    "published_absence_observed",
)
def _validate_published_stop_owner(
    paths: RuntimePaths, boundary: RuntimeBoundary | None, realm: Mapping[str, Any],
    realm_root: Path, discovery: Mapping[str, Any], marker: Mapping[str, Any] | None,
    *, observed_alive: bool | None = None,
) -> tuple[int, str, str, str] | None:
    realm_id = str(realm.get("realm_id") or "")
    if marker is not None and marker.get("state") == "stopping":
        _validate_stopping_marker(marker)
        outcome("published_marker_state", True)
    elif marker is not None and marker.get("state") is not None:
        outcome("published_marker_state", False)
        raise BootstrapError("Runtime interruption refused: owner lock has an unknown state.")
    else:
        outcome("published_marker_state", True)
    pid, birth, instance_id, endpoint = _recorded_owner_identity(
        discovery, realm_id=realm_id, realm_root=realm_root,
    )
    if (
        not outcome(
            "published_marker_present",
            marker is not None,
            blocked=("published_marker_realm", "published_marker_matches"),
        )
        or not outcome(
            "published_marker_realm",
            str(marker.get("realm_id") or "") == realm_id,
            blocked=("published_marker_matches",),
        )
        or not outcome(
            "published_marker_matches",
            _owner_record_matches(
                marker,
                pid=pid,
                instance_id=instance_id,
                process_birth_id=birth,
                realm_id=realm_id,
                realm_root=realm_root,
            ),
        )
    ):
        raise BootstrapError("Runtime interruption refused: owner lock changed or does not match discovery.")
    alive = _pid_alive(boundary, pid) if observed_alive is None else observed_alive
    if not outcome("published_pid_alive", alive):
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
            if outcome("published_absence_observed", boundary.process_birth_identity(pid) is None):
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
