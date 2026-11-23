"""Explicit create/attach/inspect configuration for the sole local workspace."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    BootstrapLockBusy,
    RuntimeBoundary,
    RuntimeStartAttempt,
    _bootstrap_mutex,
    _capture_requested_identity,
    _commit_source_profile_metadata,
    _finish_start_attempt,
    _has_symlink_component,
    _new_realm_id,
    _owner_record_matches,
    _pending_startup,
    _read_catalog,
    _read_support_json,
    _realm_owner_present,
    _recorded_owner_identity,
    _selected_realm,
    _startup_scope,
    _validate_source_profile,
    _validate_stop_endpoint,
    _validate_support_paths,
    _validated_matching_owner_identity,
)
from .paths import RuntimePaths
from runtime_protocol import platform, process_control as process_control_setting, startup_attempt, startup_operation


def _root(value: str | Path, *, must_exist: bool, empty: bool = False) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise BootstrapError("realm root must be an explicit absolute path")
    result = Path(os.path.abspath(raw))
    if _has_symlink_component(result) or result.is_symlink():
        raise BootstrapError("realm root must be symlink-free")
    if must_exist and not result.is_dir():
        raise BootstrapError(f"realm root is unavailable: {result}")
    if empty and result.exists() and (not result.is_dir() or any(result.iterdir())):
        raise BootstrapError("fresh realm root must be absent or an empty directory")
    return result.resolve()


def _opaque_realm_id(value: str | None, *, generate: bool) -> str:
    if value is None and generate:
        return _new_realm_id()
    candidate = "" if value is None else str(value)
    if (
        not candidate
        or len(candidate.encode("utf-8")) > 255
        or candidate != candidate.strip()
        or any(ch in candidate for ch in "/\\\x00\r\n")
    ):
        raise BootstrapError("realm id must be a non-empty bounded opaque identifier")
    return candidate


def _inspect(boundary: RuntimeBoundary, root: Path, *, startup=False) -> tuple[str, dict[str, Any]]:
    inspect = getattr(boundary, "inspect_startup" if startup else "inspect", None)
    if not callable(inspect):
        raise BootstrapError("runtime boundary cannot inspect a canonical realm")
    report = inspect(realm_root=root)
    if not isinstance(report, Mapping):
        raise BootstrapError("runtime realm inspection returned invalid metadata")
    report = dict(report)
    identity = report.get("checks", {}).get("realm_identity", {})
    observed = str(identity.get("realm_id") or "") if isinstance(identity, Mapping) else ""
    if report.get("state") == "uninitialized" or not report.get("ok") or not identity.get("ok") or not observed:
        raise BootstrapError("realm root is not one healthy unambiguous canonical workspace")
    return observed, report


def _live_owner_inspection(paths: RuntimePaths, boundary: RuntimeBoundary, root: Path, expected: str) -> dict[str, Any] | None:
    """Reuse only the same discovery snapshot that passed native/lock/health checks."""
    if boundary is None:
        return None
    from .bootstrap import _doctor_observation

    try:
        support, discovery = _doctor_observation(paths, boundary)
    except (BootstrapError, OSError, ValueError):
        return None
    if (not support.get("healthy") or not support.get("pid_alive")
            or support.get("realm_id") != expected or not isinstance(discovery, Mapping)):
        return None
    if (str(discovery.get("active_realm") or "") != expected
            or Path(str(discovery.get("realm_root") or "")) != root):
        return None
    return _live_report(discovery, expected)


def _live_report(discovery, expected):
    return {"ok": True, "state": "live", "source": "live_owner",
            "runtime_instance_id": discovery.get("runtime_instance_id"),
            "checks": {"realm_identity": {"ok": True, "realm_id": expected}}}


def _startup_live_owner_inspection(paths, boundary, root, expected, requested_identity):
    """Verify the same live owner through its lock, kernel birth and endpoint."""
    discovery = _read_support_json(paths.discovery_path)
    marker = _read_support_json(paths.instance_lock_path)
    if (not discovery or not marker or marker.get("state") is not None
            or not platform.is_owner_only(paths.discovery_path)
            or not platform.is_owner_only(paths.instance_lock_path)):
        return None

    def observed_birth(pid):
        identity = platform.process_identity(pid)
        if identity is not None and identity.get("uid") == platform.current_user():
            return identity.get("birth_id")
        return None

    try:
        owner = _recorded_owner_identity(discovery, realm_id=expected, realm_root=root)
        pid, birth, instance_id, _ = owner
        if not _owner_record_matches(
            marker, pid=pid, instance_id=instance_id, process_birth_id=birth,
            realm_id=expected, realm_root=root,
        ) or platform.process_birth_matches(birth, observed_birth(pid) or "") is not True:
            return None
        metadata = _validate_stop_endpoint(paths, boundary, owner=owner, realm_id=expected, realm_root=root)
        if (metadata.get("status") != "ok" or "identity" not in metadata
                or _read_support_json(paths.discovery_path) != discovery
                or _read_support_json(paths.instance_lock_path) != marker
                or not _realm_owner_present(root)
                or platform.process_birth_matches(birth, observed_birth(pid) or "") is not True):
            return None
    except (BootstrapError, OSError, ValueError):
        return None
    _validated_matching_owner_identity(metadata, instance_id=instance_id, requested_identity=requested_identity)
    return _live_report(discovery, expected)


def inspect_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    *,
    realm_root: str | Path | None = None,
    expected_realm_id: str | None = None,
    startup_operation: bool = False,
    config: BootstrapConfig | None = None,
) -> dict[str, Any]:
    """Inspect canonical identity, optionally owning a managed startup scan."""
    if startup_operation:
        return _inspect_startup_workspace(paths, boundary, realm_root, expected_realm_id, config)
    _validate_support_paths(paths)
    configured = _selected_realm(_read_catalog(paths))
    if realm_root is None:
        if configured is None:
            return {"ok": False, "state": "workspace_missing", "effects": ["observe"]}
        root = _root(str(configured["data_root"]), must_exist=True)
        expected = str(configured["realm_id"])
        live = _live_owner_inspection(paths, boundary, root, expected)
        if live is not None:
            return {"ok": True, "state": "configured", "realm_id": expected, "realm_root": str(root),
                    "effects": ["observe"], "inspection": live}
    else:
        root = _root(realm_root, must_exist=True)
        expected = (
            _opaque_realm_id(expected_realm_id, generate=False)
            if expected_realm_id is not None
            else None
        )
    observed, report = _inspect(boundary, root)
    if expected is not None and observed != expected:
        raise BootstrapError(f"workspace identity mismatch: expected {expected}, observed {observed}")
    if configured is not None and realm_root is not None:
        if observed != str(configured["realm_id"]) or root != Path(str(configured["data_root"])):
            raise BootstrapError("candidate conflicts with the configured workspace")
    return {
        "ok": True,
        "state": "configured" if configured is not None else "inspectable",
        "realm_id": observed,
        "realm_root": str(root),
        "effects": ["observe"],
        "inspection": report,
    }


def _startup_selection(paths, realm_root, expected_realm_id, config):
    _validate_support_paths(paths)
    configured = _selected_realm(_read_catalog(paths))
    if realm_root is None and configured is None:
        return None
    root = _root(realm_root if realm_root is not None else configured["data_root"], must_exist=True)
    if expected_realm_id is None and configured is not None:
        expected_realm_id = configured["realm_id"]
    expected = _opaque_realm_id(expected_realm_id, generate=False)
    if configured is not None and (expected != configured["realm_id"] or root != Path(configured["data_root"])):
        raise BootstrapError("candidate conflicts with the configured workspace")
    config = config or BootstrapConfig()
    source = config.resolve_source_profile(paths)
    _validate_source_profile(source, expected_profile=config.profile)
    requested_identity = _capture_requested_identity(source)
    scope = _startup_scope(source, expected, root, requested_identity=requested_identity)
    if scope is None:
        raise BootstrapError("Runtime startup operations require the selected installed Runtime environment.")
    return configured, root, expected, scope, requested_identity


def _startup_observation(paths, scope, operation_id=None, *, fresh=True):
    return startup_operation.read_operation(
        paths.runtime_support.resolve(), scope=scope, operation_id=operation_id, fresh=fresh,
    )


@contextmanager
def begin_startup_attempt(paths, *, realm_root=None, expected_realm_id=None, config=None, retry_attempt_id=None):
    """Reserve a scoped start attempt around an independently verified inspection and launch."""
    config = config or BootstrapConfig()
    _validate_support_paths(paths)
    with _bootstrap_mutex(paths):
        selection = _startup_selection(paths, realm_root, expected_realm_id, config)
        if selection is None:
            raise BootstrapError("No workspace is configured for the Runtime start attempt.")
        _, _, _, scope, _ = selection
        if _pending_startup(paths) is not None:
            raise BootstrapError("A Runtime startup operation already owns this installation.")
        record = startup_attempt.StartupAttempt.begin_locked(
            paths.runtime_support.resolve(), scope,
            inspecting=True, retry_attempt_id=retry_attempt_id,
        )
    succeeded = False
    try:
        yield RuntimeStartAttempt(paths, record)
        succeeded = True
    finally:
        with _bootstrap_mutex(paths):
            _finish_start_attempt(record, failed=not succeeded)


def startup_status(paths, *, realm_root=None, expected_realm_id=None, config=None, operation_id=None):
    """Read status for the selected identity without opening the realm or listener."""
    selection = _startup_selection(paths, realm_root, expected_realm_id, config)
    if selection is not None:
        _, root, expected, scope, _ = selection
        observed = _startup_observation(paths, scope, operation_id)
        if scope != startup_operation.OperationScope.from_selection(expected, root, scope.generation):
            return {"state": "unavailable"}
        if observed is not None and (operation_id is not None or observed.state == "pending"):
            return observed.as_observation()
        if operation_id is None:
            launcher = startup_attempt.read_attempt(paths.runtime_support.resolve())
            if launcher is not None and launcher.state != "finished":
                if launcher.scope != scope:
                    return {"state": "unavailable"}
                # Assignment can race this lock-free read. An independent
                # active operation takes priority over the launcher's record.
                active = _startup_observation(paths, scope, fresh=False)
                if active is not None and active.state == "pending":
                    fresh = _startup_observation(paths, scope, active.operation_id)
                    if fresh is None or fresh.state != "pending":
                        return {"state": "unavailable"}
                    return fresh.as_observation()
                if scope == startup_operation.OperationScope.from_selection(expected, root, scope.generation):
                    return launcher.as_observation()
                return {"state": "unavailable"}
        if observed is not None:
            return observed.as_observation()
    return {"state": "unavailable"}


def _pending_inspection(paths, scope):
    pending = _pending_startup(paths)
    if pending is None:
        return None
    observed = _startup_observation(paths, scope, pending.operation_id)
    if observed is None or observed.state != "pending":
        raise BootstrapError("A Runtime startup operation already owns this installation.")
    return {"ok": False, "state": "startup_pending", "startup_operation": observed.as_observation()}


def _inspect_startup_workspace(paths, boundary, realm_root, expected_realm_id, config):
    from runtime_protocol.store import realm_admission_fence

    selection = _startup_selection(paths, realm_root, expected_realm_id, config)
    if selection is None:
        return {"ok": False, "state": "workspace_missing", "effects": ["observe"]}
    _, _, _, scope, _ = selection
    pending = _pending_inspection(paths, scope)
    if pending is not None:
        return pending
    try:
        with _bootstrap_mutex(paths, blocking=False):
            current = _startup_selection(paths, realm_root, expected_realm_id, config)
            if current is None or current[3] != scope:
                raise BootstrapError("Workspace selection changed during startup inspection.")
            configured, root, expected, _, requested_identity = current
            pending = _pending_inspection(paths, scope)
            if pending is not None:
                return pending
            report = _startup_live_owner_inspection(paths, boundary, root, expected, requested_identity)
            if report is None:
                try:
                    with realm_admission_fence(root, blocking=False):
                        if _realm_owner_present(root):
                            raise BootstrapError("A different Runtime owner is active for this realm.")
                        operation = startup_operation.StartupOperation.assign(paths.runtime_support.resolve(), scope)
                        with operation.produce():
                            observed, report = _inspect(boundary, root, startup=True)
                            if observed != expected:
                                raise BootstrapError(f"workspace identity mismatch: expected {expected}, observed {observed}")
                            report["state"] = "verified_offline"
                except BlockingIOError as exc:
                    raise BootstrapError("A Runtime owner is inspecting this realm.") from exc
    except BootstrapLockBusy:
        # A request can lose before the winner publishes any operation. It
        # must return to the caller without queuing another full inspection.
        pending = _pending_inspection(paths, scope)
        return pending if pending is not None else {"ok": False, "state": "startup_busy"}
    return {
        "ok": True,
        "state": "configured" if configured is not None else "inspectable",
        "realm_id": expected,
        "realm_root": str(root),
        "effects": ["observe"],
        "inspection": report,
    }


def configure_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    config: BootstrapConfig,
    *,
    mode: str,
    realm_root: str | Path,
    realm_id: str | None,
    process_control: str | None = None,
) -> dict[str, Any]:
    """Explicitly create or attach and select exactly one canonical realm.

    ``process_control`` ("strict" or "sandbox"), when given, is written to
    Runtime support whether or not the selection changes, so re-running the
    installer with or without --sandbox switches the mode.
    """
    if mode not in {"create", "attach"}:
        raise ValueError("workspace mode must be create or attach")
    if process_control is not None and process_control not in process_control_setting.MODES:
        raise ValueError(f"process control must be one of {', '.join(process_control_setting.MODES)}")
    _validate_support_paths(paths)
    source = config.resolve_source_profile(paths)
    _validate_source_profile(source, expected_profile=config.profile)
    root = _root(realm_root, must_exist=(mode == "attach"))
    requested = _opaque_realm_id(realm_id, generate=(mode == "create"))
    inspected = False
    if mode == "attach":
        observed, _ = _inspect(boundary, root)
        inspected = True
        if observed != requested:
            raise BootstrapError(f"workspace identity mismatch: expected {requested}, observed {observed}")

    with _bootstrap_mutex(paths):
        if _pending_startup(paths) is not None:
            raise BootstrapError("A Runtime startup operation already owns this installation.")
        paths.ensure_support_dirs()
        existing = _selected_realm(_read_catalog(paths))
        if existing is not None:
            if str(existing["realm_id"]) != requested or Path(str(existing["data_root"])) != root:
                raise BootstrapError("workspace selection conflicts with the configured identity")
            if not inspected:
                observed, _ = _inspect(boundary, root)
                if observed != requested:
                    raise BootstrapError("configured workspace identity does not match its canonical realm")
            if process_control is not None:
                process_control_setting.write_setting(paths.runtime_support, process_control)
            return {"ok": True, "status": "unchanged", "realm_id": requested, "realm_root": str(root),
                    "process_control": process_control_setting.read_setting(paths.runtime_support)}

        created_here = False
        try:
            if mode == "create":
                _root(root, must_exist=False, empty=True)
                created = boundary.create(
                    realm_id=requested,
                    realm_root=root,
                    display_name=config.display_name,
                    source_profile=source,
                )
                if not isinstance(created, Mapping) or str(created.get("realm_id")) != requested:
                    raise BootstrapError("runtime realm creation returned mismatched identity")
                created_here = True
            if not inspected:
                observed, _ = _inspect(boundary, root)
                if observed != requested:
                    raise BootstrapError(f"workspace identity mismatch: expected {requested}, observed {observed}")
            catalog = {
                "version": 1,
                "selected_realm_id": requested,
                "realms": [{
                    "realm_id": requested,
                    "display_name": config.display_name,
                    "data_root": str(root),
                    "selection_source": mode,
                    "source_profile": source.profile,
                }],
                "source_profiles": {source.profile: source.as_dict()},
            }
            _commit_source_profile_metadata(paths, source, catalog)
            if process_control is not None:
                process_control_setting.write_setting(paths.runtime_support, process_control)
            selected_process_control = process_control_setting.read_setting(paths.runtime_support)
        except Exception:
            if created_here and root.is_dir() and not root.is_symlink():
                shutil.rmtree(root)
            raise
    return {
        "ok": True,
        "status": f"configured_{mode}",
        "realm_id": requested,
        "realm_root": str(root),
        "process_control": selected_process_control,
        "next_action": "astrid-runtime up",
    }


__all__ = ["configure_workspace", "inspect_workspace"]
