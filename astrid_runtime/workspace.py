"""Explicit create/attach/inspect configuration for the sole local workspace."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import Any, Mapping

from .bootstrap import (
    BootstrapConfig,
    BootstrapError,
    RuntimeBoundary,
    _bootstrap_mutex,
    _commit_source_profile_metadata,
    _has_symlink_component,
    _new_realm_id,
    _read_catalog,
    _selected_realm,
    _validate_source_profile,
    _validate_support_paths,
)
from .paths import RuntimePaths
from runtime_protocol import process_control as process_control_setting


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


def _inspect(boundary: RuntimeBoundary, root: Path, *, allow_deferred=False) -> tuple[str, dict[str, Any]]:
    inspect = getattr(boundary, "inspect", None)
    if not callable(inspect):
        raise BootstrapError("runtime boundary cannot inspect a canonical realm")
    report = inspect(realm_root=root)
    if not isinstance(report, Mapping):
        raise BootstrapError("runtime realm inspection returned invalid metadata")
    report = dict(report)
    identity = report.get("checks", {}).get("realm_identity", {})
    observed = str(identity.get("realm_id") or "") if isinstance(identity, Mapping) else ""
    from runtime_protocol.history_verification import may_defer_history
    deferred = allow_deferred and may_defer_history(report, root)
    if report.get("state") == "uninitialized" or (not report.get("ok") and not deferred) or not identity.get("ok") or not observed:
        guard = report.get("checks", {}).get("history_guards", {})
        if isinstance(guard, Mapping) and guard.get("ok") is False:
            raise BootstrapError(f"realm failed history_guards check: {guard.get('reason')}. {report.get('recovery_action', '')}")
        issues = report.get("issues", [])
        reason = ", ".join(str(issue) for issue in issues) or report.get("message") or "realm_identity"
        recovery = report.get("recovery_action", "")
        raise BootstrapError(f"realm root is not one healthy unambiguous canonical workspace: {reason}. {recovery}".rstrip())
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
    return {"ok": True, "state": "live", "source": "live_owner",
            "runtime_instance_id": discovery.get("runtime_instance_id"),
            "checks": {"realm_identity": {"ok": True, "realm_id": expected}}}


def inspect_workspace(
    paths: RuntimePaths,
    boundary: RuntimeBoundary,
    *,
    realm_root: str | Path | None = None,
    expected_realm_id: str | None = None,
) -> dict[str, Any]:
    """Observe configured or candidate identity without creating support state."""
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
    # Only the already configured root may proceed to owned read-only
    # startup. Attach/adopt of an unverified candidate stays fail-closed.
    allow_deferred = configured is not None and root == Path(str(configured["data_root"]))
    observed, report = _inspect(boundary, root, allow_deferred=allow_deferred)
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
