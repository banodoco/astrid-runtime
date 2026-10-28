"""Owner-shareable, redacted diagnostics assembled from existing records."""
from __future__ import annotations

import json
import os
from pathlib import Path, PureWindowsPath
import re
from typing import Any

from runtime_protocol import platform

from . import __version__
from .paths import RuntimePaths, _install_record_path
from .update import read_update_status

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(\b(?:authorization|proxy-authorization)\b[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?)[^\"'\s,;}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:cookie|set-cookie)[\"']?\s*[:=]\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:api[_ -]?key|openrouter[_ -]?api[_ -]?key|token|access[_ -]?token|refresh[_ -]?token|password|secret|credential)\b[\"']?\s*[=:]\s*['\"]?)[^\s,;'\"]+"), r"\1[REDACTED]"),
    (re.compile(r"\b(sk-or-v1-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,})\b"), "[REDACTED]"),
)


def redact(value: str, home: Path | None = None) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    if home is not None:
        home_text = str(home)
        if home_text:
            value = value.replace(home_text, "~")
            value = value.replace(home_text.replace("\\", "/"), "~")
            if os.name != "nt":
                value = value.replace(str(PureWindowsPath(home_text)), "~")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def _size(path: Path) -> int:
    total = 0
    try:
        for item in path.rglob("*"):
            try:
                if item.is_file() and not item.is_symlink():
                    total += item.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _tail(path: Path, home: Path, limit: int = 80) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return "(not available)"
        if not platform.is_owner_only(path):
            return "(not available; log permissions are not owner-only)"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        return redact("\n".join(lines) or "(empty)", home)
    except OSError:
        return "(not available)"


def _install_info(paths: RuntimePaths) -> tuple[dict[str, Any], Path | None]:
    record = _read_json(_install_record_path(paths.home))
    if record.get("owner") != "haus.astrid.runtime":
        return {}, None
    root = record.get("program_root")
    candidate = Path(root).expanduser() if isinstance(root, str) and root else None
    return record, candidate if candidate is not None and candidate.is_absolute() else None


def diagnostics_report(
    paths: RuntimePaths,
    support: dict[str, Any],
) -> str:
    record, program_root = _install_info(paths)
    identity = record.get("identity") if isinstance(record.get("identity"), dict) else {}
    status = read_update_status(paths.home)
    transaction_path = (program_root / "update-transaction.json") if program_root else _install_record_path(paths.home).parent / "update-transaction.json"
    transaction = _read_json(transaction_path)
    install = _read_json(program_root / "install.json") if program_root else {}
    job = install.get("update_job") if isinstance(install.get("update_job"), dict) else {}
    # Acceptance snapshots the previous transaction while holding the installer
    # lock. A different direct journal therefore belongs to a later attempt.
    # Older jobs lack this fact, so retain the historical direct-journal fallback.
    direct = bool(transaction) and not isinstance(transaction.get("update_job"), dict)
    later_direct = direct and ("prior_transaction_id" not in job or
                               transaction.get("operation_id") != job["prior_transaction_id"])
    use_job = status.get("state") != "none" and not (later_direct and status.get("state") == "terminal")
    tx_log = (status.get("log_path") if use_job else
              transaction.get("log_path") or transaction.get("log"))
    tx_log_path = (Path(tx_log).expanduser() if isinstance(tx_log, str) and tx_log else
                   None if use_job else platform.log_dir(paths.home) / "install.log")
    launcher_log = (program_root / "logs" / "launcher.log") if program_root else None
    log_path = platform.log_dir(paths.home) / "runtime.log"
    retained = program_root / "versions" if program_root else None
    result = (status.get("result") or "Update status unavailable.") if use_job else (
        transaction.get("result") or transaction.get("outcome") or transaction.get("step")
        or transaction.get("state") or "No update has run yet.")
    healthy = support.get("healthy", support.get("ok", "unknown"))
    state = support.get("state") or ("healthy" if healthy is True else "unhealthy" if healthy is False else "unknown")
    lines = [
        "Astrid diagnostics",
        f"Runtime version: {__version__}",
        f"B1 identity: managed_by={identity.get('managed_by', record.get('managed_by', 'unknown'))}; release={identity.get('release', 'unknown')}",
        f"Runtime support state: {state} (healthy={healthy})",
        f"Last update result: {result}",
        f"Update log: {tx_log_path or '(not available)'}",
        "Installer transaction log:",
        _tail(tx_log_path, paths.home) if tx_log_path else "(not available)",
    ]
    issues = support.get("issues")
    if isinstance(issues, list) and issues:
        lines += ["Runtime support issues:", *(f"- {issue}" for issue in issues if isinstance(issue, str))]
    if identity.get("managed_by", record.get("managed_by")) == "source" and launcher_log is not None:
        lines += ["Launcher log:", _tail(launcher_log, paths.home)]
    lines += [f"Retained back-end copies: {(_size(retained) if retained else 0)} bytes"]
    lines += [f"Runtime log directory: {platform.log_dir(paths.home)}", f"Runtime log tail ({log_path.name}):", _tail(log_path, paths.home)]
    return redact("\n".join(lines), paths.home)
