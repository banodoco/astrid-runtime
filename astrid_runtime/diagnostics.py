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

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(\b(?:authorization|proxy-authorization)\b[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?)[^\"'\s,;}]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]+"), r"\1[REDACTED]"),
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
    transaction_path = _install_record_path(paths.home).parent / "update-transaction.json"
    transaction = _read_json(transaction_path)
    tx_log = transaction.get("log") or transaction.get("log_path")
    tx_log_path = Path(tx_log).expanduser() if isinstance(tx_log, str) else transaction_path.with_name("update.log")
    launcher_log = (program_root / "logs" / "launcher.log") if program_root else None
    log_path = platform.log_dir(paths.home) / "runtime.log"
    retained = program_root / "versions" if program_root else None
    result = transaction.get("result") or transaction.get("state") or "No update has run yet."
    lines = [
        "Astrid diagnostics",
        f"Runtime version: {__version__}",
        f"B1 identity: managed_by={identity.get('managed_by', record.get('managed_by', 'unknown'))}; release={identity.get('release', 'unknown')}",
        f"Runtime support state: {support.get('state', 'unknown')} (healthy={support.get('healthy', 'unknown')})",
        f"Last update result: {result}",
        "Installer transaction log:",
        _tail(tx_log_path, paths.home),
    ]
    if identity.get("managed_by", record.get("managed_by")) == "source" and launcher_log is not None:
        lines += ["Launcher log:", _tail(launcher_log, paths.home)]
    lines += [f"Retained back-end copies: {(_size(retained) if retained else 0)} bytes"]
    lines += [f"Runtime log directory: {platform.log_dir(paths.home)}", f"Runtime log tail ({log_path.name}):", _tail(log_path, paths.home)]
    return redact("\n".join(lines), paths.home)
