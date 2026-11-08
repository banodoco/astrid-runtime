"""Owner-shareable, redacted diagnostics assembled from existing records."""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path, PureWindowsPath
import re
from typing import Any

from runtime_protocol import platform

from . import __version__
from .paths import INSTALL_RECORD_OWNER, RuntimePaths, _install_record_path
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
    if record.get("owner") != INSTALL_RECORD_OWNER:
        return {}, None
    root = record.get("program_root")
    candidate = Path(root).expanduser() if isinstance(root, str) and root else None
    return record, candidate if candidate is not None and candidate.is_absolute() else None


# The Agent's run receipt (astrid/installer/outcome.py): one typed record
# beside install.log, written at the end of every installer run.
RECEIPT_NAME = "last-run.json"
RECEIPT_FORMAT = "astrid-last-run/v1"
RECEIPT_SUCCESS = ("updated", "already-current", "repaired")
# The Agent's storage-move journal and its archive once normalised (astrid/installer/installation.py).
HANDOFF_JOURNAL = "astrid-r1-handoff.json"
HANDOFF_ARCHIVE = "astrid-r1-handoff.completed.json"
LOW_DISK_BYTES = 2 * 1024 ** 3
RESTART_LOOP_COUNT = 5
_DISK_FULL = re.compile(r"database or disk is full|SQLITE_FULL", re.IGNORECASE)


def _release(value: Any) -> str:
    return f"Release {value}" if type(value) is int and value >= 0 else "unknown"


def _gb(value: int | None) -> str:
    return "unknown" if value is None else f"{value / 1024 ** 3:.1f} GB ({value} bytes)"


def _path_of(value: Any) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value).expanduser()
    return path if path.is_absolute() else None


def _receipt(paths: RuntimePaths) -> dict[str, Any]:
    value = _read_json(platform.log_dir(paths.home) / RECEIPT_NAME)
    return value if value.get("format") == RECEIPT_FORMAT and isinstance(value.get("kind"), str) else {}


def _storage_move(paths: RuntimePaths, record: dict[str, Any]) -> tuple[str, list[Path]]:
    """The R0 to R1 storage move as the installer records it, and the retained R0 data roots."""
    journal_path = _install_record_path(paths.home).with_name(HANDOFF_JOURNAL)
    journal = _read_json(journal_path)
    archived = _install_record_path(paths.home).with_name(HANDOFF_ARCHIVE)
    retained = _path_of(record.get("retained_r0_data_root"))
    if journal:
        phase = journal.get("phase") if isinstance(journal.get("phase"), str) else "unknown"
        old = _path_of(journal.get("r0_data_root"))
        text = (f"phase {phase}, journal still authoritative (not normalised)" if phase == "complete"
                else f"phase {phase} (in progress or rolled back)")
        return text, [old] if old else []
    if "r1_data_root" in record:
        old = _path_of(record.get("data_root"))
        return "finished, selection not normalised (no journal found)", [old] if old else []
    if retained is not None:
        state = "journal archived" if archived.is_file() and not archived.is_symlink() else "no archived journal found"
        return f"finished and normalised ({state}); the old workspace copy is kept", [retained]
    return "none recorded", []


def _runtime_at(root: Path) -> dict[str, Any] | None:
    """The Runtime a data root's discovery record names, and whether its process is running."""
    discovery = _read_json(root / "runtime" / "discovery.json")
    if not discovery:
        return None
    pid = discovery.get("pid")
    alive: bool | None = None
    if type(pid) is int and pid > 0:
        try:
            alive = platform.process_identity(pid) is not None
        except PermissionError:
            alive = True
        except OSError:
            alive = None
    identity = discovery.get("identity") if isinstance(discovery.get("identity"), dict) else {}
    return {"pid": pid if type(pid) is int else None, "alive": alive,
            "instance": discovery.get("runtime_instance_id"), "realm": discovery.get("active_realm"),
            "release": identity.get("release")}


def _free_bytes(*candidates: Path) -> int | None:
    for path in candidates:
        try:
            if path.exists():
                return shutil.disk_usage(path).free
        except OSError:
            continue
    return None


def _versions(root: Path | None) -> tuple[int, int]:
    folder = root / "versions" if root else None
    if folder is None or not folder.is_dir():
        return 0, 0
    try:
        count = sum(1 for item in folder.iterdir() if item.is_dir() and not item.is_symlink())
    except OSError:
        count = 0
    return count, _size(folder)


def _last_update(receipt: dict[str, Any], legacy: str) -> tuple[str, list[str]]:
    """The headline's one line for the last installer run, plus its detail rows."""
    if not receipt:
        return (f"no installer run recorded ({RECEIPT_NAME} absent); in-app update record: {legacy}", [])
    kind = receipt["kind"]
    reason = receipt.get("reason") if isinstance(receipt.get("reason"), str) else None
    headline = receipt.get("headline") if isinstance(receipt.get("headline"), str) else kind
    finished = receipt.get("finished_at")
    when = (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(finished)) if type(finished) is int
            else "time unknown")
    row = (f"{when} · {receipt.get('mode', 'install')} · {_release(receipt.get('start'))} → "
           f"{_release(receipt.get('still'))} · {kind}{f' ({reason})' if reason else ''} · exit {receipt.get('exit_code', '?')}")
    rows = [row]
    if isinstance(receipt.get("reason_line"), str) and receipt["reason_line"]:
        rows.append(f"Why: {receipt['reason_line']}")
    return headline, rows


def _row(label: str, value: str) -> str:
    return f"{label:<24} {value}"


def diagnostics_report(
    paths: RuntimePaths,
    support: dict[str, Any],
    *,
    live_identity: dict[str, Any] | None = None,
    services: list[dict[str, Any]] | None = None,
) -> str:
    """The report: a plain verdict for a person first, then the raw records under a rule.

    ``live_identity`` is the running Runtime's startup identity, when the report
    is served by that Runtime; without it the installed release is the
    selection record's. ``services`` is the Runtime's supervised service state.
    """
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
    shared_log = platform.log_dir(paths.home) / "runtime.log"
    # The in-app update job and the installer's update-transaction.json. A storage
    # move or a plain installer run writes neither, so this is not "the last update".
    legacy = (status.get("result") or "Update status unavailable.") if use_job else (
        transaction.get("result") or transaction.get("outcome") or transaction.get("step")
        or transaction.get("state") or "none recorded")
    healthy = support.get("healthy", support.get("ok", "unknown"))
    state = support.get("state") or ("healthy" if healthy is True else "unhealthy" if healthy is False else "unknown")
    receipt = _receipt(paths)
    move, retained_roots = _storage_move(paths, record)
    active_root = paths.app_support
    roots = [active_root, *(root for root in retained_roots if root != active_root)]

    # Installed and latest release.
    live = live_identity.get("release") if isinstance(live_identity, dict) else None
    installed = live if type(live) is int else identity.get("release")
    installed_from = ("the running Runtime" if type(live) is int else
                      "selection record; the running Runtime was not asked")
    latest = receipt.get("target")
    latest_text = (f"{_release(latest)} (the release the last installer run aimed for)" if type(latest) is int
                   else "unknown (no installer run recorded a target)")
    last_line, last_rows = _last_update(receipt, legacy)

    # Problems a person can act on, detected from records and log tails.
    problems: list[str] = []
    codes: list[str] = []
    runtimes = []
    for root in roots:
        found = _runtime_at(root)
        if found is not None:
            runtimes.append((root, found))
    running = [(root, found) for root, found in runtimes if found["alive"] is not False]
    if len(running) > 1:
        problems.append(f"{len(running)} Astrid Runtimes are running for one workspace (should be 1)")
        codes.append("other-runtime-running")
    tails = {root: _tail(root / "runtime" / "runtime.log", paths.home) for root in roots}
    shared_tail = _tail(shared_log, paths.home)
    full_where = [str(root) for root, text in tails.items() if _DISK_FULL.search(text)]
    if _DISK_FULL.search(shared_tail):
        full_where.append("the shared Runtime log")
    free = _free_bytes(active_root, paths.home)
    if full_where:
        problems.append("disk or database full (\"database or disk is full\" in " + ", ".join(full_where) + ")")
    elif free is not None and free < LOW_DISK_BYTES:
        problems.append(f"low disk space: {_gb(free)} free, below {LOW_DISK_BYTES // 1024 ** 3} GB")
    if full_where or (free is not None and free < LOW_DISK_BYTES):
        codes.append("disk-full")
    for service in services or support.get("services") or []:
        if not isinstance(service, dict):
            continue
        count = service.get("restart_count")
        if type(count) is int and count >= RESTART_LOOP_COUNT:
            problems.append(f"service {service.get('name', '?')} restarted {count} times (last exit {service.get('last_exit')})")
            codes.append("service-restart-loop")
    if receipt and receipt["kind"] not in RECEIPT_SUCCESS:
        problems.append(f"the last installer run did not succeed ({receipt['kind']})")
    behind = type(installed) is int and type(latest) is int and installed < latest
    if healthy is False:
        problems.append(f"this Runtime's own checks report {state}")
    verdict = "NOT OK" if problems or behind else "OK"
    issues = [issue for issue in support.get("issues") or [] if isinstance(issue, str)] if isinstance(support.get("issues"), list) else []
    issues += [code for code in codes if code not in issues]

    count, size = _versions(program_root)
    lines = [
        f"Astrid diagnostics: {verdict}. Installed: {_release(installed)}. Latest: {_release(latest)}. Last update: {last_line}",
        f"Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} · {sys.platform} · Runtime {__version__}",
        "",
        _row("Installed release", f"{_release(installed)} ({installed_from})"),
        _row("Latest release", latest_text),
        _row("Last update", last_rows[0] if last_rows else last_line),
        *(_row("", extra) for extra in last_rows[1:]),
        _row("Storage move", move),
        _row("Runtimes found", f"{len(running)} running" + (" (should be 1)" if len(running) > 1 else "")),
        *(_row("", f"· {root} · {_release(found['release'])} · instance {found['instance'] or '?'} · pid {found['pid'] or '?'} · "
               + ("running" if found["alive"] else "not running" if found["alive"] is False else "running state unknown")
               + (" (selected)" if root == active_root else " (not selected; old workspace copy)"))
          for root, found in runtimes),
        _row("Disk", f"{_gb(free)} free"),
        _row("Problems", "; ".join(problems) if problems else "none detected"),
        "",
        "--- Raw detail ---",
        f"Selection record identity: managed_by={identity.get('managed_by', record.get('managed_by', 'unknown'))}; release={identity.get('release', 'unknown')}",
        f"Active data root: {active_root}",
        *(f"Retained old workspace copy: {root}" for root in retained_roots if root != active_root),
        f"Free disk space: {free if free is not None else 'unknown'} bytes",
        f"This Runtime's support state: {state} (healthy={healthy})",
        f"Last installer run ({RECEIPT_NAME}): " + (json.dumps(receipt, sort_keys=True) if receipt else "(not available)"),
        f"Last update result: {legacy}",
        f"Update log: {tx_log_path or '(not available)'}",
        f"Installer log ({tx_log_path.name if tx_log_path else 'not available'}, last 80 lines):",
        _tail(tx_log_path, paths.home) if tx_log_path else "(not available)",
        f"Program versions on disk: {count} version{'' if count == 1 else 's'}, {size} bytes (versions folder, current version included)",
    ]
    if issues:
        lines += ["Runtime support issues:", *(f"- {issue}" for issue in issues)]
    if identity.get("managed_by", record.get("managed_by")) == "source" and launcher_log is not None:
        lines += ["Launcher log:", _tail(launcher_log, paths.home)]
    for root in roots:
        label = "selected" if root == active_root else "old workspace copy"
        lines += [f"Runtime log for {root} ({label}; runtime/runtime.log, last 80 lines):", tails[root]]
    lines += [f"Runtime log directory: {platform.log_dir(paths.home)}",
              f"Shared Runtime log ({shared_log.name}; written by every Runtime on this computer, last 80 lines):",
              shared_tail]
    return redact("\n".join(lines), paths.home)
