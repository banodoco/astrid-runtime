"""Opt-in, harness-only observation for one mounted timeline commit.

This module is deliberately a test helper, not a Runtime hook.  It uses the
existing Python trace seam to observe the mounted HTTP dispatch, handler,
coordinator, provider and store methods after the harness explicitly enables it.
It keeps only a fixed phase vocabulary, relative monotonic times and bounded
counts.  The event snapshot is a bounded last-N ring, with a request-local
bounded buffer for the final failed or still-pending dispatch so setup traffic
cannot consume its evidence.  For timeline commits, the dispatch boundary is
``RuntimeHandler._dispatch`` entry and the handler boundary is
``RuntimeHandler._timeline_commit`` entry.  Socket/client arrival and body
receipt have no earlier hook here and remain explicitly unsupported; caller
receipt is outside this process and remains UNKNOWN.
For the first explicitly enabled, mounted element-insertion ``doc.patch`` request, the handler
boundary also arms one stdlib ``cProfile`` instance on that request's thread.
It is enabled on ``_timeline_commit`` entry and disabled on its return or
exception; no profile hook is installed for other requests or threads.  Only
a bounded ``pstats`` projection is emitted, with module-relative paths and no
request data.  Raw pstats, when requested, is private temporary output.
request bodies, headers, credentials, URLs, identifiers and exception text
never cross the observation boundary.

When a private phase sink is supplied, the same opt-in also arms one daemon
timer per active dispatch.  A still-pending dispatch gets at most the bounded
watchdog capture allowance, written as a raw all-Python-thread faulthandler
dump beside the phase sink.  The timer belongs to that dispatch and is
cancelled at dispatch return, including raised and aborted returns.

The normal App launcher does not import test helpers.  A launcher that wants
this diagnostic must start the Runtime worker with this checkout on
``PYTHONPATH`` and explicitly call ``P2CommitPhaseCapture(..., enabled=True)``
in that worker before starting its HTTP server, then call ``stop()`` after the
bounded request.  Existing launchers remain unchanged when the helper is not
enabled.
"""
from __future__ import annotations

import cProfile
import faulthandler
import hashlib
import json
import math
import os
import pstats
import re
import sys
import sysconfig
import threading
import time
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self, cast

PHASES = (
    "arrival",
    "dispatch_queue",
    "handler_entry",
    "authorization",
    "coordinator_admission",
    "coordinator_lock",
    "provider",
    "accept",
    "receipt",
    "http_response",
)

DEFAULT_WATCHDOG_SECONDS = 20.0
DEFAULT_MAX_WATCHDOG_CAPTURES = 2
CAPTURE_FORMAT_VERSION = 2
RETENTION_MODE = "rolling_plus_final_request"
SAMPLING_INTERVAL_SECONDS = 0.02
WITNESS_PHASES = frozenset(("dispatch_queue", "coordinator_lock", "handler_entry"))
PROFILE_FORMAT_VERSION = 1
PROFILE_TOP_FUNCTIONS = 40
PROFILE_MAX_EDGES = 1600
PROFILE_COMMAND = "doc.patch"
_CAPTURE_NAMESPACE = 0


def _process_birth_ticks() -> int | None:
    """Return the Linux process start tick used to bind a capture to its PID."""
    try:
        stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
        return int(stat.rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _safe_route_template(path: Any) -> str | None:
    """Map the commit route to a static template without retaining route IDs."""
    if not isinstance(path, str):
        return None
    route = path.split("?", 1)[0]
    if re.fullmatch(r"/v1/projects/[^/]+/timelines/[^/]+/commit", route):
        return "/v1/projects/{project_id}/timelines/{timeline_id}/commit"
    return None


def _safe_key_hash(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_frame(frame: Any) -> tuple[str, str, int] | None:
    """Return a bounded, checkout-independent frame identity for samples."""
    code = frame.f_code
    filename = code.co_filename.replace("\\", "/")
    if "/runtime_protocol/" in filename:
        filename = "<runtime>/" + filename.rsplit("/runtime_protocol/", 1)[1]
    elif "/astrid/" in filename:
        filename = "<agent>/" + filename.rsplit("/astrid/", 1)[1]
    elif "/lib/python" in filename:
        filename = "<stdlib>/" + filename.rsplit("/", 1)[-1]
    else:
        return None
    return filename, code.co_name, frame.f_lineno


class P2CommitPhaseCapture:
    """Bounded observer for mounted Runtime commit calls.

    Observation is disabled unless ``enabled=True`` and ``start()`` is called.
    The observer is process-local and must be stopped in the same lifecycle
    owner that started it.  It is safe to use while Runtime request threads
    are active; each request gets a fresh local ordinal.
    """

    def __init__(
        self,
        sink: Path | str | None = None,
        *,
        enabled: bool = False,
        max_requests: int = 8,
        max_events: int = 128,
        max_bytes: int = 64 * 1024,
        watchdog_seconds: float = DEFAULT_WATCHDOG_SECONDS,
        max_watchdog_captures: int = DEFAULT_MAX_WATCHDOG_CAPTURES,
        timer_factory: Any = None,
        clock_ns: Any = None,
        dump_traceback: Any = None,
        utc_now: Any = None,
        sampling_interval: float = SAMPLING_INTERVAL_SECONDS,
        profile_factory: Any = None,
        profile_top_functions: int = PROFILE_TOP_FUNCTIONS,
        profile_max_edges: int = PROFILE_MAX_EDGES,
        raw_pstats_sink: Path | str | None = None,
    ) -> None:
        if (max_requests < 1 or max_events < 1 or max_bytes < 256
                or watchdog_seconds <= 0 or max_watchdog_captures < 1
                or sampling_interval <= 0 or profile_top_functions < 1
                or profile_max_edges < 1):
            raise ValueError("capture bounds must be positive")
        global _CAPTURE_NAMESPACE
        _CAPTURE_NAMESPACE += 1
        self.enabled = enabled
        self.max_requests = max_requests
        self.max_events = max_events
        self.max_bytes = max_bytes
        self.watchdog_seconds = watchdog_seconds
        self.max_watchdog_captures = max_watchdog_captures
        # D88 uses one bounded run with a 5-second pending sample and a
        # request-owned 30-second follow-up. Other existing watchdog values
        # retain their single-sample behavior.
        self._followup_watchdog_delay = 25.0 if watchdog_seconds == 5.0 else None
        self._timer_factory = timer_factory or threading.Timer
        self._clock_ns = clock_ns or time.monotonic_ns
        self._dump_traceback = dump_traceback or faulthandler.dump_traceback
        self._utc_now = utc_now or (lambda: datetime.now(UTC))
        self.sampling_interval = sampling_interval
        self._profile_factory = profile_factory or cProfile.Profile
        self.profile_top_functions = min(profile_top_functions, PROFILE_TOP_FUNCTIONS)
        self.profile_max_edges = min(profile_max_edges, PROFILE_MAX_EDGES)
        self.raw_pstats_sink = (Path(raw_pstats_sink).absolute()
                                if raw_pstats_sink is not None else None)
        self._profile_raw_written: set[int] = set()
        self._profile_selection_closed = False
        self.pid = os.getpid()
        self.birth_ticks = _process_birth_ticks()
        self.namespace = (f"pid-{self.pid}-birth-{self.birth_ticks or 'unknown'}-"
                          f"capture-{_CAPTURE_NAMESPACE}")
        self.sink = Path(sink).absolute() if sink is not None else None
        self.watchdog_sink = (self.sink.with_name(f"{self.sink.stem}.stacks.txt")
                              if self.sink is not None else None)
        self.events: list[dict[str, Any]] = []
        self.failures = 0
        self.truncated = False
        self.watchdog_captures = 0
        self.active = False
        self._stream: Any = None
        self._watchdog_stream: Any = None
        self._watchdog_lock = threading.Lock()
        self._start_ns = 0
        self._utc_anchor: str | None = None
        self._sampler_stop = threading.Event()
        self._sampler_thread: threading.Thread | None = None
        self._sampler_previous = 0.0
        self._sample_total = 0
        self._lost_samples = 0
        self._sampler_cpu_ns = 0
        self._sampler_errors: list[str] = []
        self._stack_counts: dict[tuple[str, str, int], int] = {}
        self._previous_trace: Any = None
        self._previous_thread_trace: Any = None
        self._frames: dict[int, dict[str, Any]] = {}
        self._handler_requests: dict[int, int] = {}
        self._thread_requests: dict[int, int] = {}
        self._requests: dict[int, dict[str, Any]] = {}
        self._next_request = 0
        self._lock = threading.RLock()
        self._event_sequence = 0
        self._events_seen = 0
        self._rolling_events: deque[tuple[int, dict[str, Any], int]] = deque()
        self._summary_events: list[dict[str, Any]] = []
        self._final_request: dict[str, Any] | None = None
        self.retention: dict[str, Any] = {}

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.stop()

    def start(self) -> Self:
        if not self.enabled or self.active:
            return self
        if sys.gettrace() is not None or threading.gettrace() is not None:
            raise ValueError("P2 phase capture requires no existing trace hook")
        if self.sink is not None:
            temporary = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
            if not self.sink.parent.resolve().is_relative_to(temporary) or self.sink.is_symlink():
                raise ValueError("P2 phase sink must be a new file under TMPDIR")
            if (self.watchdog_sink is not None
                    and (self.watchdog_sink.exists() or self.watchdog_sink.is_symlink())):
                raise ValueError("P2 watchdog sink must be a new file")
            self._stream = os.fdopen(
                os.open(self.sink, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                "w",
            )
        self._start_ns = self._clock_ns()
        self._utc_anchor = self._utc_text()
        self._sampler_stop.clear()
        self._sampler_previous = time.perf_counter()
        self._previous_trace = sys.gettrace()
        self._previous_thread_trace = threading.gettrace()
        self.active = True
        threading.settrace(self._trace)
        sys.settrace(self._trace)
        try:
            self._sampler_thread = threading.Thread(
                target=self._sample_stack,
                name="p2-commit-passive-sampler",
                daemon=True,
            )
            self._sampler_thread.start()
        except Exception as exc:  # noqa: BLE001 - observer failure cannot affect operation
            self._sampler_thread = None
            self._sampler_errors.append(type(exc).__name__)
        return self

    def stop(self) -> None:
        if not self.active:
            return
        with self._lock:
            self.active = False
            self._sampler_stop.set()
            for request in list(self._requests.values()):
                self._cancel_watchdog(request)
                self._stop_profile(request)
        if sys.gettrace() == self._trace:
            sys.settrace(self._previous_trace)
        if threading.gettrace() == self._trace:
            threading.settrace(self._previous_thread_trace)
        if self._sampler_thread is not None:
            self._sampler_thread.join(timeout=max(0.1, self.sampling_interval * 4))
            self._sampler_thread = None
        with self._lock:
            for request in list(self._requests.values()):
                self._summary(request)
            self._finalize_snapshot()
        if self._stream is not None:
            try:
                for event in self.events:
                    encoded = json.dumps(event, separators=(",", ":"), sort_keys=True)
                    self._stream.write(encoded + "\n")
                self._stream.flush()
                self._stream.close()
            except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
                self.failures += 1
            self._stream = None
        with self._watchdog_lock:
            if self._watchdog_stream is not None:
                try:
                    self._watchdog_stream.flush()
                    self._watchdog_stream.close()
                except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
                    self.failures += 1
                self._watchdog_stream = None

    def _at_ms(self) -> float:
        return round((self._clock_ns() - self._start_ns) / 1_000_000, 3)

    def _utc_text(self) -> str:
        value = self._utc_now()
        if not isinstance(value, datetime):
            raise TypeError("utc_now must return a datetime")
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _witness(self, request: dict[str, Any], *, phase: str) -> dict[str, Any]:
        witness = {
            "namespace": phase,
            "capture_namespace": self.namespace,
            "pid": self.pid,
            "birth_ticks": self.birth_ticks,
            "utc": self._utc_text(),
            "at_ms": self._at_ms(),
        }
        if phase in WITNESS_PHASES:
            witness.update({
                "method": request["method"],
                "route_template": request["route_template"],
                "idempotency_key_sha256": request["idempotency_key_sha256"],
            })
        return witness

    def _sample_stack(self) -> None:
        """Passively sample active Runtime request threads every 20 ms.

        This is the bounded D111a method: current frames are inspected from a
        daemon sampler, and each safe frame identity is counted at most once
        per sample.  It never changes the request or Runtime execution path.
        """
        previous = time.perf_counter()
        try:
            while not self._sampler_stop.is_set():
                started_cpu = time.thread_time_ns()
                now = time.perf_counter()
                elapsed = now - previous
                previous = now
                if elapsed > self.sampling_interval * 1.5:
                    lost = max(0, int(elapsed / self.sampling_interval) - 1)
                    with self._lock:
                        self._lost_samples += lost
                        for request in self._requests.values():
                            if not request["dispatch_finished"]:
                                request["lost_samples"] += lost
                self._sample_once()
                self._sampler_stop.wait(self.sampling_interval)
                self._sampler_cpu_ns += time.thread_time_ns() - started_cpu
        except Exception as exc:  # noqa: BLE001 - observer failure cannot affect operation
            self._sampler_errors.append(type(exc).__name__)

    def _sample_once(self) -> None:
        frames = sys._current_frames()
        with self._lock:
            active = {
                request["thread"]: request
                for request in self._requests.values()
                if not request["dispatch_finished"]
            }
        for thread_id, request in active.items():
            frame = frames.get(thread_id)
            if frame is None:
                continue
            with self._lock:
                request["sample_total"] += 1
                self._sample_total += 1
            seen: set[tuple[str, str, int]] = set()
            nearest_safe: tuple[str, str, int] | None = None
            while frame is not None:
                item = _safe_frame(frame)
                if item is not None and item not in seen:
                    seen.add(item)
                    if nearest_safe is None:
                        nearest_safe = item
                    with self._lock:
                        request["stack_counts"][item] = request["stack_counts"].get(item, 0) + 1
                        self._stack_counts[item] = self._stack_counts.get(item, 0) + 1
                frame = frame.f_back
            if nearest_safe is not None:
                with self._lock:
                    request["leaf_counts"][nearest_safe] = (
                        request["leaf_counts"].get(nearest_safe, 0) + 1)

    @staticmethod
    def _sample_rows(request: dict[str, Any], dispatch_wall_ms: float | None,
                     *, interval: float, counter: str = "stack_counts") -> list[dict[str, Any]]:
        total = request["sample_total"]
        denominator = (dispatch_wall_ms
                       if isinstance(dispatch_wall_ms, (int, float)) and dispatch_wall_ms > 0
                       else None)
        rows = []
        for (file, function, line), count in sorted(
                request[counter].items(), key=lambda item: (-item[1], item[0]))[:10]:
            rows.append({
                "file": file,
                "function": function,
                "line": line,
                "sample_count": count,
                "sample_total": total,
                "lost_samples": request["lost_samples"],
                "sample_share": count / total if total else 0.0,
                "dispatch_wall_share": (count * interval * 1000 / denominator
                                         if denominator else None),
            })
        return rows

    def _sampling_summary(self, request: dict[str, Any], dispatch_wall_ms: float | None) -> dict[str, Any]:
        return {
            "sampling_interval_ms": round(self.sampling_interval * 1000, 3),
            "sample_total": request["sample_total"],
            "lost_samples": request["lost_samples"],
            "observer_cpu_ms": round(self._sampler_cpu_ns / 1_000_000, 3),
            "observer_cpu_scope": "capture-wide",
            "observer_cpu_attribution": (
                "sampler CPU covers the whole capture and is not attributed to this request"
            ),
            "top_inclusive_frames": self._sample_rows(
                request, dispatch_wall_ms, interval=self.sampling_interval),
            "top_leaf_frames": self._sample_rows(
                request, dispatch_wall_ms, interval=self.sampling_interval,
                counter="leaf_counts"),
            "sample_membership": "each safe frame identity is counted at most once per sample",
            "dispatch_wall_denominator_ms": dispatch_wall_ms,
            "counter_limits": {
                "max_requests": self.max_requests,
                "max_events": self.max_events,
                "max_bytes": self.max_bytes,
                "top_frames": 10,
            },
            "sampler_errors": list(self._sampler_errors),
        }

    def _cancel_watchdog(self, request: dict[str, Any]) -> None:
        timer = request.get("watchdog_timer")
        if timer is not None:
            request["watchdog_timer"] = None
            try:
                timer.cancel()
            except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
                self.failures += 1

    @staticmethod
    def _profile_body(handler: Any) -> dict[str, Any] | None:
        handler_type = type(handler)
        if (handler_type.__module__ != "runtime_protocol.server"
                or handler_type.__qualname__ != "RuntimeHandler"):
            return None
        path = getattr(handler, "path", None)
        if (getattr(handler, "command", None) != "POST"
                or not isinstance(path, str) or "?" in path
                or _safe_route_template(path)
                != "/v1/projects/{project_id}/timelines/{timeline_id}/commit"):
            return None
        raw = getattr(handler, "_prefetched_body", None)
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            return None
        try:
            body = json.loads(bytes(raw))
        except (TypeError, ValueError, UnicodeDecodeError):
            return None
        if not isinstance(body, dict) or body.get("api_version") != 1:
            return None
        commands = body.get("commands")
        if not isinstance(commands, list):
            return None
        return body

    @classmethod
    def _has_element_command(cls, handler: Any) -> bool:
        body = cls._profile_body(handler)
        commands = body.get("commands") if body is not None else None
        return (isinstance(commands, list)
                and any(isinstance(command, dict)
                        and command.get("op") == PROFILE_COMMAND
                        and isinstance(command.get("args"), dict)
                        and isinstance(command["args"].get("changes"), list)
                        and any(isinstance(change, dict)
                                and change.get("op") == "list.insert"
                                and isinstance(change.get("value"), dict)
                                and isinstance(change["value"].get("elementRef"), dict)
                                for change in command["args"]["changes"])
                        for command in commands))

    @classmethod
    def _is_element_request(cls, handler: Any) -> bool:
        """Recognize only the mounted App element commit at the handler seam.

        The mounted effect Apply appends one element row. documentPatchIntent
        emits its parent clips insertion and allocation; localSaveSession adds
        the original step and App source. Params use set; Undo uses inverse.
        Reading the existing prefetch never consumes or changes ``rfile``.
        Dispatch/prefetch provenance is checked separately before arming.
        """
        body = cls._profile_body(handler)
        commands = body.get("commands") if body is not None else None
        if (body is None or body.get("dry_run", False) is not False
                or body.get("source") != {"via": "app"}
                or not isinstance(commands, list) or len(commands) != 1):
            return False
        command = commands[0]
        if (not isinstance(command, dict) or command.get("op") != PROFILE_COMMAND
                or command.get("schema_version") != 1 or command.get("version") != "1"
                or "select" not in command or command["select"] is not None
                or not isinstance(command.get("args"), dict)):
            return False
        changes = command["args"].get("changes")
        if not isinstance(changes, list) or len(changes) != 1:
            return False
        change = changes[0]
        if (not isinstance(change, dict) or change.get("op") != "list.insert"
                or change.get("ref") != "parent" or change.get("path") != ["clips"]
                or change.get("before") != {"state": "absent"}):
            return False
        row = change.get("value")
        if not isinstance(row, dict):
            return False
        element = row.get("elementRef")
        identity = change.get("id")
        order = change.get("order_before")
        steps = body.get("steps")
        return (isinstance(identity, str) and bool(identity) and row.get("id") == identity
                and command.get("created") == [f"parent/clip:{identity}"]
                and isinstance(order, list) and all(isinstance(item, str) for item in order)
                and identity not in order
                and "after_id" in change and change["after_id"] == (order[-1] if order else None)
                and isinstance(element, dict) and element.get("kind") == "effect"
                and all(isinstance(element.get(key), str) and bool(element[key])
                        for key in ("id", "revision", "packId"))
                and row.get("clipType") == element["id"]
                and isinstance(steps, list) and len(steps) == 1
                and isinstance(steps[0], dict)
                and steps[0].get("intent") == "timeline.apply_element"
                and steps[0].get("command_ordinals") == [0]
                and steps[0].get("patch") == changes)

    def _start_profile(self, request: dict[str, Any], handler: Any) -> None:
        dispatch_frame = request.get("profile_dispatch_frame")
        dispatch = self._frames.get(dispatch_frame) if isinstance(dispatch_frame, int) else None
        if (dispatch is None or dispatch.get("phase") != "request_scope"
                or dispatch.get("ordinal") != request["ordinal"]
                or request["handler"] != id(handler)
                or request["thread"] != threading.get_ident()
                or request.get("profile_prefetched_body") is None
                or request["profile_prefetched_body"] != id(getattr(handler, "_prefetched_body", None))):
            return
        # Setup/native commits are allowed before the selected element edit.
        # Once an element-shaped POST is seen, consume the one-shot selection,
        # including a mixed-command or dry-run refusal, so retries cannot move
        # profiling to a different request.
        if not self._has_element_command(handler):
            return
        with self._lock:
            if self._profile_selection_closed:
                return
            self._profile_selection_closed = True
        if not self._is_element_request(handler):
            return
        request["profile_eligible"] = True
        previous = sys.getprofile()
        request["profile_previous"] = previous
        try:
            profile = self._profile_factory()
            enable = getattr(profile, "enable", None)
            if not callable(enable):
                raise TypeError
            request["profile"] = profile
            enable()
            request["profile_started"] = True
        except Exception:  # noqa: BLE001 - diagnostics never affect the request
            request["profile_failed"] = True
        finally:
            if not request["profile_started"]:
                profile = request.get("profile")
                disable = getattr(profile, "disable", None)
                if callable(disable):
                    try:
                        disable()
                    except Exception:  # noqa: BLE001 - diagnostics never affect the request
                        request["profile_failed"] = True
                try:
                    sys.setprofile(previous)
                except Exception:  # noqa: BLE001 - diagnostics never affect the request
                    request["profile_failed"] = True
                request["profile_stopped"] = True

    @staticmethod
    def _stop_profile(request: dict[str, Any]) -> None:
        profile = request.get("profile")
        if (not request.get("profile_started") or request.get("profile_stopped")
                or profile is None):
            return
        try:
            profile.disable()
        except Exception:  # noqa: BLE001 - diagnostics never affect the request
            request["profile_failed"] = True
        finally:
            try:
                sys.setprofile(request["profile_previous"])
            except Exception:  # noqa: BLE001 - diagnostics never affect the request
                request["profile_failed"] = True
            request["profile_stopped"] = True

    @staticmethod
    def _safe_profile_file(filename: Any) -> str | None:
        if not isinstance(filename, str):
            return None
        normalized = filename.replace("\\", "/")
        if normalized in {"~", "<built-in>", "<builtin>"}:
            return "<stdlib>/builtin"
        for marker, prefix in (("/runtime_protocol/", "<runtime>/"),
                               ("/astrid/", "<agent>/"),
                               ("/site-packages/", "<package>/"),
                               ("/dist-packages/", "<package>/")):
            if marker in normalized:
                value = prefix + normalized.rsplit(marker, 1)[1]
                return value if len(value) <= 240 else None
        stdlib = sysconfig.get_paths().get("stdlib")
        if isinstance(stdlib, str):
            root = stdlib.replace("\\", "/").rstrip("/") + "/"
            if normalized.startswith(root):
                value = "<stdlib>/" + normalized[len(root):]
                return value if len(value) <= 240 else None
        if normalized.startswith(("<runtime>/", "<agent>/", "<stdlib>/", "<package>/")):
            return normalized if len(normalized) <= 240 else None
        return None

    @staticmethod
    def _safe_profile_function(function: Any) -> str | None:
        if not isinstance(function, str) or not function or len(function) > 160:
            return None
        safe = re.sub(r"[^A-Za-z0-9_.$<>:' -]", "_", function)
        return safe[:160] if safe else None

    @classmethod
    def _safe_profile_key(cls, key: Any) -> tuple[str, int, str] | None:
        if not isinstance(key, tuple) or len(key) != 3:
            return None
        filename, line, function = key
        if type(line) is not int or line < 0:
            return None
        safe_file = cls._safe_profile_file(filename)
        safe_function = cls._safe_profile_function(function)
        if safe_file is None or safe_function is None:
            return None
        return safe_file, line, safe_function

    @staticmethod
    def _profile_call_count(value: Any) -> int | None:
        if type(value) is int:
            return max(0, value)
        if isinstance(value, tuple) and len(value) >= 2 and type(value[1]) is int:
            return max(0, value[1])
        return None

    def _raw_profile_path(self, ordinal: int) -> Path | None:
        if self.raw_pstats_sink is None:
            return None
        base = self.raw_pstats_sink
        if ordinal > 1:
            base = base.with_name(f"{base.stem}.request-{ordinal}{base.suffix}")
        temporary = Path(os.environ.get("TMPDIR", "/tmp")).resolve()
        parent = base.parent
        if (parent == temporary or not parent.is_relative_to(temporary)
                or base.is_symlink() or base.exists() or parent.is_symlink()
                or not parent.is_dir()):
            return None
        try:
            parent_stat = parent.stat()
            if (parent_stat.st_uid != os.getuid()
                    or parent_stat.st_mode & 0o777 != 0o700):
                return None
            current = temporary
            for component in parent.relative_to(temporary).parts:
                current /= component
                if current.is_symlink() or not current.is_dir():
                    return None
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(base, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        except OSError:
            return None
        return base

    def _profile_projection(self, request: dict[str, Any]) -> dict[str, Any]:
        if request["profile_failed"] or request["profile"] is None:
            return {
                "format_version": PROFILE_FORMAT_VERSION,
                "status": "unavailable",
                "scope": "RuntimeHandler._timeline_commit",
                "functions": [],
                "edges": [],
                "limits": {
                    "max_functions": self.profile_top_functions,
                    "max_edges": self.profile_max_edges,
                    "dropped_rows": 0,
                    "dropped_edges": 0,
                },
                "rank_meaning": "unavailable",
                "timing_note": "cProfile overhead is not measured as original budget time",
            }
        try:
            profile = request["profile"]
            stats = pstats.Stats(profile)
            stats_data = cast(
                dict[tuple[str, int, str], tuple[Any, ...]],
                getattr(stats, "stats", {}),
            )
            safe_rows: list[dict[str, Any]] = []
            unsafe_rows = 0
            for key, values in stats_data.items():
                safe_key = self._safe_profile_key(key)
                if safe_key is None or not isinstance(values, tuple) or len(values) < 4:
                    unsafe_rows += 1
                    continue
                primitive_calls, calls, tottime, cumtime = values[:4]
                if (type(primitive_calls) is not int or type(calls) is not int
                        or not isinstance(tottime, (int, float))
                        or not isinstance(cumtime, (int, float))
                        or not math.isfinite(tottime) or not math.isfinite(cumtime)):
                    unsafe_rows += 1
                    continue
                safe_rows.append({
                    "file": safe_key[0],
                    "line": safe_key[1],
                    "function": safe_key[2],
                    "ncalls": max(0, calls),
                    "primitive_calls": max(0, primitive_calls),
                    "tottime": float(tottime),
                    "cumtime": float(cumtime),
                    "_key": key,
                })
            safe_rows.sort(key=lambda row: (
                -row["cumtime"], row["file"], row["line"], row["function"]))
            top = safe_rows[:self.profile_top_functions]
            top_keys = {row["_key"]: row for row in top}
            functions = []
            for rank, row in enumerate(top, 1):
                functions.append({key: value for key, value in row.items() if key != "_key"} | {
                    "rank": rank,
                })

            candidate_edges: list[tuple[int, int, int, dict[str, Any]]] = []
            for callee_key, callee in top_keys.items():
                callee_stats = stats_data.get(callee_key)
                callers = (callee_stats[4]
                           if isinstance(callee_stats, tuple) and len(callee_stats) >= 5 else {})
                if not isinstance(callers, dict):
                    continue
                for caller_key, call_value in callers.items():
                    caller = top_keys.get(caller_key)
                    calls = self._profile_call_count(call_value)
                    if caller is None or calls is None:
                        continue
                    edge = {
                        "caller": {
                            "file": caller["file"], "line": caller["line"],
                            "function": caller["function"],
                        },
                        "callee": {
                            "file": callee["file"], "line": callee["line"],
                            "function": callee["function"],
                        },
                        "ncalls": calls,
                    }
                    candidate_edges.append((
                        top.index(caller), top.index(callee), calls, edge))
            candidate_edges.sort(key=lambda item: (-item[2], item[0], item[1]))
            edges = [item[3] for item in candidate_edges[:self.profile_max_edges]]
            raw_path = self._raw_profile_path(request["ordinal"])
            if raw_path is not None:
                try:
                    profile.dump_stats(str(raw_path))
                    os.chmod(raw_path, 0o600)
                    self._profile_raw_written.add(request["ordinal"])
                except Exception:  # noqa: BLE001 - private diagnostic persistence is optional
                    request["profile_failed"] = True
            return {
                "format_version": PROFILE_FORMAT_VERSION,
                "status": "captured",
                "scope": "RuntimeHandler._timeline_commit",
                "functions": functions,
                "edges": edges,
                "limits": {
                    "max_functions": self.profile_top_functions,
                    "max_edges": self.profile_max_edges,
                    "dropped_rows": unsafe_rows + max(0, len(safe_rows) - len(top)),
                    "dropped_edges": max(0, len(candidate_edges) - len(edges)),
                },
                "rank_meaning": "functions sorted descending cumtime, then file/line/function",
                "timing_note": "cProfile overhead inflates absolute times; use ranking and call counts observationally, never as the original budget",
            }
        except Exception:  # noqa: BLE001 - diagnostics never affect the request
            request["profile_failed"] = True
            return {
                "format_version": PROFILE_FORMAT_VERSION,
                "status": "unavailable",
                "scope": "RuntimeHandler._timeline_commit",
                "functions": [],
                "edges": [],
                "limits": {
                    "max_functions": self.profile_top_functions,
                    "max_edges": self.profile_max_edges,
                    "dropped_rows": 0,
                    "dropped_edges": 0,
                },
                "rank_meaning": "unavailable",
                "timing_note": "cProfile overhead is not measured as original budget time",
            }

    def _arm_watchdog(self, ordinal: int) -> None:
        if self.sink is None or self.watchdog_sink is None:
            return
        request: dict[str, Any] | None = None
        try:
            with self._lock:
                request = self._requests.get(ordinal)
                if request is None or not self.active:
                    return
                token = object()
                timer = self._timer_factory(
                    self.watchdog_seconds,
                    lambda: self._watchdog_fire(ordinal, token),
                )
                timer.daemon = True
                request["watchdog_token"] = token
                request["watchdog_timer"] = timer
                timer.start()
        except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
            if request is not None:
                request["watchdog_timer"] = None
            self.failures += 1

    def _watchdog_fire(self, ordinal: int, token: object) -> None:
        request = self._requests.get(ordinal)
        with self._lock:
            if (not self.active or request is None
                    or request.get("watchdog_token") is not token
                    or request.get("dispatch_finished")
                    or self.watchdog_captures >= self.max_watchdog_captures):
                return
            request["watchdog_fired"] = True
            request["watchdog_timer"] = None
            request["watchdog_stage"] += 1
            self.watchdog_captures += 1
        try:
            with self._watchdog_lock:
                if not self.active:
                    return
                if self._watchdog_stream is None:
                    assert self.watchdog_sink is not None
                    fd = os.open(
                        self.watchdog_sink,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                    os.fchmod(fd, 0o600)
                    self._watchdog_stream = os.fdopen(fd, "w", buffering=1)
                self._dump_traceback(file=self._watchdog_stream, all_threads=True)
                self._watchdog_stream.flush()
        except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
            self.failures += 1
        if request.get("watchdog_stage") == 1 and self._followup_watchdog_delay is not None:
            try:
                with self._lock:
                    if (not self.active or request.get("dispatch_finished")
                            or self.watchdog_captures >= self.max_watchdog_captures):
                        return
                    followup_token = object()
                    timer = self._timer_factory(
                        self._followup_watchdog_delay,
                        lambda: self._watchdog_fire(ordinal, followup_token),
                    )
                    timer.daemon = True
                    request["watchdog_token"] = followup_token
                    request["watchdog_timer"] = timer
                    timer.start()
            except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
                request["watchdog_timer"] = None
                self.failures += 1

    @staticmethod
    def _encoded_size(event: dict[str, Any]) -> int:
        return len(json.dumps(event, separators=(",", ":"), sort_keys=True)) + 1

    @staticmethod
    def _request_outcome(request: dict[str, Any]) -> str:
        if not request["dispatch_finished"]:
            return "pending_at_stop"
        if request["dispatch_returned"] and request["phases"]["http_response"]["count"]:
            return "completed"
        if request["dispatch_raised"]:
            return "raised"
        return "returned_without_response"

    def _record_request_event(self, request: dict[str, Any], event: dict[str, Any], size: int) -> None:
        request["events_seen"] += 1
        request["events_required_bytes"] += size
        if size > self.max_bytes:
            request["events_dropped"] += 1
            request["events_dropped_bytes"] += size
            self.truncated = True
            return
        buffer = request["event_buffer"]
        buffer.append((self._event_sequence, event, size))
        request["event_buffer_bytes"] += size
        while request["event_buffer_bytes"] > self.max_bytes:
            _sequence, _old_event, old_size = buffer.popleft()
            request["event_buffer_bytes"] -= old_size
            request["events_dropped"] += 1
            request["events_dropped_bytes"] += old_size
            self.truncated = True

    def _write(self, event: dict[str, Any], *, track_request: bool = True) -> None:
        size = self._encoded_size(event)
        with self._lock:
            self._event_sequence += 1
            self._events_seen += 1
            if track_request and type(event.get("request")) is int:
                request = self._requests.get(event["request"])
                if request is not None:
                    self._record_request_event(request, event, size)
            if len(self._rolling_events) >= self.max_events:
                self._rolling_events.popleft()
                self.truncated = True
            self._rolling_events.append((self._event_sequence, event, size))
            # Preserve the existing inspectable live view; shutdown replaces
            # it with the final request-aware snapshot.
            self.events = [entry[1] for entry in self._rolling_events]

    def _new_request(self, *, handler: Any = None, emit_handler: bool = False) -> int | None:
        with self._lock:
            if self._next_request >= self.max_requests:
                self.truncated = True
                return None
            self._next_request += 1
            ordinal = self._next_request
            method = getattr(handler, "command", None) if handler is not None else None
            headers = getattr(handler, "headers", None) if handler is not None else None
            get_header = getattr(headers, "get", None)
            key = get_header("Idempotency-Key") if callable(get_header) else None
            self._requests[ordinal] = {
                "ordinal": ordinal,
                "phases": {phase: {"count": 0, "start_ms": None, "end_ms": None, "error": False}
                            for phase in PHASES},
                "last_phase": None,
                "handler": id(handler) if handler is not None else None,
                "thread": threading.get_ident(),
                "method": method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else None,
                "route_template": _safe_route_template(getattr(handler, "path", None)),
                "idempotency_key_sha256": _safe_key_hash(key),
                "dispatch_start_ms": None,
                "dispatch_end_ms": None,
                "dispatch_finished": False,
                "dispatch_returned": False,
                "dispatch_raised": False,
                "watchdog_timer": None,
                "watchdog_token": None,
                "watchdog_fired": False,
                "watchdog_stage": 0,
                "event_buffer": deque(),
                "event_buffer_bytes": 0,
                "events_seen": 0,
                "events_required_bytes": 0,
                "events_dropped": 0,
                "events_dropped_bytes": 0,
                "sample_total": 0,
                "lost_samples": 0,
                "stack_counts": {},
                "leaf_counts": {},
                "profile_eligible": False,
                "profile": None,
                "profile_started": False,
                "profile_stopped": False,
                "profile_failed": False,
                "profile_previous": None,
            }
            if handler is not None:
                self._handler_requests[id(handler)] = ordinal
            self._thread_requests[threading.get_ident()] = ordinal
        if emit_handler:
            self._begin(ordinal, "handler_entry")
            self._arm_watchdog(ordinal)
        return ordinal

    def _select_final_request(self) -> dict[str, Any] | None:
        candidates = [request for request in self._requests.values()
                      if self._request_outcome(request) != "completed"]
        return max(candidates, key=lambda request: request["ordinal"], default=None)

    def _request_for_frame(self, frame: Any) -> int | None:
        handler = frame.f_locals.get("self")
        if handler is not None:
            ordinal = self._handler_requests.get(id(handler))
            if ordinal is not None:
                return ordinal
        ordinal = self._thread_requests.get(threading.get_ident())
        if ordinal is not None:
            return ordinal
        parent = frame.f_back
        while parent is not None:
            handler = parent.f_locals.get("self")
            ordinal = self._handler_requests.get(id(handler)) if handler is not None else None
            if ordinal is not None:
                return ordinal
            parent = parent.f_back
        return None

    def _begin(self, ordinal: int, phase: str, **fields: Any) -> None:
        request = self._requests.get(ordinal)
        if request is None or phase not in PHASES:
            return
        if phase == "arrival":
            # No earlier socket/server-accept hook is available in this
            # helper.  Never turn the dispatch hook into a false arrival.
            return
        state = request["phases"][phase]
        state["count"] = min(state["count"] + 1, 32)
        now = self._at_ms()
        state["start_ms"] = now if state["start_ms"] is None else state["start_ms"]
        if phase == "dispatch_queue" and request["dispatch_start_ms"] is None:
            request["dispatch_start_ms"] = now
        if phase == "http_response" and type(fields.get("status")) is int:
            state["status"] = fields["status"]
        request["last_phase"] = phase
        safe_fields = {"status": fields["status"]} if phase == "http_response" and type(fields.get("status")) is int else {}
        event = {"schema_version": 1, "request": ordinal, "phase": phase,
                 "state": "start", "at_ms": now, "count": state["count"], **safe_fields}
        if phase in WITNESS_PHASES:
            event.update(self._witness(request, phase=phase))
        else:
            event.update({"utc": self._utc_text(), "capture_namespace": self.namespace})
        self._write(event)

    def _end(self, ordinal: int, phase: str, *, error: bool = False, **fields: Any) -> None:
        request = self._requests.get(ordinal)
        if request is None or phase not in PHASES:
            return
        if phase == "arrival":
            return
        state = request["phases"][phase]
        state["end_ms"] = self._at_ms()
        state["error"] = state["error"] or error
        if phase == "http_response" and type(fields.get("status")) is int:
            state["status"] = fields["status"]
        safe_fields = {"status": fields["status"]} if phase == "http_response" and type(fields.get("status")) is int else {}
        event = {"schema_version": 1, "request": ordinal, "phase": phase,
                 "state": "raised" if error else "end", "at_ms": state["end_ms"],
                 "count": state["count"], **safe_fields}
        if phase in WITNESS_PHASES:
            event.update(self._witness(request, phase=phase))
        else:
            event.update({"utc": self._utc_text(), "capture_namespace": self.namespace})
        self._write(event)

    def _summary(self, request: dict[str, Any]) -> None:
        phases = {}
        for phase in PHASES:
            state = request["phases"][phase]
            phases[phase] = {
                "status": ("unsupported" if phase == "arrival" and state["count"] == 0
                            else "UNKNOWN" if state["count"] == 0 else "observed"),
                "count": state["count"],
                "start_ms": state["start_ms"],
                "end_ms": state["end_ms"],
            }
            if phase == "arrival" and state["count"] == 0:
                phases[phase]["reason"] = "no earlier socket/server-accept hook"
            if state["error"]:
                phases[phase]["status"] = "raised"
        dispatch_start = phases["dispatch_queue"]["start_ms"]
        handler_start = phases["handler_entry"]["start_ms"]
        dispatch_end = (request["dispatch_end_ms"]
                        if request["dispatch_returned"] else None)
        provider = phases["provider"]

        def duration(start: Any, end: Any) -> float | None:
            if type(start) not in (int, float) or type(end) not in (int, float):
                return None
            return round(end - start, 3)

        durations = {
            # This boundary is RuntimeHandler._dispatch entry.  It is not a
            # socket/client-arrival or body-read boundary.
            "dispatch_queue_ms": duration(dispatch_start, handler_start),
            "handler_ms": duration(handler_start, dispatch_end),
            "dispatch_total_ms": duration(dispatch_start, dispatch_end),
            "dispatch_to_completion_wall_ms": duration(dispatch_start, dispatch_end),
            "provider_wall_ms": duration(provider["start_ms"], provider["end_ms"]),
            "response_write_wall_ms": duration(
                phases["http_response"]["start_ms"], phases["http_response"]["end_ms"]),
            "execution_lock_wait_ms": None,
            "caller_receipt_ms": None,
        }
        summary = {"schema_version": 1, "request": request["ordinal"], "phase": "summary",
                   "last_phase": request["last_phase"] or "UNKNOWN", "phases": phases,
                   "lifecycle": self._request_outcome(request),
                   "durations_ms": durations,
                   "utc": self._utc_text(), "at_ms": self._at_ms(),
                   "capture_anchor": {"utc": self._utc_anchor, "at_ms": 0.0},
                   "capture_namespace": self.namespace, "pid": self.pid,
                   "birth_ticks": self.birth_ticks,
                   "method": request["method"], "route_template": request["route_template"],
                   "idempotency_key_sha256": request["idempotency_key_sha256"],
                   "dispatch_start_ms": request["dispatch_start_ms"],
                   "sampling": self._sampling_summary(
                       request, durations["dispatch_to_completion_wall_ms"]),
                   "unknown_boundaries": {
                       "client_request_to_server_receive": (
                           "unsupported: no earlier socket/server-accept hook"),
                       "request_body_receive": (
                           "unsupported: no body-read hook; body time is not separately measured"),
                       "execution_lock_wait": "phase hook has no exact threading.Lock.acquire boundary",
                       "caller_receipt": "outside Runtime process",
                   },
                   "unsupported_boundaries": {
                       "network_arrival_ms": None,
                       "request_body_receive_ms": None,
                       "execution_lock_wait_ms": None,
                       "caller_receipt_ms": None,
                   },
                   "truncated": self.truncated}
        if request["profile_eligible"]:
            summary["cprofile"] = self._profile_projection(request)
        self._summary_events.append(summary)
        # Summaries are synthetic snapshot records; the phase records are the
        # request evidence whose completeness is tracked independently.
        self._write(summary, track_request=False)

    def _incomplete_limit(self, request: dict[str, Any] | None) -> dict[str, Any] | None:
        if request is None or request["events_dropped"] == 0:
            return None
        return {
            "reason": "max_bytes",
            "limit_bytes": self.max_bytes,
            "required_bytes": request["events_required_bytes"],
            "retained_bytes": request["event_buffer_bytes"],
            "dropped_events": request["events_dropped"],
            "dropped_bytes": request["events_dropped_bytes"],
        }

    def _retention_metadata(
        self,
        *,
        selected: list[tuple[int, dict[str, Any], int]],
        rolling_events: list[tuple[int, dict[str, Any], int]],
        target: dict[str, Any] | None,
    ) -> dict[str, Any]:
        selected_sequences = {sequence for sequence, _event, _size in selected}
        rolling_selected = sum(
            sequence in selected_sequences for sequence, _event, _size in rolling_events
        )
        rolling_output_drop = len(rolling_events) - rolling_selected
        rolling_limit = None
        if rolling_output_drop:
            rolling_limit = {
                "reason": "max_bytes",
                "limit_bytes": self.max_bytes,
                "dropped_events": rolling_output_drop,
                "dropped_bytes": sum(
                    size for sequence, _event, size in rolling_events
                    if sequence not in selected_sequences
                ),
            }
        final_metadata: dict[str, Any] | None = None
        if target is not None:
            target_events = list(target["event_buffer"])
            target_sequences = {sequence for sequence, _event, _size in target_events}
            target_selected = len(target_sequences & selected_sequences)
            target_dropped_by_output = len(target_events) - target_selected
            complete = target["events_dropped"] == 0 and target_dropped_by_output == 0
            incomplete = self._incomplete_limit(target)
            if target_dropped_by_output:
                complete = False
                incomplete = {
                    "reason": "max_bytes",
                    "limit_bytes": self.max_bytes,
                    "required_bytes": target["events_required_bytes"],
                    "retained_bytes": sum(
                        size for sequence, _event, size in target_events
                        if sequence in selected_sequences
                    ),
                    "dropped_events": target["events_dropped"] + target_dropped_by_output,
                    "dropped_bytes": target["events_dropped_bytes"] + sum(
                        size for sequence, _event, size in target_events
                        if sequence not in selected_sequences
                    ),
                }
            final_metadata = {
                "request": target["ordinal"],
                "outcome": self._request_outcome(target),
                "events_seen": target["events_seen"],
                "events_retained": target_selected,
                "buffer_complete": complete,
                "complete": complete,
                "incomplete_limit": incomplete,
            }
        return {
            "format_version": CAPTURE_FORMAT_VERSION,
            "mode": RETENTION_MODE,
            "rolling": {
                "capacity_events": self.max_events,
                "events_seen": self._events_seen,
                "events_retained": rolling_selected,
                "capacity_dropped_events": max(0, self._events_seen - self.max_events),
                "complete": rolling_output_drop == 0,
                "incomplete_limit": rolling_limit,
            },
            "final_request": final_metadata,
            "output": {
                "max_bytes": self.max_bytes,
                "bytes": sum(size for _sequence, _event, size in selected),
                "events": len(selected),
            },
        }

    def _finalize_snapshot(self) -> None:
        target = self._select_final_request()
        self._final_request = target
        target_events = list(target["event_buffer"]) if target is not None else []
        snapshot: list[tuple[int, dict[str, Any], int]] = []
        for _attempt in range(3):
            rolling_events = [
                (sequence, event, self._encoded_size(event))
                for sequence, event, _size in self._rolling_events
            ]
            selected: dict[int, tuple[int, dict[str, Any], int]] = {}
            used_bytes = 0
            for entry in target_events:
                sequence, _event, size = entry
                if used_bytes + size <= self.max_bytes:
                    selected[sequence] = entry
                    used_bytes += size
            for entry in reversed(rolling_events):
                sequence, _event, size = entry
                if sequence in selected:
                    continue
                if used_bytes + size <= self.max_bytes:
                    selected[sequence] = entry
                    used_bytes += size
            snapshot = sorted(selected.values(), key=lambda entry: entry[0])
            self.retention = self._retention_metadata(
                selected=snapshot, rolling_events=rolling_events, target=target)
            for summary in self._summary_events:
                summary["retention"] = self.retention
        self.events = [event for _sequence, event, _size in snapshot]

    @staticmethod
    def _phase(frame: Any) -> str | None:
        module = frame.f_globals.get("__name__")
        qualname = frame.f_code.co_qualname
        if module == "runtime_protocol.server":
            return {
                "RuntimeHandler._dispatch": "dispatch_scope",
                "RuntimeHandler._prefetch_body": "profile_prefetch",
                "RuntimeHandler._timeline_commit": "handler_entry",
                "RuntimeHandler._authorize_timeline_commit": "authorization",
                "RuntimeHandler._send": "http_response",
            }.get(qualname)
        if module == "runtime_protocol.timeline_commit_execution":
            return "coordinator_admission" if qualname == "CommitExecutionCoordinator._execution" else None
        if module == "runtime_protocol.timeline_commit_port":
            return "accept" if qualname == "RequestCommitPort.accept" else None
        if module == "runtime_protocol.timeline_commit_store":
            return "receipt" if qualname == "TimelineCommitStore.accept" else None
        return None

    @staticmethod
    def _code_for(value: Any) -> Any:
        function = getattr(value, "__func__", value)
        return getattr(function, "__code__", None)

    def _trace(self, frame: Any, event: str, arg: Any) -> Any:
        if not self.active:
            return None
        try:
            return self._trace_inner(frame, event, arg)
        except Exception:  # noqa: BLE001 - observer failure cannot affect the operation
            self.failures += 1
            return self._trace

    def _trace_inner(self, frame: Any, event: str, arg: Any) -> Any:
        if event == "call":
            # Phase attribution needs call/return/exception, never line events.
            frame.f_trace_lines = False
            previous = self._frames.get(id(frame))
            if previous is not None and previous.get("phase") == "coordinator_admission":
                return self._trace
            phase = self._phase(frame)
            if phase == "dispatch_scope":
                handler = frame.f_locals.get("self")
                path = getattr(handler, "path", "") if handler is not None else ""
                command = getattr(handler, "command", None) if handler is not None else None
                if (command != "POST" or not isinstance(path, str)
                        or "/timelines/" not in path.split("?", 1)[0]
                        or not path.split("?", 1)[0].endswith("/commit")):
                    return None
                ordinal = self._new_request(handler=handler)
                if ordinal is None:
                    return None
                if frame.f_code is self._code_for(getattr(type(handler), "_dispatch", None)):
                    self._requests[ordinal]["profile_dispatch_frame"] = id(frame)
                self._begin(ordinal, "dispatch_queue")
                self._arm_watchdog(ordinal)
                self._frames[id(frame)] = {"phase": "request_scope", "ordinal": ordinal}
                return self._trace
            if phase == "profile_prefetch":
                handler = frame.f_locals.get("self")
                ordinal = self._handler_requests.get(id(handler))
                if ordinal is None:
                    return None
                request = self._requests[ordinal]
                if (request.get("profile_dispatch_frame") != id(frame.f_back)
                        or frame.f_code is not self._code_for(getattr(type(handler), "_prefetch_body", None))
                        or frame.f_locals.get("limit") != getattr(handler, "TIMELINE_BODY_BYTES", None)):
                    return None
                self._frames[id(frame)] = {"phase": phase, "ordinal": ordinal, "error": False}
                return self._trace
            if phase == "handler_entry":
                handler = frame.f_locals.get("self")
                ordinal = self._request_for_frame(frame)
                if ordinal is None:
                    ordinal = self._new_request(handler=handler, emit_handler=True)
                if ordinal is None:
                    return None
                if self._requests[ordinal]["phases"]["dispatch_queue"]["count"]:
                    self._end(ordinal, "dispatch_queue")
                self._begin(ordinal, phase)
                self._frames[id(frame)] = {"phase": phase, "ordinal": ordinal, "error": False}
                self._start_profile(self._requests[ordinal], handler)
                return self._trace
            if (phase is None
                    and frame.f_code.co_qualname != "CommitExecutionCoordinator.execute"
                    and frame.f_code not in self._frames):
                return None
            ordinal = self._request_for_frame(frame)
            if phase is None and frame.f_code.co_qualname == "CommitExecutionCoordinator.execute":
                ordinal = ordinal or self._new_request()
                provider = frame.f_locals.get("provider")
                code = self._code_for(getattr(provider, "commit", None))
                if code is not None:
                    self._frames[code] = {"dynamic": "provider"}
            if phase is None:
                if ordinal is None:
                    return None
                dynamic = self._frames.get(frame.f_code)
                phase = dynamic.get("dynamic") if dynamic else None
            if phase is None or ordinal is None:
                return None
            self._begin(ordinal, phase,
                        **({"status": frame.f_locals.get("status")}
                           if phase == "http_response" and type(frame.f_locals.get("status")) is int else {}))
            self._frames[id(frame)] = {"phase": phase, "ordinal": ordinal, "error": False,
                                       "yielded": False, "acquired": False}
            return self._trace

        state = self._frames.get(id(frame))
        if state is None:
            return self._trace
        phase = state["phase"]
        ordinal = state["ordinal"]
        if phase == "profile_prefetch":
            if event == "exception":
                state["error"] = True
            elif event == "return":
                handler = frame.f_locals.get("self")
                raw = getattr(handler, "_prefetched_body", None)
                if not state["error"] and isinstance(raw, bytes):
                    self._requests[ordinal]["profile_prefetched_body"] = id(raw)
                del self._frames[id(frame)]
            return self._trace
        if phase == "request_scope":
            if event == "exception":
                state["error"] = True
                return self._trace
            if event == "return":
                request = self._requests[ordinal]
                request["dispatch_returned"] = True
                request["dispatch_raised"] = state.get("error", False)
                if not request["dispatch_raised"]:
                    request["dispatch_end_ms"] = self._at_ms()
                if request["phases"]["dispatch_queue"]["end_ms"] is None:
                    self._end(ordinal, "dispatch_queue", error=state.get("error", False))
                with self._lock:
                    request["dispatch_finished"] = True
                self._cancel_watchdog(request)
                if self._handler_requests.get(request["handler"]) == ordinal:
                    del self._handler_requests[request["handler"]]
                if self._thread_requests.get(request["thread"]) == ordinal:
                    del self._thread_requests[request["thread"]]
                del self._frames[id(frame)]
            return self._trace
        if event == "exception":
            state["error"] = True
            if phase == "handler_entry":
                self._stop_profile(self._requests[ordinal])
            return self._trace
        if event != "return":
            return self._trace
        if phase == "coordinator_admission" and not state["yielded"]:
            if state["error"]:
                self._end(ordinal, phase, error=True)
                del self._frames[id(frame)]
                return self._trace
            state["yielded"] = True
            state["acquired"] = arg is True
            if state["acquired"]:
                self._begin(ordinal, "coordinator_lock")
            return self._trace
        if phase == "coordinator_admission" and state["yielded"]:
            if state["acquired"]:
                self._end(ordinal, "coordinator_lock", error=state["error"])
            self._end(ordinal, phase, error=state["error"])
        else:
            if phase == "handler_entry":
                self._stop_profile(self._requests[ordinal])
            fields = {}
            if phase == "http_response" and type(frame.f_locals.get("status")) is int:
                fields["status"] = frame.f_locals["status"]
            self._end(ordinal, phase, error=state["error"], **fields)
        del self._frames[id(frame)]
        return self._trace


CommitPhaseCapture = P2CommitPhaseCapture


def install_p2_commit_phase_capture(*args: Any, **kwargs: Any) -> P2CommitPhaseCapture:
    """Explicit activation convenience for a harness-owned worker."""
    capture = P2CommitPhaseCapture(*args, enabled=True, **kwargs)
    return capture.start()
