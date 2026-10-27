"""Profile-declared services; no product imports or executable discovery."""

from __future__ import annotations

import codecs
import errno
import json
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import platform
from .errors import ValidationError
from .logs import RotatingLog


_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_READY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_RESERVED_ENV = {"PYTHONPATH", "PYTHONHOME", "ASTRID_RUNTIME_JOB_HANDLE", "ASTRID_RUNTIME_SERVICE_NAME",
    "ASTRID_RUNTIME_SERVICE_LAUNCH_ID"}
_STARTUP_STABLE_SECONDS = 2.0
_FAST_FAILURE_LIMIT = 3


@dataclass(frozen=True)
class ServiceSpec:
    name: str
    argv: tuple[str, ...]
    restart: str
    env: dict[str, str] = field(default_factory=dict)
    ready_file: str | None = None
    ready_timeout: float = 30.0


@dataclass(frozen=True)
class ServiceConfiguration:
    services: tuple[ServiceSpec, ...]
    python: str
    source_checkout: Path


def _string(value, *, empty=False):
    return isinstance(value, str) and (empty or bool(value)) and "\0" not in value


def parse_services(value):
    """Validate the services.json contract without a runtime jsonschema dependency."""
    def invalid(detail):
        raise ValidationError("Invalid service declaration: " + detail)

    if (not isinstance(value, dict) or set(value) != {"version", "services"}
            or type(value["version"]) is not int or value["version"] != 1):
        invalid("expected version 1 and services")
    rows = value["services"]
    if not isinstance(rows, list) or len(rows) > 32:
        invalid("services must be an array of at most 32 entries")
    names, ready_files, specs = set(), set(), []
    for row in rows:
        if (not isinstance(row, dict) or set(row) - {"name", "argv", "env", "restart", "ready"}
                or not {"name", "argv", "restart"} <= set(row)):
            invalid("unsupported or missing service fields")
        name = row["name"]
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in names:
            invalid("service names must be unique lowercase identifiers")
        names.add(name)
        argv = row["argv"]
        if not isinstance(argv, list) or not 1 <= len(argv) <= 256 or not all(_string(arg) for arg in argv):
            invalid("argv must be a nonempty array of nonempty strings")
        env = row.get("env", {})
        if (not isinstance(env, dict) or any(not isinstance(k, str) or not _ENV.fullmatch(k)
                or not _string(v, empty=True) for k, v in env.items())):
            invalid("env must contain valid names and string values")
        if any(k.upper() in _RESERVED_ENV or k.upper().startswith("ASTRID_RUNTIME_CUSTODY_") for k in env):
            invalid("env must not override Python imports or Runtime custody")
        if row["restart"] not in ("always", "on-failure"):
            invalid("restart must be always or on-failure")
        ready_file, timeout = None, 30.0
        if "ready" in row:
            ready = row["ready"]
            if (not isinstance(ready, dict) or set(ready) - {"file", "timeout_seconds"}
                    or not isinstance(ready.get("file"), str) or not _READY.fullmatch(ready["file"])):
                invalid("ready.file must name a file directly inside Runtime support")
            ready_file = ready["file"]
            # Never let a readiness hint remove Runtime-owned authority files.
            if ready_file.casefold() in {"discovery.json", "catalog.json", "instance.lock", "bootstrap.lock",
                    "runtime.log", "runtime-epoch-floor.json", "replacement.json", "process-control.json"} \
                    or ready_file.casefold().endswith("-job-cleanup.json") \
                    or ready_file.casefold().endswith("-job-cleanup.lock") or ready_file.casefold() in ready_files:
                invalid("readiness files must be unique and service-owned")
            ready_files.add(ready_file.casefold())
            timeout = ready.get("timeout_seconds", 30)
            if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 300:
                invalid("ready timeout must be finite and between 0 and 300 seconds")
        specs.append(ServiceSpec(name, tuple(argv), row["restart"], dict(env), ready_file, float(timeout)))
    return tuple(specs)


def _absolute_path(value, label):
    if not _string(value) or not Path(value).expanduser().is_absolute():
        raise ValidationError(f"Service {label} must be absolute")
    path = Path(value).expanduser()
    for part in (path, *path.parents):
        if part.is_symlink() and part not in {Path("/tmp"), Path("/var")}:
            raise ValidationError(f"Service {label} must not traverse a symlink")
    return path


def load_service_configuration(declaration, *, python, source_checkout):
    if declaration is None:
        return None
    path = _absolute_path(str(declaration), "declaration path")
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValidationError("Service declaration must be a regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValidationError("Service declaration must be a regular file")
            data = handle.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValidationError("Service declaration exceeds 256 KiB")
        specs = parse_services(json.loads(data.decode("utf-8")))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise ValidationError(f"Service declaration is missing or invalid: {path}") from exc
    source = _absolute_path(str(source_checkout), "source checkout")
    if not source.is_dir():
        raise ValidationError("Service source checkout must be an existing directory")
    # Do not resolve a venv interpreter symlink: its lexical path selects the venv.
    if not _string(python) or not Path(python).is_absolute() or not Path(python).is_file():
        raise ValidationError("Service Python must be an installed absolute interpreter")
    return ServiceConfiguration(specs, str(python), source)


@dataclass
class _Service:
    spec: ServiceSpec
    state: str = "starting"
    last_exit: int | None = None
    restart_count: int = 0
    reason: str | None = None
    process: object = None
    thread: threading.Thread | None = None
    cleanup_identity: tuple[int | None, str | None, str] | None = None


class ServiceSupervisor:
    def __init__(self, config, *, support_root, realm_root, realm_id, runtime_endpoint,
                 log_directory, initial_backoff=1.0, max_backoff=30.0, stable_seconds=60.0, grace=5.0):
        self.config = config
        self.support = Path(support_root)
        self.logs = Path(log_directory)
        self.values = {"{python}": config.python, "{source_checkout}": str(config.source_checkout),
            "{support_root}": str(support_root), "{realm_root}": str(realm_root),
            "{realm_id}": str(realm_id), "{runtime_endpoint}": str(runtime_endpoint)}
        self.initial_backoff, self.max_backoff, self.stable_seconds = initial_backoff, max_backoff, stable_seconds
        self.grace = grace
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._services = [_Service(spec) for spec in config.services]

    def snapshot(self):
        with self._lock:
            return [{"name": item.spec.name, "state": item.state, "last_exit": item.last_exit,
                "restart_count": item.restart_count, **({"reason": item.reason} if item.reason else {})}
                for item in self._services]

    def _update(self, item, **values):
        with self._lock:
            for name, value in values.items():
                setattr(item, name, value)

    def start(self):
        try:
            for item in self._services:
                item.thread = threading.Thread(target=self._run, args=(item,), name="service-" + item.spec.name, daemon=True)
                item.thread.start()
        except BaseException:
            self.stop()
            raise

    def begin_shutdown(self):
        self._stop.set()

    def stop(self):
        self.begin_shutdown()
        deadline = time.monotonic() + self.grace * 2 + 5
        for item in self._services:
            if item.thread is not None and item.thread.ident is not None:
                item.thread.join(max(0, deadline - time.monotonic()))
        if any(item.thread is not None and item.thread.is_alive() for item in self._services):
            raise RuntimeError("Service shutdown did not complete")
        # Retain and retry a tree whose cleanup failed; never launch over it.
        for item in self._services:
            if item.process is not None:
                platform.stop_tree(item.process, grace=self.grace, stop_channel=True)
                self._update(item, process=None)
                if sys.platform == "win32" and item.cleanup_identity is not None:
                    self._record_service_cleanup(item.spec.name, *item.cleanup_identity)
                    self._update(item, cleanup_identity=None)

    def _environment(self, spec, *, launch_id=None):
        env = {k: v for k, v in os.environ.items() if k.upper() not in _RESERVED_ENV
            and not k.upper().startswith("ASTRID_RUNTIME_CUSTODY_")}
        scripts = str(Path(self.config.python).parent)
        env["PATH"] = scripts + os.pathsep + env.get("PATH", "")
        env["VIRTUAL_ENV"] = str(Path(scripts).parent)
        env.update({k: self.values.get(v, v) for k, v in spec.env.items()})
        env["ASTRID_RUNTIME_SERVICE_NAME"] = spec.name
        if sys.platform == "win32" and launch_id is not None:
            env["ASTRID_RUNTIME_SERVICE_LAUNCH_ID"] = launch_id
        if sys.platform == "win32" and "HOME" not in env and env.get("USERPROFILE"):
            env["HOME"] = env["USERPROFILE"]
        return env

    def _ready_path(self, spec):
        return self.support / spec.ready_file if spec.ready_file else None

    def _remove_ready(self, spec):
        path = self._ready_path(spec)
        if path is not None:
            path.unlink(missing_ok=True)

    @staticmethod
    def _pipe_log(pipe, log, errors):
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            while chunk := pipe.read1(64 * 1024):
                log.write(decoder.decode(chunk))
            log.write(decoder.decode(b"", final=True))
        except (OSError, ValueError):
            errors.set()
        finally:
            pipe.close()

    def _attempt(self, item, log):
        spec = item.spec
        self._remove_ready(spec)
        if self._stop.is_set():
            return None, 0.0, "stopped"
        argv = [self.values.get(arg, arg) for arg in spec.argv]
        launch_id = uuid.uuid4().hex if sys.platform == "win32" else None
        process = platform.spawn_tree(argv, hidden=True, cwd=self.config.source_checkout,
            env=self._environment(spec, launch_id=launch_id),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        process_identity = None
        if sys.platform == "win32":
            try:
                observed = platform.process_identity(process.pid)
                if observed and observed.get("pid") == process.pid and isinstance(observed.get("birth_id"), str):
                    process_identity = (process.pid, observed["birth_id"], launch_id)
            except OSError:
                pass
        self._update(item, process=process)
        if sys.platform == "win32":
            self._update(item, cleanup_identity=process_identity or (None, None, launch_id))
        if process_identity is not None:
            self._update(item, cleanup_identity=process_identity)
        reader = None
        try:
            log_errors = threading.Event()
            reader = threading.Thread(target=self._pipe_log, args=(process.stdout, log, log_errors), name="log-" + spec.name, daemon=True)
            started, running_since, reason = time.monotonic(), None, None
            ready_path = self._ready_path(spec)
            reader.start()
            while not self._stop.is_set():
                if log_errors.is_set():
                    reason = "log_failed"
                    break
                if platform.tree_exited(process):
                    break
                current = time.monotonic()
                ready = ready_path is not None and ready_path.is_file() and not ready_path.is_symlink()
                if running_since is None and (ready or (ready_path is None and current - started >= _STARTUP_STABLE_SECONDS)):
                    running_since = current if ready else started
                    self._update(item, state="running")
                if ready_path is not None and running_since is None and current - started >= spec.ready_timeout:
                    reason = "readiness_timeout"
                    break
                self._stop.wait(0.1)
        finally:
            ended = time.monotonic()
            platform.stop_tree(process, grace=self.grace, stop_channel=True)
            self._update(item, process=None, last_exit=process.returncode)
            if sys.platform == "win32" and item.cleanup_identity is not None:
                self._record_service_cleanup(spec.name, *item.cleanup_identity)
                self._update(item, cleanup_identity=None)
            if reader is not None and reader.ident is not None:
                reader.join(2.0)
                if reader.is_alive():
                    raise RuntimeError("Service log pipe did not close after tree shutdown")
            else:
                process.stdout.close()
            self._remove_ready(spec)
        stable_for = ended - running_since if running_since is not None else 0.0
        return process.returncode, stable_for, reason

    def _record_service_cleanup(self, service_name, pid, process_birth_id, launch_id):
        """Publish proof only after stop_tree has confirmed the Windows Job drained."""
        if (not isinstance(service_name, str) or not _NAME.fullmatch(service_name)
                or ((pid is None) != (process_birth_id is None))
                or (pid is not None and (type(pid) is not int or pid <= 0 or not isinstance(process_birth_id, str)
                    or not process_birth_id))
                or not isinstance(launch_id, str) or not re.fullmatch(r"[0-9a-f]{32}", launch_id)):
            raise ValueError("invalid service cleanup identity")
        self.support.mkdir(parents=True, exist_ok=True)
        support_root = str(self.support.resolve())
        receipt = self.support / f"{service_name}-job-cleanup.json"
        lock_path = self.support / f".{service_name}-job-cleanup.lock"
        if lock_path.is_symlink() or receipt.is_symlink():
            raise OSError(errno.ELOOP, "service cleanup authority must not be a symlink")
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            platform.owner_only(descriptor)
            platform.lock_file(descriptor)
            if receipt.exists():
                info = receipt.lstat()
                if not stat.S_ISREG(info.st_mode) or receipt.is_symlink():
                    raise OSError(errno.EINVAL, "service cleanup receipt must be a regular file")
                if sys.platform != "win32" and not platform.is_owner_only(info):
                    raise OSError(errno.EPERM, "service cleanup receipt must be owner-only")
                raw = platform.read_private_file(receipt)
                value = json.loads(raw.decode("utf-8"))
                if (not isinstance(value, dict) or set(value) != {"version", "service_name", "support_root", "receipts"}
                        or type(value.get("version")) is not int or value.get("version") != 1
                        or value.get("service_name") != service_name
                        or value.get("support_root") != support_root or not isinstance(value.get("receipts"), list)):
                    raise OSError(errno.EINVAL, "pack-host cleanup receipt has an unsupported schema")
                entries = value["receipts"]
                for entry in entries:
                    if (not isinstance(entry, dict) or set(entry) != {"pid", "process_birth_id", "runtime_service_launch_id", "job_drained"}
                            or ((entry.get("pid") is None) != (entry.get("process_birth_id") is None))
                            or (entry.get("pid") is not None and (type(entry["pid"]) is not int or entry["pid"] <= 0
                                or not isinstance(entry.get("process_birth_id"), str)))
                            or not isinstance(entry.get("runtime_service_launch_id"), str)
                            or not re.fullmatch(r"[0-9a-f]{32}", entry["runtime_service_launch_id"])
                            or entry.get("job_drained") is not True):
                        raise OSError(errno.EINVAL, "service cleanup receipt contains an invalid entry")
            else:
                entries = []
            new_entry = {"pid": pid, "process_birth_id": process_birth_id,
                "runtime_service_launch_id": launch_id, "job_drained": True}
            if not any(entry["runtime_service_launch_id"] == launch_id for entry in entries):
                entries = entries[-63:]
                entries.append(new_entry)
            data = json.dumps({"version": 1, "service_name": service_name, "support_root": support_root,
                "receipts": entries}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            temp_fd, temp_name = platform.private_temporary(self.support, f".{service_name}-job-cleanup.")
            temporary = Path(temp_name)
            try:
                platform.owner_only(temp_fd)
                with os.fdopen(temp_fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                platform.durable_replace(temporary, receipt)
                platform.owner_only(receipt)
            finally:
                temporary.unlink(missing_ok=True)
        finally:
            platform.unlock_file(descriptor)
            os.close(descriptor)

    def _run(self, item):
        delay = self.initial_backoff
        fast_failures = 0
        try:
            with RotatingLog(self.logs / ("service-" + item.spec.name + ".log")) as log:
                while not self._stop.is_set():
                    self._update(item, state="starting")
                    try:
                        code, stable_for, reason = self._attempt(item, log)
                    except OSError:
                        if item.process is not None:
                            raise
                        code, stable_for, reason = None, 0.0, "launch_failed"
                    if self._stop.is_set():
                        break
                    if item.spec.restart == "on-failure" and code == 0 and reason is None:
                        self._update(item, state="failed", reason="exited")
                        break
                    if stable_for < _STARTUP_STABLE_SECONDS:
                        fast_failures += 1
                    else:
                        fast_failures = 0
                    if stable_for >= self.stable_seconds:
                        delay = self.initial_backoff
                    failed_fast = fast_failures >= _FAST_FAILURE_LIMIT
                    self._update(item, state="failed" if failed_fast else "restarting",
                        reason=reason or "exited")
                    log.write(f"Service exited ({code}); retrying in {delay:g}s ({reason or 'exited'}).\n")
                    if self._stop.wait(delay):
                        break
                    self._update(item, restart_count=item.restart_count + 1)
                    delay = min(self.max_backoff, delay * 2)
        except Exception:
            self._update(item, state="failed", reason="cleanup_failed" if item.process is not None else "supervisor_failed")
