"""Local launcher continuity across independent Runtime startup operations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
import re
import stat
import uuid

from . import platform
from .dirfd import capture_parent, close_pinned, filesystem as os, open_directory_chain
from .errors import ConflictError
from .startup_operation import OperationScope, _directory_digest
from .util import atomic_json_write


RECORD_NAME = "startup-attempt.json"
MAX_RECORD_BYTES = 2048
_INSPECTING = "inspecting_workspace"
_STARTING = "starting_service"
_ASSIGNING = "assigning_service"
_FAILED = "failed"
_FINISHED = "finished"
_ID = re.compile(r"[a-f0-9]{32}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_BIRTH = re.compile(
    r"(proc-start-ticks:[0-9]+;boot:[0-9a-f-]{36};pidns:[0-9]+"
    r"|darwin-creation:[0-9]+:[0-9]+|windows-creation:[0-9]+)\Z"
)


class StartupAttemptError(RuntimeError):
    """Launcher continuity could not be established."""


@dataclass(frozen=True)
class _Record:
    attempt_id: str
    scope: OperationScope
    support_id: str
    owner_pid: int
    owner_birth: str
    stage: str


@dataclass(frozen=True)
class AttemptObservation:
    _record: _Record
    state: str

    @property
    def attempt_id(self) -> str:
        return self._record.attempt_id

    @property
    def scope(self) -> OperationScope:
        return self._record.scope

    @property
    def live(self) -> bool:
        return self.state in {_INSPECTING, _STARTING}

    @property
    def awaiting_service(self) -> bool:
        return self.live and self._record.stage == _STARTING

    @property
    def abandoned(self) -> bool:
        return self.state == _FAILED and self._record.stage != _FAILED

    def as_observation(self) -> dict:
        return {"state": self.state, "attempt_id": self.attempt_id}


def _read_record(directory) -> _Record | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(RECORD_NAME, flags, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not platform.is_owner_only(fd, directory=False)
                or not 0 < info.st_size <= MAX_RECORD_BYTES):
            raise StartupAttemptError("Runtime start attempt record is unsafe.")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            encoded = handle.read(MAX_RECORD_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(encoded)
        if (not isinstance(value, dict) or len(encoded) > MAX_RECORD_BYTES
                or type(value.get("version")) is not int or value.pop("version") != 1):
            raise ValueError
        value["scope"] = OperationScope._parse(value["scope"])
        record = _Record(**value)
        if (not _ID.fullmatch(record.attempt_id) or not _DIGEST.fullmatch(record.support_id)
                or type(record.owner_pid) is not int or not 0 < record.owner_pid < 2**31
                or not isinstance(record.owner_birth, str) or len(record.owner_birth) > 256
                or not _BIRTH.fullmatch(record.owner_birth)
                or record.stage not in {_INSPECTING, _STARTING, _ASSIGNING, _FAILED, _FINISHED}):
            raise ValueError
        return record
    except (TypeError, KeyError, ValueError) as exc:
        raise StartupAttemptError("Runtime start attempt record is invalid.") from exc


def _process_birth(pid: int) -> tuple[str, object] | None:
    if platform.sys.platform == "darwin":
        info = platform._read_darwin_process_info(pid, include_exit=True)
        if info is None or info["status"] == 5:  # SZOMB
            return None
        return f'darwin-creation:{info["start_sec"]}:{info["start_usec"]}', info["uid"]
    info = platform.process_identity(pid)
    if info is None:
        return None
    birth = info.get("birth_id")
    if info.get("pid") != pid or not isinstance(birth, str) or not _BIRTH.fullmatch(birth):
        raise StartupAttemptError("Runtime launcher birth identity is invalid.")
    return birth, info.get("uid")


def _launcher_is_live(record: _Record) -> bool:
    observed = _process_birth(record.owner_pid)
    if observed is None:
        if record.owner_birth.startswith("proc-start-ticks:"):
            # A missing PID is evidence of absence only in a comparable PID
            # namespace. An observer with a restricted view cannot authorize retry.
            local = _process_birth(os.getpid())
            if local is None or platform.process_birth_matches(record.owner_birth, local[0]) is None:
                raise StartupAttemptError("Runtime launcher process could not be observed.")
        return False
    birth, uid = observed
    match = platform.process_birth_matches(record.owner_birth, birth)
    if match is None or (match and uid != platform.current_user()):
        raise StartupAttemptError("Runtime launcher process could not be verified.")
    return match


def read_attempt(support_root: Path) -> AttemptObservation | None:
    """Observe an exact owner without locking, writing, or controlling any process."""
    try:
        directory = open_directory_chain(support_root)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StartupAttemptError("Runtime start attempt directory could not be opened.") from exc
    try:
        record = _read_record(directory)
        if record is None:
            return None
        pinned = os.fstat(directory)
        if (not platform.is_owner_only(directory, directory=True)
                or record.support_id != _directory_digest(support_root, pinned)):
            raise StartupAttemptError("Runtime start attempt directory is unsafe or replaced.")
        live = record.stage not in {_FINISHED, _FAILED} and _launcher_is_live(record)
        if _read_record(directory) != record:
            raise StartupAttemptError("Runtime start attempt changed while being observed.")
        if live:
            live = _launcher_is_live(record)
        current = os.stat(support_root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise StartupAttemptError("Runtime start attempt directory changed.")
        if record.stage == _FINISHED:
            return AttemptObservation(record, _FINISHED)
        if not live:
            return AttemptObservation(record, _FAILED)
        state = _STARTING if record.stage == _ASSIGNING else record.stage
        return AttemptObservation(record, state)
    except OSError as exc:
        raise StartupAttemptError("Runtime start attempt could not be observed.") from exc
    finally:
        os.close(directory)


def _publish(support_root: Path, record: _Record, previous: _Record | None) -> None:
    path = support_root / RECORD_NAME
    identity = None
    try:
        identity = capture_parent(path)
        directory = int(identity["_parent_fd"])
        if (identity["parent_was_missing"] or not platform.is_owner_only(directory, directory=True)
                or record.support_id != _directory_digest(support_root, os.fstat(directory))
                or _read_record(directory) != previous):
            raise StartupAttemptError("Runtime start attempt ownership changed.")
        atomic_json_write(path, {"version": 1, **asdict(record)}, identity=identity)
    except (ConflictError, OSError) as exc:
        raise StartupAttemptError("Runtime start attempt could not be published.") from exc
    finally:
        close_pinned(identity)


class StartupAttempt:
    """A launcher-held record. All mutations are under the bootstrap mutex."""

    def __init__(self, support_root: Path, record: _Record):
        self._support_root = support_root
        self._record = record

    @property
    def attempt_id(self) -> str:
        return self._record.attempt_id

    @classmethod
    def begin_locked(cls, support_root: Path, scope: OperationScope, *, inspecting: bool,
                     retry_attempt_id: str | None) -> StartupAttempt:
        current = read_attempt(support_root)
        if current is not None and current.live:
            raise StartupAttemptError("A Runtime launcher already owns this installation's start attempt.")
        failed_match = current is not None and current.state == _FAILED and current.scope == scope
        if retry_attempt_id is not None:
            if not failed_match or current.attempt_id != retry_attempt_id:
                raise StartupAttemptError("The specified failed Runtime start attempt is no longer available to retry.")
        elif failed_match and current.abandoned:
            raise StartupAttemptError("Retry requires the exact failed Runtime start attempt ID.")
        process = _process_birth(os.getpid())
        if (process is None or not _BIRTH.fullmatch(process[0]) or process[1] != platform.current_user()
                or platform.process_birth_matches(process[0], process[0]) is not True):
            raise StartupAttemptError("Runtime launcher birth identity is unavailable.")
        directory = open_directory_chain(support_root)
        try:
            support_id = _directory_digest(support_root, os.fstat(directory))
        finally:
            os.close(directory)
        record = _Record(uuid.uuid4().hex, scope, support_id, os.getpid(), process[0],
                         _INSPECTING if inspecting else _STARTING)
        _publish(support_root, record, current._record if current is not None else None)
        return cls(support_root, record)

    def matches(self, support_root: Path, observation: AttemptObservation) -> bool:
        return (self._support_root == support_root and observation.live
                and self._record == observation._record
                and self._record.owner_pid == os.getpid())

    def _transition_locked(self, stage: str, target: str) -> None:
        current = read_attempt(self._support_root)
        if current is None or not self.matches(self._support_root, current) or self._record.stage != stage:
            raise StartupAttemptError("The launcher no longer owns this Runtime start attempt stage.")
        replacement = replace(self._record, stage=target)
        _publish(self._support_root, replacement, self._record)
        self._record = replacement

    def starting_service_locked(self) -> None:
        self._transition_locked(_INSPECTING, _STARTING)

    def assign_native_locked(self) -> None:
        self._transition_locked(_STARTING, _ASSIGNING)

    def finish_locked(self, *, failed: bool) -> None:
        if self._record.stage not in {_FAILED, _FINISHED}:
            self._transition_locked(self._record.stage, _FAILED if failed else _FINISHED)
