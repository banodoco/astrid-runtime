"""Owner-only observations of an in-flight Runtime startup.

A launcher assigns a detached operation to the exact child before the child
can enter admission. The bootstrap mutex serializes assignment. The child's
record then protects the pre-listener interval even if the launcher exits.
The record conveys no service authority.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
import time
import uuid

from . import cancellation, platform
from .dirfd import capture_parent, close_pinned, filesystem as os, open_directory_chain
from .errors import ConflictError
from .util import atomic_json_write

RECORD_NAME = "startup-operation.json"
HEARTBEAT_SECONDS = 2
MAX_AGE_SECONDS = 30
MAX_RECORD_BYTES = 2048
_PHASES = {
    "verifying_identity", "checking_realm", "checking_objects",
    "checking_history", "establishing_service",
}
_HEX_ID = re.compile(r"[a-f0-9]{32}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_current = ContextVar("startup_operation", default=None)


class StartupOperationError(RuntimeError):
    """The local operation observation or handoff cannot be established."""


@dataclass(frozen=True)
class OperationScope:
    generation: str
    realm: str
    root: str

    @classmethod
    def from_selection(cls, realm_id: str, realm_root: Path, generation: str):
        return cls(generation, _digest(realm_id), _root_digest(realm_root))

    @classmethod
    def _parse(cls, value):
        if not isinstance(value, dict) or set(value) != {"generation", "realm", "root"}:
            raise ValueError
        if not all(isinstance(item, str) and _DIGEST.fullmatch(item) for item in value.values()):
            raise ValueError
        return cls(**value)


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _root_digest(path: Path):
    path = Path(path)
    fd = open_directory_chain(path)
    try:
        info = os.fstat(fd)
        return _directory_digest(path, info)
    finally:
        os.close(fd)


def _directory_digest(path, info):
    return _digest(f"{path}\n{info.st_dev}:{info.st_ino}")


@dataclass(frozen=True)
class OperationStatus:
    operation_id: str
    scope: OperationScope
    support_id: str
    owner_pid: int
    owner_birth: str
    phase: str
    state: str
    updated_ns: int
    objects_checked: int

    @property
    def owner(self):
        return self.operation_id, self.scope, self.support_id, self.owner_pid, self.owner_birth

    def as_observation(self):
        return {
            "operation_id": self.operation_id, "phase": self.phase, "state": self.state,
            "objects_checked": self.objects_checked,
        }


def _read_record(directory):
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
            raise StartupOperationError("Runtime startup operation record is unsafe.")
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
        status = OperationStatus(**value)
        if (not _HEX_ID.fullmatch(status.operation_id) or status.phase not in _PHASES
                or status.state not in {"pending", "ended"}
                or not _DIGEST.fullmatch(status.support_id)
                or type(status.owner_pid) is not int or not 0 < status.owner_pid < 2**32
                or not isinstance(status.owner_birth, str) or not 0 < len(status.owner_birth) <= 256
                or type(status.updated_ns) is not int or not 0 < status.updated_ns < 2**64
                or type(status.objects_checked) is not int or not 0 <= status.objects_checked < 2**63):
            raise ValueError
        return status
    except (TypeError, ValueError, KeyError) as exc:
        raise StartupOperationError("Runtime startup operation record is invalid.") from exc


def _owner_birth(pid, *, expected_birth=None):
    if platform.sys.platform == "darwin":
        # Discovery's legacy ps-lstart representation has only second
        # precision. The local operation binds the kernel's full start time.
        actual = platform._read_darwin_process_info(pid, include_exit=True)
        if (actual is None or actual["pid"] != pid or actual["uid"] != platform.current_user()
                or actual["status"] == 5):  # SZOMB
            return None
        return f'darwin-creation:{actual["start_sec"]}:{actual["start_usec"]}'
    actual = platform.process_identity(pid)
    if not actual or actual.get("pid") != pid or actual.get("uid") != platform.current_user():
        if (actual is None and expected_birth is not None
                and platform.sys.platform.startswith("linux")):
            # A hidden /proc entry proves absence only when this observer can
            # compare the recorded owner's boot and PID-namespace coordinates.
            local = platform.process_identity(os.getpid())
            if (local is None or not isinstance(local.get("birth_id"), str)
                    or platform.process_birth_matches(expected_birth, local["birth_id"]) is None):
                raise StartupOperationError("Runtime startup process identity could not be verified.")
        return None
    return actual.get("birth_id")


def read_operation(support_root, *, scope=None, operation_id=None, fresh=True):
    """Read an exact live observation without creating files or taking ownership."""
    try:
        directory = open_directory_chain(support_root)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StartupOperationError("Runtime startup operation directory could not be opened.") from exc
    try:
        status = _read_record(directory)
        if status is not None and not platform.is_owner_only(directory, directory=True):
            raise StartupOperationError("Runtime startup operation directory is unsafe.")
        pinned = os.fstat(directory)
        if status is not None and status.support_id != _directory_digest(Path(support_root), pinned):
            raise StartupOperationError("Runtime startup operation directory was replaced.")
        if (status is None or (scope is not None and scope != status.scope)
                or (operation_id is not None and operation_id != status.operation_id)):
            return None
        actual = _owner_birth(status.owner_pid, expected_birth=status.owner_birth)
        if actual is None:
            return None
        matches = platform.process_birth_matches(status.owner_birth, actual)
        if matches is False:
            return None
        if matches is not True:
            raise StartupOperationError("Runtime startup process identity could not be verified.")
        confirmed = _read_record(directory)
        if confirmed is None or confirmed.owner != status.owner:
            return None
        actual = _owner_birth(confirmed.owner_pid, expected_birth=confirmed.owner_birth)
        if actual is None:
            return None
        matches = platform.process_birth_matches(confirmed.owner_birth, actual)
        if matches is False:
            return None
        if matches is not True:
            raise StartupOperationError("Runtime startup process identity could not be reverified.")
        current = os.stat(support_root, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise StartupOperationError("Runtime startup operation directory changed.")
        age = time.monotonic_ns() - confirmed.updated_ns
        if fresh and not 0 <= age <= MAX_AGE_SECONDS * 10**9:
            return None
        return confirmed
    except OSError as exc:
        raise StartupOperationError("Runtime startup operation could not be observed.") from exc
    finally:
        os.close(directory)


class StartupOperation:
    """A producer receipt or the launcher's exact observation of that producer."""

    def __init__(self, support_root: Path, status: OperationStatus):
        self.support_root = Path(support_root)
        self.status = status
        self.objects_checked = status.objects_checked

    @classmethod
    def assign(cls, support_root, scope, *, operation_id=None, pid=None):
        """Called by the bootstrap owner while it holds the bootstrap mutex."""
        if not platform.is_owner_only(support_root, directory=True):
            raise StartupOperationError("Runtime startup operation directory is unsafe.")
        pid = os.getpid() if pid is None else pid
        birth = _owner_birth(pid)
        if not birth or platform.process_birth_matches(birth, birth) is not True:
            raise StartupOperationError("Runtime startup process identity is unavailable.")
        status = OperationStatus(
            operation_id or uuid.uuid4().hex, scope, _root_digest(support_root), pid, birth,
            "verifying_identity", "pending", time.monotonic_ns(), 0,
        )
        operation = cls(support_root, status)
        operation._publish()
        return operation

    @classmethod
    def attach(cls, support_root, scope, operation_id, *, timeout):
        """Wait for the parent to authorize this exact child before startup."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            cancellation.check()
            status = read_operation(support_root, scope=scope, operation_id=operation_id)
            if status is not None:
                if status.owner_pid != os.getpid() or status.state != "pending":
                    break
                return cls(support_root, status)
            cancellation.pause(0.05)
        raise StartupOperationError("Runtime startup operation handoff is unavailable.")

    def snapshot(self, *, fresh=True):
        status = read_operation(
            self.support_root, scope=self.status.scope, operation_id=self.status.operation_id, fresh=fresh,
        )
        return status if status is not None and status.owner == self.status.owner else None

    def _publish(self):
        path = self.support_root / RECORD_NAME
        identity = None
        try:
            identity = capture_parent(path)
            directory = int(identity["_parent_fd"])
            if (identity["parent_was_missing"] or not platform.is_owner_only(directory, directory=True)
                    or self.status.support_id != _directory_digest(self.support_root, os.fstat(directory))):
                raise StartupOperationError("Runtime startup operation directory was replaced.")
            atomic_json_write(path, {"version": 1, **asdict(self.status)}, identity=identity)
        except (OSError, ConflictError) as exc:
            raise StartupOperationError("Runtime startup operation could not be published.") from exc
        finally:
            close_pinned(identity)

    def progress(self, phase=None, *, objects_checked=None, ended=False):
        assert self.status.owner_pid == os.getpid()
        status = self.status
        now = time.monotonic_ns()
        if objects_checked is not None:
            self.objects_checked = objects_checked
        if phase is None and not ended and now - status.updated_ns < HEARTBEAT_SECONDS * 10**9:
            return
        # Do not overwrite a replaced record, even if it is under the same root.
        current = read_operation(
            self.support_root, scope=status.scope, operation_id=status.operation_id, fresh=False,
        )
        if current is None or current.owner != status.owner:
            raise StartupOperationError("Runtime startup operation ownership changed.")
        self.status = OperationStatus(
            status.operation_id, status.scope, status.support_id, status.owner_pid, status.owner_birth,
            phase or status.phase, "ended" if ended else "pending", now,
            self.objects_checked,
        )
        self._publish()

    @contextmanager
    def produce(self):
        token = _current.set(self)
        try:
            yield
        finally:
            _current.reset(token)
            # Preserve the verifier's exact refusal/cancellation and the existing
            # service authority if only the optional terminal observation fails.
            try:
                self.progress(ended=True)
            except StartupOperationError:
                pass


def current_verification(root):
    operation = _current.get()
    if operation is not None and operation.status.scope.root != _root_digest(root):
        raise StartupOperationError("Runtime startup realm identity changed.")
    return operation


def checkpoint(phase=None, *, objects_checked=None):
    operation = _current.get()
    if operation is not None:
        operation.progress(phase, objects_checked=objects_checked)
