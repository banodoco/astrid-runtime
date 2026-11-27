"""Darwin process observations and retained native process authority (stdlib only).

Audit-token words and the public census are observations. Actions require the
live Mach task-name right captured from a connected peer or an independently
retained child. A task-name right does not follow exec: only an owned child with
its original sole-waiter guard may explicitly refresh after exec.

Census and suspended SETEXEC mechanics originate in Agent custody_broker.py,
blob 75b6aa65c3ad907e6ece7ba6a0cc4a30b9514641. Its durable role/release ledger
remains the consumer's responsibility; the one-shot latch here is in-memory.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import signal as _signals
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Mapping, Sequence

SOL_LOCAL = 0
LOCAL_PEERPID = 0x002
LOCAL_PEERTOKEN = 0x006
TOKEN_BYTES = 32
TASK_AUDIT_TOKEN = 15
TASK_AUDIT_TOKEN_COUNT = 8
DARWIN_POSIX_SPAWN_SETEXEC = 0x0040
DARWIN_POSIX_SPAWN_START_SUSPENDED = 0x0080
DARWIN_SIGCONT = 19
DARWIN_SIGUSR1 = 30
ROTATES_ON_EXEC = True
PRIMITIVE = "proc_signal_with_audittoken"


class DarwinBindingError(RuntimeError):
    """A native observation or retained Darwin authority cannot be verified."""


class NativeTokenCaptureError(DarwinBindingError):
    """Capture failure without exposing the native capability."""

    def __init__(self, message, *, substage, kern_return, port_acquired, count=None):
        self.capture_failure = {
            "substage": substage, "kern_return": kern_return,
            "port_acquired": port_acquired, "count": count,
        }
        super().__init__(message)


class TaskNameUnavailable(NativeTokenCaptureError):
    """Acquisition failed before any task-name right existed.

    Only this exception maps to the broker's historical _TaskNameUnavailable.
    It never makes an observed socket token sufficient for retained custody.
    """


class AuditTokenSignalError(DarwinBindingError):
    def __init__(self, result, observed_errno):
        self.returncode, self.errno = result, observed_errno
        super().__init__(
            "proc_signal_with_audittoken failed for registered target "
            f"(returncode={result}, errno={observed_errno})"
        )


def _require_darwin():
    if sys.platform != "darwin":
        raise DarwinBindingError("Darwin process binding is unavailable")


def _pid(value):
    if type(value) is not int or not 0 < value <= 0x7fffffff:
        raise DarwinBindingError("Darwin process selector is invalid")
    return value


class _AuditToken(ctypes.Structure):
    _fields_ = [("value", ctypes.c_uint32 * TASK_AUDIT_TOKEN_COUNT)]


def _token_from_words(words):
    try:
        valid = len(words) == TASK_AUDIT_TOKEN_COUNT and all(
            not isinstance(value, bool) and isinstance(value, int) and 0 <= value <= 0xFFFFFFFF
            for value in words
        )
    except TypeError:
        valid = False
    if not valid:
        raise DarwinBindingError("registered audit token is invalid")
    result = _AuditToken()
    result.value[:] = words
    return result


def details(words: Sequence[int]) -> dict[str, object]:
    _require_darwin()
    value = _token_from_words(words)
    library = ctypes.CDLL("/usr/lib/libbsm.0.dylib", use_errno=True)
    library.audit_token_to_pid.argtypes = [_AuditToken]
    library.audit_token_to_pid.restype = ctypes.c_int
    library.audit_token_to_pidversion.argtypes = [_AuditToken]
    library.audit_token_to_pidversion.restype = ctypes.c_int
    return {
        "pid": int(library.audit_token_to_pid(value)),
        "pidversion": int(library.audit_token_to_pidversion(value)),
        "uid": int(value.value[1]),
        "sha256": "sha256:" + hashlib.sha256(bytes(value)).hexdigest(),
    }


def peer_token(connection) -> dict[str, object]:
    """Observe the current socket actor, not an immutable connection creator."""
    _require_darwin()
    if connection.family != socket.AF_UNIX:
        raise DarwinBindingError("Darwin peer observation requires a Unix socket")
    try:
        raw = connection.getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, TOKEN_BYTES)
    except OSError as exc:
        raise DarwinBindingError("Darwin peer audit token is unavailable") from exc
    if not isinstance(raw, bytes) or len(raw) != TOKEN_BYTES:
        raise DarwinBindingError("LOCAL_PEERTOKEN returned an invalid token size")
    words = list(_AuditToken.from_buffer_copy(raw).value)
    return {**details(words), "words": words}


def peer_pid(connection) -> int:
    """Preserve the legacy LOCAL_PEERPID observation; it grants no authority."""
    _require_darwin()
    import struct
    if connection.family != socket.AF_UNIX:
        raise DarwinBindingError("Darwin peer observation requires a Unix socket")
    try:
        return _pid(struct.unpack("i", connection.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0])
    except (OSError, struct.error) as exc:
        raise DarwinBindingError("Darwin peer PID is unavailable") from exc


class _DarwinBSDInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
        "svuid", "svgid", "reserved",
    )] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")
    ] + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def read_process_info(pid: int, *, include_exit=False):
    """Native BSD observation, preserving Runtime's exact absence/error rules."""
    _require_darwin()
    _pid(pid)
    if ctypes.sizeof(_DarwinBSDInfo) != 136 or _DarwinBSDInfo.start_sec.offset != 120:
        raise DarwinBindingError("Darwin BSD process-info ABI is unsupported")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    reader = library.proc_pidinfo
    reader.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    reader.restype = ctypes.c_int
    value = _DarwinBSDInfo()
    ctypes.set_errno(0)
    count = reader(pid, 3, 0, ctypes.byref(value), ctypes.sizeof(value))
    error = ctypes.get_errno()
    if count == 0 and error == errno.ESRCH:
        return None
    if count != ctypes.sizeof(value) or error:
        raise OSError(error, "native process identity observation failed or was partial")
    if value.pid != pid or value.start_sec == 0 or value.start_usec >= 1_000_000:
        raise OSError("native process identity observation was malformed")
    return {
        "pid": int(value.pid), "uid": int(value.uid), "parent_pid": int(value.ppid),
        "start_sec": int(value.start_sec), "start_usec": int(value.start_usec),
        **({"status": int(value.status)} if include_exit else {}),
    }


def identity(pid, *, timeout=1.0, _reader=None):
    """Compatibility observation; exact custody also keeps microseconds/Mach."""
    if timeout <= 0:
        raise OSError("process identity observation deadline expired")
    if pid <= 0:
        return None
    reader = _reader or read_process_info
    deadline = time.monotonic() + timeout
    first = reader(pid)
    if first is None:
        return None
    second = reader(pid)
    if time.monotonic() >= deadline:
        raise OSError("process identity observation deadline expired")
    if first != second:
        raise OSError("native process identity changed during observation")
    return _public_identity(first)


def _public_identity(row):
    return {key: row[key] for key in ("pid", "uid", "parent_pid")} | {
        "birth_id": _ps_lstart_birth(row["start_sec"]),
    }


def _live(pid):
    row = read_process_info(pid, include_exit=True)
    if row is None or row["status"] not in {1, 2, 3, 4}:
        raise DarwinBindingError("Darwin retained process is absent or exited")
    return row


def _same_birth(first, second):
    return all(first[key] == second[key] for key in ("pid", "uid", "start_sec", "start_usec"))


def _check_expected(row, expected):
    if expected is not None:
        observed = _public_identity(row)
        if not isinstance(expected, Mapping) or any(
            key not in expected or type(expected[key]) is not type(observed[key])
            or expected[key] != observed[key] for key in ("pid", "uid", "birth_id")
        ):
            raise DarwinBindingError("Darwin retained process differs from expected incarnation")


def _mach_library():
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library.task_name_for_pid.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32),
    ]
    library.task_name_for_pid.restype = ctypes.c_int
    library.task_info.argtypes = [
        ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_uint32),
    ]
    library.task_info.restype = ctypes.c_int
    library.pid_for_task.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_int)]
    library.pid_for_task.restype = ctypes.c_int
    library.mach_port_deallocate.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    library.mach_port_deallocate.restype = ctypes.c_int
    return library, ctypes.c_uint32.in_dll(library, "mach_task_self_").value


class _MachTask:
    """Own exactly one send right. Never reacquire a PID in read/close."""

    def __init__(self, pid):
        _require_darwin()
        self.pid = _pid(pid)
        self.library, self.task_self = _mach_library()
        self.port = 0
        port = ctypes.c_uint32(0)
        try:
            result = int(self.library.task_name_for_pid(self.task_self, pid, ctypes.byref(port)))
        except BaseException as error:
            # Python can surface an exception after the native call has filled
            # the out parameter. Retain that right long enough to release it.
            self.port = int(port.value)
            self._release_after_failure(error)
            raise
        self.port = int(port.value)
        if result != 0 or not self.port:
            # A malformed successful/null return is not an acquisition denial
            # and must not enable the broker's narrow observation fallback.
            kind = TaskNameUnavailable if result != 0 and not self.port else NativeTokenCaptureError
            error = kind("final-ready Runtime task-name port is unavailable",
                         substage="task_name_for_pid", kern_return=result,
                         port_acquired=bool(self.port))
            self._release_after_failure(error)
            raise error

    def _read_token(self, substage):
        value = _AuditToken()
        count = ctypes.c_uint32(TASK_AUDIT_TOKEN_COUNT)
        result = int(self.library.task_info(
            self.port, TASK_AUDIT_TOKEN,
            ctypes.cast(ctypes.byref(value), ctypes.POINTER(ctypes.c_int32)),
            ctypes.byref(count),
        ))
        if result != 0 or count.value != TASK_AUDIT_TOKEN_COUNT:
            raise NativeTokenCaptureError(
                "final-ready Runtime audit token is unavailable",
                substage=substage, kern_return=result, port_acquired=True, count=int(count.value),
            )
        return list(value.value)

    def read(self):
        if not self.port:
            raise DarwinBindingError("Darwin retained Mach authority is closed")
        first = self._read_token("task_info_first")
        bound_pid = ctypes.c_int(0)
        result = int(self.library.pid_for_task(self.port, ctypes.byref(bound_pid)))
        if result != 0 or bound_pid.value != self.pid:
            raise NativeTokenCaptureError(
                "final-ready Runtime task port changed process",
                substage="pid_for_task", kern_return=result, port_acquired=True,
            )
        second = self._read_token("task_info_second")
        if first != second:
            raise NativeTokenCaptureError(
                "final-ready Runtime audit token changed while binding",
                substage="token_consistency", kern_return=0, port_acquired=True,
            )
        value = details(first)
        if value["pid"] != self.pid:
            raise DarwinBindingError("Darwin task token differs from retained process")
        return {**value, "words": first}

    def close(self):
        port, self.port = self.port, 0
        if port:
            result = int(self.library.mach_port_deallocate(self.task_self, port))
            if result != 0:
                raise NativeTokenCaptureError(
                    "final-ready Runtime task-name port release failed",
                    substage="mach_port_deallocate", kern_return=result, port_acquired=True,
                )

    def _release_after_failure(self, primary):
        try:
            self.close()
        except BaseException as error:
            primary.port_release_error = error
            primary.add_note(str(error))
            released = False
        else:
            released = True
        if isinstance(primary, NativeTokenCaptureError) and primary.capture_failure["port_acquired"]:
            primary.capture_failure["port_release_succeeded"] = released

    def __enter__(self):
        return self

    def __exit__(self, _kind, primary, _tb):
        if primary is not None:
            self._release_after_failure(primary)
        else:
            self.close()


def token(pid):
    """A compatible observation; release the temporary task-name right."""
    with _MachTask(pid) as native:
        return native.read()


def _admit_signal(signum):
    if isinstance(signum, bool) or not isinstance(signum, int) or signum not in {15, 9, DARWIN_SIGUSR1}:
        raise DarwinBindingError("custody signal is outside the admitted set")


def _send_signal(words, signum):
    _require_darwin()
    value = _token_from_words(words)
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_signal_with_audittoken
    function.argtypes = [ctypes.POINTER(_AuditToken), ctypes.c_int]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = int(function(ctypes.byref(value), signum))
    observed_errno = int(ctypes.get_errno())
    if result != 0:
        raise AuditTokenSignalError(result, observed_errno)


_FACTORY = object()


class PeerHandle:
    """Retain a current Mach task, not a transferable transport role.

    The caller must enforce fresh-channel/original-channel routing separately.
    Token and identity properties are copies. All native actions serialize with
    close. An exec replacement refuses until independently owned child custody
    performs an explicit refresh; a peer snapshot cannot perform that refresh.
    """
    authority = "darwin-task-name-port"

    def __init__(self, native, row, value, *, _factory=None):
        if _factory is not _FACTORY:
            raise DarwinBindingError("Darwin authority must be captured from a peer or owned child")
        self._lock = threading.RLock()
        self._native, self._row, self._value = native, dict(row), dict(value)
        self._closed = False

    @property
    def token(self):
        with self._lock:
            return {**self._value, "words": list(self._value["words"])}

    @property
    def identity(self):
        with self._lock:
            return _public_identity(self._row)

    def _verify_locked(self, expected=None):
        if self._closed:
            raise DarwinBindingError("Darwin retained authority is closed")
        before = _live(self._row["pid"])
        value = self._native.read()
        after = _live(self._row["pid"])
        if not _same_birth(self._row, before) or not _same_birth(before, after):
            raise DarwinBindingError("Darwin retained process incarnation changed")
        if value["pid"] != self._row["pid"] or value["uid"] != self._row["uid"]:
            raise DarwinBindingError("Darwin retained task credentials changed")
        if value != self._value:
            raise DarwinBindingError("Darwin retained task audit token rotated; explicit owned-child refresh required")
        _check_expected(after, expected)
        return {**value, "words": list(value["words"])}

    def verify(self, expected=None):
        with self._lock:
            return self._verify_locked(expected)

    def signal(self, signum):
        _admit_signal(signum)
        with self._lock:
            value = self._verify_locked()
            _send_signal(value["words"], signum)

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._native.close()

    def __enter__(self):
        return self

    def __exit__(self, _kind, primary, _tb):
        try:
            self.close()
        except BaseException as error:
            if primary is None:
                raise
            primary.port_release_error = error
            primary.add_note(str(error))


def _capture(pid, *, expected=None, peer=None):
    before = _live(pid)
    native = _MachTask(pid)
    try:
        value = native.read()
        after = _live(pid)
        if not _same_birth(before, after) or value["uid"] != after["uid"]:
            raise DarwinBindingError("Darwin process changed while capturing native authority")
        _check_expected(after, expected)
        if peer is not None and value != peer:
            raise DarwinBindingError("Darwin peer audit token differs from captured task")
        return native, after, value
    except BaseException as error:
        native._release_after_failure(error)
        raise


def retain_peer(connection, *, expected=None):
    """Capture the current connected peer and keep its Mach right until close."""
    _require_darwin()
    if not isinstance(connection, socket.socket):
        raise DarwinBindingError("Darwin retained peer requires a native socket")
    first = peer_token(connection)
    native, row, value = _capture(first["pid"], expected=expected, peer=first)
    try:
        if peer_token(connection) != first or native.read() != value:
            raise DarwinBindingError("Darwin peer changed while retaining native authority")
        return PeerHandle(native, row, value, _factory=_FACTORY)
    except BaseException as error:
        native._release_after_failure(error)
        raise


class OwnedChildHandle(PeerHandle):
    """Independently retained direct child; the caller remains its sole reaper.

    Lock ordering is reap_guard, Popen's wait lock, then the handle lock. Ordinary
    peer operations take only the handle lock and never acquire a reaping lock.
    """
    authority = "darwin-owned-child-task-name-port"

    def __init__(self, native, row, value, *, child, reap_guard, wait_guard, _factory=None):
        super().__init__(native, row, value, _factory=_factory)
        self._child, self._reap_guard, self._wait_guard = child, reap_guard, wait_guard
        self._resume_consumed = False

    def _check_child_locked(self):
        if (_signals.getsignal(_signals.SIGCHLD) != _signals.SIG_DFL
                or self._child._waitpid_lock is not self._wait_guard
                or self._child.returncode is not None):
            raise DarwinBindingError("Darwin retained child wait ownership is unavailable")
        row = _live(self._child.pid)
        if row["parent_pid"] != os.getpid() or not _same_birth(row, self._row):
            raise DarwinBindingError("Darwin retained child incarnation changed")
        return row

    def refresh_after_exec(self):
        """Capture the original unreaped child's new task, never a cached peer PID.

        Every wait/poll must use reap_guard; external waitpid reapers are outside
        this contract. The old right is retained until new capture succeeds.
        """
        with self._reap_guard, self._wait_guard, self._lock:
            if self._closed:
                raise DarwinBindingError("Darwin retained authority is closed")
            self._check_child_locked()
            native, row, value = _capture(self._child.pid, expected=self.identity)
            try:
                self._check_child_locked()
                if not _same_birth(self._row, row):
                    raise DarwinBindingError("Darwin retained child changed during exec refresh")
            except BaseException as error:
                native._release_after_failure(error)
                raise
            old = self._native
            self._native, self._row, self._value = native, row, value
            try:
                old.close()
            except BaseException as error:
                # A failed release is visible and does not leave a new actionable
                # authority with ambiguous cleanup.
                self._closed = True
                native._release_after_failure(error)
                raise
            return self.token

    def _resume_once(self):
        with self._reap_guard, self._wait_guard, self._lock:
            if self._resume_consumed:
                raise DarwinBindingError("suspended launch release was already consumed")
            row = self._check_child_locked()
            value = self._verify_locked()
            if row["status"] != 4:
                raise DarwinBindingError("Darwin owned launch is not suspended")
            # The role owner separately persists its release intent before this
            # call. Even a failed native attempt is not replayable on this handle.
            self._resume_consumed = True
            _send_signal(value["words"], DARWIN_SIGCONT)


def retain_child(child, *, reap_guard, expected=None):
    _require_darwin()
    if not isinstance(child, subprocess.Popen):
        raise DarwinBindingError("Darwin child authority requires a retained Popen")
    from . import platform
    try:
        wait_guard = platform.validate_child_reaper(child)
    except (OSError, RuntimeError) as exc:
        raise DarwinBindingError("Darwin child wait ownership is unavailable") from exc
    with reap_guard, wait_guard:
        if child.returncode is not None:
            raise DarwinBindingError("Darwin retained child is absent or exited")
        before = _live(child.pid)
        if before["parent_pid"] != os.getpid():
            raise DarwinBindingError("Darwin retained child launch lineage is unavailable")
        native, row, value = _capture(child.pid, expected=expected)
        try:
            if not _same_birth(before, row):
                raise DarwinBindingError("Darwin retained child incarnation changed")
            return OwnedChildHandle(native, row, value, child=child, reap_guard=reap_guard,
                                    wait_guard=wait_guard, _factory=_FACTORY)
        except BaseException as error:
            native._release_after_failure(error)
            raise


def signal(words, signum, *, authority=None):
    _admit_signal(signum)
    _token_from_words(words)
    if not isinstance(authority, PeerHandle):
        raise DarwinBindingError("Darwin process signal requires retained native authority")
    with authority._lock:
        current = authority._verify_locked()
        if list(words) != current["words"]:
            raise DarwinBindingError("Darwin process token differs from retained authority")
        _send_signal(current["words"], signum)


def resume_once(authority):
    if not isinstance(authority, OwnedChildHandle):
        raise DarwinBindingError("one-shot resume requires an independently retained owned child")
    return authority._resume_once()


# Public Darwin sysctl structures, matching the 64-bit SDK kinfo_proc ABI.
# This census is an observation, never a wait record or signal capability.
class _DarwinTimeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_usec", ctypes.c_int32)]


class _DarwinItimerval(ctypes.Structure):
    _fields_ = [("interval", _DarwinTimeval), ("value", _DarwinTimeval)]


class _DarwinProcUnion(ctypes.Union):
    _fields_ = [("start", _DarwinTimeval), ("links", ctypes.c_void_p * 2)]


class _DarwinExternProc(ctypes.Structure):
    _fields_ = [
        ("un", _DarwinProcUnion), ("vmspace", ctypes.c_void_p), ("sigacts", ctypes.c_void_p),
        ("flag", ctypes.c_int32), ("status", ctypes.c_int8), ("pid", ctypes.c_int32),
        ("oppid", ctypes.c_int32), ("dupfd", ctypes.c_int32), ("user_stack", ctypes.c_void_p),
        ("exit_thread", ctypes.c_void_p), ("debugger", ctypes.c_int32), ("sigwait", ctypes.c_int32),
        ("estcpu", ctypes.c_uint32), ("cpticks", ctypes.c_int32), ("pctcpu", ctypes.c_uint32),
        ("wchan", ctypes.c_void_p), ("wmesg", ctypes.c_void_p), ("swtime", ctypes.c_uint32),
        ("slptime", ctypes.c_uint32), ("realtimer", _DarwinItimerval), ("rtime", _DarwinTimeval),
        ("uticks", ctypes.c_uint64), ("sticks", ctypes.c_uint64), ("iticks", ctypes.c_uint64),
        ("traceflag", ctypes.c_int32), ("tracep", ctypes.c_void_p), ("siglist", ctypes.c_int32),
        ("textvp", ctypes.c_void_p), ("holdcnt", ctypes.c_int32), ("sigmask", ctypes.c_uint32),
        ("sigignore", ctypes.c_uint32), ("sigcatch", ctypes.c_uint32), ("priority", ctypes.c_uint8),
        ("usrpri", ctypes.c_uint8), ("nice", ctypes.c_int8), ("comm", ctypes.c_char * 17),
        ("pgrp", ctypes.c_void_p), ("addr", ctypes.c_void_p), ("xstat", ctypes.c_uint16),
        ("acflag", ctypes.c_uint16), ("ru", ctypes.c_void_p),
    ]


class _DarwinPCred(ctypes.Structure):
    _fields_ = [("lock", ctypes.c_char * 72), ("ucred", ctypes.c_void_p),
                ("ruid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
                ("rgid", ctypes.c_uint32), ("svgid", ctypes.c_uint32), ("refcnt", ctypes.c_int32)]


class _DarwinUCred(ctypes.Structure):
    _fields_ = [("ref", ctypes.c_int32), ("uid", ctypes.c_uint32),
                ("ngroups", ctypes.c_int16), ("groups", ctypes.c_uint32 * 16)]


class _DarwinVMSpace(ctypes.Structure):
    _fields_ = [("dummy0", ctypes.c_int32), ("dummy2", ctypes.c_void_p),
                ("dummy3", ctypes.c_int32 * 5), ("dummy4", ctypes.c_void_p * 3)]


class _DarwinEProc(ctypes.Structure):
    _fields_ = [
        ("paddr", ctypes.c_void_p), ("sess", ctypes.c_void_p), ("pcred", _DarwinPCred),
        ("ucred", _DarwinUCred), ("vm", _DarwinVMSpace), ("ppid", ctypes.c_int32),
        ("pgid", ctypes.c_int32), ("jobc", ctypes.c_int16), ("tdev", ctypes.c_int32),
        ("tpgid", ctypes.c_int32), ("tsess", ctypes.c_void_p), ("wmesg", ctypes.c_char * 8),
        ("xsize", ctypes.c_int32), ("xrssize", ctypes.c_int16), ("xccount", ctypes.c_int16),
        ("xswrss", ctypes.c_int16), ("flag", ctypes.c_int32), ("login", ctypes.c_char * 12),
        ("spare", ctypes.c_int32 * 4),
    ]


class _DarwinKInfoProc(ctypes.Structure):
    _fields_ = [("proc", _DarwinExternProc), ("eproc", _DarwinEProc)]


def _check_darwin_census_abi() -> None:
    # Reject an unsupported ABI rather than parsing an apparently empty census.
    expected = (
        ctypes.sizeof(ctypes.c_void_p) == 8,
        ctypes.sizeof(ctypes.c_int) == 4,
        sys.byteorder == "little",
        ctypes.sizeof(_DarwinTimeval) == 16,
        ctypes.sizeof(_DarwinExternProc) == 296,
        ctypes.sizeof(_DarwinEProc) == 352,
        ctypes.sizeof(_DarwinKInfoProc) == 648,
        _DarwinExternProc.pid.offset == 40,
        _DarwinExternProc.status.offset == 36,
        _DarwinEProc.ucred.offset + _DarwinUCred.uid.offset == 124,
        _DarwinEProc.ppid.offset == 264,
        _DarwinEProc.pgid.offset == 268,
    )
    if sys.platform != "darwin" or not all(expected):
        raise DarwinBindingError("Darwin public process census ABI is unsupported")


def _ps_lstart_birth(start_sec: int) -> str:
    """Retain the established English ps-lstart API, including space-padded day.

    Its second resolution is compatibility data; exact kernel tokens and start
    anchors still provide the existing authority checks. It is not a new PID
    reuse guarantee, and sysctl microseconds are not silently discarded there.
    """
    try:
        value = time.localtime(start_sec)
    except (OverflowError, OSError, ValueError) as exc:
        raise DarwinBindingError("Darwin process census birth is invalid") from exc
    weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return (f"ps-lstart:{weekdays[value.tm_wday]} {months[value.tm_mon - 1]} "
            f"{value.tm_mday:2d} {value.tm_hour:02d}:{value.tm_min:02d}:{value.tm_sec:02d} {value.tm_year:04d}")


def _darwin_process_records(pid: int | None = None) -> list[dict[str, Any]]:
    """Read the public BSD census directly, including protected UIDs and zombies.

    A selected PID's absence is only an observation. Neither absence nor a
    zombie is a positive retained-parent wait/reap or cleanup receipt.
    """
    _check_darwin_census_abi()
    if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int) or not 0 < pid <= 0x7fffffff):
        raise DarwinBindingError("Darwin process census selector is invalid")
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    except OSError as exc:
        raise DarwinBindingError("Darwin process census library is unavailable") from exc
    library.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                               ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    library.sysctl.restype = ctypes.c_int
    mib = (ctypes.c_int * 4)(1, 14, 0 if pid is None else 1, 0 if pid is None else pid)
    size = ctypes.c_size_t()
    ctypes.set_errno(0)
    if library.sysctl(mib, 4, None, ctypes.byref(size), None, 0) != 0:
        raise DarwinBindingError(f"Darwin process census sizing failed (errno={ctypes.get_errno()})")
    stride, limit = ctypes.sizeof(_DarwinKInfoProc), 16 * 1024 * 1024
    # Reserve bounded headroom for arrivals between the size and fill calls.
    capacity = int(size.value) + 128 * stride
    if size.value % stride or not 0 < capacity <= limit:
        raise DarwinBindingError("Darwin process census sizing is malformed or over limit")
    buffer = ctypes.create_string_buffer(capacity)
    used = ctypes.c_size_t(capacity)
    ctypes.set_errno(0)
    if library.sysctl(mib, 4, buffer, ctypes.byref(used), None, 0) != 0:
        raise DarwinBindingError(f"Darwin process census read failed (errno={ctypes.get_errno()})")
    if used.value > capacity or used.value % stride:
        raise DarwinBindingError("Darwin process census returned a truncated record")
    if not used.value and pid is None:
        raise DarwinBindingError("Darwin public process census is unavailable")
    rows, seen = [], set()
    for offset in range(0, int(used.value), stride):
        item = _DarwinKInfoProc.from_buffer_copy(buffer, offset)
        p, e = item.proc, item.eproc
        sec, usec = int(p.un.start.tv_sec), int(p.un.start.tv_usec)
        if (p.pid < 0 or p.pid in seen or (pid is not None and p.pid != pid)
                or p.status not in {1, 2, 3, 4, 5, 6} or e.ppid < 0 or e.pgid < 0
                or sec < 0 or (p.pid > 0 and sec == 0) or not 0 <= usec < 1000000):
            raise DarwinBindingError("Darwin public process census contains an invalid identity")
        seen.add(int(p.pid))
        row: dict[str, Any] = {
            "pid": int(p.pid), "uid": int(e.ucred.uid), "parent_pid": int(e.ppid),
            "pgid": int(e.pgid), "status": int(p.status), "start_sec": sec, "start_usec": usec,
        }
        if pid is not None and p.comm:
            # The kernel's bounded executable name comes from the same native
            # sample as the precise process identity. It may be truncated.
            row["executable_name"] = p.comm.decode("utf-8", errors="replace")
        rows.append(row)
    return rows



def setexec_suspended(argv: Sequence[str], env: Mapping[str, str]) -> None:
    """Replace this trusted wrapper with argv[0], stopped before user code."""

    if sys.platform != "darwin":
        raise DarwinBindingError("suspended SETEXEC custody is available only on Darwin")
    if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
        raise DarwinBindingError("suspended SETEXEC argv is invalid")
    if any(not isinstance(key, str) or not isinstance(value, str) or "\0" in key or "\0" in value
           for key, value in env.items()):
        raise DarwinBindingError("suspended SETEXEC environment is invalid")

    library = ctypes.CDLL(None, use_errno=True)
    attr = ctypes.c_void_p()
    library.posix_spawnattr_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    library.posix_spawnattr_init.restype = ctypes.c_int
    library.posix_spawnattr_setflags.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_short]
    library.posix_spawnattr_setflags.restype = ctypes.c_int
    library.posix_spawnattr_destroy.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    library.posix_spawnattr_destroy.restype = ctypes.c_int
    library.posix_spawn.argtypes = [
        ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_char_p),
        ctypes.POINTER(ctypes.c_char_p),
    ]
    library.posix_spawn.restype = ctypes.c_int

    result = int(library.posix_spawnattr_init(ctypes.byref(attr)))
    if result != 0:
        raise OSError(result, os.strerror(result), "posix_spawnattr_init")
    primary = None
    try:
        flags = DARWIN_POSIX_SPAWN_SETEXEC | DARWIN_POSIX_SPAWN_START_SUSPENDED
        result = int(library.posix_spawnattr_setflags(ctypes.byref(attr), ctypes.c_short(flags)))
        if result != 0:
            raise OSError(result, os.strerror(result), "posix_spawnattr_setflags")
        encoded_argv = [os.fsencode(value) for value in argv] + [None]
        encoded_env = [os.fsencode(f"{key}={value}") for key, value in env.items()] + [None]
        argv_array = (ctypes.c_char_p * len(encoded_argv))(*encoded_argv)
        env_array = (ctypes.c_char_p * len(encoded_env))(*encoded_env)
        child = ctypes.c_int(-1)
        result = int(library.posix_spawn(
            ctypes.byref(child), encoded_argv[0], None, ctypes.byref(attr),
            argv_array, env_array,
        ))
        if result != 0:
            raise OSError(result, os.strerror(result), argv[0])
        # POSIX_SPAWN_SETEXEC must replace this process on success. A return
        # means the platform did not honor the required exec-like contract.
        raise DarwinBindingError("suspended SETEXEC unexpectedly returned to the wrapper")
    except BaseException as error:
        primary = error
        raise
    finally:
        result = int(library.posix_spawnattr_destroy(ctypes.byref(attr)))
        if result != 0:
            error = OSError(result, os.strerror(result), "posix_spawnattr_destroy")
            if primary is None:
                raise error
            primary.spawnattr_release_error = error
            primary.add_note(str(error))



