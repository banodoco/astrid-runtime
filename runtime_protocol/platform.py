"""The Runtime's native OS boundary (stdlib only).

Windows permissions use owner/SYSTEM protected DACLs and handle-based checks.
Process identities are observations, never signal authority;
``signal_process`` pins a kernel handle before comparing an expected identity.

Linux's public ``pidfd_open(pid, flags=0)`` and
``pidfd_send_signal(fd, signum, siginfo=None, flags=0)`` prefer each stdlib
wrapper independently, with a verified syscall fallback when it is absent.
Callers using these low-level helpers own identity checks and fd closure.

Process control is ``strict`` unless Runtime support says ``sandbox``
(``runtime_protocol.process_control``); see ``configure_process_control``.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

from . import cancellation

TERM = int(signal.SIGTERM)
KILL = int(getattr(signal, "SIGKILL", 9))
USER1 = int(signal.SIGUSR1) if hasattr(signal, "SIGUSR1") else None
_windows_worker_spawn_lock = threading.RLock()
_directory_mutex_guard = threading.Lock()
_directory_mutexes: dict[int, tuple[int, threading.Lock, int]] = {}
_directory_mutex_gates: dict[str, threading.Lock] = {}


def current_user() -> int:
    """UID on POSIX; an opaque, stable integer derived from the token SID on Windows."""
    if sys.platform != "win32":
        return os.getuid()
    return _windows_user(_kernel().GetCurrentProcess())


def data_root(home: Path | str | None = None) -> Path:
    home = Path(home).expanduser() if home is not None else Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Astrid Runtime"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Astrid Runtime"
    return Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share") / "astrid-runtime"


def log_dir(home: Path | str | None = None) -> Path:
    home = Path(home).expanduser() if home is not None else Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Logs" / "Astrid Runtime"
    if sys.platform == "win32":
        return data_root(home) / "logs"
    return Path(os.environ.get("XDG_STATE_HOME") or home / ".local" / "state") / "astrid-runtime" / "logs"


def is_remote_filesystem(path: Path | str) -> bool:
    """Identify Windows network volumes, including UNC and mapped drives.

    GetVolumePathName follows junctions and mounted folders and also accepts
    missing trailing components, so this works before a realm is created.
    Other filesystem users (including media readers) do not need this policy.
    """
    if sys.platform != "win32":
        return False
    name = os.fspath(path).replace("/", "\\")
    if name.startswith("\\\\") and (
        not name.startswith(("\\\\?\\", "\\\\.\\"))
        or name.upper().startswith("\\\\?\\UNC\\")
    ):
        return True
    from ctypes import wintypes
    kernel = _kernel()
    kernel.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetVolumePathNameW.restype = wintypes.BOOL
    kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel.GetDriveTypeW.restype = wintypes.UINT
    volume = ctypes.create_unicode_buffer(32768)
    if not kernel.GetVolumePathNameW(str(Path(path).absolute()), volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    drive_type = kernel.GetDriveTypeW(volume.value)
    if drive_type in (0, 1):  # DRIVE_UNKNOWN / DRIVE_NO_ROOT_DIR
        raise OSError(errno.ENODEV, "filesystem volume type is unavailable", str(path))
    return drive_type == 4  # DRIVE_REMOTE


def owner_only(path_or_fd, *, directory: bool | None = None) -> None:
    """Apply 0600/0700 or a protected owner/SYSTEM DACL."""
    if sys.platform == "win32":
        from .windows_security import restrict
        restrict(path_or_fd)
        return
    value = os.fstat(path_or_fd) if isinstance(path_or_fd, int) else os.stat(path_or_fd, follow_symlinks=False)
    if stat.S_ISLNK(value.st_mode):
        raise OSError(errno.ELOOP, "owner-only permissions cannot be applied through a symlink")
    directory = stat.S_ISDIR(value.st_mode) if directory is None else directory
    if isinstance(path_or_fd, int):
        os.fchmod(path_or_fd, 0o700 if directory else 0o600)
    else:
        os.chmod(path_or_fd, 0o700 if directory else 0o600)


def is_owner_only(path_or_fd_or_stat, *, directory: bool | None = None) -> bool:
    """Check native owner and access permissions; stat alone cannot check a DACL."""
    if sys.platform == "win32":
        if isinstance(path_or_fd_or_stat, os.stat_result):
            return False
        from .windows_security import validate
        try:
            validate(path_or_fd_or_stat)
            return True
        except OSError:
            return False
    try:
        value = path_or_fd_or_stat
        if not isinstance(value, os.stat_result):
            value = os.fstat(value) if isinstance(value, int) else os.stat(value, follow_symlinks=False)
        if stat.S_ISLNK(value.st_mode):
            return False
        directory = stat.S_ISDIR(value.st_mode) if directory is None else directory
        return value.st_uid == current_user() and stat.S_IMODE(value.st_mode) == (0o700 if directory else 0o600)
    except OSError:
        return False


def is_current_user(metadata) -> bool:
    """Ownership-only check for artifacts whose existing mode is not restricted."""
    return sys.platform == "win32" or metadata.st_uid == current_user()


def private_directory(path) -> None:
    if sys.platform == "win32":
        from .windows_security import private_directory as create
        create(path)
    else:
        Path(path).mkdir(parents=True, exist_ok=True)
        owner_only(path, directory=True)


def private_temporary(directory, prefix):
    if sys.platform == "win32":
        from .windows_security import private_temporary as create
        return create(directory, prefix)
    import tempfile
    return tempfile.mkstemp(dir=directory, prefix=prefix)


def _retry_windows_sharing_violation(operation, *, clock=time.monotonic, sleep=time.sleep):
    """Retry AV/reader sharing failures for at most a quarter second."""
    deadline = clock() + 0.25
    delay = 0.01
    while True:
        try:
            return operation()
        except OSError as exc:
            if getattr(exc, "winerror", None) not in (5, 32, 33) or clock() >= deadline:
                raise
            sleep(min(delay, max(0, deadline - clock())))
            delay = min(delay * 2, 0.05)


def _move_file_write_through(source, destination):
    """Replace a path with Win32's write-through namespace durability."""
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    move = kernel.MoveFileExW
    move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    move.restype = wintypes.BOOL
    if not move(os.fspath(source), os.fspath(destination), 0x1 | 0x8):
        raise ctypes.WinError(ctypes.get_last_error())


def fsync_directory(path):
    """Persist a directory entry update on POSIX; Windows has no dir fsync."""
    if sys.platform == "win32":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def replace_path(source, destination):
    """Publish a rename without a subsequent, fallible directory flush.

    Transactions must record the completed rename before calling
    ``flush_replace``. Windows includes write-through in the native move:
    there is no separate portable directory flush on that platform.
    """
    if sys.platform == "win32":
        return _retry_windows_sharing_violation(
            lambda: _move_file_write_through(source, destination)
        )
    os.replace(source, destination)


def flush_replace(source, destination):
    """Persist both renamed entries after the caller records publication."""
    parents = {Path(source).parent, Path(destination).parent}
    for parent in parents:
        fsync_directory(parent)


def durable_replace(source, destination):
    """Publish and persist a path; owns all parent-directory durability.

    Use ``replace_path`` followed by ``flush_replace`` when transaction
    bookkeeping must distinguish a rename from a subsequent flush failure.
    """
    replace_path(source, destination)
    flush_replace(source, destination)


def read_private_file(path):
    if sys.platform == "win32":
        from .windows_security import read_private
        return read_private(path)
    return Path(path).read_bytes()


def lock_file(fd: int, *, exclusive: bool = True, blocking: bool = True) -> None:
    if blocking and cancellation.active():
        while True:
            cancellation.check()
            try:
                return _lock_file(fd, exclusive=exclusive, blocking=False)
            except BlockingIOError:
                cancellation.pause(0.05)
    return _lock_file(fd, exclusive=exclusive, blocking=blocking)


def _lock_file(fd: int, *, exclusive: bool = True, blocking: bool = True) -> None:
    if sys.platform != "win32":
        import fcntl
        fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | (0 if blocking else fcntl.LOCK_NB))
        return
    info = os.fstat(fd)
    if stat.S_ISDIR(info.st_mode):
        if not exclusive:
            raise NotImplementedError("shared Windows directory locks are not supported")
        with _directory_mutex_guard:
            held = _directory_mutexes.get(fd)
            if held is not None and held[2] == threading.get_ident():
                return
        handle, gate, owner_thread = _lock_windows_directory(fd, info, blocking=blocking)
        with _directory_mutex_guard:
            _directory_mutexes[fd] = (handle, gate, owner_thread)
        return
    import msvcrt
    from ctypes import wintypes
    overlap = _windows_overlapped()
    kernel = _kernel()
    kernel.LockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    kernel.LockFileEx.restype = wintypes.BOOL
    if not kernel.LockFileEx(wintypes.HANDLE(msvcrt.get_osfhandle(fd)),
                             (2 if exclusive else 0) | (0 if blocking else 1),
                             0, 1, 0, ctypes.byref(overlap)):
        error = ctypes.get_last_error()
        if error in (33, 158):
            raise BlockingIOError(errno.EAGAIN, "file is locked")
        raise ctypes.WinError(error)


def unlock_file(fd: int) -> None:
    if sys.platform != "win32":
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    import msvcrt
    from ctypes import wintypes
    with _directory_mutex_guard:
        held = _directory_mutexes.get(fd)
        if held is not None and held[2] != threading.get_ident():
            raise RuntimeError("Windows directory locks must be released by their acquiring thread")
        if held is not None:
            del _directory_mutexes[fd]
    if held is not None:
        mutex, gate, _owner_thread = held
        kernel = _kernel()
        kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel.ReleaseMutex.restype = wintypes.BOOL
        if not kernel.ReleaseMutex(wintypes.HANDLE(mutex)):
            error = ctypes.get_last_error()
            kernel.CloseHandle(wintypes.HANDLE(mutex))
            gate.release()
            raise ctypes.WinError(error)
        kernel.CloseHandle(wintypes.HANDLE(mutex))
        gate.release()
        return
    overlap = _windows_overlapped()
    kernel = _kernel()
    kernel.UnlockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    kernel.UnlockFileEx.restype = wintypes.BOOL
    if not kernel.UnlockFileEx(wintypes.HANDLE(msvcrt.get_osfhandle(fd)), 0, 1, 0, ctypes.byref(overlap)):
        error = ctypes.get_last_error()
        if error != 158:  # unlock after an unsuccessful nonblocking acquisition
            raise ctypes.WinError(error)


def _windows_overlapped():
    """Return a correctly aligned OVERLAPPED for both Windows pointer sizes."""
    from ctypes import wintypes

    class Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]
    return Overlapped()


def _lock_windows_directory(fd: int, info, *, blocking: bool) -> tuple[int, threading.Lock, int]:
    """Lock a directory identity with an abandoned-aware named mutex.

    LockFileEx does not accept directory handles. Windows file IDs and volume
    serials identify the retained directory independently of its path. The
    global namespace also fences the same user in another logon session (for
    example, a scheduled daemon and an interactive installer). Global mutexes
    do not require SeCreateGlobalPrivilege; that restriction applies to file
    mappings and symbolic links, not synchronization objects.
    https://learn.microsoft.com/en-us/windows/win32/termserv/kernel-object-namespaces
    The non-reentrant in-process gate prevents Win32 mutex same-thread recursion;
    acquisition and release must occur on the same thread.
    """
    from ctypes import wintypes
    identity = f"{current_user()}:{int(info.st_dev)}:{int(info.st_ino)}".encode()
    name = "Global\\AstridRuntime.directory." + hashlib.sha256(identity).hexdigest()
    kernel = _kernel()
    with _directory_mutex_guard:
        gate = _directory_mutex_gates.setdefault(name, threading.Lock())
    if not gate.acquire(blocking=blocking):
        raise BlockingIOError(errno.EAGAIN, "directory is locked")
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    mutex = kernel.CreateMutexW(None, False, name)
    if not mutex:
        gate.release()
        raise ctypes.WinError(ctypes.get_last_error())
    result = int(kernel.WaitForSingleObject(mutex, 0xFFFFFFFF if blocking else 0))
    if result in (0, 0x80):  # WAIT_OBJECT_0 or WAIT_ABANDONED
        return int(mutex), gate, threading.get_ident()
    error = ctypes.get_last_error()
    kernel.CloseHandle(mutex)
    gate.release()
    if result == 0x102:  # WAIT_TIMEOUT
        raise BlockingIOError(errno.EAGAIN, "directory is locked")
    if result == 0xFFFFFFFF:  # WAIT_FAILED
        raise ctypes.WinError(error)
    raise OSError(f"unexpected Windows directory lock wait status: {result}")


@contextmanager
def file_lock(path_or_fd, *, exclusive: bool = True, blocking: bool = True):
    own = not isinstance(path_or_fd, int)
    if own:
        from .dirfd import filesystem
        fd = filesystem.open(
            path_or_fd,
            os.O_RDWR | os.O_CREAT | getattr(filesystem, "O_NOFOLLOW", 0),
            0o600,
        )
    else:
        fd = path_or_fd
    locked = False
    try:
        if own:
            owner_only(fd)
        lock_file(fd, exclusive=exclusive, blocking=blocking)
        locked = True
        yield fd
    finally:
        if locked:
            unlock_file(fd)
        if own:
            os.close(fd)


class _DarwinBSDInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "reserved",
    )] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")
    ] + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]


def _read_darwin_process_info(pid: int, *, include_exit: bool = False):
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
    return {"pid": int(value.pid), "uid": int(value.uid), "parent_pid": int(value.ppid),
            "start_sec": int(value.start_sec), "start_usec": int(value.start_usec),
            **({"status": int(value.status)} if include_exit else {})}


def _kernel():
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _windows_user(handle) -> int:
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi.GetLengthSid.restype = wintypes.DWORD
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(handle, 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_size = int(advapi.GetLengthSid(sid))
        if sid_size <= 0:
            raise OSError("current process token contains an invalid SID")
        # Runtime's persisted UID field is a signed SQLite INTEGER. Keep the
        # SID-derived identifier stable and within its non-negative range.
        return int.from_bytes(hashlib.sha256(ctypes.string_at(sid, sid_size)).digest()[:8], "big") & 0x7FFF_FFFF_FFFF_FFFF
    finally:
        _kernel().CloseHandle(token)


def _windows_identity(pid: int, handle):
    from ctypes import wintypes
    kernel = _kernel()
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(handle, *[ctypes.byref(value) for value in times]):
        raise ctypes.WinError(ctypes.get_last_error())
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    try:
        parent_pid = _windows_parent(pid)
    except (OSError, ProcessLookupError):
        # Parent enumeration is an optional observation and may race process
        # exit; it must not invalidate the kernel-backed identity fields.
        parent_pid = None
    return {"pid": pid, "uid": _windows_user(handle), "parent_pid": parent_pid,
            "birth_id": f"windows-creation:{created}", "process_group": pid, "session_id": pid}


def _windows_process_active(handle) -> bool:
    from ctypes import wintypes
    kernel = _kernel()
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    result = int(kernel.WaitForSingleObject(handle, 0))
    if result == 0x102:  # WAIT_TIMEOUT means the process object is unsignaled.
        return True
    if result == 0:  # WAIT_OBJECT_0 proves the process has exited.
        return False
    if result == 0xFFFFFFFF:  # WAIT_FAILED
        raise ctypes.WinError(ctypes.get_last_error())
    raise OSError(f"unexpected Windows process wait status: {result}")


def _windows_parent(pid):
    from ctypes import wintypes
    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]
    kernel = _kernel()
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32FirstW.restype = wintypes.BOOL
    kernel.Process32NextW.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = Entry(); entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32ProcessID == pid:
                return int(entry.th32ParentProcessID)
            found = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        raise ProcessLookupError(pid)
    finally:
        kernel.CloseHandle(snapshot)


def process_identity(pid: int, *, timeout: float = 1.0):
    """Return identity, None only for proven absence; raise on unknown observation."""
    if timeout <= 0:
        raise OSError("process identity observation deadline expired")
    if pid <= 0:
        return None
    if sys.platform == "darwin":
        deadline = time.monotonic() + timeout
        first = _read_darwin_process_info(pid)
        if first is None:
            return None
        second = _read_darwin_process_info(pid)
        if time.monotonic() >= deadline:
            raise OSError("process identity observation deadline expired")
        if first != second:
            raise OSError("native process identity changed during observation")
        local = time.localtime(first["start_sec"])
        birth = ("ps-lstart:" + time.strftime("%a %b ", local) + f"{local.tm_mday:2d}"
                 + time.strftime(" %H:%M:%S %Y", local))
        return {"pid": first["pid"], "uid": first["uid"], "parent_pid": first["parent_pid"], "birth_id": birth}
    if sys.platform == "win32":
        kernel = _kernel()
        handle = kernel.OpenProcess(0x1000 | 0x00100000, False, pid)  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        if not handle:
            if ctypes.get_last_error() == 87:
                return None
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not _windows_process_active(handle):
                return None
            try:
                identity = _windows_identity(pid, handle)
            except OSError:
                if not _windows_process_active(handle):
                    return None
                raise
            if not _windows_process_active(handle):
                return None
            return identity
        finally:
            kernel.CloseHandle(handle)
    root = Path("/proc") / str(pid)
    try:
        # Start ticks alone can collide after reboot or in another PID namespace.
        # Scope interfaces are optional in restricted proc mounts. An older
        # scoped record cannot be reclaimed if its scope becomes unreadable.
        scope = ""
        try:
            boot = (Path("/proc") / "sys/kernel/random/boot_id").read_text().strip()
            if boot:
                scope += f";boot:{boot}"
        except (FileNotFoundError, PermissionError):
            pass
        try:
            namespace = (root / "ns/pid").stat().st_ino
            scope += f";pidns:{namespace}"
        except (FileNotFoundError, PermissionError):
            pass
        raw = (root / "stat").read_text()
        fields = raw.rsplit(")", 1)[1].split()
        value = {"pid": pid, "uid": root.stat().st_uid, "parent_pid": int(fields[1]),
                 "birth_id": f"proc-start-ticks:{fields[19]}{scope}", "process_group": int(fields[2]), "session_id": int(fields[3])}
        second = (root / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[19] != second[19]:
            raise OSError("process identity changed during observation")
        if second[0] in {"Z", "X", "x"}:
            return None  # /proc still retains an exited process awaiting reap.
        return value
    except FileNotFoundError:
        return None
    except (ValueError, IndexError) as exc:
        raise OSError("process identity observation was malformed") from exc


def process_birth_matches(expected: str, actual: str) -> bool | None:
    """Compare native births, accepting pre-scope Linux owner records.

    None means scope could not be observed, never evidence for reclamation.
    Legacy records cannot prove a reboot/namespace change with equal ticks.
    """
    if expected.startswith("proc-start-ticks:") and actual.startswith("proc-start-ticks:"):
        old_tick, _, old_scope = expected.partition(";")
        new_tick, _, new_scope = actual.partition(";")
        if old_tick != new_tick:
            return False
        expected_scope = dict(part.split(":", 1) for part in old_scope.split(";") if ":" in part)
        actual_scope = dict(part.split(":", 1) for part in new_scope.split(";") if ":" in part)
        if any(actual_scope[key] != value for key, value in expected_scope.items() if key in actual_scope):
            return False
        if any(key not in actual_scope for key in expected_scope):
            return None
        return True
    return expected == actual


def process_executable(pid: int) -> str:
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        library.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        if library.proc_pidpath(int(pid), buffer, len(buffer)) <= 0:
            raise OSError(ctypes.get_errno(), "process executable observation failed")
        return os.fsdecode(buffer.value)
    if sys.platform != "win32":
        return str((Path("/proc") / str(pid) / "exe").resolve(strict=True))
    from ctypes import wintypes
    kernel = _kernel(); handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        buffer = ctypes.create_unicode_buffer(32768); size = wintypes.DWORD(len(buffer))
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value
    finally:
        kernel.CloseHandle(handle)


def process_group(pid):
    return pid if sys.platform == "win32" else os.getpgid(pid)


def session_id(pid):
    return pid if sys.platform == "win32" else os.getsid(pid)


def start_session() -> None:
    """Create a POSIX session before exec; Windows spawn_tree creates a group."""
    if sys.platform != "win32":
        os.setsid()


def validate_child_reaper(child):
    """Return the Popen wait guard after rejecting unsafe POSIX auto-reaping."""
    if sys.platform != "win32" and signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("retained child cannot bind with automatic reaping")
    wait_guard = getattr(child, "_waitpid_lock", None)
    if wait_guard is None:
        if sys.platform == "win32":
            return nullcontext()
        raise RuntimeError("retained child has no serialized wait ownership")
    return wait_guard


class _Job:
    """A non-inheritable kill-on-close Job Object owning a complete process tree."""
    def __init__(self):
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        kernel = _kernel()
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended(); limits.BasicLimitInformation.LimitFlags = 0x2000
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close(); raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process):
        from ctypes import wintypes
        kernel = _kernel()
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        if not kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def active_processes(self):
        from ctypes import wintypes
        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_int64) for name in (
                "TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime",
            )] + [(name, ctypes.c_uint32) for name in (
                "TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses",
            )]
        kernel = _kernel()
        kernel.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ]
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        accounting = Accounting()
        if not kernel.QueryInformationJobObject(
            self.handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return accounting.ActiveProcesses

    def close(self):
        if getattr(self, "handle", None):
            _kernel().CloseHandle(self.handle); self.handle = None

    def __del__(self):
        self.close()


def _resume_process(pid):
    from ctypes import wintypes
    class ThreadEntry(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in ("dwSize", "cntUsage", "th32ThreadID", "th32OwnerProcessID")] + [("tpBasePri", ctypes.c_long), ("tpDeltaPri", ctypes.c_long), ("dwFlags", wintypes.DWORD)]
    kernel = _kernel()
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    kernel.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    kernel.Thread32First.restype = wintypes.BOOL
    kernel.Thread32Next.restype = wintypes.BOOL
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD
    snapshot = kernel.CreateToolhelp32Snapshot(4, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ThreadEntry(); entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32OwnerProcessID == pid:
                handle = kernel.OpenThread(2, False, entry.th32ThreadID)
                if not handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if kernel.ResumeThread(handle) == 0xFFFFFFFF:
                        raise ctypes.WinError(ctypes.get_last_error())
                    return
                finally:
                    kernel.CloseHandle(handle)
            found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
        raise ProcessLookupError(pid)
    finally:
        kernel.CloseHandle(snapshot)


def spawn_tree(argv, *, detached=False, hidden=False, **kwargs):
    """Spawn a session/Job, assigning Windows children before their first instruction.

    Detached Windows daemons and retained Workers inherit their Job handles,
    preserving custody across an orderly owner exit.
    """
    if kwargs.get("stdin") is None:
        kwargs["stdin"] = subprocess.DEVNULL
    if sys.platform != "win32":
        kwargs.setdefault("start_new_session", True)
        return subprocess.Popen(argv, **kwargs)
    # handle_list requires temporary handle inheritance. Serialize launches so
    # concurrent callers cannot restore another launch's inheritance flags.
    with _windows_worker_spawn_lock:
        return _spawn_windows_tree(argv, detached=detached, hidden=hidden, **kwargs)


def _spawn_windows_tree(argv, *, detached=False, hidden=False, **kwargs):
    kwargs.pop("start_new_session", None)
    descriptors = kwargs.pop("pass_fds", ())
    inheritance = job = process = None
    ancestor_flags = []
    # A retained Worker must keep its Job alive when owner A exits after an
    # orderly handoff. Its own final exit closes this last handle and contains
    # descendants, just as a detached Runtime owner does.
    inherit_job = detached or bool(descriptors)
    try:
        if descriptors:
            from .windows_handoff import InheritedHandles
            inheritance = InheritedHandles(argv, kwargs, descriptors)
            argv = inheritance.argv
        job = _Job()
        if inherit_job:
            os.set_handle_inheritable(job.handle, True)
            startup = kwargs.setdefault("startupinfo", subprocess.STARTUPINFO())
            attributes = dict(startup.lpAttributeList or {})
            ancestors = [*_inherited_ancestor_jobs, *([_inherited_job_handle] if _inherited_job_handle else [])]
            for handle in ancestors:
                ancestor_flags.append((handle, os.get_handle_inheritable(handle)))
                os.set_handle_inheritable(handle, True)
            attributes["handle_list"] = list(dict.fromkeys([*attributes.get("handle_list", []), job.handle, *ancestors]))
            startup.lpAttributeList = attributes
            kwargs["env"] = dict(kwargs.get("env") or os.environ)
            kwargs["env"]["ASTRID_RUNTIME_JOB_HANDLE"] = str(job.handle)
            kwargs["env"]["ASTRID_RUNTIME_ANCESTOR_JOB_HANDLES"] = ",".join(map(str, ancestors))
            kwargs["close_fds"] = True
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x200 | 0x4 | (0x08000000 if hidden else 0)
        process = subprocess.Popen(argv, **kwargs)
        if inheritance is not None:
            inheritance.restore()
        for handle, previous in ancestor_flags:
            os.set_handle_inheritable(handle, previous)
        ancestor_flags.clear()
        job.assign(process)
        process._runtime_job = job
        _resume_process(process.pid)
        if inheritance is not None:
            inheritance.authenticate(process)
        return process
    except BaseException:
        if process is not None:
            process.kill(); process.wait()
        if job is not None:
            job.close()
        raise
    finally:
        if inheritance is not None:
            inheritance.close()
        for handle, previous in ancestor_flags:
            os.set_handle_inheritable(handle, previous)
        if inherit_job and job is not None and job.handle:
            os.set_handle_inheritable(job.handle, False)


def _posix_group_holds_only_zombies(pgid):
    """True only when `ps` shows rows for the group and every one is a zombie.

    An empty listing, a failed `ps`, or any non-zombie row returns False.
    """
    try:
        listing = subprocess.run(["ps", "-A", "-o", "pgid=", "-o", "stat="], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    stats = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == str(pgid):
            stats.append(fields[1])
    return bool(stats) and all(stat.startswith("Z") for stat in stats)


def _signal_posix_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
    except PermissionError as error:
        # macOS answers EPERM, not ESRCH, when a group has only zombies left
        # (an unreaped leader whose descendants are all gone). Treat that as
        # an already-gone group, but only once `ps` proves every row for the
        # group is a zombie; anything else is a real permission failure.
        if not _posix_group_holds_only_zombies(pgid):
            raise
        raise ProcessLookupError(errno.ESRCH, "process group has only zombie members") from error


def signal_tree(process_or_pid, signum):
    pid = process_or_pid if isinstance(process_or_pid, int) else process_or_pid.pid
    if sys.platform == "linux":
        if isinstance(process_or_pid, int):
            raise ProcessLookupError("process-group custody requires an unreaped child")
        with getattr(process_or_pid, "_waitpid_lock", nullcontext()):
            _signal_linux_group(process_or_pid, signum)
    elif sys.platform != "win32":
        _signal_posix_group(pid, signum)
    elif signum == KILL:
        job = getattr(process_or_pid, "_runtime_job", None)
        if job:
            from ctypes import wintypes
            kernel = _kernel(); kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
            if not kernel.TerminateJobObject(job.handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            signal_process(process_identity(pid), KILL)
    else:
        os.kill(pid, signal.CTRL_BREAK_EVENT)


def tree_exited(process):
    """Observe exit without reaping a POSIX tree's process-group anchor.

    The caller must remain the sole waiter until stop_tree has killed any
    surviving descendants. Windows retains that authority in the Job handle.
    """
    if sys.platform == "linux":
        with getattr(process, "_waitpid_lock", nullcontext()):
            if process.returncode is not None:
                return True
            return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    if sys.platform == "darwin":
        with getattr(process, "_waitpid_lock", nullcontext()):
            return _darwin_tree_exited(process)
    return process.poll() is not None


def tree_drained(process):
    """Confirm a Windows process tree once its retained Job has no members."""
    job = getattr(process, "_runtime_job", None)
    if job is None:
        raise ProcessLookupError("process has no Windows Job Object")
    if not job.handle:
        return True
    if job.active_processes():
        return False
    job.close()
    return True


def _darwin_tree_exited(process):
    if process.returncode is not None:
        return True
    info = _read_darwin_process_info(process.pid, include_exit=True)
    return info is None or info["status"] == 5  # SZOMB


def stop_tree(process, grace=5.0, *, stop_channel=False):
    if stop_channel:
        _close_stop_channel(process)
    if sys.platform == "linux":
        return _stop_linux_tree(process, grace, wait_full_grace=stop_channel)
    if sys.platform == "darwin":
        # Keep the unreaped leader until the last group signal, as on Linux.
        with getattr(process, "_waitpid_lock", nullcontext()):
            if process.returncode is not None:
                return
            if stop_channel or not _darwin_tree_exited(process):
                try:
                    signal_tree(process, TERM)
                except ProcessLookupError:
                    pass
            if stop_channel:
                # Descendants share stdin and may still be handling EOF after
                # the session leader has exited.
                time.sleep(max(0.0, grace))
            elif not _darwin_tree_exited(process):
                deadline = time.monotonic() + grace
                while time.monotonic() < deadline and not _darwin_tree_exited(process):
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            try:
                signal_tree(process, KILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=max(2.0, grace))
        return
    try:
        deadline = time.monotonic() + grace
        if process.poll() is None:
            try:
                if not (stop_channel and sys.platform == "win32"):
                    signal_tree(process, TERM)
            except (OSError, ValueError):
                if sys.platform != "win32":
                    raise
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        if stop_channel and sys.platform == "win32":
            # Hidden services have no console. EOF is their cooperative stop
            # request; Job termination is the forced escalation.
            time.sleep(max(0.0, deadline - time.monotonic()))
        if process.poll() is None or sys.platform != "win32":
            try:
                signal_tree(process, KILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.wait(timeout=max(2.0, grace))
    finally:
        job = getattr(process, "_runtime_job", None)
        if job:
            job.close()


def _close_stop_channel(process):
    channel = getattr(process, "stdin", None)
    if channel is not None:
        try:
            channel.close()
        except OSError:
            pass


def _stop_linux_tree(process, grace, *, wait_full_grace=False):
    # poll()/wait() reap the leader and release its numeric PID/PGID. Hold
    # Popen's wait lock and use WNOWAIT until the final descendant signal.
    with getattr(process, "_waitpid_lock", nullcontext()):
        if process.returncode is not None:
            return
        try:
            exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return  # externally reaped: no authority to signal a bare PGID
        if exited is None or wait_full_grace:
            try:
                _signal_linux_group(process, TERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and (exited is None or wait_full_grace):
            try:
                exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                return
            if exited is not None and not wait_full_grace:
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        try:
            _signal_linux_group(process, KILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=max(2.0, grace))


def _signal_linux_group(process, signum):
    """Caller holds Popen's wait lock until killpg has consumed the PGID."""
    if process.returncode is not None:
        raise ProcessLookupError("process-group custody lost: child was reaped")
    try:
        os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as exc:
        raise ProcessLookupError("process-group custody lost: child is no longer waitable") from exc
    try:
        os.killpg(process.pid, signum)
    except PermissionError:
        if not _sandbox_process_control():
            raise
        # The unreaped leader still holds the PGID, so the group cannot be
        # reused while we walk it.
        leader = process_identity(process.pid)
        signal_observed_group(process.pid, signum, leader=leader)


def _linux_pidfd_syscall(operation, *arguments):
    """Use verified Linux syscall ABIs when Python lacks a pidfd wrapper."""
    if sys.platform != "linux":
        raise NotImplementedError("identity-safe process signaling requires Linux pidfd support")
    machine = os.uname().machine
    widths = (ctypes.sizeof(ctypes.c_void_p), ctypes.sizeof(ctypes.c_long))
    # Linux's x86, ARM EABI, powerpc and s390 syscall tables agree with
    # asm-generic/unistd.h (used by arm64, riscv and loongarch) for these calls.
    # x32 adds __X32_SYSCALL_BIT; MIPS uses ABI-specific syscall bases.
    # Neither is safe to infer from the kernel's machine name alone.
    native_width = {
        "x86_64": 8, "i386": 4, "i486": 4, "i586": 4, "i686": 4,
        "aarch64": 8, "armv6l": 4, "armv7l": 4,
        "ppc64": 8, "ppc64le": 8, "s390x": 8, "riscv64": 8, "loongarch64": 8,
    }.get(machine)
    multiarch = getattr(sys.implementation, "_multiarch", "")
    x32 = "x32" in multiarch  # PER_LINUX32 can make x32 report an i686 machine.
    arm_eabi = machine not in {"armv6l", "armv7l"} or multiarch.endswith(
        ("-gnueabi", "-gnueabihf", "-musleabi", "-musleabihf")
    )
    if native_width is None or widths != (native_width, native_width) or x32 or not arm_eabi:
        raise NotImplementedError(
            f"Linux pidfd syscall fallback does not support ABI {machine} "
            f"(pointer/long bytes {widths}, multiarch {multiarch!r})"
        )
    values = []
    for argument in arguments:
        if argument is None:
            values.append(ctypes.c_void_p())
        else:
            value = ctypes.c_int(argument)
            if value.value != argument:
                raise OverflowError("pidfd syscall argument does not fit a C int")
            values.append(value)
    try:
        syscall = ctypes.CDLL(None, use_errno=True).syscall
    except AttributeError as exc:
        raise NotImplementedError("Linux pidfd syscall fallback requires libc syscall support") from exc
    syscall.argtypes = [ctypes.c_long]
    syscall.restype = ctypes.c_long
    number = {"pidfd_open": 434, "pidfd_send_signal": 424}[operation]
    result = syscall(number, *values)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, f"{operation} failed: {os.strerror(error)}")
    return int(result)


def pidfd_open(pid: int, flags: int = 0) -> int:
    """Open a Linux pidfd; the caller authenticates its target and closes it."""
    if sys.platform != "linux":
        raise NotImplementedError("identity-safe process signaling requires Linux pidfd support")
    opener = getattr(os, "pidfd_open", None)
    if opener is not None:
        return opener(pid, flags)
    return _linux_pidfd_syscall("pidfd_open", pid, flags)


def pidfd_send_signal(fd: int, signum: int, siginfo=None, flags: int = 0) -> None:
    """Signal a retained Linux pidfd; the caller owns identity checks and closure.

    The syscall fallback accepts only ``siginfo=None``. Success returns None
    through either route, and this helper leaves the descriptor open.
    """
    if sys.platform != "linux":
        raise NotImplementedError("identity-safe process signaling requires Linux pidfd support")
    sender = getattr(signal, "pidfd_send_signal", None)
    if sender is not None:
        sender(fd, signum, siginfo, flags)
    else:
        if siginfo is not None:
            raise NotImplementedError("Linux pidfd syscall fallback does not support siginfo")
        _linux_pidfd_syscall("pidfd_send_signal", fd, signum, None, flags)


# --- process control: strict (default) or sandbox ---------------------------
#
# Fixed once per process from Runtime support (runtime_protocol.process_control)
# before anything is spawned. Strict keeps every rule below as written. Sandbox
# relaxes exactly two Linux primitives that seccomp sandboxes such as OpenShell
# deny: pidfd_open (ENOSYS) and process-group kill (EPERM).

PROCESS_CONTROL_MODES = ("strict", "sandbox")
_process_control: str | None = None
_process_control_lock = threading.Lock()
_fallbacks_noted: set[str] = set()


def configure_process_control(mode: str) -> None:
    """Fix this process's process-control mode; it cannot change afterwards."""
    global _process_control
    if mode not in PROCESS_CONTROL_MODES:
        raise ValueError(f"process control must be one of {', '.join(PROCESS_CONTROL_MODES)}")
    with _process_control_lock:
        if _process_control is not None and _process_control != mode:
            raise RuntimeError(f"process control is already {_process_control}; refusing to change it to {mode}")
        _process_control = mode


def process_control() -> str:
    return _process_control or "strict"


def _sandbox_process_control() -> bool:
    return sys.platform == "linux" and _process_control == "sandbox"


def _note_fallback(kind: str, detail: str) -> None:
    with _process_control_lock:
        if kind in _fallbacks_noted:
            return
        _fallbacks_noted.add(kind)
    print(f"Runtime sandbox process control: {detail}", file=sys.stderr, flush=True)


def _probe_process_group() -> str:
    """Check a live group created in our PID namespace, never an inherited PGID.

    An inherited group leader may be outside the visible PID namespace, so
    getpgrp() followed by killpg(..., 0) can return ESRCH even though signalling
    Runtime's own child groups works. Keep the probe child alive via stdin
    until the observation completes, then close/reap it on every path.
    """
    try:
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import sys; sys.stdin.buffer.read()"],
            start_new_session=True, stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        return f"probe-error:{errno.errorcode.get(exc.errno, exc.errno)}"
    try:
        try:
            os.killpg(child.pid, 0)
            return "allowed"
        except PermissionError:
            return "denied"
        except OSError as exc:
            return f"error:{errno.errorcode.get(exc.errno, exc.errno)}"
    finally:
        child.stdin.close()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)


def process_control_probe(mode: str | None = None) -> dict:
    """What signalling actually works in this process, checked live.

    ``mode`` evaluates the result for a given setting (doctor reads the
    setting without fixing its own process); default: this process's mode.

    ``ok`` is False when Runtime cannot stop what it starts: then tasks that
    spawn processes must be refused (in strict mode, the reason points at
    sandbox mode). The capability check sends signal 0 to a temporary child
    group held alive until it completes. Cleanup closes stdin and reaps the
    child, killing only that retained child if it fails to exit promptly.
    """
    mode = mode or process_control()
    if mode not in PROCESS_CONTROL_MODES:
        raise ValueError(f"process control must be one of {', '.join(PROCESS_CONTROL_MODES)}")
    report: dict = {"process_control": mode, "platform": sys.platform}
    if sys.platform != "linux":
        report.update(signalling="native", group_signalling="native", ok=True)
        if mode == "sandbox":
            report["note"] = "sandbox mode is on; nothing to relax on this platform yet"
        return report
    try:
        os.close(pidfd_open(os.getpid()))
        pidfd = "available"
    except OSError as exc:
        pidfd = "enosys" if exc.errno == errno.ENOSYS else f"error:{errno.errorcode.get(exc.errno, exc.errno)}"
    except NotImplementedError:
        pidfd = "unsupported"
    group = _probe_process_group()
    if pidfd == "available":
        signalling = "pidfd"
    elif pidfd == "enosys" and mode == "sandbox":
        signalling = "pid-with-start-time-check"
    else:
        signalling = "unavailable"
    if group == "allowed":
        group_signalling = "killpg"
    elif group == "denied" and mode == "sandbox" and signalling != "unavailable":
        group_signalling = "member-walk"
    else:
        group_signalling = "unavailable"
    report.update(pidfd=pidfd, process_group_kill=group, signalling=signalling,
                  group_signalling=group_signalling,
                  ok=signalling != "unavailable" and group_signalling != "unavailable")
    if not report["ok"]:
        report["reason"] = (
            "Runtime cannot stop processes safely here (pidfd: %s, process-group kill: %s)%s"
            % (pidfd, group, "; if this is a seccomp sandbox such as OpenShell, install with --sandbox"
               if mode == "strict" and (pidfd == "enosys" or group == "denied") else
               "; verify that the service can create and signal its own child process groups "
               "and that /proc and PID namespaces are configured consistently"))
    return report


def _signal_checked_pid(expected, signum) -> None:
    """Sandbox process control only, after pidfd_open answered ENOSYS.

    Re-read the start time from /proc, compare it with the expected birth,
    then kill(pid). Refuse if it cannot be read or does not match. For an
    unreaped child, kill(pid) is as safe as a pidfd; otherwise the window is
    the microseconds between the check and the signal.
    """
    _note_fallback("pidfd", "pidfd_open is unavailable (ENOSYS); signalling by PID after a /proc start-time check")
    pid = int(expected["pid"])
    observed = process_identity(pid)
    if observed is None or any(observed.get(k) != expected.get(k) for k in ("pid", "uid", "birth_id")):
        raise OSError("process incarnation changed")
    os.kill(pid, signum)


def _linux_group_members(pgid: int) -> list[dict]:
    members = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            identity = process_identity(int(entry.name))
        except OSError:
            continue  # changing or unreadable right now; the next pass sees it again
        if identity is not None and identity.get("process_group") == pgid:
            members.append(identity)
    return members


_GROUP_WALK_PASSES = 10


def signal_observed_group(pgid: int, signum, *, leader=None) -> None:
    """Signal a process group member by member, leader last (sandbox mode).

    Used when process-group kill is denied, and by callers recovering a
    group whose leader was already reaped. Each member is signalled once,
    through signal_process (birth-checked), and the group is rescanned until
    no unsignalled member remains, so children forked during the walk are
    caught too. ``leader`` is the leader's expected identity (default: the
    live process whose PID is ``pgid``, if any); it is signalled last.
    Raises ProcessLookupError if nothing in the group could be signalled.
    """
    if sys.platform != "linux":
        raise NotImplementedError("member-by-member group signalling is Linux-only")
    if pgid <= 1 or pgid == os.getpgrp():
        raise PermissionError(errno.EPERM, "refusing to walk this process group")
    if _sandbox_process_control():
        _note_fallback("group", "process-group kill is denied; signalling the group member by member, leader last")
    if leader is None:
        candidate = process_identity(pgid)
        leader = candidate if candidate is not None and candidate.get("process_group") == pgid else None
    leader_pid = int(leader["pid"]) if leader else pgid
    done: set[tuple[int, str]] = set()
    signalled = False
    for attempt in range(_GROUP_WALK_PASSES + 1):
        pending = [m for m in _linux_group_members(pgid)
                   if m["pid"] != leader_pid and (m["pid"], m["birth_id"]) not in done]
        if not pending:
            break
        if attempt == _GROUP_WALK_PASSES:
            raise OSError(errno.EAGAIN, "process group kept gaining members while being signalled")
        for member in pending:
            done.add((member["pid"], member["birth_id"]))
            try:
                signal_process(member, signum)
                signalled = True
            except ProcessLookupError:
                pass
            except OSError as exc:
                if str(exc) != "process incarnation changed":
                    raise  # (a changed incarnation means it exited and its PID was reused: skip it)
    if leader is not None:
        try:
            signal_process(leader, signum)
            signalled = True
        except ProcessLookupError:
            pass
    if not signalled:
        raise ProcessLookupError(errno.ESRCH, "no process in the group could be signalled")


def signal_process(expected, signum):
    """Signal one incarnation via pidfd / retained Windows handle, never a bare PID.

    The one exception is sandbox process control on Linux when pidfd_open is
    unavailable (ENOSYS); see _signal_checked_pid.
    """
    if not expected:
        raise ProcessLookupError("missing process identity")
    pid = int(expected["pid"])
    if sys.platform == "darwin":
        # Import lazily: custody_broker itself imports this platform module.
        from astrid_runtime.custody_broker import (
            audit_token_details,
            current_process_audit_token,
            signal_audit_token,
        )
        before = process_identity(pid)
        if before is None or any(before.get(key) != expected.get(key) for key in ("pid", "uid", "birth_id")):
            raise OSError("process incarnation changed")
        token = current_process_audit_token(pid)
        details = audit_token_details(token["words"])
        if details.get("pid") != pid or details.get("uid") != expected.get("uid"):
            raise OSError("audit token does not match expected process identity")
        after = process_identity(pid)
        if after is None or any(after.get(key) != expected.get(key) for key in ("pid", "uid", "birth_id")):
            raise OSError("process incarnation changed while binding its audit token")
        signal_audit_token(token["words"], signum)
        return
    if sys.platform == "win32":
        from ctypes import wintypes
        kernel = _kernel(); handle = kernel.OpenProcess(0x1000 | 1 | 0x100000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            observed = _windows_identity(pid, handle)
            if any(observed.get(k) != expected.get(k) for k in ("pid", "uid", "birth_id")):
                raise OSError("process incarnation changed")
            # CTRL_BREAK is cooperative and addressed to the isolated group;
            # force termination always uses the identity-checked kernel handle.
            if signum != KILL:
                kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
                kernel.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
                if kernel.GenerateConsoleCtrlEvent(signal.CTRL_BREAK_EVENT, pid):
                    return
            kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            if not kernel.TerminateProcess(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(handle)
        return
    try:
        fd = pidfd_open(pid)
    except OSError as exc:
        if exc.errno != errno.ENOSYS or not _sandbox_process_control():
            raise
        _signal_checked_pid(expected, signum)
        return
    try:
        observed = process_identity(pid)
        if observed is None or any(observed.get(k) != expected.get(k) for k in ("pid", "uid", "birth_id")):
            raise OSError("process incarnation changed")
        pidfd_send_signal(fd, signum)
    finally:
        os.close(fd)


def _windows_console_handler_api():
    """Return the typed Windows console callback and registration function."""
    from ctypes import wintypes

    handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetConsoleCP.argtypes = []
    kernel.GetConsoleCP.restype = wintypes.UINT
    if not kernel.GetConsoleCP():
        # pythonw and hidden login services have no console-close channel.
        return None
    register = kernel.SetConsoleCtrlHandler
    register.argtypes = [handler_type, wintypes.BOOL]
    register.restype = wintypes.BOOL

    def set_handler(handler, add):
        if not register(handler, add):
            raise ctypes.WinError(ctypes.get_last_error())

    return handler_type, set_handler


def install_stop_handlers(callback):
    """Install native console/service-manager stop handlers; return a restore callable.

    Windows does not deliver console close, logoff, or shutdown through Python's
    signal module. Its native handler asks the Runtime's normal stop path to run,
    then stays alive until the owner has finished reclaiming its children.
    """
    signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGBREAK"):
        signals.append(signal.SIGBREAK)
    previous = {value: signal.signal(value, callback) for value in signals}

    native_handler = None
    cleanup_complete = None
    set_native_handler = None
    if sys.platform == "win32":
        try:
            api = _windows_console_handler_api()
            if api is not None:
                handler_type, set_native_handler = api
                cleanup_complete = threading.Event()

            def on_console_control(control):
                # CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT and CTRL_SHUTDOWN_EVENT.
                # Ctrl+C and Ctrl+Break already flow through the signal handlers.
                if control not in (2, 5, 6):
                    return False
                try:
                    callback(signal.SIGTERM, None)
                except BaseException:
                    # Never let a Python exception cross the native callback ABI.
                    pass
                cleanup_complete.wait()
                return True

            if api is not None:
                native_handler = handler_type(on_console_control)
                set_native_handler(native_handler, True)
        except BaseException:
            if cleanup_complete is not None:
                cleanup_complete.set()
            for value, handler in previous.items():
                signal.signal(value, handler)
            raise

    def restore():
        try:
            for value, handler in previous.items():
                signal.signal(value, handler)
            if native_handler is not None:
                set_native_handler(native_handler, False)
        finally:
            if cleanup_complete is not None:
                cleanup_complete.set()

    return restore


def _adopt_inherited_job():
    # A detached owner keeps this handle until process exit. Clear inheritance
    # before it can launch children, so its death closes the final Job handle.
    if sys.platform == "win32":
        value = os.environ.pop("ASTRID_RUNTIME_JOB_HANDLE", None)
        if value:
            handle = int(value)
            os.set_handle_inheritable(handle, False)
            return handle
    return None


_inherited_job_handle = _adopt_inherited_job()


def _adopt_ancestor_jobs():
    if sys.platform != "win32":
        return []
    handles = [int(value) for value in os.environ.pop("ASTRID_RUNTIME_ANCESTOR_JOB_HANDLES", "").split(",") if value]
    for handle in handles:
        os.set_handle_inheritable(handle, False)
    return handles


# Keep ancestor Jobs alive through orderly owner exit as well. All processes
# remain in their original Jobs; no breakaway weakens process-tree containment.
_inherited_ancestor_jobs = _adopt_ancestor_jobs()


# Worker IPC stays here so protocol/state-machine code never selects an OS.
def venv_python(root: Path | str) -> Path:
    root = Path(root)
    return root / "Scripts" / "python.exe" if sys.platform == "win32" else root / "bin" / "python"


def _handoff_transport():
    if sys.platform == "win32":
        from . import windows_handoff
        return windows_handoff
    from . import posix_handoff
    return posix_handoff


def handoff_send(channel, payload, descriptors=()):
    return _handoff_transport().send(channel, payload, descriptors)


def handoff_receive(channel, limit):
    return _handoff_transport().receive(channel, limit)


def handoff_peer_uid(channel):
    if sys.platform == "win32":
        return _handoff_transport().verify_peer(channel)["uid"]
    return _handoff_transport().peer_uid(channel)


def handoff_peer_pid(channel):
    if sys.platform == "win32":
        return _handoff_transport().verify_peer(channel)["pid"]
    return _handoff_transport().peer_pid(channel)


def handoff_close(descriptor):
    if sys.platform == "win32":
        import socket
        socket.close(descriptor)
    else:
        os.close(descriptor)


def handoff_set_inheritable(descriptor, value):
    if sys.platform == "win32":
        os.set_handle_inheritable(descriptor, value)
    else:
        os.set_inheritable(descriptor, value)


def handoff_get_inheritable(descriptor):
    return os.get_handle_inheritable(descriptor) if sys.platform == "win32" else os.get_inheritable(descriptor)


def handoff_control_family(family):
    import socket
    return family == (socket.AF_INET if sys.platform == "win32" else socket.AF_UNIX)


def handoff_inspect_socket(descriptor, *, listener):
    if sys.platform != "win32":
        return _handoff_transport().inspect_socket(descriptor, listener=listener)
    import socket
    borrowed = socket.socket(fileno=descriptor)
    try:
        kind = borrowed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        address = borrowed.getsockname()
        detail = (borrowed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), address) if listener else (borrowed.getpeername(), address)
        if not listener and (address[0] != "127.0.0.1" or detail[0][0] != "127.0.0.1"):
            raise OSError("Worker control is not loopback TCP")
        return borrowed.family, kind, detail
    finally:
        borrowed.detach()


def handoff_socket_parent() -> Path:
    """Return the short native temp parent for private POSIX sockets."""
    return Path("/private/tmp") if sys.platform == "darwin" else Path("/tmp")


def handoff_listener(expected=None, *, timeout=5.0):
    if sys.platform == "win32":
        return _handoff_transport().Listener(expected, timeout=timeout)
    return None


def handoff_connect(endpoint, *, expected=None, timeout=5.0):
    if sys.platform == "win32":
        return _handoff_transport().connect(endpoint, expected=expected, timeout=timeout)
    return None


def handoff_token(pid):
    """Encode native Windows identity in the existing eight-word token shape.

    These are creation-time observations, not Darwin audit tokens or signal
    authority. Signalling still opens and pins a process handle in this module.
    """
    observed = process_identity(pid)
    if observed is None:
        raise ProcessLookupError(pid)
    created = int(observed["birth_id"].removeprefix("windows-creation:"))
    uid = observed["uid"]
    words = [0x41535452, pid, uid & 0xffffffff, uid >> 32,
             created & 0xffffffff, created >> 32, 0, 0]
    return {**handoff_token_details(words), "words": words}


def handoff_token_details(words):
    import struct
    if (len(words) != 8 or any(type(value) is not int or not 0 <= value <= 0xffffffff for value in words)
            or words[0] != 0x41535452 or words[6:] != [0, 0]):
        raise OSError("Windows process identity token is invalid")
    created = words[4] | words[5] << 32
    return {"pid": words[1], "uid": words[2] | words[3] << 32,
            "pidversion": created, "sha256": "sha256:" + hashlib.sha256(struct.pack("=8I", *words)).hexdigest()}


def handoff_signal_token(words, signum):
    details = handoff_token_details(words)
    return signal_process({"pid": details["pid"], "uid": details["uid"],
                           "birth_id": f"windows-creation:{details['pidversion']}"}, signum)


def handoff_custody_executable(wrapper, target):
    return target if sys.platform == "win32" else wrapper


def handoff_adopt_socket(descriptor):
    if sys.platform == "win32":
        return _handoff_transport().adopt_socket(descriptor)
    import socket
    channel = socket.socket(fileno=descriptor)
    channel.set_inheritable(False)
    return channel


def handoff_peer_token(channel):
    return _handoff_transport().peer_token(channel)


def handoff_child_identity(process):
    """Pin launch identity through Popen's retained handle, before any PID lookup."""
    if sys.platform != "win32":
        return process_identity(process.pid)
    handle = getattr(process, "_handle", None)
    if handle is None or not _windows_process_active(handle):
        raise ProcessLookupError("prepared Worker is not alive")
    observed = _windows_identity(process.pid, handle)
    if not _windows_process_active(handle):
        raise ProcessLookupError("prepared Worker exited during authentication")
    return observed
