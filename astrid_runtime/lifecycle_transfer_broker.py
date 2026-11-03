"""Low-level Linux lifecycle-transfer descriptor transport.

This module does not grant lifecycle admission.  In particular, a received
file descriptor is not evidence of a successful lock acquisition.  Its caller
must already have authenticated the acquisition, the native launch, and the
transaction state, and must account for an uncertain delivery on any error.
Darwin and the broker state machine are deliberately not implemented here.
"""
from __future__ import annotations

import array
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass

MAX_FRAME = 16 * 1024
TIMEOUT = 10.0
_VERSION = "astrid.lifecycle-transfer-fds/v1"
_FIELDS = {"version", "capability", "binding_digest", "sequence", "role", "objects"}
_ROLES = {"offline-backup", "migration", "candidate", "rollback-r1"}


class TransferError(RuntimeError):
    """A transport refusal; a failed send can still have delivered aliases."""


@dataclass(frozen=True)
class LinuxPeer:
    pid: int
    uid: int
    birth: str
    executable: tuple[int, int]
    cgroup_sha256: str


def linux_peer_identity(pid: int) -> LinuxPeer:
    """Read a native incarnation; the caller must freeze and authorize it."""
    if sys.platform != "linux" or pid <= 0:
        raise TransferError("native peer identity is unsupported")
    try:
        proc = Path("/proc") / str(pid)
        def birth() -> str:
            # comm can contain spaces and parentheses; starttime is field 22.
            raw = (proc / "stat").read_text()
            return raw[raw.rindex(")") + 2:].split()[19]
        before = birth()
        uid = proc.stat().st_uid
        image = (proc / "exe").stat()
        group = (proc / "cgroup").read_bytes()
        if not group or before != birth():
            raise TransferError("peer incarnation changed")
        return LinuxPeer(pid, uid, before, (image.st_dev, image.st_ino),
                         hashlib.sha256(group).hexdigest())
    except (OSError, ValueError, IndexError) as exc:
        raise TransferError("native peer identity unavailable") from exc


def _authenticate(sock: socket.socket, expected: LinuxPeer) -> None:
    if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
        raise TransferError("native peer authentication is unsupported")
    try:
        pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.geteuid() or pid != expected.pid or uid != expected.uid:
            raise TransferError("native peer credentials differ")
        if linux_peer_identity(pid) != expected:
            raise TransferError("native peer incarnation differs")
    except OSError as exc:
        raise TransferError("native peer authentication failed") from exc


def _private_parent(path: Path) -> None:
    try:
        info = path.parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise TransferError("socket parent is not owner-only")
    except OSError as exc:
        raise TransferError("socket parent unavailable") from exc


def listen(path: Path) -> socket.socket:
    """Bind a new private endpoint; never unlink a pre-existing pathname."""
    if sys.platform != "linux":
        raise TransferError("native peer authentication is unsupported")
    path = Path(path)
    _private_parent(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.bind(str(path))
        os.chmod(path, 0o600)
        sock.listen(1)
        return sock
    except BaseException:
        sock.close()
        raise


def connect(path: Path, expected: LinuxPeer) -> socket.socket:
    path = Path(path)
    _private_parent(path)
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise TransferError("socket is not owner-only")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.connect(str(path))
        _authenticate(sock, expected)
        return sock
    except BaseException:
        sock.close()
        raise


def _object(fd: int) -> dict[str, int]:
    info = os.fstat(fd)
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IFMT(info.st_mode), "uid": info.st_uid}


def _hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def send_aliases(sock: socket.socket, *, expected_peer: LinuxPeer, capability: str,
                 binding_digest: str, sequence: int, role: str,
                 directory_fd: int, owner_fd: int) -> None:
    """Send the already-held descriptions. Any failed send is uncertain."""
    _authenticate(sock, expected_peer)
    if (not _hex(capability) or not _hex(binding_digest) or type(sequence) is not int
            or sequence < 1 or role not in _ROLES):
        raise TransferError("invalid transfer binding")
    objects = [_object(directory_fd), _object(owner_fd)]
    if (objects[0]["mode"] != stat.S_IFDIR or objects[1]["mode"] != stat.S_IFREG
            or any(item["uid"] != os.geteuid() for item in objects)):
        raise TransferError("invalid transfer objects")
    message = {"version": _VERSION, "capability": capability, "binding_digest": binding_digest,
               "sequence": sequence, "role": role, "objects": objects}
    body = json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
    if len(body) > MAX_FRAME:
        raise TransferError("transfer frame is too large")
    frame = struct.pack("!I", len(body)) + body
    sock.settimeout(TIMEOUT)
    sent = sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                  array.array("i", [directory_fd, owner_fd]))])
    if sent != len(frame):
        # No retry: the rights may already be queued at the peer.
        raise TransferError("uncertain transfer delivery")
    sock.shutdown(socket.SHUT_WR)


class CloseOnlyAliases:
    """Owned aliases; disposal always closes and never calls LOCK_UN."""
    def __init__(self, directory_fd: int, owner_fd: int):
        self._directory_fd = directory_fd
        self._owner_fd = owner_fd

    def filenos(self) -> tuple[int, int]:
        if self._directory_fd < 0 or self._owner_fd < 0:
            raise TransferError("aliases already closed")
        return self._directory_fd, self._owner_fd

    def close_directory(self) -> None:
        fd, self._directory_fd = self._directory_fd, -1
        if fd >= 0:
            os.close(fd)

    def close(self) -> None:
        try:
            self.close_directory()
        finally:
            fd, self._owner_fd = self._owner_fd, -1
            if fd >= 0:
                os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def receive_aliases(sock: socket.socket, *, expected_peer: LinuxPeer, capability: str,
                    binding_digest: str, sequence: int, role: str,
                    expected_objects: list[dict[str, int]]) -> CloseOnlyAliases:
    """Receive exactly one frame and two aliases, closing all FDs on failure."""
    _authenticate(sock, expected_peer)
    if (not _hex(capability) or not _hex(binding_digest) or type(sequence) is not int
            or sequence < 1 or role not in _ROLES):
        raise TransferError("invalid expected transfer binding")
    fds: list[int] = []
    data = bytearray()
    deadline = time.monotonic() + TIMEOUT
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransferError("transfer deadline expired")
            sock.settimeout(remaining)
            chunk, ancillary, flags, _ = sock.recvmsg(MAX_FRAME + 5 - len(data),
                socket.CMSG_SPACE(16 * array.array("i").itemsize), getattr(socket, "MSG_CMSG_CLOEXEC", 0))
            unexpected = False
            for level, kind, payload in ancillary:
                if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                    unexpected = True
                    continue
                rights = array.array("i")
                rights.frombytes(payload[:len(payload) - len(payload) % rights.itemsize])
                fds.extend(rights)
                for fd in rights:
                    os.set_inheritable(fd, False)
            if unexpected:
                raise TransferError("unexpected ancillary data")
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise TransferError("truncated transfer")
            data.extend(chunk)
            if len(data) > MAX_FRAME + 4:
                raise TransferError("transfer frame is too large")
            if not chunk:
                break
        if len(data) < 4 or struct.unpack("!I", data[:4])[0] != len(data) - 4 or len(fds) != 2:
            raise TransferError("invalid frame or descriptor count")
        def no_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise TransferError("duplicate frame field")
                result[key] = value
            return result
        message = json.loads(data[4:], object_pairs_hook=no_duplicates)
        if not isinstance(message, dict) or set(message) != _FIELDS:
            raise TransferError("invalid transfer fields")
        if (message["version"] != _VERSION or not isinstance(message["capability"], str)
                or not hmac.compare_digest(message["capability"], capability)
                or message["binding_digest"] != binding_digest or type(message["sequence"]) is not int
                or message["sequence"] != sequence or message["role"] != role
                or message["objects"] != expected_objects or [_object(fd) for fd in fds] != expected_objects
                or len(expected_objects) != 2 or expected_objects[0]["mode"] != stat.S_IFDIR
                or expected_objects[1]["mode"] != stat.S_IFREG
                or any(obj["uid"] != os.geteuid() for obj in expected_objects)):
            raise TransferError("transfer binding differs")
        _authenticate(sock, expected_peer)
        result = CloseOnlyAliases(*fds)
        fds = []
        return result
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise TransferError("invalid or incomplete transfer") from exc
    finally:
        for fd in fds:
            os.close(fd)


def _open_root(path: Path) -> int:
    """Open each existing absolute component without following symlinks."""
    if not path.is_absolute() or not path.parts or ".." in path.parts or path == Path("/"):
        raise TransferError("invalid realm path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


class ProvisionalOriginal:
    """Pinned original directory and owner descriptions, not stopped admission."""
    def __init__(self, root: Path, directory_fd: int, owner_fd: int):
        self.root = root
        self._aliases = CloseOnlyAliases(directory_fd, owner_fd)
        self.objects = [_object(directory_fd), _object(owner_fd)]

    @classmethod
    def acquire(cls, root: Path) -> "ProvisionalOriginal":
        if sys.platform != "linux":
            raise TransferError("original lock acquisition is unsupported")
        import fcntl
        root = Path(root)
        directory_fd = owner_fd = -1
        try:
            directory_fd = _open_root(root)
            directory = os.fstat(directory_fd)
            if directory.st_uid != os.geteuid():
                raise TransferError("realm owner differs")
            fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner_fd = os.open("owner.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=directory_fd)
            owner = os.fstat(owner_fd)
            if (not stat.S_ISREG(owner.st_mode) or owner.st_uid != os.geteuid()
                    or owner.st_nlink != 1 or stat.S_IMODE(owner.st_mode) & 0o077):
                raise TransferError("invalid original owner file")
            fcntl.flock(owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = cls(root, directory_fd, owner_fd)
            result.check()
            directory_fd = owner_fd = -1
            return result
        except OSError as exc:
            raise TransferError("original lock unavailable") from exc
        finally:
            if owner_fd >= 0:
                os.close(owner_fd)
            if directory_fd >= 0:
                os.close(directory_fd)

    def check(self) -> None:
        directory_fd, owner_fd = self._aliases.filenos()
        current = -1
        try:
            current = _open_root(self.root)
            info = os.stat("owner.lock", dir_fd=current, follow_symlinks=False)
            owner = os.fstat(owner_fd)
            if ([_object(directory_fd), _object(owner_fd)] != self.objects
                    or _object(current) != self.objects[0]
                    or (info.st_dev, info.st_ino) != (owner.st_dev, owner.st_ino)
                    or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise TransferError("original lock lineage changed")
        except OSError as exc:
            raise TransferError("original lock lineage unavailable") from exc
        finally:
            if current >= 0:
                os.close(current)

    def filenos(self) -> tuple[int, int]:
        self.check()
        return self._aliases.filenos()

    def close(self) -> None:
        self._aliases.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
