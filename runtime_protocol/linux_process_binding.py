"""Linux provider for the platform-neutral process-binding token.

Linux has no kernel audit token, so the token is built from the exact
identity the Runtime already observes: pid, uid, /proc start ticks (birth),
and the PID namespace inode. Tokens are observations, never signal authority.
Custody holds a socket-origin pidfd or an independently retained child's pidfd
through verification and signalling. It never reopens a PID from token words.

Exec does not change pid or start ticks, so ROTATES_ON_EXEC is False here.
A sealed, held child is the one the parent reaps; see custody_broker
AuthenticatedCleanupActor.retained_child.

Limitation: /proc start ticks have roughly 10 ms resolution. Two live processes
always differ by pid, so a token cannot be confused across pids. The real risk
is reuse of the SAME pid within one tick. That is covered by the parent holding
the child unreaped until the broker is done (AuthenticatedCleanupActor.retained_child,
sole reaper RetainedProcess); an exited-but-unreaped child keeps its pid, and the
broker refuses it before any signal.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
from typing import Mapping, Sequence

from . import platform
from .process_binding import ProcessBindingError

TOKEN_TAG = 0x4153544C  # "ASTL": Astrid Linux process token
PRIMITIVE = "proc_signal_with_pidfd_identity"
ROTATES_ON_EXEC = False
_WORD_LIMIT = 0xFFFFFFFF
SO_PEERPIDFD = 77  # Linux UAPI; Python does not expose it on every build.
_IDENTITY_FIELDS = ("pid", "uid", "birth_id")


class LinuxBindingError(ProcessBindingError):
    """Raised when a Linux process token cannot be proven exactly."""


def _split64(value: int) -> tuple[int, int]:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise LinuxBindingError("linux process token field is out of range")
    return value & _WORD_LIMIT, value >> 32


def _parse_birth(birth_id: object) -> tuple[int, int]:
    """Return (start_ticks, pidns_inode) from platform.process_identity birth_id."""
    if not isinstance(birth_id, str) or not birth_id.startswith("proc-start-ticks:"):
        raise LinuxBindingError("linux process birth identity is unavailable")
    parts = birth_id.split(";")
    try:
        ticks = int(parts[0].split(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise LinuxBindingError("linux process start ticks are malformed") from exc
    namespace = 0
    boot = ""
    for part in parts[1:]:
        if part.startswith("boot:"):
            boot = part.split(":", 1)[1]
        if part.startswith("pidns:"):
            try:
                namespace = int(part.split(":", 1)[1])
            except ValueError as exc:
                raise LinuxBindingError("linux pid namespace is malformed") from exc
    if namespace == 0:
        raise LinuxBindingError("linux pid namespace is unavailable; refusing")
    # Start ticks repeat across reboots; without boot scope two births can match. Refuse.
    if not boot:
        raise LinuxBindingError("linux boot_id is unavailable or denied; refusing custody")
    return ticks, namespace


def _observe(pid: int) -> dict[str, object]:
    identity = platform.process_identity(pid)
    if identity is None:
        raise LinuxBindingError("linux process is absent or exited")
    if identity.get("pid") != pid:
        raise LinuxBindingError("linux process identity names another pid")
    ticks, namespace = _parse_birth(identity.get("birth_id"))
    uid = identity.get("uid")
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise LinuxBindingError("linux process uid is malformed")
    return {"pid": pid, "uid": uid, "ticks": ticks, "namespace": namespace,
            "birth_id": identity["birth_id"]}


def _words(observed: Mapping[str, object]) -> list[int]:
    ticks_lo, ticks_hi = _split64(int(observed["ticks"]))
    ns_lo, ns_hi = _split64(int(observed["namespace"]))
    uid_lo, uid_hi = _split64(int(observed["uid"]))
    return [TOKEN_TAG, int(observed["pid"]), uid_lo, uid_hi, ticks_lo, ticks_hi, ns_lo, ns_hi]


def token(pid: int) -> dict[str, object]:
    """Capture the live Linux token for a pid, with its digest and birth."""
    observed = _observe(pid)
    words = _words(observed)
    return {**details(words), "words": words}


def details(words: Sequence[int]) -> dict[str, object]:
    """Public token details, with the same keys as the Darwin audit token."""
    decoded = _decode(words)
    return {key: decoded[key] for key in ("pid", "uid", "pidversion", "sha256")}


def _decode(words: Sequence[int]) -> dict[str, object]:
    """Decode and validate a Linux token; never trusts a frame's own pid."""
    if len(words) != 8 or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > _WORD_LIMIT for v in words):
        raise LinuxBindingError("linux process token is invalid")
    if words[0] != TOKEN_TAG:
        raise LinuxBindingError("linux process token tag is wrong")
    pid = words[1]
    uid = words[2] | (words[3] << 32)
    ticks = words[4] | (words[5] << 32)
    namespace = words[6] | (words[7] << 32)
    if pid <= 0 or namespace == 0:
        raise LinuxBindingError("linux process token has no pid or namespace")
    canonical = json.dumps(list(words), separators=(",", ":")).encode("utf-8")
    return {"pid": pid, "uid": uid, "pidversion": ticks, "namespace": namespace,
            "sha256": "sha256:" + hashlib.sha256(canonical).hexdigest()}


def _matches(words: Sequence[int]) -> dict[str, object]:
    decoded = _decode(words)
    observed = _observe(int(decoded["pid"]))
    if (observed["uid"] != decoded["uid"] or observed["ticks"] != decoded["pidversion"]
            or observed["namespace"] != decoded["namespace"]):
        raise LinuxBindingError("linux process identity changed or was reused")
    return decoded


def _identity(value: Mapping[str, object]) -> dict[str, object]:
    if (not isinstance(value, Mapping) or type(value.get("pid")) is not int
            or value["pid"] <= 0 or type(value.get("uid")) is not int
            or value["uid"] < 0):
        raise LinuxBindingError("linux expected process identity is malformed")
    _parse_birth(value.get("birth_id"))
    return {key: value[key] for key in _IDENTITY_FIELDS}


def _check_pidfd(fd: int, pid: int) -> None:
    """Check the retained kernel reference, including exit before PID reuse."""
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    if poller.poll(0):
        raise LinuxBindingError("linux retained process is absent or exited")
    try:
        fields = Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
        values = [line.split(":", 1)[1].strip() for line in fields if line.startswith("Pid:")]
        if len(values) != 1 or int(values[0]) != pid:
            raise LinuxBindingError("linux peer pidfd names another process")
        platform.pidfd_send_signal(fd, 0)
    except (OSError, ValueError) as exc:
        raise LinuxBindingError("linux retained process authority is unavailable") from exc
    if poller.poll(0):
        raise LinuxBindingError("linux retained process is absent or exited")


class PeerHandle:
    """A locally owned native reference, or an explicitly diagnostic observation.

    ``peercred`` snapshots may be displayed, but verify/signal refuse them. The
    caller owns close; closing a channel does not silently transfer its authority
    to a token dictionary. Snapshot properties return copies, never mutable pins.
    """

    def __init__(self, fd: int | None, observed: Mapping[str, object], *, origin: str):
        self._fd = fd
        self._identity = _identity(observed)
        self._words = tuple(_words(observed))
        self._origin = origin
        self._closed = False
        self._lock = threading.RLock()

    @property
    def token(self) -> dict[str, object]:
        return {**details(self._words), "words": list(self._words)}

    @property
    def identity(self) -> dict[str, object]:
        return dict(self._identity)

    @property
    def authority(self) -> str:
        return "peercred" if self._origin == "peercred" else "pidfd"

    def _verify(self, expected=None) -> dict[str, object]:
        if self._closed:
            raise LinuxBindingError("linux retained process authority is closed")
        if self._fd is None:
            raise LinuxBindingError("linux peercred observation has no retained native authority (SO_PEERPIDFD unavailable)")
        if expected is not None and _identity(expected) != self._identity:
            raise LinuxBindingError("linux retained process differs from expected incarnation")
        _check_pidfd(self._fd, int(self._identity["pid"]))
        observed = _observe(int(self._identity["pid"]))
        if (_identity(observed) != self._identity or tuple(_words(observed)) != self._words):
            raise LinuxBindingError("linux retained process identity changed or was reused")
        _check_pidfd(self._fd, int(self._identity["pid"]))
        return self.token

    def verify(self, expected=None) -> dict[str, object]:
        with self._lock:
            return self._verify(expected)

    def signal(self, signum: int) -> None:
        _admit_signal(signum)
        with self._lock:
            self._verify()
            try:
                platform.pidfd_send_signal(self._fd, signum)
            except OSError as exc:
                raise LinuxBindingError("linux retained process signal failed") from exc

    def close(self) -> None:
        with self._lock:
            fd, self._fd = self._fd, None
            self._closed = True
            if fd is not None:
                os.close(fd)

    def __enter__(self):
        if self._closed:
            raise LinuxBindingError("linux retained process authority is closed")
        return self

    def __exit__(self, *_exc):
        self.close()


def retain_peer(connection, *, expected=None) -> PeerHandle:
    """Bind the connection's original peer, never the process carrying its fd.

    Older kernels expose SO_PEERCRED only. That result remains an observation;
    no pidfd_open(pid) fallback can recreate the original connection's authority.
    """
    fd = None
    handle = None
    try:
        raw_before = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw_before)
        if pid <= 0 or uid < 0:
            raise LinuxBindingError("linux peer credentials are unavailable")
        try:
            raw_fd = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize("i"))
            fd, = struct.unpack("i", raw_fd)
            if fd < 0:
                raise LinuxBindingError("linux peer pidfd is invalid")
            os.set_inheritable(fd, False)
            _check_pidfd(fd, pid)
        except OSError as exc:
            if fd is not None or exc.errno not in (errno.ENOPROTOOPT, errno.EINVAL, errno.EOPNOTSUPP):
                raise LinuxBindingError("linux peer pidfd is unavailable") from exc
        observed = _observe(pid)
        raw_after = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        if raw_after != raw_before:
            raise LinuxBindingError("linux peer credentials changed during the read")
        if observed["uid"] != uid:
            raise LinuxBindingError("linux peer uid does not match its process identity")
        if expected is not None and _identity(expected) != _identity(observed):
            raise LinuxBindingError("linux retained process differs from expected incarnation")
        handle = PeerHandle(fd, observed, origin="socket-peer" if fd is not None else "peercred")
        fd = None  # ownership moves once, including verification failure cleanup
        if handle.authority == "pidfd":
            handle.verify(expected)
        return handle
    except (OSError, struct.error, ValueError) as exc:
        if handle is not None:
            handle.close()
        raise LinuxBindingError("linux peer authority observation failed") from exc
    except BaseException:
        if handle is not None:
            handle.close()
        raise
    finally:
        if fd is not None and fd >= 0:
            os.close(fd)


def retain_child(child, *, reap_guard, expected=None) -> PeerHandle:
    """Capture an owned, unreaped direct child while its sole-waiter guards hold.

    All waits/polls must use reap_guard and there must be no external waitpid
    reaper. After capture the pidfd itself prevents substitution by PID reuse.
    """
    if not isinstance(child, subprocess.Popen):
        raise LinuxBindingError("linux child authority requires a retained Popen")
    try:
        wait_guard = platform.validate_child_reaper(child)
    except (OSError, RuntimeError) as exc:
        raise LinuxBindingError("linux child wait ownership is unavailable") from exc
    fd = None
    handle = None
    try:
        with reap_guard, wait_guard:
            if child.returncode is not None:
                raise LinuxBindingError("linux retained child is absent or exited")
            before = platform.process_identity(child.pid)
            if before is None or before.get("parent_pid") != os.getpid():
                raise LinuxBindingError("linux retained child launch lineage is unavailable")
            # The retained Popen and sole-reaper guards establish origin here;
            # this is deliberately not a general retain_pid API.
            fd = platform.pidfd_open(child.pid)
            os.set_inheritable(fd, False)
            _check_pidfd(fd, child.pid)
            observed = _observe(child.pid)
            if _identity(before) != _identity(observed):
                raise LinuxBindingError("linux retained child incarnation changed")
            handle = PeerHandle(fd, observed, origin="retained-child")
            fd = None
            handle.verify(expected)
            return handle
    except (OSError, NotImplementedError) as exc:
        if handle is not None:
            handle.close()
        raise LinuxBindingError("linux retained child pidfd is unavailable") from exc
    except BaseException:
        if handle is not None:
            handle.close()
        raise
    finally:
        if fd is not None:
            os.close(fd)


def peer_token(connection) -> dict[str, object]:
    """Compatible token observation. The returned dictionary is not custody."""
    with retain_peer(connection) as handle:
        return handle.token


def _admit_signal(signum: int) -> None:
    admitted = {platform.TERM, platform.KILL}
    if platform.USER1 is not None:
        admitted.add(platform.USER1)
    if isinstance(signum, bool) or not isinstance(signum, int) or signum not in admitted:
        raise LinuxBindingError("linux process signal is not admitted")


def signal(words: Sequence[int], signum: int, *, authority: PeerHandle | None = None) -> None:
    """Signal only through supplied retained custody; never reopen token PID."""
    _admit_signal(signum)
    _decode(words)
    if not isinstance(authority, PeerHandle):
        raise LinuxBindingError("linux process signal requires retained native authority")
    if list(words) != authority.token["words"]:
        raise LinuxBindingError("linux process token differs from retained authority")
    authority.signal(signum)


def pidfd_available() -> bool:
    """Prove pidfd_open and pidfd_send_signal work on this kernel (probe on self, signal 0)."""
    import os
    try:
        fd = platform.pidfd_open(os.getpid())
    except (OSError, NotImplementedError):
        return False
    try:
        platform.pidfd_send_signal(fd, 0)
        return True
    except (OSError, NotImplementedError):
        return False
    finally:
        os.close(fd)

class LinuxCensus:
    """One non-atomic observation of the visible proc mount, never custody.

    Partial results retain individually verified observations for diagnostics.
    Live row uid is the effective UID from proc status, not proc-directory
    ownership. It can differ from the legacy platform identity observation;
    disagreement cannot establish custody.
    A missing row, partial/unavailable census, or unverified parent edge
    cannot establish absence or ancestry. Even a complete census requires
    independent retained-parent and child revalidation before adoption.
    """

    def __init__(self):
        self.live: dict[int, dict] = {}
        self.exited: dict[int, str] = {}
        self.unknown: dict[int, str] = {}
        self.unverified_parents: tuple[int, ...] = ()
        self.status = "unavailable"
        self.failure: str | None = None


def _proc_root():
    from pathlib import Path
    return Path("/proc")


def _census_boot(root) -> str:
    import uuid
    boot = (root / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if str(uuid.UUID(boot)) != boot:
        raise ValueError("Linux boot identity is malformed")
    return boot


def _read_census_stat(directory: int, pid: int):
    import os
    with os.fdopen(os.open("stat", os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory), "rb") as stream:
        prefix, separator, suffix = stream.read().rpartition(b")")
    fields = suffix.split()
    if (not separator or b" (" not in prefix
            or prefix.partition(b" (")[0] != str(pid).encode("ascii")
            or len(fields) < 20 or not fields[19].isdigit()):
        raise OSError("malformed Linux process stat")
    try:
        ppid, pgid, session = map(int, fields[1:4])
    except ValueError as exc:
        raise OSError("malformed Linux process topology") from exc
    if min(ppid, pgid, session) < 0:
        raise OSError("negative Linux process topology")
    state = fields[0]
    if state == b"Z":
        kind = "exited"
    elif state in (b"X", b"x"):
        kind = "dying"  # Not a positive unreaped-zombie witness.
    elif state in (b"R", b"S", b"D", b"T", b"t", b"W", b"K", b"P", b"I"):
        kind = "live"
    else:
        raise OSError("unknown Linux process state")
    return fields[19].decode("ascii"), ppid, pgid, session, kind


def _parse_census_uid(lines) -> int:
    """Read effective UID from the kernel status record, not proc ownership."""
    rows = [line.split() for line in lines if line.startswith(b"Uid:")]
    if (len(rows) != 1 or len(rows[0]) != 5 or rows[0][0] != b"Uid:"
            or any(not field.isdigit() for field in rows[0][1:])):
        raise OSError("malformed Linux process status uid")
    values = tuple(map(int, rows[0][1:]))
    if any(value >= 0xFFFFFFFF for value in values):
        raise OSError("Linux process status uid out of range")
    return values[1]  # real, effective, saved-set, filesystem


def _read_census_uid(directory: int) -> int:
    import os
    try:
        with os.fdopen(os.open("status", os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory), "rb") as stream:
            return _parse_census_uid(stream)
    except (FileNotFoundError, ProcessLookupError, PermissionError) as exc:
        # A missing/denied status is not evidence that this incarnation exited.
        raise OSError("Linux effective UID observation unavailable") from exc


def _read_census_record(root, pid: int, boot: str | None):
    """Bracket a single incarnation and topology using its proc directory fd."""
    import os
    if type(pid) is not int or pid <= 0:
        raise ValueError("Linux process pid must be positive")
    try:
        directory = os.open(root / str(pid), os.O_RDONLY | os.O_DIRECTORY
                            | os.O_CLOEXEC | os.O_NOFOLLOW)
    except (FileNotFoundError, ProcessLookupError):
        return None
    try:
        try:
            first = _read_census_stat(directory, pid)
            # Nondumpable processes may have root-owned proc directories even
            # while their effective UID is unprivileged. Do not infer identity
            # or authority from that inode metadata.
            uid = _read_census_uid(directory)
            namespace = None
            if boot is not None:
                # Missing scope is an unknown observation, not a vanished pid.
                try:
                    namespace = os.stat("ns/pid", dir_fd=directory).st_ino
                except OSError as exc:
                    raise OSError("Linux PID namespace observation unavailable") from exc
                if namespace <= 0:
                    raise OSError("Linux PID namespace observation malformed")
            second_uid = _read_census_uid(directory)
            second = _read_census_stat(directory, pid)
        except (FileNotFoundError, ProcessLookupError):
            return None
        if first != second or second_uid != uid:
            raise OSError("Linux process incarnation, effective UID or topology changed during observation")
        ticks, ppid, pgid, session, kind = second
        return ({"pid": pid, "uid": uid, "parent_pid": ppid,
                 "process_group": pgid, "session_id": session,
                 "birth_id": platform.linux_birth_id(ticks, boot_id=boot, pidns_inode=namespace)},
                kind, ticks)
    finally:
        os.close(directory)


def _census_pids(root) -> set[int]:
    return {int(path.name) for path in root.iterdir()
            if path.name.isascii() and path.name.isdigit() and int(path.name) > 0}


def census() -> LinuxCensus:
    """Return live identities and separate positive Z witnesses.

    Status is relative to the visible proc mount, not proof of global process
    absence. In particular permission-denied namespaces are explicit unknown
    rows (ordinary unprivileged hosts may have such rows).
    """
    result = LinuxCensus()
    root = _proc_root()
    try:
        boot = _census_boot(root)
        pids = _census_pids(root)
        if not pids:
            raise OSError("Linux proc census contains no visible process")
    except (OSError, ValueError, UnicodeError) as exc:
        result.failure = f"Linux proc census unavailable: {exc}"
        return result

    records = {}
    for pid in sorted(pids):
        try:
            record = _read_census_record(root, pid, boot)
            if record is None:
                raise OSError("enumerated process disappeared")
            if record[1] == "dying":
                raise OSError("dying process is not a zombie witness")
            records[pid] = record
        except (OSError, ValueError, UnicodeError) as exc:
            result.unknown[pid] = str(exc)

    # Never splice a new parent onto an old birth. Revalidate each whole row;
    # changed/recycled/reparented rows are unknown for this census.
    for pid, first in records.items():
        try:
            second = _read_census_record(root, pid, boot)
            if second != first:
                raise OSError("Linux process incarnation or topology changed across census")
            row, kind, _ticks = first
            if kind == "exited":
                result.exited[pid] = row["birth_id"]
            else:
                result.live[pid] = row
        except (OSError, ValueError, UnicodeError) as exc:
            result.unknown[pid] = str(exc)

    try:
        final_pids = _census_pids(root)
        if _census_boot(root) != boot:
            raise OSError("Linux boot identity changed across census")
    except (OSError, ValueError, UnicodeError) as exc:
        result.live.clear()
        result.exited.clear()
        result.failure = f"Linux proc census unavailable: {exc}"
        return result
    for pid in final_pids - pids:
        result.unknown[pid] = "process appeared during census"
    for pid in pids - final_pids:
        result.live.pop(pid, None)
        # A scoped Z observation remains a positive witness for that birth,
        # not for a replacement. Absence itself is never an exit witness.
        result.unknown[pid] = "process disappeared during census"

    unverified = []
    for pid, row in result.live.items():
        parent_pid = row["parent_pid"]
        if not parent_pid:
            continue
        parent = result.live.get(parent_pid)
        if (parent is None or parent_pid == pid
                or int(records[parent_pid][2]) > int(records[pid][2])):
            unverified.append(pid)
    result.unverified_parents = tuple(sorted(unverified))
    if result.unknown or result.unverified_parents:
        result.status = "partial"
        result.failure = ("Linux proc census partial: "
                          f"{len(result.unknown)} unknown rows, "
                          f"{len(result.unverified_parents)} unverified parent edges")
    else:
        result.status = "complete"
    return result


def zombie_birth(pid: int) -> str | None:
    """Return the canonical birth only for an observed unreaped Z incarnation.

    An unavailable scope or changing observation raises; X/x is not a witness.
    """
    root = _proc_root()
    try:
        boot = _census_boot(root)
    except (ValueError, UnicodeError) as exc:
        raise OSError("Linux boot identity unavailable") from exc
    record = _read_census_record(root, pid, boot)
    if record is not None and record[1] == "exited":
        return record[0]["birth_id"]
    return None


def birth_ticks(pid: int) -> str | None:
    """Live start ticks for the legacy Vibe registry, observation only.

    No boot or namespace is inferred from these ticks; never use them to
    promote an old journal or numeric PID to native authority.
    """
    record = _read_census_record(_proc_root(), pid, None)
    return record[2] if record is not None and record[1] == "live" else None
