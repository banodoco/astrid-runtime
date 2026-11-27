"""Linux provider for the platform-neutral process-binding token.

Linux has no kernel audit token, so the token is built from the exact
identity the Runtime already observes: pid, uid, /proc start ticks (birth),
and the PID namespace inode. The token is refused whenever any of those
differs from a fresh observation of the same pid, and signals go through a
pidfd opened before the identity re-check, so a reused pid cannot be hit.

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
from typing import Mapping, Sequence

from . import platform

TOKEN_TAG = 0x4153544C  # "ASTL": Astrid Linux process token
PRIMITIVE = "proc_signal_with_pidfd_identity"
ROTATES_ON_EXEC = False
_WORD_LIMIT = 0xFFFFFFFF


class LinuxBindingError(RuntimeError):
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
    return {"pid": pid, "uid": uid, "ticks": ticks, "namespace": namespace}


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


def peer_token(connection) -> dict[str, object]:
    """Read the connected peer's pid and uid with SO_PEERCRED, before and after the /proc read."""
    import socket
    import struct

    raw_before = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw_before)
    observed = token(pid)
    raw_after = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    if raw_after != raw_before:
        raise LinuxBindingError("linux peer credentials changed during the read")
    if observed["uid"] != uid:
        raise LinuxBindingError("linux peer uid does not match its process identity")
    return observed


def signal(words: Sequence[int], signum: int) -> None:
    """Signal the exact process named by the token, or refuse without signalling."""
    decoded = _decode(words)
    pid = int(decoded["pid"])
    if signum not in (platform.TERM, platform.KILL) and signum != platform.USER1:
        raise LinuxBindingError("linux process signal is not admitted")
    try:
        fd = platform.pidfd_open(pid)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            raise LinuxBindingError("linux process is absent") from exc
        raise
    try:
        _matches(words)
        platform.pidfd_send_signal(fd, signum)
    finally:
        import os

        os.close(fd)


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
