"""Persistent one-shot marker for provisional descriptor delivery.

A marker is never removed here, including after a failed write or lost peer.
This is transport bookkeeping, not a writer lease or native evidence.
"""
import json
import os
import stat

from astrid_runtime._transfer_session import FenceUnavailable

_NAME = "lifecycle-transfer-delivery.json"
_LIMIT = 16384


def encode(request):
    return json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def existing(directory, data):
    try:
        fd = os.open(_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        named = os.stat(_NAME, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                or info.st_size > _LIMIT):
            raise FenceUnavailable("recovery_required: invalid delivery marker")
        raw = os.read(fd, _LIMIT + 1)
        # Any incomplete or replaced marker stays occupied.
        if not raw or len(raw) != info.st_size:
            raise FenceUnavailable("recovery_required: incomplete delivery marker")
        return "lease_uncertain" if raw == data else "binding_changed"
    finally:
        os.close(fd)


def reserve(directory, data):
    if not data or len(data) > _LIMIT:
        raise FenceUnavailable("invalid delivery marker")
    # O_EXCL commits a permanent occupied slot even if writing or syncing fails.
    fd = os.open(_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            n = os.write(fd, data[offset:])
            if n <= 0:
                raise OSError("short delivery marker write")
            offset += n
        os.fsync(fd)
        info = os.fstat(fd)
        named = os.stat(_NAME, dir_fd=directory, follow_symlinks=False)
        if (info.st_dev, info.st_ino, info.st_nlink) != (named.st_dev, named.st_ino, 1):
            raise FenceUnavailable("delivery marker replaced")
        os.fsync(directory)
    finally:
        os.close(fd)
