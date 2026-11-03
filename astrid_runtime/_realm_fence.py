"""Provisional POSIX realm lock custody.

This primitive does not establish lifecycle admission or authorize a writer.
A caller must also establish the native and transaction evidence required by
R18.  In particular, an open descriptor or a free lock is not such evidence.
"""

import os
import stat
import sys
from pathlib import Path

from runtime_protocol import platform


class FenceUnavailable(RuntimeError):
    """The original realm objects could not be pinned and locked safely."""


def _open_directory(path):
    # Walk every component with no-follow, including the root's ancestors.
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise FenceUnavailable("realm path must be absolute and normalized")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _identity(info):
    return info.st_dev, info.st_ino


class ProvisionalRootPair:
    """Pin two existing roots in lock order, without authorizing a restore.

    This is an initial acquisition primitive: it must not be nested inside an
    already-held realm fence. Both roots are retained until close. Publication,
    lineage authorization, and transfer admission require separate authority.
    """

    def __init__(self, original, replacement):
        if sys.platform not in ("linux", "darwin"):
            raise FenceUnavailable("unsupported transfer platform")
        self._roots = []
        self._closed = False
        self._poisoned = False
        try:
            for path in (Path(original), Path(replacement)):
                fd = _open_directory(path)
                self._roots.append({"path": path, "directory": fd, "owner": None})
                info = os.fstat(fd)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                    raise FenceUnavailable("realm directory identity is invalid")
            self._roots.sort(key=lambda item: _identity(os.fstat(item["directory"])))
            if _identity(os.fstat(self._roots[0]["directory"])) == _identity(os.fstat(self._roots[1]["directory"])):
                raise FenceUnavailable("realm roots are not distinct")
            # Never wait while holding one root: acquire all directory locks
            # in stable file-ID order before opening and locking either owner.
            for item in self._roots:
                platform.lock_file(item["directory"], blocking=False)
            for item in self._roots:
                item["owner"] = os.open("owner.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=item["directory"])
                owner = os.fstat(item["owner"])
                if (not stat.S_ISREG(owner.st_mode) or owner.st_uid != os.geteuid()
                        or owner.st_nlink != 1 or owner.st_mode & 0o077):
                    raise FenceUnavailable("owner lock identity is invalid")
                platform.lock_file(item["owner"], blocking=False)
            self.revalidate()
        except BaseException as exc:
            self.close()
            if isinstance(exc, OSError):
                raise FenceUnavailable("realm pair custody unavailable") from exc
            raise

    def revalidate(self):
        if self._closed or self._poisoned or len(self._roots) != 2:
            raise FenceUnavailable("realm pair fence is closed")
        try:
            for item in self._roots:
                current = _open_directory(item["path"])
                try:
                    directory = os.fstat(item["directory"])
                    owner = os.fstat(item["owner"])
                    named_owner = os.stat("owner.lock", dir_fd=item["directory"], follow_symlinks=False)
                    if (_identity(os.fstat(current)) != _identity(directory)
                            or directory.st_uid != os.geteuid()
                            or _identity(owner) != _identity(named_owner)
                            or not stat.S_ISREG(named_owner.st_mode)
                            or owner.st_nlink != 1 or owner.st_uid != os.geteuid()
                            or owner.st_mode & 0o077):
                        raise FenceUnavailable("realm pair binding changed")
                finally:
                    os.close(current)
        except (OSError, FenceUnavailable) as exc:
            self._poisoned = True
            raise FenceUnavailable("realm pair binding unavailable") from exc

    def close(self):
        self._closed = True
        for item in reversed(self._roots):
            for name in ("owner", "directory"):
                fd, item[name] = item[name], None
                if fd is not None:
                    os.close(fd)
        self._roots = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class ProvisionalRealmFence:
    """Own two locked descriptions until close, without ever issuing LOCK_UN.

    This object is intentionally not a transfer session: no admission, IPC,
    descriptor delegation, durability, or recovery authority is provided.
    """

    def __init__(self, root):
        if sys.platform not in ("linux", "darwin"):
            raise FenceUnavailable("unsupported transfer platform")
        self.root = Path(root)
        self._directory_fd = None
        self._owner_fd = None
        try:
            self._directory_fd = _open_directory(self.root)
            directory = os.fstat(self._directory_fd)
            if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid():
                raise FenceUnavailable("realm directory identity is invalid")
            platform.lock_file(self._directory_fd, blocking=False)
            self._owner_fd = os.open(
                "owner.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._directory_fd,
            )
            owner = os.fstat(self._owner_fd)
            if (not stat.S_ISREG(owner.st_mode) or owner.st_uid != os.geteuid()
                    or owner.st_nlink != 1 or owner.st_mode & 0o077):
                raise FenceUnavailable("owner lock identity is invalid")
            platform.lock_file(self._owner_fd, blocking=False)
            self.revalidate()
        except BaseException as exc:
            self.close()
            if isinstance(exc, OSError):
                raise FenceUnavailable("realm lock custody unavailable") from exc
            raise

    def revalidate(self):
        """Refuse if the pinned objects no longer match their path names."""
        if self._directory_fd is None or self._owner_fd is None:
            raise FenceUnavailable("realm fence is closed")
        try:
            current_fd = _open_directory(self.root)
            try:
                current = os.fstat(current_fd)
            finally:
                os.close(current_fd)
            directory = os.fstat(self._directory_fd)
            owner = os.fstat(self._owner_fd)
            named_owner = os.stat("owner.lock", dir_fd=self._directory_fd, follow_symlinks=False)
            if (_identity(current) != _identity(directory)
                    or _identity(owner) != _identity(named_owner)
                    or not stat.S_ISREG(named_owner.st_mode)
                    or owner.st_nlink != 1 or owner.st_uid != os.geteuid()
                    or owner.st_mode & 0o077):
                raise FenceUnavailable("realm lock binding changed")
        except OSError as exc:
            raise FenceUnavailable("realm lock binding unavailable") from exc

    def close(self):
        # A duplicate shares the flock with its source. LOCK_UN here would
        # silently unlock all aliases, so disposal must always be close-only.
        for name in ("_owner_fd", "_directory_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                setattr(self, name, None)
                os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
