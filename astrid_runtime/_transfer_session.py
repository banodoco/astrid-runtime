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


class ProvisionalTransferSession:
    """Hold the existing bootstrap lock and original realm locks together.

Only existing objects are opened; acquisition is nonblocking. A failed
    revalidation poisons the session but retains its locks until close. No
    alias is exported and closing this provisional session cannot authorize a
    release of any future admitted or delegated writer.
    """

    def __init__(self, paths, realm_root):
        self._support = Path(paths.runtime_support)
        self._bootstrap_fd = None
        self._support_fd = None
        self._realm = None
        self._poisoned = False
        if sys.platform not in ("linux", "darwin"):
            raise FenceUnavailable("unsupported transfer platform")
        if Path(paths.bootstrap_lock_path) != self._support / "bootstrap.lock":
            raise FenceUnavailable("invalid bootstrap lock path")
        try:
            self._support_fd = _open_directory(self._support)
            support = os.fstat(self._support_fd)
            if not stat.S_ISDIR(support.st_mode) or support.st_uid != os.geteuid() or support.st_mode & 0o077:
                raise FenceUnavailable("runtime support directory is not private")
            self._bootstrap_fd = os.open(
                "bootstrap.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._support_fd,
            )
            self._check_bootstrap()
            platform.lock_file(self._bootstrap_fd, blocking=False)
            self._check_bootstrap()
            self._realm = ProvisionalRealmFence(realm_root)
            self.revalidate()
        except BaseException as exc:
            self.close()
            if isinstance(exc, OSError):
                raise FenceUnavailable("provisional transfer custody unavailable") from exc
            raise

    def _check_bootstrap(self):
        current_fd = _open_directory(self._support)
        try:
            current = os.fstat(current_fd)
        finally:
            os.close(current_fd)
        support = os.fstat(self._support_fd)
        held = os.fstat(self._bootstrap_fd)
        named = os.stat("bootstrap.lock", dir_fd=self._support_fd, follow_symlinks=False)
        if (_identity(current) != _identity(support) or support.st_uid != os.geteuid()
                or support.st_mode & 0o077 or not stat.S_ISREG(held.st_mode)
                or _identity(held) != _identity(named) or held.st_uid != os.geteuid()
                or held.st_nlink != 1 or held.st_mode & 0o077):
            raise FenceUnavailable("bootstrap lock binding changed")

    def revalidate(self):
        if self._poisoned or self._realm is None or self._bootstrap_fd is None:
            raise FenceUnavailable("provisional transfer session unavailable")
        try:
            self._check_bootstrap()
            self._realm.revalidate()
        except (OSError, FenceUnavailable) as exc:
            self._poisoned = True
            raise FenceUnavailable("provisional transfer binding changed") from exc

    def close(self):
        try:
            if self._realm is not None:
                realm, self._realm = self._realm, None
                realm.close()
        finally:
            try:
                if self._bootstrap_fd is not None:
                    fd, self._bootstrap_fd = self._bootstrap_fd, None
                    os.close(fd)
            finally:
                if self._support_fd is not None:
                    fd, self._support_fd = self._support_fd, None
                    os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
