"""Process-local provisional transfer custody, not lifecycle admission.

This deliberately provides no writer, IPC, stopped-owner, or recovery API.
The caller must hold installation authority before entering this primitive.
It is not the R18 TransferSession facade and must not be used to launch a
Runtime or to infer that an old owner or its descendants are absent.
"""

import os
import stat
import sys
from pathlib import Path

from runtime_protocol import platform

from ._realm_fence import FenceUnavailable, ProvisionalRealmFence, _identity, _open_directory


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
