"""Private, process-local provisional lifecycle transfer facade.

Installation authority is a caller precondition. This module does not establish
admission, native provenance, a writer, a durable ledger, or recovery authority.
"""

import hashlib
import json
import os
import re
import stat
import sys
import threading
from pathlib import Path

from ._realm_fence import FenceUnavailable, _identity, _open_directory
from ._transfer_session import ProvisionalTransferSession


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_SOURCE = 64 * 1024 * 1024


def _closed(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise FenceUnavailable("malformed closed binding")
    return value


def _text(value):
    if type(value) is not str or not value or len(value) > 4096 or "\x00" in value:
        raise FenceUnavailable("malformed binding value")
    return value


def _digest(value, pattern=_HEX):
    if type(value) is not str or not pattern.fullmatch(value):
        raise FenceUnavailable("malformed binding digest")
    return value


def _file_id(value):
    if (type(value) is not list or len(value) != 2
            or any(type(part) is not int or part < 0 for part in value)):
        raise FenceUnavailable("malformed file identity")
    return tuple(value)


def _path(value):
    _text(value)
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise FenceUnavailable("binding path must be absolute and normalized")
    return path


def _object(value):
    _closed(value, ("path", "file_id"))
    return (_path(value["path"]), _file_id(value["file_id"]))


def _source(value):
    _closed(value, ("repository_sha", "version_document_digest", "profile_digest",
                    "manifest_digest", "module"))
    _digest(value["repository_sha"], _SHA)
    for key in ("version_document_digest", "profile_digest", "manifest_digest"):
        _digest(value[key])
    module = _closed(value["module"], ("path", "file_id", "sha256"))
    return (_path(module["path"]), _file_id(module["file_id"]), _digest(module["sha256"]))


def _check_directory(bound):
    path, expected = bound
    fd = _open_directory(path)
    try:
        if _identity(os.fstat(fd)) != expected:
            raise FenceUnavailable("bound directory identity changed")
    finally:
        os.close(fd)


def _check_source(source):
    path, expected, digest = source
    parent = _open_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or _identity(before) != expected
                or _identity(named) != expected or before.st_size > _MAX_SOURCE):
            raise FenceUnavailable("bound source identity changed")
        hasher = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > _MAX_SOURCE:
                raise FenceUnavailable("bound source too large")
            hasher.update(block)
        after = os.fstat(fd)
        named_after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        current_parent = _open_directory(path.parent)
        try:
            parent_unchanged = _identity(os.fstat(current_parent)) == _identity(os.fstat(parent))
        finally:
            os.close(current_parent)
        if (not parent_unchanged or hasher.hexdigest() != digest or _identity(named_after) != expected
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise FenceUnavailable("bound source content changed")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _parse_binding(binding):
    _closed(binding, ("version", "operation_id", "attempt_id", "transfer_id", "generation",
                      "controller", "installation", "program", "data", "support", "realm",
                      "old_source", "candidate_source", "prior_selection_digest",
                      "journal_digest", "manager", "publications", "origin", "prior_state",
                      "root_lineage", "role"))
    if binding["version"] != "astrid.lifecycle-transfer/v1":
        raise FenceUnavailable("unsupported binding version")
    for key in ("operation_id", "attempt_id", "transfer_id", "generation"):
        _text(binding[key])
    controller = _closed(binding["controller"], ("pid", "uid", "birth"))
    if any(type(controller[k]) is not int or controller[k] < 0 for k in ("pid", "uid")):
        raise FenceUnavailable("malformed controller identity")
    _text(controller["birth"])
    directories = tuple(_object(binding[k]) for k in ("installation", "program", "data", "support"))
    realm = _closed(binding["realm"], ("uuid", "root", "owner_file_id"))
    _text(realm["uuid"])
    root = _object(realm["root"])
    owner_id = _file_id(realm["owner_file_id"])
    sources = (_source(binding["old_source"]), _source(binding["candidate_source"]))
    for key in ("prior_selection_digest", "journal_digest"):
        _digest(binding[key])
    manager = _closed(binding["manager"], ("kind", "namespace", "target", "definition_digest"))
    for key in ("kind", "namespace", "target"):
        _text(manager[key])
    _digest(manager["definition_digest"])
    publications = _closed(binding["publications"], ("instance", "discovery", "incarnation"))
    for name in ("instance", "discovery"):
        item = _closed(publications[name], ("status", "digest"))
        if item["status"] not in ("absent", "present") or type(item["status"]) is not str:
            raise FenceUnavailable("malformed publication status")
        if item["status"] == "absent":
            if item["digest"] is not None:
                raise FenceUnavailable("malformed publication digest")
        else:
            _digest(item["digest"])
    if publications["incarnation"] is not None:
        _text(publications["incarnation"])
    if type(binding["origin"]) is not str or binding["origin"] not in ("stopped-r0", "live-r1"):
        raise FenceUnavailable("malformed origin")
    state = _closed(binding["prior_state"], ("running", "loaded", "enabled"))
    if any(type(state[k]) is not bool for k in state):
        raise FenceUnavailable("malformed prior state")
    lineage = binding["root_lineage"]
    if type(lineage) is not list or not lineage or len(lineage) > 32:
        raise FenceUnavailable("malformed root lineage")
    for item in lineage:
        _file_id(item)
    if type(binding["role"]) is not str or binding["role"] not in ("offline-backup", "migration", "candidate", "rollback-r1"):
        raise FenceUnavailable("malformed role")
    return directories, root, owner_id, sources


class ProvisionalFence:
    """An opaque live-session reference; it is not admission or a receipt."""

    def __init__(self, session):
        self._session = session

    def revalidate(self):
        self._session._revalidate()


class TransferSession:
    """Own the R2 fence until close; no descriptor aliases are exported."""

    def __init__(self, paths, binding):
        if sys.platform not in ("linux", "darwin"):
            raise FenceUnavailable("unsupported transfer platform")
        try:
            self._directories, self._root, self._owner_id, self._sources = _parse_binding(binding)
            # Keep an immutable commitment to every closed field, including fields
            # this provisional boundary cannot independently verify yet.
            encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            self._binding_digest = hashlib.sha256(encoded).hexdigest()
            self._support = _path(str(paths.runtime_support))
            self._bootstrap = _path(str(paths.bootstrap_lock_path))
            if self._directories[3][0] != self._support or self._bootstrap != self._support / "bootstrap.lock":
                raise FenceUnavailable("support binding mismatch")
        except (AttributeError, TypeError, ValueError) as exc:
            raise FenceUnavailable("malformed transfer input") from exc
        self._pid = os.getpid()
        self._mutex = threading.RLock()
        self._custody = None
        self._fence = None
        self._closed = False
        self._poisoned = False

    def _check(self):
        if self._closed or self._poisoned or os.getpid() != self._pid:
            raise FenceUnavailable("transfer session unavailable")

    def _validate_binding(self):
        for directory in (*self._directories, self._root):
            _check_directory(directory)
        for source in self._sources:
            _check_source(source)
        if self._custody is not None:
            self._custody.revalidate()
            realm = self._custody._realm
            if (_identity(os.fstat(realm._directory_fd)) != self._root[1]
                    or _identity(os.fstat(realm._owner_fd)) != self._owner_id
                    or _identity(os.fstat(self._custody._support_fd)) != self._directories[3][1]):
                raise FenceUnavailable("held identity differs from binding")

    def _revalidate_locked(self):
        self._check()
        try:
            self._validate_binding()
        except (OSError, FenceUnavailable) as exc:
            self._poisoned = True
            raise FenceUnavailable("transfer binding changed or unavailable") from exc

    def _revalidate(self):
        with self._mutex:
            self._check()
            if self._custody is None:
                raise FenceUnavailable("provisional fence not acquired")
            self._revalidate_locked()

    def pin_and_acquire_original(self):
        with self._mutex:
            self._check()
            if self._custody is not None:
                self._revalidate_locked()
                return self._fence
            self._revalidate_locked()
            try:
                self._custody = ProvisionalTransferSession(
                    _Paths(self._support, self._bootstrap), self._root[0])
                self._revalidate_locked()
            except BaseException:
                if self._custody is not None:
                    self._custody.close()
                    self._custody = None
                self._poisoned = True
                raise
            self._fence = ProvisionalFence(self)
            return self._fence

    def close(self):
        with self._mutex:
            if os.getpid() != self._pid:
                raise FenceUnavailable("transfer session belongs to another process")
            self._closed = True
            if self._custody is not None:
                custody, self._custody = self._custody, None
                custody.close()

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *exc):
        self.close()


class _Paths:
    def __init__(self, support, bootstrap):
        self.runtime_support = support
        self.bootstrap_lock_path = bootstrap


def begin_transfer(paths, *, binding):
    """Create a session without acquiring realm write permission."""
    return TransferSession(paths, binding)
