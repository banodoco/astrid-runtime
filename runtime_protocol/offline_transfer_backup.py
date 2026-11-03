"""Detached database snapshot under an already-held provisional realm fence.

This is a database-only building block, not a Runtime backup/restore archive or
lifecycle admission. The caller must keep the genuine fence alive and ensure
all non-cooperating writers and inherited aliases are absent for the call.
Only Linux is supported: source reads require O_NOATIME and no-follow dirfds.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import os
import re
from pathlib import Path
import secrets
import shutil
import sqlite3
import stat
import sys

from astrid_runtime._realm_fence import ProvisionalRealmFence, _open_directory
from .backup import _publish_new_directory
from .errors import ConflictError, ValidationError
from .v33_manifest import canonical_manifest, legacy_manifest

_LOCK = re.compile(r"^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+\S+\s+([0-9a-fA-F]+):([0-9a-fA-F]+):(\d+)\s+0\s+EOF$", re.MULTILINE)
_COMPONENTS = ("realm.sqlite3", "realm.sqlite3-wal", "realm.sqlite3-shm", "realm.sqlite3-journal")


def _revalidate(fence):
    # Linux fdinfo reports locks on this open file description, unlike a
    # contended probe on another descriptor. A lost or unreadable lock fails.
    ProvisionalRealmFence.revalidate(fence)
    for fd in (fence._directory_fd, fence._owner_fd):
        info = os.fstat(fd)
        try:
            with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
                matches = _LOCK.findall(stream.read())
        except (OSError, UnicodeError) as exc:
            raise ConflictError("cannot observe held realm lock") from exc
        identity = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        if not any((int(major, 16), int(minor, 16), int(inode)) == identity
                   for major, minor, inode in matches):
            raise ConflictError("realm lock authority is not held")


def _state(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source_state(fd):
    result = {}
    for name in _COMPONENTS:
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            result[name] = None
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ConflictError("invalid SQLite component: " + name)
        result[name] = _state(info)
    if result[_COMPONENTS[0]] is None:
        raise ConflictError("missing realm database")
    if result[_COMPONENTS[1]] is not None and result[_COMPONENTS[3]] is not None:
        raise ConflictError("ambiguous SQLite journal state")
    return result


def _outside_source(parent_fd, source_fd):
    source = os.fstat(source_fd)
    cursor = os.dup(parent_fd)
    try:
        while True:
            current = os.fstat(cursor)
            if (current.st_dev, current.st_ino) == (source.st_dev, source.st_ino):
                raise ConflictError("snapshot destination is inside the source realm")
            next_fd = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=cursor)
            parent = os.fstat(next_fd)
            if (current.st_dev, current.st_ino) == (parent.st_dev, parent.st_ino):
                os.close(next_fd)
                break
            os.close(cursor)
            cursor = next_fd
    finally:
        os.close(cursor)


def _copy_component(source_fd, name, expected, stage_fd):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME, dir_fd=source_fd)
    try:
        if _state(os.fstat(fd)) != expected:
            raise ConflictError("SQLite component changed before copy")
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=stage_fd)
        with os.fdopen(os.dup(fd), "rb") as src, os.fdopen(out, "wb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        if _state(os.fstat(fd)) != expected:
            raise ConflictError("SQLite component changed during copy")
    finally:
        os.close(fd)


def _inspect(connection, expected_realm_id):
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    inspect = canonical_manifest if "runtime_schema" in tables else legacy_manifest
    manifest = inspect(connection, expected_realm_id=expected_realm_id)
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ConflictError("snapshot SQLite integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ConflictError("snapshot foreign key check failed")
    return manifest


def create_offline_snapshot(fence: ProvisionalRealmFence, destination: str | Path, *, expected_realm_id: str, expected_schema_kind: str) -> dict:
    """Publish a verified standalone SQLite snapshot; leave fence and source untouched.

    Requires a live, locally acquired ProvisionalRealmFence, exclusive caller
    ownership of that object, an independently established stopped-writer
    boundary, and the expected realm identity. Does not authenticate a helper,
    verify CAS, or assert backup/restore compatibility. Destination's existing
    parent must be private and outside the source root. The final directory must
    not exist. Any failure leaves a concurrently published destination intact.
    """
    if sys.platform != "linux" or not hasattr(os, "O_NOATIME"):
        raise ConflictError("safe source reads unavailable on this platform")
    if type(fence) is not ProvisionalRealmFence:
        raise ConflictError("a locally acquired realm fence is required")
    if not isinstance(expected_realm_id, str) or not expected_realm_id.strip():
        raise ValidationError("expected realm identity is required")
    if not isinstance(expected_schema_kind, str) or not expected_schema_kind.strip():
        raise ValidationError("expected predecessor schema kind is required")
    destination = Path(destination)
    if not destination.is_absolute() or ".." in destination.parts or destination.name in ("", ".", ".."):
        raise ValidationError("destination must be an absolute normalized path")
    _revalidate(fence)
    source_fd = fence._directory_fd
    root_info = os.fstat(source_fd)
    if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077:
        raise ConflictError("source root must be owner-private")
    parent_fd = _open_directory(destination.parent)
    stage = None
    stage_identity = None
    published = False
    try:
        parent = os.fstat(parent_fd)
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise ConflictError("snapshot parent must be owner-private")
        _outside_source(parent_fd, source_fd)
        before = _source_state(source_fd)
        stage = ".offline-snapshot-" + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=parent_fd)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            stage_stat = os.fstat(stage_fd)
            stage_identity = (stage_stat.st_dev, stage_stat.st_ino)
            os.mkdir("observation", 0o700, dir_fd=stage_fd)
            obs_fd = os.open("observation", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage_fd)
            try:
                for name, identity in before.items():
                    if identity is not None:
                        _copy_component(source_fd, name, identity, obs_fd)
                if _source_state(source_fd) != before:
                    raise ConflictError("SQLite components changed during snapshot")
                _revalidate(fence)
                # SQLite may recover or create sidecars only in this private copy.
                observation = f"/proc/self/fd/{obs_fd}/realm.sqlite3"
                output = f"/proc/self/fd/{stage_fd}/realm.sqlite3"
                output_fd = os.open("realm.sqlite3", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=stage_fd)
                os.close(output_fd)
                with closing(sqlite3.connect(observation)) as source, closing(sqlite3.connect(output)) as target:
                    manifest = _inspect(source, expected_realm_id)
                    if manifest["kind"] != expected_schema_kind:
                        raise ValidationError("predecessor schema mismatch")
                    source.backup(target)
                    target.commit()
                    if target.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                        raise ConflictError("cannot finalize standalone SQLite snapshot")
                with closing(sqlite3.connect(output)) as check:
                    verified = _inspect(check, expected_realm_id)
                    if verified != manifest:
                        raise ConflictError("snapshot schema verification mismatch")
                db_fd = os.open("realm.sqlite3", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage_fd)
                try:
                    digest = hashlib.sha256()
                    while chunk := os.read(db_fd, 1024 * 1024):
                        digest.update(chunk)
                    os.fsync(db_fd)
                finally:
                    os.close(db_fd)
            finally:
                os.close(obs_fd)
            shutil.rmtree(f"/proc/self/fd/{stage_fd}/observation")
            os.fsync(stage_fd)
            if _source_state(source_fd) != before:
                raise ConflictError("SQLite components changed before publication")
            _revalidate(fence)
            # Reopen the named parent and compare it with the pinned one.
            named_parent = _open_directory(destination.parent)
            try:
                if (os.fstat(named_parent).st_dev, os.fstat(named_parent).st_ino) != (parent.st_dev, parent.st_ino):
                    raise ConflictError("snapshot parent changed")
            finally:
                os.close(named_parent)
            named_stage = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(named_stage.st_mode) or (named_stage.st_dev, named_stage.st_ino) != stage_identity:
                raise ConflictError("snapshot staging directory changed")
            _publish_new_directory(parent_fd, stage, destination.name)
            published = True
            os.fsync(parent_fd)
            return {"schema": verified, "sha256": digest.hexdigest(), "database": "realm.sqlite3"}
        finally:
            os.close(stage_fd)
    finally:
        if stage_identity is not None and not published:
            # Preserve a replaced staging name and never remove a destination.
            try:
                named = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISDIR(named.st_mode) and (named.st_dev, named.st_ino) == stage_identity:
                    shutil.rmtree(stage, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
