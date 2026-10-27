"""Capture a deterministic identity for a pair of source Git checkouts."""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path


class SourceIdentityError(ValueError):
    """The requested source checkouts could not be observed reliably."""


def _git(root: Path, *args: str) -> bytes:
    # The explicit checkout paths are the source of truth. Inherited Git
    # variables can redirect -C to a different index, worktree, or object store.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(root), *args],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=30,
        )
        return result.stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SourceIdentityError(f"cannot inspect Git checkout ({args[0]}) at {root}") from exc


def _frame(hasher: "hashlib._Hash", label: bytes, value: bytes) -> None:
    hasher.update(len(label).to_bytes(8, "big"))
    hasher.update(label)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def _untracked(root: Path) -> list[tuple[bytes, bytes]]:
    raw = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    paths = sorted(path for path in raw.split(b"\0") if path)
    entries: list[tuple[bytes, bytes]] = []
    for relative in paths:
        try:
            path = root / os.fsdecode(relative)
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise SourceIdentityError(f"unsupported untracked filesystem entry: {path}")
            kind, payload = _read_entry(path, info)
            # Track executable state while deliberately excluding timestamps and ownership.
            mode = b"executable" if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 else b"ordinary"
            entries.append((relative, kind + b"\0" + mode + b"\0" + payload))
        except SourceIdentityError:
            raise
        except OSError as exc:
            raise SourceIdentityError(f"cannot read untracked source entry: {root / os.fsdecode(relative)}") from exc
    return entries


def _head(root: Path) -> str:
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip().decode("ascii", "strict")
    if len(head) not in (40, 64) or any(c not in "0123456789abcdef" for c in head):
        raise SourceIdentityError(f"Git returned an invalid full commit ID for {root}")
    return head


def _verify_checkout_root(root: Path) -> None:
    """Require root itself to be the worktree attached to its own .git marker."""
    marker = root / ".git"
    try:
        # rev-parse emits a newline terminator; a top-level worktree's prefix
        # is exactly that terminator, while a nested directory has more bytes.
        prefix = _git(root, "rev-parse", "--show-prefix")
        if prefix != b"\n":
            raise SourceIdentityError(f"source path is not the root of its Git checkout: {root}")
        marker_info = marker.lstat()
        actual_git_dir = Path(os.fsdecode(_git(root, "rev-parse", "--absolute-git-dir").removesuffix(b"\n")))
        actual_git_dir = actual_git_dir.resolve(strict=True)
        if stat.S_ISDIR(marker_info.st_mode):
            expected_git_dir = marker.resolve(strict=True)
        elif stat.S_ISREG(marker_info.st_mode):
            marker_data = marker.read_bytes()
            prefix_marker = b"gitdir: "
            if not marker_data.startswith(prefix_marker):
                raise SourceIdentityError(f"invalid Git worktree marker: {marker}")
            git_dir_text = marker_data[len(prefix_marker):].rstrip(b"\r\n")
            expected_git_dir = Path(os.fsdecode(git_dir_text))
            if not expected_git_dir.is_absolute():
                expected_git_dir = marker.parent / expected_git_dir
            expected_git_dir = expected_git_dir.resolve(strict=True)
        else:
            raise SourceIdentityError(f"source checkout has no usable .git marker: {root}")
    except SourceIdentityError:
        raise
    except (OSError, RuntimeError, UnicodeError, subprocess.SubprocessError) as exc:
        raise SourceIdentityError(f"cannot bind Git metadata to source checkout: {root}") from exc
    if actual_git_dir != expected_git_dir:
        raise SourceIdentityError(f"source path is not the root of its Git checkout: {root}")


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    """Check that a path was stable while its bytes or link target were read."""
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _read_entry(path: Path, info: os.stat_result) -> tuple[bytes, bytes]:
    """Read a regular file or symlink and reject changes during the read."""
    if stat.S_ISREG(info.st_mode):
        kind, payload = b"file", path.read_bytes()
    elif stat.S_ISLNK(info.st_mode):
        kind, payload = b"symlink", os.fsencode(os.readlink(path))
    else:
        raise SourceIdentityError(f"unsupported source filesystem entry: {path}")
    try:
        after = path.lstat()
    except OSError as exc:
        raise SourceIdentityError(f"source entry changed during identity capture: {path}") from exc
    if not _same_file_state(info, after):
        raise SourceIdentityError(f"source entry changed during identity capture: {path}")
    return kind, payload


def _tracked_inventory(root: Path) -> list[tuple[bytes, bytes]]:
    """Read current tracked filesystem entries directly, bypassing clean filters."""
    paths = sorted(path for path in _git(root, "ls-files", "-z").split(b"\0") if path)
    result: list[tuple[bytes, bytes]] = []
    for relative in paths:
        path = root / os.fsdecode(relative)
        try:
            info = path.lstat()
        except FileNotFoundError:
            result.append((relative, b"missing"))
            continue
        except OSError as exc:
            raise SourceIdentityError(f"cannot inspect tracked source entry: {path}") from exc
        try:
            if stat.S_ISREG(info.st_mode):
                kind, payload = _read_entry(path, info)
            elif stat.S_ISLNK(info.st_mode):
                kind, payload = _read_entry(path, info)
            elif stat.S_ISDIR(info.st_mode):
                # A tracked file can be replaced by a directory in the worktree;
                # Git reports its children separately as untracked entries.
                kind, payload = b"directory", b""
            else:
                raise SourceIdentityError(f"unsupported tracked filesystem entry: {path}")
        except SourceIdentityError:
            raise
        except OSError as exc:
            raise SourceIdentityError(f"cannot read tracked source entry: {path}") from exc
        mode = b"executable" if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 else b"ordinary"
        result.append((relative, kind + b"\0" + mode + b"\0" + payload))
    return result


def _capture_repo(root_arg: Path) -> tuple[str, bytes, bool, tuple]:
    root = Path(root_arg)
    if not root.is_dir():
        raise SourceIdentityError(f"source checkout is not a directory: {root}")
    _verify_checkout_root(root)
    head = _head(root)
    # Gitlinks have independent worktrees and need recursive capture. Fail closed until
    # that representation is supported rather than treating their pointer as clean.
    index = _git(root, "ls-files", "--stage", "-z")
    if any(record.startswith(b"160000 ") for record in index.split(b"\0") if record):
        raise SourceIdentityError(f"submodules are not supported for source identity: {root}")
    # ls-files -v lowercases assume-unchanged tags and uses S for skip-worktree.
    flags = _git(root, "ls-files", "-v", "-z")
    if any((record[:1].islower() or record.startswith(b"S ")) for record in flags.split(b"\0") if record):
        raise SourceIdentityError(f"assume-unchanged/skip-worktree entries are unsupported: {root}")
    expected = _git(root, "ls-tree", "-rz", "--full-tree", head)
    expected_rows: list[tuple[bytes, bytes, bytes]] = []
    for row in expected.split(b"\0"):
        if not row:
            continue
        metadata, relative = row.split(b"\t", 1)
        mode, kind, oid = metadata.split(b" ", 2)
        if mode == b"160000" or kind != b"blob":
            raise SourceIdentityError(f"submodules or unsupported tree entries are not supported: {root}")
        expected_rows.append((relative, mode, oid))
    expected_rows.sort(key=lambda item: item[0])
    try:
        unknown = sorted(_untracked(root), key=lambda item: item[0])
        tracked = _tracked_inventory(root)
        after_index = _git(root, "ls-files", "--stage", "-z")
        after_tracked = _tracked_inventory(root)
        after_unknown = sorted(_untracked(root), key=lambda item: item[0])
        after_head = _head(root)
    except UnicodeError as exc:
        raise SourceIdentityError(f"invalid Git identity data at {root}") from exc
    if (head, index, tracked, unknown) != (after_head, after_index, after_tracked, after_unknown):
        raise SourceIdentityError(f"source checkout changed during identity capture: {root}")
    index_rows = []
    for record in index.split(b"\0"):
        if not record:
            continue
        metadata, relative = record.split(b"\t", 1)
        mode, oid, stage = metadata.split(b" ", 2)
        index_rows.append((relative, mode, oid, stage))
    index_rows.sort()
    expected_index = [(relative, mode, oid, b"0") for relative, mode, oid in expected_rows]
    # Derive dirty state from logical index rows and raw filesystem entries.
    # Git status output can vary with presentation and diff configuration.
    dirty = bool(unknown or index_rows != expected_index)
    object_format = _git(root, "rev-parse", "--show-object-format").strip().decode("ascii")
    if object_format not in ("sha1", "sha256"):
        raise SourceIdentityError(f"unsupported Git object format at {root}: {object_format}")
    tracked_by_path = dict(tracked)
    if set(tracked_by_path) != {relative for relative, _, _ in expected_rows}:
        dirty = True
    else:
        for relative, mode, oid in expected_rows:
            row = tracked_by_path[relative]
            if row == b"missing":
                dirty = True
                break
            actual_kind, actual_mode, payload = row.split(b"\0", 2)
            expected_kind = b"symlink" if mode == b"120000" else b"file"
            expected_mode = b"executable" if mode == b"100755" else b"ordinary"
            blob_header = b"blob " + str(len(payload)).encode("ascii") + b"\0"
            actual_oid = hashlib.new(object_format, blob_header + payload).hexdigest().encode("ascii")
            if actual_kind != expected_kind or actual_mode != expected_mode or actual_oid != oid:
                dirty = True
                break
    digest = hashlib.sha256()
    for relative, mode, oid, stage in index_rows:
        _frame(digest, b"index-row", b"\0".join((relative, mode, oid, stage)))
    for relative, payload in tracked:
        _frame(digest, b"tracked-path", relative)
        _frame(digest, b"tracked-entry", payload)
    for relative, payload in unknown:
        _frame(digest, b"untracked-path", relative)
        _frame(digest, b"untracked-entry", payload)
    signature = (head, index_rows, tuple(tracked), tuple(unknown))
    return head, digest.digest(), dirty, signature


def capture_source_identity(runtime_checkout: Path, agent_checkout: Path) -> dict:
    """Return a content-sensitive, deterministic identity for both source trees.

    Dirty trees are valid inputs. Ignored files and filesystem timestamps do not
    contribute to the digest. Tracked bytes are compared with the HEAD blob bytes,
    so checkout transformations such as autocrlf or smudge filters count as dirty
    when they differ from the committed raw blob. Git inspection failures and
    unsupported submodules raise :class:`SourceIdentityError`.
    """
    try:
        runtime_head, runtime_state, runtime_dirty, runtime_signature = _capture_repo(Path(runtime_checkout))
        agent_head, agent_state, agent_dirty, agent_signature = _capture_repo(Path(agent_checkout))
        # Re-observe the whole pair so a head/index transition between the first
        # checkout and the second, or during pair capture, cannot slip through.
        runtime_again = _capture_repo(Path(runtime_checkout))
        agent_again = _capture_repo(Path(agent_checkout))
        if runtime_signature != runtime_again[3] or agent_signature != agent_again[3]:
            raise SourceIdentityError("source checkouts changed during identity capture")
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, SourceIdentityError):
            raise
        raise SourceIdentityError("invalid source checkout state") from exc
    digest = hashlib.sha256()
    _frame(digest, b"runtime-head", runtime_head.encode("ascii"))
    _frame(digest, b"runtime-state", runtime_state)
    _frame(digest, b"agent-head", agent_head.encode("ascii"))
    _frame(digest, b"agent-state", agent_state)
    return {
        "release": 0,
        "managed_by": "source",
        "runtime_head": runtime_head,
        "agent_head": agent_head,
        "dirty": runtime_dirty or agent_dirty,
        "dirty_hash": digest.hexdigest(),
    }
