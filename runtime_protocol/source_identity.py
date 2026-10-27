"""Capture a deterministic identity for a pair of source Git checkouts."""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path


class SourceIdentityError(ValueError):
    """The requested source checkouts could not be observed reliably."""


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    # The explicit checkout paths are the source of truth. Inherited Git
    # variables can redirect -C to a different index, worktree, or object store.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(root), *args],
            env=env,
            stdin=subprocess.DEVNULL if input is None else None,
            input=input,
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


def _untracked(root: Path) -> list[bytes]:
    return [path for path in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0") if path]


def _head(root: Path) -> str:
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip().decode("ascii", "strict")
    if len(head) not in (40, 64) or any(c not in "0123456789abcdef" for c in head):
        raise SourceIdentityError(f"Git returned an invalid full commit ID for {root}")
    return head


def validate_checkout_root(root: Path) -> Path:
    """Admit an explicit absolute worktree root without capturing its contents."""
    root = Path(root)
    if not root.is_absolute():
        raise SourceIdentityError(f"source checkout path must be absolute: {root}")
    if not root.is_dir():
        raise SourceIdentityError(f"source checkout is not a directory: {root}")
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise SourceIdentityError(f"cannot resolve source checkout: {root}") from exc
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
    return root


def _blob_ids(root: Path, paths: list[bytes]) -> list[bytes]:
    """Hash regular files in bounded argv batches, without filters or object writes."""
    result: list[bytes] = []
    batch: list[str] = []
    size = 0
    for relative in paths:
        if batch and (len(batch) == 64 or size + len(relative) > 8192):
            result.extend(_git(root, "hash-object", "--no-filters", "--", *batch).splitlines())
            batch, size = [], 0
        batch.append("./" + os.fsdecode(relative))
        size += len(relative) + 3
    if batch:
        result.extend(_git(root, "hash-object", "--no-filters", "--", *batch).splitlines())
    if len(result) != len(paths):
        raise SourceIdentityError(f"Git returned incomplete raw blob hashes at {root}")
    return result


def _worktree_rows(root: Path, paths: list[bytes], *, allow_directories: bool) -> list[tuple[bytes, bytes, bytes]]:
    """Frame path/type/mode metadata around Git's raw blob hashes.

    One metadata observation per path is enough here: capture_source_identity
    compares two complete observations, including hashes, of both checkouts.
    Symlinks hash their link text, never the referent (which may not exist).
    Only tracked replacements can be directories: Git may enumerate an entire
    untracked nested checkout as one directory, hiding its source files.
    """
    rows = []
    regular = []
    for relative in sorted(set(paths)):
        path = root / os.fsdecode(relative)
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            rows.append((relative, b"missing", b""))
            continue
        if stat.S_ISREG(mode):
            rows.append((relative, b"100755" if mode & 0o111 else b"100644", b""))
            regular.append(relative)
        elif stat.S_ISLNK(mode):
            oid = _git(root, "hash-object", "--no-filters", "--stdin", input=os.fsencode(os.readlink(path))).strip()
            rows.append((relative, b"120000", oid))
        elif stat.S_ISDIR(mode):
            if not allow_directories:
                raise SourceIdentityError(f"untracked source directory is unsupported: {path}")
            rows.append((relative, b"040000", b""))
        else:
            raise SourceIdentityError(f"unsupported source filesystem entry: {path}")
    hashes = dict(zip(regular, _blob_ids(root, regular)))
    return [(path, mode, hashes.get(path, oid)) for path, mode, oid in rows]


def _capture_repo(root_arg: Path) -> tuple[str, bytes, bool, tuple]:
    root = validate_checkout_root(root_arg)
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
    unknown = _worktree_rows(root, _untracked(root), allow_directories=False)
    tracked_paths = [row.split(b"\t", 1)[1] for row in index.split(b"\0") if row]
    tracked = _worktree_rows(root, tracked_paths, allow_directories=True)
    for _, mode, oid in tracked + unknown:
        if mode in (b"100644", b"100755", b"120000") and (
            len(oid) != len(head) or any(c not in b"0123456789abcdef" for c in oid)
        ):
            raise SourceIdentityError(f"Git returned an invalid raw blob hash at {root}")
    index_rows = []
    for record in index.split(b"\0"):
        if not record:
            continue
        metadata, relative = record.split(b"\t", 1)
        mode, oid, stage = metadata.split(b" ", 2)
        index_rows.append((relative, mode, oid, stage))
    index_rows.sort()
    expected_index = [(relative, mode, oid, b"0") for relative, mode, oid in expected_rows]
    dirty = bool(unknown or index_rows != expected_index or tracked != expected_rows)
    digest = hashlib.sha256()
    for relative, mode, oid, stage in index_rows:
        _frame(digest, b"index-row", b"\0".join((relative, mode, oid, stage)))
    for label, rows in ((b"tracked", tracked), (b"untracked", unknown)):
        for relative, mode, oid in rows:
            _frame(digest, label + b"-path", relative)
            _frame(digest, label + b"-entry", b"\0".join((mode, oid)))
    signature = (head, index_rows, flags, tuple(tracked), tuple(unknown))
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
