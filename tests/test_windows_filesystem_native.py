"""Native qualification; CI provisions 8.3 creation and a local SMB share."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import uuid

import pytest

from runtime_protocol import dirfd, platform
from tests.lanes import requires_windows_dirfd_adapter


pytestmark = [requires_windows_dirfd_adapter, pytest.mark.integration]


def _identity(fd):
    value = dirfd.filesystem.fstat(fd)
    return value.st_dev, value.st_ino


def _short_path(path):
    from ctypes import wintypes

    get_short_path = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW
    get_short_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_short_path.restype = wintypes.DWORD
    size = get_short_path(str(path), None, 0)
    if not size:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(size)
    count = get_short_path(str(path), buffer, size)
    if not count or count >= size:
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buffer.value)


def test_native_replacement_preserves_open_reader_and_pinned_parent(tmp_path):
    fs = dirfd.filesystem
    parent = dirfd.open_directory_chain(tmp_path)
    reader = -1
    try:
        dirfd.write_bytes_at(parent, "published.bin", b"old")
        reader = fs.open("published.bin", os.O_RDONLY | fs.O_NOFOLLOW, dir_fd=parent)
        dirfd.write_bytes_at(parent, "staged.bin", b"new")
        with pytest.raises(FileExistsError):
            fs.rename("staged.bin", "published.bin", src_dir_fd=parent, dst_dir_fd=parent)
        assert dirfd.read_bytes_at(parent, "published.bin") == b"old"
        fs.replace("staged.bin", "published.bin", src_dir_fd=parent, dst_dir_fd=parent)
        assert dirfd.read_bytes_at(parent, "published.bin") == b"new"
        assert os.read(reader, 100) == b"old"
        assert "staged.bin" not in fs.listdir(parent)
        (tmp_path / "durable.bin").write_bytes(b"durable")
        platform.durable_replace(tmp_path / "durable.bin", tmp_path / "published.bin")
        assert dirfd.read_bytes_at(parent, "published.bin") == b"durable"
    finally:
        if reader >= 0:
            os.close(reader)
        os.close(parent)


def test_native_case_and_short_aliases_retain_the_same_file_identity(tmp_path):
    fs = dirfd.filesystem
    root = tmp_path / "MixedCaseQualificationDirectory"
    root.mkdir()
    target = root / "LongQualificationFilename.bin"
    target.write_bytes(b"protected")
    short = _short_path(target)
    assert "~" in short.name, "qualification requires enabled 8.3 filename creation"
    parent = dirfd.open_directory_chain(root)
    short_parent = -1
    try:
        short_parent = dirfd.open_directory_chain(short.parent)
        assert _identity(parent) == _identity(short_parent)
        identities = []
        for name in (target.name, target.name.swapcase(), short.name):
            fd = fs.open(name, os.O_RDONLY | fs.O_NOFOLLOW, dir_fd=parent)
            try:
                identities.append(_identity(fd))
                assert os.read(fd, 100) == b"protected"
            finally:
                os.close(fd)
        assert identities[0] == identities[1] == identities[2]
        identity = dirfd.capture_parent(short.parent / "receipt.json")
        try:
            dirfd.atomic_json_write(short.parent / "receipt.json", b'{"ok":true}', identity=identity)
            assert (root / "receipt.json").read_bytes() == b'{"ok":true}'
        finally:
            dirfd.close_pinned(identity)
    finally:
        if short_parent >= 0:
            os.close(short_parent)
        os.close(parent)


def test_native_extended_dos_path_round_trip(tmp_path):
    extended = dirfd._WindowsFilesystem._extended_path(tmp_path)
    assert extended.startswith("\\\\?\\")
    ordinary = dirfd.open_directory_chain(tmp_path)
    retained = -1
    try:
        retained = dirfd.open_directory_chain(extended)
        assert _identity(ordinary) == _identity(retained)
        dirfd.write_bytes_at(retained, "extended.bin", b"extended")
        assert dirfd.read_bytes_at(ordinary, "extended.bin") == b"extended"
    finally:
        if retained >= 0:
            os.close(retained)
        os.close(ordinary)


@pytest.mark.parametrize("extended", [False, True], ids=["unc", "extended-unc"])
def test_native_unc_containment_and_publication(extended):
    share = os.environ.get("ASTRID_TEST_UNC_ROOT")
    assert share, "set ASTRID_TEST_UNC_ROOT to a writable SMB share (provisioned by CI)"
    root = Path(share) / ("qualification-" + uuid.uuid4().hex)
    root.mkdir()
    spelling = dirfd._WindowsFilesystem._extended_path(root) if extended else str(root)
    parent = -1
    identity = None
    try:
        parent = dirfd.open_directory_chain(spelling)
        dirfd.write_bytes_at(parent, "payload.bin", b"unc-payload")
        assert dirfd.read_bytes_at(parent, "payload.bin") == b"unc-payload"
        dirfd.write_bytes_at(parent, "payload.bin", b"unc-replaced")
        assert dirfd.read_bytes_at(parent, "payload.bin") == b"unc-replaced"
        with pytest.raises(OSError):
            dirfd.filesystem.open("../outside", os.O_WRONLY | os.O_CREAT, dir_fd=parent)
        target = Path(spelling) / "receipt.json"
        identity = dirfd.capture_parent(target)
        dirfd.atomic_json_write(target, b'{"ok":true}', identity=identity)
        assert dirfd.read_bytes_at(parent, "receipt.json") == b'{"ok":true}'
    finally:
        dirfd.close_pinned(identity)
        if parent >= 0:
            os.close(parent)
        shutil.rmtree(root)


def test_private_file_creation_is_protected_and_existing_unprotected_file_is_refused(tmp_path):
    from runtime_protocol.windows_security import open_private_file, validate
    root = tmp_path / "private"
    platform.private_directory(root)
    path = root / "custody.lock"
    descriptor = open_private_file(path)
    try:
        validate(descriptor)
        os.write(descriptor, b"retained")
    finally:
        os.close(descriptor)
    descriptor = open_private_file(path)
    try:
        assert os.read(descriptor, 32) == b"retained"
    finally:
        os.close(descriptor)
    # Inherited ACLs are not a substitute for a protected DACL.
    unsafe = root / "unsafe.lock"
    unsafe.write_bytes(b"untrusted")
    with pytest.raises(PermissionError):
        open_private_file(unsafe)
    assert unsafe.read_bytes() == b"untrusted"
