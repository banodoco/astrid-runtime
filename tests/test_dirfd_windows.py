from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

import runtime_protocol.dirfd as dirfd
from runtime_protocol import platform
from runtime_protocol.dirfd import _retry_windows_sharing_violation
from runtime_protocol.dirfd import _WindowsFilesystem as WindowsFilesystem
from runtime_protocol.errors import ConflictError
from tests.lanes import requires_windows_dirfd_adapter, skip_for_declared_error

_PARENT_FD = 1000010


def test_windows_dirfd_and_path_replacement_share_retry_policy():
    assert dirfd._retry_windows_sharing_violation is platform._retry_windows_sharing_violation


def test_windows_sharing_retry_stops_at_deadline():
    ticks = [0.0]
    attempts = []

    def operation():
        attempts.append(ticks[0])
        error = PermissionError("sharing violation")
        error.winerror = 32
        raise error

    def sleep(delay):
        ticks[0] += delay

    with pytest.raises(PermissionError, match="sharing violation"):
        _retry_windows_sharing_violation(operation, clock=lambda: ticks[0], sleep=sleep)
    assert 1 < len(attempts) < 20
    assert ticks[0] == pytest.approx(0.25)


def test_windows_replace_is_explicit_and_rename_remains_no_replace(monkeypatch):
    calls = []
    monkeypatch.setattr(WindowsFilesystem, "_move", lambda self, *args, **kwargs: calls.append(kwargs))
    filesystem = WindowsFilesystem()
    filesystem.rename("source", "destination")
    filesystem.replace("source", "destination")
    assert calls == [{"src_dir_fd": None, "dst_dir_fd": None},
                     {"src_dir_fd": None, "dst_dir_fd": None, "replace": True}]


def test_windows_dirfd_replace_retries_sharing_violation(monkeypatch):
    times = iter((0.0, 0.0, 0.01, 0.01, 0.03, 0.03))
    sleeps = []
    attempts = []

    def clock():
        return next(times, 0.03)

    def operation():
        attempts.append(1)
        if len(attempts) < 3:
            error = PermissionError("sharing violation")
            error.winerror = 32
            raise error
        return "published"

    assert _retry_windows_sharing_violation(operation, clock=clock, sleep=sleeps.append) == "published"
    assert len(attempts) == 3
    assert sleeps


@pytest.mark.parametrize("value, expected", [
    (r"C:\Root\Child", r"c:\root\child"),
    (r"\\?\C:\Root\Child" + "\\", r"c:\root\child"),
    ("C:/Root/./Child/../File", r"c:\root\file"),
    (r"\\?\UNC\Server\Share\Root", r"\\server\share\root"),
    (r"\\SERVER\Share\Root", r"\\server\share\root"),
    (r"\\?\UNC\Server\Share", "\\\\server\\share\\"),
    ("\\\\Server\\Share\\", "\\\\server\\share\\"),
])
def test_windows_final_path_normalisation(value, expected):
    assert WindowsFilesystem._normal_path(value) == expected


@pytest.mark.parametrize("root, child, expected", [
    (r"C:\Root", r"\\?\c:\ROOT\child", True),
    (r"C:\Root", r"c:\root", True),
    ("C:\\", r"C:\child", True),
    (r"C:\Root", r"C:\Root-other\child", False),
    (r"C:\Root", r"C:\Root\..\outside", False),
    (r"C:\Root", r"D:\Root\child", False),
    (r"\\server\share\root", r"\\?\UNC\SERVER\SHARE\ROOT\child", True),
    (r"\\server\share\root", r"\\server\other\root\child", False),
    (r"\\server\share", r"\\?\UNC\SERVER\SHARE\child", True),
])
def test_windows_final_path_containment(root, child, expected):
    assert WindowsFilesystem._contained(root, child) is expected


@pytest.mark.parametrize("path", [r"\\.\PhysicalDrive0", r"\\?\GLOBALROOT\Device\HarddiskVolume1",
                                  r"\??\C:\root", "C:root", "root", "C:\\a\x00b"])
def test_windows_device_and_relative_namespaces_rejected(path):
    with pytest.raises(OSError):
        WindowsFilesystem._normal_path(path)


def test_windows_extended_paths_preserve_case_and_long_names():
    path = "C:\\MixedCase\\" + "nested\\" * 50 + "File"
    assert WindowsFilesystem._extended_path(path) == "\\\\?\\" + path
    assert WindowsFilesystem._extended_path(r"\\Server\Share\MixedCase") == r"\\?\UNC\Server\Share\MixedCase"


@pytest.mark.parametrize("path", ["", "..", "../outside", r"a\..\b", r"C:\absolute", "C:relative",
                                  r"\rooted", r"\\server\share\x", "a//b", "a/./b", "file:stream",
                                  "nested/name.", "nested/name ", "NUL.txt", "COM1", "LPT¹.txt",
                                  "CONOUT$", "wild*", "nul\x00name"])
def test_windows_relative_names_cannot_escape_or_alias(path):
    with pytest.raises(OSError):
        WindowsFilesystem._parts(path)


def test_windows_relative_components_accept_both_separators():
    assert WindowsFilesystem._parts(r"nested\ordinary-name/file.bin") == ("nested", "ordinary-name", "file.bin")
    assert WindowsFilesystem._parts(".") == ()


@pytest.mark.parametrize("attributes, nofollow, directory, reject", [
    (0x80, True, False, False), (0x10, False, True, False),
    (0x400, True, False, True), (0x410, True, True, True),
    (0x410, False, True, True), (0x400, False, False, False),
])
def test_windows_reparse_refusal_is_independent_of_reparse_tag(attributes, nofollow, directory, reject):
    assert WindowsFilesystem._reject_reparse(attributes, nofollow=nofollow, directory=directory) is reject


@pytest.mark.parametrize("volume, high, low, expected", [
    (7, 0, 42, (7, 42)), (7, 0x12345678, 0x9ABCDEF0, (7, 0x123456789ABCDEF0)),
    (8, 0, 42, (8, 42)), (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, (0xFFFFFFFF, (1 << 64) - 1)),
])
def test_windows_identity_uses_volume_and_full_file_index(volume, high, low, expected):
    info = dirfd._WinFileInformation(VolumeSerialNumber=volume, FileIndexHigh=high, FileIndexLow=low)
    assert WindowsFilesystem._file_identity(info) == expected


def test_windows_native_struct_layouts():
    pointer64 = ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(dirfd._WinUnicodeString) == (16 if pointer64 else 8)
    assert ctypes.sizeof(dirfd._WinObjectAttributes) == (48 if pointer64 else 24)
    assert ctypes.sizeof(dirfd._WinIoStatus) == (16 if pointer64 else 8)
    assert ctypes.sizeof(dirfd._WinFileInformation) == 52
    assert dirfd._WinDirectoryInformation.FileName.offset == 104


@pytest.fixture
def native_calls(tmp_path, monkeypatch):
    """Mock only the native boundary; use real CRT-compatible fds for cleanup/I/O."""
    seen = SimpleNamespace(closed=[], creates=[], sets=[], attributes=0x80,
                           parent_path=r"\\?\C:\root", child_path=r"\\?\C:\root\child")
    backing = tmp_path / "backing"
    backing.write_bytes(b"unchanged")
    def create(result, access, attributes, status, allocation, attrs, sharing, disposition, options, ea, ea_length):
        obj = ctypes.cast(attributes, ctypes.POINTER(dirfd._WinObjectAttributes)).contents
        name = ctypes.wstring_at(obj.ObjectName.contents.Buffer)
        seen.creates.append((obj.RootDirectory, name, access, disposition, options, sharing))
        fd = os.open(backing, os.O_RDWR)
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = fd
        seen.fd = fd
        return 0
    def set_info(handle, status, info, size, kind):
        seen.sets.append((handle, ctypes.string_at(info, size), kind))
        return 0
    api = SimpleNamespace(NtCreateFile=create, NtSetInformationFile=set_info,
                          RtlNtStatusToDosError=lambda status: 5)
    crt = SimpleNamespace(get_osfhandle=lambda fd: fd + 1000,
                          open_osfhandle=lambda handle, flags: handle)
    kernel = SimpleNamespace(CloseHandle=lambda handle: seen.closed.append(handle.value))
    monkeypatch.setattr(WindowsFilesystem, "_api", staticmethod(lambda: (ctypes, crt, SimpleNamespace(HANDLE=ctypes.c_void_p), kernel)))
    monkeypatch.setattr(WindowsFilesystem, "_nt_api", staticmethod(lambda: api))
    monkeypatch.setattr(WindowsFilesystem, "_information", classmethod(lambda cls, fd: dirfd._WinFileInformation(
        FileAttributes=seen.attributes, VolumeSerialNumber=17, FileIndexHigh=3, FileIndexLow=fd)))
    monkeypatch.setattr(WindowsFilesystem, "_final_path", classmethod(
        lambda cls, fd: seen.parent_path if fd == _PARENT_FD else seen.child_path))
    seen.backing = backing
    return seen


def test_windows_native_open_is_relative_and_truncates_after_validation(native_calls):
    fs = WindowsFilesystem()
    fd = fs._open_native("child", os.O_RDWR | os.O_TRUNC | fs.O_NOFOLLOW, dir_fd=_PARENT_FD)
    try:
        root, name, access, disposition, options, sharing = native_calls.creates[0]
        assert root == _PARENT_FD + 1000 and name == "child"
        assert access & 0x80 and access & 0x100000
        assert disposition == 1  # FILE_OPEN, never FILE_OVERWRITE
        assert options & 0x200000 and options & 0x20
        assert sharing == 7
        assert native_calls.backing.read_bytes() == b""
    finally:
        os.close(fd)


@pytest.mark.parametrize("failure", ["outside", "prefix_sibling", "parent_renamed", "reparse"])
def test_windows_failed_handle_validation_never_truncates_and_closes(native_calls, monkeypatch, failure):
    if failure == "outside":
        native_calls.child_path = r"\\?\C:\outside\child"
    elif failure == "prefix_sibling":
        native_calls.child_path = r"\\?\C:\root-other\child"
    elif failure == "reparse":
        native_calls.attributes = 0x400
    else:
        paths = iter([r"\\?\C:\root", r"\\?\C:\moved"])
        monkeypatch.setattr(WindowsFilesystem, "_final_path", classmethod(lambda cls, fd: next(paths)))
    with pytest.raises(OSError):
        WindowsFilesystem._open_native("child", os.O_RDWR | os.O_TRUNC | WindowsFilesystem.O_NOFOLLOW, dir_fd=_PARENT_FD)
    assert native_calls.backing.read_bytes() == b"unchanged"
    with pytest.raises(OSError) as error:
        os.fstat(native_calls.fd)
    assert error.value.errno == errno.EBADF


def test_windows_fstat_returns_native_identity_and_keeps_nanoseconds(native_calls):
    fd = os.open(native_calls.backing, os.O_RDONLY)
    try:
        before = os.fstat(fd)
        value = WindowsFilesystem.fstat(fd)
        assert (value.st_dev, value.st_ino) == (17, (3 << 32) | fd)
        assert stat.S_ISREG(value.st_mode)
        assert value.st_mtime_ns == before.st_mtime_ns
        native_calls.attributes = 0x410
        assert stat.S_ISLNK(WindowsFilesystem.fstat(fd).st_mode)
    finally:
        os.close(fd)


def test_windows_failed_crt_conversion_closes_native_handle(native_calls, monkeypatch):
    api = WindowsFilesystem._api()
    def fail(handle, flags):
        # The mock handle is a real fd; CloseHandle below must release it.
        raise OSError("CRT conversion failed")
    api[1].open_osfhandle = fail
    api[3].CloseHandle = lambda handle: os.close(handle.value)
    with pytest.raises(OSError, match="CRT conversion failed"):
        WindowsFilesystem._open_native("child", os.O_RDONLY, dir_fd=_PARENT_FD)
    with pytest.raises(OSError):
        os.fstat(native_calls.fd)


@pytest.mark.parametrize("volume, inode, mode", [(18, 42, stat.S_IFDIR), (17, 43, stat.S_IFDIR), (17, 42, stat.S_IFREG)])
def test_windows_pinned_parent_identity_mismatch(monkeypatch, tmp_path, volume, inode, mode):
    fs = WindowsFilesystem()
    target = dirfd.absolute_path(tmp_path / "leaf")
    identity = {"path": str(target), "target_parent": str(target.parent), "parent_was_missing": False,
                "_parent_fd": 10, "parent_st_dev": 17, "parent_st_ino": 42,
                "parent_st_mode": stat.S_IFDIR | 0o700}
    monkeypatch.setattr(dirfd, "os", fs)
    monkeypatch.setattr(dirfd, "has_symlink_component", lambda path: False)
    monkeypatch.setattr(fs, "fstat", lambda fd: os.stat_result((mode | 0o700, inode, volume, 1, 0, 0, 0, 0, 0, 0)))
    with pytest.raises(ConflictError, match="retained parent identity changed"):
        dirfd.validate_parent(target, identity)


@pytest.mark.parametrize("destination", ["b", "renamed", "name-\U0001F680"])
def test_windows_rename_and_link_information_use_destination_handle(native_calls, monkeypatch, destination):
    from contextlib import contextmanager
    @contextmanager
    def parent(cls, path, dir_fd=None):
        yield dir_fd, path
    monkeypatch.setattr(WindowsFilesystem, "_parent", classmethod(parent))
    fs = WindowsFilesystem()
    for link in (False, True):
        if link:
            fs.link("child", destination, src_dir_fd=_PARENT_FD, dst_dir_fd=20)
        else:
            fs.replace("child", destination, src_dir_fd=_PARENT_FD, dst_dir_fd=20)
        handle, data, kind = native_calls.sets[-1]
        assert handle == native_calls.fd + 1000
        assert kind == (11 if link else 65)
        assert int.from_bytes(data[:4], "little") == (0 if link else 3)
        root_offset = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 4
        assert int.from_bytes(data[root_offset:root_offset + ctypes.sizeof(ctypes.c_void_p)], "little") == 1020
        length_offset = dirfd._WinNameInformation.FileNameLength.offset
        assert int.from_bytes(data[length_offset:length_offset + 4], "little") == len(destination.encode("utf-16-le"))
        start = dirfd._WinNameInformation.FileName.offset
        assert data[start:start + len(destination.encode("utf-16-le"))] == destination.encode("utf-16-le")
        assert len(data) >= ctypes.sizeof(dirfd._WinNameInformation) + len(destination.encode("utf-16-le"))


@pytest.mark.parametrize("code, expected_classes", [(50, [65, 10]), (87, [65, 10]), (5, [65]), (32, [65])])
def test_windows_replace_falls_back_only_for_unsupported_extended_rename(native_calls, monkeypatch, code, expected_classes):
    from contextlib import contextmanager
    @contextmanager
    def parent(cls, path, dir_fd=None):
        yield dir_fd, path
    monkeypatch.setattr(WindowsFilesystem, "_parent", classmethod(parent))
    monkeypatch.setattr(dirfd, "_retry_windows_sharing_violation", lambda operation: operation())
    calls = []
    def set_information(cls, fd, buffer, kind, size=None):
        calls.append((kind, bytes(buffer)))
        if kind == 65:
            error = OSError("rename rejected")
            error.winerror = code
            raise error
    monkeypatch.setattr(WindowsFilesystem, "_set_information", classmethod(set_information))
    if code in (50, 87):
        WindowsFilesystem().replace("child", "target", src_dir_fd=_PARENT_FD, dst_dir_fd=20)
        assert calls[-1][1][0] == 1  # legacy replace, same pinned destination handle
    else:
        with pytest.raises(OSError, match="rename rejected"):
            WindowsFilesystem().replace("child", "target", src_dir_fd=_PARENT_FD, dst_dir_fd=20)
    assert [kind for kind, _ in calls] == expected_classes


@requires_windows_dirfd_adapter
def test_windows_real_containment_and_parent_creation(tmp_path):
    target = tmp_path / "root" / "nested" / "receipt.json"
    identity = dirfd.capture_parent(target)
    created = -1
    try:
        created, name = dirfd.ensure_parent_at(target, identity)
        dirfd.validate_created_parent(target, identity, created)
        dirfd.write_bytes_at(created, name, b"payload")
        assert dirfd.read_bytes_at(created, name) == b"payload"
        opened = dirfd.filesystem.open(name, os.O_RDONLY, dir_fd=created)
        try:
            assert dirfd._identity_tuple(dirfd.filesystem.stat(name, dir_fd=created)) == dirfd._identity_tuple(
                dirfd.filesystem.fstat(opened))
        finally:
            os.close(opened)
        for escape in ("../outside", r"..\outside", r"C:\outside", "receipt.json:stream"):
            with pytest.raises(OSError):
                dirfd.filesystem.open(escape, os.O_WRONLY | os.O_CREAT, dir_fd=created)
    finally:
        if created >= 0 and created != identity["_parent_fd"]:
            os.close(created)
        dirfd.close_pinned(identity)


@requires_windows_dirfd_adapter
def test_windows_real_junction_escape_refused(tmp_path):
    outside = tmp_path / "outside"
    root = tmp_path / "root"
    outside.mkdir()
    root.mkdir()
    (outside / "secret").write_bytes(b"protected")
    junction = root / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)], check=True, capture_output=True)
    root_fd = dirfd.open_directory_chain(root)
    try:
        with pytest.raises((OSError, ConflictError)):
            dirfd.capture_parent(junction / "secret")
        for path in ("junction", "junction/secret"):
            with pytest.raises(OSError):
                dirfd.filesystem.open(path, os.O_RDONLY | dirfd.filesystem.O_NOFOLLOW, dir_fd=root_fd)
        with pytest.raises(OSError):
            dirfd.filesystem.mkdir("junction/escaped", dir_fd=root_fd)
        assert (outside / "secret").read_bytes() == b"protected"
        assert not (outside / "escaped").exists()
    finally:
        os.close(root_fd)
        junction.rmdir()


@requires_windows_dirfd_adapter
@pytest.mark.parametrize("directory", [False, True])
def test_windows_real_symlink_refused(tmp_path, directory):
    target = tmp_path / "target"
    target.mkdir() if directory else target.write_bytes(b"protected")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        skip_for_declared_error("windows-symlink-creation", exc)
    with pytest.raises(OSError):
        dirfd.filesystem.open(alias, os.O_RDONLY | dirfd.filesystem.O_NOFOLLOW)
    assert stat.S_ISLNK(dirfd.filesystem.stat(alias, follow_symlinks=False).st_mode)


@requires_windows_dirfd_adapter
def test_windows_real_rename_race_detected_and_no_write_to_replacement(tmp_path):
    parent = tmp_path / "parent"
    moved = tmp_path / "moved"
    parent.mkdir()
    target = parent / "receipt.json"
    identity = dirfd.capture_parent(target)
    try:
        parent.rename(moved)
        parent.mkdir()
        with pytest.raises(ConflictError, match="identity|parent"):
            dirfd.atomic_json_write(target, b"{}", identity=identity)
        assert list(parent.iterdir()) == []
        assert list(moved.iterdir()) == []
    finally:
        dirfd.close_pinned(identity)


def test_atomic_json_write_restricts_temp_before_writing_windows_acl(monkeypatch, tmp_path):
    """A Windows 0600 mode argument leaves inherited ACLs unchanged."""
    original_write = dirfd.os.write
    protected = set()
    events = []

    def is_owner_only(fd):
        return fd in protected

    def validate(fd):
        if not is_owner_only(fd):
            raise PermissionError("inherited DACL is not private")

    def owner_only(fd, *, directory=None):
        assert directory is None
        with pytest.raises(PermissionError, match="inherited DACL is not private"):
            validate(fd)
        events.append("reader-rejected")
        protected.add(fd)
        events.append("restricted")

    def write(fd, data):
        validate(fd)
        events.append("reader-accepted")
        events.append("written")
        return original_write(fd, data)

    monkeypatch.setattr(platform, "owner_only", owner_only)
    monkeypatch.setattr(dirfd.os, "write", write)

    target = tmp_path / "process-control.json"
    dirfd.atomic_json_write(target, b"{}\n")

    assert events == ["reader-rejected", "restricted", "reader-accepted", "written"]
    assert target.read_bytes() == b"{}\n"


def test_atomic_json_write_keeps_old_target_if_acl_restriction_fails(monkeypatch, tmp_path):
    target = tmp_path / "process-control.json"
    target.write_bytes(b"old\n")

    def deny(_fd, *, directory=None):
        raise PermissionError("cannot protect temp file")

    monkeypatch.setattr(platform, "owner_only", deny)
    with pytest.raises(PermissionError, match="cannot protect temp file"):
        dirfd.atomic_json_write(target, b"new\n")

    assert target.read_bytes() == b"old\n"
    assert list(tmp_path.iterdir()) == [target]


@requires_windows_dirfd_adapter
def test_windows_real_long_paths_and_native_identity(tmp_path):
    fs = dirfd.filesystem
    root_fd = dirfd.open_directory_chain(tmp_path)
    current = os.dup(root_fd)
    relative = Path()
    try:
        for index in range(12):
            name = f"nested-{index}-" + "x" * 20
            fs.mkdir(name, dir_fd=current)
            child = fs.open(name, os.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
            relative /= name
        assert len(fs.path_from_fd(current)) > 260
        dirfd.write_bytes_at(current, "long.bin", b"long-path")
        assert dirfd.read_bytes_at(current, "long.bin") == b"long-path"
        reopened = dirfd.open_directory_chain(tmp_path / relative)
        try:
            assert dirfd._identity_tuple(fs.fstat(reopened)) == dirfd._identity_tuple(fs.fstat(current))
        finally:
            os.close(reopened)
        fs.link("long.bin", "alias.bin", src_dir_fd=current, dst_dir_fd=current)
        assert fs.stat("long.bin", dir_fd=current).st_ino == fs.stat("alias.bin", dir_fd=current).st_ino
        assert set(fs.listdir(current)) == {"long.bin", "alias.bin"}
    finally:
        os.close(current)
        os.close(root_fd)


@pytest.mark.parametrize("changed", [False, True])
def test_windows_pinned_parent_compares_lexical_identity(monkeypatch, tmp_path, changed):
    fs = WindowsFilesystem()
    target = dirfd.absolute_path(tmp_path / "leaf")
    mode = stat.S_IFDIR | 0o700
    identity = {"path": str(target), "target_parent": str(target.parent), "parent_was_missing": False,
                "_parent_fd": 10, "parent_st_dev": 17, "parent_st_ino": 42, "parent_st_mode": mode}
    monkeypatch.setattr(dirfd, "os", fs)
    monkeypatch.setattr(dirfd, "has_symlink_component", lambda path: False)
    monkeypatch.setattr(fs, "fstat", lambda fd: os.stat_result((mode, 42, 17, 1, 0, 0, 0, 0, 0, 0)))
    monkeypatch.setattr(fs, "stat", lambda *a, **kw: os.stat_result((mode, 43 if changed else 42, 17, 1, 0, 0, 0, 0, 0, 0)))
    if changed:
        with pytest.raises(ConflictError, match="lexical parent identity changed"):
            dirfd.validate_parent(target, identity)
    else:
        assert dirfd.validate_parent(target, identity) == 10


def test_windows_handle_information_uses_native_volume_and_index(monkeypatch):
    def information(handle, output):
        assert handle.value == 1234
        info = ctypes.cast(output, ctypes.POINTER(dirfd._WinFileInformation)).contents
        info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow = 9, 1, 23
        return True
    api = (ctypes, SimpleNamespace(get_osfhandle=lambda fd: 1234), SimpleNamespace(HANDLE=ctypes.c_void_p),
           SimpleNamespace(GetFileInformationByHandle=information))
    monkeypatch.setattr(WindowsFilesystem, "_api", staticmethod(lambda: api))
    assert WindowsFilesystem._file_identity(WindowsFilesystem._information(10)) == (9, (1 << 32) | 23)


def test_windows_final_path_buffer_grows_for_long_paths(monkeypatch):
    path = r"\\?\C:\root" + "\\nested" * 100
    sizes = []
    def final_path(handle, buffer, size, flags):
        sizes.append(size)
        if size <= len(path):
            return len(path) + 1
        buffer.value = path
        return len(path)
    api = (ctypes, SimpleNamespace(get_osfhandle=lambda fd: 1234), SimpleNamespace(HANDLE=ctypes.c_void_p),
           SimpleNamespace(GetFinalPathNameByHandleW=final_path))
    monkeypatch.setattr(WindowsFilesystem, "_api", staticmethod(lambda: api))
    assert WindowsFilesystem._final_path(10) == path
    assert len(sizes) == 2 and sizes[1] > len(path)


@pytest.mark.parametrize("directory", [True, False])
def test_windows_fsync_ignores_only_directory_flushes(native_calls, monkeypatch, directory):
    native_calls.attributes = 0x10 if directory else 0x80
    def fail(fd):
        raise OSError(errno.EIO, "flush failed")
    monkeypatch.setattr(dirfd._os, "fsync", fail)
    if directory:
        WindowsFilesystem.fsync(10)
    else:
        with pytest.raises(OSError, match="flush failed"):
            WindowsFilesystem.fsync(10)


def test_windows_pinned_path_locks_all_ancestors_and_checks_identity(monkeypatch):
    calls, closed = [], []
    def opened(cls, path, flags, **kwargs):
        calls.append((path, kwargs))
        return 100 + len(calls)
    def information(cls, fd):
        return dirfd._WinFileInformation(VolumeSerialNumber=1, FileIndexLow=42)
    monkeypatch.setattr(WindowsFilesystem, "_final_path", classmethod(lambda cls, fd: r"\\?\C:\root\nested"))
    monkeypatch.setattr(WindowsFilesystem, "_open_native", classmethod(opened))
    monkeypatch.setattr(WindowsFilesystem, "_information", classmethod(information))
    monkeypatch.setattr(dirfd._os, "close", closed.append)
    with WindowsFilesystem.pinned_path(10) as path:
        assert path == r"\\?\C:\root\nested"
        assert closed == []
        assert [call[0] for call in calls] == ["\\\\?\\C:\\", "root", "nested"]
        assert all(call[1]["share_delete"] is False for call in calls)
    assert closed == [103, 102, 101]


def test_windows_pinned_path_rejects_lexical_replacement(monkeypatch):
    closed = []
    monkeypatch.setattr(WindowsFilesystem, "_final_path", classmethod(lambda cls, fd: r"\\?\C:\root"))
    monkeypatch.setattr(WindowsFilesystem, "_open_native", classmethod(lambda cls, *a, **kw: 100))
    monkeypatch.setattr(WindowsFilesystem, "_information", classmethod(lambda cls, fd: dirfd._WinFileInformation(
        VolumeSerialNumber=1, FileIndexLow=42 if fd == 10 else 43)))
    monkeypatch.setattr(dirfd._os, "close", closed.append)
    with pytest.raises(OSError, match="lexical directory identity changed"):
        with WindowsFilesystem.pinned_path(10):
            pytest.fail("replacement must be rejected before exposing the path")
    assert closed == [100, 100]


def test_windows_scandir_reads_directory_handle_and_cached_metadata(monkeypatch, tmp_path):
    fs = WindowsFilesystem()
    opened = os.open(tmp_path / "descriptor", os.O_CREAT | os.O_RDWR, 0o600)
    calls = []
    def query(handle, kind, buffer, size):
        calls.append(kind)
        if len(calls) > 1:
            return False
        info = dirfd._WinDirectoryInformation.from_buffer(buffer)
        info.FileAttributes, info.FileId, info.EndOfFile = 0x80, 12345, 9
        info.CreationTime = info.LastAccessTime = info.LastWriteTime = 116444736000000000
        data = "payload.bin".encode("utf-16-le")
        info.FileNameLength = len(data)
        ctypes.memmove(ctypes.addressof(buffer) + dirfd._WinDirectoryInformation.FileName.offset, data, len(data))
        return True
    monkeypatch.setattr(fs, "open", lambda *a, **kw: opened)
    monkeypatch.setattr(WindowsFilesystem, "_information", classmethod(lambda cls, fd: dirfd._WinFileInformation(VolumeSerialNumber=8)))
    monkeypatch.setattr(WindowsFilesystem, "_final_path", classmethod(lambda cls, fd: r"\\?\C:\root"))
    api = (ctypes, SimpleNamespace(get_osfhandle=lambda fd: fd), SimpleNamespace(HANDLE=ctypes.c_void_p),
           SimpleNamespace(GetFileInformationByHandleEx=query))
    monkeypatch.setattr(WindowsFilesystem, "_api", staticmethod(lambda: api))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 18, raising=False)
    with fs.scandir(10) as entries:
        entry = next(entries)
        assert entry.name == "payload.bin" and entry.inode() == 12345
        assert entry.is_file(follow_symlinks=False)
        assert entry.stat(follow_symlinks=False).st_dev == 8
        assert entry.stat(follow_symlinks=False).st_size == 9
        assert list(entries) == []
    assert calls == [11, 10]
    with pytest.raises(OSError):
        os.fstat(opened)


@requires_windows_dirfd_adapter
def test_windows_real_inflight_parent_rename_is_detected(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    parent.mkdir()
    fs = dirfd.filesystem
    fd = dirfd.open_directory_chain(parent)
    original = WindowsFilesystem._verify_open
    moved = tmp_path / "moved"
    raced = False
    def verify(cls, opened, parent_fd, parent_path):
        nonlocal raced
        if not raced:
            raced = True
            parent.rename(moved)
        return original(opened, parent_fd, parent_path)
    monkeypatch.setattr(WindowsFilesystem, "_verify_open", classmethod(verify))
    try:
        # Use the native boundary to race immediately after NtCreateFile and
        # before handle validation; no descriptor escapes validation.
        with pytest.raises(OSError, match="escaped its pinned parent"):
            fs._open_native(".", os.O_RDONLY | fs.O_DIRECTORY | fs.O_NOFOLLOW, dir_fd=fd)
        assert raced
        assert list(moved.iterdir()) == []
    finally:
        os.close(fd)


def test_windows_external_writer_pins_fresh_file_before_exposing_path(native_calls, monkeypatch):
    from contextlib import contextmanager
    @contextmanager
    def parent(cls, name, directory_fd):
        yield directory_fd, name
    @contextmanager
    def pinned(cls, fd):
        yield r"\\?\C:\root"
    monkeypatch.setattr(WindowsFilesystem, "_parent", classmethod(parent))
    monkeypatch.setattr(WindowsFilesystem, "pinned_path", classmethod(pinned))
    with WindowsFilesystem.create_file_path_at(_PARENT_FD, "child") as path:
        assert path == r"\\?\C:\root\child"
        root, name, access, disposition, options, share = native_calls.creates[0]
        assert root == _PARENT_FD + 1000 and name == "child"
        assert disposition == 2 and options & 0x200000
        assert share == 3  # No FILE_SHARE_DELETE, including the final entry.
        os.fstat(native_calls.fd)
    with pytest.raises(OSError):
        os.fstat(native_calls.fd)


@requires_windows_dirfd_adapter
def test_windows_real_external_writer_path_cannot_be_replaced(tmp_path):
    import sqlite3
    fs = dirfd.filesystem
    root_fd = dirfd.open_directory_chain(tmp_path)
    try:
        with fs.create_file_path_at(root_fd, "pinned.sqlite3") as path:
            with pytest.raises(OSError):
                (tmp_path / "pinned.sqlite3").unlink()
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE pinned (value TEXT)")
                connection.commit()
            finally:
                connection.close()
        assert fs.stat("pinned.sqlite3", dir_fd=root_fd).st_size > 0
    finally:
        os.close(root_fd)


def test_windows_native_dot_reopens_parent_with_empty_nt_name(native_calls):
    native_calls.attributes = 0x10
    native_calls.child_path = native_calls.parent_path
    fd = WindowsFilesystem._open_native(".", WindowsFilesystem.O_DIRECTORY | WindowsFilesystem.O_NOFOLLOW,
                                        dir_fd=_PARENT_FD)
    try:
        assert native_calls.creates[0][0] == _PARENT_FD + 1000
        assert native_calls.creates[0][1] == ""
        assert native_calls.creates[0][2] == 0x1200A9
    finally:
        os.close(fd)


def test_windows_native_name_length_never_wraps_unicode_string(native_calls):
    with pytest.raises(OSError) as error:
        WindowsFilesystem._open_native("x" * 32767, os.O_RDONLY, dir_fd=_PARENT_FD)
    assert error.value.errno == errno.ENAMETOOLONG
    assert native_calls.creates == []
