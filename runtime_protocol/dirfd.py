"""Small descriptor-relative filesystem primitives used by lifecycle code.

The lifecycle protocol performs a lot of ``validate(path); write(path)`` work.
That shape is unsafe when an untrusted process can rename a parent between the
two operations.  These helpers retain the validated parent directory and do
all subsequent operations relative to that descriptor.  Paths are kept only
for human-readable receipts and for the lexical identity check; they are never
re-opened as the authority for a material write.

On Windows, an "fd" is a CRT descriptor owning a native Win32 handle, including
for directories. NtCreateFile opens children relative to that handle; opened
handles are checked for reparse points, final-path containment and native file
identity (volume serial and 64-bit file index). Ordinary CRT I/O and duplication
remain usable. Path-only external APIs must hold ``filesystem.pinned_path(fd)``
while using the returned extended-length path. POSIX uses ordinary os descriptors.
"""

from __future__ import annotations

import os as _os
import ctypes
import errno
import functools
import ntpath
from pathlib import Path
import stat
import time
import hashlib
import json
from contextlib import contextmanager
from typing import Any, Mapping

from . import platform
from .errors import ConflictError
from .platform import _retry_windows_sharing_violation

_WIN_DIRECTORY = 0x10000000
_WIN_NOFOLLOW = 0x20000000
_WIN_NONBLOCK = 0


class _WindowsFilesystem:
    """Bounded Win32/NT implementation of the descriptor operations below.

    File descriptors are real CRT descriptors owning native handles, so read,
    write, fdopen, dup and close keep their usual meaning. Child opens use
    NtCreateFile's RootDirectory; no child pathname is reopened as authority.
    Handles share deletion so directory publication/renames remain possible.
    Every relative open verifies both the parent and child's final paths before
    exposing the descriptor (and before truncation). Lexical identity checks in
    validate_parent separately detect replacement of a retained directory.
    """

    O_DIRECTORY = _WIN_DIRECTORY
    O_NOFOLLOW = _WIN_NOFOLLOW
    O_NONBLOCK = 0

    def __getattr__(self, name):
        return getattr(_os, name)

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _api():
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                     wintypes.DWORD, wintypes.DWORD]
        kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WinFileInformation)]
        kernel.GetFileInformationByHandle.restype = wintypes.BOOL
        kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                       wintypes.LPVOID, wintypes.DWORD]
        kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        return ctypes, msvcrt, wintypes, kernel

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _nt_api():
        nt = ctypes.WinDLL("ntdll")
        nt.NtCreateFile.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32,
                                    ctypes.POINTER(_WinObjectAttributes), ctypes.POINTER(_WinIoStatus),
                                    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
        nt.NtCreateFile.restype = ctypes.c_int32
        nt.NtSetInformationFile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_WinIoStatus),
                                           ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int32]
        nt.NtSetInformationFile.restype = ctypes.c_int32
        nt.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        nt.RtlNtStatusToDosError.restype = ctypes.c_uint32
        return nt

    @classmethod
    def _winerror(cls, code=None):
        if code is None:
            code = ctypes.get_last_error()
        error = {2: errno.ENOENT, 3: errno.ENOENT, 5: errno.EACCES,
                 32: errno.EACCES, 33: errno.EACCES, 80: errno.EEXIST,
                 183: errno.EEXIST, 145: errno.ENOTEMPTY, 267: errno.ENOTDIR,
                 17: errno.EXDEV}.get(code, errno.EIO)
        exc = OSError(error, f"Windows filesystem operation failed (error {code})")
        exc.winerror = code
        raise exc

    @classmethod
    def _ntcheck(cls, status):
        if status < 0:
            cls._winerror(cls._nt_api().RtlNtStatusToDosError(status))

    @staticmethod
    def _normal_path(path):
        """Canonical comparison spelling; never accepts the Win32 device namespace."""
        value = _os.fsdecode(path).replace("/", "\\")
        if value[:8].lower() == "\\\\?\\unc\\":
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        drive, tail = ntpath.splitdrive(value)
        unc_root = drive.startswith("\\\\") and not tail
        if (not drive or (not tail.startswith("\\") and not unc_root) or "\x00" in value
                or value.startswith("\\\\.\\") or drive.startswith("\\\\?")):
            raise OSError(errno.EINVAL, "filesystem path must be a DOS or UNC absolute path")
        if not (len(drive) == 2 and drive[1] == ":"):
            # Only a UNC server/share is permitted, never GLOBALROOT or NT devices.
            if (not drive.startswith("\\\\") or len(drive[2:].split("\\")) != 2
                    or not all(drive[2:].split("\\"))):
                raise OSError(errno.EINVAL, "unsupported Windows filesystem namespace")
        if unc_root:
            value += "\\"
        return ntpath.normcase(ntpath.normpath(value))

    @classmethod
    def _extended_path(cls, path):
        # Preserve the spelling used to create entries; comparison alone folds case.
        value = _os.fsdecode(path).replace("/", "\\")
        cls._normal_path(value)
        if value[:8].lower() == "\\\\?\\unc\\":
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        value = ntpath.normpath(value)
        if value.startswith("\\\\") and not ntpath.splitdrive(value)[1]:
            value += "\\"
        return "\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value

    @classmethod
    def _contained(cls, root, child):
        root, child = cls._normal_path(root), cls._normal_path(child)
        return child == root or child.startswith(root.rstrip("\\") + "\\")

    @staticmethod
    def _parts(path):
        value = _os.fsdecode(path).replace("/", "\\")
        if value == ".":
            return ()
        if not value or ntpath.splitdrive(value)[0] or value.startswith("\\"):
            raise OSError(errno.EINVAL, "dir_fd path must be relative")
        parts = tuple(value.split("\\"))
        for part in parts:
            stem = part.split(".")[0].upper()
            if (part in ("", ".", "..") or part.endswith((".", " "))
                    or any(c in '<>:"|?*' or ord(c) < 32 for c in part)
                    or stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                    or stem in {f"{kind}{n}" for kind in ("COM", "LPT") for n in "123456789¹²³"}):
                raise OSError(errno.EINVAL, "filesystem path escapes or aliases its retained directory")
        return parts

    @staticmethod
    def _reject_reparse(attributes, *, nofollow, directory):
        return bool(attributes & 0x400) and (nofollow or directory)

    @staticmethod
    def is_reparse_point(path):
        try:
            return bool(_os.lstat(path).st_file_attributes & 0x400)
        except FileNotFoundError:
            return False

    @classmethod
    def _information(cls, fd):
        _ctypes, msvcrt, wintypes, kernel = cls._api()
        info = _WinFileInformation()
        if not kernel.GetFileInformationByHandle(wintypes.HANDLE(msvcrt.get_osfhandle(int(fd))), ctypes.byref(info)):
            cls._winerror()
        return info

    @staticmethod
    def _file_identity(info):
        return int(info.VolumeSerialNumber), (int(info.FileIndexHigh) << 32) | int(info.FileIndexLow)

    @classmethod
    def _final_path(cls, fd):
        _ctypes, msvcrt, wintypes, kernel = cls._api()
        handle = msvcrt.get_osfhandle(int(fd))
        size = 512
        while True:
            buffer = ctypes.create_unicode_buffer(size)
            count = kernel.GetFinalPathNameByHandleW(wintypes.HANDLE(handle), buffer, size, 0)
            if not count:
                cls._winerror()
            if count < size:
                return buffer.value
            size = count + 1

    @classmethod
    def path_from_fd(cls, fd):
        """Display path only. Use pinned_path when an external API must reopen it."""
        return cls._final_path(fd)

    @classmethod
    def _verify_open(cls, fd, parent_fd, parent_path):
        after = cls._final_path(parent_fd)
        if (cls._normal_path(after) != cls._normal_path(parent_path)
                or not cls._contained(parent_path, cls._final_path(fd))):
            raise OSError(errno.EACCES, "filesystem handle escaped its pinned parent")

    @classmethod
    def _open_native(cls, path, flags, mode=0o666, *, dir_fd=None, access=None,
                     disposition=None, allow_reparse=False, share_delete=True):
        _ctypes, msvcrt, wintypes, kernel = cls._api()
        directory = bool(flags & cls.O_DIRECTORY)
        nofollow = bool(flags & cls.O_NOFOLLOW) or directory
        if access is None:
            # Use directory-specific rights for NT opens (list/traverse,
            # read attributes/EA/control and synchronize).
            access = (0x1200A9 if directory else
                      0x80000000 | 0x40000000 if flags & _os.O_RDWR else
                      0x40000000 if flags & _os.O_WRONLY else 0x80000000)
        access |= 0x80  # FILE_READ_ATTRIBUTES, also for write-only descriptors
        if disposition is None:
            disposition = 2 if flags & _os.O_CREAT and flags & _os.O_EXCL else 3 if flags & _os.O_CREAT else 1
        share = 0x1 | 0x2 | (0x4 if share_delete else 0)
        parent_path = cls._final_path(dir_fd) if dir_fd is not None else None
        if dir_fd is None:
            creation = {1: 3, 2: 1, 3: 4}[disposition]  # OPEN_EXISTING / CREATE_NEW / OPEN_ALWAYS
            attributes = 0x02000000 | (0x00200000 if nofollow else 0)  # BACKUP_SEMANTICS / OPEN_REPARSE_POINT
            handle = kernel.CreateFileW(str(path), access, share, None, creation, attributes, None)
            if handle == ctypes.c_void_p(-1).value:
                cls._winerror()
        else:
            # The NT namespace reopens RootDirectory with an empty name;
            # unlike Win32, it does not resolve a literal dot component.
            native_name = "" if str(path) == "." else str(path)
            byte_length = len(native_name.encode("utf-16-le"))
            if byte_length > 65532:
                raise OSError(errno.ENAMETOOLONG, "filesystem component is too long")
            text = ctypes.create_unicode_buffer(native_name)
            name = _WinUnicodeString(byte_length, byte_length + 2, ctypes.cast(text, ctypes.c_void_p))
            attrs = _WinObjectAttributes(ctypes.sizeof(_WinObjectAttributes), msvcrt.get_osfhandle(int(dir_fd)),
                                         ctypes.pointer(name), 0x40, None, None)
            status_block = _WinIoStatus()
            result = ctypes.c_void_p()
            # Synchronous handles are required by the CRT; traversals open the
            # reparse entry itself. Truncation is deliberately deferred below.
            options = 0x20 | 0x4000 | (0x200000 if nofollow else 0) | (0x1 if directory else 0)
            cls._ntcheck(cls._nt_api().NtCreateFile(ctypes.byref(result), access | 0x100000,
                         ctypes.byref(attrs), ctypes.byref(status_block), None, 0x80, share,
                         disposition, options, None, 0))
            handle = result.value
        descriptor = None
        try:
            descriptor_flags = flags & (_os.O_WRONLY | _os.O_RDWR | _os.O_APPEND)
            descriptor_flags |= getattr(_os, "O_BINARY", 0) | getattr(_os, "O_NOINHERIT", 0)
            descriptor = msvcrt.open_osfhandle(int(handle), descriptor_flags)
            handle = None
            info = cls._information(descriptor)
            if not allow_reparse and cls._reject_reparse(info.FileAttributes, nofollow=nofollow, directory=directory):
                raise OSError(errno.ELOOP, "reparse point is not allowed")
            if directory and not info.FileAttributes & 0x10:
                raise NotADirectoryError(errno.ENOTDIR, str(path))
            if dir_fd is not None:
                cls._verify_open(descriptor, dir_fd, parent_path)
            if flags & _os.O_TRUNC:
                _os.ftruncate(descriptor, 0)
            result_fd, descriptor = descriptor, None
            return result_fd
        finally:
            if descriptor is not None:
                _os.close(descriptor)
            if handle is not None:
                kernel.CloseHandle(wintypes.HANDLE(handle))

    @classmethod
    @contextmanager
    def _parent(cls, path, dir_fd=None):
        """Retain the actual parent, resolving one ordinary component at a time."""
        owned = []
        try:
            if dir_fd is None:
                value = _os.fsdecode(path)
                drive, tail = ntpath.splitdrive(value)
                if drive and not drive.startswith("\\\\") and not tail.startswith(("/", "\\")):
                    raise OSError(errno.EINVAL, "drive-relative paths are not supported")
                absolute = cls._extended_path(_os.path.abspath(value))
                drive, tail = ntpath.splitdrive(absolute)
                current = cls._open_native(drive + "\\", _os.O_RDONLY | cls.O_DIRECTORY | cls.O_NOFOLLOW)
                owned.append(current)
                parts = cls._parts(tail.lstrip("\\")) if tail.lstrip("\\") else ()
            else:
                # Keep transient parents immovable until the child operation
                # finishes, including each component of a multi-part name.
                current = cls._open_native(".", _os.O_RDONLY | cls.O_DIRECTORY | cls.O_NOFOLLOW,
                                           dir_fd=int(dir_fd), share_delete=False)
                owned.append(current)
                parts = cls._parts(path)
            root_path = cls._final_path(current)
            for component in parts[:-1]:
                current = cls._open_native(component, _os.O_RDONLY | cls.O_DIRECTORY | cls.O_NOFOLLOW,
                                           dir_fd=current, share_delete=False)
                owned.append(current)
                if not cls._contained(root_path, cls._final_path(current)):
                    raise OSError(errno.EACCES, "filesystem directory escaped its pinned root")
            yield current, parts[-1] if parts else "."
        finally:
            for fd in reversed(owned):
                _os.close(fd)

    @classmethod
    @contextmanager
    def pinned_path(cls, fd):
        """Lock every lexical ancestor while SQLite/another path-only API runs."""
        path = cls._final_path(fd)
        drive, tail = ntpath.splitdrive(cls._extended_path(path))
        owned = []
        try:
            current = cls._open_native(drive + "\\", _os.O_RDONLY | cls.O_DIRECTORY | cls.O_NOFOLLOW,
                                       share_delete=False)
            owned.append(current)
            for component in cls._parts(tail.lstrip("\\")) if tail.lstrip("\\") else ():
                current = cls._open_native(component, _os.O_RDONLY | cls.O_DIRECTORY | cls.O_NOFOLLOW,
                                           dir_fd=current, share_delete=False)
                owned.append(current)
            if (cls._file_identity(cls._information(current)) != cls._file_identity(cls._information(fd))
                    or cls._normal_path(cls._final_path(fd)) != cls._normal_path(path)):
                raise OSError(errno.EACCES, "filesystem lexical directory identity changed")
            yield path
        finally:
            for descriptor in reversed(owned):
                _os.close(descriptor)

    @classmethod
    @contextmanager
    def create_file_path_at(cls, directory_fd, name):
        """Create and pin a fresh file for SQLite's path-only writer.

        Locking only the directory leaves the final entry replaceable by a
        reparse point before SQLite opens it. This handle denies deletion of
        that entry until the external writer has closed its connection.
        """
        with cls._parent(name, directory_fd) as (parent, leaf):
            fd = cls._open_native(leaf, _os.O_RDWR | _os.O_CREAT | _os.O_EXCL | cls.O_NOFOLLOW,
                                  dir_fd=parent, share_delete=False)
            try:
                with cls.pinned_path(parent) as root:
                    yield ntpath.join(root, leaf)
            finally:
                _os.close(fd)

    @classmethod
    @contextmanager
    def _resolved(cls, path, dir_fd=None):
        with cls._parent(path, dir_fd) as (parent, name), cls.pinned_path(parent) as root:
            yield ntpath.join(root, name)

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        with self._parent(path, dir_fd) as (parent, name):
            return self._open_native(name, flags, mode, dir_fd=parent)

    @classmethod
    def fstat(cls, fd):
        value = _os.fstat(fd)
        info = cls._information(fd)
        fields = list(value)
        fields[1], fields[2] = cls._file_identity(info)[1], cls._file_identity(info)[0]
        fields[0] = ((stat.S_IFLNK if info.FileAttributes & 0x400 else
                      stat.S_IFDIR if info.FileAttributes & 0x10 else stat.S_IFREG)
                     | stat.S_IMODE(value.st_mode))
        extra = {key: getattr(value, key) for key in ("st_atime", "st_mtime", "st_ctime",
                 "st_atime_ns", "st_mtime_ns", "st_ctime_ns", "st_birthtime", "st_birthtime_ns",
                 "st_reparse_tag") if hasattr(value, key)}
        if hasattr(value, "st_file_attributes"):
            extra["st_file_attributes"] = int(info.FileAttributes)
        return _os.stat_result(fields, extra)

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if isinstance(path, int):
            return self.fstat(path)
        with self._parent(path, dir_fd) as (parent, name):
            fd = self._open_native(name, 0 if follow_symlinks else self.O_NOFOLLOW,
                                   dir_fd=parent, access=0x80, allow_reparse=not follow_symlinks)
            try:
                return self.fstat(fd)
            finally:
                _os.close(fd)

    def lstat(self, path, *, dir_fd=None):
        return self.stat(path, dir_fd=dir_fd, follow_symlinks=False)

    def mkdir(self, path, mode=0o777, *, dir_fd=None):
        with self._parent(path, dir_fd) as (parent, name):
            fd = self._open_native(name, self.O_DIRECTORY | self.O_NOFOLLOW, mode,
                                   dir_fd=parent, disposition=2)
            _os.close(fd)

    @classmethod
    def _set_information(cls, fd, info, information_class, size=None):
        _ctypes, msvcrt, _wintypes, _kernel = cls._api()
        status_block = _WinIoStatus()
        cls._ntcheck(cls._nt_api().NtSetInformationFile(msvcrt.get_osfhandle(int(fd)),
                     ctypes.byref(status_block), ctypes.byref(info), size or ctypes.sizeof(info), information_class))

    def _delete(self, path, *, dir_fd=None, directory=False):
        with self._parent(path, dir_fd) as (parent, name):
            if name == ".":
                raise OSError(errno.EINVAL, "cannot remove a retained parent")
            fd = self._open_native(name, self.O_NOFOLLOW, dir_fd=parent, access=0x10000, allow_reparse=True)
            try:
                attributes = self._information(fd).FileAttributes
                if ((directory and not attributes & 0x10)
                        or (not directory and attributes & 0x10 and not attributes & 0x400)):
                    error = NotADirectoryError if directory else IsADirectoryError
                    raise error(errno.ENOTDIR if directory else errno.EISDIR, str(path))
                self._set_information(fd, ctypes.c_ubyte(1), 13)  # FileDispositionInformation
            finally:
                _os.close(fd)

    def unlink(self, path, *, dir_fd=None):
        return self._delete(path, dir_fd=dir_fd)

    remove = unlink

    def rmdir(self, path, *, dir_fd=None):
        return self._delete(path, dir_fd=dir_fd, directory=True)

    def _move(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None, link=False, follow_symlinks=False,
              replace=False):
        with self._parent(src, src_dir_fd) as (source_parent, source_name), self._parent(dst, dst_dir_fd) as (parent, name):
            if source_name == "." or name == ".":
                raise OSError(errno.EINVAL, "cannot rename or link a retained parent")
            fd = self._open_native(source_name, 0 if follow_symlinks else self.O_NOFOLLOW,
                                   dir_fd=source_parent, access=0x80 if link else 0x10000,
                                   allow_reparse=not follow_symlinks)
            try:
                # The destination is an NT name below the retained directory;
                # replacing a reparse entry never follows that entry's target.
                data = name.encode("utf-16-le")
                buffer = ctypes.create_string_buffer(ctypes.sizeof(_WinNameInformation) + len(data))
                info = (_WinNameInformationEx if replace and not link else _WinNameInformation).from_buffer(buffer)
                if replace and not link:
                    info.Flags = 0x1 | 0x2  # REPLACE_IF_EXISTS | POSIX_SEMANTICS
                else:
                    info.ReplaceIfExists = False
                info.RootDirectory = self._api()[1].get_osfhandle(int(parent))
                info.FileNameLength = len(data)
                ctypes.memmove(ctypes.addressof(buffer) + _WinNameInformation.FileName.offset, data, len(data))
                operation = lambda: self._set_information(fd, buffer, 11 if link else (65 if replace else 10))
                if replace and not link:
                    try:
                        _retry_windows_sharing_violation(operation)
                    except OSError as error:
                        # SMB and older filesystems may reject the extended class.
                        # The legacy handle-relative operation remains atomic; if
                        # an open destination blocks replacement it fails closed.
                        if getattr(error, "winerror", None) not in (50, 87):
                            raise
                        legacy = _WinNameInformation.from_buffer(buffer)
                        legacy.ReplaceIfExists = True
                        _retry_windows_sharing_violation(lambda: self._set_information(fd, buffer, 10))
                else:
                    operation()
            finally:
                _os.close(fd)

    def rename(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        return self._move(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    def replace(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        return self._move(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd, replace=True)

    def link(self, src, dst, *, src_dir_fd=None, dst_dir_fd=None, follow_symlinks=True):
        return self._move(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd,
                          link=True, follow_symlinks=follow_symlinks)

    def readlink(self, path, *, dir_fd=None):
        # No target traversal: the path-only API sees a locked ancestor chain.
        with self._resolved(path, dir_fd) as target:
            return _os.readlink(target)

    def symlink(self, src, dst, target_is_directory=False, *, dir_fd=None):
        with self._resolved(dst, dir_fd) as target:
            return _os.symlink(src, target, target_is_directory=target_is_directory)

    def chmod(self, path, mode, *, dir_fd=None, follow_symlinks=True):
        # POSIX modes do not configure Windows ACLs; see platform.owner_only.
        return None

    @staticmethod
    def fchmod(fd, mode):
        return None

    def scandir(self, path="."):
        return _WindowsScandir(self, path)

    def listdir(self, path="."):
        with self.scandir("." if path is None else path) as entries:
            return [entry.name for entry in entries]

    @classmethod
    def fsync(cls, fd):
        # Windows cannot flush directory handles. File flush errors still fail.
        if not cls._information(fd).FileAttributes & 0x10:
            _os.fsync(fd)


class _WinUnicodeString(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_uint16), ("MaximumLength", ctypes.c_uint16), ("Buffer", ctypes.c_void_p)]


class _WinObjectAttributes(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_uint32), ("RootDirectory", ctypes.c_void_p),
                ("ObjectName", ctypes.POINTER(_WinUnicodeString)), ("Attributes", ctypes.c_uint32),
                ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p)]


class _WinIoStatus(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


class _WinNameInformation(ctypes.Structure):
    _fields_ = [("ReplaceIfExists", ctypes.c_ubyte), ("RootDirectory", ctypes.c_void_p),
                ("FileNameLength", ctypes.c_uint32), ("FileName", ctypes.c_uint16 * 1)]


class _WinNameInformationEx(ctypes.Structure):
    _fields_ = [("Flags", ctypes.c_uint32), ("RootDirectory", ctypes.c_void_p),
                ("FileNameLength", ctypes.c_uint32), ("FileName", ctypes.c_uint16 * 1)]


class _WinFileInformation(ctypes.Structure):
    _fields_ = [("FileAttributes", ctypes.c_uint32), ("Times", ctypes.c_uint32 * 6),
                ("VolumeSerialNumber", ctypes.c_uint32), ("FileSizeHigh", ctypes.c_uint32),
                ("FileSizeLow", ctypes.c_uint32), ("NumberOfLinks", ctypes.c_uint32),
                ("FileIndexHigh", ctypes.c_uint32), ("FileIndexLow", ctypes.c_uint32)]


class _WinDirectoryInformation(ctypes.Structure):
    _fields_ = [("NextEntryOffset", ctypes.c_uint32), ("FileIndex", ctypes.c_uint32),
                ("CreationTime", ctypes.c_int64), ("LastAccessTime", ctypes.c_int64),
                ("LastWriteTime", ctypes.c_int64), ("ChangeTime", ctypes.c_int64),
                ("EndOfFile", ctypes.c_int64), ("AllocationSize", ctypes.c_int64),
                ("FileAttributes", ctypes.c_uint32), ("FileNameLength", ctypes.c_uint32),
                ("EaSize", ctypes.c_uint32), ("ShortNameLength", ctypes.c_ubyte),
                ("ShortName", ctypes.c_uint16 * 12), ("FileId", ctypes.c_int64),
                ("FileName", ctypes.c_uint16 * 1)]


class _WindowsDirEntry:
    def __init__(self, root, name, info, volume):
        self.name = name
        self.path = ntpath.join(root, name)
        mode = stat.S_IFLNK if info.FileAttributes & 0x400 else stat.S_IFDIR if info.FileAttributes & 0x10 else stat.S_IFREG
        times = [(getattr(info, key) - 116444736000000000) * 100 for key in
                 ("LastAccessTime", "LastWriteTime", "CreationTime")]
        permissions = 0o777 if info.FileAttributes & 0x10 else 0o666
        if info.FileAttributes & 0x1:
            permissions &= ~0o222
        self._stat = _os.stat_result((mode | permissions, info.FileId & ((1 << 64) - 1), volume,
                                      1, 0, 0, info.EndOfFile, *(v / 1e9 for v in times)),
                                     dict(zip(("st_atime_ns", "st_mtime_ns", "st_ctime_ns"), times)))

    def __fspath__(self):
        return self.path

    def stat(self, *, follow_symlinks=True):
        if follow_symlinks and self.is_symlink():
            raise OSError(errno.ELOOP, "reparse point is not allowed")
        return self._stat

    def inode(self):
        return self._stat.st_ino

    def is_symlink(self):
        return stat.S_ISLNK(self._stat.st_mode)

    def is_dir(self, *, follow_symlinks=True):
        return stat.S_ISDIR(self.stat(follow_symlinks=follow_symlinks).st_mode)

    def is_file(self, *, follow_symlinks=True):
        return stat.S_ISREG(self.stat(follow_symlinks=follow_symlinks).st_mode)


class _WindowsScandir:
    """Enumerate through a handle, including metadata, without an absolute reopen."""

    def __init__(self, filesystem, path):
        self._filesystem = filesystem
        flags = _os.O_RDONLY | filesystem.O_DIRECTORY | filesystem.O_NOFOLLOW
        self._fd = (filesystem.open(".", flags, dir_fd=path) if isinstance(path, int)
                    else filesystem.open(path, flags))
        self._iterator = self._entries()

    def _entries(self):
        fs = self._filesystem
        _ctypes, msvcrt, wintypes, kernel = fs._api()
        try:
            volume = fs._information(self._fd).VolumeSerialNumber
            root = fs._final_path(self._fd)
            buffer = ctypes.create_string_buffer(65536)
            first = True
            while True:
                ok = kernel.GetFileInformationByHandleEx(wintypes.HANDLE(msvcrt.get_osfhandle(self._fd)),
                                                         11 if first else 10, buffer, len(buffer))
                first = False
                if not ok:
                    code = ctypes.get_last_error()
                    if code == 18:  # ERROR_NO_MORE_FILES
                        return
                    fs._winerror(code)
                offset = 0
                while True:
                    info = _WinDirectoryInformation.from_buffer(buffer, offset)
                    start = offset + _WinDirectoryInformation.FileName.offset
                    name = buffer.raw[start:start + info.FileNameLength].decode("utf-16-le")
                    if name not in (".", ".."):
                        yield _WindowsDirEntry(root, name, info, volume)
                    if not info.NextEntryOffset:
                        break
                    offset += info.NextEntryOffset
        finally:
            self.close()

    def __iter__(self):
        return self

    def __next__(self):
        if self._fd is None:
            raise StopIteration
        return next(self._iterator)

    def close(self):
        if getattr(self, "_fd", None) is not None:
            _os.close(self._fd)
            self._fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):  # pragma: no cover - interpreter cleanup
        self.close()

filesystem = _WindowsFilesystem() if _os.name == "nt" else _os
os = filesystem


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
# Ancestors are only traversed, so Linux opens them with O_PATH: no read
# permission is needed (Landlock sandboxes, mode 0711 homes), and O_DIRECTORY
# plus O_NOFOLLOW still reject a symlinked component.
_WALK_FLAGS = (os.O_PATH | getattr(os, "O_DIRECTORY", 0) | _os.O_NOFOLLOW
               if hasattr(_os, "O_PATH") and _os.name != "nt" else _DIR_FLAGS)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def has_symlink_component(value: str | Path) -> bool:
    path = absolute_path(value)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            if getattr(os, "is_reparse_point", Path.is_symlink)(current):
                return True
        except OSError as exc:
            raise ConflictError(f"filesystem path cannot be inspected safely: {path}") from exc
    return False


def open_directory_chain(value: str | Path) -> int:
    """Open every lexical component with O_NOFOLLOW, retaining the leaf fd."""
    path = absolute_path(value)
    parts = path.parts[1:]
    fd = os.open(path.anchor, _WALK_FLAGS if parts else _DIR_FLAGS)
    try:
        for index, component in enumerate(parts):
            flags = _DIR_FLAGS if index == len(parts) - 1 else _WALK_FLAGS
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


class PinnedParent(dict):
    """Mapping-compatible identity which owns a retained parent descriptor."""

    __slots__ = ("_parent_fd",)

    def __init__(self, value: Mapping[str, Any], parent_fd: int):
        super().__init__(value)
        self._parent_fd = parent_fd

    def get(self, key, default=None):
        if key == "_parent_fd":
            return self._parent_fd
        return super().get(key, default)

    def __getitem__(self, key):
        if key == "_parent_fd":
            return self._parent_fd
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        if key == "_parent_fd":
            self._parent_fd = value
        else:
            super().__setitem__(key, value)

    def __del__(self):  # pragma: no cover - interpreter cleanup
        fd = getattr(self, "_parent_fd", None)
        if fd is not None:
            try:
                os.close(int(fd))
            except OSError:
                pass


def close_pinned(identity: Mapping[str, Any] | None) -> None:
    if not isinstance(identity, Mapping):
        return
    fd = identity.get("_parent_fd")
    if fd is None:
        return
    try:
        os.close(int(fd))
    except OSError:
        pass
    try:
        identity["_parent_fd"] = None  # type: ignore[index]
    except (TypeError, AttributeError):
        pass


def _relative_parts(value: str | Path, *, allow_dot: bool = False) -> tuple[str, ...]:
    path = Path(value)
    if path.is_absolute():
        raise ConflictError("relative filesystem path must not be absolute")
    parts = tuple(path.parts)
    if not parts and not allow_dot:
        raise ConflictError("relative filesystem path is empty")
    if any(part in ("..", os.curdir) for part in parts):
        raise ConflictError("relative filesystem path escapes its pinned parent")
    return parts


def _leaf_name(value: str | Path) -> str:
    text = os.fspath(value)
    if not text or Path(text).name != text or text in (".", ".."):
        raise ConflictError("filesystem entry name must be one direct child")
    return text


def read_bytes_at(directory_fd: int, name: str | Path) -> bytes:
    """Read one regular file below a retained directory descriptor."""
    fd = os.open(_leaf_name(name), os.O_RDONLY | _NOFOLLOW, dir_fd=int(directory_fd))
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise ConflictError(f"filesystem entry is not a regular file: {name}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_json_at(directory_fd: int, name: str | Path) -> Any:
    """Decode JSON from a descriptor-relative regular file."""
    try:
        value = json.loads(read_bytes_at(directory_fd, name).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConflictError(f"filesystem JSON artifact is invalid: {name}") from exc
    return value


def sha256_at(directory_fd: int, name: str | Path) -> tuple[str, int]:
    """Hash one descriptor-relative regular file and return digest and size."""
    fd = os.open(_leaf_name(name), os.O_RDONLY | _NOFOLLOW, dir_fd=int(directory_fd))
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode):
            raise ConflictError(f"filesystem entry is not a regular file: {name}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest(), int(value.st_size)
    finally:
        os.close(fd)


def _nearest_existing(path: Path) -> tuple[Path, bool]:
    parent = path
    while not os.path.lexists(str(parent)):
        if parent == parent.parent:
            raise ConflictError(f"filesystem path has no existing parent: {path}")
        parent = parent.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ConflictError(f"filesystem path parent is not an ordinary directory: {parent}")
    return parent, parent != path


def capture_parent(path: str | Path, *, require_fresh_target: bool = False) -> PinnedParent:
    """Capture the nearest existing parent and retain its descriptor."""
    target = absolute_path(path)
    if has_symlink_component(target):
        raise ConflictError(f"filesystem path contains a symlink component: {target}")
    if require_fresh_target and os.path.lexists(str(target)):
        raise ConflictError(f"filesystem target must be fresh: {target}")
    parent, was_missing = _nearest_existing(target.parent)
    fd = open_directory_chain(parent)
    try:
        identity = os.fstat(fd)
    except Exception:
        os.close(fd)
        raise
    if not stat.S_ISDIR(identity.st_mode):
        os.close(fd)
        raise ConflictError(f"filesystem parent is not an ordinary directory: {parent}")
    return PinnedParent({
        "path": str(target),
        "parent": str(parent),
        "target_parent": str(target.parent),
        "parent_was_missing": bool(was_missing),
        "parent_st_dev": int(identity.st_dev),
        "parent_st_ino": int(identity.st_ino),
        "parent_st_mode": int(identity.st_mode),
    }, fd)


def pin_directory(path: str | Path) -> tuple[PinnedParent, int, os.stat_result]:
    """Retain a directory's parent and directory fd for verified source reads."""
    target = absolute_path(path)
    identity = capture_parent(target)
    parent_fd = int(identity.get("_parent_fd"))
    try:
        if target.parent == Path(str(identity["parent"])):
            root_fd = os.open(target.name, _DIR_FLAGS, dir_fd=parent_fd)
        else:
            # The path shape is unusual (missing ancestors), but capture_parent
            # has retained the nearest ancestor and O_NOFOLLOW remains in force
            # for every component.
            relative = target.relative_to(Path(str(identity["parent"])))
            root_fd = os.open(str(relative), _DIR_FLAGS, dir_fd=parent_fd)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            os.close(root_fd)
            raise ConflictError(f"filesystem target is not an ordinary directory: {target}")
        return identity, root_fd, root_stat
    except Exception:
        close_pinned(identity)
        raise


def _identity_tuple(value: os.stat_result) -> tuple[int, int, int]:
    return int(value.st_dev), int(value.st_ino), int(value.st_mode)


def validate_parent(path: str | Path, identity: Mapping[str, Any], *, allow_parent_appeared: bool = False) -> int:
    """Validate both retained and lexical parent identity; return retained fd."""
    target = absolute_path(path)
    if identity.get("path") != str(target) or identity.get("target_parent") != str(target.parent):
        raise ConflictError(f"filesystem path identity changed: {target}")
    if has_symlink_component(target):
        raise ConflictError(f"filesystem path contains a symlink component: {target}")
    parent_fd = identity.get("_parent_fd")
    if parent_fd is None:
        raise ConflictError(f"filesystem path has no retained parent descriptor: {target}")
    try:
        retained = os.fstat(int(parent_fd))
    except OSError as exc:
        raise ConflictError(f"filesystem parent descriptor is unavailable: {target.parent}") from exc
    expected_values = []
    for key in ("st_dev", "st_ino", "st_mode"):
        value = identity.get(f"parent_{key}")
        if value is None:
            value = identity.get(key)
        expected_values.append(int(value))
    expected = tuple(expected_values)
    if _identity_tuple(retained) != expected or not stat.S_ISDIR(retained.st_mode):
        raise ConflictError(f"filesystem retained parent identity changed: {target.parent}")
    # This catches an ordinary directory replacement as well as a symlink.
    if not bool(identity.get("parent_was_missing")):
        try:
            named = os.stat(target.parent, follow_symlinks=False)
        except OSError as exc:
            raise ConflictError(f"filesystem lexical parent changed: {target.parent}") from exc
        if _identity_tuple(named) != expected or not stat.S_ISDIR(named.st_mode):
            raise ConflictError(f"filesystem lexical parent identity changed: {target.parent}")
    if bool(identity.get("parent_was_missing")) and os.path.lexists(str(target.parent)) and not allow_parent_appeared:
        raise ConflictError(f"filesystem target parent appeared after capture: {target.parent}")
    if not bool(identity.get("parent_was_missing")) and not os.path.lexists(str(target.parent)):
        raise ConflictError(f"filesystem target parent disappeared after capture: {target.parent}")
    return int(parent_fd)


def validate_created_parent(path: str | Path, identity: Mapping[str, Any], final_parent_fd: int) -> int:
    """Validate a target whose missing parent chain was created below a pin.

    ``validate_parent`` intentionally rejects a newly appeared lexical parent
    unless explicitly allowed.  Writers that intentionally create that chain
    use this stricter variant: it permits the appearance only when the name
    resolves to the exact descriptor returned by ``ensure_parent_at``.
    """
    target = absolute_path(path)
    validate_parent(target, identity, allow_parent_appeared=True)
    if identity.get("parent_was_missing"):
        try:
            named = os.stat(target.parent, follow_symlinks=False)
            retained = os.fstat(int(final_parent_fd))
        except OSError as exc:
            raise ConflictError(f"filesystem created parent cannot be verified: {target.parent}") from exc
        if _identity_tuple(named) != _identity_tuple(retained) or not stat.S_ISDIR(named.st_mode):
            raise ConflictError(f"filesystem created parent identity changed: {target.parent}")
    else:
        validate_parent(target, identity)
    return int(final_parent_fd)


def mkdir_chain_at(parent_fd: int, relative: str | Path, mode: int = 0o700) -> int:
    """Create/open a relative directory chain below ``parent_fd``."""
    parts = _relative_parts(relative, allow_dot=True)
    current_fd = os.dup(parent_fd)
    try:
        for component in parts:
            try:
                os.mkdir(component, mode, dir_fd=current_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, _DIR_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def ensure_parent_at(path: str | Path, identity: Mapping[str, Any]) -> tuple[int, str]:
    """Return the fd/name pair used for a target, creating missing components."""
    target = absolute_path(path)
    parent_fd = validate_parent(target, identity)
    parent = Path(str(identity["parent"]))
    if target.parent == parent:
        return parent_fd, target.name
    # A missing target parent is created only below the retained nearest
    # ancestor.  The lexical missing-shape check above prevents an attacker
    # from supplying a replacement before this operation.
    relative = target.parent.relative_to(parent)
    child_fd = mkdir_chain_at(parent_fd, relative)
    return child_fd, target.name


def ensure_directory(path: str | Path, *, mode: int = 0o700) -> PinnedParent:
    """Create a directory securely and return a retained identity for it."""
    target = absolute_path(path)
    identity = capture_parent(target)
    parent_fd, name = ensure_parent_at(target, identity)
    try:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        child_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode):
            raise ConflictError(f"filesystem target is not an ordinary directory: {target}")
        os.fsync(parent_fd)
        # Keep the target descriptor as the retained parent for callers that
        # will write children.  Preserve the lexical identity fields for the
        # target itself.
        result = PinnedParent({
            "path": str(target),
            "parent": str(target.parent),
            "target_parent": str(target.parent),
            "parent_was_missing": False,
            "parent_st_dev": int(child_stat.st_dev),
            "parent_st_ino": int(child_stat.st_ino),
            "parent_st_mode": int(child_stat.st_mode),
        }, child_fd)
        close_pinned(identity)
        return result
    except Exception:
        try:
            if parent_fd != identity.get("_parent_fd"):
                os.close(parent_fd)
        finally:
            close_pinned(identity)
        raise
    finally:
        if parent_fd != identity.get("_parent_fd"):
            try:
                os.close(parent_fd)
            except OSError:
                pass


def mkdir_temp_at(parent_fd: int, prefix: str, *, mode: int = 0o700) -> tuple[str, int]:
    for attempt in range(100):
        name = f"{prefix}{os.getpid()}-{time.time_ns()}-{attempt}"
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            return name, os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except Exception:
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise ConflictError("temporary filesystem directory could not be allocated")


def write_bytes_at(directory_fd: int, name: str, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically publish bytes as a direct child of a pinned directory."""
    name = _leaf_name(name)
    temp_name = f".{name}.{os.getpid()}-{time.time_ns()}.tmp"
    fd = -1
    try:
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, mode, dir_fd=directory_fd)
        view = memoryview(bytes(data))
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        filesystem.replace(temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name, dir_fd=directory_fd)
        except OSError:
            pass
        raise


def copy_file_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, replace: bool = False) -> None:
    _relative_parts(source_name)
    destination_name = _leaf_name(destination_name)
    source = os.open(source_name, os.O_RDONLY | _NOFOLLOW, dir_fd=source_fd)
    destination = -1
    try:
        source_stat = os.fstat(source)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ConflictError(f"filesystem source is not a regular file: {source_name}")
        flags = os.O_WRONLY | os.O_CREAT | (_NOFOLLOW if not replace else 0)
        if not replace:
            flags |= os.O_EXCL
        destination = os.open(destination_name, flags, stat.S_IRUSR | stat.S_IWUSR, dir_fd=destination_fd)
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination, view)
                view = view[written:]
        os.fchmod(destination, stat.S_IMODE(source_stat.st_mode))
        os.fsync(destination)
    finally:
        try:
            os.close(source)
        finally:
            if destination >= 0:
                os.close(destination)


def copy_tree_at(source_fd: int, source_name: str, destination_fd: int, destination_name: str, *, preserve_symlinks: bool = False) -> None:
    """Copy a directory tree below retained descriptors.

    Runtime backup/restore trees reject symlinks.  The offline source archive
    is the one deliberate exception: it preserves source symlinks as literal
    directory entries, without ever following them.
    """
    _relative_parts(source_name, allow_dot=True)
    destination_name = _leaf_name(destination_name)
    source = os.open(source_name, _DIR_FLAGS, dir_fd=source_fd)
    try:
        os.mkdir(destination_name, 0o700, dir_fd=destination_fd)
        destination = os.open(destination_name, _DIR_FLAGS, dir_fd=destination_fd)
        try:
            for entry in os.scandir(source):
                name = entry.name
                entry_stat = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(entry_stat.st_mode):
                    if not preserve_symlinks:
                        raise ConflictError(f"filesystem source contains a symlink: {source_name}/{name}")
                    os.symlink(os.readlink(name, dir_fd=source), name, dir_fd=destination)
                elif stat.S_ISDIR(entry_stat.st_mode):
                    copy_tree_at(source, name, destination, name, preserve_symlinks=preserve_symlinks)
                elif stat.S_ISREG(entry_stat.st_mode):
                    copy_file_at(source, name, destination, name)
                else:
                    raise ConflictError(f"filesystem source contains unsupported entry: {source_name}/{name}")
            os.fsync(destination)
        finally:
            os.close(destination)
    finally:
        os.close(source)


def remove_tree_at(parent_fd: int, name: str) -> None:
    name = _leaf_name(name)
    try:
        child = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    try:
        for entry in os.scandir(child):
            entry_stat = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(entry_stat.st_mode):
                remove_tree_at(child, entry.name)
            elif stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
                os.unlink(entry.name, dir_fd=child)
            else:
                raise ConflictError(f"filesystem tree contains unsupported entry: {name}/{entry.name}")
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent_fd)


def atomic_json_write(path: str | Path, encoded: bytes, *, identity: Mapping[str, Any] | None = None) -> None:
    """Write bytes atomically below a retained parent and fsync the directory."""
    target = absolute_path(path)
    own = identity is None
    identity = identity or capture_parent(target)
    child_fd = -1
    temp_name = None
    try:
        parent_fd, name = ensure_parent_at(target, identity)
        child_fd = parent_fd if parent_fd != identity.get("_parent_fd") else -1
        base_fd = parent_fd
        temp_name = f".{name}.{os.getpid()}-{time.time_ns()}.tmp"
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=base_fd)
        try:
            platform.owner_only(fd)
            view = memoryview(bytes(encoded))
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        # Parent identity is checked immediately before publication.  The
        # rename remains relative even if a concurrent swap occurs in the
        # monkeypatched syscall itself.
        validate_created_parent(target, identity, base_fd)
        filesystem.replace(temp_name, name, src_dir_fd=base_fd, dst_dir_fd=base_fd)
        os.fsync(base_fd)
        try:
            # A last lexical check turns an in-flight ordinary replacement into
            # a typed failure while the actual rename remains in the pinned
            # directory and can never land in the replacement tree.
            validate_created_parent(target, identity, base_fd)
        except Exception:
            raise
    except Exception:
        if temp_name is not None:
            try:
                base_fd = locals().get("base_fd", -1)
                if base_fd >= 0:
                    os.unlink(temp_name, dir_fd=base_fd)
            except OSError:
                pass
        raise
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if own:
            close_pinned(identity)


__all__ = ["filesystem", "PinnedParent", "absolute_path", "has_symlink_component", "open_directory_chain", "capture_parent", "pin_directory", "close_pinned", "validate_parent", "validate_created_parent", "mkdir_chain_at", "ensure_parent_at", "ensure_directory", "mkdir_temp_at", "write_bytes_at", "copy_file_at", "copy_tree_at", "remove_tree_at", "atomic_json_write"]
