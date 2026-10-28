"""M1 Windows credential security, independent of the M2 dir-fd adapter.

Only the current token user and SYSTEM receive access. All admissions use
GetSecurityInfo on the retained handle, including the handle whose bytes are
read. Reparse points, foreign owners, NULL/unprotected DACLs and unfamiliar
ACEs fail closed. No profile-location assumption grants access.
"""
from contextlib import contextmanager
import ctypes
from ctypes import wintypes as w
from functools import lru_cache
import errno
import os
from pathlib import Path
import secrets

P = ctypes.c_void_p
READ_CONTROL = 0x20000
WRITE_DAC = 0x40000


class _Attributes(ctypes.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", P), ("inherit", w.BOOL)]


class _FileInfo(ctypes.Structure):
    _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
               ("accessed", w.FILETIME), ("written", w.FILETIME),
               ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD),
               ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]


class _Acl(ctypes.Structure):
    _fields_ = [("revision", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte),
               ("size", w.WORD), ("count", w.WORD), ("reserved2", w.WORD)]


@lru_cache(maxsize=1)
def _api():
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "OpenProcessToken": ([w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL),
        "GetTokenInformation": ([w.HANDLE, ctypes.c_int, P, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL),
        "GetLengthSid": ([P], w.DWORD),
        "EqualSid": ([P, P], w.BOOL),
        "IsValidSid": ([P], w.BOOL),
        "IsValidAcl": ([P], w.BOOL),
        "ConvertSidToStringSidW": ([P, ctypes.POINTER(w.LPWSTR)], w.BOOL),
        "ConvertStringSecurityDescriptorToSecurityDescriptorW": ([w.LPCWSTR, w.DWORD, ctypes.POINTER(P), P], w.BOOL),
        "GetSecurityInfo": ([w.HANDLE, ctypes.c_int, w.DWORD, ctypes.POINTER(P), P, ctypes.POINTER(P), P, ctypes.POINTER(P)], w.DWORD),
        "GetSecurityDescriptorDacl": ([P, ctypes.POINTER(w.BOOL), ctypes.POINTER(P), ctypes.POINTER(w.BOOL)], w.BOOL),
        "GetSecurityDescriptorControl": ([P, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)], w.BOOL),
        "SetSecurityInfo": ([w.HANDLE, ctypes.c_int, w.DWORD, P, P, P, P], w.DWORD),
        "GetAce": ([P, w.DWORD, ctypes.POINTER(P)], w.BOOL),
    }
    for name, (args, result) in signatures.items():
        function = getattr(adv, name)
        function.argtypes, function.restype = args, result
    for name, args, result in (
        ("GetCurrentProcess", [], w.HANDLE),
        ("CloseHandle", [w.HANDLE], w.BOOL),
        ("LocalFree", [P], P),
        ("CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, P, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        ("CreateDirectoryW", [w.LPCWSTR, P], w.BOOL),
        ("GetFileInformationByHandle", [w.HANDLE, ctypes.POINTER(_FileInfo)], w.BOOL),
        ("ReOpenFile", [w.HANDLE, w.DWORD, w.DWORD, w.DWORD], w.HANDLE),
        ("ReadFile", [w.HANDLE, P, w.DWORD, ctypes.POINTER(w.DWORD), P], w.BOOL),
    ):
        function = getattr(kernel, name)
        function.argtypes, function.restype = args, result
    return adv, kernel


def _check(value):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


def _unsafe(reason):
    raise PermissionError(errno.EACCES, "unsafe Windows owner/DACL: " + reason)


def _token_sid(information_class):
    adv, kernel = _api()
    token = w.HANDLE()
    _check(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
    try:
        size = w.DWORD()
        adv.GetTokenInformation(token, information_class, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        _check(adv.GetTokenInformation(token, information_class, buffer, size, ctypes.byref(size)))
        sid = ctypes.cast(buffer, ctypes.POINTER(P))[0]
        _check(adv.IsValidSid(sid))
        return ctypes.create_string_buffer(ctypes.string_at(sid, adv.GetLengthSid(sid)))
    finally:
        kernel.CloseHandle(token)


def _user_sid():
    return _token_sid(1)  # TokenUser


def _default_owner_sid():
    return _token_sid(4)  # TokenOwner


def _sid_text(sid):
    adv, kernel = _api()
    text = w.LPWSTR()
    _check(adv.ConvertSidToStringSidW(sid, ctypes.byref(text)))
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, P))


@contextmanager
def _descriptor(sddl):
    adv, kernel = _api()
    descriptor = P()
    _check(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None))
    try:
        yield descriptor
    finally:
        kernel.LocalFree(descriptor)


def _private_sddl(directory=False):
    sid = _sid_text(_user_sid())
    flags = "OICI" if directory else ""
    return f"O:{sid}D:P(A;{flags};FA;;;{sid})(A;{flags};FA;;;SY)"


@contextmanager
def _handle(path_or_fd, *, write_dac=False, read=False):
    adv, kernel = _api()
    own = not isinstance(path_or_fd, int)
    if own:
        # No FILE_SHARE_DELETE: neither the opened object nor a retained
        # parent can be replaced while its descriptor is being trusted.
        access = READ_CONTROL | (WRITE_DAC if write_dac else 0) | (0x80000000 if read else 0)
        handle = kernel.CreateFileW(str(Path(path_or_fd).absolute()), access, 3, None, 3, 0x02200000, None)
        if handle == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        import msvcrt
        handle = msvcrt.get_osfhandle(path_or_fd)
        if write_dac:
            handle = kernel.ReOpenFile(handle, READ_CONTROL | WRITE_DAC, 3, 0x02200000)
            if handle == w.HANDLE(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            own = True
    try:
        info = _FileInfo()
        _check(kernel.GetFileInformationByHandle(handle, ctypes.byref(info)))
        if info.attributes & 0x400:
            _unsafe("reparse points are forbidden")
        yield handle, info
    finally:
        if own:
            kernel.CloseHandle(handle)


def _validate_handle(handle, *, owner_only=False):
    adv, kernel = _api()
    owner, dacl, descriptor = P(), P(), P()
    result = adv.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if result:
        raise ctypes.WinError(result)
    try:
        user_sid = _user_sid()
        if (not owner or not adv.IsValidSid(owner) or
                not (adv.EqualSid(owner, user_sid) or adv.EqualSid(owner, _default_owner_sid()))):
            _unsafe("owner is not the current token user or default owner")
        if owner_only:
            return
        control, revision = w.WORD(), w.DWORD()
        _check(adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)))
        if not control.value & 0x1000 or not dacl or not adv.IsValidAcl(dacl):
            _unsafe("a protected, non-NULL DACL is required")
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        user_access = False
        for index in range(acl.count):
            ace = P()
            _check(adv.GetAce(dacl, index, ctypes.byref(ace)))
            header = ctypes.string_at(ace, 4)
            size = int.from_bytes(header[2:4], "little")
            if header[0] != 0 or size < 16:
                _unsafe("unsupported ACE type")
            sid = P(ace.value + 8)
            if not adv.IsValidSid(sid) or 8 + adv.GetLengthSid(sid) > size:
                _unsafe("invalid ACE SID")
            trustee = _sid_text(sid)
            if trustee not in {_sid_text(user_sid), "S-1-5-18"}:
                _unsafe("DACL grants access outside current token user and SYSTEM")
            if adv.EqualSid(sid, user_sid) and not header[1] & 8:
                user_access = True
        if not user_access:
            _unsafe("DACL has no current token user access ACE")
    finally:
        kernel.LocalFree(descriptor)


def validate(path_or_fd):
    with _handle(path_or_fd) as (handle, _info):
        _validate_handle(handle)


def set_sddl(path_or_fd, sddl):
    """Set an explicit protected DACL on a current-user-owned object."""
    with _handle(path_or_fd, write_dac=True) as (handle, _info):
        _validate_handle(handle, owner_only=True)
        _set_dacl(handle, sddl)


def _set_dacl(handle, sddl):
    adv, _ = _api()
    with _descriptor(sddl) as descriptor:
        present, defaulted, dacl = w.BOOL(), w.BOOL(), P()
        _check(adv.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
        if not present or not dacl:
            _unsafe("refusing to install a NULL DACL")
        result = adv.SetSecurityInfo(handle, 1, 4 | 0x80000000, None, None, dacl, None)
        if result:
            raise ctypes.WinError(result)


def restrict(path_or_fd):
    with _handle(path_or_fd, write_dac=True) as (handle, info):
        _validate_handle(handle, owner_only=True)
        _set_dacl(handle, _private_sddl(bool(info.attributes & 0x10)))
        _validate_handle(handle)


def private_directory(path):
    """Create with a restricted descriptor from birth; validate existing dirs."""
    path = Path(path).absolute()
    if not path.parent.exists():
        private_directory(path.parent)
    _, kernel = _api()
    with _descriptor(_private_sddl(directory=True)) as descriptor:
        attributes = _Attributes(ctypes.sizeof(_Attributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            error = ctypes.get_last_error()
            if error != 183:
                raise ctypes.WinError(error)
    with _handle(path) as (handle, info):
        if not info.attributes & 0x10:
            _unsafe("private directory is not a directory")
        _validate_handle(handle)


def open_private_file(path, *, append=False):
    """Create with a protected DACL, or validate an existing retained handle."""
    import msvcrt
    _, kernel = _api()
    with _descriptor(_private_sddl()) as descriptor:
        attributes = _Attributes(ctypes.sizeof(_Attributes), descriptor, False)
        handle = kernel.CreateFileW(str(Path(path).absolute()), 0xC0000000 | READ_CONTROL,
                                    3, ctypes.byref(attributes), 4, 0x00200080, None)
        if handle == w.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = _FileInfo()
            _check(kernel.GetFileInformationByHandle(handle, ctypes.byref(info)))
            if info.attributes & (0x400 | 0x10) or info.links != 1:
                _unsafe("private file must be a singly linked regular file")
            _validate_handle(handle)
            return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY | (os.O_APPEND if append else 0))
        except BaseException:
            kernel.CloseHandle(handle)
            raise


def private_temporary(directory, prefix):
    """Create a file with an explicit restricted DACL before writing secrets."""
    import msvcrt
    directory = Path(directory)
    private_directory(directory)
    _, kernel = _api()
    # Hold the parent through creation and descriptor validation.
    with _handle(directory) as (parent, _info), _descriptor(_private_sddl()) as descriptor:
        _validate_handle(parent)
        attributes = _Attributes(ctypes.sizeof(_Attributes), descriptor, False)
        for _ in range(100):
            path = directory / (prefix + secrets.token_hex(16))
            handle = kernel.CreateFileW(str(path), 0xC0000000 | READ_CONTROL | WRITE_DAC,
                                        0, ctypes.byref(attributes), 1, 0x80, None)
            if handle == w.HANDLE(-1).value:
                error = ctypes.get_last_error()
                if error in (80, 183):
                    continue
                raise ctypes.WinError(error)
            try:
                _validate_handle(handle)
                fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            except BaseException:
                kernel.CloseHandle(handle)
                path.unlink(missing_ok=True)
                raise
            return fd, str(path)
    raise FileExistsError("cannot allocate private temporary file")


def read_private(path):
    path = Path(path)
    # Pin and validate the containing directory throughout admission and read.
    with _handle(path.parent) as (parent, _info):
        _validate_handle(parent)
        with _handle(path, read=True) as (handle, info):
            _validate_handle(handle)
            if info.attributes & 0x10 or info.links != 1:
                _unsafe("credential must be a regular, singly linked file")
            _, kernel = _api()
            buffer = ctypes.create_string_buffer(1024 * 1024)
            count = w.DWORD()
            chunks = []
            while True:
                _check(kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None))
                if not count.value:
                    return b"".join(chunks)
                chunks.append(buffer.raw[:count.value])
