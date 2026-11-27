"""Native Windows worker transport, reached only through platform.py.

The token is a single-use capability, not process identity. GetExtendedTcpTable
supplies the peer PID at adoption; a retained process handle supplies its user,
creation time and liveness thereafter. Serializable identities grant no action.
Socket transfer uses Winsock's process-specific WSADuplicateSocket data (Python
share/fromshare), since DuplicateHandle is not valid for Winsock sockets.
"""
from __future__ import annotations

import ctypes
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import threading
import time
import weakref

from . import platform
from .errors import ConflictError

_pins = weakref.WeakKeyDictionary()
_pins_lock = threading.RLock()
IDENTITY_FIELDS = ("pid", "uid", "birth_id")
_SINGLE_INTERPRETER_FLAGS = ("-I", "-S", "-u", "-B", "-s", "-E")
_SOCKET_TYPE = socket.socket
_QUERY = 0x1000  # PROCESS_QUERY_LIMITED_INFORMATION
_SYNCHRONIZE = 0x00100000
_TERMINATE = 0x0001
_OBSERVE_ACCESS = _QUERY | _SYNCHRONIZE
_ACTION_ACCESS = _OBSERVE_ACCESS | _TERMINATE


class WindowsBindingError(ConflictError):
    """The original Windows process authority is unavailable or mismatched."""


def _handle_api():
    from ctypes import wintypes

    if sys.platform != "win32":
        raise WindowsBindingError("Windows retained process handles are unavailable on this OS")
    kernel = platform._kernel()
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                      ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                      wintypes.BOOL, wintypes.DWORD]
    kernel.DuplicateHandle.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    return kernel


def _open_process(pid):
    """Capture permitted access once, while binding the authenticated channel."""
    kernel = _handle_api()
    access = _ACTION_ACCESS
    handle = kernel.OpenProcess(access, False, pid)
    if not handle and ctypes.get_last_error() == 5:  # ERROR_ACCESS_DENIED
        # Authentication need not grant termination. Never upgrade this handle
        # later by opening its PID again.
        access = _OBSERVE_ACCESS
        handle = kernel.OpenProcess(access, False, pid)
    if not handle:
        raise WindowsBindingError("handoff peer process handle is unavailable") from ctypes.WinError(ctypes.get_last_error())
    return handle, access


def _duplicate_process(handle, *, access=None):
    from ctypes import wintypes

    kernel = _handle_api()
    current = kernel.GetCurrentProcess()
    duplicate = wintypes.HANDLE()
    # SAME_ACCESS preserves a captured peer's permission. Only a genuine
    # Popen-owned full-access handle is deliberately narrowed at first capture.
    if not kernel.DuplicateHandle(current, handle, current, ctypes.byref(duplicate),
                                  0 if access is None else access, False,
                                  2 if access is None else 0):
        raise WindowsBindingError("Windows retained process handle duplication failed") from ctypes.WinError(ctypes.get_last_error())
    return duplicate.value


def _close_process(handle):
    if not _handle_api().CloseHandle(handle):
        raise WindowsBindingError("Windows retained process handle close failed") from ctypes.WinError(ctypes.get_last_error())


def _handle_identity(handle):
    """Read PID, user, birth and exit state from this exact process object."""
    try:
        pid = int(_handle_api().GetProcessId(handle))
        if not pid:
            raise ctypes.WinError(ctypes.get_last_error())
        if not platform._windows_process_active(handle):
            raise WindowsBindingError("Windows retained process owner exited")
        observed = identity(platform._windows_identity(pid, handle))
        if not platform._windows_process_active(handle):
            raise WindowsBindingError("Windows retained process owner exited during verification")
        return observed
    except OSError as exc:
        raise WindowsBindingError("Windows retained process identity is unavailable") from exc


def _terminate_process(handle):
    if not _handle_api().TerminateProcess(handle, 1):
        raise WindowsBindingError("Windows retained process termination failed") from ctypes.WinError(ctypes.get_last_error())


def _identity_token(observed):
    observed = identity(observed)
    prefix = "windows-creation:"
    birth = observed["birth_id"]
    if not birth.startswith(prefix) or not birth[len(prefix):].isascii() or not birth[len(prefix):].isdigit():
        raise WindowsBindingError("Windows process creation identity is invalid")
    created = int(birth[len(prefix):])
    pid, uid = observed["pid"], observed["uid"]
    if not 0 < created < 1 << 64 or not 0 < pid < 1 << 32 or not 0 <= uid < 1 << 63:
        raise WindowsBindingError("Windows process creation identity is invalid")
    words = [0x41535452, pid, uid & 0xffffffff, uid >> 32,
             created & 0xffffffff, created >> 32, 0, 0]
    return {**platform.handoff_token_details(words), "words": words}


def _admit_signal(signum):
    if isinstance(signum, bool) or not isinstance(signum, int) or signum not in (platform.TERM, platform.KILL):
        raise WindowsBindingError("Windows custody signal is outside the admitted set")


class PeerHandle:
    """An independently owned process reference; callers must close it.

    Verification, termination and close share a lock, so a handle cannot be
    closed or recycled between verification and the native operation. Snapshot
    dictionaries are copies and never substitute for this reference.
    """

    def __init__(self, handle, observed, access):
        self._identity = identity(observed)
        self._words = tuple(_identity_token(observed)["words"])
        self._access = access
        self._handle = handle
        self._lock = threading.RLock()

    @property
    def token(self):
        return {**platform.handoff_token_details(list(self._words)), "words": list(self._words)}

    @property
    def identity(self):
        return dict(self._identity)

    @property
    def authority(self):
        return "windows-process-handle"

    @property
    def access(self):
        return self._access

    def _verify(self, expected=None):
        if self._handle is None:
            raise WindowsBindingError("Windows retained process authority is closed")
        if expected is not None and identity(expected) != self._identity:
            raise WindowsBindingError("Windows retained process differs from expected incarnation")
        if _handle_identity(self._handle) != self._identity:
            raise WindowsBindingError("Windows retained process incarnation changed")
        return self.token

    def verify(self, expected=None):
        with self._lock:
            return self._verify(expected)

    def _duplicate(self, expected=None):
        with self._lock:
            self._verify(expected)
            handle = _duplicate_process(self._handle)
            try:
                duplicate = PeerHandle(handle, self._identity, self._access)
                duplicate.verify(expected)
                return duplicate
            except BaseException:
                _close_process(handle)
                raise

    def signal(self, signum):
        _admit_signal(signum)
        with self._lock:
            self._verify()
            if not self._access & _TERMINATE:
                raise WindowsBindingError("Windows retained process handle has no termination access")
            # Windows TERM and KILL both terminate this process object, as in
            # Popen. A PID-addressed console group event cannot provide this
            # retained-handle guarantee. Completion is asynchronous.
            _terminate_process(self._handle)

    def close(self):
        with self._lock:
            handle, self._handle = self._handle, None
            if handle is not None:
                _close_process(handle)

    def __enter__(self):
        try:
            self.verify()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, *_exc):
        self.close()


def _channel(channel):
    return getattr(channel, "_handoff_channel", channel)


def _endpoints(channel):
    if channel.fileno() < 0:
        raise WindowsBindingError("handoff transfer channel is closed")
    if channel.family != socket.AF_INET:
        raise WindowsBindingError("handoff transfer channel must be loopback TCP")
    endpoints = channel.getsockname(), channel.getpeername()
    if any(value[0] != "127.0.0.1" for value in endpoints):
        raise WindowsBindingError("handoff transfer channel must be loopback TCP")
    return endpoints


def _close_channel_pin(channel):
    with _pins_lock:
        pin = _pins.get(_channel(channel))
    if pin is not None:
        pin[0].close()


class _BoundSocket(_SOCKET_TYPE):
    """Close the authentication pin even when the socket object is retained."""

    def close(self):
        try:
            _close_channel_pin(self)
        finally:
            super().close()

    def detach(self):
        _close_channel_pin(self)
        return super().detach()


def _bound_socket(channel):
    if isinstance(channel, _BoundSocket) or not isinstance(channel, _SOCKET_TYPE):
        return channel
    family, kind, proto = channel.family, channel.type, channel.proto
    timeout = channel.gettimeout()
    descriptor = channel.detach()
    try:
        bound = _BoundSocket(family, kind, proto, fileno=descriptor)
    except BaseException:
        socket.close(descriptor)
        raise
    try:
        bound.settimeout(timeout)
        bound.set_inheritable(False)
        return bound
    except BaseException:
        bound.close()
        raise


def _close_channel(channel):
    try:
        _close_channel_pin(channel)
    finally:
        channel.close()


def _consume_interpreter_prefix(arguments):
    flags = []
    arguments = list(arguments)
    while arguments:
        if arguments[0] in _SINGLE_INTERPRETER_FLAGS:
            flags.append(arguments.pop(0))
        elif arguments[:2] == ["-X", "utf8"]:
            flags.extend((arguments.pop(0), arguments.pop(0)))
        else:
            break
    return flags, arguments


def identity(value):
    if (not isinstance(value, dict) or any(key not in value for key in IDENTITY_FIELDS)
            or type(value["pid"]) is not int or value["pid"] <= 0
            or type(value["uid"]) is not int or value["uid"] < 0
            or not isinstance(value["birth_id"], str) or not value["birth_id"]):
        raise ConflictError("handoff peer process identity is unavailable")
    return {key: value[key] for key in IDENTITY_FIELDS}


def tcp_peer_pid(channel):
    """Read the reverse established IPv4 tuple, never a client-supplied PID."""
    from ctypes import wintypes

    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    query = library.GetExtendedTcpTable
    query.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                      wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    query.restype = wintypes.DWORD
    size = wintypes.DWORD()
    result = query(None, ctypes.byref(size), False, socket.AF_INET, 5, 0)
    # TCP_TABLE_OWNER_PID_ALL = 5; the table can grow between the two calls.
    for _ in range(4):
        if result != 122 or size.value > 16 * 1024 * 1024:
            raise ConflictError("cannot authenticate handoff transfer peer PID")
        buffer = ctypes.create_string_buffer(size.value)
        result = query(buffer, ctypes.byref(size), False, socket.AF_INET, 5, 0)
        if result == 0:
            break
    if result != 0:
        raise ConflictError("cannot authenticate handoff transfer peer PID")
    return tcp_peer_from_table(bytes(buffer), channel.getsockname(), channel.getpeername())


def tcp_peer_from_table(table, local, remote):
    if len(table) < 4:
        raise ConflictError("handoff TCP owner table is malformed")
    count, = struct.unpack_from("=I", table)
    if 4 + count * 24 > len(table):
        raise ConflictError("handoff TCP owner table is malformed")
    matches = []
    for index in range(count):
        state, address1, port1, address2, port2, pid = struct.unpack_from("=6I", table, 4 + index * 24)
        address = lambda value: socket.inet_ntoa(struct.pack("=I", value))
        endpoint = (address(address1), socket.ntohs(port1 & 0xffff))
        other = (address(address2), socket.ntohs(port2 & 0xffff))
        if state == 5 and endpoint == remote and other == local:
            matches.append(pid)
    if len(matches) != 1 or matches[0] <= 0:
        raise ConflictError("cannot authenticate handoff transfer peer PID")
    return matches[0]


def _capture_peer(channel, expected=None):
    endpoints = _endpoints(channel)
    pid = tcp_peer_pid(channel)
    handle, access = _open_process(pid)
    try:
        observed = _handle_identity(handle)
        if observed["pid"] != pid or observed["uid"] != platform.current_user():
            raise WindowsBindingError("handoff transfer peer incarnation is invalid")
        peer = PeerHandle(handle, observed, access)
        if tcp_peer_pid(channel) != pid or _endpoints(channel) != endpoints:
            raise WindowsBindingError("handoff peer process incarnation changed")
        peer.verify(expected)
        return peer, endpoints
    except BaseException:
        _close_process(handle)
        raise


def observe_peer(channel):
    """Diagnostic observation; the temporary handle never escapes as authority."""
    peer, _ = _capture_peer(_channel(channel))
    try:
        return peer.identity
    finally:
        peer.close()


def verify_peer(channel, expected=None):
    channel = _channel(channel)
    with _pins_lock:
        pinned = _pins.get(channel)
    if pinned is None:
        raise WindowsBindingError("handoff transfer peer has no retained process authority")
    peer, endpoints = pinned
    with peer._lock:
        peer._verify(expected)
        if (_endpoints(channel) != endpoints or tcp_peer_pid(channel) != peer.identity["pid"]
                or peer.identity["uid"] != platform.current_user()):
            raise WindowsBindingError("handoff transfer peer incarnation changed")
        peer._verify(expected)
        return peer.identity


def pin_peer(channel, expected, *, authority=None):
    channel = _channel(channel)
    expected = identity(expected)
    with _pins_lock:
        pinned = _pins.get(channel)
    if pinned is not None:
        return verify_peer(channel, expected)
    if authority is None:
        peer, endpoints = _capture_peer(channel, expected)
    else:
        if not isinstance(authority, PeerHandle):
            raise WindowsBindingError("handoff adoption requires the original retained process handle")
        peer = authority._duplicate(expected)
        try:
            endpoints = _endpoints(channel)
            if tcp_peer_pid(channel) != peer.identity["pid"]:
                raise WindowsBindingError("handoff transfer peer incarnation changed")
            peer.verify(expected)
        except BaseException:
            peer.close()
            raise
    try:
        with _pins_lock:
            if channel not in _pins:
                _pins[channel] = (peer, endpoints)
                # Managed sockets close deterministically. This also protects
                # a borrowed socket whose owner releases the object outright.
                weakref.finalize(channel, peer.close)
            else:
                peer.close()
        return verify_peer(channel, expected)
    except BaseException:
        peer.close()
        raise


def retain_peer(connection, *, expected=None):
    """Duplicate a channel's original pin, never reopen its observed PID."""
    connection = _channel(connection)
    verify_peer(connection, expected)
    with _pins_lock:
        peer, _ = _pins[connection]
    retained = peer._duplicate(expected)
    try:
        verify_peer(connection, expected)
        return retained
    except BaseException:
        retained.close()
        raise


def retain_child(child, *, reap_guard, expected=None):
    """Capture an independent restricted duplicate of Popen's own handle."""
    import subprocess

    if (not isinstance(child, subprocess.Popen) or not getattr(child, "_child_created", False)
            or reap_guard is None):
        raise WindowsBindingError("Windows child authority requires the retained Popen and reap guard")
    with reap_guard:
        original = getattr(child, "_handle", None)
        if original is None:
            raise WindowsBindingError("Windows child has no retained process handle")
        handle = _duplicate_process(original, access=_ACTION_ACCESS)
        try:
            observed = _handle_identity(handle)
            if observed["pid"] != child.pid or observed["uid"] != platform.current_user():
                raise WindowsBindingError("Windows retained child incarnation changed")
            retained = PeerHandle(handle, observed, _ACTION_ACCESS)
            retained.verify(expected)
            return retained
        except BaseException:
            _close_process(handle)
            raise


def signal(words, signum, *, authority=None):
    _admit_signal(signum)
    if not isinstance(authority, PeerHandle):
        raise WindowsBindingError("Windows signalling requires retained native authority, not a token or PID")
    try:
        supplied = list(words)
        platform.handoff_token_details(supplied)
    except (TypeError, ValueError, OSError) as exc:
        raise WindowsBindingError("Windows process identity token is invalid") from exc
    if supplied != authority.token["words"]:
        raise WindowsBindingError("Windows signal token differs from retained incarnation")
    authority.signal(signum)


def read_exact(channel, count, *, deadline=None):
    data = bytearray()
    while len(data) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("handoff transport authentication timed out")
            channel.settimeout(remaining)
        part = channel.recv(count - len(data))
        if not part:
            raise ConflictError("handoff authority transfer channel closed")
        data.extend(part)
    return bytes(data)


class Listener:
    def __init__(self, expected=None, *, timeout=5.0):
        self.expected = identity(expected) if expected is not None else None
        self.token = secrets.token_hex(32)
        self.used = False
        self._token_lock = threading.Lock()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.set_inheritable(False)
            self.socket.settimeout(timeout)
            self.socket.bind(("127.0.0.1", 0))
            self.socket.listen(4)
        except BaseException:
            self.socket.close()
            raise
        self.timeout = timeout
        self.owner = identity(platform.process_identity(os.getpid()))

    @property
    def endpoint(self):
        return json.dumps({"port": self.socket.getsockname()[1], "token": self.token,
                           "owner": self.owner}, separators=(",", ":"))

    def accept(self, expected=None, *, acceptor=None, frame_io=None, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + self.timeout
        acceptor = self.socket if acceptor is None else acceptor
        while True:
            if self.used:
                raise ConflictError("handoff transport token was already consumed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("handoff transport authentication timed out")
            acceptor.settimeout(remaining)
            channel, _ = acceptor.accept()
            channel = _bound_socket(channel)
            try:
                channel.set_inheritable(False)
                selected = expected if expected is not None else self.expected
                if callable(selected):
                    selected = selected(observe_peer(channel))
                pin_peer(channel, selected)
                reader = channel if frame_io is None else frame_io(channel)
                supplied = read_exact(reader, 64, deadline=deadline)
                if not hmac.compare_digest(supplied, self.token.encode("ascii")):
                    raise ConflictError("handoff transport token is invalid")
                verify_peer(channel)
                with self._token_lock:
                    if self.used:
                        raise ConflictError("handoff transport token was already consumed")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("handoff transport authentication timed out")
                    channel.settimeout(remaining)
                    channel.sendall(b"\x01")
                    self.used = True
                channel.settimeout(self.timeout)
                return channel
            except (ConflictError, OSError):
                # A local connection is not admission. Keep the capability for
                # the selected child, with no new budget for rejected peers.
                _close_channel(channel)
            except BaseException:
                _close_channel(channel)
                raise

    def accept_child(self, parent, *, deadline=None):
        def select(observed):
            actual = platform.process_identity(observed["pid"])
            if actual is None or actual.get("parent_pid") != parent["pid"]:
                raise ConflictError("handoff child launch lineage is invalid")
            return observed
        return self.accept(select, deadline=deadline), None

    def close(self):
        self.socket.close()


def connect(endpoint, *, expected=None, timeout=5.0):
    try:
        value = json.loads(endpoint)
        if set(value) != {"port", "token", "owner"} or type(value["port"]) is not int or not 1 <= value["port"] <= 65535:
            raise ValueError()
        token = value["token"]
        if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            raise ValueError()
        owner = identity(value["owner"])
        if expected is not None and owner != identity(expected):
            raise ValueError()
    except (TypeError, ValueError, KeyError) as exc:
        raise ConflictError("handoff transport endpoint is invalid") from exc
    channel = _bound_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    deadline = time.monotonic() + timeout
    try:
        channel.settimeout(timeout)
        channel.connect(("127.0.0.1", value["port"]))
        pin_peer(channel, owner)
        channel.sendall(token.encode("ascii"))
        if read_exact(channel, 1, deadline=deadline) != b"\x01":
            raise ConflictError("handoff transport authentication failed")
        verify_peer(channel)
        channel.settimeout(timeout)
        return channel
    except BaseException:
        _close_channel(channel)
        raise


def send(channel, payload, descriptors=()):
    peer = verify_peer(channel)
    if not descriptors:
        channel.sendall(payload)
        return
    shares = []
    for descriptor in descriptors:
        borrowed = socket.socket(fileno=descriptor)
        try:
            shares.append(borrowed.share(peer["pid"]))
        finally:
            borrowed.detach()
    # Transport metadata encloses the unchanged protocol frame. Bound both the
    # count and native WSAPROTOCOL_INFO size before receiver allocation.
    if len(shares) not in (0, 2) or any(len(value) > 4096 for value in shares):
        raise ConflictError("handoff transfer must carry exactly two authority descriptors")
    header = struct.pack("!II", len(payload), len(shares))
    attachments = b"".join(struct.pack("!I", len(value)) + value for value in shares)
    verify_peer(channel)
    channel.sendall(b"\x00" + header + attachments + payload)


def receive(channel, limit):
    verify_peer(channel)
    first = read_exact(channel, 1)
    if first != b"\x00":
        return first, []
    length, count = struct.unpack("!II", read_exact(channel, 8))
    if length > limit or count != 2:
        raise ConflictError("handoff transfer carried an invalid frame boundary")
    sockets = []
    try:
        for _ in range(count):
            size, = struct.unpack("!I", read_exact(channel, 4))
            if size == 0 or size > 4096:
                raise ConflictError("handoff transfer descriptor record is invalid")
            value = socket.fromshare(read_exact(channel, size))
            sockets.append(value)
            value.set_inheritable(False)
        payload = read_exact(channel, length)
        verify_peer(channel)
        return payload, [value.detach() for value in sockets]
    except BaseException:
        for value in sockets:
            try:
                value.close()
            except OSError:
                pass
        raise


class InheritedHandles:
    """A bounded Python worker launch using STARTUPINFO.handle_list.

    Raw Winsock handles keep their numeric value in the child. CRT file
    descriptors are reconstructed by the bootstrap before the selected module
    sees them. An independent single-use connection authenticates the child
    before spawn_tree returns it to a protocol owner.
    """
    def __init__(self, argv, kwargs, descriptors):
        import msvcrt
        import subprocess
        self.listener = Listener(timeout=10.0)
        self.handles = []
        self.previous = []
        files, sockets = {}, []
        try:
            for descriptor in descriptors:
                try:
                    borrowed = socket.socket(fileno=descriptor)
                except OSError:
                    handle = msvcrt.get_osfhandle(descriptor)
                    files[str(descriptor)] = handle
                else:
                    borrowed.detach()
                    handle = descriptor
                    sockets.append(handle)
                self.handles.append(handle)
                self.previous.append(os.get_handle_inheritable(handle))
                os.set_handle_inheritable(handle, True)
            startup = kwargs.setdefault("startupinfo", subprocess.STARTUPINFO())
            attributes = dict(startup.lpAttributeList or {})
            attributes["handle_list"] = [*attributes.get("handle_list", []), *self.handles]
            startup.lpAttributeList = attributes
            environment = dict(kwargs.get("env") if kwargs.get("env") is not None else os.environ)
            executable = python_executable(argv[0])
            environment.pop("__PYVENV_LAUNCHER__", None)
            if executable != argv[0]:
                environment["__PYVENV_LAUNCHER__"] = str(argv[0])
            environment["ASTRID_RUNTIME_WORKER_BOOTSTRAP"] = json.dumps({
                "endpoint": self.listener.endpoint, "argv": list(argv), "files": files,
                "sockets": sockets,
            }, separators=(",", ":"))
            kwargs.update(env=environment, close_fds=True)
            # Strict workers install their network guard before site.main;
            # the authenticated bootstrap must also suppress automatic site.
            flags, _arguments = _consume_interpreter_prefix(argv[1:])
            self.argv = [executable, *flags, str(Path(__file__).with_name("windows_worker_bootstrap.py"))]
        except BaseException:
            self.close()
            raise

    def authenticate(self, process):
        deadline = time.monotonic() + self.listener.timeout
        expected = identity(platform.handoff_child_identity(process))
        channel = self.listener.accept(expected, deadline=deadline)
        try:
            if read_exact(channel, 1, deadline=deadline) != b"\x02":
                raise ConflictError("worker bootstrap authentication was incomplete")
        finally:
            _close_channel(channel)

    def restore(self):
        for handle, previous in zip(self.handles, self.previous):
            os.set_handle_inheritable(handle, previous)
        self.handles.clear()
        self.previous.clear()

    def close(self):
        self.listener.close()
        self.restore()


def run_worker():
    """Enter the selected Python module in this authenticated process/PID."""
    import msvcrt
    value = json.loads(os.environ.pop("ASTRID_RUNTIME_WORKER_BOOTSTRAP"))
    global _inherited_owner, _inherited_peer, _inherited_sockets
    try:
        channel = connect(value["endpoint"], timeout=10.0)
        try:
            owner = verify_peer(channel)
            # Preserve the original process object across closing the bootstrap
            # transport and any delayed network/site setup before adoption.
            _inherited_peer = retain_peer(channel, expected=owner)
            _inherited_owner = owner
            channel.sendall(b"\x02")
        finally:
            _close_channel(channel)
        for number, handle in value["files"].items():
            os.set_handle_inheritable(handle, False)
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
            if descriptor != int(number):
                os.dup2(descriptor, int(number), inheritable=False)
                os.close(descriptor)
        # Inherited endpoints authenticate their original Runtime creator.
        # Successor authentication needs its own newly accepted connection.
        _inherited_sockets = {}
        for handle in value["sockets"]:
            os.set_handle_inheritable(handle, False)
            borrowed = socket.socket(fileno=handle)
            try:
                _inherited_sockets[handle] = (borrowed.getsockname(), borrowed.getpeername())
            finally:
                borrowed.detach()
        if not _inherited_sockets:
            _release_inherited_peer()
        return enter_module(value["argv"])
    finally:
        with _inherited_lock:
            _inherited_sockets.clear()
            _release_inherited_peer()


def enter_module(argv):
    import runpy
    import sys
    # A same-process module transition cannot switch Python installations.
    if os.path.normcase(os.path.realpath(argv[0])) != os.path.normcase(os.path.realpath(sys.executable)):
        raise ConflictError("Windows custody target requires the selected Python interpreter")
    flags, arguments = _consume_interpreter_prefix(argv[1:])
    if "-X" in flags and sys.flags.utf8_mode != 1:
        raise ConflictError("Windows custody UTF-8 flag was not active in the selected interpreter")
    if len(arguments) < 2 or arguments[0] not in ("-m", "-c"):
        raise ConflictError("Windows worker launch requires a Python module or command")
    if "-I" not in flags:
        roots = [] if "-E" in flags else os.environ.get("PYTHONPATH", "").split(os.pathsep)
        sys.path[:0] = [os.getcwd(), *[root for root in roots if root and root not in sys.path]]
    if arguments[0] == "-c":
        sys.argv = ["-c", *arguments[2:]]
        exec(compile(arguments[1], "<string>", "exec"), {"__name__": "__main__"})
    else:
        sys.argv = arguments[1:]
        runpy.run_module(arguments[1], run_name="__main__", alter_sys=True)


_inherited_owner = None
_inherited_peer = None
_inherited_sockets = {}
_inherited_lock = threading.RLock()


def _release_inherited_peer():
    global _inherited_owner, _inherited_peer
    retained, _inherited_peer = _inherited_peer, None
    _inherited_owner = None
    if retained is not None:
        retained.close()


def adopt_socket(descriptor):
    channel = None
    try:
        with _inherited_lock:
            endpoints = _inherited_sockets.pop(descriptor, None)
            try:
                channel = _bound_socket(socket.socket(fileno=descriptor))
                channel.set_inheritable(False)
                if endpoints != (channel.getsockname(), channel.getpeername()):
                    raise ConflictError("inherited Worker control endpoint identity changed")
                if _inherited_peer is None:
                    raise WindowsBindingError("inherited Worker control has no original retained owner handle")
                pin_peer(channel, _inherited_owner, authority=_inherited_peer)
            finally:
                if not _inherited_sockets:
                    _release_inherited_peer()
        return channel
    except BaseException:
        if channel is not None:
            _close_channel(channel)
        raise


def peer_token(channel):
    # Derive the compatible observation from the held object. No PID lookup is
    # needed between channel verification and token encoding.
    return _identity_token(verify_peer(channel))


def python_executable(requested):
    """Bypass CPython's venv redirector so Popen retains the interpreter PID.

    This is the same __PYVENV_LAUNCHER__ boundary used by the stdlib's Windows
    multiprocessing launcher. The lexical venv executable remains sys.executable.
    """
    requested = str(requested)
    if os.path.normcase(requested) == os.path.normcase(sys.executable):
        return getattr(sys, "_base_executable", None) or requested
    executable = Path(requested)
    config = executable.parent.parent / "pyvenv.cfg"
    if executable.parent.name.lower() != "scripts" or not config.is_file():
        return requested
    values = {}
    for line in config.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip().lower()] = value.strip()
    home = Path(values.get("home", ""))
    base = home / "python.exe"
    if not home.is_absolute() or not base.is_file():
        raise ConflictError("configured Worker venv has no observable base Python")
    return str(base)
