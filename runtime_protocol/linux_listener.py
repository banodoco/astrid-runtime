"""Linux socket activation using a parent-held listener and an unreaped child.

Only ``platform.reserve_loopback_listener`` constructs this local resource.
The parent never accepts: the descriptor is passed to exactly one child, which
must adopt it before loading application code (``handoff_adopt_socket`` clears
inheritability). The parent retains its copy across every health operation.
No reuse-port option, socket discovery, /proc identity or PID-derived signal
authority is used here. Trusted child code must not delegate the listener to
unrelated processes or change its binding/reuse options. This is not isolation
from malicious code running as the same OS user.

The caller must retain this object and be the child's sole waiter. Do not call
poll/wait/communicate before platform.stop_tree has consumed group authority.
The public child property exists for that existing cleanup boundary. Closing
this resource does NOT prove descendant draining; the owner must establish
that separately before recording cleanup completion or permitting a restart.
There is no automatic cleanup, process adoption, service protocol, durable
state or HTTP policy here. The abstract Unix helpers below supply only native
IPC sockets. Lost owner state cannot be reconstructed from IDs.
"""
from __future__ import annotations

from contextlib import contextmanager
import io
import math
import os
import signal
import socket
import subprocess
import sys
import threading
import time

from . import cancellation, platform

LISTENER_FD_ENV = "RUNTIME_LISTENER_FD"


def _abstract_name(name):
    if sys.platform != "linux":
        raise NotImplementedError("abstract local IPC requires Linux")
    if (not isinstance(name, bytes) or not 9 <= len(name) <= 107
            or not name.startswith(b"\0astrid-")
            or any(byte not in b"abcdefghijklmnopqrstuvwxyz0123456789.-" for byte in name[1:])):
        raise ValueError("invalid Astrid abstract socket name")
    return name


def abstract_listener(name: bytes, *, backlog: int = 8):
    """Native IPC substrate only: use peer UID plus mutual capability auth.

    Abstract names have no filesystem permissions, are not secrets, and confer
    no service/process authority. Caller bounds accept and all framed I/O.
    """
    name = _abstract_name(name)
    if type(backlog) is not int or not 1 <= backlog <= 8:
        raise ValueError("invalid local IPC backlog")
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        channel.set_inheritable(False)
        channel.bind(name)
        channel.listen(backlog)
        return channel
    except BaseException:
        channel.close()
        raise


def abstract_connect(name: bytes, *, deadline):
    """Bound this connect only; caller rechecks the deadline during framed I/O."""
    name = _abstract_name(name)
    remaining = _remaining(deadline)
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        channel.set_inheritable(False)
        channel.settimeout(remaining)
        channel.connect(name)
        return channel
    except BaseException:
        channel.close()
        raise


def _remaining(deadline):
    if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)):
        raise ValueError("listener deadline must be finite")
    cancellation.check()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("listener operation deadline expired")
    return remaining


def _acquire(lock, deadline, message):
    while True:
        try:
            remaining = _remaining(deadline)
        except TimeoutError as exc:
            raise TimeoutError(message) from exc
        if lock.acquire(timeout=min(0.1, remaining)):
            return


class _Reader(io.RawIOBase):
    def __init__(self, connection):
        super().__init__()
        self._connection = connection

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.closed:
            raise ValueError("read from closed listener stream")
        data = self._connection.recv(len(buffer))
        buffer[:len(data)] = data
        return len(data)


class _Connection:
    """Deadline-bound stream; buffered HTTP reads retain the same deadline."""
    def __init__(self, channel, deadline):
        self._channel, self._deadline = channel, deadline

    def sendall(self, data):
        view = memoryview(data)
        while view:
            remaining = _remaining(self._deadline)
            self._channel.settimeout(min(0.1, remaining) if cancellation.active() else remaining)
            try:
                sent = self._channel.send(view)
            except TimeoutError:
                _remaining(self._deadline)
                continue
            if not sent:
                raise ConnectionError("listener stream closed during write")
            view = view[sent:]

    def recv(self, count):
        while True:
            remaining = _remaining(self._deadline)
            self._channel.settimeout(min(0.1, remaining) if cancellation.active() else remaining)
            try:
                return self._channel.recv(count)
            except TimeoutError:
                _remaining(self._deadline)

    def makefile(self, mode="rb"):
        if mode != "rb":
            raise ValueError("listener stream supports binary reads only")
        return io.BufferedReader(_Reader(self))


class RetainedListener:
    """One exclusive IPv4 loopback binding and at most one child incarnation.

    ``spawn`` injects only LISTENER_FD_ENV and passes only this FD (besides
    explicit standard streams). Its argv must invoke a reviewed socket-aware
    bootstrap; an unmodified program that binds its own socket cannot use this
    primitive. Spawn has the existing platform.spawn_tree/Popen semantics,
    including possible ambiguous launch; it is never automatically retried.

    ``connection`` holds sole-waiter serialization, checks child liveness
    without reaping before and after the actual I/O, and retains the listener
    throughout. Publish evidence only after successful context exit. The
    connection is local and proxy-free; the caller owns HTTP status, redirect,
    framing, byte limits and JSON policy. All recv/sendall/buffered reads use
    one absolute monotonic deadline, not a renewable inactivity timeout.
    """
    def __init__(self, port: int, *, backlog: int = 128):
        if sys.platform != "linux":
            raise NotImplementedError("retained loopback listener requires Linux")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid listener port")
        if type(backlog) is not int or not 1 <= backlog <= 128:
            raise ValueError("invalid listener backlog")
        self._owner = os.getpid()
        self._lock = threading.Lock()
        self._child = None
        self._attempted = False
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.set_inheritable(False)
            listener.bind(("127.0.0.1", port))
            listener.listen(backlog)
            self._address = listener.getsockname()
        except BaseException:
            listener.close()
            raise
        self._listener = listener

    @property
    def address(self):
        return self._address

    @property
    def child(self):
        """Original Popen for existing stop_tree; not a durable reference."""
        return self._child

    def _check_owner(self):
        if os.getpid() != self._owner or self._listener.fileno() < 0:
            raise ProcessLookupError("listener owner resource is unavailable")

    def spawn(self, argv, *, cwd, env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL):
        """Attempt exactly one launch, retaining its Popen before returning it.

        A native spawn exception consumes this object's launch attempt too. The caller
        records intent durably before invoking this method; exceptions do not
        certify absence or permit another launch.
        """
        with self._lock:
            self._check_owner()
            if self._attempted:
                raise RuntimeError("listener launch was already attempted")
            if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                raise RuntimeError("listener child requires sole wait ownership")
            if LISTENER_FD_ENV in env:
                raise ValueError("listener descriptor environment is reserved")
            descriptor = self._listener.fileno()
            child_env = {**env, LISTENER_FD_ENV: str(descriptor)}
            self._attempted = True
            self._child = platform.spawn_tree(
                argv, cwd=cwd, env=child_env, pass_fds=(descriptor,),
                close_fds=True, stdin=stdin, stdout=stdout, stderr=stderr,
            )
            return self._child

    def _require_live(self):
        if (self._listener.getsockname() != self._address
                or not self._listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or self._listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT)):
            raise ProcessLookupError("retained listener binding changed")
        child = self._child
        if child is None or child.returncode is not None:
            raise ProcessLookupError("listener child is unavailable or reaped")
        try:
            exited = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as exc:
            raise ProcessLookupError("listener child wait ownership was lost") from exc
        if exited is not None:
            raise ProcessLookupError("listener child exited")

    @contextmanager
    def connection(self, *, deadline):
        """Yield a bounded stream to the still-pinned listener, never a port lookup."""
        _acquire(self._lock, deadline, "listener owner is busy")
        channel = None
        wait_guard = None
        acquired_wait = False
        try:
            self._check_owner()
            if self._child is None:
                raise ProcessLookupError("listener child has not been launched")
            wait_guard = platform.validate_child_reaper(self._child)
            _acquire(wait_guard, deadline, "listener child waiter is busy")
            acquired_wait = True
            self._require_live()
            channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            channel.settimeout(_remaining(deadline))
            channel.connect(self._address)
            yield _Connection(channel, deadline)
            _remaining(deadline)
            self._require_live()
        finally:
            if channel is not None:
                channel.close()
            if acquired_wait:
                wait_guard.release()
            self._lock.release()

    def close(self):
        """Release the parent socket after direct-child cleanup, or before spawn.

        A retained live/unreaped child or lost wait ownership refuses release.
        This method neither signals nor certifies complete tree cleanup.
        """
        with self._lock:
            self._check_owner()
            if self._child is not None and self._child.returncode is None:
                raise ProcessLookupError("stop and reap the owned child before listener release")
            self._listener.close()

    def __reduce__(self):
        raise TypeError("listener custody cannot be serialized")
