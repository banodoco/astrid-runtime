"""Disposable local socket/process subjects, never an operational service."""
from __future__ import annotations

import ctypes
import http.client
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

from runtime_protocol import platform

ROOT = Path(__file__).resolve().parents[1]


def child(mode):
    descriptor = int(os.environ.pop("RUNTIME_LISTENER_FD"))
    listener = platform.handoff_adopt_socket(descriptor)
    details = {"pid": os.getpid(), "inheritable": listener.get_inheritable(),
               "fd_env_removed": "RUNTIME_LISTENER_FD" not in os.environ}
    if mode.startswith("leak:"):
        other = int(mode.split(":")[1])
        try:
            os.fstat(other)
        except OSError:
            details["unrelated_fd_closed"] = True
        else:
            details["unrelated_fd_closed"] = False
        probe = subprocess.run(
            [sys.executable, "-c", "import os,sys; "
             "exec('try:\\n os.fstat(int(sys.argv[1]))\\nexcept OSError:\\n sys.exit(0)\\nelse:\\n sys.exit(1)')",
             str(descriptor)], close_fds=False, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=5,
        )
        details["exec_fd_closed"] = probe.returncode == 0
    print(json.dumps(details), flush=True)
    if mode == "gate":
        if sys.stdin.buffer.read(1) != b"G":
            return
    if mode == "ignore":
        time.sleep(30)
        return
    while True:
        connection, _address = listener.accept()
        with connection:
            request = b""
            while b"\r\n\r\n" not in request:
                part = connection.recv(1024)
                if not part:
                    break
                request += part
            body = json.dumps({"pid": os.getpid(), "incarnation": "fixture-1"}).encode()
            if mode == "drip":
                body = b"x" * 100
            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                               + b"\r\nConnection: close\r\n\r\n")
            if mode == "disconnect":
                continue
            if mode == "drip":
                try:
                    for byte in body:
                        connection.sendall(bytes([byte]))
                        time.sleep(0.03)
                except OSError:
                    pass
            else:
                connection.sendall(body)
            if mode == "exit":
                return


def start_subject(mode="serve", *, stdin=subprocess.DEVNULL):
    owner = platform.reserve_loopback_listener(0)
    process = owner.spawn(
        [sys.executable, str(Path(__file__).resolve()), "child", mode],
        cwd=str(ROOT), env={"PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert select.select([process.stdout], [], [], 5)[0], "child did not announce adoption"
    ready = json.loads(process.stdout.readline())
    return owner, ready


def request(owner, seconds=2):
    with owner.connection(deadline=time.monotonic() + seconds) as stream:
        stream.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(stream)
        response.begin()
        assert response.status == 200
        with response:
            assert response.length is not None and response.length <= 4096
            result = json.loads(response.read())
    return result


def dispose(owner):
    if owner.child is not None:
        platform.stop_tree(owner.child, grace=0.05)
        for stream in (owner.child.stdin, owner.child.stdout, owner.child.stderr):
            if stream is not None:
                stream.close()
    owner.close()


def custodian(descriptor):
    channel = platform.handoff_adopt_socket(descriptor)
    owner, _ready = start_subject()
    assert request(owner)["pid"] == owner.child.pid
    fd = platform.pidfd_open(owner.child.pid)
    try:
        platform.handoff_send(channel, json.dumps({"pid": owner.child.pid, "address": owner.address}).encode(), (fd,))
    finally:
        os.close(fd)
    # A finite client may disconnect without granting stop/restart authority.
    # This tiny test protocol exercises the retained resource only; production
    # IPC authentication, durable state and service wire are separate A2 work.
    channel.settimeout(10)
    try:
        while True:
            message = channel.recv(1)
            if not message:
                time.sleep(30)
                return
            if message != b"h":
                raise AssertionError("unexpected fixture request")
            channel.sendall(json.dumps(request(owner)).encode() + b"\n")
    finally:
        channel.close()
        dispose(owner)


def finite_launcher(parent_descriptor, owner_descriptor):
    parent_channel = platform.handoff_adopt_socket(parent_descriptor)
    owner = platform.spawn_tree(
        [sys.executable, str(Path(__file__).resolve()), "custodian", str(owner_descriptor)],
        pass_fds=(owner_descriptor,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    fd = platform.pidfd_open(owner.pid)
    try:
        platform.handoff_send(parent_channel, json.dumps({"pid": owner.pid}).encode(), (fd,))
    finally:
        os.close(fd)
        parent_channel.close()
        os.close(owner_descriptor)
    # Deliberate finite-client exit. Its child owner is not polled or stopped.


def owner_loss():
    # Subreaper only in this isolated test subject, so its orphan is reaped too.
    library = ctypes.CDLL(None, use_errno=True)
    assert library.prctl(36, 1, 0, 0, 0) == 0, ctypes.get_errno()
    local, remote = socket.socketpair()
    launch_local, launch_remote = socket.socketpair()
    launcher = platform.spawn_tree(
        [sys.executable, str(Path(__file__).resolve()), "finite-launcher",
         str(launch_remote.fileno()), str(remote.fileno())],
        pass_fds=(remote.fileno(), launch_remote.fileno()), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    remote.close()
    launch_remote.close()
    local.settimeout(5)
    launch_local.settimeout(5)
    owner_fd = None
    owner_pid = None
    engine_fd = None
    engine_pid = None
    outsider = platform.spawn_tree([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        raw, descriptors = platform.handoff_receive(launch_local, 4096)
        assert len(descriptors) == 1
        owner_fd = descriptors[0]
        owner_pid = json.loads(raw)["pid"]
        assert launcher.wait(timeout=5) == 0
        raw, descriptors = platform.handoff_receive(local, 4096)
        assert len(descriptors) == 1
        engine_fd = descriptors[0]
        value = json.loads(raw)
        engine_pid = value["pid"]
        for _ in range(2):
            local.sendall(b"h")
            response = bytearray()
            while not response.endswith(b"\n"):
                response.extend(local.recv(4096))
            assert json.loads(response)["pid"] == engine_pid
        local.close()  # actual peer loss; owner and engine stay alive
        platform.pidfd_send_signal(owner_fd, 0)
        platform.pidfd_send_signal(owner_fd, platform.KILL)
        assert select.select([owner_fd], [], [], 5)[0]
        os.waitpid(owner_pid, 0)
        owner_pid = None
        platform.pidfd_send_signal(engine_fd, 0)
        # An engine really survives a lost custodian, but its port cannot become
        # a new owner's authority. The old in-memory resource is gone.
        with socket.create_connection(tuple(value["address"]), timeout=2) as stream:
            stream.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            response = http.client.HTTPResponse(stream)
            response.begin()
            assert json.loads(response.read())["pid"] == engine_pid
        try:
            platform.reserve_loopback_listener(value["address"][1])
        except OSError:
            pass
        else:
            raise AssertionError("replacement custodian stole a live listener")
        assert not platform.tree_exited(outsider)
        print(json.dumps({"finite_launcher_exited": True, "peer_lost": True,
                          "owner_lost": True, "engine_survived": True,
                          "replacement_refused": True, "collateral_alive": True}), flush=True)
    finally:
        if engine_fd is not None:
            platform.pidfd_send_signal(engine_fd, platform.KILL)
            assert select.select([engine_fd], [], [], 5)[0]
            os.waitpid(engine_pid, 0)
            os.close(engine_fd)
        if owner_fd is not None:
            if owner_pid is not None:
                platform.pidfd_send_signal(owner_fd, platform.KILL)
                os.waitpid(owner_pid, 0)
            os.close(owner_fd)
        platform.stop_tree(launcher, grace=0.05)
        platform.stop_tree(outsider, grace=0.05)
        for stream in (launcher.stdout, launcher.stderr):
            stream.close()
        local.close()
        launch_local.close()
    try:
        os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        print(json.dumps({"all_fixture_children_reaped": True}), flush=True)
    else:
        raise AssertionError("fixture left a child")


if __name__ == "__main__":
    if sys.argv[1] == "child":
        child(sys.argv[2])
    elif sys.argv[1] == "custodian":
        custodian(int(sys.argv[2]))
    elif sys.argv[1] == "owner-loss":
        owner_loss()
    elif sys.argv[1] == "finite-launcher":
        finite_launcher(int(sys.argv[2]), int(sys.argv[3]))
    else:
        raise SystemExit("unknown fixture")
