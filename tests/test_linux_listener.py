from __future__ import annotations

import errno
import http.client
import json
import os
from pathlib import Path
import pickle
import select
import socket
import subprocess
import sys
import threading
import time
import uuid

import pytest

from runtime_protocol import cancellation, platform
from tests.listener_fixtures import ROOT, dispose, request, start_subject

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux retained listener primitive")


@pytest.fixture
def owned():
    owner, ready = start_subject()
    try:
        yield owner, ready
    finally:
        dispose(owner)


def test_real_http_uses_inherited_listener_and_retained_child(owned):
    owner, ready = owned
    assert owner.address[0] == "127.0.0.1"
    assert ready == {"pid": owner.child.pid, "inheritable": False, "fd_env_removed": True}
    for _ in range(3):
        assert request(owner) == {"pid": owner.child.pid, "incarnation": "fixture-1"}
    assert owner.child.returncode is None  # health never reaps the anchor


def test_bootstrap_can_wait_for_native_custody_before_application_release():
    owner, _ready = start_subject("gate", stdin=subprocess.PIPE)
    try:
        assert not platform.tree_exited(owner.child)
        owner.child.stdin.write(b"G")
        owner.child.stdin.flush()
        owner.child.stdin.close()
        assert request(owner)["pid"] == owner.child.pid
    finally:
        dispose(owner)


@pytest.mark.parametrize("reuse_port", [False, True])
def test_replacement_cannot_bind_while_parent_retains_listener(owned, reuse_port):
    owner, _ready = owned
    platform.stop_tree(owner.child, grace=0.05)
    with socket.socket() as foreign:
        foreign.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuse_port:
            foreign.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        with pytest.raises(OSError) as caught:
            foreign.bind(owner.address)
        assert caught.value.errno == errno.EADDRINUSE
    with pytest.raises(ProcessLookupError):
        request(owner)


def test_foreign_listener_is_never_adopted_or_stopped():
    with socket.socket() as foreign:
        foreign.bind(("127.0.0.1", 0))
        foreign.listen()
        address = foreign.getsockname()
        with pytest.raises(OSError) as caught:
            platform.reserve_loopback_listener(address[1])
        assert caught.value.errno == errno.EADDRINUSE
        assert foreign.getsockname() == address


def test_closed_resource_cannot_admit_later_port_replacement():
    owner = platform.reserve_loopback_listener(0)
    address = owner.address
    owner.close()
    with socket.socket() as foreign:
        foreign.bind(address)
        foreign.listen()
        with pytest.raises(ProcessLookupError, match="owner resource"):
            request(owner)
        assert foreign.getsockname() == address


@pytest.mark.parametrize("mode", ["ignore", "drip"])
def test_total_deadline_bounds_no_accept_and_slow_http_then_owned_stop(mode):
    owner, _ready = start_subject(mode)
    collateral = platform.spawn_tree([sys.executable, "-c", "import time; time.sleep(30)"])
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            with owner.connection(deadline=started + 0.2) as stream:
                stream.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                with response:
                    response.read(4096)
        assert time.monotonic() - started < 2
        platform.stop_tree(owner.child, grace=0.05)
        assert owner.child.returncode is not None
        assert not platform.tree_exited(collateral)
    finally:
        dispose(owner)
        platform.stop_tree(collateral, grace=0.05)


def test_child_exit_during_actual_http_invalidates_buffered_success():
    owner, _ready = start_subject("exit")
    fd = platform.pidfd_open(owner.child.pid)
    try:
        with pytest.raises(ProcessLookupError, match="exited"):
            with owner.connection(deadline=time.monotonic() + 3) as stream:
                stream.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                with response:
                    assert json.loads(response.read())["pid"] == owner.child.pid
                assert select.select([fd], [], [], 2)[0]
        assert owner.child.returncode is None  # exited, still held unreaped
    finally:
        os.close(fd)
        dispose(owner)


def test_listener_and_other_parent_descriptors_do_not_leak_through_exec():
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    owner = None
    try:
        owner, ready = start_subject("leak:" + str(write_fd))
        assert ready["unrelated_fd_closed"]
        assert ready["exec_fd_closed"]
        assert request(owner)["pid"] == owner.child.pid
    finally:
        if owner is not None:
            dispose(owner)
        os.close(read_fd)
        os.close(write_fd)


def test_launch_attempt_is_not_replayed_after_an_error(monkeypatch):
    owner = platform.reserve_loopback_listener(0)
    calls = []
    def failed(*args, **kwargs):
        calls.append((args, kwargs))
        raise OSError("ambiguous native spawn")
    monkeypatch.setattr(platform, "spawn_tree", failed)
    try:
        with pytest.raises(OSError):
            owner.spawn(["subject"], cwd="/", env={})
        with pytest.raises(RuntimeError, match="already attempted"):
            owner.spawn(["subject"], cwd="/", env={})
        assert len(calls) == 1
    finally:
        owner.close()


def test_live_child_cannot_be_replaced_or_parent_anchor_closed(owned):
    owner, _ready = owned
    with pytest.raises(RuntimeError, match="already attempted"):
        owner.spawn(["subject"], cwd="/", env={})
    with pytest.raises(ProcessLookupError, match="stop and reap"):
        owner.close()
    assert request(owner)["pid"] == owner.child.pid


def test_waiter_contention_obeys_deadline(owned):
    owner, _ready = owned
    guard = owner.child._waitpid_lock
    with guard:
        with pytest.raises(TimeoutError, match="waiter is busy"):
            request(owner, seconds=0.05)
    assert request(owner)["pid"] == owner.child.pid


def test_reaped_child_cannot_authorize_health(owned):
    owner, _ready = owned
    platform.stop_tree(owner.child, grace=0.05)
    with pytest.raises(ProcessLookupError, match="unavailable or reaped"):
        request(owner)


def test_external_wait_ownership_loss_refuses(owned):
    owner, _ready = owned
    platform.signal_tree(owner.child, platform.KILL)
    os.waitpid(owner.child.pid, 0)  # violate sole-waiter contract deliberately
    try:
        with pytest.raises(ProcessLookupError, match="wait ownership was lost"):
            request(owner)
    finally:
        # Record the positive reap evidence for fixture resource release only.
        owner.child.returncode = -platform.KILL


def test_cancellation_uses_existing_scope_and_preserves_cleanup(owned):
    owner, _ready = owned
    stop = threading.Event()
    with cancellation.startup_scope(stop):
        stop.set()
        with pytest.raises(cancellation.StartupCancelled):
            request(owner)
    assert request(owner)["pid"] == owner.child.pid


def test_cancellation_interrupts_blocked_read_within_scope():
    owner, _ready = start_subject("ignore")
    stop = threading.Event()
    trigger = threading.Timer(0.1, stop.set)
    trigger.start()
    started = time.monotonic()
    try:
        with cancellation.startup_scope(stop):
            with pytest.raises(cancellation.StartupCancelled):
                with owner.connection(deadline=started + 5) as stream:
                    stream.recv(1)
        assert time.monotonic() - started < 2
    finally:
        trigger.join()
        dispose(owner)


def test_http_peer_disconnect_is_not_successful_health():
    owner, _ready = start_subject("disconnect")
    try:
        with pytest.raises(http.client.IncompleteRead):
            request(owner)
        assert not platform.tree_exited(owner.child)
    finally:
        dispose(owner)


def test_listener_shutdown_invalidates_binding_before_health(owned):
    owner, _ready = owned
    # Shared underlying socket state can change through a passed descriptor.
    # Deliberately break it and ensure a live child alone cannot admit health.
    owner._listener.shutdown(socket.SHUT_RDWR)
    with pytest.raises(ProcessLookupError, match="binding changed"):
        request(owner)


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), "later", -1])
def test_invalid_or_expired_deadline_never_connects(deadline):
    owner = platform.reserve_loopback_listener(0)
    try:
        with pytest.raises((ValueError, TimeoutError)):
            with owner.connection(deadline=deadline):
                pytest.fail("invalid deadline connected")
    finally:
        owner.close()


@pytest.mark.parametrize("port", [-1, 65536, True, "8188"])
def test_invalid_port_refuses(port):
    with pytest.raises(ValueError):
        platform.reserve_loopback_listener(port)


def test_no_serialized_handle_can_reconstitute_authority(owned):
    owner, _ready = owned
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(owner)


def test_actual_custodian_crash_keeps_engine_but_refuses_replacement():
    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("listener_fixtures.py")), "owner-loss"],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert [json.loads(line) for line in result.stdout.splitlines()] == [
        {"finite_launcher_exited": True, "peer_lost": True, "owner_lost": True,
         "engine_survived": True, "replacement_refused": True, "collateral_alive": True},
        {"all_fixture_children_reaped": True},
    ]


def test_private_ipc_uses_kernel_peer_credentials_and_rejects_name_replacement():
    name = b"\0astrid-a2-test-" + uuid.uuid4().hex.encode()
    listener = platform.linux_abstract_listener(name)
    listener.settimeout(3)
    client = platform.spawn_tree(
        [sys.executable, "-c", "import sys,time; from runtime_protocol import platform; "
         "s=platform.linux_abstract_connect(bytes.fromhex(sys.argv[1]),deadline=time.monotonic()+3); "
         "s.sendall(b'hello'); time.sleep(30)", name.hex()],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
    )
    try:
        with pytest.raises(OSError) as caught:
            platform.linux_abstract_listener(name)
        assert caught.value.errno == errno.EADDRINUSE
        with listener.accept()[0] as peer:
            peer.settimeout(3)
            assert platform.handoff_peer_uid(peer) == platform.current_user()
            assert platform.handoff_peer_pid(peer) == client.pid
            assert peer.recv(5) == b"hello"
            assert not listener.get_inheritable()
        assert not platform.tree_exited(client)
    finally:
        platform.stop_tree(client, grace=0.05)
        listener.close()
    with pytest.raises(ConnectionRefusedError):
        platform.linux_abstract_connect(name, deadline=time.monotonic() + 1)


@pytest.mark.parametrize("name", [b"", b"astrid-test", "@astrid-test", b"\0foreign", b"\0astrid-../bad", b"\0astrid-" + b"a" * 108])
def test_private_ipc_invalid_names_refuse_before_connect(name):
    with pytest.raises(ValueError):
        platform.linux_abstract_listener(name)
    with pytest.raises(ValueError):
        platform.linux_abstract_connect(name, deadline=time.monotonic() + 1)
