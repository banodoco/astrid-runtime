"""Real Linux control socket tests. This endpoint cannot authorize a writer."""
import array
import json
import multiprocessing
import os
import socket
import struct
from types import SimpleNamespace

import pytest

from astrid_runtime import lifecycle_transfer_broker as transport
from test_lifecycle_transfer_session import contender, fixture

pytestmark = pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED") or not os.path.exists("/proc/self/cgroup"), reason="Linux only")
CAPABILITY = "a" * 64


def broker(path, support, binding, controller, pipe):
    from astrid_runtime.lifecycle_transfer import begin_transfer
    from runtime_protocol.lifecycle_transfer_control import ProvisionalControl
    config = SimpleNamespace(runtime_support=support, bootstrap_lock_path=support / "bootstrap.lock")
    with begin_transfer(config, binding=binding) as session:
        with ProvisionalControl(path, session=session, binding=binding, controller=controller, capability=CAPABILITY) as control:
            pipe.send((os.getpid(), session.binding_digest))
            while not pipe.poll():
                control.serve_once(timeout=0.1)
    pipe.send("closed")


def wrong_peer(path, expected, request, pipe):
    try:
        reply = exchange(path, expected, request)
        pipe.send(reply)
    except (OSError, transport.TransferError):
        pipe.send(None)


def encode(value):
    data = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(data)) + data


def exchange(path, peer, request=None, *, raw=None, rights=None):
    with transport.connect(path, peer) as conn:
        conn.settimeout(5)
        data = raw if raw is not None else encode(request)
        if rights is None:
            conn.sendall(data)
        else:
            conn.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))])
        conn.shutdown(socket.SHUT_WR)
        output = bytearray()
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            output.extend(chunk)
        if not output:
            return None
        assert struct.unpack("!I", output[:4])[0] == len(output) - 4
        return json.loads(output[4:])


@pytest.fixture
def running(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    controller = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": controller.pid, "uid": controller.uid, "birth": controller.birth}
    path = tmp_path / "control.sock"
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=broker, args=(path, config.runtime_support, binding, controller, child))
    process.start()
    child.close()
    assert parent.poll(10)
    pid, digest = parent.recv()
    peer = transport.linux_peer_identity(pid)
    request = {"version": "astrid.provisional-control/v1", "capability": CAPABILITY,
               "operation_id": binding["operation_id"], "generation": binding["generation"],
               "binding_digest": digest, "request_id": "first", "expected_phase": "observed",
               "sequence": 1, "action": "query", "target_phase": ""}
    try:
        yield path, root, peer, request
    finally:
        parent.send("stop")
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
        assert process.exitcode == 0
        parent.close()


def test_live_controller_retains_lock_and_refuses_admission_and_writer(running):
    path, root, peer, request = running
    assert contender(root / "owner.lock") == 17
    assert exchange(path, peer, request) == {"code": "observed", "phase": "observed", "request_count": 0}
    admission = dict(request, action="transition", target_phase="held_admitted")
    first = exchange(path, peer, admission)
    assert first["code"] == "incomplete_census"
    assert exchange(path, peer, admission) == first
    assert exchange(path, peer, dict(admission, target_phase="writer_claimed")) is None
    writer = dict(admission, request_id="second", sequence=2, target_phase="writer_claimed")
    assert exchange(path, peer, writer)["code"] == "lease_uncertain"
    assert exchange(path, peer, dict(request, sequence=3))["request_count"] == 2
    assert contender(root / "owner.lock") == 17


@pytest.mark.parametrize("change", ["capability", "operation_id", "generation", "binding_digest", "sequence", "extra"])
def test_bad_binding_fails_closed(running, change):
    path, root, peer, request = running
    altered = dict(request)
    altered[change] = 2 if change == "sequence" else "wrong"
    assert exchange(path, peer, altered) is None
    assert exchange(path, peer, request)["request_count"] == 0
    assert contender(root / "owner.lock") == 17


def test_rejects_malformed_trailing_and_ancillary(running):
    path, _, peer, request = running
    payload = encode(request)
    for raw in (payload + b"x", b"\x00\x00\x40\x01", b"\x00\x00\x00\x0d{\"x\":1,\"x\":2}"):
        assert exchange(path, peer, raw=raw) is None
    fd = os.open("/dev/null", os.O_RDONLY)
    try:
        assert exchange(path, peer, request, rights=[fd]) is None
    finally:
        os.close(fd)
    assert exchange(path, peer, request)["request_count"] == 0


def test_different_process_cannot_control(running):
    path, root, peer, request = running
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe()
    process = ctx.Process(target=wrong_peer, args=(path, peer, request, child))
    process.start()
    child.close()
    assert parent.poll(10) and parent.recv() is None
    process.join(10)
    assert process.exitcode == 0
    assert exchange(path, peer, request)["request_count"] == 0
    assert contender(root / "owner.lock") == 17
    parent.close()


def test_second_connection_rejected_while_controller_active(running):
    path, _, peer, request = running
    with transport.connect(path, peer) as first:
        first.settimeout(5)
        first.sendall(encode(request)[:5])
        with transport.connect(path, peer) as second:
            second.settimeout(5)
            try:
                second.sendall(encode(request))
                second.shutdown(socket.SHUT_WR)
                assert second.recv(1) == b""
            except (BrokenPipeError, ConnectionResetError):
                pass
        first.sendall(encode(request)[5:])
        first.shutdown(socket.SHUT_WR)
        assert first.recv(4)
    assert exchange(path, peer, request)["code"] == "observed"
