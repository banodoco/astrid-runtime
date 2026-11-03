"""Real broker delivery is a one-shot transport probe, never writer admission."""
import json
import multiprocessing
import os
from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

from runtime_protocol import lifecycle_transfer_broker as transport
from test_lifecycle_transfer_control import CAPABILITY, encode, exchange
from test_lifecycle_transfer_session import contender, directory_contender, fixture

pytestmark = pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED") or not os.path.exists("/proc/self/cgroup"), reason="Linux only")


def _broker(path, support, binding, controller, pipe, pause_before_send):
    from astrid_runtime.lifecycle_transfer import begin_transfer
    from runtime_protocol.lifecycle_transfer_control import ProvisionalControl
    if pause_before_send:
        original = transport.send_aliases
        def pause(*args, **kwargs):
            pipe.send("before-send")
            pipe.recv()
            return original(*args, **kwargs)
        transport.send_aliases = pause
    config = SimpleNamespace(runtime_support=support, bootstrap_lock_path=support / "bootstrap.lock")
    try:
        with begin_transfer(config, binding=binding) as session:
            with ProvisionalControl(path, session=session, binding=binding, controller=controller,
                                    capability=CAPABILITY, allow_provisional_delivery=True) as control:
                pipe.send((os.getpid(), session.binding_digest))
                while not pipe.poll():
                    if control.serve_once(timeout=0.1):
                        pipe.send("served")
    except Exception as exc:
        pipe.send(type(exc).__name__)
    finally:
        pipe.close()


def _start(path, support, binding, controller, pause_before_send=False):
    parent, child = multiprocessing.get_context("spawn").Pipe()
    process = multiprocessing.get_context("spawn").Process(target=_broker, args=(path, support, binding, controller, child, pause_before_send))
    process.start()
    child.close()
    assert parent.poll(10)
    return process, parent, parent.recv()


def _stop(process, pipe):
    if process.is_alive():
        try:
            pipe.send("stop")
        except (BrokenPipeError, EOFError):
            pass
        process.join(10)
    if process.is_alive():
        process.terminate()
        process.join(10)
    pipe.close()


def _object(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        return transport._object(fd)
    finally:
        os.close(fd)


def _request(digest, binding):
    return {"version": "astrid.provisional-control/v1", "capability": CAPABILITY,
            "operation_id": binding["operation_id"], "generation": binding["generation"],
            "binding_digest": digest, "request_id": "one", "expected_phase": "observed",
            "sequence": 1, "action": "provisional_delivery", "target_phase": "candidate"}


def _send(path, peer, request, objects):
    with transport.connect(path, peer) as conn:
        conn.sendall(encode(request))
        conn.shutdown(socket.SHUT_WR)
        return transport.receive_aliases(conn, expected_peer=peer, capability=CAPABILITY,
                    binding_digest=request["binding_digest"], sequence=1, role="candidate", expected_objects=objects)


def test_connected_delivery_replay_and_restart_remain_occupied(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    controller = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": controller.pid, "uid": controller.uid, "birth": controller.birth}
    path = Path(os.path.relpath(tmp_path / "d.sock"))
    process, pipe, started = _start(path, config.runtime_support, binding, controller)
    aliases = None
    try:
        pid, digest = started
        peer = transport.linux_peer_identity(pid)
        request = _request(digest, binding)
        aliases = _send(path, peer, request, [_object(root), _object(root / "owner.lock")])
        assert all(not os.get_inheritable(fd) for fd in aliases.filenos())
        aliases.close_directory()
        assert directory_contender(root) == 17
        marker = json.loads((config.runtime_support / "lifecycle-transfer-delivery.json").read_text())
        ledger = json.loads((config.runtime_support / "lifecycle-transfer-ledger.json").read_text())
        assert marker["request_id"] == "one"
        assert ledger["requests"][-1]["result"]["phase"] == "recovery_required"
        assert contender(root / "owner.lock") == 17
        assert exchange(path, peer, request)["code"] == "lease_uncertain"
        assert exchange(path, peer, dict(request, target_phase="migration"))["code"] == "binding_changed"
        process.kill()
        process.join(10)
        assert directory_contender(root) == 0
        assert contender(root / "owner.lock") == 17
        # Kernel aliases prevent a restarted holder from reacquiring the owner.
        path2 = Path(os.path.relpath(tmp_path / "e.sock"))
        other, other_pipe, failed = _start(path2, config.runtime_support, binding, controller)
        try:
            assert failed == "FenceUnavailable"
        finally:
            _stop(other, other_pipe)
        aliases.close()
        aliases = None
        assert contender(root / "owner.lock") == 0
        path3 = Path(os.path.relpath(tmp_path / "f.sock"))
        restarted, restarted_pipe, restart = _start(path3, config.runtime_support, binding, controller)
        try:
            new_pid, new_digest = restart
            assert new_digest == digest
            new_peer = transport.linux_peer_identity(new_pid)
            assert exchange(path3, new_peer, request)["code"] == "lease_uncertain"
            assert exchange(path3, new_peer, dict(request, request_id="two", sequence=2))["code"] == "binding_changed"
            # A missing marker does not permit reuse when the ledger remains occupied.
            (config.runtime_support / "lifecycle-transfer-delivery.json").unlink()
            assert exchange(path3, new_peer, request) is None
            assert contender(root / "owner.lock") == 17
        finally:
            _stop(restarted, restarted_pipe)
    finally:
        if aliases is not None:
            aliases.close()
        _stop(process, pipe)


def test_lost_claim_reply_never_causes_resend(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    controller = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": controller.pid, "uid": controller.uid, "birth": controller.birth}
    path = Path(os.path.relpath(tmp_path / "d.sock"))
    process, pipe, started = _start(path, config.runtime_support, binding, controller)
    try:
        pid, digest = started
        peer = transport.linux_peer_identity(pid)
        request = _request(digest, binding)
        with transport.connect(path, peer) as conn:
            conn.sendall(encode(request))
            conn.shutdown(socket.SHUT_WR)
            # Closing without receiving simulates a lost reply and queued rights.
        assert pipe.poll(10) and pipe.recv() == "served"
        assert exchange(path, peer, request)["code"] == "lease_uncertain"
        assert exchange(path, peer, dict(request, request_id="other"))["code"] == "binding_changed"
        assert contender(root / "owner.lock") == 17
    finally:
        _stop(process, pipe)


def test_crash_at_pre_send_barrier_keeps_durable_slot_occupied(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    controller = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": controller.pid, "uid": controller.uid, "birth": controller.birth}
    path = Path(os.path.relpath(tmp_path / "d.sock"))
    process, pipe, started = _start(path, config.runtime_support, binding, controller, True)
    try:
        pid, digest = started
        peer = transport.linux_peer_identity(pid)
        request = _request(digest, binding)
        with transport.connect(path, peer) as conn:
            conn.sendall(encode(request))
            conn.shutdown(socket.SHUT_WR)
            assert pipe.poll(10) and pipe.recv() == "before-send"
            marker = json.loads((config.runtime_support / "lifecycle-transfer-delivery.json").read_text())
            ledger = json.loads((config.runtime_support / "lifecycle-transfer-ledger.json").read_text())
            assert marker["request_id"] == request["request_id"]
            assert ledger["requests"][-1]["result"]["phase"] == "recovery_required"
            assert contender(root / "owner.lock") == 17
            process.kill()
            process.join(10)
            assert conn.recv(1) == b""
        path2 = Path(os.path.relpath(tmp_path / "e.sock"))
        restarted, restarted_pipe, started2 = _start(path2, config.runtime_support, binding, controller)
        try:
            new_pid, new_digest = started2
            assert new_digest == digest
            peer2 = transport.linux_peer_identity(new_pid)
            assert exchange(path2, peer2, request)["code"] == "lease_uncertain"
            # A replaced marker cannot be interpreted as an available slot.
            marker_path = config.runtime_support / "lifecycle-transfer-delivery.json"
            marker_path.unlink()
            marker_path.write_text("replacement")
            marker_path.chmod(0o600)
            assert exchange(path2, peer2, request)["code"] == "binding_changed"
            assert contender(root / "owner.lock") == 17
        finally:
            _stop(restarted, restarted_pipe)
    finally:
        _stop(process, pipe)
