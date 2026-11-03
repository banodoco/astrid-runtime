"""Real Linux connected transport; no native admission or DB writer is granted."""
import json
from dataclasses import replace
import multiprocessing
import os
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from astrid_runtime.lifecycle_transfer import begin_transfer
from runtime_protocol import lifecycle_transfer_broker as broker_module
from runtime_protocol import lifecycle_transfer_transport as transport
from test_lifecycle_transfer_control import CAPABILITY, encode, exchange
from test_lifecycle_transfer_session import contender, directory_contender, fixture

pytestmark = pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED") or not Path("/proc/self/cgroup").exists(), reason="Linux only")
RECIPIENT_CAPABILITY = "b" * 64


def recipient_process(pipe):
    aliases = None
    queued = None
    pipe.send(os.getpid())
    try:
        while True:
            command = pipe.recv()
            if command[0] == "stop":
                return
            if command[0] == "close":
                aliases.close()
                aliases = None
                pipe.send("closed")
                continue
            if command[0] == "directory-close":
                aliases.close_directory()
                pipe.send("directory-closed")
                continue
            if command[0] == "queue-close":
                queued.close()
                queued = None
                pipe.send("queue-closed")
                continue
            _, path, peer, request, objects, role = command
            try:
                if command[0] == "queue":
                    queued = transport.connect(path, peer)
                    queued.sendall(encode(request))
                    queued.shutdown(socket.SHUT_WR)
                    pipe.send("queued")
                    continue
                aliases = broker_module.receive_provisional(path, broker=peer,
                    request=request, expected_objects=objects, role=role)
                pipe.send(("received", [transport.object_id(fd) for fd in aliases.filenos()],
                           [os.get_inheritable(fd) for fd in aliases.filenos()]))
            except (OSError, transport.TransferError):
                pipe.send("refused")
    finally:
        if aliases is not None:
            aliases.close()
        if queued is not None:
            queued.close()
        pipe.close()


def broker_process(path, support, binding, controller, recipient, pipe, stop, sends, failure):
    config = SimpleNamespace(runtime_support=support, bootstrap_lock_path=support / "bootstrap.lock")
    original_send = transport.send_aliases
    original_record = broker_module._create_only
    if failure == "recipient-timeout":
        from runtime_protocol import lifecycle_transfer_control
        lifecycle_transfer_control._TIMEOUT = 0.3

    def send(*args, **kwargs):
        with sends.get_lock():
            sends.value += 1
        if failure == "before-send":
            raise OSError("injected send error")
        if failure == "partial-send":
            class ShortSocket:
                def __init__(self, conn):
                    self.conn = conn

                def __getattr__(self, name):
                    return getattr(self.conn, name)

                def sendmsg(self, buffers, ancillary):
                    return self.conn.sendmsg([buffers[0][:5]], ancillary)

            args = (ShortSocket(args[0]), *args[1:])
        original_send(*args, **kwargs)
        if failure == "after-send":
            raise OSError("injected lost delivery outcome")

    def record(directory, name, value):
        original_record(directory, name, value)
        if name == broker_module._DELIVERY and failure == "after-marker":
            raise OSError("injected persistence error")

    transport.send_aliases = send
    broker_module._create_only = record
    with begin_transfer(config, binding=binding) as session:
        with broker_module.TransferBroker(path, session=session, binding=binding,
                controller=controller, capability=CAPABILITY, recipient_path=path.parent / "recipient",
                recipient=recipient, recipient_capability=RECIPIENT_CAPABILITY) as broker:
            realm = session._custody._realm
            pipe.send((os.getpid(), session.binding_digest,
                       [transport.object_id(realm._directory_fd), transport.object_id(realm._owner_fd)]))
            broker.serve_forever(stop)
    pipe.close()


@pytest.fixture
def connected(tmp_path):
    processes = []
    pipes = []

    def start(failure=None):
        config, root, _, binding = fixture(tmp_path)
        controller = transport.linux_peer_identity(os.getpid())
        binding["controller"] = {"pid": controller.pid, "uid": controller.uid, "birth": controller.birth}
        ctx = multiprocessing.get_context("spawn")
        receiver_pipe, receiver_child = ctx.Pipe()
        receiver = ctx.Process(target=recipient_process, args=(receiver_child,))
        receiver.start()
        receiver_child.close()
        processes.append(receiver)
        pipes.append(receiver_pipe)
        assert receiver_pipe.poll(10) and receiver_pipe.recv() == receiver.pid
        recipient = transport.linux_peer_identity(receiver.pid)
        parent, child = ctx.Pipe()
        stop = ctx.Event()
        sends = ctx.Value("i", 0)
        path = tmp_path / "control"
        process = ctx.Process(target=broker_process, args=(path, config.runtime_support,
            binding, controller, recipient, child, stop, sends, failure))
        process.start()
        child.close()
        processes.append(process)
        pipes.append(parent)
        assert parent.poll(10)
        pid, digest, objects = parent.recv()
        request = {"version": broker_module.VERSION, "capability": CAPABILITY,
            "operation_id": binding["operation_id"], "generation": binding["generation"],
            "binding_digest": digest, "request_id": "delivery", "expected_phase": "observed",
            "sequence": 1, "action": "deliver-provisional", "target_phase": ""}
        return SimpleNamespace(path=path, support=config.runtime_support, root=root,
            config=config, binding=binding, request=request, peer=transport.linux_peer_identity(pid),
            objects=objects, receiver=receiver, receiver_pipe=receiver_pipe, broker=process,
            stop=stop, sends=sends, recipient=recipient)

    yield start
    # Close listeners first so a refused or not-yet-accepted recipient wakes.
    for process in reversed(processes):
        if process.is_alive():
            process.terminate()
        process.join(10)
        assert not process.is_alive()
    for pipe in pipes:
        pipe.close()


def receive(started, *, command="receive", **changes):
    request = dict(started.request, capability=RECIPIENT_CAPABILITY)
    request.update(changes)
    started.receiver_pipe.send((command, started.path.parent / "recipient", started.peer,
                               request, started.objects, "candidate"))


def receiver_result(started):
    assert started.receiver_pipe.poll(10)
    return started.receiver_pipe.recv()


def query(started):
    return exchange(started.path, started.peer, dict(started.request, action="query",
                    request_id="query", expected_phase="recovery_required", sequence=2))


def test_connected_delivery_is_close_only_and_broker_loss_preserves_kernel_lock(connected):
    run = connected()
    assert contender(run.root / "owner.lock") == 17
    assert directory_contender(run.root) == 17
    receive(run)
    result = exchange(run.path, run.peer, run.request)
    assert result == {"code": "lease_uncertain", "stage": "provisional_delivery",
        "phase": "recovery_required", "side_effects": "uncertain", "writer_occupancy": "uncertain"}
    assert receiver_result(run) == ("received", run.objects, [False, False])
    assert run.sends.value == 1
    record = json.loads((run.support / broker_module._DELIVERY).read_bytes())
    assert record["request_digest"] == broker_module.request_binding(run.request)
    assert "capability" not in record["request"]
    assert record["disposition"] == "may_have_delivered"
    assert query(run)["writer_occupancy"] == "uncertain"
    # No native/verifier/adoption object or admitted phase was manufactured.
    ledger = json.loads((run.support / "lifecycle-transfer-ledger.json").read_bytes())
    assert ledger["requests"][0]["request"]["reason"] == "lease_uncertain"
    run.receiver_pipe.send(("directory-close",))
    assert receiver_result(run) == "directory-closed"
    assert directory_contender(run.root) == 17  # holder still has its alias
    # Abrupt broker death, not a validated handoff, must preserve the owner FD.
    run.broker.terminate()
    run.broker.join(10)
    assert contender(run.root / "owner.lock") == 17
    assert directory_contender(run.root) == 0
    run.receiver_pipe.send(("close",))
    assert receiver_result(run) == "closed"
    assert contender(run.root / "owner.lock") == 0


@pytest.mark.parametrize("failure", [None, "before-send", "partial-send", "after-send", "after-marker"])
def test_replay_changed_requests_and_failed_delivery_never_resend(connected, failure):
    run = connected(failure)
    receive(run)
    result = exchange(run.path, run.peer, run.request)
    assert result["code"] == ("durability_failed" if failure == "after-marker" else "lease_uncertain")
    if failure != "after-marker":
        received = receiver_result(run)
        if failure in ("before-send", "partial-send"):
            assert received == "refused"
        else:
            assert received[0] == "received"
    attempts = run.sends.value
    assert attempts == (0 if failure == "after-marker" else 1)
    marker = run.support / broker_module._DELIVERY
    before = marker.read_bytes()
    for _ in range(2):
        assert exchange(run.path, run.peer, run.request) == result
    for change in ({"request_id": "second"}, {"sequence": 2},
                   {"expected_phase": "recovery_required"}, {"target_phase": "candidate"}):
        response = exchange(run.path, run.peer, dict(run.request, **change))
        assert response is None or response["code"] == "binding_changed"
    assert run.sends.value == attempts
    assert marker.read_bytes() == before
    assert contender(run.root / "owner.lock") == 17
    if failure in ("before-send", "partial-send"):
        run.stop.set()
        run.broker.join(10)
        assert run.broker.exitcode == 0
        assert contender(run.root / "owner.lock") == 0
        assert directory_contender(run.root) == 0


@pytest.mark.parametrize("change", [{"capability": "c" * 64}, {"sequence": 2},
                                    {"generation": "other"}, {"version": "astrid.provisional-control/v1"}])
def test_mismatched_recipient_consumes_slot_without_delivering(connected, change):
    run = connected()
    receive(run, **change)
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert receiver_result(run) == "refused"
    assert run.sends.value == 0
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert query(run)["writer_occupancy"] == "uncertain"
    assert contender(run.root / "owner.lock") == 17


def test_recipient_death_and_lost_ack_do_not_release_another_writer(connected):
    run = connected("after-send")
    receive(run)
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert receiver_result(run)[0] == "received"
    run.receiver.terminate()
    run.receiver.join(10)
    assert contender(run.root / "owner.lock") == 17
    assert directory_contender(run.root) == 17
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    writer = dict(run.request, action="transition", target_phase="writer_claimed",
                  request_id="writer", sequence=2, expected_phase="recovery_required")
    assert exchange(run.path, run.peer, writer)["code"] == "lease_uncertain"
    assert run.sends.value == 1


def test_existing_tombstone_blocks_new_broker_even_after_delivery_record_loss(connected):
    run = connected()
    receive(run)
    exchange(run.path, run.peer, run.request)
    assert receiver_result(run)[0] == "received"
    run.receiver_pipe.send(("close",))
    assert receiver_result(run) == "closed"
    run.stop.set()
    run.broker.join(10)
    assert run.broker.exitcode == 0
    # Lose BOTH subordinate delivery records; the controller tombstone remains
    # occupied. This is not a claim about loss/rollback of every authority.
    (run.support / broker_module._DELIVERY).unlink()
    (run.support / "lifecycle-transfer-ledger.json").unlink()
    with begin_transfer(run.config, binding=run.binding) as session:
        with pytest.raises(transport.TransferError, match="occupied broker"):
            broker_module.TransferBroker(run.path.parent / "new-control", session=session,
                binding=run.binding, controller=transport.linux_peer_identity(os.getpid()),
                capability=CAPABILITY, recipient_path=run.path.parent / "new-recipient",
                recipient=run.recipient, recipient_capability=RECIPIENT_CAPABILITY)
        assert contender(run.root / "owner.lock") == 17


def test_only_one_controller_can_be_attached_to_a_live_session(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    peer = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": peer.pid, "uid": peer.uid, "birth": peer.birth}
    from runtime_protocol.lifecycle_transfer_control import ProvisionalControl
    with begin_transfer(config, binding=binding) as session:
        with ProvisionalControl(tmp_path / "first", session=session, binding=binding,
                                controller=peer, capability=CAPABILITY):
            with pytest.raises(transport.TransferError, match="already bound"):
                ProvisionalControl(tmp_path / "second", session=session, binding=binding,
                                   controller=peer, capability=CAPABILITY)
        with pytest.raises(transport.TransferError, match="already bound"):
            ProvisionalControl(tmp_path / "third", session=session, binding=binding,
                               controller=peer, capability=CAPABILITY)
        assert contender(root / "owner.lock") == 17


def test_queued_rights_keep_lock_after_broker_death_and_remain_unresolved(connected):
    run = connected()
    receive(run, command="queue")
    assert receiver_result(run) == "queued"
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert query(run)["writer_occupancy"] == "uncertain"
    assert run.sends.value == 1
    run.broker.terminate()
    run.broker.join(10)
    # Recipient has not called recvmsg: queued kernel copies retain BOTH locks.
    assert contender(run.root / "owner.lock") == 17
    assert directory_contender(run.root) == 17
    run.receiver_pipe.send(("queue-close",))
    assert receiver_result(run) == "queue-closed"
    assert contender(run.root / "owner.lock") == 0
    assert directory_contender(run.root) == 0


def test_wrong_recipient_peer_cannot_receive_and_still_occupies_slot(connected):
    run = connected()
    # The authenticated controller is not the frozen recipient process.
    with transport.connect(run.path.parent / "recipient", run.peer) as wrong:
        wrong.sendall(encode(dict(run.request, capability=RECIPIENT_CAPABILITY)))
        wrong.shutdown(socket.SHUT_WR)
        assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
        with pytest.raises((OSError, transport.TransferError)):
            transport.receive_aliases(wrong, expected_peer=run.peer,
                capability=RECIPIENT_CAPABILITY, binding_digest=broker_module.request_binding(run.request),
                sequence=1, role="candidate", expected_objects=run.objects)
    assert run.sends.value == 0
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert contender(run.root / "owner.lock") == 17


@pytest.mark.parametrize("change", [{"version": "astrid.provisional-control/v1"},
    {"sequence": True}, {"expected_phase": "held_admitted"}, {"generation": "stale"},
    {"native_verified": True}, {"capability": "\u00e9" * 64}, {"action": []}])
def test_malformed_stale_or_authority_messages_cannot_reach_delivery(connected, change):
    run = connected()
    assert exchange(run.path, run.peer, dict(run.request, **change)) is None
    assert not (run.support / broker_module._DELIVERY).exists()
    assert run.sends.value == 0
    receive(run)
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert receiver_result(run)[0] == "received"
    assert run.sends.value == 1


def test_recipient_deadline_never_reopens_delivery(connected):
    run = connected("recipient-timeout")
    before = time.monotonic()
    assert exchange(run.path, run.peer, run.request) is None
    assert time.monotonic() - before < 3
    assert run.sends.value == 0
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert query(run)["writer_occupancy"] == "uncertain"
    assert contender(run.root / "owner.lock") == 17


@pytest.mark.parametrize("field,value", [("birth", "wrong"), ("executable", (0, 0)),
                                        ("cgroup_sha256", "0" * 64)])
def test_frozen_recipient_incarnation_is_checked_before_endpoint_creation(tmp_path, field, value):
    config, root, _, binding = fixture(tmp_path)
    peer = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": peer.pid, "uid": peer.uid, "birth": peer.birth}
    with begin_transfer(config, binding=binding) as session:
        with pytest.raises(transport.TransferError, match="recipient"):
            broker_module.TransferBroker(tmp_path / "control", session=session,
                binding=binding, controller=peer, capability=CAPABILITY,
                recipient_path=tmp_path / "recipient", recipient=replace(peer, **{field: value}),
                recipient_capability=RECIPIENT_CAPABILITY)
        assert not (tmp_path / "control").exists()
        assert contender(root / "owner.lock") == 0


def test_replaced_endpoint_keeps_process_and_original_custody_alive(connected):
    run = connected()
    run.path.rename(run.path.parent / "original-control")
    run.path.write_text("replacement")
    # Let the loop perform its next no-follow endpoint validation.
    run.stop.wait(0.3)
    assert run.broker.is_alive()
    assert run.path.read_text() == "replacement"
    assert contender(run.root / "owner.lock") == 17
    assert directory_contender(run.root) == 17
    assert run.sends.value == 0


def test_lost_control_reply_does_not_reauthorize_send(connected):
    run = connected()
    receive(run)
    with transport.connect(run.path, run.peer) as controller:
        controller.sendall(encode(run.request))
        controller.shutdown(socket.SHUT_WR)
        # Drop the reply channel before observing its outcome.
    assert receiver_result(run)[0] == "received"
    assert exchange(run.path, run.peer, run.request)["code"] == "lease_uncertain"
    assert run.sends.value == 1
    assert contender(run.root / "owner.lock") == 17


def test_host_loop_stop_closes_only_endpoints_and_retains_original_session(tmp_path):
    config, root, _, binding = fixture(tmp_path)
    peer = transport.linux_peer_identity(os.getpid())
    binding["controller"] = {"pid": peer.pid, "uid": peer.uid, "birth": peer.birth}
    stop = threading.Event()
    stop.set()
    with begin_transfer(config, binding=binding) as session:
        broker_module.run_transfer_broker(tmp_path / "control", session=session,
            binding=binding, controller=peer, capability=CAPABILITY,
            recipient_path=tmp_path / "recipient", recipient=peer,
            recipient_capability=RECIPIENT_CAPABILITY, stop=stop)
        assert contender(root / "owner.lock") == 17
        assert directory_contender(root) == 17
        assert contender(config.bootstrap_lock_path) == 17
