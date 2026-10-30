"""Real synthetic CPU child, native role authentication, and original wait.

The fixture projects an already selected host profile; package/manifest launch
verification is outside this focused cleanup protocol proof. No custody actor,
peer authentication, role verification, signal, frame, or reap is replaced.
"""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import socket
import subprocess
import sys

from astrid_runtime.custody_broker import RoleBoundCustodyBroker, default_process_identity
from runtime_protocol.local_execution_supervisor import RetainedProcess
from runtime_protocol.local_worker import _digest
from runtime_protocol.local_worker_composition import CrossProcessWorkerPreparer, _PreparedWorker
from tests.test_local_worker import host_only_profile_case


def test_authenticated_delayed_cleanup_ack_precedes_original_child_reap(tmp_path):
    root = Path(__file__).resolve().parents[1]
    scope = tmp_path / "custody"
    scope.mkdir(mode=0o700)
    parent, child_control = socket.socketpair()
    observer, child_observer = socket.socketpair()
    activation, activation_peer = socket.socketpair()
    profile = host_only_profile_case()

    class SelectedHostPreparer(CrossProcessWorkerPreparer):
        def _host_only_report(self, handle):
            handle.retained.verify()
            return {"profile_binding_digest": _digest({"selected": "synthetic-host"}),
                    "custody_capabilities": {"host": handle.broker.role_authority.reference()}}

    code = r'''
import os, socket, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from astrid_runtime.custody_broker import AuthenticatedCleanupActor, RoleCustodyAuthority
from runtime_protocol.local_worker_composition import _frame_receive, _frame_send
channel = socket.socket(fileno=int(sys.argv[2]))
observer = socket.socket(fileno=int(sys.argv[3]))
request = _frame_receive(channel)
actor = AuthenticatedCleanupActor.private_peer(channel)
reference = request["custody_capabilities"]["host"]
RoleCustodyAuthority(Path(request["custody_scope"]), "host").verify_reference(
    reference, expected_actor=actor.verify(), owner_epoch=request["owner_epoch"])
assert reference["target"]["pid"] == os.getpid()
observer.sendall(b"A")
assert observer.recv(1) == b"R"
reply = {k: v for k, v in request.items() if k != "command"}
reply.update(status="cleaned", cleanup={"host_children": "absent"})
_frame_send(channel, reply)
observer.sendall(b"K")
observer.recv(1)
'''
    broker = None
    process = None
    retained = None
    try:
        broker = RoleBoundCustodyBroker(role="host", identity_provider=default_process_identity,
            ledger_root=scope / "admission", authority_scope_root=scope,
            authority_journal=scope / "admissions.jsonl", owner_epoch="synthetic-owner", timeout=5)
        environment = dict(os.environ)
        environment.update(broker.child_environment([sys.executable, "-I", "-c", code, str(root),
            str(child_control.fileno()), str(child_observer.fileno())], start_new_session=True))
        wrapper = "import sys;sys.path.insert(0," + repr(str(root)) + ");from astrid_runtime.custody_broker import child_exec_from_environment;raise SystemExit(child_exec_from_environment())"
        process = subprocess.Popen([sys.executable, "-I", "-c", wrapper], env=environment,
            stdin=subprocess.DEVNULL, pass_fds=(child_control.fileno(), child_observer.fileno()))
        child_control.close()
        child_observer.close()
        broker.wait_until_sealed()
        retained = RetainedProcess(process)
        retained.bind_actor()
        identity = retained.verify()
        preparer = SelectedHostPreparer(profile=profile, config={}, environment={}, cleanup_timeout_seconds=5)
        handle = _PreparedWorker(process, identity["birth_id"], parent, {}, tmp_path / "selected.json",
            retained=retained, broker=broker, owner_epoch="synthetic-owner", custody_scope=str(scope),
            host_only=True, activation=activation, preparation={"version": "runtime.local-execution-preparation/v1",
                "operation_id": "synthetic-operation", "channel_id": "synthetic-channel", "owner_epoch": "synthetic-owner"})
        preparer._active = handle
        observer.settimeout(5)
        with ThreadPoolExecutor(max_workers=1) as pool:
            cleanup = pool.submit(preparer.abort, handle)
            assert observer.recv(1) == b"A"  # Real private-peer + role authority passed.
            assert not cleanup.done()
            assert retained.exit_code is None and process.returncode is None
            observer.sendall(b"R")
            assert observer.recv(1) == b"K"  # Exact positive ACK was put on the wire.
            cleanup.result(timeout=5)
        assert handle.closed and preparer._active is None
        assert isinstance(retained.exit_code, int)
        assert process.returncode == retained.exit_code
    finally:
        # This test retains its sole original Popen through every failure.
        if process is not None and process.returncode is None:
            if broker is not None and broker.state in {"sealed", "ready-bound"}:
                broker.signal(15, expected_pid=process.pid)
            if retained is not None:
                retained.wait(5)
            else:
                process.wait(timeout=5)
        elif broker is not None and process is None:
            broker.abort_before_spawn()
        for channel in (parent, child_control, observer, child_observer, activation, activation_peer):
            channel.close()
