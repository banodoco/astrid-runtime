"""CPU-only ownership protocol proof; no kernel signaling qualification."""

from concurrent.futures import ThreadPoolExecutor
import os
import signal
import socket
import threading
import traceback
from types import SimpleNamespace

import pytest

from astrid_runtime import custody_broker as custody
from runtime_protocol import platform as runtime_platform


@pytest.fixture
def graph(tmp_path, monkeypatch):
    identities = {pid: {"pid": pid, "uid": 501, "birth_id": f"birth-{pid}"} for pid in (101, 102, 103)}
    tokens = {pid: {"pid": pid, "uid": 501, "pidversion": pid + 1,
                    "sha256": f"sha256:token-{pid}", "words": [pid] * 8} for pid in identities}
    monkeypatch.setattr(custody, "audit_token_details", lambda words: {k: v for k, v in tokens[words[0]].items() if k != "words"})
    observe = identities.get
    actors = {pid: custody.AuthenticatedCleanupActor(lambda pid=pid: tokens[pid], observe) for pid in (101, 102)}
    authority = custody.RoleCustodyAuthority(tmp_path / "scope", "engine", timeout=0.2)
    authority.designate_pending(actor=actors[101], identity=identities[103], token=tokens[103], owner_epoch="runtime-A")
    authority.bind_target(actor=actors[101], generation=1, identity=identities[103], token=tokens[103])
    return authority, actors, identities, tokens


def transfer(graph, *, transition_id="handoff-1", dead_actor=None):
    authority, actors, _, _ = graph
    return authority.transfer(actor=actors[102] if dead_actor else actors[101], next_actor=actors[102], generation=1,
                              transition_id=transition_id, owner_epoch="runtime-B", dead_actor=dead_actor)


def fire(graph, *, actor_pid=101, generation=1, observe=None, signal_provider=None):
    authority, actors, identities, _ = graph
    authority.signal(actor=actors[actor_pid], generation=generation, expected_target=authority.reference()["target"],
                     signum=signal.SIGTERM, identity_provider=observe or identities.get,
                     signal_provider=signal_provider or (lambda words, signum: None))


def test_pending_cleanup_owner_is_durable_but_cannot_signal(tmp_path, graph):
    _, actors, identities, tokens = graph
    authority = custody.RoleCustodyAuthority(tmp_path / "pending", "host")
    authority.designate_pending(actor=actors[101], identity=identities[103], token=tokens[103], owner_epoch="runtime-A")
    with pytest.raises(custody.CustodyError, match="pending"):
        authority.signal(actor=actors[101], generation=1, expected_target=authority.reference()["target"],
                         signum=signal.SIGKILL, identity_provider=identities.get, signal_provider=lambda *_: pytest.fail("pending signal"))


def test_pre_spawn_obligation_binds_only_exact_admission_before_exec(tmp_path, graph):
    _, actors, identities, tokens = graph
    authority = custody.RoleCustodyAuthority(tmp_path / "launch", "relay")
    authority.reserve_before_spawn(actor=actors[101], owner_epoch="runtime-A", admission_id="launch-1")
    assert authority.reference()["target"] == {"admission_id": "launch-1"}
    with pytest.raises(custody.CustodyError, match="differs"):
        authority.bind_pending(actor=actors[101], admission_id="other-launch", identity=identities[103], token=tokens[103])
    authority.bind_pending(actor=actors[101], admission_id="launch-1", identity=identities[103], token=tokens[103])
    authority.bind_target(actor=actors[101], generation=1, identity=identities[103], token=tokens[103])
    with pytest.raises(custody.CustodyError, match="differs"):
        authority.bind_pending(actor=actors[101], admission_id="launch-1", identity=identities[103], token=tokens[103])


def test_signal_holds_shared_guard_until_kernel_call_completes(graph):
    authority, _, _, _ = graph
    in_kernel, release, attempted, transferred = (threading.Event() for _ in range(4))
    events = []

    def kernel(*_):
        in_kernel.set()
        assert release.wait(1)
        events.append("kernel-complete")

    def move():
        attempted.set()
        result = transfer(graph)
        events.append("transfer-durable")
        transferred.set()
        return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        signaling = pool.submit(fire, graph, signal_provider=kernel)
        assert in_kernel.wait(1)
        moving = pool.submit(move)
        assert attempted.wait(1)
        assert not transferred.wait(0.03)
        release.set()
        signaling.result(timeout=1)
        assert moving.result(timeout=1)["generation"] == 2
    assert events == ["kernel-complete", "transfer-durable"]
    assert authority.reference()["generation"] == 2


@pytest.mark.parametrize("actor_pid,generation", [(101, 1), (101, 2), (102, 1)])
def test_old_actor_or_generation_cannot_signal_after_transfer(graph, actor_pid, generation):
    transfer(graph)
    with pytest.raises(custody.CustodyError, match="stale"):
        fire(graph, actor_pid=actor_pid, generation=generation, signal_provider=lambda *_: pytest.fail("stale signal"))
    fire(graph, actor_pid=102, generation=2)


def test_transfer_before_durable_commit_leaves_old_owner(graph, monkeypatch):
    authority, _, _, _ = graph
    write = authority._write
    monkeypatch.setattr(authority, "_write", lambda _: (_ for _ in ()).throw(OSError("before write")))
    with pytest.raises(OSError, match="before write"):
        transfer(graph)
    assert authority.reference()["generation"] == 1
    fire(graph)
    monkeypatch.setattr(authority, "_write", write)
    assert transfer(graph)["generation"] == 2


def test_commit_then_lost_ack_recovers_exact_durable_replay(graph, monkeypatch):
    authority, _, _, _ = graph
    write = authority._write

    def lose_ack(record):
        write(record)
        raise OSError("lost ACK")

    monkeypatch.setattr(authority, "_write", lose_ack)
    with pytest.raises(OSError, match="lost ACK"):
        transfer(graph)
    assert authority.reference()["generation"] == 2
    monkeypatch.setattr(authority, "_write", lambda _: pytest.fail("replay must not recommit"))
    ack = transfer(graph)
    assert transfer(graph) == ack
    with pytest.raises(custody.CustodyError, match="conflicts"):
        authority.transfer(actor=graph[1][101], next_actor=graph[1][102], generation=1,
                           transition_id="handoff-1", owner_epoch="different")


class Child:
    pid = 101
    exit_code = None

    def poll(self):
        return self.exit_code


def test_positive_owned_child_exit_allows_recovery_but_unknown_does_not(graph):
    child = Child()
    retained = custody.RetainedChildActor(child, graph[1][101])
    with pytest.raises(custody.CustodyError, match="positive"):
        transfer(graph, dead_actor=retained)
    child.exit_code = 0
    assert transfer(graph, dead_actor=retained)["generation"] == 2
    fire(graph, actor_pid=102, generation=2)


def test_pid_reuse_or_absence_never_creates_actor_death_proof(graph):
    _, actors, identities, _ = graph
    child = Child()
    retained = custody.RetainedChildActor(child, actors[101])
    identities[101] = {"pid": 101, "birth_id": "reused", "uid": 501}
    with pytest.raises(custody.CustodyError, match="positive"):
        transfer(graph, dead_actor=retained)
    identities.pop(101)
    with pytest.raises(custody.CustodyError, match="positive"):
        transfer(graph, dead_actor=retained)
    assert graph[0].reference()["generation"] == 1


@pytest.mark.parametrize("observed", [None, {"pid": 103, "birth_id": "reused", "uid": 501}])
def test_unknown_or_reused_target_never_signals(graph, observed):
    with pytest.raises(custody.CustodyError, match="unknown"):
        fire(graph, observe=lambda _: observed, signal_provider=lambda *_: pytest.fail("unknown target signal"))


def test_runtime_epoch_transition_does_not_seize_delegated_roles(graph):
    authority, actors, identities, tokens = graph
    relay = custody.RoleCustodyAuthority(authority.root, "relay")
    relay.designate_pending(actor=actors[101], identity=identities[103], token=tokens[103], owner_epoch="runtime-A")
    relay.bind_target(actor=actors[101], generation=1, identity=identities[103], token=tokens[103])
    relay.transfer(actor=actors[101], next_actor=actors[102], generation=1, transition_id="runtime-transfer", owner_epoch="runtime-B")
    assert relay.reference()["generation"] == 2
    assert authority.reference()["generation"] == 1
    fire(graph)


def test_bounded_exclusive_lock_timeout_leaves_authority_unchanged(graph):
    authority = graph[0]
    with authority._guard(exclusive=False):
        with pytest.raises(custody.CustodyError, match="timed out"):
            transfer(graph)
    assert authority.reference()["generation"] == 1


def test_inherited_creator_credentials_do_not_bind_retained_child(graph, monkeypatch):
    from types import SimpleNamespace
    _, _, identities, tokens = graph
    child = SimpleNamespace(pid=103, returncode=None, _waitpid_lock=threading.Lock())
    identities[103]["parent_pid"] = __import__("os").getpid()
    monkeypatch.setattr(custody, "_peer_token", lambda _: tokens[101])
    actor = custody.AuthenticatedCleanupActor.retained_child(child, reap_guard=threading.RLock(), identity_provider=identities.get, token_provider=tokens.get)
    assert actor.verify()["pid"] == 103
    identities[103]["birth_id"] = "reused"
    with pytest.raises(custody.CustodyError, match="changed"):
        actor.verify()


def test_retained_binding_serializes_waiter_and_refuses_changed_capture(graph):
    from types import SimpleNamespace
    _, _, identities, tokens = graph
    identities[103]["parent_pid"] = __import__("os").getpid()
    wait_guard = threading.Lock()
    child = SimpleNamespace(pid=103, returncode=None, _waitpid_lock=wait_guard)
    def token(pid):
        assert wait_guard.locked(), "waiter must be excluded throughout kernel binding"
        identities[103] = {**identities[103], "birth_id": "replacement"}
        return tokens[pid]
    with pytest.raises(custody.CustodyError, match="changed") as error:
        custody.AuthenticatedCleanupActor.retained_child(child, reap_guard=threading.RLock(), identity_provider=identities.get, token_provider=token)
    assert str(error.value).endswith("[stage=retained_child.after; identity=available; mismatched_fields=birth_id]")


@pytest.mark.parametrize("edge,diagnostic", [
    ("before-absent", "stage=retained_child.before; identity=absent; mismatched_fields=none"),
    ("wrong-parent", "stage=retained_child.before; identity=available; mismatched_fields=parent_pid"),
    ("after-absent", "stage=retained_child.after; identity=absent; mismatched_fields=none"),
])
def test_retained_binding_diagnostics_preserve_refusal(graph, edge, diagnostic):
    identity = {**graph[2][103], "parent_pid": os.getpid()}
    child = SimpleNamespace(pid=103, returncode=None, _waitpid_lock=threading.Lock())
    if edge == "before-absent":
        observations = iter([None])
    elif edge == "wrong-parent":
        observations = iter([{**identity, "parent_pid": os.getpid() + 1}])
    else:
        observations = iter([identity, identity, None])
    with pytest.raises(custody.CustodyError) as error:
        custody.AuthenticatedCleanupActor.retained_child(child, reap_guard=threading.RLock(),
            identity_provider=lambda pid: next(observations), token_provider=graph[3].get)
    assert str(error.value).endswith("[" + diagnostic + "]")
    assert child.returncode is None


@pytest.fixture
def retained_diagnostics(tmp_path, monkeypatch):
    """Production retained/report/abort path with only synthetic OS inputs."""
    from runtime_protocol.local_execution_supervisor import RetainedProcess
    from runtime_protocol import local_worker_composition as composition
    from test_local_worker import host_only_profile_case

    identity = {"pid": 103, "uid": 501, "birth_id": "private-birth", "parent_pid": os.getpid()}
    token = {"pid": 103, "uid": 501, "pidversion": 17, "sha256": "private-token-digest",
             "words": [987654321] * 8, "credential": "synthetic-private-credential"}
    observations = {"identity": dict(identity), "token": dict(token)}

    def observe(kind):
        value = observations[kind]
        if isinstance(value, Exception):
            raise value
        return dict(value) if value is not None else None

    monkeypatch.setattr(custody, "default_process_identity", lambda pid: observe("identity"))
    monkeypatch.setattr(custody, "current_process_audit_token", lambda pid: observe("token"))
    child = SimpleNamespace(pid=103, returncode=None, _waitpid_lock=threading.Lock(), poll=lambda: None)
    retained = RetainedProcess(child)
    actor = retained.bind_actor()
    pinned = retained.verify()
    preparer = composition.CrossProcessWorkerPreparer(profile=host_only_profile_case(), config={}, environment={})
    control, peer = socket.socketpair()
    activation, activation_peer = socket.socketpair()
    events = []
    handle = composition._PreparedWorker(child, identity["birth_id"], control, {}, tmp_path / "config.json",
        retained=retained, host_only=True, activation=activation, owner_epoch="epoch", custody_scope=str(tmp_path),
        preparation={"version": "runtime.local-execution-preparation/v1", "operation_id": "op",
                     "channel_id": "ch", "owner_epoch": "epoch"},
        broker=SimpleNamespace(signal=lambda *a, **k: events.append("signal"),
                               role_authority=SimpleNamespace(reference=lambda: {"unit": "reference"})),
        launch_verifier=SimpleNamespace(verify_child=lambda *a, **k: None), verified_launch=object())
    preparer._active = handle
    retained.wait = lambda timeout: events.append("reap")
    requests = []
    monkeypatch.setattr(composition, "_frame_send", lambda channel, request: (requests.append(request), events.append("request")))

    def acknowledge(channel):
        events.append("ack")
        return {**{k: v for k, v in requests[-1].items() if k != "command"},
                "status": "cleaned", "cleanup": {"host_children": "absent"}}

    monkeypatch.setattr(composition, "_frame_receive", acknowledge)
    try:
        yield SimpleNamespace(identity=identity, token=token, observations=observations, actor=actor,
            pinned=pinned, retained=retained, preparer=preparer, handle=handle, events=events, composition=composition)
    finally:
        for channel in (control, peer, activation, activation_peer):
            channel.close()


def test_retained_diagnostics_healthy_identity_keeps_ack_before_signal_and_reap(retained_diagnostics, capsys, caplog):
    case = retained_diagnostics
    for _ in range(2):
        assert case.retained.verify() == case.pinned
        assert case.preparer._host_only_report(case.handle)["processes"]["host"]["pid"] == 103
    case.preparer.abort(case.handle)
    assert case.events == ["request", "ack", "signal", "reap"]
    assert case.handle.closed and case.preparer._active is None
    assert case.handle.control.fileno() == case.handle.activation.fileno() == -1
    assert case.actor._pinned == case.pinned
    captured = capsys.readouterr()
    assert not captured.out and not captured.err and not caplog.text


@pytest.mark.parametrize("edge,diagnostic", [
    ("pid", "stage=verify.compare; identity=available; mismatched_fields=pid"),
    ("uid", "stage=verify.compare; identity=available; mismatched_fields=uid"),
    ("birth_id", "stage=verify.compare; identity=available; mismatched_fields=birth_id"),
    ("sha256", "stage=verify.compare; identity=available; mismatched_fields=audit_token_sha256"),
    ("pidversion", "stage=verify.compare; identity=available; mismatched_fields=audit_token_pidversion"),
    ("multiple", "stage=verify.compare; identity=available; mismatched_fields=birth_id,audit_token_sha256,audit_token_pidversion"),
    ("absent", "stage=verify.identity; identity=absent; mismatched_fields=none"),
    ("identity-unavailable", "stage=verify.identity; identity=unavailable; mismatched_fields=none"),
    ("token-unavailable", "stage=verify.token; identity=unobserved; mismatched_fields=none"),
    ("token-custody-unavailable", "stage=verify.token; identity=unobserved; mismatched_fields=none"),
    ("invalid-identity", "stage=verify.incarnation; identity=available; mismatched_fields=none"),
    ("invalid-token", "stage=verify.incarnation; identity=available; mismatched_fields=none"),
])
def test_retained_diagnostics_reject_without_disclosing_or_rebinding(retained_diagnostics, edge, diagnostic, capsys, caplog):
    case = retained_diagnostics
    observed = case.observations
    if edge in {"pid", "uid"}:
        observed["identity"][edge] += 1
        observed["token"][edge] += 1
    elif edge in {"birth_id", "multiple"}:
        observed["identity"]["birth_id"] = "changed-private-birth"
    if edge in {"sha256", "multiple"}:
        observed["token"]["sha256"] = "changed-private-token-digest"
    if edge in {"pidversion", "multiple"}:
        observed["token"]["pidversion"] += 1
    if edge == "absent":
        observed["identity"] = None
    elif edge.endswith("unavailable"):
        kind = edge.split("-")[0]
        error_type = custody.CustodyError if "custody" in edge else OSError
        observed[kind] = error_type("synthetic-private-credential 987654321 private-token-digest")
    elif edge == "invalid-identity":
        observed["identity"]["birth_id"] = ""
    elif edge == "invalid-token":
        observed["token"]["uid"] += 1
    # Unknown DTO keys and credential-like data must never become field labels.
    if isinstance(observed["identity"], dict):
        observed["identity"]["private-field-label"] = "synthetic-private-credential"
    for action in (lambda: case.preparer._host_only_report(case.handle), lambda: case.preparer.abort(case.handle)):
        with pytest.raises(custody.CustodyError) as error:
            action()
        message = str(error.value)
        assert message.endswith("[" + diagnostic + "]")
        rendered = "".join(traceback.format_exception(error.value)) + caplog.text + str(capsys.readouterr())
        for secret in ("private-birth", "private-token-digest", "987654321", "synthetic-private-credential", "private-field-label"):
            assert secret not in rendered
        assert len(message) < 300
    assert case.retained.actor is case.actor and case.actor._pinned == case.pinned
    assert case.retained.exit_code is None and case.handle.worker.returncode is None
    assert not case.events  # No request/ACK, signal, or reap after rejection.
    assert case.preparer._active is case.handle and not case.handle.closed
    assert case.handle.control.fileno() >= 0 and case.handle.activation.fileno() >= 0


@pytest.mark.parametrize("ack", ["missing", "wrong-epoch", "children-unresolved"])
def test_retained_diagnostics_invalid_ack_keeps_handle_and_never_signals(retained_diagnostics, monkeypatch, ack):
    case = retained_diagnostics
    original_receive = case.composition._frame_receive

    def receive(channel):
        if ack == "missing":
            raise OSError("synthetic missing ACK")
        response = original_receive(channel)
        if ack == "wrong-epoch":
            response["owner_epoch"] = "other"
        else:
            response["cleanup"]["host_children"] = "unresolved"
        return response

    monkeypatch.setattr(case.composition, "_frame_receive", receive)
    with pytest.raises((OSError, case.composition.ConflictError)):
        case.preparer.abort(case.handle)
    assert "signal" not in case.events and "reap" not in case.events
    assert case.preparer._active is case.handle and not case.handle.closed
    assert case.handle.control.fileno() >= 0 and case.handle.activation.fileno() >= 0
    assert case.actor._pinned == case.pinned


def test_reference_verification_is_read_only_and_requires_exact_designated_actor(graph):
    authority, actors, identities, tokens = graph
    ref = authority.reference()
    before = authority.path.read_bytes()
    assert authority.verify_reference(ref, expected_actor=actors[101].verify(), owner_epoch="runtime-A", identity_provider=identities.get, token_provider=tokens.get) == ref
    assert authority.path.read_bytes() == before
    with pytest.raises(custody.CustodyError, match="designation differs"):
        authority.verify_reference(ref, expected_actor=actors[102].verify(), owner_epoch="runtime-A", identity_provider=identities.get, token_provider=tokens.get)


@pytest.fixture
def runtime_owner(tmp_path, graph):
    _, actors, identities, tokens = graph
    authority = custody.RoleCustodyAuthority(tmp_path / "runtime-scope", "runtime_owner", timeout=0.2)
    authority.designate_pending(actor=actors[101], identity=identities[103], token=tokens[103], owner_epoch="runtime-A")
    authority.bind_target(actor=actors[101], generation=1, identity=identities[103], token=tokens[103])
    return authority, actors, identities, tokens, authority.reference()


def release_runtime(g, actor=101, generation=1, identifier="release-1"):
    return g[0].relinquish(actor=g[1][actor], generation=generation, transition_id=identifier, owner_epoch="runtime-A")


def claim_runtime(g, actor=102, generation=2, identifier="claim-1"):
    return g[0].claim(actor=g[1][actor], generation=generation, transition_id=identifier,
                      sealed=g[4], owner_epoch="runtime-A", identity_provider=g[2].get)


def test_runtime_owner_two_handoff_cycles_fence_historical_claim(runtime_owner):
    g = runtime_owner
    release_runtime(g)
    old_claim = claim_runtime(g)
    release_runtime(g, actor=102, generation=3, identifier="release-2")
    assert claim_runtime(g, actor=101, generation=4, identifier="claim-2")["generation"] == 5
    assert claim_runtime(g) == old_claim  # replay is knowledge of a commit, not current authority
    with pytest.raises(custody.CustodyError, match="stale"):
        g[0].signal(actor=g[1][102], generation=old_claim["generation"], expected_target=g[4]["target"],
                    signum=signal.SIGTERM, identity_provider=g[2].get, signal_provider=lambda *_: pytest.fail("stale signal"))
    with pytest.raises(custody.CustodyError, match="conflicts"):
        claim_runtime(g, actor=101)


@pytest.mark.parametrize("actor,generation", [(102, 1), (101, 2)])
def test_runtime_relinquish_rejects_wrong_actor_or_generation_unchanged(runtime_owner, actor, generation):
    before = runtime_owner[0].path.read_bytes()
    with pytest.raises(custody.CustodyError, match="stale"):
        release_runtime(runtime_owner, actor=actor, generation=generation)
    assert runtime_owner[0].path.read_bytes() == before


def test_legacy_detached_runtime_never_acquires_new_claim_authority(runtime_owner):
    g = runtime_owner
    g[2].pop(101)  # lack of a live actor is not retained exit evidence or relinquishment
    before = g[0].path.read_bytes()
    with pytest.raises(custody.CustodyError, match="not relinquished"):
        claim_runtime(g, generation=1)
    assert g[0].path.read_bytes() == before


@pytest.mark.parametrize("broken", ["epoch", "generation", "kind", "target", "actor", "duplicate"])
def test_runtime_lineage_breaks_refuse_without_write(runtime_owner, broken):
    g = runtime_owner
    release_runtime(g)
    record = g[0]._read()
    if broken == "epoch": record["owner_epoch"] = "wrong"
    elif broken == "generation": record["generation"] = 4
    elif broken == "kind": record["transitions"][0]["intent"]["kind"] = "transfer"
    elif broken == "target": record["transitions"][0]["ack"]["target"] = {}
    elif broken == "actor": record["actor"] = g[1][102].verify()
    else:
        record["transitions"].append(record["transitions"][0])
        record["generation"] += 1
    g[0]._write(record)
    before = g[0].path.read_bytes()
    with pytest.raises(custody.CustodyError, match="lineage"):
        claim_runtime(g)
    assert g[0].path.read_bytes() == before


@pytest.mark.parametrize("failure", ["absent", "reused", "uid"])
def test_runtime_claim_rechecks_incarnation_and_same_uid(runtime_owner, failure):
    g = runtime_owner
    release_runtime(g)
    if failure == "absent": g[2].pop(103)
    elif failure == "reused": g[2][103]["birth_id"] = "replacement"
    else:
        g[2][102]["uid"] = 502
        g[3][102]["uid"] = 502
    before = g[0].path.read_bytes()
    with pytest.raises(custody.CustodyError, match="incarnation|uid"):
        claim_runtime(g)
    assert g[0].path.read_bytes() == before


def test_runtime_claim_exclusive_guard_commits_only_one_successor(runtime_owner):
    g = runtime_owner
    release_runtime(g)
    barrier = threading.Barrier(2)
    def run(actor):
        barrier.wait(timeout=1)
        try:
            return claim_runtime(g, actor=actor, identifier=f"claim-{actor}")
        except custody.CustodyError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [101, 102]))
    assert sum(x is not None for x in results) == 1
    assert g[0].reference()["generation"] == 3


@pytest.mark.parametrize("kind", ["relinquish", "claim"])
def test_runtime_commit_lost_ack_replays_exact_intent(runtime_owner, monkeypatch, kind):
    g = runtime_owner
    if kind == "claim": release_runtime(g)
    action = (lambda: release_runtime(g)) if kind == "relinquish" else (lambda: claim_runtime(g))
    write = g[0]._write
    def lost_ack(record):
        write(record)
        raise OSError("lost ACK")
    monkeypatch.setattr(g[0], "_write", lost_ack)
    with pytest.raises(OSError, match="lost ACK"): action()
    before = g[0].path.read_bytes()
    monkeypatch.setattr(g[0], "_write", lambda _: pytest.fail("replay rewrote designation"))
    ack = action()
    assert ack["generation"] == (2 if kind == "relinquish" else 3)
    assert g[0].path.read_bytes() == before


def test_runtime_release_precommit_failure_preserves_original_signal_authority(runtime_owner, monkeypatch):
    g = runtime_owner
    monkeypatch.setattr(g[0], "_write", lambda _: (_ for _ in ()).throw(OSError("before write")))
    with pytest.raises(OSError): release_runtime(g)
    calls = []
    g[0].signal(actor=g[1][101], generation=1, expected_target=g[4]["target"], signum=signal.SIGTERM,
                identity_provider=g[2].get, signal_provider=lambda *x: calls.append(x))
    assert len(calls) == 1


def test_other_roles_cannot_enter_runtime_relinquish_contract(graph):
    with pytest.raises(custody.CustodyError, match="binding"):
        graph[0].relinquish(actor=graph[1][101], generation=1, transition_id="wrong-role", owner_epoch="runtime-A")
    fire(graph)


@pytest.mark.darwin_native
def test_actual_darwin_self_identity_and_boundary_use_native_shared_marker(monkeypatch):
    import os
    import sys
    from astrid_runtime.runtime_boundary import LocalRuntimeBoundary
    assert sys.platform == "darwin", "this native proof requires its admitted Darwin venue"
    monkeypatch.setattr(custody.subprocess, "run", lambda *a, **k: pytest.fail("native observation spawned ps"))
    actual = custody.default_process_identity(os.getpid())
    assert actual["pid"] == os.getpid() and actual["uid"] == runtime_platform.current_user()
    assert actual["parent_pid"] == os.getppid()
    assert actual["birth_id"].startswith("ps-lstart:")
    assert LocalRuntimeBoundary.process_birth_identity(os.getpid()) == actual["birth_id"]
