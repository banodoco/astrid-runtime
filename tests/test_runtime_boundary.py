import errno
import json
import os
import signal
import threading
import time
import signal
import subprocess
import sys
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from astrid_runtime.bootstrap import BootstrapError, SourceProfile
from astrid_runtime.runtime_boundary import ADMISSION_TIMEOUT_ENV, LocalRuntimeBoundary
from runtime_protocol import platform as runtime_platform


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({"status": "ok", "protocol": "workspace.v1"}).encode()


def test_http_health_allows_bounded_startup_latency(monkeypatch):
    observed = {}

    def delayed_health(_request, *, timeout):
        observed["timeout"] = timeout
        return _Response()

    monkeypatch.setattr(
        "urllib.request.OpenerDirector.open",
        lambda _self, request, data=None, timeout=None: delayed_health(request, timeout=timeout),
    )

    assert LocalRuntimeBoundary._http_health("http://127.0.0.1:61217") is True
    assert observed["timeout"] == LocalRuntimeBoundary.HEALTH_TIMEOUT_SECONDS
    assert observed["timeout"] > 0.5


def test_startup_admission_budget_is_validated_and_forwarded(tmp_path, monkeypatch):
    monkeypatch.delenv(ADMISSION_TIMEOUT_ENV, raising=False)
    assert LocalRuntimeBoundary().admission_timeout_seconds == 120.0
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "120")
    boundary = LocalRuntimeBoundary()
    assert boundary.admission_timeout_seconds == 120.0
    assert boundary.wait_seconds >= 125.0
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))
    argv = boundary._argv(
        profile,
        realm_id="realm",
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        display_name="Astrid Workspace",
        owner_lock=tmp_path / "support" / "instance.lock",
        token_file=tmp_path / "support" / "bootstrap-token",
    )
    flag = argv.index("--admission-timeout")
    assert argv[flag + 1] == "120.0"


def test_runtime_start_argv_enables_utf8_mode_and_controls_default_off(tmp_path):
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))
    argv = LocalRuntimeBoundary()._argv(
        profile,
        realm_id="realm",
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        display_name="Astrid Workspace",
        owner_lock=tmp_path / "support" / "instance.lock",
        token_file=tmp_path / "support" / "bootstrap-token",
    )
    assert argv[:4] == [sys.executable, "-X", "utf8", "-m"]
    environment = {**os.environ, "PYTHONUTF8": "0"}
    probe = subprocess.run(
        [*argv[:3], "-c", "import sys; print(sys.flags.utf8_mode)"],
        env=environment, capture_output=True, text=True, check=True,
    )
    control = subprocess.run(
        [sys.executable, "-c", "import sys; print(sys.flags.utf8_mode)"],
        env=environment, capture_output=True, text=True, check=True,
    )
    assert probe.stdout.strip() == "1"
    assert control.stdout.strip() == "0"


def test_runtime_create_and_doctor_argv_enable_utf8_mode(tmp_path, monkeypatch):
    from astrid_runtime import runtime_boundary as module

    calls = []
    monkeypatch.setattr(module.subprocess, "run", lambda argv, **_kwargs: (
        calls.append(list(argv)) or SimpleNamespace(stdout='{"created":true}', returncode=0)
    ))
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))
    boundary = LocalRuntimeBoundary()
    created = boundary.create(realm_id="realm", realm_root=tmp_path / "new-realm",
                              display_name="Astrid Workspace", source_profile=profile)
    assert created == {"created": True}
    support = tmp_path / "existing-realm"
    support.mkdir()
    boundary.inspect(realm_root=support)
    assert all(argv[:4] == [sys.executable, "-X", "utf8", "-m"] for argv in calls)


def test_custody_wrapper_enables_utf8_before_isolation():
    from astrid_runtime.custody_broker import custody_wrapper_argv

    argv = custody_wrapper_argv(sys.executable)
    assert argv[:4] == [sys.executable, "-X", "utf8", "-I"]
    result = subprocess.run(
        [*argv[:4], "-c", "import sys; print(sys.flags.utf8_mode)"],
        env={**os.environ, "PYTHONUTF8": "0"}, capture_output=True, text=True, check=True,
    )
    assert result.stdout.strip() == "1"


def test_default_product_runtime_argv_forwards_validated_authoring_profile(tmp_path):
    profile = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))
    argv = LocalRuntimeBoundary()._argv(
        profile,
        realm_id="realm",
        realm_root=tmp_path / "realm",
        support_root=tmp_path / "support",
        display_name="Astrid Workspace",
        owner_lock=tmp_path / "support" / "instance.lock",
        token_file=tmp_path / "support" / "bootstrap-token",
    )

    assert argv[argv.index("--authoring-profile") + 1] == "astrid"


def test_default_product_runtime_argv_rejects_unmapped_authoring_profile(tmp_path):
    profile = SourceProfile(profile="unknown", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path))

    with pytest.raises(BootstrapError, match="no supported Runtime authoring profile"):
        LocalRuntimeBoundary()._argv(
            profile,
            realm_id="realm",
            realm_root=tmp_path / "realm",
            support_root=tmp_path / "support",
            display_name="Astrid Workspace",
            owner_lock=tmp_path / "support" / "instance.lock",
            token_file=tmp_path / "support" / "bootstrap-token",
        )


def test_direct_runtime_defaults_remain_neutral(tmp_path):
    from runtime_protocol.cli import _parser
    from runtime_protocol.daemon import RuntimeDaemon

    assert _parser().parse_args(["start"]).authoring_profile == "neutral"
    assert RuntimeDaemon(tmp_path / "realm").authoring_profile is None


def test_worker_profile_is_validated_through_installed_source_boundary(tmp_path):
    worker_profile = tmp_path / "worker-profile.json"
    worker_profile.write_text("{}")
    profile = SourceProfile(
        profile="astrid",
        runtime_checkout=str(tmp_path),
        source_checkout=str(tmp_path),
        worker_profile=str(worker_profile),
    )

    LocalRuntimeBoundary._validate_source(profile)


def test_invalid_startup_admission_budget_fails_closed(monkeypatch):
    monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, "not-a-duration")
    with pytest.raises(BootstrapError, match="ADMISSION_TIMEOUT"):
        LocalRuntimeBoundary()


def test_pid_liveness_treats_permission_denied_as_alive(monkeypatch):
    from astrid_runtime import runtime_boundary as module
    from astrid_runtime.custody_broker import CustodyError
    def deny_signal(_pid, _signal):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(os, "kill", deny_signal)
    monkeypatch.setattr(module, "default_process_identity", lambda _: (_ for _ in ()).throw(CustodyError("observation denied")))

    assert LocalRuntimeBoundary.is_pid_alive(12345)


def test_validate_owner_uses_daemon_identity_when_birth_probe_is_unavailable(tmp_path, monkeypatch):
    from astrid_runtime import runtime_boundary as module
    from astrid_runtime.custody_broker import CustodyError
    boundary = LocalRuntimeBoundary()
    owner = tmp_path / "instance.lock"
    owner.write_text(json.dumps({"pid": 12345, "runtime_instance_id": "instance", "process_birth_id": "birth"}))

    def deny_signal(_pid, _signal):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr(os, "kill", deny_signal)
    monkeypatch.setattr(module, "default_process_identity", lambda _: (_ for _ in ()).throw(CustodyError("observation denied")))
    monkeypatch.setattr(boundary, "process_birth_identity", lambda _pid: None)
    monkeypatch.setattr(
        boundary,
        "_http_health_payload",
        lambda _endpoint: {"protocol": "workspace.v1", "status": "ok", "runtime_instance_id": "instance"},
    )
    monkeypatch.setattr(boundary, "_http_status", lambda _endpoint: "ok")

    assert boundary.validate_owner(
        endpoint="http://127.0.0.1:61217",
        pid=12345,
        instance_id="instance",
        owner_lock=owner,
    )
    monkeypatch.setattr(
        boundary,
        "_http_health_payload",
        lambda _endpoint: {"protocol": "workspace.v1", "status": "ok", "runtime_instance_id": "other"},
    )
    assert not boundary.validate_owner(
        endpoint="http://127.0.0.1:61217",
        pid=12345,
        instance_id="instance",
        owner_lock=owner,
    )


def test_slow_healthy_runtime_and_degraded_owner(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        status = "ok"

        def do_GET(self):
            time.sleep(0.6)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": self.status,
                "protocol": "workspace.v1",
                "runtime_instance_id": "test",
            }).encode())

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    boundary = LocalRuntimeBoundary()
    pid = os.getpid()
    birth = boundary.process_birth_identity(pid)
    lock = tmp_path / "instance.lock"
    lock.write_text(json.dumps({"pid": pid, "runtime_instance_id": "test", "process_birth_id": birth}))
    try:
        assert boundary._http_health(endpoint)
        Handler.status = "degraded"
        assert boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id="test", owner_lock=lock, process_birth_id=birth)
        assert not boundary.health(endpoint=endpoint, pid=pid, instance_id="test")
        assert not boundary.validate_owner(endpoint=endpoint, pid=pid, instance_id="wrong", owner_lock=lock, process_birth_id=birth)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class _CustodyChild:
    pid = 51001
    _runtime_boundary_sole_reaper = True

    def __init__(self):
        self.exited = False
        self.returncode = None

    def poll(self):
        if self.exited:
            self.returncode = 0
        return self.returncode

    def wait(self, *, timeout):
        assert timeout > 0
        self.exited = True
        self.returncode = 0
        return self.returncode


@pytest.fixture
def darwin_boundary(monkeypatch):
    from astrid_runtime import runtime_boundary as module
    # These broker tests exercise Darwin's audit-token custody on every host.
    # Replace only this module's sys reference, leaving native OS helpers alone.
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform="darwin", exc_info=sys.exc_info))
    return module


def _stub_owner_broker(monkeypatch, child, *, exit_during_signal=False):
    from astrid_runtime import runtime_boundary as boundary_module

    class Broker:
        error = None
        authority_scope_root = None

        def set_cleanup_deadline(self, deadline):
            assert deadline > time.monotonic()

        def signal(self, signum, *, expected_pid):
            assert expected_pid == child.pid
            if exit_during_signal:
                child.exited = True
            raise boundary_module.CustodyError("identity unavailable")

    monkeypatch.setattr(boundary_module, "RoleBoundCustodyBroker", Broker)
    child._runtime_custody_broker = Broker()
    monkeypatch.setattr(runtime_platform, "signal_process", lambda *_: pytest.fail("numeric PID fallback"))
    monkeypatch.setattr(runtime_platform, "signal_tree", lambda *_: pytest.fail("numeric PGID fallback"))
    return boundary_module


def test_token_signal_exit_race_uses_only_retained_child_exit(monkeypatch, darwin_boundary):
    child = _CustodyChild()
    _stub_owner_broker(monkeypatch, child, exit_during_signal=True)
    LocalRuntimeBoundary._terminate(child)
    assert child.exited


def test_unverifiable_live_owner_retains_cleanup_uncertainty(monkeypatch, darwin_boundary):
    child = _CustodyChild()
    _stub_owner_broker(monkeypatch, child)
    with pytest.raises(BootstrapError, match="cleanup remains uncertain"):
        LocalRuntimeBoundary._terminate(child)
    assert not child.exited
    assert isinstance(child._runtime_cleanup_error, BootstrapError)


def test_primary_start_error_retains_cleanup_uncertainty_as_cause(monkeypatch, darwin_boundary):
    child = _CustodyChild()
    _stub_owner_broker(monkeypatch, child)
    primary = OSError("ready reply failed")
    with pytest.raises(OSError) as result:
        try:
            raise primary
        except OSError:
            LocalRuntimeBoundary._terminate(child)
    assert result.value is primary
    assert result.value.__cause__ is child._runtime_cleanup_error
    assert not child.exited


def test_unowned_handle_does_not_infer_termination_from_poll(monkeypatch, darwin_boundary):
    child = _CustodyChild()
    child.exited = True
    child._runtime_boundary_sole_reaper = False
    _stub_owner_broker(monkeypatch, child)
    with pytest.raises(BootstrapError, match="sole-reaper"):
        LocalRuntimeBoundary._terminate(child)


def test_runtime_spawn_retains_owner_and_wires_escrow_before_seal(tmp_path, monkeypatch, darwin_boundary):
    boundary_module = darwin_boundary
    child = _CustodyChild()
    facts = {}

    class Broker:
        def __init__(self, **kwargs):
            facts.update(kwargs)
            assert kwargs["authority_scope_root"].is_dir()
            assert kwargs["authority_journal"].parent == kwargs["authority_scope_root"]

        def child_environment(self, argv, *, start_new_session):
            assert argv == ["/isolated/python", "-m", "runtime_protocol"]
            assert start_new_session
            return {"CUSTODY_TEST": "1"}

        def wait_until_sealed(self):
            assert boundary._process is child
            assert child._runtime_custody_broker is self
            assert child._runtime_boundary_owner is boundary
            raise boundary_module.CustodyError("seal persistence failed")

    monkeypatch.setattr(boundary_module, "RoleBoundCustodyBroker", Broker)
    monkeypatch.setattr(boundary_module.subprocess, "Popen", lambda *_args, **kwargs: child)
    boundary = LocalRuntimeBoundary()
    with pytest.raises(boundary_module.RuntimeCustodyLaunchUncertain) as result:
        boundary._spawn_runtime(["/isolated/python", "-m", "runtime_protocol"], support_root=tmp_path, stdout=None)
    assert result.value.process is child
    assert result.value.broker is child._runtime_custody_broker
    assert facts["role"] == "runtime_owner"
    assert boundary._process is child


def _runtime_handoff_fixture(tmp_path, monkeypatch):
    from astrid_runtime import custody_broker as custody
    from astrid_runtime import runtime_boundary as module
    uid = runtime_platform.current_user()
    identities = {pid: {"pid": pid, "uid": uid, "birth_id": f"birth-{pid}"} for pid in (101, 102, 103)}
    tokens = {pid: {"pid": pid, "uid": uid, "pidversion": pid + 1,
                    "sha256": f"sha256:token-{pid}", "words": [pid] * 8} for pid in identities}
    monkeypatch.setattr(custody, "audit_token_details", lambda words: {k: v for k, v in tokens[words[0]].items() if k != "words"})
    actors = {pid: custody.AuthenticatedCleanupActor(lambda pid=pid: tokens[pid], identities.get) for pid in (101, 102)}
    authority = custody.RoleCustodyAuthority(tmp_path / "scope", "runtime_owner", timeout=0.2)
    authority.designate_pending(actor=actors[101], identity=identities[103], token=tokens[103], owner_epoch="runtime-A")
    authority.bind_target(actor=actors[101], generation=1, identity=identities[103], token=tokens[103])
    sealed = authority.reference()
    monkeypatch.setattr(module, "default_process_identity", identities.get)
    return module, authority, actors, identities, sealed


def test_boundary_lost_relinquish_ack_advances_only_from_durable_readback(tmp_path, monkeypatch):
    module, authority, actors, _, _ = _runtime_handoff_fixture(tmp_path, monkeypatch)
    boundary = module.LocalRuntimeBoundary()
    child = _CustodyChild()
    boundary._process = child
    write = authority._write
    def lost(record):
        write(record)
        raise OSError("lost ACK")
    monkeypatch.setattr(authority, "_write", lost)
    ack = boundary._commit_owner_transition(authority, kind="relinquish", actor=actors[101], generation=1, owner_epoch="runtime-A")
    assert ack["generation"] == 2
    assert len(authority._read()["transitions"]) == 1
    assert boundary._process is child


def test_windows_spawn_passes_only_current_operation_binding(tmp_path, monkeypatch):
    from astrid_runtime import runtime_boundary as module

    child = _CustodyChild()
    observed = {}
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr("runtime_protocol.windows_handoff.python_executable", lambda executable: executable)
    def spawn(argv, **kwargs):
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return child
    monkeypatch.setattr(module.platform, "spawn_tree", spawn)
    boundary = LocalRuntimeBoundary()
    monkeypatch.setenv("ASTRID_INSTALLER_OPERATION_ID", "stale")
    process, broker = boundary._spawn_runtime(
        ["/isolated/python", "-m", "runtime_protocol"], support_root=tmp_path, stdout=None,
    )
    assert process is child and broker is None
    assert "ASTRID_INSTALLER_OPERATION_ID" not in observed["kwargs"]["env"]


def test_boundary_unknown_commit_retains_controller_and_child(tmp_path, monkeypatch):
    from astrid_runtime.bootstrap import BootstrapCustodyUncertain
    module, authority, actors, _, _ = _runtime_handoff_fixture(tmp_path, monkeypatch)
    boundary = module.LocalRuntimeBoundary()
    child = _CustodyChild()
    boundary._process = child
    monkeypatch.setattr(authority, "_write", lambda _: (_ for _ in ()).throw(OSError("write unavailable")))
    monkeypatch.setattr(authority, "committed", lambda *_: (_ for _ in ()).throw(OSError("read unavailable")))
    with pytest.raises(BootstrapCustodyUncertain) as failure:
        boundary._commit_owner_transition(authority, kind="relinquish", actor=actors[101], generation=1, owner_epoch="runtime-A")
    assert failure.value.controller is boundary
    assert failure.value.replay_intent["transition_id"] == failure.value.transition_id
    assert failure.value.replay_intent["from_generation"] == 1
    assert boundary._process is child
    assert child.poll() is None


def _detached_runtime(tmp_path, monkeypatch, *, release=True):
    from astrid_runtime.bootstrap import SourceProfile
    module, authority, actors, identities, sealed = _runtime_handoff_fixture(tmp_path, monkeypatch)
    if release:
        authority.relinquish(actor=actors[101], generation=1, transition_id="initial-release", owner_epoch="runtime-A")
    support = tmp_path / "support"
    realm = tmp_path / "realm"
    support.mkdir()
    realm.mkdir()
    boundary = module.LocalRuntimeBoundary()
    boundary._source = SourceProfile(profile="astrid", runtime_checkout=str(tmp_path), source_checkout=str(tmp_path), capability_digest="fake")
    boundary._support_root, boundary._realm_root, boundary._realm_id = support, realm, "realm"
    boundary._process, boundary._detached_pid = None, 103
    marker = {"pid": 103, "runtime_instance_id": "instance", "process_birth_id": "birth-103", "realm_id": "realm", "realm_root": str(realm)}
    (support / "instance.lock").write_text(json.dumps(marker))
    discovery = dict(marker, endpoint="http://127.0.0.1:1234", active_realm="realm")
    (support / "discovery.json").write_text(json.dumps(discovery))
    monkeypatch.setattr(boundary, "is_pid_alive", lambda pid: pid in identities)
    monkeypatch.setattr(boundary, "process_birth_identity", lambda pid: identities.get(pid, {}).get("birth_id"))
    monkeypatch.setattr(boundary, "_http_health_payload", lambda _: {"status": "ok", "runtime_instance_id": "instance"})
    monkeypatch.setattr(boundary, "endpoint_metadata", lambda **_: {"runtime_instance_id": "instance", "realm_id": "realm"})
    monkeypatch.setattr(module.platform, "process_group", lambda _: 103)
    monkeypatch.setattr(module, "load_sealed_capability", lambda *a, **kw: {"reference": {"role_custody": sealed}, "owner_epoch": "runtime-A"})
    monkeypatch.setattr(module, "RoleCustodyAuthority", lambda *args, **kwargs: authority)
    monkeypatch.setattr(module.AuthenticatedCleanupActor, "current", classmethod(lambda cls: actors[102]))
    signals = []
    def send(*args, **kwargs):
        authority.signal(actor=kwargs["actor"], generation=kwargs["generation"], expected_target=sealed["target"],
                         signum=kwargs["signum"], identity_provider=identities.get, signal_provider=kwargs["signal_provider"])
    monkeypatch.setattr(module, "signal_sealed_capability", send)
    kwargs = dict(endpoint=discovery["endpoint"], pid=103, instance_id="instance", process_birth_id="birth-103",
                  realm_id="realm", owner_lock=support / "instance.lock", discovery_path=support / "discovery.json")
    return module, boundary, authority, actors, identities, sealed, signals, kwargs


def test_detached_down_claims_before_signal_and_reports_only_nonchild_absence(tmp_path, monkeypatch):
    module, boundary, authority, _, identities, _, signals, kwargs = _detached_runtime(tmp_path, monkeypatch)
    def deliver(words, signum):
        signals.append((words, signum))
        identities.pop(103)
    monkeypatch.setattr(module, "signal_audit_token", deliver)
    result = boundary.stop_owner(**kwargs)
    assert result["exit_evidence"] == "nonchild_absence_observed"
    assert "reap" not in result
    assert len(signals) == 1
    assert authority.reference()["generation"] == 3
    assert [t["intent"]["kind"] for t in authority._read()["transitions"]] == ["relinquish", "claim"]


def test_detached_presignal_failure_relinquishes_for_next_authenticated_claim(tmp_path, monkeypatch):
    from astrid_runtime import custody_broker as custody
    module, boundary, authority, actors, identities, sealed, _, kwargs = _detached_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "signal_sealed_capability", lambda *a, **kw: (_ for _ in ()).throw(custody.CustodyError("load failed")))
    monkeypatch.setattr(module, "signal_audit_token", lambda *_: pytest.fail("no signal attempted"))
    with pytest.raises(BootstrapError, match="signal attempted=False"):
        boundary.stop_owner(**kwargs)
    assert authority._read()["state"] == "relinquished"
    assert authority.claim(actor=actors[101], generation=4, transition_id="next-claim", sealed=sealed,
                           owner_epoch="runtime-A", identity_provider=identities.get)["generation"] == 5
    assert boundary._detached_pid == 103


def test_detached_live_target_after_escalation_releases_and_reports_uncertainty(tmp_path, monkeypatch):
    module, boundary, authority, _, _, _, signals, kwargs = _detached_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "signal_audit_token", lambda words, signum: signals.append(signum))
    ticks = iter(range(0, 1000, 10))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(BootstrapError, match="uncertain"):
        boundary.stop_owner(**kwargs)
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert authority._read()["state"] == "relinquished"
    assert boundary._detached_pid == 103


def test_detached_unknown_release_retains_named_controller(tmp_path, monkeypatch):
    from astrid_runtime import custody_broker as custody
    from astrid_runtime.bootstrap import BootstrapCustodyUncertain
    module, boundary, authority, _, _, _, _, kwargs = _detached_runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "signal_sealed_capability", lambda *a, **kw: (_ for _ in ()).throw(custody.CustodyError("load failed")))
    commit = boundary._commit_owner_transition
    def uncertain_release(authority, **options):
        if options["kind"] == "relinquish":
            raise BootstrapCustodyUncertain("release unknown", controller=boundary)
        return commit(authority, **options)
    monkeypatch.setattr(boundary, "_commit_owner_transition", uncertain_release)
    with pytest.raises(BootstrapCustodyUncertain) as failure:
        boundary.stop_owner(**kwargs)
    assert failure.value.controller is boundary
    assert boundary._detached_pid == 103
    assert authority._read()["state"] == "active"


def test_detached_legacy_active_designation_is_refused_without_signal(tmp_path, monkeypatch):
    module, boundary, authority, _, _, _, _, kwargs = _detached_runtime(tmp_path, monkeypatch, release=False)
    monkeypatch.setattr(module, "signal_audit_token", lambda *_: pytest.fail("legacy signal"))
    with pytest.raises(BootstrapError, match="not committed"):
        boundary.stop_owner(**kwargs)
    assert authority.reference()["generation"] == 1
    assert authority._read()["transitions"] == []


def test_retained_stop_owner_reclaims_release_before_term_kill_and_positive_wait(tmp_path, monkeypatch, darwin_boundary):
    import subprocess
    module, boundary, authority, actors, identities, _, _, kwargs = _detached_runtime(tmp_path, monkeypatch, release=False)
    events = []
    class Child:
        pid = 103
        exit_code = None
        returncode = None
        _runtime_boundary_sole_reaper = True
        def poll(self):
            self.returncode = self.exit_code
            return self.returncode
        def wait(self, timeout):
            events.append(("wait", self.exit_code))
            if self.exit_code is None: raise subprocess.TimeoutExpired("fake", timeout)
            self.returncode = self.exit_code
            return self.returncode
    child = Child()
    class Broker:
        role_authority = authority
        cleanup_actor = actors[101]
        owner_epoch = "runtime-A"
        custody_generation = 1
        authority_scope_root = None
        error = None
        def set_cleanup_deadline(self, deadline): pass
        def signal(self, signum, *, expected_pid):
            assert expected_pid == child.pid
            def deliver(words, signum):
                events.append(("signal", signum, self.custody_generation))
                if signum == signal.SIGKILL:
                    child.exit_code = 0
                    identities.pop(103)
            authority.signal(actor=self.cleanup_actor, generation=self.custody_generation,
                             expected_target=authority.reference()["target"], signum=signum,
                             identity_provider=identities.get, signal_provider=deliver)
    broker = Broker()
    child._runtime_custody_broker = broker
    boundary._process = child
    monkeypatch.setattr(module, "RoleBoundCustodyBroker", Broker)
    assert boundary.release_owner_custody()["generation"] == 2
    result = boundary.stop_owner(**kwargs)
    assert result["status"] == "stopped"
    assert broker.custody_generation == 3
    assert events == [("signal", signal.SIGTERM, 3), ("wait", None), ("signal", signal.SIGKILL, 3), ("wait", 0)]
    assert boundary._process is None


@pytest.mark.parametrize("replacement", [False, True, "invalid"])
def test_postterm_escalation_allows_withdrawal_but_rejects_replacement(tmp_path, monkeypatch, replacement):
    module, boundary, authority, _, identities, _, signals, kwargs = _detached_runtime(tmp_path, monkeypatch)
    def deliver(words, signum):
        signals.append(signum)
        if signum == signal.SIGTERM:
            Path(kwargs["discovery_path"]).unlink()
            Path(kwargs["owner_lock"]).unlink()
            monkeypatch.setattr(boundary, "_http_health_payload", lambda _: None)
            monkeypatch.setattr(boundary, "endpoint_metadata", lambda **_: {})
            if replacement:
                Path(kwargs["discovery_path"]).write_text("null" if replacement == "invalid" else json.dumps({"pid": 999, "runtime_instance_id": "replacement"}))
        else:
            identities.pop(103)
    from pathlib import Path
    monkeypatch.setattr(module, "signal_audit_token", deliver)
    ticks = iter(range(0, 1000, 10))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    if replacement:
        with pytest.raises(BootstrapError, match="unreadable" if replacement == "invalid" else "conflicting replacement"):
            boundary.stop_owner(**kwargs)
        assert signals == [signal.SIGTERM]
        assert authority._read()["state"] == "relinquished"
    else:
        assert boundary.stop_owner(**kwargs)["exit_evidence"] == "nonchild_absence_observed"
        assert signals == [signal.SIGTERM, signal.SIGKILL]
        assert authority.reference()["generation"] == 3



@pytest.mark.parametrize("outcome", ["live", "absent", "unknown"])
def test_boundary_birth_uses_shared_platform_identity(monkeypatch, outcome):
    from astrid_runtime import runtime_boundary as module
    from runtime_protocol import platform
    calls = []
    def observe(pid, *, timeout=1.0):
        calls.append((pid, timeout))
        if outcome == "unknown": raise OSError("observation denied")
        return None if outcome == "absent" else {"pid": pid, "uid": 501, "parent_pid": 41, "birth_id": "proc-start-ticks:19"}
    monkeypatch.setattr(platform, "process_identity", observe)
    if outcome == "unknown":
        with pytest.raises(BootstrapError, match="identity remains uncertain"):
            LocalRuntimeBoundary.process_birth_identity(123)
        assert calls == [(123, 1.0)]
        return
    assert LocalRuntimeBoundary.process_birth_identity(123) == ("proc-start-ticks:19" if outcome == "live" else None)
    assert calls == [(123, 1.0)]


@pytest.mark.parametrize("configured, expected", [(None, "120.0"), ("37.5", "37.5")])
@pytest.mark.parametrize("healthy", [True, False])
def test_workspace_inspection_forwards_selected_admission_budget_without_changing_report(
    tmp_path, monkeypatch, configured, expected, healthy,
):
    if configured is None:
        monkeypatch.delenv(ADMISSION_TIMEOUT_ENV, raising=False)
    else:
        monkeypatch.setenv(ADMISSION_TIMEOUT_ENV, configured)
    root = tmp_path / "realm"
    root.mkdir()
    report = {"ok": healthy, "state": "healthy" if healthy else "unhealthy", "checks": {"sqlite_integrity": {"ok": healthy}}}
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        return SimpleNamespace(returncode=0 if healthy else 1, stdout=json.dumps(report))

    monkeypatch.setattr("astrid_runtime.runtime_boundary.subprocess.run", fake_run)
    assert LocalRuntimeBoundary().inspect(realm_root=root) == report
    assert observed["argv"] == [
        __import__("sys").executable, "-X", "utf8", "-m", "runtime_protocol", "doctor",
        "--root", str(root), "--json", "--admission-timeout", expected,
    ]
    assert list(root.iterdir()) == []


def test_local_boundary_stop_attests_only_successful_exact_child_cleanup():
    boundary = LocalRuntimeBoundary()
    assert boundary.stop() == {"children_stopped": True}

    process = SimpleNamespace(poll=lambda: None)
    boundary._process = process
    failure = RuntimeError("injected cleanup uncertainty")

    def uncertain(_process):
        raise failure

    boundary._terminate = uncertain
    with pytest.raises(RuntimeError, match="injected cleanup uncertainty"):
        boundary.stop()
    assert boundary._process is process

    boundary._terminate = lambda _process: None
    assert boundary.stop() == {"children_stopped": True}
    assert boundary._process is None
