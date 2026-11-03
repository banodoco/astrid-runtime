"""Focused Agent-v1 branch coverage and strict mutation fence regressions."""

import importlib
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from astrid_runtime import identity
from astrid_runtime.owner_diagnostics import observation, outcome, predicate_chain
from tests import test_bootstrap as bootstrap_test

PROFILE = bootstrap_test.PROFILE
from tests.test_owner_diagnostics_v1 import records

boot = importlib.import_module("astrid_runtime.bootstrap")


@pytest.fixture
def runtime_case():
    case = bootstrap_test.BootstrapTests()
    case.setUp()
    case._configure()
    try:
        yield case
    finally:
        case.tearDown()
        case.doCleanups()


def enabled(monkeypatch):
    monkeypatch.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")


def by_name(capfd):
    result = records(capfd)
    assert all(item["observed"] in (True, False, None) for item in result)
    assert all(item.get("depends_on") for item in result if item["result"] == "unavailable")
    assert json.dumps(result).find("private") == -1
    return {item["predicate"]: item for item in result}


@pytest.mark.parametrize(
    "field,value,failed",
    [
        ("protocol_version", "private", "compatibility_protocol"),
        ("schema_version", "private", "compatibility_schema"),
        ("capability_digest", "private", "compatibility_capability"),
    ],
)
def test_individual_compatibility_short_circuit(monkeypatch, capfd, field, value, failed):
    enabled(monkeypatch)
    discovery = {
        "protocol_version": boot.PROTOCOL_VERSION,
        "schema_version": boot.SCHEMA_VERSION,
        "capability_digest": "caps-v1",
        field: value,
    }
    with pytest.raises(boot.CompatibilityError):
        boot._compatible(discovery, boot.BootstrapConfig(capability_digest="caps-v1"), PROFILE)
    result = by_name(capfd)
    assert result[failed]["result"] == "fail"
    assert result["compatibility_source_schema"]["result"] == "unavailable"
    assert result["compatibility_source_schema"]["depends_on"] == failed


@pytest.mark.parametrize(
    "value,failed",
    [
        (None, "identity_object"),
        ({"managed_by": "pinokio", "release": "private"}, "identity_release_integer"),
        ({"managed_by": "pinokio", "release": -1}, "identity_release_valid"),
        ({"managed_by": "private", "release": 0}, "identity_management"),
        ({"managed_by": "pinokio", "release": 0, "private": True}, "identity_fields"),
    ],
)
def test_identity_subpredicates_are_redacted(monkeypatch, capfd, value, failed):
    enabled(monkeypatch)
    with pytest.raises(identity.StartupIdentityError):
        identity.normalize_startup_identity(value)
    assert by_name(capfd)[failed]["result"] == "fail"


def test_identity_instance_precedes_parse_and_legacy_shape_is_preserved(monkeypatch, capfd):
    enabled(monkeypatch)
    with pytest.raises(identity.StartupIdentityError):
        identity.validate_live_owner_identity({"runtime_instance_id": "private"}, instance_id="selected")
    result = by_name(capfd)
    assert result["identity_health_instance"]["result"] == "fail"
    assert result["identity_instance_present"]["depends_on"] == "identity_health_instance"
    assert identity.validate_live_owner_identity({"runtime_instance_id": "selected"}, instance_id="selected") == {
        "release": 0,
        "managed_by": None,
    }
    assert by_name(capfd)["identity_wire_present"]["result"] == "fail"


@pytest.mark.parametrize(
    "endpoint,failed",
    [
        ("https://localhost:1", "loopback_scheme"),
        ("http://private@localhost:1", "loopback_no_username"),
        ("http://example.invalid:1", "loopback_host"),
        ("http://localhost:1/private", "loopback_path"),
        ("http://localhost:private", "loopback_parse"),
    ],
)
def test_loopback_parse_and_individual_checks(monkeypatch, capfd, endpoint, failed):
    enabled(monkeypatch)
    with pytest.raises(boot.BootstrapError):
        boot._validate_loopback_endpoint(endpoint)
    result = by_name(capfd)
    assert result[failed]["result"] == "fail"
    assert result["loopback_no_fragment"]["depends_on"] == failed


def marker_for(case, state):
    root = case.paths.realms_dir / "configured-realm"
    binding = {
        key: ("0" * 64 if key.endswith("_sha256") else 0 if key.endswith("_release") else "selected")
        for key in boot.PINOKIO_STOP_BINDING_KEYS
    }
    return {
        "pid": 123,
        "process_birth_id": "birth",
        "runtime_instance_id": "instance",
        "realm_id": "configured-realm",
        "realm_root": str(root),
        "data_root": str(case.paths.app_support),
        "state": state,
        state: {"version": boot.PINOKIO_STOP_HANDOFF_VERSION, "binding": binding},
    }


@pytest.mark.parametrize("state", ["completed_stop", "stopping"])
@pytest.mark.parametrize(
    "change,failed",
    [
        ("version", "version_integer"),
        ("pid", "pid_integer"),
        ("binding", "binding_keys"),
        ("birth", "birth_string"),
    ],
)
def test_marker_subpredicates(runtime_case, monkeypatch, capfd, state, change, failed):
    enabled(monkeypatch)
    marker = marker_for(runtime_case, state)
    prefix = "completed" if state == "completed_stop" else "stopping"
    if change == "version":
        marker[state]["version"] = "private"
    elif change == "binding":
        marker[state]["binding"].pop("data_root")
    elif change == "pid":
        marker["pid"] = "private"
    else:
        marker["process_birth_id"] = ""
        failed = "birth_string" if prefix == "completed" else "process_birth_id_string"
    with pytest.raises(boot.BootstrapError):
        (boot._validate_completed_stop_marker if state == "completed_stop" else boot._validate_stopping_marker)(marker)
    assert by_name(capfd)[prefix + "_" + failed]["result"] == "fail"


def test_binding_digest_and_absence_errors_have_distinct_outcomes(runtime_case, monkeypatch, capfd):
    enabled(monkeypatch)
    marker = marker_for(runtime_case, "completed_stop")
    marker["completed_stop"]["binding"]["profile_sha256"] = "private"
    with pytest.raises(boot.BootstrapError):
        boot._validate_completed_stop_marker(marker)
    assert by_name(capfd)["binding_profile_sha256_digest"]["result"] == "fail"

    def unreadable(pid):
        raise PermissionError("private")

    with pytest.raises(boot.BootstrapError, match="absence is unknown"):
        boot._require_owner_absent(SimpleNamespace(is_pid_alive=unreadable), 123, "private", context="test")
    result = by_name(capfd)
    assert result["owner_absent_pid"]["result"] == "unknown"
    assert result["owner_absent_birth"]["depends_on"] == "owner_absent_pid"


def test_observer_failure_cannot_change_authority_or_exception(monkeypatch, capfd):
    enabled(monkeypatch)
    import astrid_runtime.owner_diagnostics as diagnostic

    monkeypatch.setattr(diagnostic.os, "write", lambda *args: (_ for _ in ()).throw(OSError("private")))

    @predicate_chain("connect_pid_alive", "connect_owner_valid")
    def refuse():
        with observation("connect_pid_alive"):
            raise PermissionError("selected authority read")

    with pytest.raises(PermissionError, match="selected authority read"):
        refuse()
    assert capfd.readouterr().err == ""


@pytest.mark.parametrize("operation", ["up", "connect"])
def test_replacement_during_credentials_blocks_connect_with_diagnostic_parity(
    runtime_case, monkeypatch, capfd, operation
):
    case = runtime_case
    boot.bootstrap(case.paths, case.boundary, case.config)
    original_credential = boot._credential
    events = []

    def credential(paths):
        events.append("credential")
        result = original_credential(paths)
        case.boundary.valid_owner = False
        return result

    monkeypatch.setattr(boot, "_credential", credential)
    monkeypatch.setattr(case.boundary, "connect", lambda **kwargs: events.append("connect"))
    before = {
        p: p.read_bytes() for p in (case.paths.catalog_path, case.paths.discovery_path, case.paths.instance_lock_path)
    }
    traces = []
    for on in (False, True):
        case.boundary.valid_owner = True
        if on:
            enabled(monkeypatch)
        else:
            monkeypatch.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
        with pytest.raises(boot.BootstrapError, match="owner changed"):
            (boot.bootstrap if operation == "up" else boot.connect)(case.paths, case.boundary, case.config)
        traces.append(events[:])
        events.clear()
        stderr = capfd.readouterr().err
        assert ("[astrid installer all-predicates v1]" in stderr) == on
        assert str(case.paths.home) not in stderr
        assert {p: p.read_bytes() for p in before} == before
    assert traces == [["credential"], ["credential"]]


def test_startup_rechecks_owner_before_custody_release(runtime_case, monkeypatch, capfd):
    case = runtime_case
    enabled(monkeypatch)
    original_commit = boot._commit_bootstrap_metadata
    events = []

    def commit(*args, **kwargs):
        original_commit(*args, **kwargs)
        case.boundary.valid_owner = False

    monkeypatch.setattr(boot, "_commit_bootstrap_metadata", commit)
    monkeypatch.setattr(case.boundary, "release_owner_custody", lambda: events.append("release"), raising=False)
    with pytest.raises(boot.BootstrapError, match="owner changed during startup"):
        boot.bootstrap(case.paths, case.boundary, case.config)
    assert events == []
    result = by_name(capfd)
    assert result["startup_owner_valid"]["result"] == "fail"
    assert result["startup_owner_valid"]["phase"] == "startup"


def test_stale_cleanup_revalidates_before_each_unlink(runtime_case, monkeypatch, capfd):
    case = runtime_case
    enabled(monkeypatch)
    stale = {"pid": 999, "runtime_instance_id": "old"}
    replacement = {"pid": 998, "runtime_instance_id": "replacement"}
    for path in (case.paths.discovery_path, case.paths.instance_lock_path):
        path.write_text(json.dumps(stale))
    original_remove = boot.remove_file

    def remove(path):
        original_remove(path)
        case.paths.instance_lock_path.write_text(json.dumps(replacement))

    monkeypatch.setattr(boot, "remove_file", remove)
    with pytest.raises(boot.BootstrapError, match="changed during stale-owner cleanup"):
        boot._reclaim_stale_owner_locked(case.paths, case.boundary)
    assert json.loads(case.paths.instance_lock_path.read_text()) == replacement
    assert by_name(capfd)["reclaim_fresh_snapshots"]["result"] == "fail"


def test_stop_rechecks_replacement_between_cleanup_mutations(runtime_case, monkeypatch, capfd):
    case = runtime_case
    boot.bootstrap(case.paths, case.boundary, case.config)
    enabled(monkeypatch)
    original_remove = boot.remove_file
    original_fence = boot.interruption_fence
    events = []
    replacement = {"pid": 999, "runtime_instance_id": "replacement"}

    def remove(path):
        original_remove(path)
        if path == case.paths.discovery_path:
            case.paths.instance_lock_path.write_text(json.dumps(replacement))

    @contextmanager
    def fence(root):
        events.append("C1")
        with original_fence(root) as report:
            yield report

    original_stop = case.boundary.stop_owner

    def stop(**kwargs):
        events.append("stop")
        return original_stop(**kwargs)

    monkeypatch.setattr(boot, "remove_file", remove)
    monkeypatch.setattr(boot, "interruption_fence", fence)
    monkeypatch.setattr(case.boundary, "stop_owner", stop)
    with pytest.raises(boot.BootstrapError, match="changed before stop cleanup"):
        boot.down(case.paths, case.boundary, stop_manager=lambda: events.append("manager"))
    assert events == ["C1", "stop", "manager"]
    assert json.loads(case.paths.instance_lock_path.read_text()) == replacement
    assert by_name(capfd)["stop_cleanup_marker_unchanged"]["result"] == "fail"


def test_re_attestation_observes_existing_fence_and_refuses_replacement(runtime_case, monkeypatch, capfd):
    case = runtime_case
    root = case.paths.realms_dir / "configured-realm"
    marker = marker_for(case, "completed_stop")
    binding = marker["completed_stop"]["binding"]
    monkeypatch.setattr(boot, "_pinokio_stop_binding", lambda *args: dict(binding))
    original_fence = boot.interruption_fence
    calls = []

    @contextmanager
    def fence(root):
        calls.append("C1")
        with original_fence(root) as report:
            case.paths.discovery_path.write_text(json.dumps({"pid": 998}))
            yield report

    monkeypatch.setattr(boot, "interruption_fence", fence)
    enabled(monkeypatch)
    assert boot._reattest_aborted_launch_stop(case.paths, case.boundary, marker, realm_root=root) is False
    assert calls == ["C1"]
    result = by_name(capfd)
    assert result["recovery_reattest_publications_absent"]["result"] == "fail"
    assert result["recovery_reattest_binding"]["depends_on"] == "recovery_reattest_publications_absent"
    assert not case.paths.instance_lock_path.exists()


def test_detached_stop_native_observation_and_signal_parity(tmp_path, monkeypatch, capfd):
    from tests.test_runtime_boundary import _detached_runtime

    traces = []
    for on in (False, True):
        root = tmp_path / str(on)
        root.mkdir()
        with monkeypatch.context() as patcher:
            module, boundary, _, _, identities, _, signals, kwargs = _detached_runtime(root, patcher)
            trace = []
            for method in ("is_pid_alive", "process_birth_identity", "_http_health_payload", "endpoint_metadata"):
                original = getattr(boundary, method)

                def observed(*args, _original=original, _method=method, **kw):
                    trace.append(_method)
                    return _original(*args, **kw)

                patcher.setattr(boundary, method, observed)
            native = module.default_process_identity

            def native_identity(*args, **kw):
                trace.append("native_identity")
                return native(*args, **kw)

            patcher.setattr(module, "default_process_identity", native_identity)

            def signal(words, signum):
                signals.append(signum)
                trace.append("signal")
                identities.pop(103)

            patcher.setattr(module, "signal_audit_token", signal)
            if on:
                patcher.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
            else:
                patcher.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
            assert boundary.stop_owner(**kwargs)["exit_evidence"] == "nonchild_absence_observed"
            assert len(signals) == 1
            traces.append(trace)
            stderr = capfd.readouterr().err
            assert ("[astrid installer all-predicates v1]" in stderr) == on
            assert str(root) not in stderr
    assert traces[0] == traces[1]


def test_native_stop_error_observations_preserve_call_and_exception(monkeypatch, capfd):
    from astrid_runtime import runtime_boundary as module

    traces = []
    for on in (False, True):
        with monkeypatch.context() as patcher:
            patcher.setattr(module.sys, "platform", "linux")
            calls = []

            def fail(*args, **kwargs):
                calls.append("native_stop")
                raise PermissionError("private native error")

            patcher.setattr(module.platform, "stop_tree", fail)
            if on:
                patcher.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
            else:
                patcher.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
            with pytest.raises(boot.BootstrapError, match="cleanup remains uncertain"):
                module.LocalRuntimeBoundary._terminate(SimpleNamespace())
            traces.append(calls)
            if on:
                observed = by_name(capfd)
                assert observed["cleanup_native_stop"]["result"] == "unknown"
                assert observed["cleanup_complete"]["result"] == "unknown"
            else:
                assert capfd.readouterr().err == ""
    assert traces == [["native_stop"], ["native_stop"]]


def test_startup_wait_owner_gates_preserve_reads_with_diagnostics(monkeypatch, capfd, tmp_path):
    from astrid_runtime import runtime_boundary as module

    traces = []
    for on in (False, True):
        calls = []
        boundary = module.LocalRuntimeBoundary()
        boundary._log_offset = 0
        advertisements = iter(
            [
                {"pid": 888, "endpoint": "http://127.0.0.1:1"},
                {"pid": 123, "endpoint": "http://127.0.0.1:2"},
            ]
        )

        def discovery(root):
            calls.append("discovery")
            return next(advertisements)

        def health(endpoint):
            calls.append("health")
            return True

        def poll():
            calls.append("poll")
            return None

        with monkeypatch.context() as patcher:
            patcher.setattr(boundary, "_read_discovery", discovery)
            patcher.setattr(boundary, "_http_health", health)
            patcher.setattr(module.time, "sleep", lambda _: None)
            if on:
                patcher.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
            else:
                patcher.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
            assert boundary._wait_endpoint(tmp_path, SimpleNamespace(pid=123, poll=poll)) == "http://127.0.0.1:2"
            traces.append(calls)
            if on:
                result = by_name(capfd)
                assert result["startup_advertised_pid_matches"]["result"] == "pass"
                assert result["startup_endpoint_health"]["result"] == "pass"
            else:
                assert capfd.readouterr().err == ""
    assert traces == [["poll", "discovery", "poll", "discovery", "health"]] * 2


def test_fallback_stale_removal_rechecks_after_native_observation(runtime_case, monkeypatch, capfd):
    case = runtime_case
    stale = {
        "pid": 999,
        "active_realm": "configured-realm",
        "protocol_version": boot.PROTOCOL_VERSION,
        "schema_version": boot.SCHEMA_VERSION,
    }
    replacement = {**stale, "pid": 998, "runtime_instance_id": "replacement"}
    case.paths.discovery_path.write_text(json.dumps(stale))
    monkeypatch.setattr(boot, "_reclaim_stale_owner_locked", lambda *args: False)
    calls = []

    def stale_owner(*args):
        calls.append("native")
        if len(calls) == 2:
            case.paths.discovery_path.write_text(json.dumps(replacement))
        return False

    monkeypatch.setattr(boot, "_owner_may_be_alive", stale_owner)
    enabled(monkeypatch)
    with pytest.raises(boot.BootstrapError, match="changed before stale discovery removal"):
        boot.bootstrap(case.paths, case.boundary, case.config)
    assert case.boundary.starts == []
    assert json.loads(case.paths.discovery_path.read_text()) == replacement
    assert by_name(capfd)["stale_final_discovery_unchanged"]["result"] == "fail"


@pytest.mark.parametrize(
    "field,value,failed",
    [
        ("version", 999, "catalog_version"),
        ("realms", {}, "catalog_realms_list"),
        ("source_profiles", [], "catalog_profiles_object"),
    ],
)
def test_catalog_parse_subpredicates(runtime_case, monkeypatch, capfd, field, value, failed):
    catalog = json.loads(runtime_case.paths.catalog_path.read_text())
    catalog[field] = value
    enabled(monkeypatch)
    with pytest.raises(boot.BootstrapError):
        boot._validate_catalog(catalog)
    result = by_name(capfd)
    assert result[failed]["result"] == "fail"
    assert result["catalog_realm_named"]["depends_on"] == failed


def test_support_json_parse_does_not_add_reads(monkeypatch, capfd, tmp_path):
    path = tmp_path / "discovery.json"
    path.write_text('{"private":')
    traces = []
    native_read = boot.os.read
    for on in (False, True):
        calls = []

        def read(fd, size):
            calls.append(size)
            return native_read(fd, size)

        with monkeypatch.context() as patcher:
            patcher.setattr(boot.os, "read", read)
            if on:
                patcher.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
            else:
                patcher.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
            with pytest.raises(boot.BootstrapError, match="malformed"):
                boot._read_support_json(path)
            traces.append(calls)
            if on:
                result = by_name(capfd)
                assert result["support_json_decode"]["result"] == "pass"
                assert result["support_json_parse"]["result"] == "fail"
            else:
                assert capfd.readouterr().err == ""
    assert traces[0] == traces[1] == [1024 * 1024, 1024 * 1024]


def test_incomplete_upgrade_reports_individual_owner_gates(runtime_case, monkeypatch, capfd):
    case = runtime_case
    (case.paths.runtime_support / "upgrade-journal.json").write_text(
        json.dumps({"operation": "astrid-runtime-upgrade/v1", "state": "switching", "operation_id": "private"})
    )
    enabled(monkeypatch)
    monkeypatch.delenv("ASTRID_V33_OPERATOR_OPERATION", raising=False)
    with pytest.raises(boot.BootstrapError, match="upgrade is incomplete"):
        boot._bootstrap_locked(case.paths, case.boundary, case.config)
    assert case.boundary.starts == []
    result = by_name(capfd)
    assert result["upgrade_journal_present"]["result"] == "pass"
    assert result["upgrade_journal_operation"]["result"] == "pass"
    assert result["upgrade_journal_terminal"]["result"] == "fail"
    assert result["upgrade_journal_operator_matches"]["result"] == "fail"
