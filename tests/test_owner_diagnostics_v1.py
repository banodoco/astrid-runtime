"""The shared installer records observe existing decisions without authorizing them."""
import json
from types import SimpleNamespace

from astrid_runtime.owner_diagnostics import outcome, unavailable
from runtime_protocol import platform

PREFIX = "[astrid installer all-predicates v1] "


def records(capfd):
    lines = capfd.readouterr().err.splitlines()
    assert all(line.startswith(PREFIX) for line in lines)
    return [json.loads(line[len(PREFIX):]) for line in lines]


def test_v1_outcomes_are_bounded_and_repeated(monkeypatch, capfd):
    monkeypatch.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
    outcome("birth_direct_inputs", True)
    outcome("birth_direct_inputs", False)
    outcome("birth_direct_parsed", None)
    unavailable("birth_direct_scope", depends_on="birth_direct_parsed")
    outcome("secret /private/path", True)
    result = records(capfd)
    assert [r["result"] for r in result] == ["pass", "fail", "unknown", "unavailable"]
    assert [r["observed"] for r in result] == [True, False, None, None]
    assert result[-1]["depends_on"] == "birth_direct_parsed"
    assert all(set(r) == {"format", "phase", "predicate", "expected", "observed", "provenance", "result"} | ({"depends_on"} if r["result"] == "unavailable" else set()) for r in result)
    assert all(r["format"] == "astrid-installer-all-predicates/v1" for r in result)
    assert "secret" not in json.dumps(result) and "/private/path" not in json.dumps(result)


def test_failed_native_prerequisite_and_call_parity(monkeypatch, capfd):
    import sys
    boot = "b38142f7-84c5-487d-95a4-8180cbff3972"
    calls = []
    class FakePath:
        def __init__(self, value): pass
        def __truediv__(self, value): return self
        def read_text(self):
            calls.append("boot")
            return boot
        def stat(self):
            calls.append("namespace")
            raise PermissionError("private path")
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux", modules=sys.modules))
    monkeypatch.setattr(platform, "Path", FakePath)
    monkeypatch.setattr(platform, "process_identity", lambda pid: calls.append("identity"))
    def run():
        return platform.legacy_linux_birth_matches_live_owner(
            "proc-start-ticks:42", f"proc-start-ticks:42;boot:{boot};pidns:77", pid=123)
    monkeypatch.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
    assert run() is None
    assert calls == ["boot", "namespace"]
    assert capfd.readouterr().err == ""
    calls.clear()
    monkeypatch.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
    assert run() is None
    assert calls == ["boot", "namespace"]
    result = records(capfd)
    items = {r["predicate"]: r for r in result}
    assert items["birth_bridge_pidns_read"]["result"] == "unknown"
    assert items["birth_bridge_identity_read"]["result"] == "unavailable"
    assert items["birth_bridge_identity_read"]["depends_on"] == "birth_bridge_pidns_read"
    assert all(secret not in json.dumps(result) for secret in (boot, "private", "123", "77"))


def test_connect_refusal_and_observation_counts_match(monkeypatch, capfd):
    import importlib
    import pytest
    bootstrap = importlib.import_module("astrid_runtime.bootstrap")

    calls = []
    monkeypatch.setattr(bootstrap, "_validate_support_paths", lambda paths: calls.append("paths"))
    monkeypatch.setattr(bootstrap, "_read_catalog", lambda paths: calls.append("catalog") or {})
    monkeypatch.setattr(bootstrap, "_selected_realm", lambda catalog: {"realm_id": "private-realm"})
    monkeypatch.setattr(bootstrap, "_read_support_json", lambda path: calls.append("discovery") or {
        "pid": 123, "endpoint": "http://127.0.0.1:1", "runtime_instance_id": "private-instance"})
    monkeypatch.setattr(bootstrap, "_compatible", lambda *args: calls.append("compatible"))
    monkeypatch.setattr(bootstrap, "_capture_requested_identity", lambda source: calls.append("identity"))
    monkeypatch.setattr(bootstrap, "_pid_alive", lambda boundary, pid: calls.append("pid") or False)
    config = SimpleNamespace(resolve_source_profile=lambda paths: "source")
    paths = SimpleNamespace(discovery_path="private-path")
    boundary = SimpleNamespace(validate_owner=lambda **kwargs: calls.append("owner"))
    def run():
        with pytest.raises(bootstrap.BootstrapError, match="discovery is stale or owned"):
            bootstrap.connect(paths, boundary, config)
    monkeypatch.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
    run()
    baseline = calls[:]
    assert capfd.readouterr().err == ""
    calls.clear()
    monkeypatch.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
    run()
    assert calls == baseline and "owner" not in calls
    result = records(capfd)
    admission = [
        r
        for r in result
        if r["predicate"]
        in {
            "connect_realm_present",
            "connect_discovery_present",
            "connect_pid_alive",
            "connect_owner_valid",
        }
    ]
    assert [(r["phase"], r["predicate"], r["result"]) for r in admission] == [
        ("admission", "connect_realm_present", "pass"),
        ("admission", "connect_discovery_present", "pass"),
        ("admission", "connect_pid_alive", "fail"),
        ("admission", "connect_owner_valid", "unavailable"),
    ]
    assert admission[-1]["depends_on"] == "connect_pid_alive"
    assert {r["predicate"] for r in result if r["result"] == "unavailable"} >= {
        "connect_owner_valid",
        "connect_health",
        "connect_selected_realm",
    }
    assert "private" not in json.dumps(result) and "123" not in json.dumps(result)


def test_reconnect_revalidates_between_provision_and_selection_with_parity(monkeypatch, capfd):
    import pytest
    from tests.test_bootstrap import BootstrapTests, FakeConnection
    from astrid_runtime.bootstrap import BootstrapError, bootstrap

    results = []
    for enabled in (False, True):
        case = BootstrapTests()
        case.setUp()
        try:
            case._configure()
            bootstrap(case.paths, case.boundary, case.config)
            calls = []
            original_validate = case.boundary.validate_owner
            def validate(**kwargs):
                calls.append("validate")
                return original_validate(**kwargs)
            case.boundary.validate_owner = validate
            class ReplacingConnection(FakeConnection):
                def provision_actor(self, **kwargs):
                    calls.append("provision")
                    case.boundary.valid_owner = False
                    return {"scope": "astrid"}
                def select_realm(self, **kwargs):
                    calls.append("select")
            case.boundary.connect = lambda **kwargs: ReplacingConnection(case.boundary)
            if enabled:
                monkeypatch.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
            else:
                monkeypatch.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
            with pytest.raises(BootstrapError, match="owner changed during reconnect"):
                bootstrap(case.paths, case.boundary, case.config)
            results.append(calls)
            stderr = capfd.readouterr().err
            if enabled:
                assert "[astrid installer all-predicates v1]" in stderr
                assert str(case.paths.app_support) not in stderr
            else:
                assert stderr == ""
        finally:
            case.tearDown()
            case.doCleanups()
    assert results[0] == results[1]
    assert "provision" in results[0] and "select" not in results[0]
    assert results[0][results[0].index("provision") + 1] == "validate"


def test_stop_diagnostics_preserve_fence_and_stop_order(monkeypatch, capfd):
    import importlib
    from contextlib import contextmanager
    from tests.test_bootstrap import BootstrapTests
    bootstrap_module = importlib.import_module("astrid_runtime.bootstrap")
    results = []
    for enabled in (False, True):
        case = BootstrapTests()
        case.setUp()
        try:
            case._configure()
            bootstrap_module.bootstrap(case.paths, case.boundary, case.config)
            events = []
            original_fence = bootstrap_module.interruption_fence
            original_stop = case.boundary.stop_owner
            @contextmanager
            def counted_fence(root):
                events.append("fence")
                with original_fence(root) as report:
                    yield report
            def stop_owner(**kwargs):
                events.append("stop_owner")
                return original_stop(**kwargs)
            case.boundary.stop_owner = stop_owner
            with monkeypatch.context() as patcher:
                patcher.setattr(bootstrap_module, "interruption_fence", counted_fence)
                if enabled:
                    patcher.setenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", "1")
                else:
                    patcher.delenv("ASTRID_INSTALLER_ALL_PREDICATES_DIAGNOSTICS", raising=False)
                result = bootstrap_module.down(case.paths, case.boundary,
                                               stop_manager=lambda: events.append("manager"))
            assert result["status"] == "stopped"
            results.append(events)
            stderr = capfd.readouterr().err
            if enabled:
                assert "[astrid installer all-predicates v1]" in stderr
                assert str(case.paths.app_support) not in stderr
            else:
                assert stderr == ""
        finally:
            case.tearDown()
            case.doCleanups()
    assert results == [["fence", "stop_owner", "manager"]] * 2
