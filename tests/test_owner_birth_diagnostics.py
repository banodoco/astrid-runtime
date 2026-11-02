"""Member diagnostics follow the real comparison and never expose its inputs."""
import json
from types import SimpleNamespace

import pytest

from astrid_runtime.owner_diagnostics import capture
from runtime_protocol import platform


@pytest.mark.parametrize("expected,actual,result,fields", [
    ("proc-start-ticks:42;boot:secret-a;pidns:77", "proc-start-ticks:42;boot:secret-a;pidns:77", True, ("matched", "matched", "matched")),
    ("proc-start-ticks:42;boot:secret-a;pidns:77", "proc-start-ticks:42;boot:secret-b;pidns:77", False, ("matched", "false", "unobserved")),
    ("proc-start-ticks:42;boot:secret-a;pidns:77", "proc-start-ticks:43;boot:secret-a;pidns:77", False, ("matched", "matched", "false")),
    ("proc-start-ticks:42;boot:secret-a;pidns:77", "proc-start-ticks:42;boot:secret-a;pidns:78", None, ("false", "unobserved", "unobserved")),
    ("proc-start-ticks:42", "proc-start-ticks:42;boot:secret-a;pidns:77", None, ("unobserved",)*3),
    ("proc-start-ticks:bad", "proc-start-ticks:42;boot:secret-a;pidns:77", None, ("unobserved",)*3),
    ("proc-start-ticks:42;boot:a;boot:b;pidns:77", "proc-start-ticks:42;boot:a;pidns:77", None, ("unobserved",)*3),
])
def test_direct_members(monkeypatch, capfd, expected, actual, result, fields):
    monkeypatch.delenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", raising=False)
    with capture():
        assert platform.process_birth_matches(expected, actual) is result
    assert capfd.readouterr().err == ""
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "1")
    with capture():
        assert platform.process_birth_matches(expected, actual) is result
    output = capfd.readouterr().err
    assert "secret" not in output and "77" not in output and "42" not in output
    predicates = json.loads(output.split(" ", 1)[1])["predicates"]
    assert tuple(predicates["birth_direct_" + name] for name in ("pidns", "boot", "tick")) == fields


@pytest.mark.parametrize("case,result,fields", [
    ("match", True, ("matched", "matched", "matched", "matched", "matched", "matched")),
    ("tick", False, ("false", "unobserved", "unobserved", "unobserved", "unobserved", "unobserved")),
    ("boot", None, ("matched", "matched", "matched", "matched", "false", "unobserved")),
    ("namespace", None, ("matched", "matched", "matched", "matched", "matched", "false")),
    ("bad_namespace", None, ("matched", "matched", "matched", "false", "unobserved", "unobserved")),
    ("bad_boot", None, ("matched", "matched", "unobserved", "unobserved", "unobserved", "unobserved")),
    ("noncanonical_boot", None, ("matched", "matched", "false", "unobserved", "unobserved", "unobserved")),
    ("missing", None, ("unobserved",)*6),
    ("unreadable", None, ("matched", "unobserved", "unobserved", "unobserved", "unobserved", "unobserved")),
    ("replaced", None, ("matched", "false", "unobserved", "unobserved", "unobserved", "unobserved")),
])
def test_bridge_members(monkeypatch, capfd, case, result, fields):
    boot = "b38142f7-84c5-487d-95a4-8180cbff3972"
    other = "de2e05aa-6956-451e-9dd9-521955212d27"
    observed = f"proc-start-ticks:42;boot:{other if case == 'boot' else boot};pidns:{'78' if case == 'namespace' else 'bad' if case == 'bad_namespace' else '77'}"
    if case == "missing":
        observed = "proc-start-ticks:42;boot:secret"

    class FakePath:
        def __init__(self, value): pass
        def __truediv__(self, value): return self
        def read_text(self):
            if case == "unreadable":
                raise OSError("secret error")
            return "invalid-secret" if case == "bad_boot" else boot.upper() if case == "noncanonical_boot" else boot
        def stat(self): return SimpleNamespace(st_ino=77)

    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux", modules=__import__('sys').modules))
    monkeypatch.setattr(platform, "Path", FakePath)
    monkeypatch.setattr(platform, "process_identity", lambda pid: {"pid": pid, "birth_id": "different-secret" if case == "replaced" else observed})
    def run():
        with capture():
            return platform.legacy_linux_birth_matches_live_owner("proc-start-ticks:43" if case == "tick" else "proc-start-ticks:42", observed, pid=123)
    monkeypatch.delenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", raising=False)
    assert run() is result
    assert capfd.readouterr().err == ""
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "1")
    assert run() is result
    output = capfd.readouterr().err
    assert all(value not in output for value in (boot, other, "secret", "123", "77", "42"))
    predicates = json.loads(output.split(" ", 1)[1])["predicates"]
    assert tuple(predicates["birth_bridge_" + name] for name in ("tick", "fresh_birth", "boot_valid", "pidns_numeric", "boot", "pidns")) == fields


def test_native_bridge_reports_missing_prerequisites_without_extra_reads(monkeypatch, capfd):
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "1")
    monkeypatch.setattr(platform, "sys", SimpleNamespace(platform="linux", modules=__import__('sys').modules))
    calls = []

    class FakePath:
        def __init__(self, value): pass
        def __truediv__(self, value): return self
        def read_text(self):
            calls.append("boot")
            return "b38142f7-84c5-487d-95a4-8180cbff3972"
        def stat(self):
            calls.append("namespace")
            return SimpleNamespace(st_ino=77)

    monkeypatch.setattr(platform, "Path", FakePath)
    def identity(pid):
        calls.append("identity")
        return {"pid": pid + 1, "birth_id": "private"}
    monkeypatch.setattr(platform, "process_identity", identity)
    with capture():
        assert platform.legacy_linux_birth_matches_live_owner(
            "proc-start-ticks:42",
            "proc-start-ticks:42;boot:b38142f7-84c5-487d-95a4-8180cbff3972;pidns:77",
            pid=123,
        ) is None
    output = capfd.readouterr().err
    predicates = json.loads(output.split(" ", 1)[1])["predicates"]
    assert calls == ["boot", "namespace", "identity"]
    assert predicates["birth_bridge_native_readable"] == "matched"
    assert predicates["birth_bridge_fresh_present"] == "matched"
    assert predicates["birth_bridge_fresh_pid"] == "false"
    assert predicates["birth_bridge_fresh_birth"] == "unobserved"
    assert predicates["birth_bridge_boot_parseable"] == "unobserved"
    assert "private" not in output and "123" not in output


def test_direct_missing_scope_is_distinct_from_malformed_birth(monkeypatch, capfd):
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "1")
    for expected, parsed, scope in [("proc-start-ticks:bad", "false", "unobserved"),
                                    ("proc-start-ticks:42", "matched", "false")]:
        with capture():
            assert platform.process_birth_matches(expected, "proc-start-ticks:42;boot:secret;pidns:77") is None
        output = capfd.readouterr().err
        predicates = json.loads(output.split(" ", 1)[1])["predicates"]
        assert predicates["birth_direct_inputs"] == "matched"
        assert predicates["birth_direct_parsed"] == parsed
        assert predicates["birth_direct_scope"] == scope
        assert predicates["birth_direct_pidns"] == "unobserved"
        assert "secret" not in output


@pytest.mark.parametrize("alive,birth,match,result", [
    (False, "private", True, False),
    (True, None, True, True),
    (True, "private", None, True),
    (True, "private", False, False),
    (True, "private", True, True),
])
def test_discovery_liveness_observation_does_not_change_decision(
    monkeypatch, capfd, alive, birth, match, result,
):
    from astrid_runtime.bootstrap import _owner_may_be_alive

    calls = []
    boundary = SimpleNamespace(
        is_pid_alive=lambda pid: calls.append("pid") or alive,
        process_birth_identity=lambda pid: calls.append("birth") or birth,
    )
    monkeypatch.setattr(platform, "process_birth_matches",
                        lambda expected, actual: calls.append("compare") or match)
    record = {"pid": 123, "process_birth_id": "private-expected"}
    monkeypatch.delenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", raising=False)
    assert _owner_may_be_alive(boundary, record) is result
    baseline_calls = calls[:]
    assert capfd.readouterr().err == ""
    calls.clear()
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "1")
    assert _owner_may_be_alive(boundary, record) is result
    assert calls == baseline_calls
    output = capfd.readouterr().err
    assert "private" not in output and "123" not in output
    predicates = json.loads(output.split(" ", 1)[1])["predicates"]
    assert predicates["liveness_pid_alive"] == ("matched" if alive else "false")
    if alive and birth is not None:
        assert predicates["liveness_birth_compatible"] == (
            "unobserved" if match is None else "matched" if match else "false"
        )
    else:
        assert predicates["liveness_birth_compatible"] == "unobserved"
