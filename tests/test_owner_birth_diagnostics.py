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
