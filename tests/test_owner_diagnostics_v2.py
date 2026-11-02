"""Versioned diagnostics contain only redacted predicate outcomes."""
import json

import pytest

from astrid_runtime.owner_diagnostics import capture, outcome, skipped
from astrid_runtime.bootstrap import BootstrapError, _recorded_owner_identity


def _record(capfd):
    output = capfd.readouterr().err
    assert output.startswith("ASTRID_OWNER_DIAGNOSTICS ")
    return json.loads(output.split(" ", 1)[1])


def test_v2_outcomes_and_redaction(monkeypatch, capfd):
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "2")
    with capture():
        outcome("birth_direct_inputs", True)
        outcome("birth_direct_parsed", False)
        outcome("birth_direct_scope", None)
        skipped("birth_direct_pidns")
        outcome("birth_bridge_native_readable", False, error=True)
        outcome("private secret", True)  # Unknown names never enter the record.
    document = _record(capfd)
    assert document["schema"] == 2
    predicates = document["predicates"]
    assert [p["status"] for p in predicates] == ["pass", "fail", "unknown", "skipped", "error"]
    assert [p["observed"] for p in predicates] == [True, False, None, None, None]
    assert all(p["expected"] is True and p["provenance"] for p in predicates)
    assert [p["unavailable_due_to"] for p in predicates] == [None, None, "indeterminate", "not_evaluated", "observation_error"]
    assert "private secret" not in json.dumps(document)


@pytest.mark.parametrize("version", [None, "1", "2"])
def test_recorded_identity_refusal_parity(monkeypatch, capfd, tmp_path, version):
    if version is None:
        monkeypatch.delenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", raising=False)
    else:
        monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", version)
    with pytest.raises(BootstrapError, match="discovery or owner identity is incomplete"):
        _recorded_owner_identity({"pid": "private secret"}, realm_id="private", realm_root=tmp_path)
    output = capfd.readouterr().err
    assert "private" not in output
    if version == "2":
        doc = json.loads(output.split(" ", 1)[1])
        assert doc["predicates"][0]["name"] == "recorded_identity_readable"
        assert doc["predicates"][0]["status"] == "fail"
    elif version is None:
        assert output == ""


def test_bridge_reports_exact_native_read_error_without_extra_reads(monkeypatch, capfd):
    from types import SimpleNamespace
    import sys
    from runtime_protocol import platform

    calls = []
    boot = "b38142f7-84c5-487d-95a4-8180cbff3972"

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
        with capture():
            return platform.legacy_linux_birth_matches_live_owner(
                "proc-start-ticks:42", f"proc-start-ticks:42;boot:{boot};pidns:77", pid=123)
    monkeypatch.delenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", raising=False)
    assert run() is None
    assert calls == ["boot", "namespace"]
    calls.clear()
    monkeypatch.setenv("ASTRID_RUNTIME_OWNER_DIAGNOSTICS", "2")
    assert run() is None
    assert calls == ["boot", "namespace"]
    doc = _record(capfd)
    predicates = {p["name"]: p for p in doc["predicates"]}
    assert predicates["birth_bridge_boot_read"]["status"] == "pass"
    assert predicates["birth_bridge_pidns_read"]["status"] == "error"
    assert "birth_bridge_identity_read" not in predicates
    assert all(secret not in json.dumps(doc) for secret in (boot, "private", "123", "77"))
