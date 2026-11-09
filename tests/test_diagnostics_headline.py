"""The diagnostics headline from install states that exist in the field (UR-15b).

Each state is built from tests/fixtures/field_states.json, whose records copy
the shapes the Agent writes (astrid-agent PR #319: the storage-move journal,
the selection before and after normalisation, and last-run.json).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from astrid_runtime import diagnostics
from astrid_runtime.diagnostics import diagnostics_report
from astrid_runtime.paths import RuntimePaths, _install_record_path
from runtime_protocol import platform

FIXTURES = json.loads((Path(__file__).parent / "fixtures" / "field_states.json").read_text(encoding="utf-8"))
RULE = "--- Raw detail ---"


def _fill(value, roots):
    text = json.dumps(value)
    for key, path in roots.items():
        text = text.replace("{" + key + "}", str(path))
    text = text.replace('"{pid}"', str(os.getpid()))
    return json.loads(text)


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")
    platform.owner_only(path)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    for name in ("XDG_DATA_HOME", "XDG_STATE_HOME", "LOCALAPPDATA", "ASTRID_RUNTIME_DATA_ROOT"):
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    roots = {"r0": tmp_path / "Astrid Runtime", "r1": tmp_path / "Astrid Runtime-r1", "program": tmp_path / "program"}
    for root in roots.values():
        root.mkdir(parents=True)
    (roots["program"] / "versions" / "release0").mkdir(parents=True)
    (roots["program"] / "versions" / "release1").mkdir(parents=True)
    (roots["program"] / "versions" / "release1" / "big.bin").write_bytes(b"x" * 7)
    return home, roots


def _hannah(home, roots, *, receipt=None):
    state = _fill(FIXTURES["handed_off_release1_r0_live"], roots)
    record = _install_record_path(home)
    _write(record, state["selection"])
    _write(record.with_name(diagnostics.HANDOFF_JOURNAL), state["journal"])
    _write(roots["r0"] / "runtime" / "discovery.json", state["r0_discovery"])
    _write(roots["r0"] / "runtime" / "runtime.log", state["r0_runtime_log"])
    if receipt is not None:
        _write(platform.log_dir(home) / "last-run.json", receipt)
    paths = RuntimePaths.current(home)
    # The Runtime reads the selection the way it does on her Mac: R1 is the active root.
    assert paths.app_support == roots["r1"]
    return paths, state


def _headline(report):
    head, rule, raw = report.partition(RULE)
    assert rule, report
    return head.splitlines(), raw


def test_hannah_release1_handoff_complete_not_updated(machine):
    """The 8 Nov state, with the receipt a UR-15a installer writes when an update installs nothing."""
    home, roots = machine
    paths, state = _hannah(home, roots, receipt=FIXTURES["receipt_not_updated"])
    report = diagnostics_report(paths, {"healthy": True, "state": "ready", "issues": []},
                                live_identity=state["live_identity"], services=state["services"])
    lines, raw = _headline(report)
    assert lines[0] == ("Astrid diagnostics: NOT OK. Installed: Release 1. Latest: Release 10. "
                        "Last update: Astrid did NOT update. It is still Release 1; Release 10 is available.")
    head = "\n".join(lines)
    assert "Installed release        Release 1 (the running Runtime)" in head
    assert "Latest release           Release 10" in head
    assert "update · Release 1 → Release 1 · not-updated (installer-bug) · exit 3" in head
    assert "Why: the installer finished without installing the new release." in head
    # The summary says it plainly; the journal and phase wording is raw detail (Plan 29 R11 card 6).
    assert "Moving your projects     finished; the old copy is kept" in head
    for internal in ("journal", "normalised", "not normalised", "authoritative", "phase"):
        assert internal not in head
    assert "Storage move: phase complete, journal still authoritative (not normalised)" in raw
    assert "2 running (should be 1)" not in head  # R1 publishes no discovery in this fixture
    assert "disk or database full" in head and "database or disk is full" in head
    assert "service pack-host restarted 16 times (last exit 1)" in head
    # Raw detail follows the rule, with true labels and nothing from the old ones.
    assert raw.lstrip("\n").startswith("Selection record identity: managed_by=None; release=1")
    assert "Installer log (install.log, last 80 lines):" in raw
    assert "Program versions on disk: 2 versions, 7 bytes" in raw
    assert "- disk-full" in raw  # support issues carry disk-full although the Runtime said ready
    for gone in ("B1", "Installer transaction log", "Retained back-end copies", "No update has run yet"):
        assert gone not in report
    # Each Runtime's log sits under its own data root.
    assert f"Runtime log for {roots['r0']} (old workspace copy; runtime/runtime.log, last 80 lines):\nTraceback" in raw
    assert f"Runtime log for {roots['r1']} (selected; runtime/runtime.log, last 80 lines):\n(not available)" in raw


def test_hannah_before_any_receipt_says_no_run_recorded(machine):
    """Installers before UR-15a write no receipt: the headline must not claim no update ran."""
    home, roots = machine
    paths, state = _hannah(home, roots)
    report = diagnostics_report(paths, {"healthy": True, "state": "ready", "issues": []},
                                live_identity=state["live_identity"])
    lines, _raw = _headline(report)
    assert lines[0].startswith("Astrid diagnostics: NOT OK. Installed: Release 1. Latest: unknown. "
                               "Last update: no installer run recorded (last-run.json absent)")
    assert any(line.startswith("Problems") and "disk or database full" in line for line in lines)


def test_two_runtimes_for_one_workspace_are_a_problem(machine):
    home, roots = machine
    paths, state = _hannah(home, roots, receipt=FIXTURES["receipt_not_updated"])
    _write(roots["r1"] / "runtime" / "discovery.json", {
        "pid": os.getpid(), "runtime_instance_id": "r1-1", "active_realm": "r0",
        "identity": {"release": 1, "managed_by": None}, "endpoint": "http://127.0.0.1:17341"})
    report = diagnostics_report(paths, {"healthy": True, "state": "ready"}, live_identity=state["live_identity"])
    lines, raw = _headline(report)
    head = "\n".join(lines)
    assert "Runtimes found           2 running (should be 1)" in head
    assert "2 Astrid Runtimes are running for one workspace (should be 1)" in head
    assert "(selected)" in head and "(not selected; old workspace copy)" in head
    # Instance ids and process ids are for support, under the rule.
    assert "instance" not in head and "pid" not in head
    assert f"pid {os.getpid()}" in raw and "instance r1-1" in raw
    assert "- other-runtime-running" in raw


def test_normalised_install_after_update_is_ok(machine, monkeypatch):
    home, roots = machine
    state = _fill(FIXTURES["normalised_after_update"], roots)
    record = _install_record_path(home)
    _write(record, state["selection"])
    _write(record.with_name(diagnostics.HANDOFF_ARCHIVE), state["archive"])
    _write(platform.log_dir(home) / "last-run.json", state["receipt"])
    paths = RuntimePaths.current(home)
    assert paths.app_support == roots["r1"]
    monkeypatch.setattr(diagnostics, "_free_bytes", lambda *_roots: 50 * 1024 ** 3)
    report = diagnostics_report(paths, {"healthy": True, "state": "ready", "issues": []}, live_identity=state["live_identity"])
    lines, raw = _headline(report)
    assert lines[0] == ("Astrid diagnostics: OK. Installed: Release 10. Latest: Release 10. "
                        "Last update: Astrid updated: Release 1 → Release 10.")
    head = "\n".join(lines)
    assert "Moving your projects     finished; the old copy is kept" in head
    assert "journal" not in head and "normalised" not in head
    assert "Storage move: finished and normalised (journal archived); the old workspace copy is kept" in raw
    assert "Problems                 none detected" in head
    assert f"Retained old workspace copy: {roots['r0']}".replace(str(home), "~") in raw
    assert "Free disk space: 53687091200 bytes" in raw


def test_low_free_space_is_a_disk_problem(machine, monkeypatch):
    home, roots = machine
    paths, state = _hannah(home, roots, receipt=FIXTURES["receipt_not_updated"])
    (roots["r0"] / "runtime" / "runtime.log").write_text("ok\n")
    monkeypatch.setattr(diagnostics, "_free_bytes", lambda *_roots: 1024 ** 3)
    report = diagnostics_report(paths, {"healthy": True}, live_identity=state["live_identity"])
    lines, raw = _headline(report)
    assert any("low disk space: 1.0 GB (1073741824 bytes) free, below 2 GB" in line for line in lines)
    assert "- disk-full" in raw
