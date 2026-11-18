"""Adversarial checks for selection custody and complete stored test results."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.ci.check_test_results import check_bundle, check_counts
from tests.test_skip_guard import REPO, sandbox  # noqa: F401

pytest_plugins = ["pytester"]


@pytest.mark.parametrize("workers", [0, 2], ids=["serial", "xdist"])
@pytest.mark.parametrize("method", ["drop", "collect_ignore", "collect_ignore_glob", "ignore-hook", "deselect"])
def test_collection_guard_refuses_hidden_deselection(sandbox, workers, method):
    sandbox.makepyfile(check_keep="def test_keep(): pass", check_hidden="def test_hidden(): pass")
    conftest = sandbox.path / "conftest.py"
    extra = []
    if method == "drop":
        addition = "\ndef pytest_collection_modifyitems(items):\n    items[:] = [item for item in items if 'test_hidden' not in item.nodeid]\n"
    elif method in {"collect_ignore", "collect_ignore_glob"}:
        addition = f"\n{method} = ['check_hidden.py']\n"
    elif method == "ignore-hook":
        addition = "\ndef pytest_ignore_collect(collection_path):\n    return collection_path.name == 'check_hidden.py'\n"
    else:
        addition = ""
        extra = ["--deselect=check_hidden.py::test_hidden"]
    conftest.write_text(conftest.read_text() + addition)
    result = sandbox.runpytest_subprocess("-q", *extra, *(("-n", str(workers)) if workers else ()))
    assert result.ret != 0
    assert "UNDECLARED DESELECTION" in result.stdout.str() + result.stderr.str()


@pytest.mark.parametrize("change", ["remove", "add"])
def test_execution_must_match_independent_collect_only_inventory(sandbox, change):
    path = sandbox.makepyfile(check_it="def test_a(): pass\ndef test_b(): pass")
    manifest = sandbox.path / "collection.json"
    result = sandbox.runpytest_subprocess("-q", "--collect-only", f"--collection-manifest={manifest}")
    assert result.ret == 0
    path.write_text("def test_a(): pass\n" if change == "remove" else "def test_a(): pass\ndef test_b(): pass\ndef test_new(): pass\n")
    result = sandbox.runpytest_subprocess("-q", f"--collection-manifest={manifest}")
    assert result.ret != 0
    assert "execution differs from independent --collect-only inventory" in result.stdout.str() + result.stderr.str()


@pytest.mark.parametrize("workers", [0, 2], ids=["serial", "xdist"])
def test_complete_results_are_checked_even_when_a_test_fails(sandbox, workers):
    sandbox.makepyfile(check_it="def test_pass(): pass\ndef test_fail(): assert False")
    directory = sandbox.path / "results"
    manifest = directory / "collection.json"
    collected = sandbox.runpytest_subprocess("-q", "--collect-only", f"--collection-manifest={manifest}")
    assert collected.ret == 0
    result = sandbox.runpytest_subprocess(
        "-q", "-rA", f"--junitxml={directory / 'results.xml'}", f"--collection-manifest={manifest}",
        f"--result-log={directory / 'events.jsonl'}", *(("-n", str(workers)) if workers else ()),
    )
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    (directory / "pytest.log").write_text(result.stdout.str())
    assert check_bundle(directory) == ([], 2)
    events = directory / "events.jsonl"
    events.write_text("\n".join(events.read_text().splitlines()[:-1]) + "\n")
    assert any("no session finish" in error for error in check_bundle(directory)[0])


def test_ci_entrypoint_records_the_same_selection_and_preserves_test_failure(sandbox):
    sandbox.makepyfile(check_it="def test_pass(): pass\ndef test_fail(): assert False")
    directory = sandbox.path / "recorded"
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/ci/run_pytest.py"), str(directory), "proof", "--", "-q", "-n", "2"],
        cwd=sandbox.path, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert check_bundle(directory) == ([], 2)
    assert "2 tests collected" in (directory / "collection.log").read_text()


@pytest.mark.parametrize("variant", ["inflated-header", "short-file", "zero", "missing-summary"])
def test_results_checker_refuses_untrustworthy_xml(tmp_path, variant):
    xml, console = tmp_path / "result.xml", tmp_path / "pytest.log"
    cases, header, summary = '<testcase name="one"/>', 1, "1 passed in 0.01s"
    if variant == "inflated-header":
        header = 2
    elif variant == "short-file":
        header, summary = 2, "2 passed in 0.01s"
    elif variant == "zero":
        cases, header, summary = "", 0, "0 passed in 0.01s"
    else:
        summary = "process was killed before its final summary"
    xml.write_text(f'<testsuites><testsuite tests="{header}">{cases}</testsuite></testsuites>')
    console.write_text(summary)
    assert check_counts(xml, console)[0]


def test_passing_subtests_explain_only_their_exact_header_difference(tmp_path):
    xml, console = tmp_path / "result.xml", tmp_path / "pytest.log"
    console.write_text("1 passed, 2 subtests passed in 0.01s")
    xml.write_text('<testsuites><testsuite tests="3"><testcase name="one"/></testsuite></testsuites>')
    assert check_counts(xml, console) == ([], 1)
    xml.write_text('<testsuites><testsuite tests="4"><testcase name="one"/></testsuite></testsuites>')
    assert check_counts(xml, console)[0]


def test_killed_test_process_leaves_flushed_partial_results(sandbox):
    started = sandbox.path / "started"
    sandbox.makepyfile(check_it=f'''
import time
from pathlib import Path
def test_first(): pass
def test_second():
    Path({str(started)!r}).write_text("started")
    time.sleep(30)
''')
    events_path = sandbox.path / "events.jsonl"
    with (sandbox.path / "killed.log").open("w") as output:
        child = subprocess.Popen(
            [sys.executable, "-m", "pytest", "-q", f"--result-log={events_path}"],
            cwd=sandbox.path, stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while not started.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            assert started.exists(), (sandbox.path / "killed.log").read_text()
            # Read while the second test is still executing: preservation
            # cannot depend on normal shutdown or a JUnit finalizer.
            events = [json.loads(line) for line in events_path.read_text().splitlines()]
            assert any(event.get("nodeid") == "check_it.py::test_first" and event.get("when") == "teardown" for event in events)
            child.kill()
            child.wait(timeout=10)
            assert all(event["event"] != "finish" for event in map(json.loads, events_path.read_text().splitlines()))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
