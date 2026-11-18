"""Fail closed when a CI test-results bundle is empty, shortened or unfinished."""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from xml.etree import ElementTree as ET


_OUTCOME = re.compile(r"\b(\d+) (passed|failed|skipped|xfailed|xpassed|errors?)\b")
_SUBTESTS = re.compile(r"\b(\d+) subtests? passed\b")


def check_counts(xml: Path, console: Path) -> tuple[list[str], int]:
    try:
        root = ET.parse(xml).getroot()
        lines = console.read_text(encoding="utf-8").splitlines()
    except (OSError, ET.ParseError) as exc:
        return [f"test result input unreadable: {exc}"], 0
    actual = len(list(root.iter("testcase")))
    errors = []
    if not actual:
        errors.append("JUnit has zero testcase elements")
    # Nested pytester output also contains summaries; only the final completed
    # pytest summary is the job's result, and no header is its authority.
    summaries = [line for line in lines if re.search(r"\bin \d+(?:\.\d+)?s\b", line) and _OUTCOME.search(line)]
    if not summaries:
        return [*errors, "pytest final outcome summary is missing"], actual
    summary = summaries[-1]
    reported = sum(int(count) for count, _ in _OUTCOME.findall(summary))
    if actual != reported:
        errors.append(f"JUnit testcase count {actual} differs from pytest summary {reported}: {summary.strip()}")
    # pytest's subtest reporter adds passing subtests to the suite header
    # without emitting testcase elements. Accept exactly that documented-by-
    # evidence difference, not an arbitrary inflated header.
    subtests = sum(map(int, _SUBTESTS.findall(summary)))
    try:
        header = sum(int(suite.attrib["tests"]) for suite in root.iter("testsuite"))
    except (KeyError, ValueError) as exc:
        errors.append(f"invalid JUnit tests header: {exc}")
    else:
        if header not in {actual, actual + subtests}:
            errors.append(f"JUnit header claims {header} tests but contains {actual} cases and reports {subtests} passing subtests")
    return errors, actual


def check_bundle(directory: Path) -> tuple[list[str], int]:
    files = sorted(directory.glob("*.xml"))
    if len(files) != 1:
        return [f"expected one JUnit file, found {len(files)} in {directory}"], 0
    errors, actual = check_counts(files[0], directory / "pytest.log")
    try:
        reference = json.loads((directory / "collection.json").read_text(encoding="utf-8"))["nodeids"]
        events = [json.loads(line) for line in (directory / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    except (OSError, ValueError, KeyError) as exc:
        return [*errors, f"collection/report evidence unreadable: {exc}"], actual
    if not reference or len(reference) != len(set(reference)):
        errors.append("independent collection inventory is empty or contains duplicate IDs")
    collected = {nodeid for event in events if event.get("event") == "collection" for nodeid in event["nodeids"]}
    expected = set(reference)
    if collected != expected:
        errors.append(f"collected ID union differs from manifest: missing={sorted(expected - collected)} added={sorted(collected - expected)}")
    completed = {
        event["nodeid"] for event in events
        if event.get("event") == "test_report" and event.get("when") == "teardown" and not event.get("subtest")
    }
    if completed != expected:
        errors.append(f"incomplete per-test results: missing={sorted(expected - completed)} added={sorted(completed - expected)}")
    if not events or events[-1].get("event") != "finish":
        errors.append("incremental report log has no session finish; the run was interrupted or killed")
    elif events[-1].get("collected") != len(expected):
        errors.append(f"session collected count {events[-1].get('collected')} differs from manifest {len(expected)}")
    return errors, actual


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    errors, actual = check_bundle(args.directory)
    line = f"test-results: {actual} actual testcase elements; {'FAIL' if errors else 'PASS'}"
    print(line)
    for error in errors:
        print(f"ERROR: {error}")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
            stream.writelines(f"- {error}\n" for error in errors)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
