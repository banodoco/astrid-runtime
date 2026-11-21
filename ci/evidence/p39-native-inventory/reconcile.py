"""Replay archived Runtime receipts using an exported, unchanged destination.

This is an offline evidence recipe, never a CI policy or product test runner.
The original executed head and UTC evaluation date stay explicit. Download the
archives named by inputs/source/artifacts.json into inputs/raw/<id>.zip first.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

REPOSITORY = "banodoco/astrid-runtime"
BASE = "97321788fab40400878f9abf1860a7adbf6ddb92"
REPLAY_AT = "2026-11-19T06:56:07+00:00"
RUNS = {"CI": ("ci", 44462380054), "Nightly": ("nightly", 44462380084)}
BASE_DIGESTS = {
    "ci/test-inventory.json.gz": "35edf366eaa8f86f244130a2ce818057384d0813d6e94465c94a8d6ee571ed56",
    "ci/required-checks.json": "b45558565298c82830b1af389fb75111ef58dc7814dca00fe815bded314d0f15",
    "ci/failure-ceiling.json": "c5a2d15127c82e5c52f7a02b1c5e7dac89448f57a4009de1b6975722cf61961b",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    path = Path(path)
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == ".gz" else raw)


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    path.write_bytes(gzip.compress(raw, mtime=0) if path.suffix == ".gz" else raw)


def module(path):
    spec = importlib.util.spec_from_file_location("trusted_hosted", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def native_row(row):
    value = {key: row.get(key) for key in ("lane", "native_id", "parameter", "subtest")}
    if "source" in row:
        value["source"] = row["source"]
    return value


def evaluate(args):
    hosted = module(args.trusted / "scripts/ci/ceiling_hosted.py")
    verdict = hosted.core.evaluate(
        hosted.core.load_policy(args.trusted, REPOSITORY),
        hosted.core.load_policy(args.candidate, REPOSITORY), read(args.report),
        repository=REPOSITORY, head=BASE, tier=args.tier,
        expected_tuple={REPOSITORY: BASE}, now=dt.datetime.fromisoformat(REPLAY_AT),
    )
    write(args.output, verdict)
    print(json.dumps(verdict, indent=2, ensure_ascii=False))
    return {"PASS": 0, "FAIL": 1, "NO-RESULT": 2}[verdict["verdict"]]


def reconcile(args):
    hosted = module(args.trusted / "scripts/ci/ceiling_hosted.py")
    core = hosted.core
    for relative, expected in BASE_DIGESTS.items():
        assert sha(args.trusted / relative) == expected, relative
    trusted = core.load_policy(args.trusted, REPOSITORY)
    checks, ledger, inventory = trusted
    assert not ledger["entries"] and not ledger["retired"]
    artifacts = read(args.inputs / "source/artifacts.json")
    jobs, manifests, command_rows, archives = [], {}, [], []
    for workflow, (slug, run_id) in RUNS.items():
        run = read(args.inputs / f"source/run-{slug}.json")
        job_data = read(args.inputs / f"source/jobs-{slug}.json")
        assert run["id"] == run_id and run["head_sha"] == BASE
        assert run["status"] == "completed" and run["conclusion"] == "failure"
        assert run["run_attempt"] == 1 and len(job_data["jobs"]) == job_data["total_count"]
        roots = []
        for artifact in artifacts:
            if artifact["workflow_run"]["id"] != run_id or not artifact["name"].startswith("failure-ceiling-"):
                continue
            archive = args.inputs / "raw" / f"{artifact['id']}.zip"
            assert artifact["digest"] == "sha256:" + sha(archive)
            assert artifact["workflow_run"]["head_sha"] == BASE and not artifact["expired"]
            root = args.inputs / "raw" / str(artifact["id"])
            with zipfile.ZipFile(archive) as zipped:
                for info in zipped.infolist():
                    target = root / info.filename
                    assert target.resolve().is_relative_to(root.resolve())
                    if not info.is_dir():
                        data = zipped.read(info)
                        if target.exists():
                            assert target.read_bytes() == data, str(target)
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_bytes(data)
            roots.append(root)
            archives.append({"id": artifact["id"], "name": artifact["name"],
                             "run_id": run_id, "sha256": sha(archive), "bytes": archive.stat().st_size})
        for spec in checks["release"]:
            if spec["workflow"] != workflow:
                continue
            raw = [job for job in job_data["jobs"] if job["name"] == spec["job"]]
            assert len(raw) == 1
            job = hosted.normalized_job(spec, raw[0], run, roots, REPOSITORY, BASE,
                                        args.candidate, {REPOSITORY: BASE})
            assert job["commands_complete"] and not job["unexplained_failed_steps"]
            jobs.append(job)
            manifests[core.canonical([workflow, spec["job"]])] = raw[0]
            receipts = {}
            for root in roots:
                for step, (directory, receipt) in hosted.read_command(
                    root, spec, job, REPOSITORY, BASE, args.candidate
                ).items():
                    assert step not in receipts
                    receipts[step] = (directory, receipt)
            for expected in spec["commands"]:
                if expected["id"] not in receipts:
                    assert expected.get("optional")
                    continue
                directory, receipt = receipts[expected["id"]]
                row = {
                    "workflow": workflow, "job": spec["job"], "job_id": job["job_id"],
                    "run_id": run_id, "attempt": job["attempt"], "step": expected["id"],
                    "kind": expected["kind"], "lane": expected.get("lane"),
                    "archive_id": int(directory.parent.name), "command": (directory / "command.txt").read_text(),
                    "command_receipt": receipt, "files": {
                        path.name: {"sha256": sha(path), "bytes": path.stat().st_size}
                        for path in sorted(directory.iterdir()) if path.is_file()
                    },
                }
                if expected["kind"] == "tests":
                    suites = [suite for suite in job["suites"] if suite["name"] == expected["id"]]
                    row["native"] = [{"lane": suite["lane"], "raw_exit": suite["raw_exit"],
                                      "primary_count": len(suite["collected"]),
                                      "identity_count": len(suite["tests"]),
                                      "outcomes": dict(Counter(test["outcome"] for test in suite["tests"]))}
                                     for suite in suites]
                command_rows.append(row)
    assert len(jobs) == 10 and sum(len(job["suites"]) for job in jobs) == 13
    observed = core.index_unique([row for job in jobs for suite in job["suites"]
                                  for row in core.verify_suite(suite, suite["lane"]).values()],
                                 core.identity, "observed identity")
    original = core.index_unique(inventory["tests"], core.identity, "original identity")
    assert len(original) == 30871 and len(observed) == 31322
    assert original.keys() <= observed.keys()
    additions = [native_row(observed[key]) for key in sorted(observed.keys() - original.keys())
                 if observed[key]["outcome"] == "passed"]
    assert len(additions) == 437 and sum(row["subtest"] is not None for row in additions) == 180
    proposed = {**inventory, "tests": inventory["tests"] + additions}
    if args.write_inventory:
        current = read(args.candidate / "ci/test-inventory.json.gz")
        assert current in (inventory, proposed), "candidate has unrelated inventory edits"
        write(args.candidate / "ci/test-inventory.json.gz", proposed)
    candidate = core.load_policy(args.candidate, REPOSITORY)
    assert candidate[0] == trusted[0] and candidate[1] == trusted[1]
    assert candidate[2] == proposed
    assert candidate[2]["tests"][:len(inventory["tests"])] == inventory["tests"]
    write(args.output / "pass-additions.json", additions)
    write(args.output / "command-provenance.json.gz", command_rows)
    write(args.output / "archive-digests.json", archives)
    write(args.output / "original-job-manifests.json.gz", manifests)
    unmapped = [row for key, row in observed.items() if key not in original and row["outcome"] != "passed"]
    unallowed = [row for key, row in observed.items() if row["outcome"] in {"skipped", "xfailed"}
                 and not original.get(key, {}).get("allowed_omission")]
    assert len(unmapped) == 14 and len(unallowed) == 51
    assert sum(row["outcome"] == "failed" for row in observed.values()) == 1630
    write(args.output / "remaining-native-refusals.json.gz", {
        "unseeded_nonpass": unmapped, "unapproved_omissions": unallowed,
        "uncovered_failures": [row for row in observed.values() if row["outcome"] == "failed"],
        "reconciliation": inventory["reconciliation"],
        "omission_evaluation_note": "Census only; evaluator stops at its first disallowed omission.",
    })
    evidence = {
        "repository": REPOSITORY, "executed_head": BASE, "replay_at_utc": REPLAY_AT,
        "classification": "offline historical original-record replay; not candidate execution or a qualifying night",
        "trusted_hashes": {str(p.relative_to(args.trusted)): sha(p)
                           for base in (args.trusted / "ci", args.trusted / "scripts/ci")
                           for p in sorted(base.rglob("*")) if p.is_file() and "__pycache__" not in p.parts},
        "candidate_inventory_sha256": sha(args.candidate / "ci/test-inventory.json.gz"),
        "original_inventory_sha256": sha(args.trusted / "ci/test-inventory.json.gz"),
        "original_identities": len(original), "observed_identities": len(observed),
        "added_passes": len(additions), "added_subtests": 180, "preserved_failures": 1630,
        "unapproved_omissions": len(unallowed), "unseeded_nonpass": len(unmapped),
        "native_outcomes_sha256": core.digest(sorted(observed.values(), key=lambda r: core.key_text(core.identity(r)))),
        "comparisons": {},
    }
    for tier in ("merge", "release"):
        required = core.required_jobs(checks, tier)
        report = {"schema": 1, "repository": REPOSITORY, "head": BASE, "tier": tier,
                  "tuple": {REPOSITORY: BASE}, "complete": True,
                  "jobs": [job for job in jobs if core.job_key(job) in required], "collection_errors": []}
        report_path = args.output / f"{tier}-observed.json.gz"
        write(report_path, report)
        receipt = {"tier": tier, "observed_report_sha256": sha(report_path),
                   "replay_at_utc": REPLAY_AT, "executed_head": BASE,
                   "candidate_inventory_sha256": evidence["candidate_inventory_sha256"],
                   "required_jobs": len(required), "native_invocations": sum(len(j["suites"]) for j in report["jobs"])}
        verdicts = {}
        for label, candidate_root in (("before", args.trusted), ("after", args.candidate)):
            path = args.output / f"{tier}-{label}-verdict.json"
            command = [sys.executable, "-I", str(Path(__file__).resolve()), "--evaluate",
                       "--trusted", str(args.trusted), "--candidate", str(candidate_root),
                       "--report", str(report_path), "--tier", tier, "--output", str(path)]
            result = subprocess.run(command, capture_output=True, text=True, check=False,
                                    env={**os.environ, "PYTHONHASHSEED": "0"})
            (args.output / f"{tier}-{label}.stdout").write_text(result.stdout)
            (args.output / f"{tier}-{label}.stderr").write_text(result.stderr)
            verdict = read(path)
            assert result.returncode == 1 and verdict["verdict"] == "FAIL"
            verdicts[label] = verdict
            receipt[label] = {"raw_exit": result.returncode, "verdict": verdict["verdict"],
                              "verdict_sha256": sha(path), "error_count": len(verdict["errors"]),
                              "first_recorded_error": verdict["errors"][0],
                              "first_fatal_refusal": verdict["errors"][-1],
                              "unknown": verdict["unknown"], "covered": verdict["covered"],
                              "retired": verdict["retired"], "warnings": verdict["warnings"]}
        removed = sorted(set(verdicts["before"]["errors"]) - set(verdicts["after"]["errors"]))
        added = sorted(set(verdicts["after"]["errors"]) - set(verdicts["before"]["errors"]))
        assert len(removed) == 437 and not added
        assert all(value.startswith("observed ID must be retained in the inventory:") for value in removed)
        assert receipt["before"]["first_fatal_refusal"] == receipt["after"]["first_fatal_refusal"]
        receipt["removed_findings"] = removed
        receipt["added_findings"] = added
        receipt["unresolved_obligations_not_reached_by_evaluator"] = inventory["reconciliation"]
        write(args.output / f"{tier}-comparison.json", receipt)
        evidence["comparisons"][tier] = {key: receipt[key] for key in ("before", "after", "required_jobs", "native_invocations")}
    write(args.output / "comparison-summary.json", evidence)
    print(json.dumps({key: evidence[key] for key in ("original_identities", "observed_identities", "added_passes", "preserved_failures", "comparisons")}, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--write-inventory", action="store_true")
    parser.add_argument("--evaluate", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--tier", choices=("merge", "release"))
    args = parser.parse_args()
    args.trusted, args.candidate, args.output = (path.resolve() for path in (args.trusted, args.candidate, args.output))
    if args.inputs:
        args.inputs = args.inputs.resolve()
    return evaluate(args) if args.evaluate else reconcile(args)


if __name__ == "__main__":
    raise SystemExit(main())
