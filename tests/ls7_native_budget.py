"""Packet-owned native attribution using the unchanged LS-2 counter.

Run with --agent-checkout pointing at the exact LS-2 checkout. The reference
fixture performs separate create/claim/settle under the effective WAL/FULL
configuration. Neither checkpoints nor filesystem syncs are disabled. Raw
capture, application intervals and the unchanged counter output are retained.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def measure(output):
    from runtime_protocol.service import RuntimeService
    from runtime_protocol.store import RealmStore
    with tempfile.TemporaryDirectory(prefix="astrid-ls7-budget-") as temporary:
        root = Path(temporary) / "realm"
        RealmStore.initialize(root).close()
        service = RuntimeService(root)
        try:
            service.register_executor({"executor_id": "ls7-budget", "capabilities": ["ls7.budget"]}, idempotency_key="register")
            # This creates only the shared preparation directory, no attempt,
            # output, receipt or WAL policy for the measured job.
            service.store.attempt_staging_dir("preparation")
            modes = {name: service.store.conn.execute("PRAGMA " + name).fetchone()[0]
                     for name in ("journal_mode", "synchronous", "wal_autocheckpoint")}
            assert modes["journal_mode"] == "wal" and modes["synchronous"] == 2
            statements, commits, app_syncs, phases = [], [], [], []
            changes = service._changes()
            committed = changes.committed
            def successful_commit():
                commits.append(time.time_ns())
                committed()
            changes.committed = successful_commit
            service.store.conn.set_trace_callback(statements.append)
            original_fsync = os.fsync
            def fsync(fd):
                started = time.time_ns()
                path = os.readlink(f"/proc/self/fd/{fd}") if sys.platform.startswith("linux") else None
                result = original_fsync(fd)
                app_syncs.append({"path": path, "start_ns": started, "end_ns": time.time_ns()})
                return result
            def phase(name, operation):
                start = time.time_ns()
                value = operation()
                phases.append({"name": name, "start_ns": start, "end_ns": time.time_ns()})
                return value
            os.fsync = fsync
            interval = {"pid": os.getpid(), "epoch_start_ns": time.time_ns()}
            try:
                created = phase("create", lambda: service.create_task({"capability_id": "ls7.budget", "idempotency_key": "one-output"}))
                claim = phase("claim", lambda: service.claim_next({"executor_id": "ls7-budget", "capability_ids": ["ls7.budget"],
                    "runtime_epoch": service._runtime_state["runtime_epoch"]}, idempotency_key="claim"))
                payload = b"one new durable LS7 output\n"
                digest = "sha256:" + hashlib.sha256(payload).hexdigest()
                result = phase("settle", lambda: service.settle_attempt(claim["attempt_id"], {
                    **{key: claim[key] for key in ("lease_id", "fence", "runtime_epoch")},
                    "outputs": [{"digest": digest, "data_base64": base64.b64encode(payload).decode(), "size": len(payload),
                                 "kind": "object", "name": "result", "media_type": "application/octet-stream"}],
                    "progress": {"phase": "complete", "percent": 100},
                }, idempotency_key="settle"))
                snapshot = service.wait_for_task(created["task"]["id"], {"timeout_seconds": 0})
                interval["epoch_reply_ns"] = time.time_ns()
            finally:
                os.fsync = original_fsync
                changes.committed = committed
                service.store.conn.set_trace_callback(None)
            assert len(commits) == 3 and statements.count("COMMIT") == 3
            assert len(app_syncs) == 9
            assert snapshot["task"]["state"] == "succeeded"
            assert snapshot["task"]["progress"] == {"phase": "complete", "percent": 100}
            assert len(snapshot["managed_outputs"]["items"]) == 1 and service.cas.read(digest[7:]) == payload
            report = {"schema": "astrid.ls7-write-budget.v1", "interval": interval, "phases": phases,
                      "sqlite": modes, "successful_outer_commits": len(commits), "commit_times_ns": commits,
                      "application_sync_calls": app_syncs, "application_sync_count": len(app_syncs),
                      "database": str(service.store.db_path), "output_digest": digest,
                      "native_status": "NO-RESULT", "native": None,
                      "fixture": "warm Runtime, one new inline output, no concurrent maintenance; startup excluded"}
            output.write_text(json.dumps(report, indent=2) + "\n")
            return report
        finally:
            service.close()


def capture(output, agent_checkout):
    output.mkdir(parents=True, exist_ok=False)
    command = ["strace", "-ff", "--seccomp-bpf", "-ttt", "-T", "-yy", "-e", "trace=process,fsync,fdatasync",
               "-o", str(output / "trace"), "--", sys.executable, str(Path(__file__).resolve()),
               "--measure", str(output / "application.json")]
    metadata = {"command": command, "platform": platform.platform(), "python": sys.version,
                "runtime_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                "ls2_agent_sha": subprocess.check_output(["git", "-C", str(agent_checkout), "rev-parse", "HEAD"], text=True).strip()}
    with (output / "proof.log").open("wb") as log:
        try:
            metadata["exit_code"] = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120).returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            metadata.update(exit_code=1, error=str(error))
    (output / "capture.json").write_text(json.dumps(metadata, indent=2) + "\n")
    if metadata["exit_code"] != 0:
        return {"native_status": "NO-RESULT", "reason": "native capture failed; inspect proof.log", **metadata}
    spec = importlib.util.spec_from_file_location("ls2_native_counter", agent_checkout / "tests" / "_local_speed_native.py")
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    report = json.loads((output / "application.json").read_text())
    counter = reader.count_interval(reader.trace_strace(output), report["interval"])
    report["native"] = counter
    report.update(metadata)
    interval = report["interval"]
    # -yy adds fd paths to the same raw syscall stream consumed by LS-2.
    # Attribute only fully decoded successful calls inside the exact interval.
    calls = []
    pattern = re.compile(r"^(\d+\.\d+)\s+(fsync|fdatasync)\(\d+<(.+)>\)\s+=\s+0\s+<(\d+\.\d+)>$")
    for trace in sorted(output.glob("trace.*")):
        for line in trace.read_text().splitlines():
            match = pattern.match(line)
            if match:
                start = reader.seconds_ns(match[1])
                end = start + reader.seconds_ns(match[4])
                if interval["epoch_start_ns"] <= start and end <= interval["epoch_reply_ns"]:
                    calls.append({"path": match[3], "operation": match[2], "start_ns": start, "end_ns": end})
    database = report["database"]
    wal = [call for call in calls if call["path"] == database + "-wal"]
    db_syncs = [call for call in calls if call["path"] == database]
    application = [call for call in calls if any(
        item["path"] == call["path"] and item["start_ns"] - 1000 <= call["start_ns"] <= item["end_ns"] + 1000
        for item in report["application_sync_calls"])]
    unknown = [call for call in calls if call not in wal and call not in db_syncs and call not in application]
    vector = {"wal_syncs": len(wal), "application_syncs": len(application),
              "checkpoint_database_syncs": len(db_syncs), "unattributed_syncs": unknown,
              "per_phase": {phase["name"]: {"wal_syncs": sum(phase["start_ns"] <= call["start_ns"] <= phase["end_ns"] for call in wal),
                    "application_syncs": sum(phase["start_ns"] <= call["start_ns"] <= phase["end_ns"] for call in application)}
                    for phase in report["phases"]}}
    report["vector"] = vector
    qualified = (counter["native_flushes"] is not None and counter["observed_failed_flushes"] == 0
                 and len(calls) == counter["native_flushes"] and len(wal) == 3 and len(application) == 9
                 and not unknown and all(v["wal_syncs"] == 1 for v in vector["per_phase"].values()))
    report["native_status"] = "PASS" if qualified else "NO-RESULT"
    if not qualified:
        report["reason"] = "reference vector or complete attribution missing; preserve raw trace and investigate"
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--measure", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--agent-checkout", type=Path)
    args = parser.parse_args()
    if args.measure:
        measure(args.measure)
        return 0
    if args.output is None or args.agent_checkout is None:
        parser.error("capture requires --output and --agent-checkout")
    report = capture(args.output.resolve(), args.agent_checkout.resolve())
    (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["native_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
