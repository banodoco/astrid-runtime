"""Lane-only cross-checkout proof for SV-L5; no hosted CI or pins.

Run from the candidate checkout with the existing Runtime test environment:
  python tests/prove_history_guard_rollback.py --previous /path/to/previous --previous /path/to/release14

The previous sources are read-only worktrees. Only temporary realm copies are
opened. Report the exact previous commits, doctor results and restored rows.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runtime_protocol.backup import create_backup, restore_backup  # noqa: E402
from runtime_protocol.history_guards import (  # noqa: E402
    history_guard_manifest, prepare_history_guard_rollback,
)
from runtime_protocol.service import RuntimeService  # noqa: E402
from runtime_protocol.store import RealmStore  # noqa: E402
from runtime_protocol.v33_manifest import canonical_manifest  # noqa: E402
from test_timeline_commit_port import PreparedProvider, commit, request  # noqa: E402

EXPECTED_PREVIOUS = {
    "789d3e2c97cecb10aad1d2914167e999bdbce5fe",
    "24e2c9291d5bcaface78324696286f2dc896debc",
    "5120462d67479dc4719406d0d34440edb616ace1",
}
ROWS = "SELECT * FROM timeline_commit_history ORDER BY publication_id"
KEY = b"SV-L5 lane rollback synthetic proof key" * 2


def git_head(root):
    return subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()


def prior_observation(previous, realm, *, open_owner=False):
    code = r"""
import json
from pathlib import Path
import sys
import runtime_protocol.store as module

root = Path(sys.argv[1])
report = module.RealmStore.inspect_realm(root, timeout_seconds=120, deep=True)
result = {"module": module.__file__, "schema_version": module.SCHEMA_VERSION,
          "doctor": report}
if sys.argv[2] == "open":
    with module.RealmStore(root, admission_timeout=120) as store:
        result["rows"] = [list(row) for row in store.conn.execute(
            "SELECT * FROM timeline_commit_history ORDER BY publication_id")]
        result["opened"] = True
print(json.dumps(result, sort_keys=True))
"""
    env = {**os.environ, "PYTHONPATH": str(previous)}
    process = subprocess.run(
        [sys.executable, "-c", code, str(realm), "open" if open_owner else "inspect"],
        cwd=previous, env=env, text=True, capture_output=True, check=True, timeout=300,
    )
    result = json.loads(process.stdout.splitlines()[-1])
    if not Path(result["module"]).resolve().is_relative_to(previous):
        raise AssertionError("previous proof imported the wrong Runtime source")
    return result


def sqlite_rows(root):
    with closing(sqlite3.connect(root / "realm.sqlite3")) as connection:
        return [list(row) for row in connection.execute(ROWS)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous", type=Path, action="append", required=True)
    args = parser.parse_args()
    previous = [(path.resolve(), git_head(path.resolve())) for path in args.previous]
    if any(sha not in EXPECTED_PREVIOUS for _, sha in previous):
        raise AssertionError(f"unexpected previous Runtime revision: {previous}")
    if not any(sha == "5120462d67479dc4719406d0d34440edb616ace1" for _, sha in previous):
        raise AssertionError("published Release 14 Runtime worktree missing")
    if not any(sha in EXPECTED_PREVIOUS - {"5120462d67479dc4719406d0d34440edb616ace1"} for _, sha in previous):
        raise AssertionError("pre-change Release 15 Runtime worktree missing")

    with tempfile.TemporaryDirectory(prefix="sv-l5-rollback-") as directory:
        work = Path(directory)
        root = work / "guarded"
        RealmStore.initialize(root, realm_id="sv-l5-rollback").close()
        service = RuntimeService(root)
        try:
            service.test_provider = PreparedProvider()
            service.register_timeline_commit_provider(service.test_provider)
            service.test_project = service.create_project({"slug": "rollback", "name": "Rollback"})["id"]
            service.create_timeline(service.test_project, "main", idempotency_key="create-main")
            commit(service, request(service), key="rollback-recorded")
            manifest = canonical_manifest(service.store.conn)
            layer = history_guard_manifest(service.store.conn)
            rows = [list(row) for row in service.store.conn.execute(ROWS)]
            assert manifest["version"] == 33 and layer["version"] == 1 and len(rows) >= 2
            assert service.store.integrity_report()["ok"]
            backup = work / "backup"
            create_backup(service.store, backup, key=KEY)
            assert history_guard_manifest(service.store.conn) == layer
        finally:
            service.close()

        observations = []
        for index, (source, sha) in enumerate(previous):
            # This uses the real previous Runtime's read-only detached doctor,
            # not an inferred result from comparing source strings.
            old = prior_observation(source, root)
            print(json.dumps({"previous_sha": sha, "guarded_realm": old}, sort_keys=True), flush=True)
            if not old["doctor"]["ok"]:
                assert old["doctor"]["issues"] == ["schema"], old
                assert not old["doctor"]["checks"]["schema"]["ok"], old
            assert sqlite_rows(root) == rows

            restored = work / f"restored-{index}"
            restore_backup(backup, restored, key=KEY)
            restored_report = prior_observation(source, restored, open_owner=True)
            assert restored_report["doctor"]["ok"] and restored_report["opened"], restored_report
            assert restored_report["rows"] == rows

            raw = work / f"raw-{index}"
            shutil.copytree(root, raw)
            confirmation = "REMOVE HISTORY GUARDS sv-l5-rollback"
            first = prepare_history_guard_rollback(raw, confirmation=confirmation)
            second = prepare_history_guard_rollback(raw, confirmation=confirmation)
            assert first["changed"] and not second["changed"] and first["fingerprint"] == manifest["fingerprint"]
            raw_report = prior_observation(source, raw, open_owner=True)
            assert raw_report["doctor"]["ok"] and raw_report["opened"] and raw_report["rows"] == rows
            observations.append({"previous_sha": sha, "guarded_issues": old["doctor"]["issues"],
                                 "guarded_open_readonly_ok": old["doctor"]["ok"],
                                 "rollback_backup_opened": True, "raw_removal_opened": True,
                                 "rows_identical": True, "removal": [first, second]})
        print(json.dumps({"candidate": git_head(ROOT), "manifest": manifest, "layer": layer,
                          "accepted_rows": len(rows), "previous": observations}, sort_keys=True))


if __name__ == "__main__":
    main()
