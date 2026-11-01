"""Uncatchable interruptions retain the upgrade's original workspace identity."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys

import pytest

from astrid_runtime import operator_upgrade
from runtime_protocol.store import SCHEMA_VERSION
from runtime_protocol.upgrade import inspect_canonical_schema
from tests.lanes import requires_posix_process_groups
from test_operator_upgrade import _Boundary, _fixture
from tests.schema_fixtures import walk_back_to_v30


@pytest.mark.parametrize("state", [
    "planned", "stopping", "stopped", "migration-committed", "activated", "restarted", "complete",
])
@requires_posix_process_groups
def test_sigkill_keeps_upgrade_transaction_identity_at_every_journal_step(tmp_path, state):
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([
        str(Path(__file__).resolve().parents[1]), os.environ.get("PYTHONPATH", ""),
    ])}
    result = subprocess.run([sys.executable, __file__, str(tmp_path), state],
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == -signal.SIGKILL, result.stderr
    support = tmp_path / "support"
    journal = json.loads((support / "runtime" / "upgrade-journal.json").read_text())
    assert journal["state"] == ("backup_verified" if state == "migration-committed" else state)
    assert len(journal["operation_id"]) == 32
    assert journal["realm_id"] == "realm-1"
    assert journal["source_support_root"] == str(support)
    realm = support / "runtime" / "realms" / "realm-1"
    assert journal["realm_root"] == str(realm)
    assert journal["schema_before"] == "v29"
    expected = 29 if state in {"planned", "stopping", "stopped"} else SCHEMA_VERSION
    assert inspect_canonical_schema(realm)["version"] == expected


def test_journal_refuses_changed_transaction_identity(tmp_path):
    paths, _, realm = _fixture(tmp_path, version=SCHEMA_VERSION)
    operation_id = "a" * 32
    journal = operator_upgrade._journal(
        paths, operation_id=operation_id, state="planned", realm_id="realm-1",
        realm_root=str(realm), source_support_root=str(paths.app_support), schema_before="v30",
    )
    before = journal.read_bytes()
    with pytest.raises(operator_upgrade.OperatorUpgradeError, match="identity changed"):
        operator_upgrade._journal(paths, operation_id=operation_id, state="stopped", realm_id="other")
    assert journal.read_bytes() == before


def test_recovery_required_journal_refuses_new_upgrade_without_mutation(tmp_path):
    from astrid_runtime.bootstrap import BootstrapConfig

    paths, profile, realm = _fixture(tmp_path, version=SCHEMA_VERSION)
    journal = operator_upgrade._journal(
        paths, operation_id="a" * 32, state="recovery_required", realm_id="realm-1",
        realm_root=str(realm), source_support_root=str(paths.app_support), schema_before="U33",
    )
    before_journal = journal.read_bytes()
    before_database = (realm / "realm.sqlite3").read_bytes()
    boundary = _Boundary(paths)
    with pytest.raises(operator_upgrade.OperatorUpgradeError, match="needs recovery"):
        operator_upgrade.upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert journal.read_bytes() == before_journal
    assert (realm / "realm.sqlite3").read_bytes() == before_database
    assert boundary.calls == []


def test_historical_upgrade_refuses_unknown_manifest_before_journal_or_stop(tmp_path):
    from astrid_runtime.bootstrap import BootstrapConfig
    paths, profile, realm = _fixture(tmp_path, version=SCHEMA_VERSION)
    with sqlite3.connect(realm / "realm.sqlite3") as connection:
        connection.execute("CREATE TRIGGER unknown_write AFTER INSERT ON projects BEGIN SELECT 1; END")
    before = (realm / "realm.sqlite3").read_bytes()
    boundary = _Boundary(paths)
    from runtime_protocol.errors import ValidationError
    with pytest.raises(operator_upgrade.OperatorUpgradeError, match="unsupported SQLite schema object"):
        operator_upgrade.upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
    assert (realm / "realm.sqlite3").read_bytes() == before
    assert not (paths.runtime_support / "upgrade-journal.json").exists()
    assert boundary.calls == []


if __name__ == "__main__":
    from types import SimpleNamespace
    from astrid_runtime.bootstrap import BootstrapConfig

    base, kill_state = Path(sys.argv[1]), sys.argv[2]
    paths, profile, realm = _fixture(base, version=SCHEMA_VERSION)
    with sqlite3.connect(realm / "realm.sqlite3") as connection:
        walk_back_to_v30(connection)
        connection.execute("ALTER TABLE timelines DROP COLUMN name")
        connection.execute("DROP TABLE user_app_state")
        connection.execute("DROP INDEX idx_generations_gen")
        connection.execute("UPDATE runtime_schema SET version=29 WHERE id=1")
    boundary = _Boundary(paths)
    original_journal = operator_upgrade._journal
    original_migrate = operator_upgrade.migrate_canonical_to_current

    def journal_and_kill(*args, **kwargs):
        result = original_journal(*args, **kwargs)
        if kwargs["state"] == kill_state:
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    def start(target, *_args):
        from runtime_protocol.service import RuntimeService
        from test_timeline_commit_provider import Provider
        service = RuntimeService(realm)
        service.register_timeline_commit_provider(Provider())
        service.close()
        discovery = {
            "pid": 1235, "active_realm": "realm-1", "endpoint": "http://127.0.0.1:17540",
            "runtime_instance_id": "instance-2", "process_birth_id": "birth-2", "realm_root": str(realm),
        }
        target.discovery_path.write_text(json.dumps(discovery))
        target.instance_lock_path.write_text(json.dumps({**discovery, "realm_id": "realm-1"}))
        return SimpleNamespace(endpoint=discovery["endpoint"], pid=1235, runtime_instance_id="instance-2")

    def migrate_and_kill(*args, **kwargs):
        result = original_migrate(*args, **kwargs)
        if kill_state == "migration-committed":
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    operator_upgrade._journal = journal_and_kill
    operator_upgrade._bootstrap_locked = start
    operator_upgrade.migrate_canonical_to_current = migrate_and_kill
    operator_upgrade.upgrade_workspace(paths, boundary, BootstrapConfig(source_profile=profile))
