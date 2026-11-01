"""Two-publication history captured from M1 Runtime 9f9b25c000485e919f30f1411831fe2d5a3c1316.

Capture ran Python -B against /home/user/work/runtime, without changing it.
tests/test_shot_composition_runtime.py::_service created the project/timeline;
_publication supplied parent-1, shot-rev-1 and timeline-rev-1. A second
_publication used expected_head=parent-1, parent_revision_id=parent-2 and empty
shot/internal revision lists. Keys were history-publish-1 / history-publish-2.
Normal create_backup used FIXTURE_BACKUP_KEY; no rows, IDs, clocks, receipts or
payloads were rewritten. In particular, API normalization and the initial
internal timeline revision remain intact. There is no extra parent bootstrap.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from runtime_protocol.backup import restore_backup, verify_backup
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline

from precut_realm_fixture import FIXTURE_BACKUP_KEY, _extract_archive

ARCHIVE = Path(__file__).with_name("fixtures") / "precut-restore-history-v31.tar.gz"


@dataclass(frozen=True)
class RestoreHistoryFixture:
    root: Path
    project_id: str
    first: dict
    head: dict


def load_restore_history_fixture(tmp_path: Path) -> RestoreHistoryFixture:
    """Return an inactive restored root, project, first receipt/result and head.

    The first envelope comes from verified stored publication facts, with the
    original normalized result; neither publication is replayed or synthesized.
    Provider registration is left to the caller's normal startup path.
    """
    backup = _extract_archive(tmp_path / "restore-history-archive", ARCHIVE)
    verified = verify_backup(backup, key=FIXTURE_BACKUP_KEY)
    if verified["manifest"]["schema"]["version"] != 31:
        raise AssertionError("restore history fixture is not schema 31")
    root = tmp_path / "restore-history-realm"
    restore_backup(backup, root, key=FIXTURE_BACKUP_KEY)
    service = RuntimeService(root)
    try:
        project_id = service.get_project("composition")["id"]
        facts = verify_baseline(service.store.conn, project_id, "main", read_object=service.cas.read)
        if [entry["revision_id"] for entry in facts["entries"]] != ["parent-1", "parent-2"]:
            raise AssertionError("restore history fixture must have exactly two publications")
        receipt = facts["entries"][0]["receipt"]
        return RestoreHistoryFixture(root, project_id,
                                     {"data": receipt["result"], "receipt": receipt}, facts["head"])
    finally:
        service.close()
