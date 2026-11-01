"""Restore the historical two-project setup without retired timeline writers.

Captured from Runtime 9f9b25c using the existing film fixture and the real
two-project acceptance case prefix, before Agent/rendering tripwires or edits.
Both projects' media, bindings, publications and receipts came from M1 APIs;
the schema-31 archive is an authenticated Runtime backup, with no row rewrites.
"""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

from runtime_protocol.backup import restore_backup, verify_backup
from runtime_protocol.service import RuntimeService


ARCHIVE = Path(__file__).with_name("fixtures") / "precut-two-projects-v31.tar.gz"
# Public test-only key, shared with the historical pre-cut fixture captures.
FIXTURE_BACKUP_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "ffeeddccbbaa99887766554433221100"
)


def _extract_archive(destination: Path, archive_path: Path = ARCHIVE) -> Path:
    destination.mkdir()
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        expected = {"backup/manifest.json", "backup/cas-manifest.json", "backup/realm.sqlite3"}
        names = {member.name.rstrip("/") for member in members}
        if not expected.issubset(names) or any(
            member.name != member.name.lstrip("/")
            or ".." in Path(member.name).parts
            or member.issym()
            or member.islnk()
            or not (member.isdir() or member.isfile())
            for member in members
        ):
            raise AssertionError("pre-cut fixture archive has an unsafe or incomplete layout")
        # Validate every member before extracting.  Use the data filter where
        # available, while retaining Python 3.11 compatibility.
        if sys.version_info >= (3, 12):
            for member in members:
                archive.extract(member, destination, filter="data")
        else:
            for member in members:
                archive.extract(member, destination)
    return destination / "backup"


def load_project_isolation_fixture(tmp_path: Path) -> SimpleNamespace:
    """Restore only this capture and read its real identities and receipts."""
    backup = _extract_archive(tmp_path / "two-project-archive")
    verified = verify_backup(backup, key=FIXTURE_BACKUP_KEY)
    assert verified["manifest"]["schema"]["version"] == 31
    root = tmp_path / "two-project-realm"
    restore_backup(backup, root, key=FIXTURE_BACKUP_KEY)
    service = RuntimeService(root)
    try:
        projects = {row["slug"]: row["project_id"] for row in service.list_projects()["items"]}
        assert set(projects) == {"synthetic-film", "isolated-film"}
        films = []
        for slug, key in (("synthetic-film", "film-two-clip-publication"),
                          ("isolated-film", "isolated-publication")):
            project = projects[slug]
            timeline, = service.list_timelines(project)["items"]
            timeline_id = timeline["timeline_id"]
            receipt = service.committed_receipt(
                "parent_composition.publish", timeline_id, key, project_id=project,
            )
            assert receipt["result"]["new_head"] == timeline["head_revision_id"]
            films.append(SimpleNamespace(
                fixture=SimpleNamespace(duplicate_root=root, project_id=project, timeline_id=timeline_id),
                publication={"data": receipt["result"], "receipt": receipt},
            ))
        film, isolated = films
        last_event = max(int(event) for event in film.publication["receipt"]["event_ids"])
        film.original_events = [tuple(row) for row in service.store.conn.execute(
            "SELECT * FROM timeline_events WHERE id<=? ORDER BY id", (last_event,),
        )]
        film.isolated = isolated
        return film
    finally:
        service.close()
