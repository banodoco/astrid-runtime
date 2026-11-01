"""Bounded legacy-baseline captures from unchanged M1 Runtime 9f9b25c.

Python -B used /home/user/work/runtime and its test_shot_composition_runtime
public-API builders. Each directory is a normal authenticated create_backup,
with original schema-31 rows, CAS, clocks, IDs and receipt hashes. The bundle
contains single and same-revision selections of _publication, explicit media,
five empty payloads, four opaque locations, the baseline test's synthetic film,
and a publication followed by the original legacy document write. Publication
JSON files preserve the M1 receipt serializer's original envelopes; film-input
preserves the authored request, audio ID and transcript binding. No accepted
history is inserted, rewritten or replayed by this loader.

The two-distinct-revision history capture and its loader are reused unchanged
from tl/rt-m2-restore-history-capture. The single/same-content backups share one
M1 realm, so a caller can observe the exact before/after facts without a writer.
XZ keeps the finite bundle (including repeated SQLite pages) below 100 KB.
"""
from __future__ import annotations

import json
import tarfile
from pathlib import Path

from precut_realm_fixture import FIXTURE_BACKUP_KEY
from restore_history_fixture import load_restore_history_fixture
from runtime_protocol.backup import restore_backup, verify_backup
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_baseline import verify_baseline

ARCHIVE = Path(__file__).with_name("fixtures") / "precut-baseline-v31.tar.xz"
ARCHIVE_VARIANTS = {
    "cutover": Path(__file__).with_name("fixtures") / "precut-cutover-v31.tar.xz",
    "repeat-media": Path(__file__).with_name("fixtures") / "precut-repeat-media-v31.tar.xz",
}
VARIANTS = (
    "single", "same-content", "explicit-media", "legacy-document", "film",
    "empty", "empty-config", "empty-config-app", "empty-registry", "empty-extension",
    "opaque-config", "opaque-parent", "opaque-shot", "opaque-internal", "repeat-media", "cutover",
)


def load_baseline_fixture(tmp_path, variant="single"):
    if variant == "history":
        fixture = load_restore_history_fixture(tmp_path)
        service = RuntimeService(fixture.root)
        facts = verify_baseline(service.store.conn, fixture.project_id, "main", read_object=service.cas.read)
        return service, fixture.project_id, [
            {"data": entry["receipt"]["result"], "receipt": entry["receipt"]}
            for entry in facts["entries"]
        ]
    if variant not in VARIANTS:
        raise ValueError(f"unknown baseline fixture variant: {variant}")
    archive_path = ARCHIVE_VARIANTS.get(variant, ARCHIVE)
    extracted = tmp_path / (
        "baseline-archive" if archive_path == ARCHIVE else f"{archive_path.stem}-archive"
    )
    if not extracted.exists():
        extracted.mkdir()
        with tarfile.open(archive_path, "r:xz") as archive:
            members = archive.getmembers()
            if len(members) > 256 or sum(member.size for member in members) > 32_000_000 or any(
                member.name != member.name.lstrip("/")
                or ".." in Path(member.name).parts
                or not (member.isdir() or member.isfile())
                for member in members
            ):
                raise AssertionError("invalid baseline fixture archive")
            archive.extractall(extracted, members=members, filter="data")
    name = "backup" if variant == "single" else variant
    backup = extracted / name
    verified = verify_backup(backup, key=FIXTURE_BACKUP_KEY)
    if verified["manifest"]["schema"]["version"] != 31:
        raise AssertionError("baseline fixture is not schema 31")
    root = tmp_path / f"baseline-{variant}"
    restore_backup(backup, root, key=FIXTURE_BACKUP_KEY)
    publications = json.loads((extracted / f"{name}-publications.json").read_text())
    service = RuntimeService(root)
    project_selector = "cutover" if variant == "cutover" else "composition"
    return service, service.get_project(project_selector)["id"], publications


def film_inputs(tmp_path):
    return json.loads((tmp_path / "baseline-archive" / "film-input.json").read_text())
