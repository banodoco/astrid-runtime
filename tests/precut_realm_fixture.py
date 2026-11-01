"""Load the committed schema-31, pre-cut realm backup fixture.

The archive is a real Runtime backup made from the public API-built film
fixture.  This module only extracts it into a caller-owned temporary directory
and uses the Runtime backup/restore implementation; it does not install rows
or synthesize history.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path

from runtime_protocol.backup import restore_backup, verify_backup


ARCHIVE = Path(__file__).with_name("fixtures") / "precut-v31.tar.gz"
VARIANT_ARCHIVES = {
    name: ARCHIVE.with_name(f"precut-{name}-v31.tar.gz")
    for name in ("music-documents", "anchor", "raw")
}
FIXTURE_LABEL = "schema31/pre-cut80973d3"
SCHEMA_VERSION = 31

# This is a public test-only HMAC key for the committed synthetic backup.  It
# is not an operator credential and is deliberately not stored in the archive.
FIXTURE_BACKUP_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "ffeeddccbbaa99887766554433221100"
)


@dataclass(frozen=True)
class PrecutRealmFixture:
    backup_root: Path
    copy_roots: tuple[Path, Path]
    manifest: dict
    pins: dict


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


def _read_pins(backup_root: Path) -> dict:
    database = backup_root / "realm.sqlite3"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        project = connection.execute(
            "SELECT id FROM projects WHERE slug=?", ("synthetic-film",)
        ).fetchone()
        if project is None:
            raise AssertionError("pre-cut fixture project is missing")
        project_id = project["id"]
        timeline = connection.execute(
            "SELECT id FROM timelines WHERE project_id=? AND id=?", (project_id, "film")
        ).fetchone()
        head = connection.execute(
            "SELECT revision_id, publication_id FROM parent_composition_heads "
            "WHERE project_id=? AND timeline_id=?",
            (project_id, "film"),
        ).fetchone()
        transcript = connection.execute(
            "SELECT id FROM project_documents WHERE project_id=? AND kind=?",
            (project_id, "media.transcript"),
        ).fetchone()
        binding = connection.execute(
            "SELECT id, media_digest FROM shot_text_bindings WHERE project_id=?",
            (project_id,),
        ).fetchone()
        reference = connection.execute(
            "SELECT id FROM project_references WHERE project_id=? AND name=?",
            (project_id, "River frame reference"),
        ).fetchone()
        association = connection.execute(
            "SELECT id, media_id FROM media_references WHERE reference_id=?",
            (reference["id"],) if reference else ("",),
        ).fetchone()
        publication = connection.execute(
            "SELECT id, payload_json FROM timeline_events "
            "WHERE timeline_id=? AND kind=? AND json_extract(payload_json, '$.new_head')=?",
            ("film", "parent.composition.published", head["revision_id"] if head else None),
        ).fetchone()
        receipt = connection.execute(
            "SELECT txn_id, event_ids_json FROM command_idempotency "
            "WHERE command_kind=? AND aggregate_id=? "
            "AND ? IN (SELECT value FROM json_each(event_ids_json))",
            ("parent_composition.publish", "film", str(publication["id"]) if publication else None),
        ).fetchone()
        if not all((timeline, head, transcript, binding, reference, association, publication, receipt)):
            raise AssertionError("pre-cut fixture pins are incomplete")
        media = tuple(
            "sha256:" + row["digest"]
            for row in connection.execute(
                "SELECT digest FROM project_objects WHERE project_id=? AND relation='managed' ORDER BY digest",
                (project_id,),
            )
        )
        return {
            "project_id": project_id,
            "timeline_id": timeline["id"],
            "parent_revision_id": head["revision_id"],
            "publication_id": head["publication_id"],
            "transcript_document_id": transcript["id"],
            "text_binding_id": binding["id"],
            "text_binding_media_id": "sha256:" + binding["media_digest"],
            "reference_id": reference["id"],
            "association_id": association["id"],
            "association_media_id": "sha256:" + association["media_id"],
            "media_ids": media,
            "publication_event_id": str(publication["id"]),
            "publication_event_ids": tuple(json.loads(receipt["event_ids_json"])),
            "publication_receipt_id": receipt["txn_id"],
            "publication_payload": json.loads(publication["payload_json"]),
        }
    finally:
        connection.close()


def load_precut_realm_fixture(tmp_path: Path, *, variant: str | None = None) -> PrecutRealmFixture:
    """Extract and restore two independent copies of the committed realm.

    The returned roots are inactive until opened by the caller.  IDs and
    provenance pins are read from the extracted database, not duplicated in
    this helper, so the fixture remains an exact backup/restore exercise.
    Optional variants select only the three committed historical captures.
    """
    if variant is not None and variant not in VARIANT_ARCHIVES:
        raise ValueError(f"unknown pre-cut fixture variant: {variant}")
    archive_path = ARCHIVE if variant is None else VARIANT_ARCHIVES[variant]
    if not archive_path.is_file():
        raise AssertionError(f"missing committed fixture archive: {archive_path}")
    stem = archive_path.name.removesuffix(".tar.gz")
    extracted = tmp_path / f"{stem}-archive"
    backup_root = _extract_archive(extracted, archive_path)
    verified = verify_backup(backup_root, key=FIXTURE_BACKUP_KEY)
    manifest = verified["manifest"]
    if manifest["schema"]["version"] != SCHEMA_VERSION:
        raise AssertionError("pre-cut fixture is not schema 31")
    copy_a = tmp_path / f"{stem}-copy-a"
    copy_b = tmp_path / f"{stem}-copy-b"
    restore_backup(backup_root, copy_a, key=FIXTURE_BACKUP_KEY)
    restore_backup(backup_root, copy_b, key=FIXTURE_BACKUP_KEY)
    return PrecutRealmFixture(
        backup_root=backup_root,
        copy_roots=(copy_a, copy_b),
        manifest=manifest,
        pins=_read_pins(backup_root),
    )


def readonly_tree_digest(root: Path) -> str:
    """Digest the immutable SQLite/CAS bytes without opening a writer."""
    digest = hashlib.sha256()
    for path in sorted((root / "realm.sqlite3", *(root / "cas").rglob("*"))):
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()
