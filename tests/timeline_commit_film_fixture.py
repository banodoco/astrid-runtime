"""Captured main-API historical film used by publication baseline tests.

The genuine pre-cut backup is restored into two independent roots. Tests open
only the duplicate, preserving the captured source and its immutable provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from runtime_protocol.service import RuntimeService
from precut_realm_fixture import load_precut_realm_fixture


@dataclass(frozen=True)
class FilmFixture:
    source_root: Path
    duplicate_root: Path
    project_id: str
    timeline_id: str
    parent_revision_id: str
    media_ids: tuple[str, ...]
    transcript_document_id: str
    text_binding_id: str


def build_film_fixture(tmp_path: Path) -> FilmFixture:
    """Restore the captured main-API historical film and an independent copy.

    This is schema 31 / pre-cut80973d3 data, created before the legacy writers
    retired. The authenticated source backup and immutable times stay intact.
    """
    captured = load_precut_realm_fixture(tmp_path)
    pins = captured.pins
    return FilmFixture(
        source_root=captured.copy_roots[0],
        duplicate_root=captured.copy_roots[1],
        project_id=pins["project_id"],
        timeline_id=pins["timeline_id"],
        parent_revision_id=pins["parent_revision_id"],
        media_ids=pins["media_ids"],
        transcript_document_id=pins["transcript_document_id"],
        text_binding_id=pins["text_binding_id"],
    )


def read_object_from_realm(realm_root: Path, digest: str) -> bytes:
    bare = digest.removeprefix("sha256:")
    return (realm_root / "cas" / "sha256" / bare[:2] / bare[2:]).read_bytes()


def fixture_facts(service: RuntimeService, fixture: FilmFixture) -> dict:
    """Return small API/read facts used by tests and handoff documentation."""
    parent = service.get_project_parent_composition_revision(
        fixture.project_id, fixture.timeline_id, fixture.parent_revision_id
    )
    transcript = service.get_document(fixture.project_id, fixture.transcript_document_id)
    binding = service.get_project_shot_text_binding(fixture.project_id, fixture.text_binding_id)
    return {
        "parent": parent,
        "transcript": transcript,
        "binding": binding,
        "realm_id": service.store.realm["id"],
        "cas_ids": tuple(sorted(fixture.media_ids)),
    }
