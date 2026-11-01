"""Structural observations only; these do not exercise the upgrader."""
import sqlite3

import pytest

from runtime_protocol.canonical_schema import CANONICAL_SCHEMA_SQL
from runtime_protocol.errors import ValidationError
from runtime_protocol.v33_manifest import canonical_manifest, legacy_manifest


def database(family):
    connection = sqlite3.connect(":memory:")
    connection.executescript(CANONICAL_SCHEMA_SQL)
    base = family.removesuffix("-nullable")
    version = int(base[1:] if base.startswith("C") else {"H31": 31, "M32": 32, "TL32": 32, "U33": 33}[base])
    if base not in ("M32", "U33"):
        connection.execute("DROP INDEX idx_generations_gen")
    if base.startswith("C") or base == "M32":
        for table in ("timeline_document_input_links", "timeline_document_input_bindings", "timeline_document_input_contents", "timeline_commit_history"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("ALTER TABLE parent_composition_heads DROP COLUMN publication_id")
        connection.execute("ALTER TABLE parent_composition_revisions DROP COLUMN commit_manifest_json")
    if base == "H31" or version < 31:
        connection.execute("DROP TABLE user_app_state")
    if version < 30:
        connection.execute("ALTER TABLE timelines DROP COLUMN name")
    if version < 28:
        connection.execute("DROP INDEX idx_tasks_retention")
        for table in ("runs", "tasks"):
            suffix = "" if family.endswith("-nullable") else " NOT NULL"
            connection.execute(f"ALTER TABLE {table} ADD COLUMN spec_json TEXT{suffix}")
            connection.execute(f"ALTER TABLE {table} DROP COLUMN spec_digest")
        connection.execute("DROP TABLE task_specs")
    if version < 27:
        connection.execute("DROP TABLE user_preferences")
    if version < 26:
        connection.execute("DROP TABLE execution_bindings")
        connection.execute("ALTER TABLE tasks DROP COLUMN execution_request_json")
    if version < 25:
        for column in ("thumbnail_object_id", "thumbnail_source_object_id", "thumbnail_recipe_version", "viewed_at"):
            connection.execute(f"ALTER TABLE generation_variants DROP COLUMN {column}")
    connection.execute("INSERT INTO runtime_schema VALUES (1, 'astrid-runtime-sqlite-v1', ?, 't')", (version,))
    connection.execute("INSERT INTO realm VALUES ('r', 'realm', 't', 't')")
    return connection


@pytest.mark.parametrize("family", [
    "C24", "C24-nullable", "C25", "C25-nullable", "C26", "C26-nullable",
    "C27", "C27-nullable", "C28", "C29", "C30", "C31", "H31", "M32", "TL32", "U33",
])
def test_canonical_fingerprints(family):
    connection = database(family)
    assert canonical_manifest(connection, expected_realm_id="r")["kind"] == family


@pytest.mark.parametrize("mutation", [
    "UPDATE runtime_schema SET version=31",  # unnumbered U33 union
    "UPDATE runtime_schema SET version=32",
    "DROP INDEX idx_generations_gen",
    "CREATE INDEX extra_index ON generations(id)",
    "CREATE TABLE sqliteXhidden (id INTEGER)",
    "CREATE VIEW extra_view AS SELECT id FROM generations",
    "CREATE TRIGGER extra_trigger AFTER INSERT ON realm BEGIN SELECT 1; END",
])
def test_hybrids_and_extra_objects_are_rejected(mutation):
    connection = database("U33")
    connection.execute(mutation)
    with pytest.raises(ValidationError):
        canonical_manifest(connection)


def test_rejects_mismatched_realm():
    with pytest.raises(ValidationError, match="realm identity mismatch"):
        canonical_manifest(database("C31"), expected_realm_id="other")


@pytest.mark.parametrize("archive_name", ["precut-v31.tar.gz", "precut-baseline-v31.tar.xz"])
def test_timeline_archive_structural_identity(archive_name):
    # The backup images are checkpointed; change only the detached in-memory
    # copy's journal flags, as in the approved design's extraction recipe.
    import tarfile
    from pathlib import Path

    with tarfile.open(Path(__file__).parent / "fixtures" / archive_name) as archive:
        image = bytearray(archive.extractfile("backup/realm.sqlite3").read())
    image[18:20] = b"\x01\x01"
    connection = sqlite3.connect(":memory:")
    connection.deserialize(image)
    assert canonical_manifest(connection)["kind"] == "H31"


_REVISION_TABLES = (
    "internal_timeline_revisions", "shot_revisions", "parent_composition_revisions",
    "shot_revision_heads", "parent_composition_heads", "composition_revision_occurrences",
    "composition_revision_dependencies",
)


def legacy_database(nullable=False, components=()):
    connection = database("C27-nullable" if nullable else "C27")
    for table in (*_REVISION_TABLES, "runtime_schema", "managed_output_associations", "managed_output_lifecycle", "user_preferences"):
        connection.execute(f"DROP TABLE {table}")
    connection.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    connection.execute("INSERT INTO schema_migrations VALUES (23, 't')")
    source = database("C31")
    for table in components:
        rows = source.execute("SELECT sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type DESC", (table,)).fetchall()
        for row in rows:
            connection.execute(row[0])
    return connection


@pytest.mark.parametrize("nullable", [False, True])
@pytest.mark.parametrize("components", [(), ("user_preferences",), ("user_app_state", "task_specs"), _REVISION_TABLES])
def test_legacy_base_and_optional_components(nullable, components):
    result = legacy_manifest(legacy_database(nullable, components), expected_realm_id="r")
    assert result["kind"] == ("L23-nullable" if nullable else "L23")
    assert set(result["components"]) == set(components)


def test_legacy_archival_variants_and_unknown_index():
    connection = legacy_database()
    connection.execute("CREATE TABLE lost_and_found(id INTEGER PRIMARY KEY, payload BLOB)")
    assert legacy_manifest(connection)["components"] == ["lost_and_found-fixture"]
    connection.execute("CREATE INDEX extra_archive_index ON lost_and_found(payload)")
    with pytest.raises(ValidationError):
        legacy_manifest(connection)


def test_legacy_rejects_newer_migration_identity():
    connection = legacy_database()
    connection.execute("INSERT INTO schema_migrations VALUES (24, 't')")
    with pytest.raises(ValidationError, match="migration identity"):
        legacy_manifest(connection)


@pytest.mark.parametrize("version", [30, 31, 32, 33])
@pytest.mark.parametrize("app_state", [False, True])
@pytest.mark.parametrize("timeline_bundle", [False, True])
@pytest.mark.parametrize("generation_index", [False, True])
def test_canonical_component_matrix(version, app_state, timeline_bundle, generation_index):
    """Only the approved complete A/T/G combinations may classify."""
    connection = database("U33")
    if not app_state:
        connection.execute("DROP TABLE user_app_state")
    if not timeline_bundle:
        for table in ("timeline_document_input_links", "timeline_document_input_bindings", "timeline_document_input_contents", "timeline_commit_history"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("ALTER TABLE parent_composition_heads DROP COLUMN publication_id")
        connection.execute("ALTER TABLE parent_composition_revisions DROP COLUMN commit_manifest_json")
    if not generation_index:
        connection.execute("DROP INDEX idx_generations_gen")
    connection.execute("UPDATE runtime_schema SET version=?", (version,))
    expected = {
        (30, False, False, False): "C30",
        (31, True, False, False): "C31",
        (31, False, True, False): "H31",
        (32, True, False, True): "M32",
        (32, True, True, False): "TL32",
        (33, True, True, True): "U33",
    }.get((version, app_state, timeline_bundle, generation_index))
    if expected:
        assert canonical_manifest(connection)["kind"] == expected
    else:
        with pytest.raises(ValidationError):
            canonical_manifest(connection)


@pytest.mark.parametrize("mutation", [
    "DROP TABLE timeline_document_input_links",
    "DROP INDEX timeline_document_input_links_pin_idx",
    "ALTER TABLE parent_composition_heads DROP COLUMN publication_id",
    "DROP INDEX idx_generations_gen; CREATE INDEX idx_generations_gen ON generations(id)",
])
def test_partial_or_wrong_definition_components_are_rejected(mutation):
    connection = database("U33")
    connection.executescript(mutation)
    with pytest.raises(ValidationError):
        canonical_manifest(connection)
