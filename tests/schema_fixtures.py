from __future__ import annotations

import sqlite3


def walk_back_to_v30(connection: sqlite3.Connection) -> None:
    """Return a current-schema database to the authentic v30 layout."""
    # DESIGN rev 3 §8 (migration): pin the historical inventory before rewinding.
    from custody_schema_fixtures import to_u33
    to_u33(connection)
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.execute("ALTER TABLE parent_composition_heads DROP COLUMN publication_id")
    connection.execute("ALTER TABLE parent_composition_revisions DROP COLUMN commit_manifest_json")
    for table in (
        "timeline_commit_history",
        "timeline_document_input_links",
        "timeline_document_input_bindings",
        "timeline_document_input_contents",
    ):
        connection.execute(f"DROP TABLE {table}")
    connection.execute("UPDATE runtime_schema SET version=30 WHERE id=1")

