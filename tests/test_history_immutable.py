"""SV-L5: accepted timeline publications are append-only in SQLite."""
import sqlite3

import pytest

import test_timeline_commit_authentication as auth
from test_timeline_commit_port import commit

service = auth.service


@pytest.mark.parametrize("statement", [
    "UPDATE timeline_commit_history SET intent=intent WHERE publication_id=?",
    "DELETE FROM timeline_commit_history WHERE publication_id=?",
    "INSERT OR REPLACE INTO timeline_commit_history SELECT * FROM timeline_commit_history WHERE publication_id=?",
])
def test_accepted_publication_is_immutable(service, statement):
    auth.provider(service)
    publication = commit(service, auth.body(service))["receipt"]["receipt_id"]
    connection = service.store.conn
    read = "SELECT * FROM timeline_commit_history WHERE publication_id=?"
    original = tuple(connection.execute(read, (publication,)).fetchone())

    with pytest.raises(sqlite3.IntegrityError, match="accepted timeline history is immutable"):
        connection.execute(statement, (publication,))

    assert tuple(connection.execute(read, (publication,)).fetchone()) == original
