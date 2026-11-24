"""Test-only intentional corruption of an otherwise immutable history row."""


def forge_history_row(connection, statement, parameters=()):
    """Temporarily remove only the UPDATE guard; restore it before releasing.

    The nested savepoint works with autocommit or an outer transaction.
    Failure rolls back both the row change and the schema change. Never use
    executescript here: it can commit the caller's transaction.
    """
    if not statement.lstrip().upper().startswith("UPDATE TIMELINE_COMMIT_HISTORY SET "):
        raise ValueError("history forge requires a single history UPDATE")
    connection.execute("SAVEPOINT forge_history_row")
    try:
        sql = connection.execute(
            "SELECT sql FROM main.sqlite_master WHERE type='trigger' AND name='timeline_history_no_update'"
        ).fetchone()
        if sql is None:
            raise RuntimeError("history UPDATE guard missing before forge")
        connection.execute("DROP TRIGGER main.timeline_history_no_update")
        cursor = connection.execute(statement, parameters)
        connection.execute(sql[0])
    except BaseException:
        connection.execute("ROLLBACK TO forge_history_row")
        raise
    finally:
        connection.execute("RELEASE forge_history_row")
    return cursor
