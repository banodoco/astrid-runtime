"""Test-only intentional corruption of an otherwise immutable history row."""


def forge_history_row(connection, statement, parameters=()):
    """Temporarily remove only the matching guard; restore it before releasing.

    The nested savepoint works with autocommit or an outer transaction.
    Failure rolls back both the row change and the schema change. Never use
    executescript here: it can commit the caller's transaction.
    """
    operation = statement.lstrip().upper()
    if operation.startswith("UPDATE TIMELINE_COMMIT_HISTORY SET "):
        trigger = "timeline_history_no_update"
    elif operation.startswith("DELETE FROM TIMELINE_COMMIT_HISTORY"):
        trigger = "timeline_history_no_delete"
    else:
        raise ValueError("history forge requires a single history UPDATE or DELETE")
    # A test adapter that routes UPDATEs to a second connection names it here so
    # the guard drop, the UPDATE and the restore all run on that one connection.
    connection = getattr(connection, "forge_target", connection)
    connection.execute("SAVEPOINT forge_history_row")
    try:
        sql = connection.execute(
            "SELECT sql FROM main.sqlite_master WHERE type='trigger' AND name=?", (trigger,)
        ).fetchone()
        if sql is None:
            raise RuntimeError("history guard missing before forge: " + trigger)
        connection.execute(f"DROP TRIGGER main.{trigger}")
        cursor = connection.execute(statement, parameters)
        connection.execute(sql[0])
    except BaseException:
        connection.execute("ROLLBACK TO forge_history_row")
        raise
    finally:
        connection.execute("RELEASE forge_history_row")
    return cursor
