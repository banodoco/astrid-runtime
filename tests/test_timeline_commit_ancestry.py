"""A verified history survives unrelated writes, so an import never forces a re-walk.

Accepted history is immutable and each proof is valid for the SQL results and
CAS bytes it consumed.  After another committed write by this Runtime the proofs
are kept when no other process wrote and every retained SQL result still reads
back identically.  Counts and events only; no clocks.
"""
from __future__ import annotations

import threading

import pytest
from test_timeline_commit_authentication import candidate
from test_timeline_commit_cost import Film, film  # noqa: F401  (fixture)

from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.timeline_commit_validation import validate_commit_value


def statements(subject):
    log = []
    subject.service.store.conn.set_trace_callback(log.append)
    return log


def head_reads(subject, commits, head):
    commits.revision_closure(subject.project, subject.timeline, head["revision_id"])
    commits.history_entry(subject.project, subject.timeline, head["publication_id"])


def head_of(subject):
    value = subject.service.get_project_timeline(subject.project, subject.timeline)
    return {"revision_id": value["head_revision_id"], "publication_id": value["head_publication_id"]}


def unrelated_write(service, slug):
    return service.create_project({"slug": slug, "name": slug}, idempotency_key=f"project-{slug}")


def cost_after_unrelated_write(film, root, entries):
    subject = Film(root, film.fixture)
    try:
        subject.grow(entries)
        commits, _ = subject.service._timeline_commits()
        head = head_of(subject)
        log = statements(subject)
        head_reads(subject, commits, head)
        log.clear()
        head_reads(subject, commits, head)
        subject.edit()  # a later accepted commit moves rows the earlier reads consumed
        head = head_of(subject)
        head_reads(subject, commits, head)
        log.clear()
        head_reads(subject, commits, head)
        warm = len(log)
        unrelated_write(subject.service, "other")
        log.clear()
        head_reads(subject, commits, head)
        return warm, len(log)
    finally:
        subject.service.close()


def test_head_verification_after_an_unrelated_write_costs_the_same_at_3_and_30_entries(film):
    few = cost_after_unrelated_write(film, film.fixture.source_root, 3)
    many = cost_after_unrelated_write(film, film.fixture.duplicate_root, 30)
    assert few == many
    warm, after = many
    assert after == warm, "an unrelated write must not force the history to be verified again"


def test_a_write_in_the_same_project_keeps_the_retained_history(film):
    subject = Film(film.fixture.duplicate_root, film.fixture)
    try:
        subject.grow(3)
        commits, _ = subject.service._timeline_commits()
        head = head_of(subject)
        log = statements(subject)
        head_reads(subject, commits, head)
        log.clear()
        head_reads(subject, commits, head)
        warm = len(log)
        store = subject.service.store
        with store._mutex, store._transaction():  # what an import does to the project's sequence
            store.conn.execute("UPDATE project_sequences SET next_seq=next_seq+1 WHERE project_id=?", (subject.project,))
        log.clear()
        head_reads(subject, commits, head)
        assert len(log) == warm
    finally:
        subject.service.close()


def test_a_write_to_a_row_a_proof_consumed_discards_the_retained_history(film):
    subject = Film(film.fixture.duplicate_root, film.fixture)
    try:
        subject.grow(3)
        commits, _ = subject.service._timeline_commits()
        head = head_of(subject)
        log = statements(subject)
        head_reads(subject, commits, head)
        log.clear()
        head_reads(subject, commits, head)
        warm = len(log)
        with subject.service.store._mutex, subject.service.store._transaction():
            subject.service.store.conn.execute(
                "UPDATE timeline_commit_history SET compiler_version=COALESCE(compiler_version, '') || 'x' "
                "WHERE publication_id=?", (head["publication_id"],))
        log.clear()
        try:
            head_reads(subject, commits, head)
        except RuntimeErrorBase:
            pass
        assert len(log) > warm, "a changed accepted row must be read and verified again"
    finally:
        subject.service.close()


def test_an_external_writer_discards_the_retained_history(film):
    import sqlite3
    from contextlib import closing

    subject = Film(film.fixture.duplicate_root, film.fixture)
    try:
        subject.grow(3)
        commits, _ = subject.service._timeline_commits()
        head = head_of(subject)
        log = statements(subject)
        head_reads(subject, commits, head)
        log.clear()
        head_reads(subject, commits, head)
        warm = len(log)
        with closing(sqlite3.connect(subject.service.store.db_path, isolation_level=None)) as other:
            other.execute("UPDATE timelines SET name=COALESCE(name, '') || ' e'")
        unrelated_write(subject.service, "after-external")
        log.clear()
        head_reads(subject, commits, head)
        assert len(log) > warm
    finally:
        subject.service.close()


def test_an_import_completes_while_a_commit_is_validating_and_does_not_force_a_rewalk(film):
    subject = Film(film.fixture.duplicate_root, film.fixture)
    try:
        subject.grow(3)
        commits, _ = subject.service._timeline_commits()
        previous = head_of(subject)
        log = statements(subject)
        observed = {}

        def execute(context, port):
            port.revision_closure(previous["revision_id"])  # validation phase: the walk
            log.clear()
            port.revision_closure(previous["revision_id"])
            observed["warm"] = len(log)
            write = threading.Thread(target=unrelated_write, args=(subject.service, "during-commit"))
            write.start()
            write.join()  # returns only if the write needs no mutex the commit still holds
            assert not write.is_alive()
            log.clear()
            port.revision_closure(previous["revision_id"])
            observed["after"] = len(log)
            value = candidate(context, port)
            validate_commit_value(value, "PreparedCommit")
            return port.accept(value)

        subject.provider.action = execute
        subject.edit()
        assert observed["after"] == observed["warm"]
    finally:
        subject.service.close()
