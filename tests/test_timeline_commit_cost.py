"""A commit and a history read cost the same however long the history is.

CAS objects are immutable, so each is hashed once per process while its file
identity (inode, size, mtime, ctime) is unchanged.  Later confirms are one
stat.  Trust survives memo clears, refusals and unrelated database writes,
and any change to the file is hashed again and refused.  Everything below
counts operations; none of it reads a clock.
"""
from __future__ import annotations

import copy
import logging
import os
import sqlite3
from collections import Counter
from contextlib import closing

import pytest
import test_timeline_commit_integration as real
from test_timeline_commit_authentication import candidate
from test_timeline_commit_port import PreparedProvider
from test_timeline_history_read_cost import _body

from runtime_protocol import cas as cas_module
from runtime_protocol.errors import HeadBusyError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit_port import route_path
from runtime_protocol.timeline_commit_validation import validate_commit_value

ContentAddressedStore = cas_module.ContentAddressedStore


class Counts:
    def __init__(self, monkeypatch):
        self.hashes, self.opens, self.stats = Counter(), Counter(), Counter()
        digest, opened, identity = cas_module._digest_bytes, ContentAddressedStore.open, ContentAddressedStore.current_identity

        def hashed(data):
            value = digest(data)
            self.hashes[value] += 1
            return value

        def open_(store, name):
            self.opens[name] += 1
            return opened(store, name)

        def stat_(store, name):
            self.stats[name] += 1
            return identity(store, name)

        monkeypatch.setattr(cas_module, "_digest_bytes", hashed)
        monkeypatch.setattr(ContentAddressedStore, "open", open_)
        monkeypatch.setattr(ContentAddressedStore, "current_identity", stat_)

    def snapshot(self):
        return Counter(self.hashes), Counter(self.opens), Counter(self.stats)

    def since(self, snapshot):
        return tuple(sum((now - before).values()) for now, before in zip(self.snapshot(), snapshot))


film = real.film


class Film:
    """A service over a captured film, committing one note at a time."""

    def __init__(self, root, fixture):
        self.service = RuntimeService(root)
        self.project, self.timeline = fixture.project_id, fixture.timeline_id
        self.next, self.before = 0, {"state": "absent"}

        def execute(context, port):
            value = candidate(context, port)
            validate_commit_value(value, "PreparedCommit")
            return port.accept(value)

        self.service.register_timeline_commit_provider(PreparedProvider(execute))

    def edit(self, *, key=None, base=None):
        body, change = _body(self.service, self.project, self.timeline, f"note {self.next}", self.before)
        if base is not None:
            body["base_revision_id"] = base
        result = self.service.commit_timeline(
            self.project, self.timeline, body, idempotency_key=key or f"cost-{self.next}",
            publisher="commit-cost", invocation_path=route_path(self.project, self.timeline),
            authorize=lambda: None)
        self.next += 1
        self.before = {"state": "present", "value": copy.deepcopy(change["value"])}
        return result

    def read(self):
        return self.service.list_timeline_commits(self.project, self.timeline, limit=200, authorize=lambda: None)

    def grow(self, count):
        for _ in range(count):
            self.edit()


def per_commit_cost(root, fixture, monkeypatch, entries):
    counts = Counts(monkeypatch)
    subject = Film(root, fixture)
    try:
        subject.grow(entries)
        # Warm: one commit and one read pay the first verification of new objects.
        subject.edit()
        subject.read()
        mark = counts.snapshot()
        subject.edit()
        commit_cost = counts.since(mark)
        mark = counts.snapshot()
        subject.read()
        return commit_cost, counts.since(mark), counts
    finally:
        subject.service.close()


def test_commit_and_history_read_cost_does_not_grow_with_history(film, monkeypatch):
    few = per_commit_cost(film.fixture.source_root, film.fixture, monkeypatch, 3)
    many = per_commit_cost(film.fixture.duplicate_root, film.fixture, monkeypatch, 30)
    for (hashes_few, opens_few, stats_few), (hashes_many, opens_many, stats_many) in zip(few[:2], many[:2]):
        assert hashes_many == hashes_few
        assert opens_many == opens_few
        assert stats_many == stats_few
    # A warm commit confirms the film's media by stat alone: no open, no hash.
    assert many[0][:2] == (0, 0) and many[0][2] > 0
    # A warm history read hashes and opens nothing; every confirm is a stat.
    assert many[1][:2] == (0, 0) and many[1][2] > 0


@pytest.fixture
def warm(film, monkeypatch):
    counts = Counts(monkeypatch)
    subject = Film(film.fixture.duplicate_root, film.fixture)
    try:
        subject.grow(3)
        subject.read()
        assert counts.hashes, "the first verification of the film's objects must hash them"
        yield subject, counts
    finally:
        subject.service.close()


def rehashed_since(counts, before):
    return sorted(digest for digest, number in counts.hashes.items() if before.get(digest) and number > before[digest])


def test_trust_survives_a_refused_commit_and_an_unrelated_database_write(warm):
    subject, counts = warm
    service = subject.service
    subject.edit()
    subject.read()  # every object the next commits consult is now hashed
    before = Counter(counts.hashes)
    commits, _ = service._timeline_commits()

    mark = counts.snapshot()
    with pytest.raises(RuntimeErrorBase):
        subject.edit(base="not-the-head")
    commits.clear_replay_memo()
    subject.edit()
    assert rehashed_since(counts, before) == []
    assert counts.since(mark)[:2] == (0, 0), "no object is opened or read after a refusal"

    before = Counter(counts.hashes)
    mark = counts.snapshot()
    service.store.conn.execute("UPDATE timelines SET name=COALESCE(name, '') || ' x'")
    service.store.conn.commit()
    with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as other:
        other.execute("UPDATE timelines SET name=COALESCE(name, '') || ' y'")
    subject.edit()
    subject.read()
    assert rehashed_since(counts, before) == []
    assert counts.since(mark)[:2] == (0, 0), "no object is opened or read after a database write"


def an_old_object(service):
    commits, _ = service._timeline_commits()
    object_id = next(iter(commits._history_state["objects"]))
    return object_id, service.store.cas_root / object_id[:2] / object_id[2:]


def tamper_in_place(path, restore_mtime):
    seen = os.stat(path)
    os.chmod(path, 0o600)
    with open(path, "r+b") as stream:
        data = stream.read()
        stream.seek(0)
        stream.write(bytes([data[0] ^ 1]) + data[1:])  # same size, different bytes
    if restore_mtime:
        os.utime(path, ns=(seen.st_atime_ns, seen.st_mtime_ns))
        assert os.stat(path).st_mtime_ns == seen.st_mtime_ns
    assert os.stat(path).st_size == seen.st_size


def tamper_by_replacing(path, restore_mtime):
    seen = os.stat(path)
    data = path.read_bytes()
    replacement = path.with_name(path.name + ".new")
    replacement.write_bytes(bytes([data[0] ^ 1]) + data[1:])
    if restore_mtime:
        os.utime(replacement, ns=(seen.st_atime_ns, seen.st_mtime_ns))
    os.replace(replacement, path)
    assert os.stat(path).st_ino != seen.st_ino


@pytest.mark.parametrize("tamper", [
    pytest.param(lambda path: tamper_in_place(path, False), id="same-size-rewrite"),
    pytest.param(lambda path: tamper_by_replacing(path, False), id="replaced-file-new-inode"),
    pytest.param(lambda path: tamper_in_place(path, True), id="rewrite-with-restored-mtime"),
    pytest.param(lambda path: tamper_by_replacing(path, True), id="replaced-file-restored-mtime"),
])
def test_changed_object_is_rehashed_and_refused(warm, tamper):
    subject, counts = warm
    object_id, path = an_old_object(subject.service)
    assert object_id in subject.service.store.verified_cas
    mark = sum(counts.hashes.values())
    tamper(path)
    with pytest.raises(RuntimeErrorBase):
        subject.read()
    assert sum(counts.hashes.values()) > mark
    with pytest.raises(RuntimeErrorBase):
        subject.edit()


def test_inputs_changed_during_verification_is_the_retryable_head_busy(warm, caplog):
    subject, _ = warm
    service = subject.service
    commits, _ = service._timeline_commits()
    original = commits._verify_accepted

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        with closing(sqlite3.connect(service.store.db_path, isolation_level=None)) as connection:
            connection.execute("UPDATE timelines SET name=COALESCE(name, '') || ' changed'")
        return result

    commits._verify_accepted = changed
    caplog.set_level(logging.WARNING)
    commits.clear_replay_memo()
    with pytest.raises(HeadBusyError) as caught:
        subject.read()
    error = caught.value
    assert (error.status, error.code) == (409, "conflict")
    assert error.details["status"] == "refused" and error.details["reason"] == "head_busy"
    assert error.message == "accepted commit inputs changed during verification"
    assert any("moved" in record.getMessage() and "files" in record.getMessage() for record in caplog.records)
