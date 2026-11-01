"""Clear projection through real Runtime acceptance, not Agent command semantics."""
from __future__ import annotations

import copy
import json

import pytest

from runtime_protocol.errors import ConflictError, NotFoundError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_baseline import _text_bindings
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_acceptance import validate_prepared
from test_timeline_text_selection import (
    ABSENT, KEY, accept, bind, binding, events, present, put, realm, row_for,  # noqa: F401 (realm fixture)
)


def clear(realm, row, n=2):
    return bind(realm, n, [], [(KEY, present(row), ABSENT)])


def assert_absent(service, project):
    with pytest.raises(NotFoundError):
        binding(service, project)
    assert service.list_project_shot_text_bindings(project, shot_id="shot-1")["items"] == []


@pytest.mark.parametrize("data", [b"gone", b""])
def test_first_birth_inverse_and_clear_inverse_keep_append_only_history(realm, data):
    service, commits, project, _, _ = realm
    object_id = put(realm, data)
    row = row_for(object_id, len(data))
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    first_event = dict(service.store.conn.execute("SELECT * FROM shot_text_binding_events").fetchone())
    ctx, value = clear(realm, row)
    result = accept(commits, ctx, value)
    assert_absent(service, project)
    assert service.get_project_shot_revision(project, "shot-1", "shot-1-r2")["payload"]["text_bindings"] == []
    assert commits.revision_closure(project, "main", "parent-2")["shot_revisions"][0]["payload"]["text_bindings"] == []
    before_retry = list(service.store.conn.iterdump())
    assert accept(commits, ctx, value) == result
    assert list(service.store.conn.iterdump()) == before_retry
    assert dict(service.store.conn.execute("SELECT * FROM shot_text_binding_events WHERE seq=1").fetchone()) == first_event
    anchor = service.store.conn.execute("SELECT * FROM shot_text_bindings").fetchone()
    assert (anchor["media_digest"], anchor["head_seq"]) == (object_id[7:], 2)
    payload = json.loads(service.store.conn.execute("SELECT payload_json FROM shot_text_binding_events WHERE seq=2").fetchone()[0])
    assert payload["state"] == "absent"
    assert payload["media_id"] == object_id
    # This is the recorded inverse of clear; Agent's native inverse is qualified separately.
    accept(commits, *bind(realm, 3, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    assert binding(service, project)["head"] == 3
    assert binding(service, project)["byte_size"] == len(data)
    assert commits.revision_closure(project, "main", "parent-3")["shot_revisions"][0]["payload"]["text_bindings"] == [row]
    assert events(service) == [(1, "shot.text_binding.created"), (2, "shot.text_binding.rebound"), (3, "shot.text_binding.rebound")]
    assert service.doctor()["ok"]


def test_clear_and_inverse_preserve_descriptor_order(realm):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"ordered")
    rows = [row_for(object_id, 7, kind="transcript"), row_for(object_id, 7), row_for(object_id, 7, kind="prompt", slot="hero")]
    refs = ["occurrence:occ-1/text-binding:transcript", KEY, "occurrence:occ-1/text-binding:prompt:hero"]
    accept(commits, *bind(realm, 1, rows, [(ref, ABSENT, present(row)) for ref, row in zip(refs, rows)], media=[object_id]))
    accept(commits, *bind(realm, 2, [rows[0], rows[2]], [(KEY, present(rows[1]), ABSENT)], media=[object_id]))
    accept(commits, *bind(realm, 3, rows, [(KEY, ABSENT, present(rows[1]))], media=[object_id]))
    assert service.get_project_shot_revision(project, "shot-1", "shot-1-r3")["payload"]["text_bindings"] == rows
    assert len(service.list_project_shot_text_bindings(project, shot_id="shot-1")["items"]) == 3


def validate_pin(service, project, descriptor):
    shot = {"shot_id": "shot-1", "payload": {"text_bindings": [descriptor]}}
    service._validate_published_text_bindings(project, "shot-1", shot["payload"], require_current=False)
    _text_bindings(service.store.conn, project, shot, lambda bare: service.cas.path_for(bare).read_bytes())


def test_old_pin_survives_clear_restart_and_backup_restore(realm, tmp_path):
    service, commits, project, _, root = realm
    data = "héllo\r\n".encode()
    object_id = put(realm, data)
    row = row_for(object_id, len(data))
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    pin = binding(service, project)
    second_id = put(realm, b"later")
    second = row_for(second_id, 5)
    accept(commits, *bind(realm, 2, [second], [(KEY, present(row), present(second))], media=[second_id]))
    accept(commits, *clear(realm, second, n=3))
    validate_pin(service, project, pin)
    exported = service.export_structured()
    assert len(exported["shot_text_bindings"]) == 1
    assert exported["shot_text_binding_events"][-1]["payload"]["state"] == "absent"
    assert service.store.integrity_report()["checks"]["reachable_cas"]["ok"]
    backup_path = tmp_path / "backup"
    service.backup(backup_path)
    service.restore(backup_path, tmp_path / "restored")
    service.close()
    for path in (root, tmp_path / "restored"):
        reopened = RuntimeService(path)
        try:
            assert_absent(reopened, project)
            validate_pin(reopened, project, pin)
            assert reopened.cas.path_for(object_id[7:]).read_bytes() == data
            assert TimelineCommitStore(reopened.store, validate_prepared=validate_prepared).revision_closure(project, "main", "parent-1")["shot_revisions"][0]["payload"]["text_bindings"] == [row]
            assert reopened.doctor()["ok"]
        finally:
            reopened.close()


@pytest.mark.parametrize("reader", ["service", "baseline"])
def test_absent_head_cannot_be_claimed_as_a_present_pin(realm, reader):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"pin")
    row = row_for(object_id, 3)
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    pin = binding(service, project)
    accept(commits, *clear(realm, row))
    pin["head"] = 2
    pin.pop("updated_at")
    before = list(service.store.conn.iterdump())
    with pytest.raises(ConflictError):
        if reader == "service":
            service._validate_published_text_bindings(project, "shot-1", {"text_bindings": [pin]}, require_current=False)
        else:
            _text_bindings(service.store.conn, project, {"shot_id": "shot-1", "payload": {"text_bindings": [pin]}},
                           lambda bare: service.cas.path_for(bare).read_bytes())
    assert list(service.store.conn.iterdump()) == before


@pytest.mark.parametrize("case", ["absent_before", "wrong_size", "wrong_hash", "wrong_mime", "wrong_kind", "stale_clear"])
def test_clear_checks_exact_before_state_without_writes(realm, case):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"guard")
    row = row_for(object_id, 5)
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    prior = copy.deepcopy(row)
    if case == "stale_clear":
        accept(commits, *clear(realm, row))
    elif case == "wrong_size":
        prior["byte_size"] = 6
    elif case == "wrong_hash":
        prior["content_hash"] = "sha256:" + "0" * 64
    elif case == "wrong_mime":
        prior["mime_type"] = "text/plain"
    elif case == "wrong_kind":
        prior["kind"] = "transcript"
    ctx, value = bind(realm, 3, [], [(KEY, ABSENT if case == "absent_before" else present(prior), ABSENT)])
    before = list(service.store.conn.iterdump())
    with pytest.raises((CommitRejected, RuntimeErrorBase)):
        accept(commits, ctx, value)
    assert list(service.store.conn.iterdump()) == before


def test_clear_state_is_covered_by_the_event_hash(realm):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"hash")
    row = row_for(object_id, 4)
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    accept(commits, *clear(realm, row))
    payload = json.loads(service.store.conn.execute("SELECT payload_json FROM shot_text_binding_events WHERE seq=2").fetchone()[0])
    payload["state"] = "present"
    service.store.conn.execute("UPDATE shot_text_binding_events SET payload_json=? WHERE seq=2", (json.dumps(payload),))
    with pytest.raises(ConflictError):
        binding(service, project)


def test_clear_rolls_back_with_acceptance_and_birth_replay_keeps_absence(realm):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"atomic")
    row = row_for(object_id, 6)
    birth_ctx, birth = bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id])
    first = accept(commits, birth_ctx, birth)
    ctx, value = clear(realm, row)

    class Boom:
        def validate(self, candidate):
            pass

        def persist(self, candidate, publication_id, revision_id):
            assert_absent(service, project)
            raise RuntimeError("after clear projection")

    before = list(service.store.conn.iterdump())
    with pytest.raises(RuntimeError, match="after clear projection"):
        commits.accept(ctx, value, authorize=lambda: None, inputs=Boom())
    assert list(service.store.conn.iterdump()) == before
    assert binding(service, project)["head"] == 1
    accept(commits, ctx, value)
    before = list(service.store.conn.iterdump())
    assert accept(commits, birth_ctx, birth) == first
    assert list(service.store.conn.iterdump()) == before
    assert_absent(service, project)


def test_legacy_present_event_without_state_can_be_cleared(realm):
    from runtime_protocol.timeline_commit_store import digest
    from runtime_protocol.util import canonical_json

    service, commits, project, _, _ = realm
    object_id = put(realm, b"legacy")
    row = row_for(object_id, 6)
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    event = service.store.conn.execute("SELECT * FROM shot_text_binding_events").fetchone()
    payload = json.loads(event["payload_json"])
    payload = {key: payload[key] for key in ("binding_id", "media_id", "content_hash")}
    event_hash = digest({"event_id": event["event_id"], "binding_id": event["binding_id"], "seq": 1,
                         "kind": event["kind"], "payload": payload, "previous_hash": ""})[7:]
    # Emulate the pre-state event format, keeping its actual hash contract.
    service.store.conn.execute("UPDATE shot_text_binding_events SET payload_json=?, event_hash=?",
                               (canonical_json(payload), event_hash))
    pin = binding(service, project)
    assert pin["head"] == 1
    accept(commits, *clear(realm, row))
    assert_absent(service, project)
    validate_pin(service, project, pin)
