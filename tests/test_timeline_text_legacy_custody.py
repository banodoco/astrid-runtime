"""Authentic main text custody through canonical replacement, clear and inverse."""
from __future__ import annotations

import copy
import json

import pytest

from legacy_text_binding_fixture import LegacyTextWriter
from runtime_protocol.errors import RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_store import TimelineCommitStore
from test_timeline_commit_acceptance import validate_prepared
from test_timeline_text_binding_clear import assert_absent, validate_pin
from test_timeline_text_selection import (
    ABSENT, KEY, accept, bind, binding, port_for, present, put, realm, row_for,  # noqa: F401 (realm fixture)
)


def seed_legacy(realm, data, *, media_type=None):
    service, commits, project, _, _ = realm
    accept(commits, *bind(realm, 1, [], []))
    if media_type is not None:
        put(realm, data, media_type=media_type)
    writer = object.__new__(LegacyTextWriter)
    writer.__dict__.update(service.__dict__)
    pin = writer.set_project_shot_text_binding(project, {
        "shot_id": "shot-1", "kind": "voiceover_script", "text": data, "expected_head": 0,
    }, idempotency_key="original-main-writer")["data"]
    row = {key: pin[key] for key in ("kind", "slot", "media_id", "content_hash", "byte_size", "mime_type")}
    row.update(text=data.decode(), opaque={"null": None, "nested": [False, 0]})
    # Retain the real descriptor without manufacturing a binding write/event.
    accept(commits, *bind(realm, 2, [row], [], media=[row["media_id"]]))
    return row, pin


@pytest.mark.parametrize("data", [b"", "héllo\r\ne\u0301\u2028".encode()])
@pytest.mark.parametrize("edit", ["clear", "replacement"])
def test_legacy_exact_inverse_retains_bytes_events_and_pins_after_restart(realm, data, edit):
    service, commits, project, _, root = realm
    row, pin = seed_legacy(realm, data)
    assert row["mime_type"] == "text/plain"
    original_event = dict(service.store.conn.execute("SELECT * FROM shot_text_binding_events").fetchone())
    assert set(json.loads(original_event["payload_json"])) == {"binding_id", "media_id", "content_hash"}
    original_object = dict(service.store.conn.execute("SELECT * FROM objects WHERE digest=?", (row["media_id"][7:],)).fetchone())
    if edit == "clear":
        after = ABSENT
        accept(commits, *bind(realm, 3, [], [(KEY, present(row), after)]))
        assert_absent(service, project)
    else:
        object_id = put(realm, b"new canonical")
        new = row_for(object_id, 13)
        after = present(new)
        accept(commits, *bind(realm, 3, [new], [(KEY, present(row), after)], media=[object_id]))
    validate_pin(service, project, pin)
    old = commits.revision_closure(project, "main", "parent-2")
    assert old["shot_revisions"][0]["payload"]["text_bindings"] == [row]
    forward = commits.history_entry(project, "main", commits.head(project, "main")["publication_id"])
    assert forward["records"]["commands"][0]["writes"] == [{"ref": KEY, "path": [], "before": present(row), "after": after}]
    ctx, candidate = bind(realm, 4, [row], [(KEY, after, present(row))], media=[row["media_id"]])
    result = accept(commits, ctx, candidate)
    inverse = commits.history_entry(project, "main", result["receipt"]["receipt_id"])
    assert inverse["records"]["commands"][0]["writes"][0] == {"ref": KEY, "path": [], "before": after, "after": present(row)}
    before_retry = list(service.store.conn.iterdump())
    assert accept(commits, ctx, candidate) == result
    assert list(service.store.conn.iterdump()) == before_retry
    assert dict(service.store.conn.execute("SELECT * FROM shot_text_binding_events WHERE seq=1").fetchone()) == original_event
    assert dict(service.store.conn.execute("SELECT * FROM objects WHERE digest=?", (row["media_id"][7:],)).fetchone()) == original_object
    states = [json.loads(event[0]).get("state", "present") for event in service.store.conn.execute(
        "SELECT payload_json FROM shot_text_binding_events ORDER BY seq")]
    assert states == ["present", "absent" if edit == "clear" else "present", "present"]
    service.close()
    reopened = RuntimeService(root)
    try:
        assert binding(reopened, project)["mime_type"] == "text/plain"
        assert binding(reopened, project)["byte_size"] == len(data)
        assert binding(reopened, project)["head"] == 3
        assert reopened.cas.read(row["media_id"][7:]) == data
        validate_pin(reopened, project, pin)
        retained = TimelineCommitStore(reopened.store, validate_prepared=validate_prepared)
        for revision in ("parent-2", "parent-4"):
            assert retained.revision_closure(project, "main", revision)["shot_revisions"][0]["payload"]["text_bindings"] == [row]
        assert reopened.doctor()["ok"]
    finally:
        reopened.close()


@pytest.mark.parametrize("case", [
    "unretained", "wrong_kind", "wrong_size", "wrong_hash", "wrong_mime", "wrong_project",
    "referenced_only", "corrupt_bytes", "corrupt_chain", "absent_only",
])
def test_legacy_reuse_refuses_without_any_writes(realm, case):
    service, commits, project, _, _ = realm
    row, _ = seed_legacy(realm, b"legacy")
    new_id = put(realm, b"canonical")
    new = row_for(new_id, 9)
    accept(commits, *bind(realm, 3, [new], [(KEY, present(row), present(new))], media=[new_id]))
    target, ref, before = copy.deepcopy(row), KEY, present(new)
    if case == "unretained":
        target["media_id"] = target["content_hash"] = put(realm, b"unseen", media_type="text/plain")
        target["text"] = "unseen"
    elif case == "wrong_kind":
        target["kind"], ref, before = "transcript", "occurrence:occ-1/text-binding:transcript", ABSENT
    elif case == "wrong_size":
        target["byte_size"] += 1
    elif case == "wrong_hash":
        target["content_hash"] = new_id
    elif case == "wrong_mime":
        target["mime_type"] = "text/plain; charset=utf-8"
    elif case == "wrong_project":
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")["id"]
        service.store.conn.execute("UPDATE project_objects SET project_id=? WHERE project_id=? AND digest=?", (foreign, project, row["media_id"][7:]))
    elif case == "referenced_only":
        service.store.conn.execute("UPDATE project_objects SET relation='referenced' WHERE digest=?", (row["media_id"][7:],))
    elif case == "corrupt_bytes":
        path = service.cas.path_for(row["media_id"][7:])
        path.chmod(0o644)
        path.write_bytes(b"LEGACY")
    elif case == "corrupt_chain":
        service.store.conn.execute("UPDATE shot_text_binding_events SET event_hash='forged' WHERE seq=1")
    elif case == "absent_only":
        # Even a self-consistent absent event is not custody of a present input.
        from runtime_protocol.timeline_commit_store import digest
        from runtime_protocol.util import canonical_json

        event = service.store.conn.execute("SELECT * FROM shot_text_binding_events WHERE seq=1").fetchone()
        payload = {**json.loads(event["payload_json"]), "state": "absent"}
        first_hash = digest({"event_id": event["event_id"], "binding_id": event["binding_id"], "seq": 1,
                             "kind": event["kind"], "payload": payload, "previous_hash": ""})[7:]
        service.store.conn.execute("UPDATE shot_text_binding_events SET payload_json=?, event_hash=? WHERE seq=1", (canonical_json(payload), first_hash))
        event = service.store.conn.execute("SELECT * FROM shot_text_binding_events WHERE seq=2").fetchone()
        second_hash = digest({"event_id": event["event_id"], "binding_id": event["binding_id"], "seq": 2,
                              "kind": event["kind"], "payload": json.loads(event["payload_json"]), "previous_hash": first_hash})[7:]
        service.store.conn.execute("UPDATE shot_text_binding_events SET previous_hash=?, event_hash=? WHERE seq=2", (first_hash, second_hash))
    rows = [new, target] if case == "wrong_kind" else [target]
    ctx, candidate = bind(realm, 4, rows, [(ref, before, present(target))], media=sorted({r["media_id"] for r in rows}))
    snapshot = list(service.store.conn.iterdump())
    with pytest.raises((RuntimeErrorBase, CommitRejected)):
        accept(commits, ctx, candidate)
    assert list(service.store.conn.iterdump()) == snapshot


@pytest.mark.parametrize("media_type", ["text/plain", "text/markdown"])
def test_unbound_first_use_remains_strict_on_port_and_projection(realm, media_type):
    service, commits, _, _, _ = realm
    object_id = put(realm, b"first", media_type=media_type)
    row = {**row_for(object_id, 5), "mime_type": media_type, "text": "inline is not authority"}
    selection = {"object_id": object_id, "digest": object_id, "size": 5, "media_type": media_type}
    port, _ = port_for(realm, selection)
    snapshot = list(service.store.conn.iterdump())
    with pytest.raises(RuntimeErrorBase):
        port.text_selection(selection)
    with pytest.raises(RuntimeErrorBase):
        accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    assert list(service.store.conn.iterdump()) == snapshot


def test_retained_binding_does_not_authorize_arbitrary_text_mime(realm):
    service, commits, _, _, _ = realm
    row, _ = seed_legacy(realm, b"markdown", media_type="text/markdown")
    snapshot = list(service.store.conn.iterdump())
    with pytest.raises(RuntimeErrorBase):
        accept(commits, *bind(realm, 3, [], [(KEY, present(row), ABSENT)]))
    assert list(service.store.conn.iterdump()) == snapshot
