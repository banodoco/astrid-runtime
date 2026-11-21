"""Immutable closure safeguards through real host acceptance, without rendering."""
from __future__ import annotations

import copy
import json
import subprocess
import sys

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_store import digest
from test_timeline_commit_acceptance import realm  # noqa: F401 (shared real store)
from test_timeline_projection_occupancy import (
    accept, image, media_item, new_timeline, proposal, refresh, snapshot, with_media,
)


@pytest.fixture
def closure(realm, monkeypatch):
    service, commits, project, _, _ = realm

    def unavailable(*args, **kwargs):
        pytest.fail("closure acceptance or inspection evaluated a scene")

    monkeypatch.setattr("runtime_protocol.service.evaluate_closure", unavailable)
    monkeypatch.setattr("runtime_protocol.visual_seam.evaluate_closure", unavailable)
    item = media_item(service, project, "item-v1")
    child = image("source", "source-v1", items=[item])
    child[1]["payload"]["future_raw"] = {"clear": None, "opaque": [False, None]}
    child[1]["content_digest"] = digest(child[1]["payload"])
    pair = with_media(proposal(service, commits, project, "main", "parent-v1", shots=[child]), item)
    parent = pair[1]["canonical_document"]["parent_revision"]["payload"]
    second = copy.deepcopy(parent["occurrences"][0])
    second.update(occurrence_id="occ-1", placement={"start_ms": 1000}, future_occurrence=None)
    parent["occurrences"].append(second)
    parent["future_parent"] = {"clear": None}
    refresh(pair[1])
    accepted = accept(commits, pair)
    assert service.store.integrity_report()["ok"]
    return service, commits, project, child, item, accepted


def test_old_raw_closure_and_items_survive_own_advance_then_cross_timeline_reuse(closure):
    service, commits, project, child, item, first = closure
    old_shot = service.get_project_shot_revision(project, "source", "source-v1")
    old_internal = service.get_project_timeline_revision(project, "shot:source", "source-v1-internal")
    old_parent = service.get_project_parent_composition_revision(project, "main", "parent-v1")
    assert old_shot["payload"] == child[0]["payload"]
    assert old_internal["payload"] == child[1]["payload"]
    assert old_parent["payload"] == first["data"]["canonical_document"]["parent_revision"]["payload"]
    newer_item = {**item, "item_id": "item-v2", "metadata": {"new": None}}
    newer = image("source", "source-v2", items=[newer_item])
    accept(commits, with_media(proposal(service, commits, project, "main", "parent-v2", shots=[newer]), item))
    mutable = service.get_project_shot(project, "source")
    assert [entry["item_id"] for entry in mutable["items"]] == ["item-v2"]
    head = dict(service.store.conn.execute(
        "SELECT * FROM shot_revision_heads WHERE shot_id='source'",
    ).fetchone())
    assert head["revision_id"] == "source-v2"
    new_timeline(service, commits, project, "linked")
    linked = accept(commits, with_media(
        proposal(service, commits, project, "linked", "linked-v1", shots=[child]), item,
    ))
    assert linked["data"]["canonical_document"]["shot_revisions"] == [child[0]]
    assert service.get_project_shot(project, "source") == mutable
    assert dict(service.store.conn.execute(
        "SELECT * FROM shot_revision_heads WHERE shot_id='source'",
    ).fetchone()) == head
    assert service.get_project_shot_revision(project, "source", "source-v1") == old_shot
    assert service.get_project_timeline_revision(project, "shot:source", "source-v1-internal") == old_internal
    assert service.get_project_parent_composition_revision(project, "main", "parent-v1") == old_parent
    assert commits.revision_closure(project, "main", "parent-v1") == first["data"]["canonical_document"]
    assert service.store.integrity_report()["ok"]


@pytest.mark.parametrize("source", ["missing", "foreign"])
def test_unavailable_selected_item_refuses_without_identity_leak_or_db_cas_changes(closure, source):
    service, commits, project, _, _, _ = closure
    foreign = service.create_project({"slug": "private-owner", "name": "Private owner"})["id"]
    secret = b"private foreign media payload"
    foreign_media = service.ingest(foreign, secret, media_type="video/mp4",
                                   idempotency_key="foreign-media")["data"]["object_id"]
    selected = "sha256:" + "f" * 64 if source == "missing" else foreign_media
    item = {"item_id": "unavailable-item", "media_id": selected, "metadata": {"clear": None}}
    pair = with_media(proposal(service, commits, project, "main", "bad-media",
                               shots=[image("new-source", "bad-shot", items=[item])]), item)
    before = snapshot(service)
    cas = {path.relative_to(service.store.cas_root): path.read_bytes()
           for path in service.store.cas_root.rglob("*") if path.is_file()}
    changes = service.store.conn.total_changes
    with pytest.raises(CommitRejected) as caught:
        accept(commits, pair)
    assert caught.value.failure == {
        "http_status": 409, "code": "conflict", "message": "dependency_unavailable",
        "details": {"status": "refused", "reason": "dependency_unavailable",
                    "base": None, "current": None, "conflicts": []},
    }
    wire = json.dumps(caught.value.failure)
    assert all(value not in wire for value in (foreign, foreign_media, selected, secret.decode()))
    assert snapshot(service) == before
    assert service.store.conn.total_changes == changes
    assert {path.relative_to(service.store.cas_root): path.read_bytes()
            for path in service.store.cas_root.rglob("*") if path.is_file()} == cas


def test_duplicate_occurrence_identity_refuses_before_acceptance(closure):
    service, commits, project, _, _, _ = closure
    pair = proposal(service, commits, project, "main", "duplicate-occurrence")
    occurrences = pair[1]["canonical_document"]["parent_revision"]["payload"]["occurrences"]
    occurrences[1]["occurrence_id"] = occurrences[0]["occurrence_id"]
    refresh(pair[1])
    before = snapshot(service)
    changes = service.store.conn.total_changes
    with pytest.raises(CommitRejected) as caught:
        accept(commits, pair)
    assert caught.value.failure["http_status"] == 422
    assert caught.value.failure["details"]["reason"] == "invalid_closure"
    assert snapshot(service) == before
    assert service.store.conn.total_changes == changes


@pytest.mark.parametrize("fault", ["healthy", "missing-cas", "missing-pointer"])
def test_doctor_distinguishes_missing_cas_from_missing_dependency_pointer(closure, fault):
    service, _, _, _, item, _ = closure
    media = item["media_id"]
    bare = media.removeprefix("sha256:")
    if fault == "missing-cas":
        (service.store.cas_root / bare[:2] / bare[2:]).unlink()
    elif fault == "missing-pointer":
        service.store.conn.execute(
            "DELETE FROM composition_revision_dependencies WHERE parent_revision_id=? AND dependency_id=?",
            ("parent-v1", media),
        )
    before = snapshot(service)
    report = service.store.integrity_report()
    assert report["ok"] is (fault == "healthy")
    missing = [bare] if fault == "missing-cas" else []
    assert report["checks"]["cas_missing"] == missing
    assert report["checks"]["reachable_cas"]["missing"] == missing

    assert report["checks"]["reachable_cas"]["ok"] is (fault != "missing-cas")
    if fault == "missing-pointer":
        assert "dependency_graph_mismatch" in {
            error["reason"] for error in report["checks"]["revisions"]["errors"]
        }
    completed = subprocess.run(
        [sys.executable, "-m", "runtime_protocol", "doctor", "--root", str(service.store.root), "--json", "--deep"],
        capture_output=True, text=True, timeout=20,
    )
    assert completed.returncode == (0 if fault == "healthy" else 1), completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["ok"] == report["ok"]
    assert observed["checks"]["cas_missing"] == missing
    assert snapshot(service) == before


def test_unchanged_evaluations_reuse_history_objects_and_records(closure, monkeypatch):
    service, commits, project, _, _, accepted = closure
    publication = accepted["receipt"]["receipt_id"]
    commits.clear_replay_memo()
    reads, records = [], []
    read_object, verify = commits._read_object, commits._verify_accepted_record

    def counted_read(object_id):
        reads.append(object_id)
        return read_object(object_id)

    def counted_record(*args, **kwargs):
        records.append(True)
        return verify(*args, **kwargs)

    monkeypatch.setattr(commits, "_read_object", counted_read)
    monkeypatch.setattr(commits, "_verify_accepted_record", counted_record)
    expected = commits.history_entry(project, "main", publication)
    head = commits.head(project, "main")
    document = commits.revision_closure(project, "main", head["revision_id"])
    assert commits._history_state["objects"] and records, "the initial evaluation must verify real media and history"
    reads.clear()
    records.clear()
    for _ in range(3):
        assert commits.history_entry(project, "main", publication) == expected
        assert commits.head(project, "main") == head
        assert commits.revision_closure(project, "main", head["revision_id"]) == document
        with commits.history_read_scope():
            assert commits.head(project, "main") == head
    assert reads == []
    assert records == []

    # A write to history must discard the retained results even if it keeps
    # the same head and bytes. Existing corruption tests cover forged values.
    service.store.conn.execute("UPDATE timeline_commit_history SET metadata_json=metadata_json WHERE publication_id=?",
                               (publication,))
    assert commits.history_entry(project, "main", publication) == expected
    assert commits.revision_closure(project, "main", head["revision_id"]) == document
    assert commits._history_state["objects"] and records


@pytest.mark.parametrize("mutation", ["rewrite", "replace", "missing"])
def test_warm_history_still_rejects_changed_cas(closure, tmp_path, mutation):
    service, commits, project, _, item, accepted = closure
    from runtime_protocol.errors import RuntimeErrorBase

    publication = accepted["receipt"]["receipt_id"]
    commits.history_entry(project, "main", publication)
    path = service.cas.path_for(item["media_id"].removeprefix("sha256:"))
    if mutation == "missing":
        path.unlink()
    else:
        damaged = bytes([path.read_bytes()[0] ^ 1]) + path.read_bytes()[1:]
        if mutation == "replace":
            replacement = tmp_path / "replacement"
            replacement.write_bytes(damaged)
            replacement.replace(path)
        else:
            path.write_bytes(damaged)
    before = snapshot(service)
    with pytest.raises(RuntimeErrorBase):
        commits.history_entry(project, "main", publication)
    assert snapshot(service) == before
    assert not any(commits._history_state.values())


@pytest.mark.xfail(strict=True, reason="banodoco/astrid-dev#1222: Plan 59's verify-once design trusts _read_object; open whether a pinned read can return unverified bytes")
def test_descriptor_reader_does_not_inherit_live_cas_proofs(closure, monkeypatch):
    service, commits, project, _, item, accepted = closure
    from runtime_protocol.errors import ProtocolError

    publication = accepted["receipt"]["receipt_id"]
    commits.history_entry(project, "main", publication)
    object_id = item["media_id"].removeprefix("sha256:")
    original = service.cas.read(object_id)
    damaged = bytes([original[0] ^ 1]) + original[1:]
    monkeypatch.setattr(service.store, "_read_cas_object",
                        lambda value: damaged if value == object_id else service.cas.read(value), raising=False)
    before = snapshot(service)
    with pytest.raises(ProtocolError, match="object changed"):
        commits.history_entry(project, "main", publication)
    assert snapshot(service) == before
    assert not any(commits._history_state.values())


@pytest.mark.parametrize("tamper,reason", [
    ("duplicate-dependency", "dependency_graph_mismatch"),
    ("noncontiguous-dependency", "dependency_graph_mismatch"),
    ("occurrence-order", "occurrence_sequence_mismatch"),
    ("occurrence-identity", "occurrence_missing"),
])
def test_accepted_dependency_and_occurrence_corruption_fails_closed(closure, tamper, reason):
    service, commits, project, _, item, _ = closure
    conn = service.store.conn
    # Damage only genuinely accepted rows; never invent publication provenance.
    if tamper == "duplicate-dependency":
        conn.execute("INSERT INTO composition_revision_dependencies VALUES (?, 'media', ?, ?, 3)",
                     ("parent-v1", item["media_id"], item["media_id"]))
    elif tamper == "noncontiguous-dependency":
        conn.execute("UPDATE composition_revision_dependencies SET ordinal=7 WHERE parent_revision_id=? AND dependency_kind='media'",
                     ("parent-v1",))
    elif tamper == "occurrence-order":
        conn.execute("UPDATE composition_revision_occurrences SET ordinal=1-ordinal WHERE parent_revision_id=?",
                     ("parent-v1",))
    else:
        conn.execute("UPDATE composition_revision_occurrences SET occurrence_id='changed' WHERE parent_revision_id=? AND occurrence_id='occ-0'",
                     ("parent-v1",))
    before = snapshot(service)
    report = service.store.integrity_report()
    assert not report["ok"]
    assert reason in {error["reason"] for error in report["checks"]["revisions"]["errors"]}
    with pytest.raises(CommitRejected) as caught:
        commits.revision_closure(project, "main", "parent-v1")
    assert caught.value.failure["details"]["reason"] == "history_unavailable"
    assert snapshot(service) == before
