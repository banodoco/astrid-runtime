"""Exact UTF-8 text selection on the commit port and its recorded binding projection."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from test_timeline_commit_acceptance import accept, context, counts, prepared, realm  # noqa: F401 (realm is a fixture)
from test_timeline_verified_media import settle_media

from runtime_protocol import timeline_commit as abi
from runtime_protocol.errors import ConflictError, NotFoundError, RuntimeErrorBase, ValidationError
from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_port import (
    TEXT_MAX_BYTES,
    TEXT_MEDIA_TYPE,
    MediaReads,
    RequestCommitPort,
)
from runtime_protocol.timeline_commit_store import digest

KEY = "occurrence:occ-1/text-binding:voiceover_script"


def put(realm, data, *, media_type=TEXT_MEDIA_TYPE, key=None):
    service, _, project, _, _ = realm
    object_id = service.ingest(project, data, media_type=media_type, idempotency_key=key or "text-" + hashlib.sha256(data + media_type.encode()).hexdigest()[:12])["data"]["object_id"]
    return object_id


def selection_of(data, object_id=None, **changes):
    object_id = object_id or "sha256:" + hashlib.sha256(data).hexdigest()
    return {"object_id": object_id, "digest": object_id, "size": len(data), "media_type": TEXT_MEDIA_TYPE, **changes}


def port_for(realm, selection):
    service, commits, project, head, _ = realm
    ctx = context(service, project, head, "text-port")
    ctx["request"]["commands"][0]["args"] = {"text": selection}
    ctx["invocation"]["body"] = copy.deepcopy(ctx["request"])
    from runtime_protocol.timeline_commit_store import request_identity
    ctx["request_hash"] = request_identity(ctx)
    return RequestCommitPort(service, commits, ctx, lambda: None), ctx


def test_port_declares_text_selection():
    # The Agent-side strict xfail test_runtime_port_declares_exact_text_selection checks this text.
    assert "def text_selection(" in Path(abi.__file__).read_text()
    assert hasattr(RequestCommitPort, "text_selection")


@pytest.mark.parametrize("data", ["", "héllo\r\n ", "x" * TEXT_MAX_BYTES])
def test_text_selection_verifies_exact_utf8_including_empty_and_max(realm, data):
    data = data.encode()
    selection = selection_of(data, put(realm, data))
    port, _ = port_for(realm, selection)
    assert port.text_selection(selection) == {**selection, "utf8": True}
    assert set(port.text_selection(selection)) == {"object_id", "digest", "size", "media_type", "utf8"}


def refusal(realm, case):
    """Return (selection, expected error) for one way a selection can be wrong."""
    good, other = b"hello", b"other"
    if case == "non_utf8":
        data = b"\xff\xfe"
        return selection_of(data, put(realm, data)), ValidationError
    if case == "size_mismatch":
        return selection_of(good, put(realm, good), size=len(good) + 1), ConflictError
    if case == "digest_mismatch":
        return selection_of(good, put(realm, good), digest=put(realm, other)), ValidationError
    if case == "unstored_digest":
        return selection_of(good, "sha256:" + "0" * 64), NotFoundError
    if case == "stored_wrong_media_type":
        data = b"plain"
        return selection_of(data, put(realm, data, media_type="text/plain")), ConflictError
    if case == "selection_wrong_media_type":
        return selection_of(good, put(realm, good), media_type="text/plain"), ValidationError
    if case == "non_text_media_type":
        data = b"png"
        return selection_of(data, put(realm, data, media_type="image/png"), media_type="image/png"), ValidationError
    if case == "over_limit":
        data = b"x" * (TEXT_MAX_BYTES + 1)
        return selection_of(data, put(realm, data)), ValidationError
    if case == "negative_size":
        return selection_of(good, put(realm, good), size=-1), ValidationError
    if case == "bool_size":
        return selection_of(b"", put(realm, b""), size=False), ValidationError
    if case == "extra_field":
        return {**selection_of(good, put(realm, good)), "utf8": True}, ValidationError
    if case == "foreign_project":
        service, _, _, _, _ = realm
        foreign = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign")["id"]
        object_id = service.ingest(foreign, good, media_type=TEXT_MEDIA_TYPE, idempotency_key="foreign-text")["data"]["object_id"]
        return selection_of(good, object_id), NotFoundError
    if case == "referenced_only":
        service, _, project, _, _ = realm
        object_id = put(realm, good)
        service.store.conn.execute("UPDATE project_objects SET relation='referenced' WHERE project_id=? AND digest=?", (project, object_id[7:]))
        return selection_of(good, object_id), NotFoundError
    if case == "corrupt_bytes":
        service, _, _, _, _ = realm
        object_id = put(realm, good)
        path = service.cas.path_for(object_id[7:])
        path.chmod(0o644)
        path.write_bytes(b"HELLO")
        return selection_of(good, object_id), ConflictError
    raise AssertionError(case)


@pytest.mark.parametrize("case", [
    "non_utf8", "size_mismatch", "digest_mismatch", "unstored_digest", "stored_wrong_media_type",
    "selection_wrong_media_type", "non_text_media_type", "over_limit", "negative_size", "bool_size",
    "extra_field", "foreign_project", "referenced_only", "corrupt_bytes",
])
def test_text_selection_refuses_without_writes(realm, case):
    service = realm[0]
    selection, error = refusal(realm, case)
    port, _ = port_for(realm, selection)
    before = list(service.store.conn.iterdump())
    with pytest.raises(error):
        port.text_selection(selection)
    assert list(service.store.conn.iterdump()) == before


def test_undeclared_text_selection_is_refused(realm):
    selection = selection_of(b"hello", put(realm, b"hello"))
    port, _ = port_for(realm, {**selection, "size": 99})
    with pytest.raises(CommitRejected) as error:
        port.text_selection(selection)
    assert error.value.failure["details"]["reason"] == "dependency_unavailable"


def test_text_is_admitted_to_the_manifest_only_through_the_port_and_rechecked_at_acceptance(realm):
    service, commits, project, head, _ = realm
    data = b"voice"
    object_id = put(realm, data)
    selection = selection_of(data, object_id)
    port, ctx = port_for(realm, selection)

    def candidate():
        value = prepared(commits, ctx)
        value["canonical_document"]["dependency_manifest"]["media"] = [{"media_id": object_id, "content_digest": object_id}]
        value["document_digest"] = digest(value["canonical_document"])
        return value

    with pytest.raises(CommitRejected) as error:
        port.validate(candidate())
    assert error.value.failure["details"]["reason"] == "dependency_unavailable"
    port.text_selection(selection)
    port.validate(candidate())
    service.store.conn.execute("UPDATE objects SET media_type='text/plain' WHERE digest=?", (object_id[7:],))
    with pytest.raises(ConflictError):
        port.validate(candidate())


def test_media_selection_still_rejects_text(tmp_path):
    service, project, outputs = settle_media(tmp_path, {"image": b"\x89PNG\r\n\x1a\nplaceholder"})
    try:
        output = outputs["image"]
        selection = service.get_project_media_selection(project, {
            "association_id": output["association_id"], "object_id": output["object_id"],
            "version": output["lifecycle"]["version"]}, authorize=lambda: None)
        service.store.conn.execute("UPDATE objects SET media_type=? WHERE digest=?", (TEXT_MEDIA_TYPE, output["object_id"][7:]))
        with pytest.raises(ValidationError):
            MediaReads(service).selected(project, selection)
    finally:
        service.close()


def test_old_port_without_text_selection_fails_closed():
    class OldPort:
        """The previous port surface: no text_selection."""

    # A provider needing text gets no fallback: the missing method is an error, never inline text.
    assert not hasattr(OldPort(), "text_selection")
    with pytest.raises(AttributeError):
        OldPort().text_selection(selection_of(b"x"))


# -- recorded binding projection ----------------------------------------------------------

def row_for(object_id, size, *, kind="voiceover_script", slot=None):
    return {"kind": kind, "slot": slot, "media_id": object_id, "content_hash": object_id, "byte_size": size,
            "mime_type": TEXT_MEDIA_TYPE}


def present(value):
    return {"state": "present", "value": value}


ABSENT = {"state": "absent"}


def bind(realm, n, rows, writes, *, shot_read="shot-1", media=(), key=None):
    """Accept revision n of shot-1 (occ-1) carrying `rows` and recording `writes`."""
    service, commits, project, _, _ = realm
    ctx = context(service, project, commits.head(project, "main"), key or f"bind-{n}")
    value = prepared(commits, ctx, revision=f"parent-{n}")
    internal_payload = {"clips": [], "tracks": [], "app": {"opaque": None}}
    internal = {"timeline_id": "shot:shot-1", "revision_id": "internal-1", "payload": internal_payload, "content_digest": digest(internal_payload)}
    shot_payload = {"name": "Opening", "metadata": {}, "items": [], "text_bindings": rows, "internal_timeline_revision_id": "internal-1"}
    shot = {"shot_id": "shot-1", "revision_id": f"shot-1-r{n}", "internal_timeline_revision_id": "internal-1", "payload": shot_payload, "content_digest": digest(shot_payload)}
    occurrence = {"occurrence_id": "occ-1", "shot_id": "shot-1", "shot_revision_id": shot["revision_id"], "placement": {"start_ms": 0},
                  "duration_ms": 1000, "source_offset": 0, "speed": {"numerator": 1, "denominator": 1}, "track": "picture",
                  "transform": {}, "gain": 1, "muted": False, "provenance": {}}
    document = value["canonical_document"]
    document["shot_revisions"], document["internal_timeline_revisions"] = [shot], [internal]
    document["parent_revision"]["payload"]["occurrences"] = [occurrence]
    document["parent_revision"]["content_digest"] = digest(document["parent_revision"]["payload"])
    manifest = document["dependency_manifest"]
    manifest["shots"] = [{k: shot[k] for k in ("shot_id", "revision_id", "internal_timeline_revision_id", "content_digest")}]
    manifest["internal_timelines"] = [{k: internal[k] for k in ("timeline_id", "revision_id", "content_digest")}]
    manifest["media"] = sorted(({"media_id": m, "content_digest": m} for m in media), key=lambda item: item["media_id"])
    value["document_digest"] = digest(document)
    record = value["records"]["commands"][0]
    record["reads"] = [{"ref": "occurrence:occ-1/shot", "path": ["shot_id"], "state": present(shot_read)}]
    record["writes"] = [{"ref": ref, "path": [], "before": before, "after": after} for ref, before, after in writes]
    return ctx, value


def binding(service, project, key="voiceover_script"):
    from runtime_protocol.service import RuntimeService
    return service.get_project_shot_text_binding(project, RuntimeService._text_binding_id(project, "shot-1", key, None))


def events(service):
    return [(r["seq"], r["kind"]) for r in service.store.conn.execute("SELECT seq, kind FROM shot_text_binding_events ORDER BY binding_id, seq")]


@pytest.mark.parametrize("data", [b"first use", b""])
def test_first_use_text_projects_created_event_and_live_readers_agree(realm, data):
    service, commits, project, _, _ = realm
    object_id = put(realm, data)
    row = row_for(object_id, len(data))
    ctx, value = bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id])
    accept(commits, ctx, value)
    live = binding(service, project)
    assert (live["head"], live["media_id"], live["content_hash"], live["byte_size"], live["mime_type"]) == (
        1, object_id, object_id, len(data), TEXT_MEDIA_TYPE)
    assert (live["kind"], live["slot"], live["shot_id"]) == ("voiceover_script", None, "shot-1")
    assert events(service) == [(1, "shot.text_binding.created")]
    payload = json.loads(service.store.conn.execute("SELECT payload_json FROM shot_text_binding_events").fetchone()[0])
    assert payload["publication_id"] == commits.head(project, "main")["publication_id"]
    assert service.list_project_shot_text_bindings(project, shot_id="shot-1")["items"] == [live]
    assert service.store.integrity_report()["ok"]


def test_rebind_advances_head_and_same_value_set_does_not(realm):
    service, commits, project, _, _ = realm
    one, two = put(realm, b"one"), put(realm, b"two")
    first, second = row_for(one, 3), row_for(two, 3)
    accept(commits, *bind(realm, 1, [first], [(KEY, ABSENT, present(first))], media=[one]))
    accept(commits, *bind(realm, 2, [second], [(KEY, present(first), present(second))], media=[two]))
    assert (binding(service, project)["head"], binding(service, project)["media_id"]) == (2, two)
    accept(commits, *bind(realm, 3, [second], [(KEY, present(second), present(second))], media=[two]))
    assert binding(service, project)["head"] == 2
    assert events(service) == [(1, "shot.text_binding.created"), (2, "shot.text_binding.rebound")]
    assert service.store.integrity_report()["ok"]


def test_prompt_slot_is_a_separate_binding(realm):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"hero prompt")
    row = row_for(object_id, 11, kind="prompt", slot="hero")
    accept(commits, *bind(realm, 1, [row], [("occurrence:occ-1/text-binding:prompt:hero", ABSENT, present(row))], media=[object_id]))
    live = service.list_project_shot_text_bindings(project, shot_id="shot-1", kind="prompt", slot="hero")["items"]
    assert [(item["slot"], item["head"]) for item in live] == [("hero", 1)]


def test_historical_reuse_does_not_repoint_the_live_binding(realm):
    service, commits, project, _, _ = realm
    one, two = put(realm, b"one"), put(realm, b"two")
    first, second = row_for(one, 3), row_for(two, 3)
    accept(commits, *bind(realm, 1, [first], [(KEY, ABSENT, present(first))], media=[one]))
    accept(commits, *bind(realm, 2, [second], [(KEY, present(first), present(second))], media=[two]))
    # Re-accept the older shot revision (no text-binding write): the live head stays at 2.
    ctx, value = bind(realm, 1, [first], [], media=[one], key="restore")
    value["canonical_document"]["parent_revision"]["revision_id"] = "parent-restored"
    value["records"]["commands"][0]["reads"] = []
    value["canonical_document"]["parent_revision"]["content_digest"] = digest(value["canonical_document"]["parent_revision"]["payload"])
    value["document_digest"] = digest(value["canonical_document"])
    accept(commits, ctx, value)
    assert (binding(service, project)["head"], binding(service, project)["media_id"]) == (2, two)


@pytest.mark.parametrize("case", ["before_absent_but_live", "before_wrong_media", "owner_changed", "no_owner_read",
                                  "wrong_mime_object", "unstored_object", "key_mismatch", "malformed_ref"])
def test_projection_refusal_rolls_back_the_whole_acceptance(realm, case):
    service, commits, project, head, _ = realm
    one, two = put(realm, b"one"), put(realm, b"two")
    first, second = row_for(one, 3), row_for(two, 3)
    accept(commits, *bind(realm, 1, [first], [(KEY, ABSENT, present(first))], media=[one]))
    ref, shot_read, after = KEY, "shot-1", second
    media, prior = [two], present(first)
    if case == "before_absent_but_live":
        prior = ABSENT
    elif case == "before_wrong_media":
        prior = present(second)
    elif case == "owner_changed":
        shot_read = "shot-2"
    elif case == "wrong_mime_object":
        other = put(realm, b"png", media_type="image/png")
        after, media = row_for(other, 3), [other]
    elif case == "unstored_object":
        ghost = "sha256:" + "1" * 64
        after, media = row_for(ghost, 3), [two]
    elif case == "key_mismatch":
        after = row_for(two, 3, kind="transcript")
    elif case == "malformed_ref":
        ref = "occurrence:occ-1/text-binding:nonsense"
    ctx, value = bind(realm, 2, [after], [(ref, prior, present(after))], shot_read=shot_read, media=media)
    if case == "no_owner_read":
        value["records"]["commands"][0]["reads"] = []
    before_rows = list(service.store.conn.iterdump())
    with pytest.raises((CommitRejected, RuntimeErrorBase)):
        accept(commits, ctx, value)
    assert list(service.store.conn.iterdump()) == before_rows
    assert binding(service, project)["head"] == 1


def test_projection_commits_atomically_with_acceptance_and_rolls_back_with_it(realm):
    service, commits, project, head, _ = realm
    object_id = put(realm, b"atomic")
    row = row_for(object_id, 6)
    ctx, value = bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id])

    class Boom:
        def validate(self, candidate):
            pass

        def persist(self, candidate, publication_id, revision_id):
            assert service.store.conn.execute("SELECT COUNT(*) FROM shot_text_bindings").fetchone()[0] == 1
            raise RuntimeError("input persistence failed after the projection")

    before = list(service.store.conn.iterdump())
    with pytest.raises(RuntimeError, match="after the projection"):
        commits.accept(ctx, value, authorize=lambda: None, inputs=Boom())
    assert list(service.store.conn.iterdump()) == before
    assert commits.head(project, "main") == head
    accept(commits, ctx, value)  # exact retry after rollback publishes once
    assert binding(service, project)["head"] == 1
    assert counts(service)["timeline_commit_history"] == 2


def test_clear_removes_the_live_binding(realm):
    service, commits, project, _, _ = realm
    object_id = put(realm, b"gone")
    row = row_for(object_id, 4)
    accept(commits, *bind(realm, 1, [row], [(KEY, ABSENT, present(row))], media=[object_id]))
    accept(commits, *bind(realm, 2, [], [(KEY, present(row), ABSENT)]))
    assert service.list_project_shot_text_bindings(project, shot_id="shot-1")["items"] == []
