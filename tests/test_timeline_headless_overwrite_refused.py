"""A headless shell holding authored content is never overwritten by publication.

The shell is installed by direct rows (a historical image). D16 retains the exact
legacy publication requests and proves their earlier retired-route refusal, not
the removed stale-head/content predicates. Positives use bootstrap and commits.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from runtime_protocol.errors import RetiredRouteError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.timeline_commit_baseline import verify_baseline
from runtime_protocol.timeline_commit_port import digest, route_path
from runtime_protocol.timeline_commit_provider import load_timeline_commit_provider
from runtime_protocol.util import canonical_json

AUTHORED = {
    "config": {"fps": 24, "extension": {"keep": [None, False, {"__proto__": 1}]}},
    "registry": {"assets": {"a": {"object_id": "x", "type": "video"}}},
    "clips": [{"id": "edited", "asset": "a", "at": 0, "duration": 3}],
    "occurrences": [],
}
EMPTY = {"config": {}, "registry": {}, "clips": [], "occurrences": []}


class CountingProvider:
    """Count calls while delegating every call to the real Agent provider."""

    def __init__(self, provider):
        self.provider_id = provider.provider_id
        self.interface_version = provider.interface_version
        self.contract_digest = provider.contract_digest
        self.provider = provider
        self.calls = 0

    def commit(self, context, port):
        self.calls += 1
        return self.provider.commit(context, port)


@pytest.fixture
def service(tmp_path, astrid_importable):
    root = tmp_path / "realm"
    RealmStore.initialize(root).close()
    runtime = RuntimeService(root)
    project = runtime.create_project({"slug": "shell", "name": "Shell"}, idempotency_key="project")["id"]
    # Preserve the historical headless shell shape: the timeline aggregate
    # exists, but its publication authority is absent. Registering the provider
    # does not make an unpublished historical source admissible.
    runtime.create_timeline(project, "main", idempotency_key="create-main")
    provider = CountingProvider(load_timeline_commit_provider("astrid"))
    runtime.__dict__["test_provider"] = provider
    runtime.register_timeline_commit_provider(provider)
    try:
        yield runtime, project
    finally:
        runtime.close()


def _shell(runtime, project, payload):
    conn = runtime.store.conn
    with runtime.store._mutex, runtime.store._transaction():
        conn.execute(
            "INSERT INTO parent_composition_revisions(id, project_id, timeline_id, payload_json, content_digest, created_at) VALUES (?,?,?,?,?,?)",
            ("shell-rev", project, "main", json.dumps(payload), digest(payload), "2026-01-01T00:00:00Z"))
        conn.execute(
            "INSERT INTO composition_revision_dependencies(parent_revision_id, dependency_kind, dependency_id, content_digest, ordinal) VALUES (?,?,?,?,0)",
            ("shell-rev", "object", "x", "0" * 64))
        conn.execute(
            "INSERT OR REPLACE INTO parent_composition_heads(timeline_id, project_id, revision_id, publication_id, updated_at) VALUES (?,?,?,NULL,?)",
            ("main", project, "shell-rev", "2026-01-01T00:00:00Z"))


def _commit(runtime, project, key, *, base, replacement, declare_track=False):
    base = base or runtime.get_project_timeline(project, "main")
    document = runtime._timeline_commits()[0].revision_closure(
        project, "main", base["head_revision_id"] if "head_revision_id" in base else base["revision_id"]
    )
    payload = document["parent_revision"]["payload"]
    # Removing bootstrap's config.clips also removes its synchronized root
    # mirror. Restore the original authored root clips explicitly afterward.
    changes = [
        {"op": "set", "ref": "parent", "path": ["config"],
         "before": {"state": "present", "value": copy.deepcopy(payload["config"])},
         "value": copy.deepcopy(replacement["config"])},
        {"op": "set", "ref": "parent", "path": ["registry"],
         "before": {"state": "present", "value": copy.deepcopy(payload["registry"])},
         "value": copy.deepcopy(replacement["registry"])},
        {"op": "set", "ref": "parent", "path": ["clips"],
         "before": {"state": "absent"}, "value": copy.deepcopy(replacement["clips"])},
    ]
    command = {
        "schema_version": 1,
        "op": "doc.patch",
        "version": "1",
        "select": None,
        "created": [
            *(["parent/track:picture"] if declare_track else []),
            "parent/asset:a",
            "parent/clip:edited",
        ],
        "args": {"changes": changes},
    }
    media_id = replacement["registry"]["assets"]["a"]["object_id"]
    admission = {
        "schema_version": 1, "op": "media.admit", "version": "1", "select": None,
        "args": {"inputs": [{"pin": {"media_id": media_id, "content_digest": media_id}}]},
    }
    return runtime.commit_timeline(
        project,
        "main",
        {
            "api_version": 1,
            "project_id": project,
            "timeline_id": "main",
            "base_revision_id": base["head_revision_id"] if "head_revision_id" in base else base["revision_id"],
            "base_publication_id": base["head_publication_id"] if "head_publication_id" in base else base["publication_id"],
            "commands": [command, admission],
            "label": "Headless publication probe",
            "steps": [{
                "id": "headless-probe",
                "label": "Headless publication probe",
                "intent": "prove current publication authority",
                "tags": ["headless"],
                "command_ordinals": [0],
                "patch": copy.deepcopy(changes),
                "reads": [],
            }, {
                "id": "headless-media",
                "label": "Capture authored raw media",
                "intent": "verify the authored media through Runtime",
                "tags": ["headless"],
                "command_ordinals": [1],
                "patch": [],
                "reads": [],
            }],
            "merge": "fields",
            "reads": [],
            "dry_run": False,
            "source": {"via": "python", "detail": "headless overwrite family"},
            "rationale": "Preserve the headless publication boundary.",
            "group_id": "headless-overwrite-family",
        },
        idempotency_key=key,
        publisher="headless-test",
        invocation_path=route_path(project, "main"),
        authorize=lambda: None,
    )


def _assert_retired(error):
    assert error.status == 410
    assert error.code == "retired_route"
    assert isinstance(error.details, dict)
    assert error.details["reason"] == "timeline_commit_required"


def _legacy_publish_empty(runtime, project, key):
    return runtime.publish_parent_composition(
        project,
        "main",
        {
            "project_id": project,
            "timeline_id": "main",
            "expected_head": None,
            "parent_revision_id": "empty-default",
            "parent_composition": EMPTY,
        },
        idempotency_key=key,
    )


def _dump(runtime):
    return (
        tuple(runtime.store.conn.iterdump()),
        tuple((str(path.relative_to(runtime.cas.root)), path.read_bytes())
              for path in sorted(runtime.cas.root.rglob("*")) if path.is_file()),
        runtime.__dict__["test_provider"].calls,
    )


def _stored(runtime):
    return runtime.store.conn.execute("SELECT payload_json FROM parent_composition_revisions WHERE id='shell-rev'").fetchone()[0]


def test_empty_default_over_authored_headless_shell_is_refused_untouched(service):
    runtime, project = service
    _shell(runtime, project, AUTHORED)
    original = _stored(runtime)
    before = _dump(runtime)
    for key in ("empty-default", "empty-default"):  # the retry is refused the same way
        with pytest.raises(RetiredRouteError) as error:
            _legacy_publish_empty(runtime, project, key)
        _assert_retired(error.value)
        assert _dump(runtime) == before
    assert _stored(runtime) == original
    assert json.loads(original) == AUTHORED
    assert runtime.store.conn.execute("SELECT publication_id FROM parent_composition_heads WHERE timeline_id='main'").fetchone()[0] is None


def test_empty_default_over_empty_headless_shell_is_refused_untouched(service):
    runtime, project = service
    _shell(runtime, project, EMPTY)
    before = _dump(runtime)
    with pytest.raises(RetiredRouteError) as error:
        _legacy_publish_empty(runtime, project, "empty-default")
    _assert_retired(error.value)
    assert _dump(runtime) == before


def test_empty_default_on_a_fresh_timeline_is_accepted_and_replays(service):
    runtime, project = service
    accepted = runtime.create_timeline(project, "main", idempotency_key="empty-default")
    assert accepted["receipt"]["command_kind"] == "timeline.create"
    facts = verify_baseline(runtime.store.conn, project, "main", read_object=runtime.cas.read)
    assert facts is not None
    assert facts["head"] == {
        "revision_id": accepted["data"]["head_revision_id"],
        "publication_id": accepted["data"]["head_publication_id"],
    }
    publication = facts["entries"][-1]
    assert publication["receipt"]["command_kind"] == "parent_composition.publish"
    assert publication["receipt"]["result"]["revision_id"] == accepted["data"]["head_revision_id"]
    assert publication["receipt"]["event_ids"] == accepted["receipt"]["event_ids"]
    event = runtime.store.conn.execute(
        "SELECT kind, payload_json FROM timeline_events WHERE id=?",
        (publication["receipt"]["event_ids"][-1],),
    ).fetchone()
    assert event is not None
    assert event["kind"] == "parent.composition.published"
    assert json.loads(event["payload_json"])["new_head"] == accepted["data"]["head_revision_id"]
    before = _dump(runtime)
    assert runtime.create_timeline(project, "main", idempotency_key="empty-default") == accepted
    assert _dump(runtime) == before


def _hide_content(runtime, project, content):
    with runtime.store.conn:
        runtime.store.conn.execute(
            "INSERT INTO project_documents VALUES (?, ?, ?, ?, 1, ?, ?)",
            ("timeline:main", project, "timeline", canonical_json(content), "2026-10-20T00:00:00Z", "2026-10-20T00:00:00Z"))


def test_empty_parent_over_hidden_nonempty_content_of_a_headless_timeline_is_refused_untouched(service):
    """App's probe: head is None publicly while project_documents holds authored content."""
    runtime, project = service
    fixture = json.loads((Path(__file__).parent / "fixtures" / "headless_hidden_content_candidate.json").read_text())
    content = {"slug": "edited", "config": fixture["hiddenAuthored"], "registry": {"assets": {}}}
    _hide_content(runtime, project, content)
    assert runtime.get_project_timeline(project, "main")["head_revision_id"] is None
    body = {**copy.deepcopy(fixture["submitted"]), "project_id": project, "timeline_id": "main"}
    assert body["parent_composition"] == fixture["submitted"]["parent_composition"]
    before = _dump(runtime)
    for key in ("repair-shell", "repair-shell"):  # the retry is refused the same way
        with pytest.raises(RetiredRouteError) as error:
            runtime.publish_parent_composition(project, "main", body, idempotency_key=key)
        _assert_retired(error.value)
        assert _dump(runtime) == before
    stored = runtime.store.conn.execute("SELECT content_json FROM project_documents WHERE id='timeline:main'").fetchone()[0]
    assert json.loads(stored) == content


def test_genuinely_empty_headless_timeline_still_accepts_expected_head_null(service):
    runtime, project = service
    _hide_content(runtime, project, {"config": {}, "registry": {"assets": {}}, "clips": []})
    accepted = runtime.create_timeline(project, "main", idempotency_key="repair-genuine-empty")
    assert accepted["receipt"]["command_kind"] == "timeline.create"
    hidden = runtime.store.conn.execute(
        "SELECT content_json FROM project_documents WHERE id='timeline:main'"
    ).fetchone()
    assert hidden is not None
    assert hidden[0] == canonical_json({"config": {}, "registry": {"assets": {}}, "clips": []})
    facts = verify_baseline(runtime.store.conn, project, "main", read_object=runtime.cas.read)
    assert facts is not None
    assert facts["head"] == {
        "revision_id": accepted["data"]["head_revision_id"],
        "publication_id": accepted["data"]["head_publication_id"],
    }


def test_cas_correct_republish_after_reading_the_head_is_accepted(service):
    runtime, project = service
    media = subprocess.run(
        ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=c=blue:s=16x16:r=10",
         "-t", "3", "-an", "-c:v", "libx264", "-pix_fmt", "yuv420p",
         "-movflags", "+frag_keyframe+empty_moov", "-f", "mp4", "pipe:1"],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    ingested = runtime.ingest(project, media, media_type="video/mp4", idempotency_key="authored-media")
    media_id = ingested["data"]["object_id"]
    assert media_id == "sha256:" + hashlib.sha256(media).hexdigest()
    assert runtime.cas.read(media_id.removeprefix("sha256:")) == media
    # Current commit probes substitute Runtime's genuine CAS identity.
    # Historical shells and legacy requests keep the original literal "x".
    expected = copy.deepcopy(AUTHORED)
    assert expected["registry"]["assets"]["a"]["object_id"] == "x"
    expected["registry"]["assets"]["a"]["object_id"] = media_id
    # Match the standard Agent document_fixture's authored visual track.
    assert "tracks" not in expected["config"]
    assert "track" not in expected["clips"][0]
    expected["config"]["tracks"] = [{"id": "picture", "kind": "visual"}]
    expected["clips"][0]["track"] = "picture"
    original = copy.deepcopy(expected)
    assert original["config"].pop("tracks") == [{"id": "picture", "kind": "visual"}]
    assert original["clips"][0].pop("track") == "picture"
    original["registry"]["assets"]["a"]["object_id"] = "x"
    assert json.dumps(original) == json.dumps(AUTHORED)
    first = runtime.create_timeline(project, "main", idempotency_key="repair-cas")
    head = runtime.get_project_timeline(project, "main")
    assert {"revision_id": head["head_revision_id"], "publication_id": head["head_publication_id"]} == {
        "revision_id": first["data"]["head_revision_id"],
        "publication_id": first["data"]["head_publication_id"],
    }
    again = _commit(runtime, project, "second", base=head, replacement=expected, declare_track=True)
    assert again["data"]["status"] == "accepted"
    assert again["data"]["previous_revision_id"] == first["data"]["head_revision_id"]
    assert again["data"]["previous_publication_id"] == first["data"]["head_publication_id"]
    actual = again["data"]["canonical_document"]["parent_revision"]["payload"]
    assert actual == expected
    assert canonical_json(actual) == canonical_json(expected)
    assert again["receipt"]["result"] == again["data"]
    history = runtime.list_timeline_commits(project, "main", authorize=lambda: None)["items"]
    entry = next(item for item in history if item["publication_id"] == again["receipt"]["receipt_id"])
    assert entry["receipt"] == again["receipt"]
    assert entry["records"]["commands"][0]["command"] == again["data"]["commands"][0]
    assert entry["records"]["commands"][0]["created"] == [
        {"kind": "track", "owner": "parent", "ref": "parent/track:picture"},
        {"kind": "asset", "owner": "parent", "ref": "parent/asset:a"},
        {"kind": "clip", "owner": "parent", "ref": "parent/clip:edited"},
    ]
    event = runtime.store.conn.execute(
        "SELECT kind, payload_json FROM timeline_events WHERE id=?",
        (again["receipt"]["event_ids"][-1],),
    ).fetchone()
    assert event is not None
    assert event["kind"] == "timeline.commit.accepted"
    event_payload = json.loads(event["payload_json"])
    assert event_payload["previous"] == {
        "revision_id": first["data"]["head_revision_id"],
        "publication_id": first["data"]["head_publication_id"],
    }
    assert event_payload["records_digest"] == digest(entry["records"])
    closure = runtime._timeline_commits()[0].revision_closure(
        project, "main", again["data"]["accepted_revision_id"]
    )
    assert closure == again["data"]["canonical_document"]
    assert closure["dependency_manifest"]["media"] == [
        {"media_id": media_id, "content_digest": media_id},
    ]
    assert closure["shot_revisions"] == closure["internal_timeline_revisions"] == []
    assert runtime.store.conn.execute(
        "SELECT content_digest, commit_manifest_json FROM parent_composition_revisions WHERE id=?",
        (again["data"]["accepted_revision_id"],),
    ).fetchone()["content_digest"] == again["data"]["canonical_document"]["parent_revision"]["content_digest"]
    before = _dump(runtime)
    assert _commit(runtime, project, "second", base=head, replacement=expected, declare_track=True) == again
    assert _dump(runtime) == before
    assert runtime.__dict__["test_provider"].calls == 1
    runtime.close()
    reloaded = RuntimeService(runtime.store.root)
    try:
        provider = CountingProvider(load_timeline_commit_provider("astrid"))
        reloaded.__dict__["test_provider"] = provider
        reloaded.register_timeline_commit_provider(provider)
        reloaded_head = reloaded.get_project_timeline(project, "main")
        assert reloaded_head["head_revision_id"] == again["data"]["accepted_revision_id"]
        assert reloaded_head["head_publication_id"] == again["receipt"]["receipt_id"]
        assert reloaded._timeline_commits()[0].revision_closure(
            project, "main", reloaded_head["head_revision_id"]
        ) == closure
        before = _dump(reloaded)
        assert _commit(reloaded, project, "second", base=head, replacement=expected, declare_track=True) == again
        assert _dump(reloaded) == before
        assert provider.calls == 0
    finally:
        reloaded.close()


def test_original_trackless_authored_payload_with_verified_media_is_invalid_untouched(service):
    runtime, project = service
    media = subprocess.run(
        ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=c=blue:s=16x16:r=10",
         "-t", "3", "-an", "-c:v", "libx264", "-pix_fmt", "yuv420p",
         "-movflags", "+frag_keyframe+empty_moov", "-f", "mp4", "pipe:1"],
        check=True, stdout=subprocess.PIPE,
    ).stdout
    ingested = runtime.ingest(project, media, media_type="video/mp4", idempotency_key="authored-media")
    media_id = ingested["data"]["object_id"]
    assert media_id == "sha256:" + hashlib.sha256(media).hexdigest()
    assert runtime.cas.read(media_id.removeprefix("sha256:")) == media
    trackless = copy.deepcopy(AUTHORED)
    trackless["registry"]["assets"]["a"]["object_id"] = media_id
    original = copy.deepcopy(trackless)
    original["registry"]["assets"]["a"]["object_id"] = "x"
    assert json.dumps(original) == json.dumps(AUTHORED)
    runtime.create_timeline(project, "main", idempotency_key="repair-trackless")
    head = runtime.get_project_timeline(project, "main")
    history = runtime.list_timeline_commits(project, "main", authorize=lambda: None)
    before = _dump(runtime)
    for calls in (1, 2):
        with pytest.raises(RuntimeErrorBase, match="must reference an existing track") as error:
            _commit(runtime, project, "trackless", base=head, replacement=trackless)
        assert error.value.status == 422
        assert error.value.code == "validation_error"
        assert isinstance(error.value.details, dict)
        assert error.value.details["status"] == "invalid"
        assert error.value.details["reason"] == "invalid_document"
        assert "clips['edited'].track" in str(error.value)
        assert _dump(runtime)[:2] == before[:2]
        assert runtime.__dict__["test_provider"].calls == before[2] + calls
        assert runtime.get_project_timeline(project, "main") == head
        assert runtime.list_timeline_commits(project, "main", authorize=lambda: None) == history


def test_fresh_creation_is_unchanged(service):
    runtime, project = service
    created = runtime.create_timeline(project, "second", idempotency_key="create-second")
    assert runtime.create_timeline(project, "second", idempotency_key="create-second") == created


def _scoped_rows(runtime, project, kind):
    conn = runtime.store.conn
    with runtime.store._mutex, runtime.store._transaction():
        if kind == "timeline_references":
            conn.execute("INSERT INTO timeline_references(id, timeline_id, object_id, role) VALUES ('r1','main','obj',NULL)")
        elif kind == "timeline_shots":
            conn.execute("INSERT INTO timeline_shots(id, timeline_id, start_ms, duration_ms, reference_ids_json) VALUES ('s1','main',0,1000,'[]')")
        elif kind == "snapshot":
            conn.execute("INSERT INTO timeline_revisions(timeline_id, version, shots_json, references_json, created_at) VALUES ('main',2,'[{\"id\":\"s1\"}]','[]','2026-01-01T00:00:00Z')")
        else:  # a dependency row on an unpublished parent revision of the headless timeline
            conn.execute(
                "INSERT INTO parent_composition_revisions(id, project_id, timeline_id, payload_json, content_digest, created_at) VALUES (?,?,?,?,?,?)",
                ("orphan-rev", project, "main", json.dumps(EMPTY), digest(EMPTY), "2026-01-01T00:00:00Z"))
            conn.execute(
                "INSERT INTO composition_revision_dependencies(parent_revision_id, dependency_kind, dependency_id, content_digest, ordinal) VALUES (?,?,?,?,0)",
                ("orphan-rev", "object", "x", "0" * 64))


@pytest.mark.parametrize("kind", ["timeline_references", "timeline_shots", "snapshot", "dependency"])
def test_headless_timeline_with_scoped_rows_refuses_empty_publish_untouched(service, kind):
    runtime, project = service
    _scoped_rows(runtime, project, kind)
    before = _dump(runtime)
    for key in ("scope-deny", "scope-deny"):  # the retry is refused the same way
        with pytest.raises(RetiredRouteError) as error:
            _legacy_publish_empty(runtime, project, key)
        _assert_retired(error.value)
        assert _dump(runtime) == before


def test_retired_parent_publication_route_stays_410_and_write_free(service):
    runtime, project = service
    before = _dump(runtime)
    for key in ("legacy-empty-default", "legacy-empty-default"):
        with pytest.raises(RetiredRouteError) as error:
            _legacy_publish_empty(runtime, project, key)
        assert error.value.status == 410
        assert error.value.code == "retired_route"
        details = error.value.details
        assert isinstance(details, dict)
        assert details["reason"] == "timeline_commit_required"
        assert _dump(runtime) == before
