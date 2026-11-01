"""Physical fork ownership and its scoped authoring projection."""
from __future__ import annotations

import copy
import importlib
import inspect
from types import SimpleNamespace

import pytest

from runtime_protocol.timeline_commit import CommitRejected
from runtime_protocol.timeline_commit_auth import (
    _authoring_identity,
    _authoring_parent_identity,
    _fork_owner_before,
    command_output,
)
from runtime_protocol.timeline_commit_validation import digest

from .test_timeline_popup_fork_authority import _case


def _production_projection_case(projected_owner="old-shot"):
    boundary, record, following, accepted = _case()
    owner = boundary["parent"]["payload"]["occurrences"][0]
    projected = {key: value for key, value in owner.items()
                 if key != "shot_revision_id"}
    projected["shot_id"] = projected_owner
    record["reads"] = [
        {"ref": "occurrence:occ-new", "path": [],
         "state": {"state": "present", "value": projected}},
        {"ref": "occurrence:occ-new/shot", "path": ["shot_id"],
         "state": {"state": "present", "value": owner["shot_id"]}},
    ]
    record["writes"][1]["before"] = {"state": "present", "value": projected_owner}
    scope = ("project", "fork-shot")
    initial_internal = boundary["internal-revision:old-internal"]["payload"]
    internal_id = _authoring_identity(
        "authoring-timeline-revision", *scope, "fork-shot", initial_internal)
    initial_shot = copy.deepcopy(accepted["shot-revision:fork-r1"]["payload"])
    initial_shot["internal_timeline_revision_id"] = internal_id
    shot_revision_id = _authoring_identity(
        "authoring-shot-revision", "project", "fork-shot", initial_shot)
    projected_parent = copy.deepcopy(accepted["parent"]["payload"])
    projected_parent["occurrences"][0]["shot_revision_id"] = shot_revision_id
    projected_images = {
        "parent": {"payload": projected_parent},
        "shot-revision:" + shot_revision_id: {
            "shot_id": "fork-shot", "revision_id": shot_revision_id,
            "internal_timeline_revision_id": internal_id,
            "payload": initial_shot,
            "content_digest": digest(initial_shot),
        },
        "internal-revision:" + internal_id: {
            "timeline_id": "fork-shot", "revision_id": internal_id,
            "payload": initial_internal,
            "content_digest": digest(initial_internal),
        },
    }
    manifest = {"shots": [], "internal_timelines": [], "media": [], "documents": []}
    expected_parent = _authoring_parent_identity(projected_images, scope, manifest)
    for binding in following["bindings"]:
        if binding.get("physical_ref") == "parent":
            binding.update(revision_id=expected_parent, content_digest=digest(projected_parent))
        elif binding.get("ref") == "occurrence:occ-new/source":
            binding.update(physical_ref="internal-revision:" + internal_id,
                          revision_id=internal_id, content_digest=digest(initial_internal))
    return boundary, record, following, accepted


def test_fork_owner_uses_authenticated_agent_projection():
    boundary, record, _, _ = _production_projection_case()
    owner = boundary["parent"]["payload"]["occurrences"][0]

    assert _fork_owner_before(boundary, record, "occurrence:occ-new", owner,
                              ("project", "fork-shot")) == "old-shot"


@pytest.mark.parametrize("mutation", ["source", "projection", "missing"])
def test_fork_owner_projection_rejects_tampering(mutation):
    boundary, record, following, accepted = _production_projection_case()
    if mutation == "source":
        record["reads"][1]["state"]["value"] = "foreign-shot"
    elif mutation == "projection":
        record["reads"][0]["state"]["value"]["duration_ms"] = 999
    else:
        record["reads"].pop()

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, accepted=accepted,
                       identity_scope=("project", "timeline"))


def test_fork_owner_projection_rejects_absent_identity_scope():
    boundary, record, following, accepted = _production_projection_case()

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, accepted=accepted)


def test_fork_owner_projection_rejects_forged_identity_scope():
    boundary, record, following, accepted = _production_projection_case()

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, accepted=accepted,
                       identity_scope=("project", None))


def test_fork_owner_projection_rejects_forged_local_identity():
    boundary, record, following, accepted = _production_projection_case("forged-owner")
    record["writes"][1]["before"]["value"] = "forged-owner"

    with pytest.raises(CommitRejected):
        command_output(boundary, record, following, accepted=accepted,
                       identity_scope=("project", "timeline"))


@pytest.mark.parametrize("mutation", ["shot-pin", "revision-pin", "physical-owner", "physical-digest"])
def test_fork_owner_definition_requires_exact_source_image(mutation):
    boundary, record, _, _ = _production_projection_case()
    owner = boundary["parent"]["payload"]["occurrences"][0]
    if mutation == "shot-pin":
        record["reads"][0]["state"]["value"]["shot_revision_id"] = "foreign"
    elif mutation == "revision-pin":
        record["reads"][0]["state"]["value"]["revision_id"] = "foreign"
    elif mutation == "physical-owner":
        boundary["shot-revision:old-r1"]["shot_id"] = "foreign"
    else:
        boundary["shot-revision:old-r1"]["content_digest"] = digest({})

    with pytest.raises(CommitRejected):
        _fork_owner_before(boundary, record, "occurrence:occ-new", owner,
                           ("project", "fork-shot"))


@pytest.mark.parametrize("mutation", [None, "scope", "sibling", "owner"])
def test_shared_owner_definition_matches_agent(astrid_importable, mutation):
    authoring_id = importlib.import_module("astrid.core.timeline.authoring_bundle")._authoring_shot_id
    boundary, record, _, _ = _production_projection_case()
    rows = boundary["parent"]["payload"]["occurrences"]
    rows.append({**rows[0], "occurrence_id": "sibling"})
    scope = ("project", "fork-shot")
    expected = authoring_id(*scope, "occ-new", "old-shot", shared=True)
    record["reads"][0]["state"]["value"]["shot_id"] = expected
    owner = rows[0]
    if mutation == "scope":
        scope = ("foreign-project", "foreign-timeline")
    elif mutation == "sibling":
        record["reads"][0]["state"]["value"]["shot_id"] = authoring_id(
            *scope, "sibling", "old-shot", shared=True)
    elif mutation == "owner":
        owner = rows[1]
    if mutation is None:
        assert _fork_owner_before(boundary, record, "occurrence:occ-new", owner, scope) == expected
    else:
        with pytest.raises(CommitRejected):
            _fork_owner_before(boundary, record, "occurrence:occ-new", owner, scope)


@pytest.fixture
def actual_child_public(tmp_path, astrid_importable):
    from test_timeline_commit_authentication import created_child_public

    wrapped = created_child_public.__wrapped__  # type: ignore[reportAttributeAccessIssue]
    captured = wrapped(
        tmp_path, astrid_importable, SimpleNamespace(param=False))
    value = next(captured)
    try:
        yield value
    finally:
        captured.close()


def test_actual_agent_fork_add_media_reaches_owner_projection(actual_child_public, monkeypatch):
    import runtime_protocol.timeline_commit_auth as auth
    agent_commit = importlib.import_module("astrid.sdk.timeline.commit")
    execute = importlib.import_module("astrid.sdk.timeline.commands").execute
    capture_occurrence_fork = importlib.import_module(
        "astrid.sdk.timeline.native_occurrence_fork").capture_occurrence_fork
    capture_occurrence_add_media = importlib.import_module(
        "astrid.sdk.timeline.native_occurrence_media_commands").capture_occurrence_add_media

    runtime, project, _source, submitted, _held, document, publish = actual_child_public
    publish(submitted, "popup-child")
    current = document()
    bundle = agent_commit.bundle_from_document(current)
    fork = capture_occurrence_fork(bundle, "occurrence:new", "popup-fork-shot")
    forked = execute(bundle, [fork]).bundle

    occurrence = next(row for row in current["parent_revision"]["payload"]["occurrences"]
                      if row["occurrence_id"] == "new")
    shot = next(row for row in current["shot_revisions"]
                if row["revision_id"] == occurrence["shot_revision_id"])
    internal = next(row for row in current["internal_timeline_revisions"]
                    if row["revision_id"] == shot["internal_timeline_revision_id"])
    asset = next(iter(internal["payload"]["registry"]["assets"]))
    entry = internal["payload"]["registry"]["assets"][asset]
    media = runtime.get_project_media_selection(
        project, {"asset": asset, "generation_id": entry["generationId"],
                  "variant_id": entry["variantId"]}, authorize=lambda: None)
    row = {"id": "popup-added", "clipType": "image", "asset": media["asset"],
           "track": "picture", "at": 0, "hold": 1}
    verified = {"selection": media, "media_type": "image/fixture", "size": 1}
    add = capture_occurrence_add_media(
        forked, "occurrence:new", row, media, verified_media=[verified])

    calls = []
    original = auth._fork_owner_before

    def counted(*args, **kwargs):
        calls.append(tuple(frame.function for frame in inspect.stack()[1:4]))
        return original(*args, **kwargs)

    monkeypatch.setattr(auth, "_fork_owner_before", counted)
    head = runtime.get_project_timeline(project, "film")
    request = copy.deepcopy(submitted)
    request.update(
        base_revision_id=head["head_revision_id"],
        base_publication_id=head["head_publication_id"],
        commands=[fork, add],
        label="Popup fork add media",
        steps=[{"id": "popup", "label": "Popup fork add media",
                 "intent": "Popup fork add media", "tags": [],
                 "command_ordinals": [0, 1], "patch": [], "reads": []}],
    )

    result = publish(request, "popup-fork-add")

    assert [command["op"] for command in request["commands"]] == [
        "occurrence.fork", "occurrence.add-media"]
    assert result["data"]["status"] == "accepted"
    assert calls
    assert all(call and call[0] == "_project_created_child" for call in calls)
    assert calls == [("_project_created_child", "command_output", "validate")] * 4
    assert document()["parent_revision"]["payload"]["occurrences"][0]["shot_id"] == "popup-fork-shot"


@pytest.mark.parametrize("uncaptured", [False, True])
def test_shared_source_fork_add_media_and_history_use_same_owner(actual_child_public, monkeypatch, uncaptured):
    runtime, project, _source, submitted, _held, document, publish = actual_child_public
    commit = importlib.import_module("astrid.sdk.timeline.commit")
    capture_shared = importlib.import_module(
        "astrid.sdk.timeline.native_occurrence_shared").capture_occurrence_place_shared
    capture_track = importlib.import_module("astrid.sdk.timeline.capture").capture_track_create

    def request(command):
        head = runtime.get_project_timeline(project, "film")
        return {**copy.deepcopy(submitted), "base_revision_id": head["head_revision_id"],
                "base_publication_id": head["head_publication_id"], "commands": [command],
                "steps": [{"id": "edit", "label": "Owner control", "intent": "Owner control",
                           "tags": [], "command_ordinals": [0], "patch": [], "reads": []}]}

    publish(submitted, "popup-child")
    shared = capture_shared(commit.bundle_from_document(document()), "occurrence:new", "sibling", on=10)
    assert publish(request(shared), "popup-shared")["data"]["status"] == "accepted"
    before = document()
    sibling = copy.deepcopy(before["parent_revision"]["payload"]["occurrences"][1])
    bundle = commit.bundle_from_document(before)
    assert bundle["placements"][0]["shot_id"] != sibling["shot_id"]

    def app_publish(body, key):
        if uncaptured and [call["op"] for call in body["commands"]] == [
                "occurrence.fork", "occurrence.add-media"]:
            body = copy.deepcopy(body)
            for call in body["commands"]:
                for field in list(call):
                    if field not in {"schema_version", "op", "version", "select", "args", "intent", "created"}:
                        call.pop(field)
        return publish(body, key)

    fixture = runtime, project, _source, submitted, _held, document, app_publish
    test_actual_agent_fork_add_media_reaches_owner_projection(fixture, monkeypatch)

    after = document()
    assert after["parent_revision"]["payload"]["occurrences"][1] == sibling
    assert next(row for row in after["shot_revisions"]
                if row["revision_id"] == sibling["shot_revision_id"]) in before["shot_revisions"]
    # An ordinary later commit scans the accepted fork's native allocation proof.
    track = capture_track(commit.bundle_from_document(after), "parent", {"id": "later", "kind": "visual"})
    assert publish(request(track), "popup-later")["data"]["status"] == "accepted"


@pytest.mark.parametrize("mutation", ["owner-before", "owner-after", "source", "alias", "allocation"])
def test_production_fork_add_owner_tampering_never_writes(actual_child_public, monkeypatch, mutation):
    from runtime_protocol.errors import RuntimeErrorBase
    from runtime_protocol.timeline_commit_port import RequestCommitPort

    runtime, _project, _source, submitted, _held, _document, publish = actual_child_public
    publish(submitted, "popup-child")

    def snapshot():
        files = [{str(path.relative_to(root)): path.read_bytes()
                  for path in root.rglob("*") if path.is_file()}
                 for root in (runtime.store.cas_root, runtime.store.staging_root)]
        return tuple(runtime.store.conn.iterdump()), files, runtime.store.conn.total_changes

    before = snapshot()
    accept = RequestCommitPort.accept
    reached = []

    def attacked(port, prepared):
        if [record["command"]["op"] for record in prepared["records"]["commands"]] == [
                "occurrence.fork", "occurrence.add-media"]:
            prepared = copy.deepcopy(prepared)
            record, following = prepared["records"]["commands"]
            owner = next(write for write in record["writes"] if write["path"] == ["shot_id"])
            if mutation in {"owner-before", "owner-after"}:
                owner[mutation.removeprefix("owner-")]["value"] = "foreign"
            elif mutation == "source":
                read = next(read for read in record["reads"] if read["ref"].endswith("/shot")
                            and read["path"] == ["shot_id"])
                read["state"]["value"] = "foreign"
            elif mutation == "alias":
                binding = next(binding for binding in following["bindings"]
                               if binding["physical_ref"].startswith("internal-revision:"))
                binding["physical_ref"] = "internal-revision:foreign"
            else:
                record["created"][0]["owner"] = "occurrence:foreign"
            reached.append(True)
        return accept(port, prepared)

    monkeypatch.setattr(RequestCommitPort, "accept", attacked)
    with pytest.raises(RuntimeErrorBase):
        test_actual_agent_fork_add_media_reaches_owner_projection(actual_child_public, monkeypatch)
    assert reached == [True]
    assert snapshot() == before
