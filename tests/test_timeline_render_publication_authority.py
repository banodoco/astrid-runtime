"""Requester publication preserves admitted producer authority and exact replay."""
from __future__ import annotations

import copy

import pytest
from test_timeline_render_publication import _assembly, _publish
from test_timeline_render_publication import requester as requester  # noqa: PLC0414
from test_timeline_render_publication import (
    requester_factory as requester_factory,  # noqa: PLC0414
)


def _state(service):
    return (tuple(service.store.conn.iterdump()),
            {(root.name, str(path.relative_to(root))): path.read_bytes()
             for root in (service.store.cas_root, service.store.staging_root)
             for path in root.rglob("*") if path.is_file()})


def _refused(world, *, proposal=None, reasons=("producer_dependency_unavailable",), **options):
    from astrid.sdk.workspace_client import WorkspaceClientError

    before, changes = _state(world.service), world.service.store.conn.total_changes
    with pytest.raises(WorkspaceClientError) as error:
        _publish(world, proposal=proposal, **options)
    assert error.value.details["status"] in {"invalid", "refused", "conflict"}
    assert error.value.details.get("reason", error.value.details.get("code")) in reasons
    assert _state(world.service) == before
    assert world.service.store.conn.total_changes == changes
    return error.value.details



def _peer(world, *, timeline="main", track="visual"):
    from astrid.sdk.timeline.capture import capture_track_create
    from astrid.sdk.timeline.sync import TimelineSession

    peer = TimelineSession.open(world.project, timeline, client=world.client,
                                outbox_path=world.tmp_path / ("peer-" + timeline + ".json"))
    command = capture_track_create(peer._bundle(peer._state()), "parent", {"id": track, "kind": "visual"})
    return peer.commit_many([command], idempotency_key="peer-" + timeline, label="Peer track", reads=[])


def _assert_pin(world, result):
    data, receipt = result["data"], result["receipt"]
    render = world.service.task(result["render_task_id"])["task"]
    assert render["spec"]["spec"]["params"]["canonical_revision"] == {
        "project_id": world.project, "timeline_id": "main",
        "revision_id": data["accepted_revision_id"], "publication_id": receipt["receipt_id"],
        "content_digest": data["canonical_document"]["parent_revision"]["content_digest"],
    }
    assert world.service.store.conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'",
    ).fetchone()[0] == 1
    assert world.service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_commit_history WHERE publication_id=?", (receipt["receipt_id"],),
    ).fetchone()[0] == 1


def test_tracked_target_refuses_without_invalidating_canonical_history(requester):
    world = requester
    _assembly(world)
    head = _peer(world)
    details = _refused(world, reasons=("atomic_scope_changed",), merge="atomic")
    assert details["status"] == "conflict"
    assert world.service.get_project_timeline(world.project, "main")["head_revision_id"] == head["data"]["accepted_revision_id"]
    assert world.service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'").fetchone()[0] == 0


def test_existing_same_project_unadmitted_target_refuses_before_checkpoint(requester):
    from astrid.core.contracts.runtime_orchestration import OrchestrationContractError

    world = requester
    _assembly(world)
    world.service.create_timeline(world.project, "other", idempotency_key="other")
    proposal = copy.deepcopy(world.proposal)
    proposal["admitted_target"]["timeline_id"] = "other"
    before, changes = _state(world.service), world.service.store.conn.total_changes
    with pytest.raises(OrchestrationContractError, match="scope"):
        _publish(world, proposal=proposal)
    assert _state(world.service) == before
    assert world.service.store.conn.total_changes == changes
    assert world.session._state()["flight"] is None


@pytest.mark.parametrize("publication", [
    {}, False, [], "main", {"timeline_id": None}, {"timeline_id": []}, {"timeline_id": " "},
    {"timeline_id": "main", "admitted_target": None},
    {"timeline_id": "main", "admitted_target": {"timeline_id": "main"}},
])
def test_missing_or_malformed_admitted_target_fails_closed(requester, publication):
    world = requester
    _assembly(world, publication=publication)
    _refused(world)


def test_inconsistent_native_target_cannot_override_legacy_admission(requester):
    world = requester
    _assembly(world, publication={"timeline_id": "main", "admitted_target": {
        "project_id": "foreign", "timeline_id": "other", "base_revision_id": "base",
        "base_publication_id": "receipt",
    }})
    _refused(world)


def test_corrupt_immutable_spec_cannot_supply_target_authority(requester):
    world = requester
    _assembly(world)
    world.service.store.conn.execute(
        "UPDATE task_specs SET body_json='{}' WHERE digest=(SELECT spec_digest FROM tasks WHERE id=?)",
        (world.attempt["task_id"],),
    )
    _refused(world)


def test_canonical_tracking_after_prepare_refuses_before_publication_writes(requester, monkeypatch):
    world = requester
    _assembly(world)
    commits = world.service._timeline_commits()[0]
    original = commits.accept
    after_peer = []

    def accept_after_peer(*args, **kwargs):
        if not after_peer:
            after_peer.append(None)
            _peer(world)
            after_peer[0] = _state(world.service), world.service.store.conn.total_changes
        return original(*args, **kwargs)

    monkeypatch.setattr(commits, "accept", accept_after_peer)
    from astrid.sdk.workspace_client import WorkspaceClientError

    with pytest.raises(WorkspaceClientError) as error:
        _publish(world, merge="atomic")
    assert error.value.details["status"] == "conflict"
    assert (_state(world.service), world.service.store.conn.total_changes) == after_peer[0]
    assert world.service.store.conn.execute("SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'").fetchone()[0] == 0


def test_exact_published_checkpoint_replays_before_live_target_changes(requester, monkeypatch):
    from astrid.sdk.workspace_client import WorkspaceClientError

    world = requester
    _assembly(world)
    transport = world.client._remote._transport
    original = transport.commit_timeline
    requests = []

    def record_request(project, timeline, body, **kwargs):
        requests.append(copy.deepcopy(body))
        return original(project, timeline, body, **kwargs)

    monkeypatch.setattr(transport, "commit_timeline", record_request)
    result = _publish(world)
    _assert_pin(world, result)
    world.service.cancel_task_canonical(world.attempt["task_id"], {}, idempotency_key="cancel")
    # Exact accepted replay must precede mutable producer/spec/target reads.
    world.service.store.conn.execute("UPDATE tasks SET spec_digest=NULL WHERE id=?", (world.attempt["task_id"],))
    world.service.store.conn.execute("UPDATE timelines SET archived_at=created_at WHERE id='main'")
    before, changes = _state(world.service), world.service.store.conn.total_changes
    assert _publish(world) == result
    changed = {**requests[0], "label": "Changed publication intent"}
    with pytest.raises(WorkspaceClientError) as error:
        transport.commit_timeline(world.project, "main", changed, idempotency_key="publish")
    assert error.value.details["reason"] == "idempotency_mismatch"
    assert _state(world.service) == before
    assert world.service.store.conn.total_changes == changes


def test_tracking_is_scoped_to_the_publication_target(requester):
    world = requester
    _assembly(world)
    world.service.create_timeline(world.project, "other", idempotency_key="other")
    peer = _peer(world, timeline="other")
    result = _publish(world)
    assert result["data"]["previous_revision_id"] == world.proposal["admitted_target"]["base_revision_id"]
    assert world.service.get_project_timeline(world.project, "other")["head_revision_id"] == peer["data"]["accepted_revision_id"]
    _assert_pin(world, result)


def test_legacy_head_without_canonical_publication_remains_publishable(requester_factory):
    world = requester_factory("legacy", legacy=True)
    assert world.legacy_head["revision_id"] and world.legacy_head["publication_id"] is None
    assert world.session._state()["base"]["publication_id"]
    _assembly(world)
    result = _publish(world)
    assert result["data"]["status"] == "accepted"
    _assert_pin(world, result)
