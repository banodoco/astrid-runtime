from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest

from runtime_protocol.errors import LeaseError
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


def _connect(world):
    from astrid.sdk.client import AstridClient
    from astrid.sdk.timeline.sync import TimelineSession

    world.service = world.daemon.service
    world.client = AstridClient.open(
        endpoint=world.daemon.endpoint, credential=world.daemon.credential_path,
        realm_id=world.service.realm["id"], actor_id="owner", client_name="render-publication-test",
        client_version="1", protocol_version="workspace.v1",
    )
    world.session = TimelineSession.open(world.project, "main", client=world.client,
                                        outbox_path=world.tmp_path / "outbox.json")


@pytest.fixture
def requester_factory(tmp_path, astrid_importable):
    from runtime_protocol.daemon import RuntimeDaemon

    worlds = []

    def start(name, *, legacy=False):
        directory = tmp_path / name
        directory.mkdir()
        legacy_head = None
        project = None
        if legacy:
            from baseline_fixture import load_baseline_fixture

            historical, project, _ = load_baseline_fixture(directory, "empty")
            root = historical.store.root
            assert historical.store.conn is not None
            legacy_head = dict(historical.store.conn.execute(
                "SELECT revision_id, publication_id FROM parent_composition_heads WHERE timeline_id='main'",
            ).fetchone())
            assert legacy_head["publication_id"] is None
            historical.close()
        else:
            root = directory / "realm"
            RealmStore.initialize(root).close()
        daemon = RuntimeDaemon(root, support_root=directory / "support", authoring_profile="astrid").start()
        world = SimpleNamespace(daemon=daemon, service=daemon.service, root=root, tmp_path=directory)
        worlds.append(world)
        service = world.service
        if legacy:
            assert project is not None
            world.project = project
            world.legacy_head = legacy_head
        else:
            world.project = service.create_project({"slug": "publication", "name": "Publication"})["id"]
            service.create_timeline(world.project, "main", idempotency_key="canonical-create")
        capabilities = ("test.child", "rendering.assemble_timeline", "rendering.render")
        for capability in capabilities:
            service.register_capability({"capability_id": capability, "definition_digest": _digest(capability),
                                         "status": "ready"})
        service.register_executor({"executor_id": "worker", "capabilities": list(capabilities),
                                   "max_concurrency": 4}, idempotency_key="register-worker")
        _connect(world)
        return world

    try:
        yield start
    finally:
        for world in worlds:
            world.daemon.stop()


@pytest.fixture
def requester(requester_factory):
    return requester_factory("requester")



def _assembly(world, *, settle=True, publication: object = ...):
    from test_generation_publish_v1_settlement import _effect, _output

    service = world.service
    children, claims = [], []
    effect = _effect(world.project, groups=[{"group_key": "main", "selectors": [
        {"selector": "primary", "ordinal": 0, "variant_key": "primary", "output_port": "video"},
    ]}])
    effect["payload"]["metadata"] = {"params": {"duration_seconds": 1.0, "width": 16, "height": 16}}
    for index in range(2):
        admitted = world.client.tasks.create(
            project_id=world.project, capability="test.child", capability_digest=_digest("test.child"),
            spec={"index": index}, input_manifest=[], settlement_effect=effect,
            idempotency_key=f"child-{index}",
        )
        assert admitted.ok, admitted.as_dict()
        children.append(admitted.data["task_id"])
        claims.append(_claim(service, "test.child", f"claim-child-{index}"))
    for index in (1, 0):
        claim = claims[index]
        raw = f"visual-{index}".encode()
        service.settle_attempt(claim["attempt_id"], {
            **{key: claim[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "outputs": [_output(raw, output_port="video", group_key="main", variant_key="primary", ordinal=0,
                                name="primary", role="primary", is_primary=True, media_type="video/mp4",
                                duration_seconds=1.0)], "effect": effect,
        }, idempotency_key=f"settle-child-{index}")
    selectors = []
    for task in children:
        output, = service.managed_outputs(task)
        selectors.append({"association_id": output["association_id"], "object_id": output["object_id"],
                          "version": output["lifecycle"]["version"]})
    bundle = world.session._bundle(world.session._state())
    replace_clips = ["parent/clip:" + row["id"] for row in bundle["parent"]["clips"]]
    if publication is ...:
        admission = world.session.admit_assembly(
            selectors, replace_clips=replace_clips,
            assembler_digest=_digest("rendering.assemble_timeline"), idempotency_key="assembly",
        )
    else:
        from astrid.core.contracts.runtime_orchestration import (
            build_assembler_admission,
        )
        from astrid.sdk.timeline.assembly import capture_assembly

        capture = capture_assembly(world.session, world.session._state(), selectors, replace_clips=replace_clips)
        body = build_assembler_admission(capture=capture, assembler_digest=_digest("rendering.assemble_timeline"),
                                         idempotency_key="assembly").body
        body["spec"]["runtime_dependencies"]["publication"] = publication
        admitted = world.client.tasks.create(
            project_id=world.project, capability=body["capability_id"], capability_digest=body["capability_digest"],
            spec=body["spec"], input_manifest=body["input_object_ids"], storage_estimate=body["storage_estimate"],
            idempotency_key="assembly",
        )
        assert admitted.ok, admitted.as_dict()
        admission = admitted.as_dict()
    attempt = _claim(service, "rendering.assemble_timeline", "claim-assembly")
    assert attempt["task_id"] == admission["data"]["task_id"]
    return _produce(world, attempt, settle=settle, valid_admission=publication is ...)


def _produce(world, attempt, *, settle=True, valid_admission=True):
    from astrid.core.pack.entrypoint import canonical_runtime_entrypoint
    from astrid.sdk.timeline.assembly import read_assembly_proposal
    from test_generation_publish_v1_settlement import _output

    service = world.service
    spec = service.task(attempt["task_id"])["task"]["spec"]["spec"]
    capture = spec["inputs"]["resolved_children"]
    dependencies = spec["runtime_dependencies"]
    payload = {"family": spec["family"], "continuation_id": attempt["task_id"],
               "resolved_children": dependencies["resolved_children"], "edges": dependencies["edges"],
               "aggregation": dependencies["aggregation"], "capture": capture,
               "associations": [service.managed_output(row["association"]["association_id"])
                                for row in capture["children"]],
               "producer": {"task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"],
                            "executor_id": "worker", "fence": attempt["fence"],
                            "runtime_epoch": attempt["runtime_epoch"]}}
    with canonical_runtime_entrypoint("rendering.assemble_timeline"):
        from astrid.packs.rendering.actions.assemble_timeline.run import (
            build_authoring_proposal,
            build_native_proposal,
        )

    proposal = build_native_proposal(payload, build_authoring_proposal(payload))
    world.proposal, world.attempt = proposal, attempt
    if not settle:
        return proposal
    raw = canonical_json(proposal).encode()
    service.settle_attempt(attempt["attempt_id"], {
        **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
        "outputs": [_output(raw, output_port="authoring_proposal", group_key="default", variant_key="0",
                            ordinal=0, name="authoring_proposal", media_type="application/json")],
    }, idempotency_key="settle-assembly")
    if valid_admission:
        assert read_assembly_proposal(world.session, attempt["task_id"], attempt["attempt_id"]) == proposal
    world.proposal, world.attempt = proposal, attempt
    return proposal


def _publish(world, *, proposal=None, key="publish", **options):
    from astrid.packs.video_editing.shared.runtime_orchestration import (
        publish_stitched_render,
    )

    return publish_stitched_render(
        world.client, project=world.project, timeline_ref="main", expected_version=1,
        proposal=world.proposal if proposal is None else proposal, requester_session=world.session,
        render_capability_digest=_digest("rendering.render"), output_name="final.mp4",
        idempotency_key=key, **options,
    )


def _digest(value: str | bytes) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _claim(service, capability, key):
    return service.claim_next(
        {"executor_id": "worker", "capability_ids": [capability], "runtime_epoch": service.health()["runtime_epoch"]},
        idempotency_key=key,
    )


def _settle(service, attempt, key, value):
    raw = value.encode()
    return service.settle_attempt(
        attempt["attempt_id"],
        {"lease_id": attempt["lease_id"], "fence": attempt["fence"], "runtime_epoch": attempt["runtime_epoch"],
         "outputs": [{"digest": _digest(raw), "data_base64": base64.b64encode(raw).decode(),
                      "media_type": "video/mp4", "name": "primary", "role": "primary", "is_primary": True}]},
        idempotency_key=key,
    )


def test_publication_is_fenced_atomic_and_exactly_replayable(requester, monkeypatch):
    import copy
    import json

    from astrid.core.timeline.authoring_bundle import compile_authoring_candidate
    from astrid.sdk.timeline.commands import execute
    from astrid.sdk.workspace_client import WorkspaceClientError
    from test_timeline_render_publication_authority import _state

    world = requester
    authored_bundle = world.session._bundle(world.session._state())
    _assembly(world)
    assembly_spec = world.service.task(world.attempt["task_id"])["task"]["spec"]["spec"]
    verified_media = [child["verified_media"]
                      for child in assembly_spec["inputs"]["resolved_children"]["children"]]
    expected_bundle = execute(
        copy.deepcopy(authored_bundle), copy.deepcopy(world.proposal["commands"]),
        verified_media=verified_media,
    ).bundle
    expected_parent = compile_authoring_candidate(expected_bundle).publication["parent_composition"]
    steps = [{"id": "assembly", "label": "Ordered visuals", "intent": "Keep the original requester intent",
              "tags": ["assembly", "render"], "command_ordinals": list(range(len(world.proposal["commands"]) + 1)),
              "patch": [], "reads": []}]
    options = {"label": "Ordered visuals", "steps": steps, "merge": "fields", "reads": []}
    transport = world.client._remote._transport
    original = transport.commit_timeline
    requests = []

    def record_request(project, timeline, body, **kwargs):
        requests.append(copy.deepcopy(body))
        return original(project, timeline, body, **kwargs)

    monkeypatch.setattr(transport, "commit_timeline", record_request)
    before = _state(world.service), world.service.store.conn.total_changes
    preview = _publish(world, key="preview", dry_run=True, **options)
    assert preview["data"]["status"] == "preview"
    assert preview["data"]["would_status"] == "accepted"
    assert preview["receipt"] is None
    assert (_state(world.service), world.service.store.conn.total_changes) == before
    result = _publish(world, **options)
    sent = requests[-1]
    assert sent == {
        "api_version": 1, **world.proposal["admitted_target"], "commands": sent["commands"],
        "source": {"via": "python"}, "dry_run": False, "rationale": world.proposal["rationale"], **options,
    }
    assert sent["commands"][0]["op"] == "producer.guard"
    assert sent["commands"][1:] == world.proposal["commands"]
    assert result["data"]["status"] == "accepted"
    data, receipt = result["data"], result["receipt"]
    render = world.service.task(result["render_task_id"])["task"]
    params = render["spec"]["spec"]["params"]
    assert params["canonical_revision"] == {
        "project_id": world.project, "timeline_id": "main",
        "revision_id": data["accepted_revision_id"], "publication_id": receipt["receipt_id"],
        "content_digest": data["canonical_document"]["parent_revision"]["content_digest"],
    }
    assert params["output_name"] == "final.mp4"
    assert "timeline_snapshot" not in params
    accepted_parent = data["canonical_document"]["parent_revision"]
    assert accepted_parent["payload"]["config"] == expected_parent["config"]
    assert accepted_parent["payload"]["registry"] == expected_parent["registry"]
    durable_parent = world.service.store.conn.execute(
        "SELECT payload_json, content_digest FROM parent_composition_revisions WHERE id=?",
        (accepted_parent["revision_id"],),
    ).fetchone()
    assert (
        json.loads(durable_parent["payload_json"]) == expected_parent
        and durable_parent["content_digest"] == _digest(canonical_json(expected_parent))
        and params["canonical_revision"]["content_digest"] == durable_parent["content_digest"]
    )
    assert _publish(world, **options) == result
    assert world.service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_commit_history WHERE publication_id=?", (receipt["receipt_id"],),
    ).fetchone()[0] == 1
    assert world.service.store.conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'",
    ).fetchone()[0] == 1
    history = world.service._timeline_commits()[0].history_entry(world.project, "main", receipt["receipt_id"])
    assert history["steps"] == history["records"]["steps"] == data["steps"]
    assert history["receipt"] == receipt
    assert history["records"]["undo_steps"] is None
    assert any(record["bindings"] for record in history["records"]["commands"])
    assert any(record["writes"] for record in history["records"]["commands"])
    assert all(step["patch"] for step in data["steps"])
    changed = {**sent, "label": "Changed body under original key"}
    with pytest.raises(WorkspaceClientError) as error:
        transport.commit_timeline(world.project, "main", changed, idempotency_key="publish")
    assert error.value.details["reason"] == "idempotency_mismatch"
    world.service.cancel_task_canonical(world.attempt["task_id"], {}, idempotency_key="cancel-author")
    assert _publish(world, **options) == result


def _restart(world):
    from runtime_protocol.daemon import RuntimeDaemon

    world.daemon.stop()
    world.daemon = RuntimeDaemon(world.root, support_root=world.tmp_path / "support",
                                 authoring_profile="astrid").start()
    _connect(world)


def test_prepared_checkpoint_cannot_publish_after_cancel_or_stale_fence(requester_factory):
    import copy

    from astrid.sdk.workspace_client import WorkspaceClientError
    from test_timeline_render_publication_authority import _state

    stale = requester_factory("stale")
    _assembly(stale)
    proposal = copy.deepcopy(stale.proposal)
    proposal["producer"]["fence"] += 1
    before = _state(stale.service)
    with pytest.raises(WorkspaceClientError) as error:
        _publish(stale, proposal=proposal)
    assert error.value.details["reason"] in {"producer_attempt_mismatch", "producer_dependency_unavailable"}
    assert _state(stale.service) == before

    cancelled = requester_factory("cancelled")
    _assembly(cancelled, settle=False)
    with pytest.raises(WorkspaceClientError):
        _publish(cancelled)
    # A refused publication releases its flight into ``rejected`` (Agent f31564fd0,
    # bca403b02); the prepared checkpoint is retained there, not as a live flight.
    assert cancelled.session._state()["flight"] is None
    checkpoint = cancelled.session._state()["rejected"]["flight"].copy()
    cancelled.service.cancel_task_canonical(cancelled.attempt["task_id"], {}, idempotency_key="cancel-at-seam")
    before = _state(cancelled.service)
    with pytest.raises(LeaseError):
        _produce(cancelled, cancelled.attempt)
    with pytest.raises(WorkspaceClientError):
        _publish(cancelled)
    assert cancelled.session._state()["flight"] is None
    # The refused retry rebuilds the same request under a fresh random fence.
    retried = cancelled.session._state()["rejected"]["flight"]
    assert {key: value for key, value in retried.items() if key != "fence"} == {
        key: value for key, value in checkpoint.items() if key != "fence"}
    assert _state(cancelled.service) == before
    assert cancelled.service.store.conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'",
    ).fetchone()[0] == 0


def test_prepared_checkpoint_resumes_on_retried_attempt_after_runtime_restart(requester, monkeypatch):
    import copy

    from astrid.sdk.workspace_client import WorkspaceClientError

    world = requester
    _assembly(world, settle=False)
    original_target = world.proposal["admitted_target"].copy()
    old_attempt = world.attempt.copy()
    original_base = world.session._state()["base"].copy()
    _restart(world)
    world.service.register_executor({
        "executor_id": "worker", "capabilities": ["test.child", "rendering.assemble_timeline", "rendering.render"],
        "max_concurrency": 4, "runtime_epoch": world.service.health()["runtime_epoch"],
    }, idempotency_key="register-after-restart")
    recovered = _claim(world.service, "rendering.assemble_timeline", "reclaim-author")
    assert recovered["task_id"] == old_attempt["task_id"]
    assert recovered["attempt_id"] != old_attempt["attempt_id"]
    assert recovered["fence"] > old_attempt["fence"]
    assert recovered["runtime_epoch"] > old_attempt["runtime_epoch"]
    with pytest.raises(LeaseError):
        _produce(world, old_attempt)
    _produce(world, recovered)
    assert world.proposal["admitted_target"] == original_target
    assert world.session._state()["base"] == original_base
    transport = world.client._remote._transport
    original = transport.commit_timeline
    raw_first = []

    def commit_then_lose_ack(*args, **kwargs):
        response = original(*args, **kwargs)
        raw_first.append(copy.deepcopy(response))
        raise WorkspaceClientError(503, "unavailable", "lost commit acknowledgement", {})

    monkeypatch.setattr(transport, "commit_timeline", commit_then_lose_ack)
    # The client reports an unverifiable commit outcome in its own words (Agent ae620ee55).
    with pytest.raises(WorkspaceClientError, match="No reply could be verified; this edit may or may not have been committed"):
        _publish(world)
    flight = world.session._state()["flight"].copy()
    assert flight["key"] == "publish"
    _restart(world)
    assert world.session._state()["flight"] == flight
    retry_transport = world.client._remote._transport
    retry_original = retry_transport.commit_timeline
    raw_retry = []

    def record_retry(*args, **kwargs):
        response = retry_original(*args, **kwargs)
        raw_retry.append(copy.deepcopy(response))
        return response

    monkeypatch.setattr(retry_transport, "commit_timeline", record_retry)
    result = _publish(world)
    assert len(raw_first) == len(raw_retry) == 1
    first_raw, retry_raw = raw_first[0], raw_retry[0]
    assert retry_raw == first_raw
    assert retry_raw["data"] == first_raw["data"]
    assert retry_raw["receipt"] == first_raw["receipt"]
    public_data = {
        **retry_raw["data"],
        "accepted_publication_id": retry_raw["receipt"]["receipt_id"],
        "show_command": (
            f"astrid timelines show main --project {world.project} --published --revision-id "
            f"{retry_raw['data']['accepted_revision_id']}"
        ),
        # The client now reports a confirmed retry as a structured outcome (Agent f31564fd0).
        "confirmed": True,
        "replayed": False,
        "summary": (f'Confirmed "Assemble timeline" as {retry_raw["receipt"]["receipt_id"]}; '
                    "the earlier request was applied once."),
        "undo": {"publications": [retry_raw["receipt"]["receipt_id"]]},
    }
    assert set(result) == {"ok", "data", "error", "receipt", "idempotency_key", "render", "render_task_id"}
    assert result["ok"] is True
    assert result["error"] is None
    assert result["idempotency_key"] == "publish"
    assert result["data"] == public_data
    assert result["receipt"] == retry_raw["receipt"]
    render = world.service.task(result["render_task_id"])["task"]
    assert render["spec"]["spec"]["params"]["canonical_revision"] == {
        "project_id": world.project,
        "timeline_id": "main",
        "revision_id": result["data"]["accepted_revision_id"],
        "publication_id": result["receipt"]["receipt_id"],
        "content_digest": result["data"]["canonical_document"]["parent_revision"]["content_digest"],
    }
    # Re-reading the settled publication is no longer a confirmation of a lost reply.
    assert _publish(world) == {**result, "data": {
        **result["data"], "confirmed": False,
        "summary": f'Committed "Assemble timeline" as {result["receipt"]["receipt_id"]}.'}}
    assert world.service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_commit_history WHERE publication_id=?", (result["receipt"]["receipt_id"],),
    ).fetchone()[0] == 1
    assert world.service.store.conn.execute(
        "SELECT COUNT(*) FROM tasks WHERE capability='rendering.render'",
    ).fetchone()[0] == 1
