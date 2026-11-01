"""Settled image/video authority through real service capture and acceptance.

The prepared provider tests Runtime acceptance, not Agent placement semantics.
SQL faults below are corruption probes, separate from normal API transitions.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta

import pytest

from runtime_protocol import store as store_module
from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, RuntimeErrorBase
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json
from test_generation_publish_v1_settlement import CAPABILITY, _digest, _output, _settle
from test_timeline_commit_port import PreparedProvider, commit, request, use_provider
from test_timeline_media_selection import _capture, _prepared_media_candidate
import test_timeline_verified_media as media_support
from test_timeline_verified_media import settle_media, snapshot


settled_media_bytes = media_support.settled_media_bytes


@pytest.fixture
def media(tmp_path, settled_media_bytes):
    provider = PreparedProvider()
    service, project, outputs = settle_media(tmp_path, settled_media_bytes, provider=provider)
    service.test_provider = provider
    try:
        yield service, project, outputs
    finally:
        service.close()


def _request(service, project, selection):
    service.test_project = project
    body = request(service)
    body["commands"][0].update(op="fixture.inspect", args={"selection": selection})
    return body


def _provider(selection, *, before_capture=None, before_accept=None):
    def action(context, port):
        if before_capture:
            before_capture()
        candidate, _ = _prepared_media_candidate(context, port, selection)
        if before_accept:
            before_accept()
        return port.accept(candidate)
    return PreparedProvider(action)


def _retry(service, output, *, claim=False):
    task = service.task(output["task_id"])["task"]
    service.retry_task(output["task_id"], idempotency_key="retry-media")
    if not claim:
        return
    service.register_executor({"executor_id": "replacement-worker", "capabilities": [CAPABILITY]},
                              idempotency_key="register-replacement")
    newer = service.claim_next({"executor_id": "replacement-worker", "capability_ids": [CAPABILITY],
                               "runtime_epoch": service.health()["runtime_epoch"]},
                              idempotency_key="replacement-claim")
    assert newer["task_id"] == task["id"] and newer["attempt_id"] != output["attempt_id"]
    assert newer["fence"] > task["lease_fence"]


def _api_invalidation(service, output, change):
    if change in {"retry", "replacement", "retry-cancel"}:
        _retry(service, output, claim=change == "replacement")
        if change == "retry-cancel":
            service.cancel_task_canonical(output["task_id"], idempotency_key="cancel-retry")
            assert service.task(output["task_id"])["task"]["status"] == "cancelled"
    else:
        service.update_managed_output_lifecycle(output["association_id"], {
            "operation": change, "expected_version": 1,
            **({"lease_seconds": 60} if change == "lease" else {}),
        }, idempotency_key="change-output")


@pytest.mark.parametrize("name", ["image", "old"], ids=["image", "video"])
@pytest.mark.parametrize("phase", ["capture", "acceptance"])
@pytest.mark.parametrize("change", ["retry", "replacement", "retry-cancel",
                                   "promote", "pin", "lease"])
def test_normal_api_invalidation_refuses_original_pin_without_writes(media, name, phase, change):
    service, project, outputs = media
    output = outputs[name]
    selection = _capture(service, project, output)
    original = copy.deepcopy(selection)
    body = _request(service, project, selection)
    before = None

    def invalidate():
        nonlocal before
        _api_invalidation(service, output, change)
        before = snapshot(service)
        with pytest.raises(RuntimeErrorBase) as error:
            service.get_project_verified_media(project, selection, authorize=lambda: None)
        assert error.value.status in {404, 409}
        assert snapshot(service) == before

    provider = use_provider(service, _provider(selection, **{
        "before_capture" if phase == "capture" else "before_accept": invalidate,
    }))
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, body, key="invalidated-media")
    assert error.value.status in {404, 409}
    assert provider.calls == 1 and before is not None
    assert selection == original
    assert snapshot(service) == before
    assert service.store.conn.execute(
        "SELECT COUNT(*) FROM timeline_commit_history WHERE intent='recorded'",
    ).fetchone()[0] == 0


def _corrupt(service, project, output, selection, change):
    conn = service.store.conn
    if change == "current-attempt":
        conn.execute("UPDATE tasks SET attempt_id=NULL WHERE id=?", (output["task_id"],))
    elif change == "not-completed":
        conn.execute("UPDATE tasks SET status='failed' WHERE id=?", (output["task_id"],))
    elif change == "unsettled":
        conn.execute("UPDATE attempts SET settled=0 WHERE id=?", (output["attempt_id"],))
    elif change in {"executor", "fence", "epoch"}:
        column = {"executor": "executor_id", "fence": "fence", "epoch": "runtime_epoch"}[change]
        value = "foreign-worker" if change == "executor" else 999
        conn.execute(f"UPDATE attempts SET {column}=? WHERE id=?", (value, output["attempt_id"]))
    elif change == "provenance":
        conn.execute("UPDATE managed_output_associations SET provenance_json='{}' WHERE association_id=?",
                     (output["association_id"],))
    elif change == "result":
        conn.execute("UPDATE tasks SET result_json='{}' WHERE id=?", (output["task_id"],))
    elif change == "catalog":
        row = conn.execute("SELECT metadata_json FROM generations WHERE id=?",
                           (selection["generation_id"],)).fetchone()
        metadata = json.loads(row[0])
        metadata["params"]["duration_seconds"] = 3
        conn.execute("UPDATE generations SET metadata_json=? WHERE id=?",
                     (json.dumps(metadata), selection["generation_id"]))
    elif change == "ownership":
        conn.execute("DELETE FROM project_objects WHERE project_id=? AND digest=? AND relation='managed'",
                     (project, selection["object_id"][7:]))
    elif change == "scope":
        conn.execute("UPDATE managed_output_associations SET project_id=NULL WHERE association_id=?",
                     (output["association_id"],))
    conn.commit()


@pytest.mark.parametrize("name", ["image", "old"], ids=["image", "video"])
@pytest.mark.parametrize("phase", ["capture", "acceptance"])
@pytest.mark.parametrize("change", ["current-attempt", "not-completed", "unsettled", "executor", "fence",
                                   "epoch", "provenance", "result", "catalog", "ownership", "scope"])
def test_corrupt_settlement_refuses_without_writes(media, name, phase, change):
    service, project, outputs = media
    output = outputs[name]
    selection = _capture(service, project, output)
    body = _request(service, project, selection)
    before = None

    def corrupt():
        nonlocal before
        _corrupt(service, project, output, selection, change)
        before = snapshot(service)

    use_provider(service, _provider(selection, **{
        "before_capture" if phase == "capture" else "before_accept": corrupt,
    }))
    with pytest.raises(RuntimeErrorBase) as error:
        commit(service, body, key="corrupt-media")
    assert error.value.status in {404, 409}
    assert before is not None and snapshot(service) == before


@pytest.mark.parametrize("name", ["image", "old"], ids=["image", "video"])
@pytest.mark.parametrize("change", ["completed-cancel", "boot", "executor-refresh", "viewed", "unrelated-output"])
def test_completed_authority_survives_noninvalidating_api_changes(media, name, change):
    service, project, outputs = media
    output = outputs[name]
    selection = _capture(service, project, output)
    body = _request(service, project, selection)

    def change_after_capture():
        task = service.task(output["task_id"])["task"]
        if change == "completed-cancel":
            service.cancel_task_canonical(task["id"], idempotency_key="cancel-completed")
        elif change == "boot":
            # The actual restart recovery transaction, between port capture and accept.
            service.store.begin_runtime_session("next-boot")
            assert service.store._current_runtime_epoch() > task["runtime_epoch"]
        elif change == "executor-refresh":
            service.register_executor({"executor_id": task["executor_id"], "capabilities": [],
                                       "runtime_epoch": service.health()["runtime_epoch"]},
                                      idempotency_key="refresh-completed-executor")
        elif change == "viewed":
            service.mark_variant_viewed(selection["variant_id"], idempotency_key="view-media")
        else:
            service.update_managed_output_lifecycle(outputs["new"]["association_id"], {
                "operation": "pin", "expected_version": 1,
            }, idempotency_key="pin-other-output")
        assert service.task(task["id"])["task"] == task
        before = snapshot(service)
        assert service.get_project_verified_media(project, selection, authorize=lambda: None)["selection"] == selection
        assert snapshot(service) == before

    use_provider(service, _provider(selection, before_accept=change_after_capture))
    assert commit(service, body)["data"]["status"] == "accepted"


@pytest.mark.parametrize("name", ["image", "old"], ids=["image", "video"])
def test_completed_lease_deadline_is_historical_not_live_authority(media, name, monkeypatch):
    service, project, outputs = media
    selection = _capture(service, project, outputs[name])
    body = _request(service, project, selection)

    def advance_clock():
        class Later(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(days=1)
        monkeypatch.setattr(store_module, "datetime", Later)
        attempt = service.store.conn.execute("SELECT * FROM attempts WHERE id=?",
                                              (outputs[name]["attempt_id"],)).fetchone()
        assert Later.fromisoformat(attempt["lease_expires_at"]) < Later.now().astimezone()
        before = snapshot(service)
        service.store.reap_overdue_leases()
        assert service.task(outputs[name]["task_id"])["task"]["status"] == "completed"
        assert snapshot(service) == before

    use_provider(service, _provider(selection, before_accept=advance_clock))
    assert commit(service, body)["data"]["status"] == "accepted"


@pytest.mark.parametrize("operation", ["heartbeat", "fail", "settle"])
def test_worker_cannot_mutate_a_completed_attempt_between_capture_and_acceptance(media, operation):
    service, project, outputs = media
    output = outputs["image"]
    selection = _capture(service, project, output)
    body = _request(service, project, selection)

    def worker_request():
        attempt = service.store.conn.execute("SELECT * FROM attempts WHERE id=?",
                                              (output["attempt_id"],)).fetchone()
        lease = {"lease_id": attempt["lease_id"], "fence": attempt["fence"],
                 "runtime_epoch": attempt["runtime_epoch"]}
        before = snapshot(service)
        with pytest.raises(LeaseError):
            if operation == "heartbeat":
                service.heartbeat_attempt(attempt["id"], lease, idempotency_key="late-heartbeat")
            elif operation == "fail":
                service.fail_attempt(attempt["id"], {**lease, "error": {"code": "late"}},
                                     idempotency_key="late-fail")
            else:
                service.settle_attempt(attempt["id"], {**lease, "outputs": []},
                                       idempotency_key="late-settle")
        assert snapshot(service) == before

    use_provider(service, _provider(selection, before_accept=worker_request))
    assert commit(service, body)["data"]["status"] == "accepted"


@pytest.mark.parametrize("name", ["image", "old"], ids=["image", "video"])
def test_new_primary_variant_does_not_reselect_captured_media(media, name):
    service, project, outputs = media
    selection = _capture(service, project, outputs[name])
    body = _request(service, project, selection)
    effect = {"effect_type": "generation.variant.append", "target_id": selection["generation_id"],
              "expected_version": 1, "payload": {"source_variant_id": selection["variant_id"],
                  "source_object_id": selection["object_id"], "variant_type": "edited",
                  "output_name": "edited", "output_ordinal": 0, "primary_policy": "promote"}}

    def append():
        service.create_task({"project": project, "capability_id": CAPABILITY,
            "capability_digest": _digest(CAPABILITY.encode()), "input_object_ids": [selection["object_id"]],
            "settlement_effect": effect, "idempotency_key": "append-task"})
        task = service.task(outputs[name]["task_id"])["task"]
        attempt = service.claim_next({"executor_id": task["executor_id"], "capability_ids": [CAPABILITY],
                                      "runtime_epoch": service.health()["runtime_epoch"]},
                                     idempotency_key="append-claim")
        data = service.cas.read(selection["object_id"][7:])
        _settle(service, attempt, [_output(data, name="edited", output_port="edited", group_key="default",
            variant_key="0", ordinal=0, media_type="image/png" if name == "image" else "video/mp4")],
            effect=effect, key="append-settle")
        assert service.get_generation(selection["generation_id"])["version"] == 2
        assert service.get_project_verified_media(project, selection, authorize=lambda: None)["selection"] == selection

    use_provider(service, _provider(selection, before_accept=append))
    assert commit(service, body)["data"]["status"] == "accepted"


@pytest.mark.parametrize("modality", ["image", "video"])
@pytest.mark.parametrize("retry", [False, True], ids=["accept", "retry-refuses"])
def test_single_variant_completion_uses_the_same_fence(tmp_path, settled_media_bytes, modality, retry):
    def effect(project):
        return {"effect_type": "generation.create_with_variant", "target_id": project,
                "payload": {"generation_type": modality, "metadata": {"params": {"duration_seconds": 2}},
                    "variant_type": "original", "output_name": "visual", "output_ordinal": 0,
                    "primary_policy": "preserve"}}

    root = tmp_path / "single-variant"
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    try:
        provider = PreparedProvider()
        service.register_timeline_commit_provider(provider)
        service.test_provider = provider
        project = service.create_project({"slug": "single", "name": "Single variant"})
        service.register_executor({"executor_id": "single-worker", "capabilities": [CAPABILITY]},
                                  idempotency_key="single-executor")
        data = settled_media_bytes["image" if modality == "image" else "old"]
        source = service.ingest(project["id"], data,
            media_type="image/png" if modality == "image" else "video/mp4",
            idempotency_key="single-input")["data"]["digest"]
        effect = effect(project["id"])
        service.create_task({"project": project["id"], "capability_id": CAPABILITY,
            "capability_digest": _digest(CAPABILITY.encode()), "input_object_ids": [source],
            "settlement_effect": effect, "idempotency_key": "single-task"})
        attempt = service.claim_next({"executor_id": "single-worker", "capability_ids": [CAPABILITY],
                                      "runtime_epoch": service.health()["runtime_epoch"]},
                                     idempotency_key="single-claim")
        _settle(service, attempt, [_output(settled_media_bytes["image" if modality == "image" else "old"],
            name="visual", output_port="visual", group_key="default", variant_key="0", ordinal=0,
            media_type="image/png" if modality == "image" else "video/mp4")], effect=effect)
        service.create_timeline(project["id"], "main", idempotency_key="create-main")
        output, = service.managed_outputs(attempt["task_id"])
        selection = _capture(service, project["id"], output)
        body = _request(service, project["id"], selection)
        before = None

        def invalidate():
            nonlocal before
            _retry(service, output)
            before = snapshot(service)

        use_provider(service, _provider(selection, before_accept=invalidate if retry else None))
        if retry:
            with pytest.raises(ConflictError):
                commit(service, body)
            assert snapshot(service) == before
        else:
            assert commit(service, body)["data"]["status"] == "accepted"
    finally:
        service.close()


def test_authorization_revocation_between_capture_and_acceptance_writes_nothing(media):
    service, project, outputs = media
    selection = _capture(service, project, outputs["image"])
    body = _request(service, project, selection)
    revoked, before = False, None

    def authorize():
        if revoked:
            raise AuthorizationError("project authority revoked")

    def revoke():
        nonlocal revoked, before
        revoked = True
        before = snapshot(service)

    use_provider(service, _provider(selection, before_accept=revoke))
    with pytest.raises(AuthorizationError, match="project authority revoked"):
        commit(service, body, authorize=authorize)
    assert before is not None and snapshot(service) == before


@pytest.mark.parametrize("name", ["image", "old"], ids=["image", "video"])
def test_original_selection_accepts_after_restart_then_exact_replay_precedes_invalidated_reads(media, name):
    service, project, outputs = media
    output = outputs[name]
    selection = _capture(service, project, output)
    body = _request(service, project, selection)
    root, epoch = service.store.root, service.health()["runtime_epoch"]
    service.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        assert restarted.health()["runtime_epoch"] > epoch
        provider = _provider(selection)
        restarted.register_timeline_commit_provider(provider)
        accepted = commit(restarted, body, key="original-media")
        assert accepted["data"]["status"] == "accepted"
        assert provider.calls == 1
        _retry(restarted, output)
    finally:
        restarted.close()
    restarted = RuntimeService(root)
    try:
        restarted.test_project = project
        provider = _provider(selection)
        restarted.register_timeline_commit_provider(provider)
        before = snapshot(restarted)
        assert canonical_json(commit(restarted, body, key="original-media")) == canonical_json(accepted)
        assert provider.calls == 0 and snapshot(restarted) == before
        changed = copy.deepcopy(body)
        changed["rationale"] = "changed retry payload"
        with pytest.raises(RuntimeErrorBase) as error:
            commit(restarted, changed, key="original-media")
        assert error.value.details["reason"] == "idempotency_mismatch"
        assert provider.calls == 0 and snapshot(restarted) == before
        with pytest.raises(ConflictError):
            commit(restarted, body, key="fresh-stale-media")
        assert provider.calls == 1 and snapshot(restarted) == before
    finally:
        restarted.close()
