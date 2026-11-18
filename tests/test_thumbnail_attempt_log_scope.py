"""Thumbnail job logs keep immutable identities across ordinary task retries."""
from __future__ import annotations

import base64
from copy import deepcopy

import pytest

from astrid_runtime_client import ApiError
from tests.test_generation_thumbnail_settlement import CAPABILITY
from tests.test_thumbnail_attach_log_boundary import (
    _assert_rejected_without_publication,
    _settle_http,
    attachment,
)


def _scoped_logs(attachment, attempt_id):
    return [
        {**deepcopy(log), "group_key": f"thumbnail-attempt:{attempt_id}"}
        for log in attachment.logs
    ]


def _assert_log_custody(attachment, rows, attempt):
    assert len(rows) == 2
    by_name = {row["variant_key"]: row for row in rows}
    assert set(by_name) == {"job.stdout", "job.stderr"}
    for expected in attachment.logs:
        row = by_name[expected["name"]]
        assert row["task_id"] == attachment.task_id
        assert row["attempt_id"] == attempt["attempt_id"]
        assert row["project_id"] == attachment.project["id"]
        assert row["group_key"] == f"thumbnail-attempt:{attempt['attempt_id']}"
        assert row["role"] == "log" and row["output_port"] == "logs"
        assert row["filename"] == expected["filename"]
        assert row["durability"] == "durable" and row["media_type"] == "text/plain"
        assert row["object_id"] == expected["digest"] and row["size"] == expected["size"]
        assert row["provenance"]["task_id"] == attachment.task_id
        assert row["provenance"]["attempt_id"] == attempt["attempt_id"]
        assert row["provenance"]["fence"] == attempt["fence"]
        assert row["provenance"]["runtime_epoch"] == attempt["runtime_epoch"]
        assert row["provenance"]["executor_id"] == "thumbnail-log-worker"
        assert row["provenance"]["capability_id"] == CAPABILITY
        assert attachment.service.cas.path_for(expected["digest"].removeprefix("sha256:")).read_bytes() == base64.b64decode(expected["data_base64"])


def _assert_success_and_replay(attachment, *, prior_logs=()):
    logs = _scoped_logs(attachment, attachment.attempt["attempt_id"])
    outputs = [logs[0], attachment.thumbnail, logs[1]]
    first = _settle_http(attachment, outputs)
    assert first["state"] == "succeeded"
    associations = attachment.service.managed_outputs(attachment.task_id)
    assert len(associations) == len(prior_logs) + 3
    prior_ids = {row["association_id"] for row in prior_logs}
    assert {row["association_id"]: row for row in associations if row["association_id"] in prior_ids} == {
        row["association_id"]: row for row in prior_logs
    }
    current_logs = [row for row in associations if row["role"] == "log" and row["attempt_id"] == attachment.attempt["attempt_id"]]
    _assert_log_custody(attachment, current_logs, attachment.attempt)
    thumbnail, = [row for row in associations if row["role"] == "thumbnail"]
    assert thumbnail["attempt_id"] == attachment.attempt["attempt_id"]
    assert thumbnail["object_id"] == attachment.thumbnail["digest"]
    assert thumbnail["generation_id"] == attachment.seeded["generation_id"]
    assert attachment.service.cas.path_for(attachment.thumbnail["digest"].removeprefix("sha256:")).read_bytes() == base64.b64decode(attachment.thumbnail["data_base64"])
    generation = attachment.service.get_generation(attachment.seeded["generation_id"])
    assert generation["version"] == 2
    assert generation["source_task_id"] == attachment.generation_before["source_task_id"]
    assert generation["metadata"]["shot_id"] == attachment.generation_before["metadata"]["shot_id"]
    assert generation["metadata"]["thumbnail"] == {
        "object_id": attachment.thumbnail["digest"],
        "source_object_id": attachment.seeded["source_object_id"],
        "recipe_version": 1,
    }
    assert attachment.service.list_variants(attachment.seeded["generation_id"])["items"] == attachment.variants_before
    replay = _settle_http(attachment, outputs)
    assert replay == first
    assert attachment.service.managed_outputs(attachment.task_id) == associations
    assert attachment.service.get_generation(attachment.seeded["generation_id"]) == generation


def _fail_and_owner_retry(attachment):
    previous = dict(attachment.attempt)
    failed = attachment.client.fail_attempt(
        previous["attempt_id"],
        **{name: previous[name] for name in ("lease_id", "fence", "runtime_epoch")},
        error={"code": "thumbnail_extraction_failed", "message": "decoder refused"},
        outputs=_scoped_logs(attachment, previous["attempt_id"]),
        idempotency_key="thumbnail-attempt-failed",
    )
    assert failed.state == "failed"
    saved = deepcopy(attachment.service.managed_outputs(attachment.task_id))
    _assert_log_custody(attachment, saved, previous)
    assert attachment.service.get_generation(attachment.seeded["generation_id"]) == attachment.generation_before
    task = attachment.client.get_task(attachment.task_id)
    assert task.state == "failed" and task.attempt_id == previous["attempt_id"]
    # The scoped worker cannot grant itself a retry. The fixture's owner-side
    # service uses the normal version-checked task transition, as in the
    # existing durable-thumbnail tests; no task/attempt rows are rewritten.
    with pytest.raises(ApiError) as denied:
        attachment.client.retry_task(attachment.task_id, expected_version=task.version,
                                     idempotency_key="worker-cannot-retry-thumbnail")
    assert denied.value.status == 401
    assert denied.value.code == "unauthorized"
    assert denied.value.message == "credential lacks required scope"
    assert denied.value.details == {"scope": "tasks:write"}
    retried = attachment.service.retry_task(
        attachment.task_id, {"expected_version": task.version}, idempotency_key="owner-retry-thumbnail",
    )
    assert retried["data"]["task_id"] == attachment.task_id
    current = attachment.service.claim_next(
        {"executor_id": "thumbnail-log-worker", "capability_ids": [CAPABILITY],
         "runtime_epoch": attachment.service.health()["runtime_epoch"]},
        idempotency_key="thumbnail-retry-claim",
    )
    assert current["task_id"] == attachment.task_id
    assert current["attempt_id"] != previous["attempt_id"]
    assert current["fence"] > previous["fence"]
    assert attachment.service.managed_outputs(attachment.task_id) == saved
    attachment.attempt = current
    return previous, saved


def test_current_attempt_thumbnail_logs_succeed_with_owned_custody_and_replay(attachment):
    _assert_success_and_replay(attachment)


@pytest.mark.parametrize("scope", ["foreign_attempt", "empty_suffix", "extra_suffix"])
def test_thumbnail_log_scope_rejects_foreign_or_malformed_attempt_over_http(attachment, scope):
    current = attachment.attempt["attempt_id"]
    if scope == "foreign_attempt":
        primary = attachment.service.store.get_task(attachment.seeded["task"]["task"]["id"])["task"]
        assert primary["attempt_id"] and primary["attempt_id"] != current
        group = f"thumbnail-attempt:{primary['attempt_id']}"
    elif scope == "empty_suffix":
        group = "thumbnail-attempt:"
    else:
        group = f"thumbnail-attempt:{current}:extra"
    logs = deepcopy(attachment.logs)
    logs[0]["group_key"] = group
    _assert_rejected_without_publication(attachment, [attachment.thumbnail, *logs])


def test_duplicate_stdout_across_default_and_current_scope_is_rejected_over_http(attachment):
    logs = _scoped_logs(attachment, attachment.attempt["attempt_id"])
    duplicate = {**deepcopy(attachment.logs[0]), "group_key": "default"}
    _assert_rejected_without_publication(attachment, [attachment.thumbnail, *logs, duplicate])


def test_previous_real_attempt_scope_is_rejected_after_owner_retry_without_publication(attachment):
    previous, saved = _fail_and_owner_retry(attachment)
    outputs = [attachment.thumbnail, *_scoped_logs(attachment, previous["attempt_id"])]
    objects_before = [dict(row) for row in attachment.service.store.conn.execute("SELECT * FROM objects ORDER BY digest")]
    with pytest.raises(ApiError) as rejected:
        _settle_http(attachment, outputs, key="previous-attempt-scope")
    assert rejected.value.status == 422
    current = attachment.service.store.get_task(attachment.task_id)["task"]
    assert current["status"] == "running" and current["attempt_id"] == attachment.attempt["attempt_id"]
    assert attachment.service.get_generation(attachment.seeded["generation_id"]) == attachment.generation_before
    assert attachment.service.list_variants(attachment.seeded["generation_id"])["items"] == attachment.variants_before
    assert attachment.service.managed_outputs(attachment.task_id) == saved
    assert [dict(row) for row in attachment.service.store.conn.execute("SELECT * FROM objects ORDER BY digest")] == objects_before
    assert not attachment.service.cas.path_for(attachment.thumbnail["digest"].removeprefix("sha256:")).exists()
    _assert_log_custody(attachment, saved, previous)


def test_owner_retry_keeps_old_logs_immutable_and_publishes_current_attempt_logs(attachment):
    previous, saved = _fail_and_owner_retry(attachment)
    _assert_success_and_replay(attachment, prior_logs=saved)
    _assert_log_custody(attachment, saved, previous)
    primary = attachment.service.store.get_task(attachment.seeded["task"]["task"]["id"])["task"]
    assert primary["status"] == "completed"
    assert attachment.service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
    assert attachment.service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 2
