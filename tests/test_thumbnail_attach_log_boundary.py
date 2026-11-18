"""HTTP thumbnail settlement admits only the thumbnail and canonical job logs."""
from __future__ import annotations

import base64
from copy import deepcopy
from types import SimpleNamespace

import pytest

from astrid_runtime_client import ApiError, WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.store import RealmStore
from tests.test_generation_thumbnail_settlement import (
    CAPABILITY, _output, _seed_generation, _task, _thumbnail,
)


# A decoder-verified 1x1 JPEG. Keeping the fixture bytes inline adds no image
# decoder dependency to Runtime's settlement tests.
JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof"
    "Hh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwh"
    "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy"
    "MjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAb/xAAUEAEAAAAAAAAA"
    "AAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAABv/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAM"
    "AwEAAhEDEQA/AIcAlH3/2Q=="
)


def _job_log(name: str) -> dict:
    value = _output(
        f"{name}: thumbnail job finished\n".encode(), name=name,
        media_type="text/plain", output_port="logs", variant_key=name, role="log",
    )
    value.update(filename=name + ".log", durability="durable")
    return value


@pytest.fixture
def attachment(tmp_path):
    realm = tmp_path / "realm"
    RealmStore.initialize(realm).close()
    daemon = RuntimeDaemon(realm, support_root=tmp_path / "support").start()
    try:
        service = daemon.service
        executor = "thumbnail-log-worker"
        service.register_executor(
            {"executor_id": executor, "capabilities": [CAPABILITY]}, idempotency_key="executor",
        )
        project = service.create_project(
            {"slug": "thumbnail-log-boundary", "name": "Thumbnail log boundary"}, idempotency_key="project",
        )
        seeded = _seed_generation(service, project, key="primary", with_thumbnail=False)
        effect = {
            "effect_type": "generation.thumbnail.attach",
            "target_id": seeded["generation_id"], "expected_version": 1,
            "payload": {"source_object_id": seeded["source_object_id"], "output_name": "thumbnail.jpg",
                        "output_ordinal": 0, "recipe_version": 1},
        }
        task, attempt = _task(
            service, project["id"], effect, key="thumbnail-task", inputs=[seeded["source_object_id"]],
        )
        token, _ = daemon.credentials.provision(executor, ["handshake", "worker:execute", "tasks:read"])
        thumbnail = _thumbnail(JPEG, [seeded["source_object_id"]])
        thumbnail["filename"] = "thumbnail.jpg"
        yield SimpleNamespace(
            service=service, client=WorkspaceClient(daemon.endpoint, token), project=project,
            seeded=seeded, effect=effect, task_id=task["task"]["id"], attempt=attempt,
            thumbnail=thumbnail, logs=[_job_log("job.stdout"), _job_log("job.stderr")],
            generation_before=service.get_generation(seeded["generation_id"]),
            variants_before=service.list_variants(seeded["generation_id"])["items"],
        )
    finally:
        daemon.stop()


def _settle_http(attachment, outputs, *, key="thumbnail-settle"):
    attempt = attachment.attempt
    return attachment.client.settle_attempt(
        attempt["attempt_id"],
        {**{name: attempt[name] for name in ("lease_id", "fence", "runtime_epoch")},
         "effect": attachment.effect, "outputs": outputs},
        idempotency_key=key,
    )


def _assert_rejected_without_publication(attachment, outputs):
    with pytest.raises(ApiError) as rejected:
        _settle_http(attachment, outputs)
    assert rejected.value.status == 422
    service = attachment.service
    assert service.store.get_task(attachment.task_id)["task"]["status"] == "running"
    assert service.get_generation(attachment.seeded["generation_id"]) == attachment.generation_before
    assert service.list_variants(attachment.seeded["generation_id"])["items"] == attachment.variants_before
    assert service.managed_outputs(attachment.task_id) == []
    for digest in {output["digest"].removeprefix("sha256:") for output in outputs}:
        assert service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone() is None
        assert not service.cas.path_for(digest).exists()


def test_thumbnail_attach_accepts_one_jpeg_with_durable_stdout_and_stderr_over_http(attachment):
    outputs = [attachment.logs[0], attachment.thumbnail, attachment.logs[1]]
    first = _settle_http(attachment, outputs)
    assert first["state"] == "succeeded"
    replay = _settle_http(attachment, outputs)
    assert replay["state"] == "succeeded"
    service = attachment.service
    assert service.store.get_task(attachment.task_id)["task"]["status"] == "completed"
    generation = service.get_generation(attachment.seeded["generation_id"])
    assert generation["version"] == 2
    assert generation["source_task_id"] == attachment.generation_before["source_task_id"]
    assert generation["metadata"]["shot_id"] == attachment.generation_before["metadata"]["shot_id"]
    assert generation["metadata"]["thumbnail"] == {
        "object_id": attachment.thumbnail["digest"],
        "source_object_id": attachment.seeded["source_object_id"], "recipe_version": 1,
    }
    assert service.list_variants(attachment.seeded["generation_id"])["items"] == attachment.variants_before
    associations = service.managed_outputs(attachment.task_id)
    assert len(associations) == 3
    thumbnail, = [row for row in associations if row["role"] == "thumbnail"]
    assert thumbnail["object_id"] == attachment.thumbnail["digest"]
    assert thumbnail["generation_id"] == attachment.seeded["generation_id"]
    logs = {row["variant_key"]: row for row in associations if row["role"] == "log"}
    assert set(logs) == {"job.stdout", "job.stderr"}
    settled_outputs = service.store.get_task(attachment.task_id)["task"]["result"]["outputs"]
    assert {(row["name"], row["variant_key"]) for row in settled_outputs if row.get("role") == "log"} == {
        ("job.stdout", "job.stdout"), ("job.stderr", "job.stderr"),
    }
    for expected in attachment.logs:
        row = logs[expected["name"]]
        assert row["filename"] == expected["filename"]
        assert row["output_port"] == "logs"
        assert row["durability"] == "durable"
        assert row["object_id"] == expected["digest"]
        assert row["project_id"] == attachment.project["id"]
        assert service.cas.path_for(expected["digest"].removeprefix("sha256:")).read_bytes() == base64.b64decode(expected["data_base64"])


@pytest.mark.parametrize("case", ["missing_thumbnail", "second_thumbnail", "other_extra"])
def test_thumbnail_attach_rejects_non_thumbnail_extras_and_cardinality_over_http(attachment, case):
    outputs = [attachment.thumbnail, *attachment.logs]
    if case == "missing_thumbnail":
        outputs = list(attachment.logs)
    elif case == "second_thumbnail":
        outputs.append({**attachment.thumbnail, "name": "second.jpg", "filename": "second.jpg", "group_key": "second"})
    else:
        outputs.append(_output(b"ordinary unrelated output", name="report.txt", media_type="text/plain",
                               output_port="report", role="auxiliary"))
    _assert_rejected_without_publication(attachment, outputs)


@pytest.mark.parametrize("case", ["wrong_role", "wrong_name", "wrong_filename", "wrong_port", "temporary", "duplicate_name"])
def test_thumbnail_attach_rejects_noncanonical_job_logs_over_http(attachment, case):
    outputs = deepcopy([attachment.thumbnail, *attachment.logs])
    log = outputs[1]
    changes = {
        "wrong_role": {"role": "auxiliary"},
        "wrong_name": {"name": "job.other"},
        "wrong_filename": {"filename": "stdout.log"},
        "wrong_port": {"output_port": "stdout"},
        "temporary": {"durability": "temporary"},
    }
    if case == "duplicate_name":
        # A distinct association key leaves the repeated canonical log name
        # for the thumbnail effect's boundary to reject.
        outputs.append({**log, "variant_key": "duplicate"})
    else:
        log.update(changes[case])
    _assert_rejected_without_publication(attachment, outputs)


@pytest.mark.parametrize("case", [
    "non_object", "wrong_media", "wrong_variant", "wrong_group", "wrong_ordinal",
    "primary", "generation", "duration", "producer", "provenance",
])
def test_thumbnail_attach_rejects_creative_metadata_on_job_logs_over_http(attachment, case):
    outputs = deepcopy([attachment.thumbnail, *attachment.logs])
    changes = {
        "non_object": {"kind": "value"},
        "wrong_media": {"media_type": "image/jpeg"},
        "wrong_variant": {"variant_key": "other"},
        "wrong_group": {"group_key": "other"},
        "wrong_ordinal": {"ordinal": 1},
        "primary": {"is_primary": True},
        "generation": {"generation_id": attachment.seeded["generation_id"]},
        "duration": {"duration_seconds": 1.0},
        "producer": {"producer": {"capability_id": CAPABILITY}},
        "provenance": {"provenance": {"source": "job"}},
    }
    outputs[1].update(changes[case])
    _assert_rejected_without_publication(attachment, outputs)
