"""R14-FIX-12: canonical logs never authorize another creative output."""
from __future__ import annotations

import pytest

from runtime_protocol.errors import ValidationError
from tests.test_generation_thumbnail_settlement import (
    _create_effect, _output, _seed_generation, _service, _settle, _task,
)


def _job_log(name):
    output = _output(
        f"{name}\n".encode(), name=name, media_type="text/plain",
        output_port="logs", group_key="default", variant_key=name, ordinal=0, role="log",
    )
    return {**output, "filename": name + ".log", "durability": "durable"}


@pytest.fixture(params=["create_with_variant", "variant.append"])
def creative(tmp_path, request):
    service, project = _service(tmp_path, "creative-job-logs")
    try:
        if request.param == "create_with_variant":
            source = service.ingest(project["id"], b"source", idempotency_key="source")["data"]["digest"]
            effect = _create_effect(project["id"])
        else:
            seed = _seed_generation(service, project, key="seed", with_thumbnail=False)
            source = seed["source_object_id"]
            effect = {
                "effect_type": "generation.variant.append", "target_id": seed["generation_id"],
                "expected_version": 1, "payload": {
                    "source_variant_id": seed["variant_id"], "source_object_id": source,
                    "variant_type": "edit", "output_name": "video", "output_ordinal": 0,
                    "primary_policy": "preserve",
                },
            }
        task, attempt = _task(service, project["id"], effect, key="task", inputs=[source])
        output = _output(b"creative video", name="video", media_type="video/mp4", ordinal=0)
        yield service, task, attempt, effect, output
    finally:
        service.close()


def test_one_creative_output_with_canonical_logs_settles_and_replays(creative):
    service, task, attempt, effect, output = creative
    outputs = [_job_log("job.stdout"), output, _job_log("job.stderr")]
    first = _settle(service, attempt, effect, outputs, key="settle")
    assert first["data"]["task_id"] == task["task"]["id"]
    associations = service.managed_outputs(task["task"]["id"])
    assert len(associations) == 3
    assert {row["variant_key"] for row in associations if row["role"] == "log"} == {"job.stdout", "job.stderr"}
    assert _settle(service, attempt, effect, outputs, key="settle") == first
    assert service.managed_outputs(task["task"]["id"]) == associations


def test_second_creative_output_is_refused_even_with_valid_job_logs(creative):
    service, task, attempt, effect, output = creative
    second = _output(b"second video", name="second-video", media_type="video/mp4", ordinal=0)
    outputs = [output, second, _job_log("job.stdout"), _job_log("job.stderr")]
    with pytest.raises(ValidationError, match="exactly one settlement output"):
        _settle(service, attempt, effect, outputs)
    assert service.store.get_task(task["task"]["id"])["task"]["status"] == "running"
    assert service.managed_outputs(task["task"]["id"]) == []


@pytest.mark.parametrize("change", [
    {"name": "job.other"}, {"role": "result"}, {"output_port": "other"},
    {"filename": "other.log"}, {"media_type": "image/png"}, {"durability": "temporary"},
    {"variant_key": "other"}, {"group_key": "other"}, {"ordinal": 1},
    {"is_primary": True}, {"generation_id": "forged"}, {"duration_seconds": 1.0},
    {"producer": {"source": "creative"}}, {"provenance": {"source": "creative"}},
])
def test_noncanonical_log_cannot_escape_creative_output_count(creative, change):
    service, task, attempt, effect, output = creative
    malformed = {**_job_log("job.stdout"), **change}
    with pytest.raises(ValidationError, match="exactly one settlement output"):
        _settle(service, attempt, effect, [output, malformed])
    assert service.store.get_task(task["task"]["id"])["task"]["status"] == "running"
    assert service.managed_outputs(task["task"]["id"]) == []
