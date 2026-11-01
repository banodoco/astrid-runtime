from __future__ import annotations

import base64
import hashlib
import io
import json
import wave

import pytest

from astrid_runtime_client import WorkspaceClient
from runtime_protocol.daemon import RuntimeDaemon
from runtime_protocol.errors import ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore
from runtime_protocol.util import canonical_json


CAPABILITY = "generation.publish.v1"


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(value: bytes, *, output_port: str, group_key: str, variant_key: str, ordinal: int, name: str | None = None, **fields) -> dict:
    result = {
        "name": name or output_port,
        "kind": "object",
        "digest": _digest(value),
        "media_type": "application/octet-stream",
        "size": len(value),
        "data_base64": base64.b64encode(value).decode("ascii"),
        "output_port": output_port,
        "group_key": group_key,
        "variant_key": variant_key,
        "ordinal": ordinal,
    }
    result.update(fields)
    return result


def _effect(project_id: str, *, policy: str = "reject", groups: list[dict] | None = None) -> dict:
    return {
        "effect_type": "generation.publish_v1",
        "target_id": project_id,
        "payload": {
            "version": 1,
            "modality": "video",
            "generation_type": "multi_output_render",
            "metadata": {"prompt": "bounded publish"},
            "partial_success_policy": policy,
            "groups": groups or [
                {
                    "group_key": "main",
                    "selectors": [
                        {"selector": "first", "ordinal": 0, "variant_key": "first", "output_port": "video"},
                        {"selector": "second", "ordinal": 1, "variant_key": "second", "output_port": "video"},
                    ],
                },
                {
                    "group_key": "audio",
                    "selectors": [
                        {"selector": "track", "ordinal": 0, "variant_key": "original", "output_port": "audio"},
                    ],
                },
            ],
        },
    }


def _fixture(tmp_path, *, effect_factory=_effect, slug="publish", generation_intent=None, capability=CAPABILITY):
    root = tmp_path / slug
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    digest = _digest(capability.encode())
    service.register_executor(
        {"executor_id": f"{slug}-worker", "capabilities": [capability]},
        idempotency_key=f"{slug}-executor",
    )
    project = service.create_project(
        {"slug": slug, "name": slug.title()}, idempotency_key=f"{slug}-project"
    )
    effect = effect_factory(project["id"])
    task = service.create_task(
        {
            "capability_id": capability,
            "capability_digest": digest,
            "project": project["id"],
            "settlement_effect": effect,
            **({"generation_intent": generation_intent} if generation_intent is not None else {}),
            "idempotency_key": f"{slug}-task",
        }
    )
    attempt = service.claim_next(
        {
            "executor_id": f"{slug}-worker",
            "capability_ids": [capability],
            "runtime_epoch": service.health()["runtime_epoch"],
        },
        idempotency_key=f"{slug}-claim",
    )
    return service, project, task, attempt, effect


def _speech_effect(project_id, *, output_port="speech", metadata=None):
    effect = _effect(
        project_id,
        groups=[{
            "group_key": "main",
            "selectors": [{
                "selector": "speech", "ordinal": 0,
                "variant_key": "original", "output_port": output_port,
            }],
        }],
    )
    effect["payload"].update({
        "modality": "audio",
        "generation_type": "speech",
        "metadata": {} if metadata is None else metadata,
    })
    return effect


def _wav_bytes(*, frames=8000, rate=8000):
    stream = io.BytesIO()
    with wave.open(stream, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(rate)
        output.writeframes(b"\0\0" * frames)
    return stream.getvalue()


def _zero_rate_wav():
    wav = bytearray(_wav_bytes())
    wav[24:28] = (0).to_bytes(4, "little")
    return bytes(wav)


def _settle(service, attempt, outputs, *, effect, key="settle", fence=None):
    return service.settle_attempt(
        attempt["attempt_id"],
        {
            "lease_id": attempt["lease_id"],
            "fence": attempt["fence"] if fence is None else fence,
            "runtime_epoch": attempt["runtime_epoch"],
            "outputs": outputs,
            "effect": effect,
        },
        idempotency_key=key,
    )


def _derived_generation(task_id: str, group_key: str) -> str:
    return "generation-" + hashlib.sha256(
        canonical_json({"task_id": task_id, "group_key": group_key}).encode()
    ).hexdigest()


def _derived_variant(generation_id: str, ordinal: int, variant_key: str) -> str:
    return "variant-" + hashlib.sha256(
        canonical_json({"generation_id": generation_id, "ordinal": ordinal, "variant_key": variant_key}).encode()
    ).hexdigest()


@pytest.mark.parametrize("origin", ["generated", "imported"])
def test_generation_tags_preserve_opaque_intent_and_publication_metadata(tmp_path, origin):
    metadata = {
        "prompt": "original prompt",
        "gen": {
            "kind": "video", "origin": origin, "generator": "vibecomfy",
            "model": "WAN/model.safetensors", "mode": "t2v", "backend": "comfy",
            "target": "runpod", "machine": "fixture-machine",
            "workflow_digest": _digest(b"workflow"), "task_id": "producer-task",
            "run_id": "producer-run", "seed": 0, "cost_usd": 0.012,
            "duration_ms": 1234, "tags": ["hero", "test"],
            "future_field": {"nested": [True, None]},
        },
    }
    if origin == "imported":
        metadata["provenance"] = {"origin": "imported", "source": "fixture-import"}

    def effect_factory(project_id):
        effect = _effect(project_id, groups=[{
            "group_key": "main",
            "selectors": [{"selector": "video", "ordinal": 0,
                           "variant_key": "original", "output_port": "video"}],
        }])
        effect["payload"]["metadata"] = metadata
        return effect

    intent = {"modality": "video", "metadata": metadata}
    service, project, task, attempt, effect = _fixture(
        tmp_path, effect_factory=effect_factory, generation_intent=intent,
    )
    try:
        assert service.task(task["task"]["id"])["task"]["generation_intent"] == intent
        assert attempt["generation_intent"] == intent
        _settle(service, attempt, [
            _output(b"video", output_port="video", group_key="main",
                    variant_key="original", ordinal=0),
        ], effect=effect)
        generation_id = _derived_generation(task["task"]["id"], "main")
        assert service.get_generation(generation_id)["metadata"] == metadata
        assert service.list_generations(project["id"], model="WAN/model.safetensors",
                                        target="runpod", tag="hero")["items"][0]["metadata"] == metadata
    finally:
        service.close()

    reopened = RuntimeService(tmp_path / "publish")
    try:
        assert reopened.get_generation(generation_id)["metadata"] == metadata
        assert reopened.task(task["task"]["id"])["task"]["generation_intent"] == intent
    finally:
        reopened.close()


def test_publish_v1_matches_out_of_order_groups_and_derives_domain_identity(tmp_path):
    service, project, task, attempt, effect = _fixture(tmp_path)
    try:
        outputs = [
            _output(b"audio", output_port="audio", group_key="audio", variant_key="original", ordinal=0),
            _output(b"extra", output_port="thumbnail", group_key="other", variant_key="preview", ordinal=0, generation_id="forged-generation"),
            _output(
                b"first",
                output_port="video",
                group_key="main",
                variant_key="first",
                ordinal=0,
                filename="first.mp4",
                provenance={"task_id": "forged", "attempt_id": "forged", "fence": -1},
            ),
            _output(b"second", output_port="video", group_key="main", variant_key="second", ordinal=1, filename="second.mp4"),
        ]
        settled = _settle(service, attempt, outputs, effect=effect)
        task_id = task["task"]["id"]
        assert settled["data"]["state"] == "succeeded"
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 2
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 3

        for group_key in ("main", "audio"):
            generation_id = _derived_generation(task_id, group_key)
            generation = service.get_generation(generation_id)
            assert generation["project_id"] == project["id"]
            assert generation["source_task_id"] == task_id
            assert generation["type"] == "multi_output_render"
            assert generation["metadata"] == effect["payload"]["metadata"]
        for group_key, ordinal, variant_key in (("main", 0, "first"), ("main", 1, "second"), ("audio", 0, "original")):
            generation_id = _derived_generation(task_id, group_key)
            variant_id = _derived_variant(generation_id, ordinal, variant_key)
            variant = service.get_variant(variant_id)
            assert variant["generation_id"] == generation_id
            assert variant["variant_type"] == variant_key
            if variant_key == "first":
                assert variant["metadata"]["provenance"]["task_id"] == task_id
                assert variant["metadata"]["provenance"]["attempt_id"] == attempt["attempt_id"]
                assert variant["metadata"]["provenance"]["fence"] == attempt["fence"]

        associations = service.managed_outputs(task_id)
        selected = {(item["output_port"], item["group_key"], item["variant_key"], item["ordinal"]): item for item in associations}
        first = selected[("video", "main", "first", 0)]
        assert first["generation_id"] == _derived_generation(task_id, "main")
        assert first["provenance"]["selector"] == "first"
        assert selected[("video", "main", "second", 1)]["generation_id"] == _derived_generation(task_id, "main")
        assert selected[("audio", "audio", "original", 0)]["generation_id"] == _derived_generation(task_id, "audio")
        extra = selected[("thumbnail", "other", "preview", 0)]
        assert extra["generation_id"] is None
        assert "selector" not in extra["provenance"]
    finally:
        service.close()


def test_publish_v1_reject_missing_selector_rolls_back_everything(tmp_path):
    service, _project, task, attempt, effect = _fixture(tmp_path, slug="reject-missing")
    try:
        output = _output(b"first", output_port="video", group_key="main", variant_key="first", ordinal=0)
        with pytest.raises(ValidationError, match="requires every declared selector"):
            _settle(service, attempt, [output], effect=effect, key="reject-missing-settle")
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.store.conn.execute("SELECT COUNT(*) FROM managed_output_associations").fetchone()[0] == 0
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
    finally:
        service.close()


def test_publish_v1_reject_policy_disallows_explicit_optional_selector(tmp_path):
    def effect_factory(project_id):
        return _effect(
            project_id,
            policy="reject",
            groups=[{
                "group_key": "main",
                "selectors": [{
                    "selector": "optional",
                    "ordinal": 0,
                    "variant_key": "optional",
                    "output_port": "video",
                    "required": False,
                }],
            }],
        )

    with pytest.raises(ValidationError, match="reject policy cannot declare an optional selector"):
        _fixture(tmp_path, effect_factory=effect_factory, slug="reject-optional")


def test_publish_v1_allow_records_missing_members_without_empty_generations(tmp_path):
    def effect_factory(project_id):
        return _effect(
            project_id,
            policy="allow",
            groups=[
                {
                    "group_key": "main",
                    "selectors": [
                        {"selector": "present", "ordinal": 0, "variant_key": "present", "output_port": "video"},
                        {"selector": "missing", "ordinal": 1, "variant_key": "missing", "output_port": "video"},
                    ],
                },
                {
                    "group_key": "empty",
                    "selectors": [
                        {"selector": "none", "ordinal": 0, "variant_key": "none", "output_port": "audio"},
                    ],
                },
            ],
        )

    service, _project, task, attempt, effect = _fixture(tmp_path, effect_factory=effect_factory, slug="allow-partial")
    try:
        _settle(
            service,
            attempt,
            [_output(b"present", output_port="video", group_key="main", variant_key="present", ordinal=0)],
            effect=effect,
            key="allow-partial-settle",
        )
        task_value = service.task(task["task"]["id"])["task"]
        publication = task_value["result"]["generation_publish_v1"]
        assert len(publication["publications"]) == 2
        assert publication["publications"][0]["missing_selectors"] == [effect["payload"]["groups"][0]["selectors"][1]]
        assert publication["publications"][1]["published"] == []
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 1
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 1
    finally:
        service.close()


def test_publish_v1_allow_still_rejects_an_explicit_required_member(tmp_path):
    def effect_factory(project_id):
        return _effect(
            project_id,
            policy="allow",
            groups=[{
                "group_key": "main",
                "selectors": [
                    {"selector": "required", "ordinal": 0, "variant_key": "required", "output_port": "video", "required": True},
                    {"selector": "optional", "ordinal": 1, "variant_key": "optional", "output_port": "video", "required": False},
                ],
            }],
        )

    service, _project, _task, attempt, effect = _fixture(
        tmp_path, effect_factory=effect_factory, slug="allow-required"
    )
    try:
        with pytest.raises(ValidationError, match="required selectors are missing"):
            _settle(
                service,
                attempt,
                [_output(b"optional", output_port="video", group_key="main", variant_key="optional", ordinal=1)],
                effect=effect,
                key="allow-required-settle",
            )
    finally:
        service.close()


def test_publish_v1_settlement_uses_one_runtime_timestamp_for_publication_rows(tmp_path):
    service, _project, task, attempt, effect = _fixture(
        tmp_path,
        slug="shared-timestamp",
        effect_factory=lambda project_id: _effect(
            project_id,
            policy="allow",
            groups=[{
                "group_key": "main",
                "selectors": [{
                    "selector": "first", "ordinal": 0, "variant_key": "first", "output_port": "video",
                }],
            }],
        ),
    )
    try:
        _settle(
            service,
            attempt,
            [_output(b"first", output_port="video", group_key="main", variant_key="first", ordinal=0)],
            effect=effect,
            key="shared-timestamp-settle",
        )
        task_id = task["task"]["id"]
        run_id = task["task"]["run_id"]
        generation_id = _derived_generation(task_id, "main")
        values = {
            row[0]
            for row in service.store.conn.execute(
                "SELECT created_at FROM generations WHERE id=? UNION ALL "
                "SELECT updated_at FROM generations WHERE id=? UNION ALL "
                "SELECT created_at FROM generation_variants WHERE generation_id=? UNION ALL "
                "SELECT a.created_at FROM managed_output_associations a WHERE a.task_id=? UNION ALL "
                "SELECT l.created_at FROM managed_output_lifecycle l JOIN managed_output_associations a ON a.association_id=l.association_id WHERE a.task_id=? UNION ALL "
                "SELECT l.updated_at FROM managed_output_lifecycle l JOIN managed_output_associations a ON a.association_id=l.association_id WHERE a.task_id=? UNION ALL "
                "SELECT updated_at FROM tasks WHERE id=? UNION ALL "
                "SELECT updated_at FROM runs WHERE id=? UNION ALL "
                "SELECT released_at FROM reservations WHERE task_id=? UNION ALL "
                "SELECT created_at FROM events WHERE task_id=? AND kind='task.completed' UNION ALL "
                "SELECT created_at FROM command_idempotency WHERE command_kind='attempt.settle' AND aggregate_id=?",
                (generation_id, generation_id, generation_id, task_id, task_id, task_id, task_id, run_id, task_id, task_id, task_id),
            )
        }
        assert len(values) == 1
        receipt = service.store.conn.execute(
            "SELECT created_at FROM command_idempotency "
            "WHERE command_kind='attempt.settle' AND aggregate_id=?",
            (attempt["attempt_id"],),
        ).fetchone()
        assert receipt is not None
        assert receipt[0] in values
    finally:
        service.close()


def test_publish_v1_rejects_wrong_shape_duplicates_and_project_target_at_admission(tmp_path):
    RealmStore.initialize(tmp_path / "realm").close()
    service = RuntimeService(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "shape", "name": "Shape"}, idempotency_key="shape-project")
        base = _effect(project["id"])
        for index, bad in enumerate((
            {**base, "extra": True},
            {**base, "payload": {**base["payload"], "groups": [{"group_key": "main", "selectors": []}]}},
            {**base, "payload": {**base["payload"], "modality": "text"}},
            {**base, "payload": {**base["payload"], "modality": []}},
            {**base, "payload": {**base["payload"], "partial_success_policy": {}}},
        )):
            with pytest.raises(ValidationError):
                service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": bad, "idempotency_key": "shape-" + str(index)})
        duplicate = _effect(
            project["id"],
            groups=[{
                "group_key": "main",
                "selectors": [
                    {"selector": "one", "ordinal": 0, "variant_key": "same", "output_port": "video"},
                    {"selector": "two", "ordinal": 0, "variant_key": "same", "output_port": "audio"},
                ],
            }],
        )
        with pytest.raises(ValidationError, match="ordinal and variant_key"):
            service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": duplicate, "idempotency_key": "shape-duplicate"})
        full_duplicate = _effect(
            project["id"],
            groups=[{
                "group_key": "main",
                "selectors": [
                    {"selector": "one", "ordinal": 0, "variant_key": "same", "output_port": "video"},
                    {"selector": "two", "ordinal": 0, "variant_key": "same", "output_port": "video"},
                ],
            }],
        )
        with pytest.raises(ValidationError, match="must not contain duplicates"):
            service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": full_duplicate, "idempotency_key": "shape-full-duplicate"})
        foreign_project = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="shape-foreign-project")
        foreign = _effect(foreign_project["id"])
        with pytest.raises(ConflictError, match="target project does not match"):
            service.create_task({"capability_id": CAPABILITY, "project": project["id"], "settlement_effect": foreign, "idempotency_key": "shape-foreign"})
        assert service.store.conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 0
    finally:
        service.close()


def test_publish_v1_replay_conflict_and_stale_fence_are_atomic(tmp_path):
    service, _project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=lambda project_id: _effect(project_id, policy="allow"),
        slug="replay",
    )
    try:
        output = _output(b"stable", output_port="video", group_key="main", variant_key="first", ordinal=0)
        first = _settle(service, attempt, [output], effect=effect, key="replay-settle")
        assert _settle(service, attempt, [output], effect=effect, key="replay-settle") == first
        before = tuple(service.store.conn.execute("SELECT COUNT(*) FROM generations, generation_variants, managed_output_associations").fetchone())
        changed = _output(b"changed", output_port="video", group_key="main", variant_key="first", ordinal=0)
        with pytest.raises(ConflictError):
            _settle(service, attempt, [changed], effect=effect, key="replay-settle")
        after = tuple(service.store.conn.execute("SELECT COUNT(*) FROM generations, generation_variants, managed_output_associations").fetchone())
        assert after == before
    finally:
        service.close()

    service, _project, task, attempt, effect = _fixture(tmp_path, slug="stale-fence")
    try:
        output = _output(b"stale", output_port="video", group_key="main", variant_key="first", ordinal=0)
        with pytest.raises(LeaseError):
            _settle(service, attempt, [output], effect=effect, key="stale-fence-settle", fence=attempt["fence"] - 1)
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
    finally:
        service.close()


def test_generic_output_generation_id_remains_managed_only(tmp_path):
    service, project, task, attempt, _effect_value = _fixture(
        tmp_path,
        effect_factory=lambda _project_id: None,
        slug="generic",
    )
    try:
        output = _output(
            b"generic",
            output_port="video",
            group_key="default",
            variant_key="original",
            ordinal=0,
            generation_id="producer-forged-generation",
        )
        # The fixture admits no effect; the helper's claim is still valid.
        service.settle_attempt(
            attempt["attempt_id"],
            {
                "lease_id": attempt["lease_id"],
                "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"],
                "outputs": [output],
                "effect": None,
            },
            idempotency_key="generic-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        assert association["generation_id"] is None
        assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
        assert project["id"] == association["project_id"]
    finally:
        service.close()


@pytest.mark.parametrize("output_port", ["audio", "speech"])
def test_speech_settlement_derives_wav_duration_for_exact_media_selection(tmp_path, output_port):
    service, project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=lambda project_id: _speech_effect(
            project_id, output_port=output_port
        ),
        slug="speech-wav",
        capability="generation.generate_speech",
    )
    try:
        wav = _wav_bytes()
        settled = _settle(
            service,
            attempt,
            [_output(
                wav,
                output_port=output_port,
                group_key="main",
                variant_key="original",
                ordinal=0,
                filename="speech.wav",
                media_type="audio/wav",
            )],
            effect=effect,
            key="speech-wav-settle",
        )
        task_id = task["task"]["id"]
        association = service.managed_outputs(task_id)[0]
        receipt = service.store.conn.execute(
            "SELECT command_kind FROM command_idempotency "
            "WHERE command_kind='attempt.settle' AND aggregate_id=?",
            (attempt["attempt_id"],),
        ).fetchone()
        assert settled["data"]["state"] == "succeeded"
        assert receipt["command_kind"] == "attempt.settle"
        assert service.cas.path_for(association["object_id"][7:]).read_bytes() == wav
        assert association["attempt_id"] == attempt["attempt_id"]
        assert association["provenance"]["task_id"] == task_id

        before = {
            table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("parent_composition_heads", "parent_composition_revisions", "timeline_commit_history")
        }
        selection = service.get_project_media_selection(project["id"], {
            "association_id": association["association_id"],
            "object_id": association["object_id"],
            "version": association["lifecycle"]["version"],
        }, authorize=lambda: None)
        assert set(selection) == {"asset", "generation_id", "variant_id", "object_id", "catalog_digest"}
        verified = service.get_project_verified_media(project["id"], selection, authorize=lambda: None)
        assert verified["selection"] == selection
        assert verified["media_type"] == "audio/wav"
        assert verified["duration_seconds"] == 1.0
        assert {
            table: service.store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in before
        } == before
    finally:
        service.close()


def test_speech_settlement_exact_replay_returns_original_result(tmp_path):
    service, _project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=_speech_effect,
        slug="speech-replay",
        capability="generation.generate_speech",
    )
    try:
        output = _output(
            _wav_bytes(),
            output_port="speech",
            group_key="main",
            variant_key="original",
            ordinal=0,
            filename="speech.wav",
            media_type="audio/wav",
        )
        first = _settle(
            service, attempt, [output], effect=effect, key="speech-replay-settle"
        )
        assert _settle(
            service, attempt, [output], effect=effect, key="speech-replay-settle"
        ) == first
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM generations WHERE source_task_id=?", (task["task"]["id"],)
        ).fetchone()[0] == 1
    finally:
        service.close()


def test_speech_settlement_invalid_wav_keeps_duration_unknown_and_selection_refused(tmp_path):
    service, project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=_speech_effect,
        slug="speech-invalid-wav",
        capability="generation.generate_speech",
    )
    try:
        invalid = b"not a WAV"
        _settle(
            service,
            attempt,
            [_output(
                invalid,
                output_port="speech",
                group_key="main",
                variant_key="original",
                ordinal=0,
                filename="speech.wav",
                media_type="audio/wav",
            )],
            effect=effect,
            key="speech-invalid-wav-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        variant = service.list_variants(association["generation_id"])["items"][0]
        assert "duration_seconds" not in variant["metadata"]
        with pytest.raises(ValidationError, match="invalid selected media metadata"):
            service.get_project_media_selection(project["id"], {
                "association_id": association["association_id"],
                "object_id": association["object_id"],
                "version": association["lifecycle"]["version"],
            }, authorize=lambda: None)
    finally:
        service.close()


def test_speech_settlement_preserves_explicit_null_duration_and_refuses_selection(tmp_path):
    service, project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=_speech_effect,
        slug="speech-null-duration",
        capability="generation.generate_speech",
    )
    try:
        settled = _settle(
            service,
            attempt,
            [_output(
                _wav_bytes(),
                output_port="speech",
                group_key="main",
                variant_key="original",
                ordinal=0,
                filename="speech.wav",
                media_type="audio/wav",
                duration_seconds=None,
            )],
            effect=effect,
            key="speech-null-duration-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        variant = service.list_variants(association["generation_id"])["items"][0]
        assert variant["metadata"]["duration_seconds"] is None
        assert "duration_seconds" not in settled["data"]["result"]["outputs"][0]
        with pytest.raises(ValidationError, match="invalid selected media metadata"):
            service.get_project_media_selection(project["id"], {
                "association_id": association["association_id"],
                "object_id": association["object_id"],
                "version": association["lifecycle"]["version"],
            }, authorize=lambda: None)
    finally:
        service.close()


def test_speech_settlement_zero_rate_wav_keeps_duration_unknown_and_selection_refused(tmp_path):
    service, project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=_speech_effect,
        slug="speech-zero-rate-wav",
        capability="generation.generate_speech",
    )
    try:
        _settle(
            service,
            attempt,
            [_output(
                _zero_rate_wav(),
                output_port="speech",
                group_key="main",
                variant_key="original",
                ordinal=0,
                filename="speech.wav",
                media_type="audio/wav",
            )],
            effect=effect,
            key="speech-zero-rate-wav-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        variant = service.list_variants(association["generation_id"])["items"][0]
        assert "duration_seconds" not in variant["metadata"]
        with pytest.raises(ValidationError, match="invalid selected media metadata"):
            service.get_project_media_selection(project["id"], {
                "association_id": association["association_id"],
                "object_id": association["object_id"],
                "version": association["lifecycle"]["version"],
            }, authorize=lambda: None)
    finally:
        service.close()


def test_speech_settlement_preserves_explicit_duration_metadata(tmp_path):
    explicit = 2.5
    service, project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=lambda project_id: _speech_effect(
            project_id, metadata={"params": {"duration_seconds": explicit}}
        ),
        slug="speech-explicit-duration",
        capability="generation.generate_speech",
    )
    try:
        _settle(
            service,
            attempt,
            [_output(
                _wav_bytes(),
                output_port="speech",
                group_key="main",
                variant_key="original",
                ordinal=0,
                filename="speech.wav",
                media_type="audio/wav",
                duration_seconds=explicit,
            )],
            effect=effect,
            key="speech-explicit-duration-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        selection = service.get_project_media_selection(project["id"], {
            "association_id": association["association_id"],
            "object_id": association["object_id"],
            "version": association["lifecycle"]["version"],
        }, authorize=lambda: None)
        assert service.get_project_verified_media(
            project["id"], selection, authorize=lambda: None
        )["duration_seconds"] == explicit
    finally:
        service.close()


def test_speech_settlement_verified_media_is_exact_over_authenticated_http(tmp_path):
    service, project, task, attempt, effect = _fixture(
        tmp_path,
        effect_factory=_speech_effect,
        slug="speech-http",
        capability="generation.generate_speech",
    )
    daemon = None
    try:
        wav = _wav_bytes()
        _settle(
            service,
            attempt,
            [_output(
                wav,
                output_port="speech",
                group_key="main",
                variant_key="original",
                ordinal=0,
                filename="speech.wav",
                media_type="audio/wav",
            )],
            effect=effect,
            key="speech-http-settle",
        )
        association = service.managed_outputs(task["task"]["id"])[0]
        service.close()
        service = None

        daemon = RuntimeDaemon(
            tmp_path / "speech-http", support_root=tmp_path / "speech-http-support"
        ).start()
        reader_token, _ = daemon.credentials.provision(
            "speech-http-reader", ["projects:read"]
        )
        client = WorkspaceClient(daemon.endpoint, reader_token)
        selector = {
            "association_id": association["association_id"],
            "object_id": association["object_id"],
            "version": association["lifecycle"]["version"],
        }
        selection = client.get_project_media_selection(project["id"], selector)
        assert selection["object_id"] == _digest(wav)
        assert selection["object_id"] == "sha256:" + hashlib.sha256(wav).hexdigest()

        verified = client.get_project_verified_media(project["id"], selection)
        assert verified == {
            "selection": selection,
            "media_type": "audio/wav",
            "size": len(wav),
            "duration_seconds": 1.0,
        }
    finally:
        if daemon is not None:
            daemon.stop()
        elif service is not None:
            service.close()
