from __future__ import annotations

import base64
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from runtime_protocol.errors import AuthorizationError, ConflictError, LeaseError, ValidationError
from runtime_protocol.service import RuntimeService
from runtime_protocol.store import RealmStore

sys.path.insert(0, str(Path(__file__).parents[1] / "packages" / "python"))
from astrid_runtime_client import WorkspaceClient


CAPABILITY = "durable-terminal.fixture"


def _digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _output(value: bytes, *, name: str, output_port: str, role: str, **fields) -> dict:
    result = {
        "name": name,
        "kind": "object",
        "filename": name + (".json" if role == "manifest" else ".bin"),
        "digest": _digest(value),
        "media_type": "application/json" if role == "manifest" else "application/octet-stream",
        "size": len(value),
        "output_port": output_port,
        "role": role,
        "data_base64": base64.b64encode(value).decode("ascii"),
    }
    result.update(fields)
    return result


def _service(tmp_path, *, key="durable", inputs=False, claim=True, generation_effect=False):
    root = tmp_path / key
    RealmStore.initialize(root).close()
    service = RuntimeService(root)
    project = service.create_project({"slug": key, "name": key.title()}, idempotency_key=f"{key}-project")
    digest = _digest(CAPABILITY)
    service.register_capability({"capability_id": CAPABILITY, "definition_digest": digest})
    service.register_executor({"executor_id": f"{key}-worker", "capabilities": [CAPABILITY]}, idempotency_key=f"{key}-executor")
    input_ids = []
    if inputs:
        source = service.ingest(project["id"], b"submitted-source", media_type="application/octet-stream", idempotency_key=f"{key}-source")
        input_ids.append(source["data"]["digest"])
    task_body = {
        "capability_id": CAPABILITY,
        "capability_digest": digest,
        "project": project["id"],
        "input_object_ids": input_ids,
        "spec": {"source_ref": input_ids[0]} if input_ids else {},
        "idempotency_key": f"{key}-task",
    }
    if generation_effect:
        task_body["settlement_effect"] = {
            "effect_type": "generation.create_with_variant",
            "target_id": project["id"],
            "payload": {
                "generation_type": "image",
                "metadata": {"prompt": "partial evidence must not publish"},
                "variant_type": "original",
                "output_name": "generated_images",
                "output_ordinal": 0,
                "primary_policy": "preserve",
            },
        }
    task = service.create_task(task_body)
    attempt = None
    if claim:
        attempt = service.claim_next({
            "executor_id": f"{key}-worker",
            "capability_ids": [CAPABILITY],
            "runtime_epoch": service.health()["runtime_epoch"],
        }, idempotency_key=f"{key}-claim")
    return service, task, attempt, root


def _evidence(task, attempt, *, manifest=None, partial=b"partial-output"):
    if manifest is None:
        manifest = json.dumps({"kind": "runtime-result", "task": task["task"]["id"]}, sort_keys=True).encode()
    outputs = [
        _output(manifest, name="result-manifest", output_port="result_manifest", role="manifest"),
        _output(partial, name="partial-output", output_port="partial", role="result"),
    ]
    result = {"manifest_ref": {"object_id": _digest(manifest), "size": len(manifest)}}
    fence = {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}
    return outputs, result, fence


def _reopen(root):
    return RuntimeService(root)


def _associations(service, task_id):
    return service.managed_outputs(task_id)


def _assert_no_generation_effect(service):
    assert service.store.conn.execute("SELECT COUNT(*) FROM generations").fetchone()[0] == 0
    assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 0


def _managed_evidence(service, task, attempt, *, task_id=None, attempt_id=None):
    """Build the contract envelope from project-associated input/output bytes."""
    project_id = task["run"]["project_id"]
    source = b"exact-submitted-workflow-bytes"
    settings = b"exact-compiled-settings-bytes"
    source_ref = service.ingest(project_id, source, media_type="application/octet-stream",
                                idempotency_key=f"{task['task']['id']}-managed-source")
    settings_ref = service.ingest(project_id, settings, media_type="application/octet-stream",
                                  idempotency_key=f"{task['task']['id']}-managed-settings")
    partial = b"managed-partial-output"
    partial_digest = _digest(partial).removeprefix("sha256:")
    envelope = {
        "schema_version": 1,
        "kind": "managed-generation-result.v1",
        "inputs": {
            "source": {"sha256": _digest(source).removeprefix("sha256:"), "bytes": len(source), "filename": "workflow.json"},
            "effective_settings": {"sha256": _digest(settings).removeprefix("sha256:"), "bytes": len(settings), "filename": "compiled.json"},
            "values": {},
        },
        "outputs": [{
            "producer_output_id": "partial-0", "output_port": "partial", "ordinal": 0,
            "path": "partial.bin", "media_type": "application/octet-stream",
            "bytes": len(partial), "sha256": partial_digest,
        }],
        "created": "2026-10-31T00:00:00Z",
        "warnings": [],
        "task_id": task_id or task["task"]["id"],
        "attempt_id": attempt_id or attempt["attempt_id"],
        "producer_run_id": "producer-run-managed",
        "outcomes": {
            "execution": {"status": "succeeded"}, "retrieval": {"status": "succeeded"},
            "verification": {"status": "succeeded"}, "publication": {"status": "pending"},
        },
        "evidence": {"producer": {}, "transport": {}},
    }
    payload = json.dumps(envelope, sort_keys=True).encode()
    outputs = [
        _output(payload, name="managed-result", output_port="result_manifest", role="manifest"),
        _output(partial, name="managed-partial", output_port="partial", role="result"),
    ]
    result = {"manifest_ref": {"object_id": _digest(payload), "size": len(payload)}}
    fence = {key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")}
    return outputs, result, fence, source_ref["data"]["digest"], settings_ref["data"]["digest"]


def test_failure_evidence_survives_restart_and_exact_replay(tmp_path):
    service, task, attempt, root = _service(tmp_path, key="failed", generation_effect=True)
    outputs, result, fence = _evidence(task, attempt)
    body = {**fence, "error": {"code": "producer_failed"}, "outputs": outputs, "result": result}
    try:
        first = service.fail_attempt(attempt["attempt_id"], body, idempotency_key="durable-fail")
        assert not service.store.attempt_staging_dir(attempt["attempt_id"]).exists()
        service.close()
        service = _reopen(root)
        replay = service.fail_attempt(attempt["attempt_id"], body, idempotency_key="durable-fail")
        assert replay == first
        stored = service.task(task["task"]["id"])
        assert stored["task"]["status"] == "failed"
        assert stored["task"]["result"]["manifest_ref"] == result["manifest_ref"]
        associations = _associations(service, task["task"]["id"])
        assert len(associations) == 2
        assert {item["output_port"] for item in associations} == {"result_manifest", "partial"}
        assert len({item["association_id"] for item in associations}) == 2
        _assert_no_generation_effect(service)
    finally:
        service.close()


@pytest.mark.parametrize("terminal", ["success", "failure", "cancel"], ids=["success", "failure", "observed-cancel"])
def test_managed_envelope_terminal_artifacts_survive_cleanup_and_restart(tmp_path, terminal):
    service, task, attempt, root = _service(tmp_path, key=f"managed-{terminal}", inputs=True)
    outputs, result, fence, source_digest, settings_digest = _managed_evidence(service, task, attempt)
    if terminal == "success":
        publish = lambda: service.settle_attempt(attempt["attempt_id"], {**fence, "outputs": outputs, "result": result}, idempotency_key="managed-terminal")
    elif terminal == "failure":
        publish = lambda: service.fail_attempt(attempt["attempt_id"], {**fence, "error": {"code": "producer_failed"}, "outputs": outputs, "result": result}, idempotency_key="managed-terminal")
    else:
        publish = lambda: service.cancel_task_canonical(task["task"]["id"], {**fence, "attempt_id": attempt["attempt_id"], "outputs": outputs, "result": result, "stop_observed": True}, idempotency_key="managed-terminal")
    try:
        first = publish()
        assert not service.store.attempt_staging_dir(attempt["attempt_id"]).exists()
        service.close()
        service = _reopen(root)
        if terminal == "success":
            replay = service.settle_attempt(attempt["attempt_id"], {**fence, "outputs": outputs, "result": result}, idempotency_key="managed-terminal")
        elif terminal == "failure":
            replay = service.fail_attempt(attempt["attempt_id"], {**fence, "error": {"code": "producer_failed"}, "outputs": outputs, "result": result}, idempotency_key="managed-terminal")
        else:
            replay = service.cancel_task_canonical(task["task"]["id"], {**fence, "attempt_id": attempt["attempt_id"], "outputs": outputs, "result": result, "stop_observed": True}, idempotency_key="managed-terminal")
        assert replay == first
        stored = service.task(task["task"]["id"])["task"]
        assert stored["status"] == {"success": "completed", "failure": "failed", "cancel": "cancelled"}[terminal]
        assert stored["result"]["manifest_ref"] == result["manifest_ref"]
        associations = _associations(service, task["task"]["id"])
        assert len(associations) == 2
        assert {item["output_port"] for item in associations} == {"result_manifest", "partial"}
        project_id = task["run"]["project_id"]
        envelope = json.loads(base64.b64decode(outputs[0]["data_base64"]))
        for digest in (source_digest, settings_digest):
            bare_digest = digest.removeprefix("sha256:")
            assert service.store.conn.execute("SELECT 1 FROM project_objects WHERE project_id=? AND digest=?", (project_id, bare_digest)).fetchone()
        for input_name in ("source", "effective_settings"):
            reference = envelope["inputs"][input_name]
            service._verify_child_object_bytes(reference["sha256"], reference["bytes"], label=f"test {input_name} readback")
        for item in associations:
            service._verify_child_object_bytes(item["object_id"].removeprefix("sha256:"), item["size"], label="test readback")
        assert len({item["association_id"] for item in associations}) == 2
    finally:
        service.close()


def test_managed_envelope_rejects_foreign_project_refs_and_wrong_attempt(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="managed-reject")
    foreign_project = service.create_project({"slug": "foreign", "name": "Foreign"}, idempotency_key="foreign-project")
    foreign = service.ingest(foreign_project["id"], b"private-source", media_type="application/octet-stream", idempotency_key="foreign-source")
    outputs, result, fence, _source_digest, _settings_digest = _managed_evidence(service, task, attempt)
    envelope = json.loads(base64.b64decode(outputs[0]["data_base64"]))
    envelope["inputs"]["source"] = {"sha256": foreign["data"]["digest"].removeprefix("sha256:"), "bytes": len(b"private-source"), "filename": "workflow.json"}
    payload = json.dumps(envelope, sort_keys=True).encode()
    outputs[0] = _output(payload, name="managed-result", output_port="result_manifest", role="manifest")
    result = {"manifest_ref": {"object_id": _digest(payload), "size": len(payload)}}
    try:
        with pytest.raises((ValidationError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {**fence, "error": {"code": "failed"}, "outputs": outputs, "result": result}, idempotency_key="foreign-input")
        outputs, result, fence, _source_digest, _settings_digest = _managed_evidence(service, task, attempt, attempt_id="another-attempt")
        with pytest.raises((ValidationError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {**fence, "error": {"code": "failed"}, "outputs": outputs, "result": result}, idempotency_key="wrong-managed-attempt")
        outputs, result, fence, _source_digest, _settings_digest = _managed_evidence(service, task, attempt)
        envelope = json.loads(base64.b64decode(outputs[0]["data_base64"]))
        envelope["inputs"]["effective_settings"]["sha256"] = _digest(b"missing-settings").removeprefix("sha256:")
        payload = json.dumps(envelope, sort_keys=True).encode()
        outputs[0] = _output(payload, name="managed-result", output_port="result_manifest", role="manifest")
        result = {"manifest_ref": {"object_id": _digest(payload), "size": len(payload)}}
        with pytest.raises((ValidationError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {**fence, "error": {"code": "failed"}, "outputs": outputs, "result": result}, idempotency_key="wrong-managed-settings-hash")
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
    finally:
        service.close()


@pytest.mark.parametrize("input_ref", ["source", "effective_settings"])
def test_managed_envelope_rejects_corrupt_same_project_input_bytes(tmp_path, input_ref):
    service, task, attempt, _root = _service(tmp_path, key=f"managed-corrupt-{input_ref}")
    outputs, result, fence, source_digest, settings_digest = _managed_evidence(service, task, attempt)
    try:
        digest = source_digest if input_ref == "source" else settings_digest
        service.cas.path_for(digest.removeprefix("sha256:")).write_bytes(b"corrupted project object")
        with pytest.raises((ValidationError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {
                **fence, "error": {"code": "failed"}, "outputs": outputs, "result": result,
            }, idempotency_key=f"corrupt-managed-{input_ref}")
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
    finally:
        service.close()


def test_observed_cancel_evidence_survives_restart_and_replay(tmp_path):
    service, task, attempt, root = _service(tmp_path, key="cancelled", generation_effect=True)
    outputs, result, fence = _evidence(task, attempt)
    body = {
        **fence,
        "attempt_id": attempt["attempt_id"],
        "outputs": outputs,
        "result": result,
        "stop_observed": True,
    }
    try:
        first = service.cancel_task_canonical(task["task"]["id"], body, idempotency_key="durable-cancel")
        assert not service.store.attempt_staging_dir(attempt["attempt_id"]).exists()
        service.close()
        service = _reopen(root)
        replay = service.cancel_task_canonical(task["task"]["id"], body, idempotency_key="durable-cancel")
        assert replay == first
        stored = service.task(task["task"]["id"])
        assert stored["task"]["status"] == "cancelled"
        assert stored["task"]["result"]["manifest_ref"] == result["manifest_ref"]
        associations = _associations(service, task["task"]["id"])
        assert len(associations) == 2
        _assert_no_generation_effect(service)
    finally:
        service.close()


def test_corrupt_digest_and_stale_failure_fence_publish_nothing(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="reject")
    outputs, result, fence = _evidence(task, attempt)
    try:
        corrupt = [dict(item) for item in outputs]
        corrupt[1]["digest"] = _digest(b"wrong bytes")
        with pytest.raises((ValidationError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {
                **fence, "error": {"code": "failed"}, "outputs": corrupt, "result": result,
            }, idempotency_key="bad-digest")
        stale = {**fence, "fence": fence["fence"] + 1}
        with pytest.raises((LeaseError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {
                **stale, "error": {"code": "failed"}, "outputs": outputs, "result": result,
            }, idempotency_key="stale-fence")
        stale_epoch = {**fence, "runtime_epoch": fence["runtime_epoch"] + 1}
        with pytest.raises((LeaseError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {
                **stale_epoch, "error": {"code": "failed"}, "outputs": outputs, "result": result,
            }, idempotency_key="stale-epoch")
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
        _assert_no_generation_effect(service)
    finally:
        service.close()


def test_managed_envelope_identity_mismatch_is_rejected(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="identity")
    envelope = {
        "schema_version": 1,
        "kind": "managed-generation-result.v1",
        "inputs": {"source": None, "effective_settings": None, "values": {}},
        "outputs": [],
        "created": "2026-10-31T00:00:00Z",
        "warnings": [],
        "task_id": "another-task",
        "attempt_id": attempt["attempt_id"],
        "producer_run_id": "producer-run",
        "outcomes": {},
        "evidence": {"producer": {}, "transport": {}},
    }
    payload = json.dumps(envelope, sort_keys=True).encode()
    outputs = [_output(payload, name="managed-result", output_port="result_manifest", role="manifest")]
    try:
        with pytest.raises((ValidationError, ConflictError)):
            service.fail_attempt(attempt["attempt_id"], {
                "lease_id": attempt["lease_id"], "fence": attempt["fence"],
                "runtime_epoch": attempt["runtime_epoch"], "error": {"code": "failed"},
                "outputs": outputs,
                "result": {"manifest_ref": {"object_id": _digest(payload), "size": len(payload)}},
            }, idempotency_key="wrong-managed-identity")
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
    finally:
        service.close()


def test_unknown_stop_retains_fenced_attempt_and_custody(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="unknown-stop")
    outputs, result, fence = _evidence(task, attempt)
    body = {
        **fence,
        "attempt_id": attempt["attempt_id"],
        "outputs": outputs,
        "result": result,
        "stop_observed": False,
    }
    try:
        service.cancel_task_canonical(task["task"]["id"], body, idempotency_key="unknown-stop-cancel")
        stored = service.task(task["task"]["id"])
        assert stored["task"]["status"] == "cancel_requested"
        assert stored["task"].get("attempt_id") == attempt["attempt_id"]
        assert stored["task"].get("lease_token") == attempt["lease_id"]
        assert stored["task"].get("result", {}).get("cancel", {}).get("stop_observed") is False
        assert stored["task"]["result"]["manifest_ref"] == result["manifest_ref"]
        associations = _associations(service, task["task"]["id"])
        assert len(associations) == 2
        followup = {**fence, "attempt_id": attempt["attempt_id"], "stop_observed": True}
        service.cancel_task_canonical(task["task"]["id"], followup, idempotency_key="observed-stop-followup")
        finalized = service.task(task["task"]["id"])
        assert finalized["task"]["status"] == "cancelled"
        assert finalized["task"]["result"]["cancel"]["stop_observed"] is True
        assert len(_associations(service, task["task"]["id"])) == 2
        _assert_no_generation_effect(service)
    finally:
        service.close()


def test_cancel_requested_rejects_replacement_bytes_and_preserves_original_readback(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="cancel-replacement")
    original_outputs, original_result, fence = _evidence(task, attempt)
    request = {
        **fence, "attempt_id": attempt["attempt_id"], "outputs": original_outputs,
        "result": original_result, "stop_observed": False,
    }
    try:
        service.cancel_task_canonical(task["task"]["id"], request, idempotency_key="cancel-original-evidence")
        before = _associations(service, task["task"]["id"])
        original_digests = {item["output_port"]: item["object_id"].removeprefix("sha256:") for item in before}
        original_bytes = {
            item["output_port"]: service.cas.path_for(original_digests[item["output_port"]]).read_bytes()
            for item in before
        }
        changed_manifest = b'{"kind":"runtime-result","replacement":true}'
        changed_outputs, changed_result, _ = _evidence(task, attempt, manifest=changed_manifest, partial=b"replacement-output")
        with pytest.raises(ConflictError):
            service.cancel_task_canonical(task["task"]["id"], {
                **fence, "attempt_id": attempt["attempt_id"], "outputs": changed_outputs,
                "result": changed_result, "stop_observed": False,
            }, idempotency_key="cancel-replacement-evidence")
        assert service.task(task["task"]["id"])["task"]["status"] == "cancel_requested"
        after = _associations(service, task["task"]["id"])
        assert {item["output_port"]: item["object_id"].removeprefix("sha256:") for item in after} == original_digests
        for port, digest in original_digests.items():
            assert service.cas.path_for(digest).read_bytes() == original_bytes[port]
        service.cancel_task_canonical(task["task"]["id"], {
            **fence, "attempt_id": attempt["attempt_id"], "stop_observed": True,
        }, idempotency_key="cancel-observed-after-reject")
        assert service.task(task["task"]["id"])["task"]["status"] == "cancelled"
        assert len(_associations(service, task["task"]["id"])) == 2
    finally:
        service.close()


@pytest.mark.parametrize("terminal", ["failure", "cancel"])
def test_expired_attempt_rejects_terminal_evidence_without_publication(tmp_path, terminal):
    service, task, attempt, _root = _service(tmp_path, key=f"expired-evidence-{terminal}")
    outputs, result, fence = _evidence(task, attempt)
    expired = "2000-01-01T00:00:00+00:00"
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, task["task"]["id"]))
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
    try:
        with pytest.raises(LeaseError, match="expired"):
            if terminal == "failure":
                service.fail_attempt(attempt["attempt_id"], {
                    **fence, "error": {"code": "failed"}, "outputs": outputs, "result": result,
                }, idempotency_key="expired-failure-evidence")
            else:
                service.cancel_task_canonical(task["task"]["id"], {
                    **fence, "attempt_id": attempt["attempt_id"], "outputs": outputs,
                    "result": result, "stop_observed": True,
                }, idempotency_key="expired-cancel-evidence")
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 0
        for output in outputs:
            digest = output["digest"].removeprefix("sha256:")
            assert not service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone()
            assert not service.cas.path_for(digest).exists()
        assert not service.store.attempt_staging_dir(attempt["attempt_id"]).exists()
    finally:
        service.close()


def test_legacy_expired_failure_without_evidence_still_cedes_owner(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="expired-legacy-failure")
    expired = "2000-01-01T00:00:00+00:00"
    service.store.conn.execute("UPDATE tasks SET lease_expires_at=? WHERE id=?", (expired, task["task"]["id"]))
    service.store.conn.execute("UPDATE attempts SET lease_expires_at=? WHERE id=?", (expired, attempt["attempt_id"]))
    try:
        service.fail_attempt(attempt["attempt_id"], {
            **{key: attempt[key] for key in ("lease_id", "fence", "runtime_epoch")},
            "error": {"code": "legacy-owner-failed"},
        }, idempotency_key="expired-legacy-fail")
        stored = service.task(task["task"]["id"])["task"]
        assert stored["status"] == "failed"
        assert stored["attempt_id"] == attempt["attempt_id"]
        assert service.store.conn.execute("SELECT settled FROM attempts WHERE id=?", (attempt["attempt_id"],)).fetchone()[0] == 1
        assert _associations(service, task["task"]["id"]) == []
    finally:
        service.close()


def test_other_executor_cannot_publish_cancellation_evidence(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="wrong-cancel-worker")
    service.register_executor({"executor_id": "intruder", "capabilities": [CAPABILITY]}, idempotency_key="intruder")
    outputs, result, fence = _evidence(task, attempt)
    try:
        with pytest.raises(AuthorizationError, match="not bound to executor"):
            service.cancel_task_canonical(task["task"]["id"], {
                **fence, "attempt_id": attempt["attempt_id"], "outputs": outputs,
                "result": result, "stop_observed": True,
            }, idempotency_key="wrong-worker-cancel", identity={"actor": "intruder", "scopes": ["worker"]})
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
        for output in outputs:
            digest = output["digest"].removeprefix("sha256:")
            assert not service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone()
            assert not service.cas.path_for(digest).exists()
    finally:
        service.close()


def test_public_python_client_sends_evidence_payloads_matching_worker_wire_schema():
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import ValidationError as SchemaValidationError

    worker_schema = json.loads((Path(__file__).parents[1] / "contract" / "schemas" / "worker.json").read_text())
    definitions = worker_schema["definitions"]
    failure_validator = Draft202012Validator({"$schema": worker_schema["$schema"], "definitions": definitions, **definitions["AttemptFailure"]})
    cancel_validator = Draft202012Validator({"$schema": worker_schema["$schema"], "definitions": definitions, **definitions["TaskCancellation"]})
    outputs = [_output(b"manifest", name="manifest", output_port="result_manifest", role="manifest")]
    result = {"manifest_ref": {"object_id": _digest(b"manifest"), "size": len(b"manifest")}}
    calls = []

    def transport(method, path, headers, body):
        calls.append((method, path, headers, json.loads(body)))
        receipt = {"receipt_id": "receipt", "command_kind": "terminal", "idempotency_key": headers["Idempotency-Key"]}
        return 200, {}, json.dumps({"data": {"task_id": "task", "state": "terminal"}, "receipt": receipt}).encode()

    client = WorkspaceClient("http://runtime", transport=transport)
    client.fail_attempt("attempt", lease_id="lease", fence=7, runtime_epoch=3,
        error={"code": "failed"}, outputs=outputs, result=result, idempotency_key="client-fail-evidence")
    client.cancel_task("task", attempt_id="attempt", lease_id="lease", fence=7, runtime_epoch=3,
        outputs=outputs, result=result, stop_observed=False, idempotency_key="client-cancel-evidence")
    failure, cancel = [call[3] for call in calls]
    assert calls[0][1] == "/v1/attempts/attempt/fail"
    assert calls[1][1] == "/v1/tasks/task/cancel"
    assert failure == {"lease_id": "lease", "fence": 7, "runtime_epoch": 3,
        "error": {"code": "failed"}, "outputs": outputs, "result": result}
    assert cancel == {"attempt_id": "attempt", "lease_id": "lease", "fence": 7,
        "runtime_epoch": 3, "outputs": outputs, "result": result, "stop_observed": False}
    failure_validator.validate(failure)
    cancel_validator.validate(cancel)
    with pytest.raises(SchemaValidationError):
        cancel_validator.validate({"outputs": outputs})
    with pytest.raises(SchemaValidationError):
        cancel_validator.validate({"attempt_id": "attempt", "lease_id": "lease"})


def test_failure_publication_error_rolls_back_terminal_and_associations(tmp_path, monkeypatch):
    service, task, attempt, _root = _service(tmp_path, key="publication-rollback")
    outputs, result, fence = _evidence(task, attempt)
    original = service._publish_staged_outputs

    def publish_then_fail(staged, *, project_id=None):
        original(staged, project_id=project_id)
        raise OSError("injected publication failure after CAS copy")

    monkeypatch.setattr(service, "_publish_staged_outputs", publish_then_fail)
    try:
        with pytest.raises(OSError, match="injected publication failure"):
            service.fail_attempt(attempt["attempt_id"], {
                **fence, "error": {"code": "failed"}, "outputs": outputs, "result": result,
            }, idempotency_key="publication-rollback")
        assert service.task(task["task"]["id"])["task"]["status"] == "running"
        assert _associations(service, task["task"]["id"]) == []
        for output in outputs:
            digest = output["digest"].removeprefix("sha256:")
            assert not service.store.conn.execute("SELECT 1 FROM objects WHERE digest=?", (digest,)).fetchone()
            assert not service.cas.path_for(digest).exists()
        assert not service.store.attempt_staging_dir(attempt["attempt_id"]).exists()
    finally:
        service.close()


def test_cancel_before_start_preserves_input_refs_without_inventing_attempt(tmp_path):
    service, _unused_task, _attempt, _root = _service(tmp_path, key="before-start", inputs=True, claim=False)
    try:
        row = service.store.conn.execute("SELECT * FROM tasks ORDER BY created_at LIMIT 1").fetchone()
        queued_id = row["id"]
        source_refs = list(service.store._spec(row).get("input_object_ids", []))
        cancelled = service.cancel_task_canonical(queued_id, {}, idempotency_key="before-start-cancel")
        stored = service.task(queued_id)
        assert stored["task"]["status"] == "cancelled"
        assert stored["task"].get("attempt_id") is None
        assert stored["task"]["result"].get("attempt_id") is None
        assert stored["task"]["result"].get("input_object_ids") == source_refs
        assert cancelled
        assert _associations(service, queued_id) == []
    finally:
        service.close()


def test_success_and_observed_cancel_race_has_one_terminal_and_no_failure_effect(tmp_path):
    service, task, attempt, _root = _service(tmp_path, key="race")
    outputs, result, fence = _evidence(task, attempt)
    cancel_body = {
        **fence, "attempt_id": attempt["attempt_id"], "outputs": outputs,
        "result": result, "stop_observed": True,
    }
    success_body = {**fence, "outputs": outputs, "result": result}

    def cancel():
        return service.cancel_task_canonical(task["task"]["id"], cancel_body, idempotency_key="race-cancel")

    def succeed():
        return service.settle_attempt(attempt["attempt_id"], success_body, idempotency_key="race-success")

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(cancel), pool.submit(succeed)]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result())
                except (ConflictError, LeaseError, ValidationError) as exc:
                    outcomes.append(exc)
        status = service.task(task["task"]["id"])["task"]["status"]
        assert status in {"completed", "cancelled"}
        assert sum(not isinstance(value, Exception) for value in outcomes) == 1
        _assert_no_generation_effect(service)
        assert len(_associations(service, task["task"]["id"])) == 2
    finally:
        service.close()
