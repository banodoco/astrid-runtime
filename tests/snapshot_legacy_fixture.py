"""Subprocess-only public API fixture for the M1 capture upgrade regression."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _cas_files(service):
    return {str(path.relative_to(service.store.cas_root)): path.read_bytes()
            for path in service.store.cas_root.rglob("*") if path.is_file()}


def _cas_hashes(service):
    return {path: hashlib.sha256(data).hexdigest() for path, data in _cas_files(service).items()}


def main():
    stage, runtime_root, agent_root, directory, field, inline = sys.argv[1:]
    sys.path[:0] = [agent_root, runtime_root]
    from tests.sdk.test_capture_source_runtime import CAPABILITY, CaptureRuntime, runtime
    from runtime_protocol.errors import ValidationError
    from runtime_protocol.service import RuntimeService

    directory = Path(directory)
    transfer = directory / "capture.json"
    if stage == "admit":
        fixture = runtime.__wrapped__(directory)
        client = next(fixture)
        try:
            snapshot = client.snapshot()
            if field == "config":
                snapshot["config"]["clips"][0]["hold"] = 123
            elif field == "registry":
                next(iter(snapshot["registry"]["assets"].values()))["opaque_asset"] = "forged meaning"
            elif field == "expansion":
                for key in ("capture_authority", "canonical_timeline"):
                    snapshot["metadata"][key]["expansion"]["shots"][0]["content_digest"] = "sha256:" + "0" * 64
            if field == "native":
                snapshot["metadata"].pop("capture_authority")
                snapshot["metadata"].pop("canonical_timeline")
            else:
                # A valid self-hash proves custody, never canonical meaning.
                identity = {"authority": snapshot["metadata"]["capture_authority"],
                            "config": snapshot["config"], "registry": snapshot["registry"]}
                snapshot["metadata"]["capture_identity"] = "sha256:" + hashlib.sha256(_json(identity).encode()).hexdigest()
                snapshot["video_digest"] = snapshot["metadata"]["capture_identity"]
            context = {"mode": "composed_capture", "project_id": client.project_id, "timeline_id": "main"}
            if field != "native":
                context["revision_id"] = "parent-1"
            if int(inline):
                context["capture_snapshot"] = snapshot
            else:
                if field == "native":
                    digest = client.service.ingest(client.project_id, _json(snapshot).encode(),
                                                   idempotency_key="native-capture")["data"]["object_id"]
                    context["capture_snapshot_ref"] = {"digest": digest, "project_id": client.project_id,
                                                       "timeline_id": "main", "source_kind": "cas"}
                else:
                    context["capture_snapshot_ref"] = client.ref(snapshot)
            request = {"project": client.project_id, "capability_id": CAPABILITY,
                       "idempotency_key": "legacy-capture",
                       "input_object_ids": [item["object_id"] for item in client.media_list(client.project_id)[0]],
                       "spec": {"authority_context": context,
                                "inputs": {"filmstrip_authority": _json(context)}}}
            accepted = client.service.create_task(request)
            ref = accepted["task"]["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
            assert client.service.object(ref["digest"])[1] == _json(snapshot).encode()
            transfer.write_text(_json({"request": request, "accepted": accepted, "snapshot": snapshot,
                                       "cas": _cas_hashes(client.service)}))
        finally:
            fixture.close()
        return

    recorded = json.loads(transfer.read_text())
    with_service = RuntimeService(directory / "realm")
    try:
        service = with_service
        before = _cas_files(service)
        assert _cas_hashes(service) == recorded["cas"]
        accepted = recorded["accepted"]
        task_id = accepted["task"]["id"]
        retry_refusal = None
        try:
            assert service.create_task(recorded["request"]) == accepted
        except ValidationError as exc:
            # This is the existing optional-provider refusal, not evidence of
            # safe claim/materialization. Continue exercising the stored task.
            assert str(exc) == "canonical capture projection provider is unavailable"
            retry_refusal = str(exc)
        task = service.task(task_id)
        assert task["task"]["id"] == task_id
        assert task["task"]["spec"] == accepted["task"]["spec"]
        claim = service.claim_next({"executor_id": "probe", "capability_ids": [CAPABILITY],
                                    "runtime_epoch": service.health()["runtime_epoch"]})
        assert claim["task_id"] == task_id
        client = CaptureRuntime(service, recorded["request"]["project"])
        values = client.materialize({"spec": claim["spec"]}, directory / "attempt")
        assert json.loads(Path(values["timeline"]).read_text()) == recorded["snapshot"]["config"]
        source = values.timeline_source
        if source is not None:
            binding = source.read()
            assert binding["snapshot"] == recorded["snapshot"]
            assert binding["authority"] == recorded["snapshot"]["metadata"]["capture_authority"]
            assert binding["ref"] == claim["spec"]["spec"]["authority_context"]["capture_snapshot_ref"]
        assert _cas_files(service) == before
        if field == "native":
            assert source is None, "native CAS preview must remain uncertified"
        print(_json({"canonical_source": type(source).__name__ if source is not None else None,
                     "retry_refusal": retry_refusal}))
    finally:
        with_service.close()


if __name__ == "__main__":
    main()
