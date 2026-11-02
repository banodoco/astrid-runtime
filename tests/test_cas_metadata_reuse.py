"""A content digest identifies bytes; output annotations identify each use."""

import base64
import hashlib
import pytest

from runtime_protocol.errors import ConflictError
from test_generic_output_publication import (
    _descriptor, _filmstrip_attempt, _new_service, _settle_body, _upload_binding,
)
from test_runtime_child_delegation import (
    CHILD, admit, authority, claim, digest, parent, publish_snapshot,
    runtime, settle, snapshot_child, snapshot_parent, snapshot_upload, upload,
)


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "bound-upload"])
@pytest.mark.parametrize("scoped", [True, False], ids=["project-input", "unscoped-object"])
def test_preexisting_content_keeps_per_output_annotations_and_exports(tmp_path, inline, scoped):
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "reuse", "name": "Reuse"})
        payload = b"same Python source reused as JSON evidence"
        digest = hashlib.sha256(payload).hexdigest()
        original = service.ingest(project["id"] if scoped else None, payload,
            media_type="text/x-python", original_name="z_image_turbo.py", idempotency_key="source")["data"]
        task, attempt = _filmstrip_attempt(service, project["id"])
        output = _descriptor(payload, name="evidence", filename="evidence-source-source.json",
            output_port="evidence", primary=True, media_type="application/json")
        if inline:
            output["data_base64"] = base64.b64encode(payload).decode()
        if not inline or not scoped:
            key, binding = _upload_binding(payload, attempt=attempt, project_id=project["id"],
                run_id=task["run"]["id"], executor_id="filmstrip-worker", output_key=output["name"],
                output_port=output["output_port"], filename=output["filename"], media_type=output["media_type"])
            uploaded = service.ingest_object(payload, media_type=output["media_type"],
                original_name=output["filename"], idempotency_key=key, upload_binding=binding,
                identity={"actor": "filmstrip-worker", "scopes": ["objects:write", "worker:execute"]})
            assert uploaded["data"]["media_type"] == "application/json"
            assert uploaded["data"]["filename"] == output["filename"]
            assert service.ingest_object(payload, media_type=output["media_type"],
                original_name=output["filename"], idempotency_key=key, upload_binding=binding,
                identity={"actor": "filmstrip-worker", "scopes": ["objects:write", "worker:execute"]}) == uploaded
        body = _settle_body(attempt, [output])
        settled = service.settle_attempt(attempt["attempt_id"], body, idempotency_key="settle")
        assert service.task(attempt["task_id"])["task"]["status"] == "completed"
        association, = service.managed_outputs(attempt["task_id"])
        assert (association["digest"], association["filename"], association["media_type"]) == (
            "sha256:" + digest, output["filename"], output["media_type"])
        assert service.settle_attempt(attempt["attempt_id"], body, idempotency_key="settle") == settled
        row, data = service.object(digest)
        assert data == payload
        assert (row["original_name"], row["media_type"]) == ("z_image_turbo.py", "text/x-python")
        assert service.store.conn.execute("SELECT COUNT(*) FROM objects WHERE digest=?", (digest,)).fetchone()[0] == 1
        service.export_root = tmp_path / "exports"
        service.export_root.mkdir()
        exported = service.export_managed_output(association["association_id"],
            {"destination_filename": output["filename"], "expected": {
                "media_type": "application/json", "digest": original["digest"]}}, idempotency_key="export")
        assert exported["data"]["media_type"] == "application/json"
        assert (service.export_root / output["filename"]).read_bytes() == payload
        integrity = service.store.integrity_report()
        assert integrity["ok"], integrity
    finally:
        service.close()


@pytest.mark.parametrize("inline", [True, False], ids=["inline", "bound-upload"])
def test_two_uses_of_one_digest_can_have_different_types(tmp_path, inline):
    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "two-uses", "name": "Two uses"})
        task, attempt = _filmstrip_attempt(service, project["id"])
        payload = b"one object, two annotations"
        outputs = []
        for index, (filename, media_type) in enumerate((("source.py", "text/x-python"), ("evidence.json", "application/json"))):
            output = _descriptor(payload, name=f"use-{index}", filename=filename,
                output_port=f"use-{index}", primary=True, media_type=media_type)
            if inline:
                output["data_base64"] = base64.b64encode(payload).decode()
            else:
                key, binding = _upload_binding(payload, attempt=attempt, project_id=project["id"],
                    run_id=task["run"]["id"], executor_id="filmstrip-worker", output_key=output["name"],
                    output_port=output["output_port"], filename=filename, media_type=media_type)
                service.ingest_object(payload, media_type=media_type, original_name=filename,
                    idempotency_key=key, upload_binding=binding,
                    identity={"actor": "filmstrip-worker", "scopes": ["objects:write", "worker:execute"]})
            outputs.append(output)
        service.settle_attempt(attempt["attempt_id"], _settle_body(attempt, outputs), idempotency_key="settle")
        associations = service.managed_outputs(attempt["task_id"])
        assert len(associations) == 2 and len({item["object_id"] for item in associations}) == 1
        assert {(item["filename"], item["media_type"]) for item in associations} == {
            ("source.py", "text/x-python"), ("evidence.json", "application/json")}
        integrity = service.store.integrity_report()
        assert integrity["ok"], integrity
    finally:
        service.close()


def test_claimed_digest_with_different_bytes_still_refuses(tmp_path):
    service = _new_service(tmp_path / "realm")
    try:
        payload = b"immutable"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        service.ingest_object(payload, expected_digest=digest, idempotency_key="original")
        with pytest.raises(ConflictError, match="hash does not match expected digest"):
            service.ingest_object(b"different", expected_digest=digest,
                media_type="application/json", original_name="evidence.json", idempotency_key="collision")
        assert service.object(digest)[1] == payload
    finally:
        service.close()


def test_derived_input_annotations_survive_registration_and_child_admission(runtime):
    service, _ = runtime
    payload = b"new-parent-frame"
    service.ingest_object(payload, media_type="text/x-python", original_name="original.py", idempotency_key="original")
    attempt = parent(runtime)
    ref = upload(service, attempt, data=payload)
    receipt = authority(service, attempt, refs=[ref])
    child = admit(service, receipt, refs=[ref])
    assert child["task"]["spec"]["delegated_inputs"][0]["media_type"] == "application/octet-stream"


def test_snapshot_uses_its_receipted_annotations(runtime):
    service, _ = runtime
    payload = b'{"draft":1}'
    service.ingest_object(payload, media_type="text/plain", original_name="original.txt", idempotency_key="original")
    p = snapshot_parent(runtime)
    child = snapshot_child(service, p)
    output = snapshot_upload(service, child, data=payload)
    publish_snapshot(service, child, output)
    association, = service.managed_outputs(child["task_id"])
    assert (association["filename"], association["media_type"]) == ("draft.json", "application/json")


def test_parent_accepts_child_output_with_per_use_media_type(runtime):
    service, project = runtime
    payload = b"shared-child-output"
    service.ingest(project, payload, media_type="text/x-python", original_name="original.py", idempotency_key="original")
    p = parent(runtime)
    admit(service, authority(service, p))
    child = claim(service, CHILD, "child-claim")
    settle(service, child, "child-settle", [{"name": "result", "digest": digest(payload),
        "media_type": "application/json", "data_base64": base64.b64encode(payload).decode()}])
    settle(service, p, "parent-settle")
    assert service.task(p["task_id"])["task"]["status"] == "completed"


def test_historical_association_migration_uses_its_own_media_type(tmp_path):
    import sqlite3
    from test_historical_managed_output_migration import _historical_realm
    from runtime_protocol.upgrade import migrate_historical_managed_outputs

    root = tmp_path / "realm"
    digest_value = _historical_realm(root)
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        connection.execute("UPDATE objects SET media_type='application/octet-stream', original_name='original.bin' WHERE digest=?", (digest_value,))
    result = migrate_historical_managed_outputs(root, project_id="project-history", task_id="task-history",
        confirmation="MIGRATE MANAGED OUTPUTS realm-history")
    assert result["migrated"] == 1, result
    with sqlite3.connect(root / "realm.sqlite3") as connection:
        assert connection.execute("SELECT media_type, original_name FROM objects WHERE digest=?", (digest_value,)).fetchone() == (
            "application/octet-stream", "original.bin")
        assert connection.execute("SELECT media_type, filename FROM managed_output_associations").fetchone() == (
            "clip/visual", "historical.mp4")


def test_media_catalog_imports_keep_per_use_annotations(tmp_path):
    import io
    import wave

    service = _new_service(tmp_path / "realm")
    try:
        project = service.create_project({"slug": "catalog-reuse", "name": "Catalog reuse"})
        stream = io.BytesIO()
        with wave.open(stream, "wb") as audio:
            audio.setnchannels(1)
            audio.setsampwidth(2)
            audio.setframerate(8000)
            audio.writeframes(b"\0\0" * 80)
        payload = stream.getvalue()
        for index, (filename, media_type) in enumerate((("source.wav", "audio/wav"), ("evidence.wav", "audio/x-wav"))):
            imported = service.import_media(project["id"], payload, media_type=media_type,
                original_name=filename, actor_id="owner", idempotency_key=f"catalog-{index}")["data"]
            assert imported["status"] == "completed"
            assert imported["entry"]["media_type"] == media_type
            association, = service.managed_outputs(imported["task_id"])
            assert (association["filename"], association["media_type"]) == (filename, media_type)
        row, data = service.object(digest(payload))
        assert data == payload and (row["original_name"], row["media_type"]) == ("source.wav", "audio/wav")
        assert service.store.conn.execute("SELECT COUNT(*) FROM generation_variants").fetchone()[0] == 2
        integrity = service.store.integrity_report()
        assert integrity["ok"], integrity
    finally:
        service.close()
