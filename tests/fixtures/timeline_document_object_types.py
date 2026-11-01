from astrid_runtime_client.timeline_commit_types import VerifiedDocumentObject

value: VerifiedDocumentObject = {
    "object_id": "sha256:" + "a" * 64, "digest": "sha256:" + "a" * 64,
    "size": 2, "media_type": "application/json", "bytes_base64": "e30=",
}
missing: VerifiedDocumentObject = {"object_id": "id"}  # type: ignore[typeddict-item]
extra: VerifiedDocumentObject = {**value, "local_path": "/tmp/snapshot"}  # type: ignore[typeddict-unknown-key]
wrong_size: VerifiedDocumentObject = {**value, "size": "2"}  # type: ignore[typeddict-item]
wrong_media: VerifiedDocumentObject = {**value, "media_type": "text/plain"}  # type: ignore[typeddict-item]
raw_bytes: VerifiedDocumentObject = {**value, "bytes_base64": b"{}"}  # type: ignore[typeddict-item]
