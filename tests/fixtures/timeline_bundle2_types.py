from astrid_runtime_client import (
    ClipAddArgs,
    ClipDeleteArgs,
    ClipMoveArgs,
    ClipSetArgs,
    ClipSetParamsArgs,
    ClipSplitArgs,
    ClipTrimArgs,
    DocumentPin,
    InverseArgs,
    MediaSelection,
    OccurrenceAddMediaArgs,
    OccurrenceSwapMediaArgs,
    RestoreArgs,
    TrackCreateArgs,
    TrackSetArgs,
    VerifiedDocumentObject,
)

source: DocumentPin = {"document_id": "pack", "version": 1, "content_digest": "sha256:" + "a" * 64}
media: MediaSelection = {"asset": "asset", "generation_id": "g", "variant_id": "v", "object_id": source["content_digest"], "catalog_digest": source["content_digest"]}
added: ClipAddArgs = {"row": {"id": "c", "clipType": "element", "track": "v", "at": 0, "hold": 1}}
popup: OccurrenceAddMediaArgs = {"row": added["row"], "media": media}
swapped: OccurrenceSwapMediaArgs = {"old_media": media, "media": media}
moved: ClipMoveArgs = {"on": 1.25}
deleted: ClipDeleteArgs = {}
params: ClipSetParamsArgs = {"values": {"literal.key": None}, "clear": [], "schema_source": source}
scalar: ClipSetArgs = {"values": {"hold": 1.5}, "clear": ["asset", "transition"]}
trim: ClipTrimArgs = {"in_s": None, "out_s": 2.5}
split: ClipSplitArgs = {"on": 2.5, "right_id": "right"}
track: TrackCreateArgs = {"row": {"id": "v", "kind": "video"}}
label: TrackSetArgs = {"values": {"label": ""}, "clear": []}
inverse: InverseArgs = {"publications": ["receipt"]}
restore: RestoreArgs = {"revision_id": "r", "content_digest": source["content_digest"]}
object_value: VerifiedDocumentObject = {"object_id": media["object_id"], "digest": media["object_id"], "size": 2, "media_type": "application/json", "bytes_base64": "e30="}
missing_row: OccurrenceAddMediaArgs = {"row": {}, "media": media}  # type: ignore[typeddict-item]
extra_delete: ClipDeleteArgs = {"unknown": True}  # type: ignore[typeddict-unknown-key]
inline_schema: ClipSetParamsArgs = {"values": {"seed": 1}, "clear": [], "schema": {}}  # type: ignore[assignment]
