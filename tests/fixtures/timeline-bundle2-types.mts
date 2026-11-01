import type {
  ClipAddArgs, ClipDeleteArgs, ClipMoveArgs, ClipSetArgs, ClipSetParamsArgs,
  ClipSplitArgs, ClipTrimArgs, DocumentPin, InverseArgs, MediaSelection,
  OccurrenceAddMediaArgs, OccurrenceSwapMediaArgs, RestoreArgs,
  TrackCreateArgs, TrackSetArgs, VerifiedDocument, VerifiedDocumentObject, VerifiedMedia,
} from "../../packages/typescript/src/index.js";
import { WorkspaceClient } from "../../packages/typescript/src/index.js";

const source: DocumentPin = { document_id: "pack", version: 1, content_digest: "sha256:" + "a".repeat(64) };
const media: MediaSelection = { asset: "asset", generation_id: "g", variant_id: "v", object_id: source.content_digest, catalog_digest: source.content_digest };
const verified: VerifiedMedia = { selection: media, media_type: "video/mp4", size: 42, duration_seconds: 2 };
function readVerified(client: WorkspaceClient): Promise<VerifiedMedia> {
  // @ts-expect-error The metadata read requires the complete captured pin.
  client.getProjectVerifiedMedia("p", { asset: "a", generation_id: "g", variant_id: "v" });
  return client.getProjectVerifiedMedia("p", media);
}
function readObject(client: WorkspaceClient): Promise<VerifiedDocumentObject> {
  // @ts-expect-error The retained object read requires the complete DocumentPin.
  client.getProjectVerifiedDocumentObject("p", { document_id: "pack" }, media.object_id);
  return client.getProjectVerifiedDocumentObject("p", source, media.object_id);
}
function readDocument(client: WorkspaceClient): Promise<VerifiedDocument> {
  // @ts-expect-error The retained document read requires the complete DocumentPin.
  client.getProjectVerifiedDocument("p", { document_id: "pack" });
  return client.getProjectVerifiedDocument("p", source);
}
void [verified, readVerified, readObject, readDocument];
const added: ClipAddArgs = { row: { id: "c", clipType: "element", track: "v", at: 0, hold: 1, opaque: { nil: null } } };
const popup: OccurrenceAddMediaArgs = { row: added.row, media };
const swapped: OccurrenceSwapMediaArgs = { old_media: media, media };
const moved: ClipMoveArgs = { on: 1.25 };
const deleted: ClipDeleteArgs = {};
const params: ClipSetParamsArgs = { values: { "literal.key": null, seed: 2 }, clear: [], schema_source: source };
const clearedParams: ClipSetParamsArgs = { values: {}, clear: ["seed"], schema_source: source };
const scalar: ClipSetArgs = { values: { hold: 1.5 }, clear: ["asset", "transition"] };
const cleared: ClipSetArgs = { values: {}, clear: ["hold"] };
const trim: ClipTrimArgs = { in_s: null, out_s: 2.5 };
const split: ClipSplitArgs = { on: 2.5, right_id: "right" };
const track: TrackCreateArgs = { row: { id: "v", kind: "video", label: "Picture", future: null } };
const label: TrackSetArgs = { values: { label: "" }, clear: [] };
const inverse: InverseArgs = { publications: ["receipt"] };
const restore: RestoreArgs = { revision_id: "r", content_digest: source.content_digest };
const object: VerifiedDocumentObject = { object_id: media.object_id, digest: media.object_id, size: 2, media_type: "application/json", bytes_base64: "e30=" };
const document: VerifiedDocument = { pin: source, document: { id: "pack", project_id: "p", kind: "astrid.project-pack", content: {}, version: 1, created_at: "now", updated_at: "now" } };
// @ts-expect-error schema_source is a complete immutable Document pin.
const missingPin: ClipSetParamsArgs = { values: { seed: 1 }, clear: [], schema_source: { document_id: "pack" } };
// @ts-expect-error No caller-supplied inline schema authority.
const inlineSchema: ClipSetParamsArgs = { values: { seed: 1 }, clear: [], schema: {} };
// @ts-expect-error Row pointer must retain its required fields.
const missingRow: OccurrenceAddMediaArgs = { row: {}, media };
// @ts-expect-error Numeric source times cannot be booleans.
const wrongHold: ClipAddArgs = { row: { ...added.row, hold: true } };
// @ts-expect-error Delete has closed empty arguments.
const extraDelete: ClipDeleteArgs = { ignored: true };
// @ts-expect-error Scalar clear must name a supported field.
const wrongClear: ClipSetArgs = { values: {}, clear: ["registry"] };
// @ts-expect-error Unknown outer operation arguments are closed.
const extraSplit: ClipSplitArgs = { on: 2, right_id: "right", extra: true };
// @ts-expect-error Native type keeps the immutable old media pin.
const missingOld: OccurrenceSwapMediaArgs = { media };
