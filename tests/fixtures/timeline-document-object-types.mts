import type { VerifiedDocumentObject } from "../../packages/typescript/src/index.js";

const object: VerifiedDocumentObject = {
  object_id: "sha256:" + "a".repeat(64), digest: "sha256:" + "a".repeat(64),
  size: 2, media_type: "application/json", bytes_base64: "e30=",
};
// @ts-expect-error All five fields are required.
const missing: VerifiedDocumentObject = { object_id: object.object_id };
// @ts-expect-error Closed object rejects unrelated fields.
const extra: VerifiedDocumentObject = { ...object, local_path: "/tmp/snapshot" };
// @ts-expect-error Booleans are not sizes.
const boolSize: VerifiedDocumentObject = { ...object, size: true };
// @ts-expect-error Only the approved JSON media type is supported.
const wrongMedia: VerifiedDocumentObject = { ...object, media_type: "text/plain" };
// @ts-expect-error Bytes must use the JSON-safe string representation.
const rawBytes: VerifiedDocumentObject = { ...object, bytes_base64: new Uint8Array() };
