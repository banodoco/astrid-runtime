import type { TrackSetArgs } from "../../packages/typescript/src/timeline-commit-types.js";

const label: TrackSetArgs = { values: { label: "Picture" }, clear: [] };
const empty: TrackSetArgs = { values: { label: "" }, clear: [] };
const unicode: TrackSetArgs = { values: { label: "Picture é 🎬" }, clear: [] };
const clear: TrackSetArgs = { values: {}, clear: ["label"] };
const combined: TrackSetArgs = { values: { label: "Picture" }, clear: ["label"] };

// @ts-expect-error Both shared fields are required.
const missing: TrackSetArgs = {};
// @ts-expect-error Label setting still requires the clear field.
const missingClear: TrackSetArgs = { values: { label: "Picture" } };
// @ts-expect-error Explicit clear still requires the values field.
const missingValues: TrackSetArgs = { clear: ["label"] };
// @ts-expect-error Neither branch permits an empty edit.
const noChange: TrackSetArgs = { values: {}, clear: [] };
// @ts-expect-error Null is not a label.
const nullLabel: TrackSetArgs = { values: { label: null }, clear: [] };
// @ts-expect-error Clear does not permit malformed label values.
const wrongLabel: TrackSetArgs = { values: { label: false }, clear: ["label"] };
// @ts-expect-error A label value does not permit malformed clears.
const wrongClear: TrackSetArgs = { values: { label: "Picture" }, clear: ["volume"] };
// @ts-expect-error Null is not an explicit clear list.
const nullClear: TrackSetArgs = { values: { label: "Picture" }, clear: null };
// @ts-expect-error The values object is closed.
const extraValue: TrackSetArgs = { values: { label: "Picture", volume: 1 }, clear: [] };
// @ts-expect-error The argument object is closed.
const extraArgument: TrackSetArgs = { values: {}, clear: ["label"], extra: true };

void [label, empty, unicode, clear, combined];
