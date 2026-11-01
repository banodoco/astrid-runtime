/** Consumer imports resolve through the published package exports and declarations. */
import {
  CONTRACT_VERSION, WorkspaceClient, OperationHost, OperationHandle, OperationRetiredError,
  type OperationIdentity, type OperationConnection,
  type Health, type Handshake, type PreferenceResource, type MutationResult, type ServiceStatus, type TrackSetArgs,
  type MutationReceipt as MainMutationReceipt,
} from "@astrid/runtime-client";
import type { MutationReceipt as CommitMutationReceipt } from "../src/timeline-commit-types.js";

const version: string = CONTRACT_VERSION;
const client = new WorkspaceClient("http://runtime.invalid");
const roots = client.listProjectTasks("p", undefined, 1, "root_generation", "admitted_desc");
void roots;
const health: Promise<Health> = client.health();
const sourceIdentity: NonNullable<Health["identity"]> = {
  release: 0, managed_by: "source", runtime_head: "a".repeat(40), agent_head: "b".repeat(40),
  dirty: true, dirty_hash: "c".repeat(64),
};
const sourceHealth: Health = {
  status: "ok", protocol: "workspace.v1", schema_digest: "sha256:" + "a".repeat(64),
  runtime_epoch: 1, runtime_session_id: "session", runtime_instance_id: "instance", identity: sourceIdentity,
};
const handshake: Promise<Handshake> = client.handshake("consumer", version, []);
const preference: Promise<PreferenceResource> = client.getPreferences("user");
const mutation: Promise<MutationResult<unknown>> = client.createProject("consumer", "key");
const service: ServiceStatus = { name: "example", state: "starting", last_exit: null, restart_count: 0 };
void [health, sourceHealth, handshake, preference, mutation, service];
declare const commitReceipt: CommitMutationReceipt;
declare const mainReceipt: MainMutationReceipt;
const mainReceiptFromCommit: MainMutationReceipt = commitReceipt;
const commitReceiptFromMain: CommitMutationReceipt = mainReceipt;
const projectSequence: [number, number] = commitReceipt.project_seq;
const labeledTrack: TrackSetArgs = { values: { label: "Picture" }, clear: [] };
const clearedTrack: TrackSetArgs = { values: {}, clear: ["label"] };
const connection: OperationConnection = { baseUrl: "http://runtime.invalid", token: "owned-credential" };
const host = new OperationHost();
const handle: OperationHandle = host.bind(connection);
const operationIdentity: Promise<OperationIdentity> = handle.negotiate("consumer", version, []);
const current: boolean = handle.isCurrentIdentity({ actorId: "actor", realmId: "realm" });
const recovery: Promise<OperationIdentity> = handle.getRecoverableIdentity();
const operationClient: WorkspaceClient = handle.client;
const retiredError: Error = new OperationRetiredError();
handle.retire();
host.dispose();

// @ts-expect-error Both shared fields are required.
const missingTrackFields: TrackSetArgs = {};
// @ts-expect-error Label setting still requires the clear field.
const missingTrackClear: TrackSetArgs = { values: { label: "Picture" } };
// @ts-expect-error Explicit clear still requires the values field.
const missingTrackValues: TrackSetArgs = { clear: ["label"] };
// @ts-expect-error Track labels must be strings.
const invalidTrackLabel: TrackSetArgs = { values: { label: false }, clear: [] };
// @ts-expect-error Track clears only accept the label field.
const invalidTrackClear: TrackSetArgs = { values: {}, clear: ["volume"] };

void [
  health, handshake, preference, mutation, service, mainReceiptFromCommit, commitReceiptFromMain,
  projectSequence, labeledTrack, clearedTrack, missingTrackFields, missingTrackClear,
  missingTrackValues, invalidTrackLabel, invalidTrackClear,
  operationIdentity, current, recovery, operationClient, retiredError,
];

import type {
  ClipSetElementArgs, ElementRef, OccurrenceDeleteArgs, OccurrenceDuplicateArgs,
  OccurrenceAddMediaArgs, PlacementCreateArgs, PlacementUnplaceArgs,
  ProducerAdmittedTarget, ProducerIdentity, ProducerAttemptPin, ProducerGuardArgs,
  SettledProducerProposal, ShotPoolArgs, ShotSetArgs,
} from "@astrid/runtime-client";

const admittedTarget: ProducerAdmittedTarget = {
  project_id: "p", timeline_id: "t", base_revision_id: "r", base_publication_id: "txn",
};
const producer: ProducerIdentity = {
  task_id: "task", attempt_id: "attempt", executor_id: "executor", fence: 1, runtime_epoch: 1,
};
const producerPin: ProducerAttemptPin = {
  ...producer, admitted_target: admittedTarget, proposal_digest: "sha256:" + "a".repeat(64),
};
const producerGuard: ProducerGuardArgs = { pin: producerPin };
const proposal: SettledProducerProposal = {
  schema_version: 1, producer, admitted_target: admittedTarget, rationale: "Add track",
  proposal_digest: producerPin.proposal_digest,
  commands: [{ schema_version: 1, op: "track.create", version: "1", select: "parent",
    args: { row: { id: "v", kind: "video" } },
    reads: [{ ref: "parent", path: ["tracks"], state: { state: "present", value: [] } }],
  }],
};
const selectedMedia = { asset: "a", generation_id: "g", variant_id: "v", object_id: "digest", catalog_digest: "digest" };
const placement: PlacementCreateArgs = { id: "new", on: 0, hold: 1.5, media: selectedMedia, consumed: ["old"] };
const occurrenceMedia: OccurrenceAddMediaArgs = {
  row: { id: "c", clipType: "media", track: "v", at: 0, hold: 1.5 },
  media: selectedMedia, consumed: ["old"],
};
const element: ElementRef = { id: "e", kind: "component", revision: "r" };
const setElement: ClipSetElementArgs = { elementRef: element };
const retainedElement: ClipSetElementArgs = { elementRef: element,
  schema_source: { document_id: "pack", version: 1, content_digest: producerPin.proposal_digest } };
// @ts-expect-error A retained element declaration requires a complete DocumentPin.
const missingElementPinDigest: ClipSetElementArgs = { elementRef: element, schema_source: { document_id: "pack", version: 1 } };
void [retainedElement, missingElementPinDigest];
const shotSet: ShotSetArgs = { values: { settings: { enhancePrompt: false, batchVideoFrames: 1.5 } }, clear: [] };
const duplicate: OccurrenceDuplicateArgs = { occurrence_id: "o", shot_id: "s" };
const deleteOccurrence: OccurrenceDeleteArgs = {};
const unplace: PlacementUnplaceArgs = {};
const pool: ShotPoolArgs = { action: "add", media: selectedMedia };

// @ts-expect-error Producer pins require the original proposal digest.
const missingProducerDigest: ProducerAttemptPin = { ...producer, admitted_target: admittedTarget };
// @ts-expect-error Producer fence numbers cannot be booleans.
const booleanFence: ProducerIdentity = { ...producer, fence: true };
// @ts-expect-error Producer guard args are closed.
const extraGuardArg: ProducerGuardArgs = { pin: producerPin, extra: true };
// @ts-expect-error Consumed raw IDs are typed array items.
const booleanConsumed: PlacementCreateArgs = { ...placement, consumed: [false] };
// @ts-expect-error Read paths retain string tokens.
proposal.commands[0].reads = [{ ref: "parent", path: [1], state: { state: "absent" } }];
// @ts-expect-error Shot setting booleans cannot be numbers.
const numberBooleanSetting: ShotSetArgs = { values: { settings: { enhancePrompt: 1 } }, clear: [] };
// @ts-expect-error Shot setting numbers cannot be booleans.
const booleanNumberSetting: ShotSetArgs = { values: { settings: { batchVideoFrames: true } }, clear: [] };
// @ts-expect-error Element revisions remain required.
const missingElementRevision: ElementRef = { id: "e", kind: "component" };

void [producerGuard, proposal, occurrenceMedia, setElement, shotSet, duplicate,
  deleteOccurrence, unplace, pool, missingProducerDigest, booleanFence, extraGuardArg,
  booleanConsumed, numberBooleanSetting, booleanNumberSetting, missingElementRevision];

const persistedView: Promise<Record<string, unknown>> = client.createTimelineView("p", "t", {}, "view-key");
// @ts-expect-error Persisted views require an explicit caller idempotency key.
client.createTimelineView("p", "t", {});
void persistedView;
