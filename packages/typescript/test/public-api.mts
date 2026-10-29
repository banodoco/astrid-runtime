/** Consumer imports resolve through the published package exports and declarations. */
import {
  CONTRACT_VERSION, WorkspaceClient,
  type Health, type Handshake, type PreferenceResource, type MutationResult, type ServiceStatus,
} from "@astrid/runtime-client";

const version: string = CONTRACT_VERSION;
const client = new WorkspaceClient("http://runtime.invalid");
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
