import { WorkspaceClient, type Transport } from "./generated.js";

async function main(): Promise<void> {
  const requests: { method: string; path: string; headers: Record<string, string>; body?: Uint8Array }[] = [];
  const viewOptions = { formats: ["md"], revision_id: "revision-smoke" };
  const viewResult = { inspection: { revision_id: "revision-smoke" }, artifacts: { md: { object_id: "view-smoke" } } };
  const transport: Transport = async (method, path, headers, body) => {
    requests.push({ method, path, headers, body });
    const payload = path === "/v1/health"
      ? { status: "ok", protocol: "workspace.v1", future_health_field: { retained: true } }
      : path.endsWith("/views")
        ? viewResult
      : { actor_id: "actor-smoke", realm_id: "realm-smoke", protocol: "workspace.v1", scopes: ["projects:read"], session_id: "session-smoke", future_handshake_field: "retained" };
    return { status: 200, headers: { "Content-Type": "application/json" }, body: new TextEncoder().encode(JSON.stringify(payload)) };
  };

  const client = new WorkspaceClient("http://runtime.invalid", "smoke-token", transport);
  const healthResponse = await client.call("health", "GET", "/v1/health");
  const health = JSON.parse(new TextDecoder().decode(healthResponse.body)) as Record<string, unknown>;
  if (health.status !== "ok" || (health.future_health_field as Record<string, unknown>)?.retained !== true) throw new Error("generic health response decoding failed");

  const handshake = await client.handshake("independent-smoke", "0.1.0", ["projects:read"]);
  if (handshake.actor_id !== "actor-smoke" || handshake.future_handshake_field !== "retained") throw new Error("handshake response decoding failed");
  const persistedView = await client.createTimelineView("project/smoke", "timeline/smoke", viewOptions, "view-smoke-key");
  if (JSON.stringify(persistedView) !== JSON.stringify(viewResult)) throw new Error("persisted view response decoding failed");
  if (requests.length !== 3 || requests.some((request) => request.headers.Authorization !== "Bearer smoke-token")) throw new Error("authorization header was not sent");
  const handshakeRequest = JSON.parse(new TextDecoder().decode(requests[1].body)) as Record<string, unknown>;
  if (requests[1].method !== "POST" || requests[1].path !== "/v1/handshake" || handshakeRequest.protocol !== "workspace.v1" || handshakeRequest.client_name !== "independent-smoke") throw new Error("handshake request encoding failed");
  const viewRequest = requests[2];
  if (viewRequest.method !== "POST" || viewRequest.path !== "/v1/projects/project%2Fsmoke/timelines/timeline%2Fsmoke/views" || viewRequest.headers["Idempotency-Key"] !== "view-smoke-key" || JSON.stringify(JSON.parse(new TextDecoder().decode(viewRequest.body))) !== JSON.stringify(viewOptions)) throw new Error("persisted view request encoding failed");
  console.log("independent TypeScript conformance client smoke passed");
}

function checkPersistedViewSignature(viewClient: WorkspaceClient): void {
  void viewClient.createTimelineView("project", "timeline", {}, "view-key");
  // @ts-expect-error Persisted views require an explicit caller idempotency key.
  void viewClient.createTimelineView("project", "timeline", {});
}

main().catch(error => { console.error(error); (globalThis as any).process.exitCode = 1; });
