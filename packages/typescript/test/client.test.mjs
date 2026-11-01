import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { ApiError, CONTRACT_VERSION, WorkspaceClient } from "@astrid/runtime-client";

const json = (value) => new TextEncoder().encode(JSON.stringify(value));

test("generated TypeScript task query preserves default URL and forwards scoped generation query", async () => {
  const paths = [];
  const transport = async (method, path) => {
    assert.equal(method, "GET");
    paths.push(path);
    return { status: 200, headers: {}, body: json({ items: [], next_cursor: null }) };
  };
  const client = new WorkspaceClient("http://runtime", undefined, transport);
  assert.deepEqual(await client.listProjectTasks("p /"), { items: [], next_cursor: null });
  await client.listProjectTasks("p /", "signed/cursor", 1, "root_generation", "admitted_desc");
  assert.deepEqual(paths, ["/v1/projects/p%20%2F/tasks?limit=50",
    "/v1/projects/p%20%2F/tasks?limit=1&cursor=signed%2Fcursor&kind=root_generation&order=admitted_desc"]);
});

test("public commit client preserves v2 requests, receipts, previews and historical rebased replies", async () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const change = { op: "set", ref: "parent", path: ["config", "title"], before: { state: "absent" }, value: "Title" };
  const request = {
    api_version: 1, project_id: "p", timeline_id: "t", base_revision_id: "r", base_publication_id: "txn",
    commands: [
      { schema_version: 1, op: "doc.patch", version: "1", select: null, args: { changes: [change] } },
      { schema_version: 1, op: "clip.move", version: "1", select: "parent/clip:c", args: { on: 2 } },
    ],
    label: "Mixed edit", merge: "fields", reads: [{ kind: "scope", ref: "timeline", path: [] }], dry_run: false,
    steps: [
      { id: "patch", label: "Title", intent: "title", tags: [], command_ordinals: [0], patch: [change], reads: [{ kind: "scope", ref: "timeline", path: [] }] },
      { id: "semantic", label: "Move", intent: "move", tags: [], command_ordinals: [1], patch: [], reads: [{ kind: "scope", ref: "timeline", path: [] }] },
    ],
  };
  const candidate = {
    canonical_document: { schema_version: 1, project_id: "p", timeline_id: "t", parent_revision: { revision_id: "next-r", content_digest: digest, payload: { config: { clips: [], tracks: [] }, registry: {}, clips: [], occurrences: [] } }, shot_revisions: [], internal_timeline_revisions: [], dependency_manifest: { shots: [], internal_timelines: [], media: [], documents: [] } },
    document_digest: digest, commands: request.commands, id_map: {}, provider_version: "provider-v2", compiler_version: "compiler-v2",
    merge_mode: "fields", steps: request.steps,
  };
  const accepted = status => {
    const data = { status, base_revision_id: "r", base_publication_id: "txn", previous_revision_id: "head-r", previous_publication_id: "head-txn", accepted_revision_id: "next-r", rebased_onto: status === "accepted" ? null : { revision_id: "head-r", publication_id: "head-txn" }, publisher: "actor", ...candidate };
    return { data, receipt: { receipt_id: "receipt", command_kind: "timeline.commit", idempotency_key: "key", request_hash: digest, project_id: "p", project_seq: [1, 1], event_ids: [], result: data, created_at: "2026-10-23T00:00:00Z" } };
  };
  const preview = status => ({ data: { status: "preview", would_status: status, base_revision_id: "r", base_publication_id: "txn", evaluated_head: { revision_id: "head-r", publication_id: "head-txn" }, ...candidate }, receipt: null });
  let response, sent, httpStatus = 200;
  const client = new WorkspaceClient("http://runtime", "token", async (method, path, headers, body) => {
    assert.equal(method, "POST");
    assert.equal(path, "/v1/projects/p/timelines/t/commit");
    assert.equal(headers["Idempotency-Key"], "key");
    sent = JSON.parse(new TextDecoder().decode(body));
    return { status: httpStatus, headers: {}, body: json(response) };
  });
  for (const merge of ["fields", "atomic"]) {
    for (const status of ["accepted", "merged", "rebased"]) {
      response = accepted(status);
      assert.deepEqual(await client.commitTimeline("p", "t", { ...request, merge }, "key"), response);
      assert.deepEqual(sent, { ...request, merge });
    }
    for (const status of ["accepted", "merged"]) {
      response = preview(status);
      const body = { ...request, merge, dry_run: true };
      assert.deepEqual(await client.commitTimeline("p", "t", body, "key"), response);
      assert.deepEqual(sent, body);
    }
  }
  for (const field of Object.keys(accepted("merged").receipt)) {
    response = accepted("merged");
    delete response.receipt[field];
    await assert.rejects(client.commitTimeline("p", "t", request, "key"), /invalid commit receipt/);
  }
  for (const [field, value] of [
    ["receipt_id", null], ["command_kind", 1], ["idempotency_key", []], ["request_hash", {}], ["project_id", false], ["created_at", 1],
    ["project_seq", null], ["project_seq", [1]], ["project_seq", [1, 2, 3]], ["project_seq", [true, 1]], ["project_seq", [0, 1]], ["project_seq", [1, 1.5]], ["project_seq", ["1", 1]], ["event_ids", null], ["event_ids", [1]],
  ]) {
    response = accepted("merged");
    response.receipt[field] = value;
    await assert.rejects(client.commitTimeline("p", "t", request, "key"), /invalid commit receipt/);
  }
  response = accepted("merged");
  response.receipt = { receipt_id: "partial" };
  await assert.rejects(client.commitTimeline("p", "t", request, "key"), /invalid commit receipt/);
  for (const status of [undefined, null, "conflict", "invalid", "preview", [], {}]) {
    response = accepted("merged");
    response.data.status = status;
    await assert.rejects(client.commitTimeline("p", "t", request, "key"), /invalid commit status/);
  }
  for (const wouldStatus of [undefined, null, "rebased", "invalid", "preview", 1, [], {}]) {
    response = preview(wouldStatus);
    await assert.rejects(client.commitTimeline("p", "t", { ...request, dry_run: true }, "key"), /invalid commit preview/);
  }
  for (const [status, code, details] of [
    [409, "conflict", { status: "conflict", reason: "dependency_changed", current: { revision_id: "head-r", publication_id: "head-txn" } }],
    [422, "invalid", { status: "invalid", code: "previous_value_mismatch", path: ["commands", "0"], hint: "Read the current head", suggested_command: "timeline show" }],
  ]) {
    httpStatus = status;
    response = { code, message: code, details };
    await assert.rejects(client.commitTimeline("p", "t", request, "key"), error => error instanceof ApiError && error.status === status && error.code === code && assert.deepEqual(error.details, details) === undefined);
  }
});

test("verified media read preserves the complete pin and encoded alias without mutation authority", async () => {
  const selection = { asset: "alias/ &", generation_id: "g", variant_id: "v", object_id: `sha256:${"a".repeat(64)}`, catalog_digest: `sha256:${"b".repeat(64)}` };
  const verified = { selection, media_type: "video/mp4", size: 42, duration_seconds: 2 };
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push(path);
    assert.equal(method, "GET");
    assert.equal(body, undefined);
    assert.equal(headers.Authorization, "Bearer token");
    assert.equal(headers["Idempotency-Key"], undefined);
    const url = new URL(path, "http://runtime");
    assert.equal(url.pathname, "/v1/projects/project%2Fone/media-selection/verified");
    assert.deepEqual(Object.fromEntries(url.searchParams), selection);
    assert.equal([...url.searchParams].length, 5);
    return { status: 200, headers: {}, body: json(verified) };
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  assert.deepEqual(await client.getProjectVerifiedMedia("project/one", selection), verified);
  assert.equal(calls.length, 1);
});

test("verified document read sends the exact pin without mutation authority", async () => {
  const pin = { document_id: "document:pack/1", version: 1, content_digest: `sha256:${"a".repeat(64)}` };
  const verified = { pin, document: { document_id: pin.document_id, project_id: "p", kind: "astrid.project-pack", content: {}, version: 1, created_at: "now", updated_at: "now" } };
  const transport = async (method, path, headers, body) => {
    assert.equal(method, "GET");
    assert.equal(body, undefined);
    assert.equal(headers["Idempotency-Key"], undefined);
    const url = new URL(path, "http://runtime");
    assert.equal(url.pathname, "/v1/projects/project%2Fone/document-inputs/verified");
    assert.deepEqual(Object.fromEntries(url.searchParams), { ...pin, version: "1" });
    return { status: 200, headers: {}, body: json(verified) };
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  assert.deepEqual(await client.getProjectVerifiedDocument("project/one", pin), verified);
});

test("verified document object read sends the exact pin and object without mutation authority", async () => {
  const pin = { document_id: "document:pack/1", version: 1, content_digest: `sha256:${"a".repeat(64)}` };
  const objectId = `sha256:${"b".repeat(64)}`;
  const object = { object_id: objectId, digest: objectId, size: 2, media_type: "application/json", bytes_base64: "e30=" };
  const transport = async (method, path, headers, body) => {
    assert.equal(method, "GET");
    assert.equal(body, undefined);
    assert.equal(headers["Idempotency-Key"], undefined);
    const url = new URL(path, "http://runtime");
    assert.equal(url.pathname, "/v1/projects/project%2Fone/document-objects/verified");
    assert.deepEqual(Object.fromEntries(url.searchParams), { ...pin, version: "1", object_id: objectId });
    return { status: 200, headers: {}, body: json(object) };
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  assert.deepEqual(await client.getProjectVerifiedDocumentObject("project/one", pin, objectId), object);
});

test("generated TypeScript client performs scoped handshake and idempotent project admission", async () => {
  const release = JSON.parse(readFileSync(new URL("../../../generators/release.json", import.meta.url), "utf8"));
  assert.equal(CONTRACT_VERSION, release.contract_version);
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, headers, body });
    if (path === "/v1/handshake") return { status: 200, headers: {}, body: json({ protocol: "workspace.v1", schema_digest: `sha256:${"a".repeat(64)}`, session_id: "s", actor_id: "a", realm_id: "r", scopes: ["project:write"] }) };
    if (path === "/v1/projects") return { status: 201, headers: {}, body: json({ data: { project_id: "p", realm_id: "r", name: "Neutral", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }, receipt: { receipt_id: "runtime-command-1", command_kind: "project.create", idempotency_key: "idempotency-1", request_hash: `sha256:${"a".repeat(64)}`, project_id: "p", project_seq: [1, 1], event_ids: [], result: {}, created_at: "2026-01-01T00:00:00Z" } }) };
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const session = await client.handshake("neutral-gallery", "0.1.0", ["project:write"]);
  const project = await client.createProject("Neutral", "idempotency-1");
  assert.equal(session.realm_id, "r");
  assert.equal(project.project_id, "p");
  assert.equal(project.receipt.command_kind, "project.create");
  assert.equal(calls[1].headers.Authorization, "Bearer token");
  assert.equal(calls[1].headers["Idempotency-Key"], "idempotency-1");
});

test("public package exports the client and preserves response extensions without echoing envelope fields", async () => {
  const extension = { vendor_payload: { nested: ["opaque", 3] } };
  const extendedPreference = { ...preference, extension };
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, body: body && JSON.parse(new TextDecoder().decode(body)) });
    if (method === "GET") return { status: 200, headers: {}, body: json({ ...extendedPreference, response_extension: { retained: true } }) };
    return { status: 200, headers: {}, body: json({ data: extendedPreference, receipt: null, envelope_extension: { ignored: true } }) };
  };
  const client = new WorkspaceClient("http://runtime", undefined, transport);
  const received = await client.getPreferences("user");
  assert.deepEqual(received.extension, extension);
  assert.equal(received.response_extension.retained, true);
  const updated = await client.updatePreferences("user", "edited", 0, "extension-write");
  assert.deepEqual(updated.extension, extension);
  assert.deepEqual(calls[1].body, { content: "edited", expected_version: 0 });
});

test("generated TypeScript client preserves inclusive range and strong ETag", async () => {
  const transport = async (method, path, headers) => {
    assert.equal(method, "GET"); assert.equal(path, "/v1/objects/o"); assert.equal(headers.Range, "bytes=2-5");
    return { status: 206, headers: { ETag: `"sha256:${"b".repeat(64)}"`, "Content-Range": "bytes 2-5/10" }, body: new TextEncoder().encode("2345") };
  };
  const response = await new WorkspaceClient("http://runtime", undefined, transport).getObject("o", [2, 5]);
  assert.equal(response.status, 206); assert.equal(new TextDecoder().decode(response.data), "2345"); assert.equal(response.content_range, "bytes 2-5/10");
});

test("generated TypeScript client preserves the EventPage boundary", async () => {
  const event = { event_id: "1", sequence: 1, cursor: "1", event_type: "task.admitted", aggregate_type: "run", aggregate_id: "run-1", payload: {}, occurred_at: "2026-01-01T00:00:00Z" };
  const transport = async (method, path) => {
    assert.equal(method, "GET");
    assert.equal(path, "/v1/runs/run-1/events");
    return { status: 200, headers: {}, body: json({ items: [event], next_cursor: null }) };
  };
  const page = await new WorkspaceClient("http://runtime", undefined, transport).listRunEvents("run-1");
  assert.deepEqual(page, { items: [event], next_cursor: null });
});

test("generated TypeScript client exposes structured conflict errors", async () => {
  const transport = async () => ({ status: 409, headers: {}, body: json({ code: "version_conflict", message: "stale", request_id: "q", details: { actual: 2 } }) });
  await assert.rejects(() => new WorkspaceClient("http://runtime", undefined, transport).getProject("p"), (error) => error instanceof ApiError && error.code === "version_conflict" && error.details.actual === 2);
});

test("generated TypeScript client registers capabilities and fences failure", async () => {
  const task = { task_id: "t", run_id: "r", state: "failed", version: 2, capability_id: "render.basic", capability_digest: `sha256:${"b".repeat(64)}`, idempotency_key: "i", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" };
  const transport = async (method, path, headers, body) => {
    if (path === "/v1/capabilities") {
      assert.equal(method, "POST");
      const value = JSON.parse(new TextDecoder().decode(body));
      assert.equal(value.capability_id, "render.new");
      return { status: 201, headers: {}, body: json({ capability_id: "render.new", definition_digest: value.definition_digest, status: "ready", required_resource_keys: [], estimated_scratch_bytes: 0, estimated_output_bytes: 0 }) };
    }
    if (path === "/v1/attempts/a/fail") {
      assert.equal(JSON.parse(new TextDecoder().decode(body)).fence, 4);
      return { status: 200, headers: {}, body: json({ data: task, receipt: { receipt_id: "fail-receipt" } }) };
    }
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const capability = await client.registerCapability({ capability_id: "render.new", definition_digest: `sha256:${"c".repeat(64)}` }, "cap-1");
  const failed = await client.failAttempt("a", "lease", 4, { code: "worker_error" }, "fail-1");
  assert.equal(capability.capability_id, "render.new");
  assert.equal(failed.state, "failed");
});

test("generated TypeScript recovery routes preserve path identity and 201 checkpoint responses", async () => {
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, body: JSON.parse(new TextDecoder().decode(body)) });
    if (path.endsWith("/prepare-reboot")) return { status: 200, headers: {}, body: json({ attempt_id: "a/1", nonce: "n" }) };
    if (path.endsWith("/checkpoint")) return { status: 201, headers: {}, body: json({ checkpoint_id: "c", attempt_id: "a/1" }) };
    throw new Error(`unexpected ${method} ${path}`);
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  const prepared = await client.prepareReboot("a/1", "lease", 3, 7);
  const checkpoint = await client.checkpointAttempt("a/1", "lease", 3, "n", "n", { step: 2 }, 7);
  assert.equal(prepared.attempt_id, "a/1");
  assert.equal(checkpoint.checkpoint_id, "c");
  assert.equal(calls[0].path, "/v1/attempts/a%2F1/prepare-reboot");
  assert.equal(calls[0].body.attempt_id, undefined);
  assert.equal(calls[1].path, "/v1/attempts/a%2F1/checkpoint");
});

const preference = JSON.parse(readFileSync(new URL("../../../conformance/fixtures/preferences-user.json", import.meta.url), "utf8"));

test("preference clients preserve user null receipts and committed project receipts", async () => {
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, headers, body: body ? JSON.parse(new TextDecoder().decode(body)) : undefined });
    const data = path.includes("project") ? { ...preference, scope: "project", actor_id: null, project_id: "p /?", document_id: "preferences:project:p /?" } : preference;
    return { status: 200, headers: {}, body: json(method === "GET" ? data : { data, receipt: data.scope === "user" ? null : { receipt_id: "project-commit" } }) };
  };
  const client = new WorkspaceClient("http://runtime", "token", transport);
  assert.deepEqual(await client.getPreferences("user"), preference);
  const user = await client.updatePreferences("user", preference.content, 0, "write-1");
  assert.equal(user.receipt, null);
  assert.equal(user.content, preference.content);
  assert.deepEqual(calls.at(-1).body, { content: preference.content, expected_version: 0 });
  assert.equal(calls.at(-1).headers["Idempotency-Key"], "write-1");
  assert.equal(calls.at(-1).headers.Authorization, "Bearer token");
  const project = await client.updatePreferences("project", "text", 0, "write-2", "p /?");
  assert.equal(project.receipt.receipt_id, "project-commit");
  assert.equal(calls.at(-1).path, "/v1/preferences/project?project_id=p%20%2F%3F");
  await client.getPreferences("project");
  assert.equal(calls.at(-1).path, "/v1/preferences/project");
});

test("preference clients reject caller ownership and malformed null receipt results", async () => {
  const noTransport = new WorkspaceClient("http://runtime", undefined, async () => { throw new Error("transport called"); });
  await assert.rejects(() => noTransport.getPreferences("user", "p"), /cannot select a project/);
  await assert.rejects(() => noTransport.updatePreferences("user", "text", 0, "key", "p"), /cannot select a project/);
  await assert.rejects(() => noTransport.getPreferences("invalid"), /scope must be/);
  for (const response of [
    { data: preference, receipt: {} },
    { data: preference },
    { data: { ...preference, content: {} }, receipt: null },
    { data: { ...preference, version: true, future_extension: { opaque: true } }, receipt: null, future_envelope: true },
    { data: Object.fromEntries(Object.entries(preference).filter(([key]) => key !== "content")), receipt: null },
    { data: { ...preference, actor_id: null }, receipt: null },
    { data: { ...preference, project_id: "forged" }, receipt: null },
    { data: { ...preference, document_id: "other" }, receipt: null },
  ]) {
    const client = new WorkspaceClient("http://runtime", undefined, async () => ({ status: 200, headers: {}, body: json(response) }));
    await assert.rejects(() => client.updatePreferences("user", "text", 0, "key"), /invalid/);
  }
});

test("null preference receipts do not weaken ordinary or project mutation decoding", async () => {
  const data = { ...preference, scope: "project", actor_id: null, project_id: "p", document_id: "preferences:project:p" };
  const client = new WorkspaceClient("http://runtime", undefined, async () => ({ status: 200, headers: {}, body: json({ data, receipt: null }) }));
  await assert.rejects(() => client.updatePreferences("project", "text", 0, "key"), /committed receipt/);
  await assert.rejects(() => client.updateDocument("p", "d", 1, "key", "text"), /committed receipt/);
});

test("ordinary mutation extensions do not bypass known data and receipt types", async () => {
  for (const response of [
    null, [], { data: {}, receipt: "committed" }, { data: {}, receipt: [] },
    { data: [], receipt: {} }, { data: "project", receipt: {} },
  ]) {
    const body = response && !Array.isArray(response) ? { ...response, future_field: true } : response;
    const client = new WorkspaceClient("http://runtime", undefined, async () => ({ status: 201, headers: {}, body: json(body) }));
    await assert.rejects(() => client.createProject("Project", "key"), /invalid mutation response/);
  }
  const client = new WorkspaceClient("http://runtime", undefined, async () => ({ status: 201, headers: {}, body: json({ data: { project_id: "p", metadata: { opaque: [1, { future: true }] } }, receipt: { receipt_id: "r", future_receipt: true }, future_envelope: true }) }));
  const result = await client.createProject("Project", "key");
  assert.deepEqual(result.metadata, { opaque: [1, { future: true }] });
  assert.equal(result.receipt.future_receipt, true);
  assert.equal(result.future_envelope, undefined);
});

test("document kind filter preserves existing pagination arguments and escapes query values", async () => {
  const client = new WorkspaceClient("http://runtime", undefined, async (method, path) => {
    assert.equal(method, "GET");
    assert.equal(path, "/v1/projects/p%20%2F/documents?limit=5&cursor=next%2Fpage&kind=astrid.note%20%2F%3F");
    return { status: 200, headers: {}, body: json({ items: [], next_cursor: null }) };
  });
  assert.deepEqual(await client.listDocuments("p /", "next/page", 5, "astrid.note /?"), { items: [], next_cursor: null });
});
test("binary client imports forward Blob without materializing its bytes", async () => {
  const blob = new Blob(["media"], { type: "video/mp4" });
  blob.arrayBuffer = async () => { throw new Error("whole file was buffered"); };
  const calls = [];
  const transport = async (method, path, headers, body) => {
    assert.equal(body, blob);
    calls.push(path);
    return { status: 201, headers: {}, body: json({ data: { object_id: "sha256:media" }, receipt: { receipt_id: "receipt" } }) };
  };
  const client = new WorkspaceClient("http://runtime", undefined, transport);
  await client.ingestObject(blob, "video/mp4", "object");
  await client.ingestProjectObject("project", blob, "video/mp4", "project-object");
  await client.importProjectMedia("project", blob, "video/mp4", "media");
  assert.deepEqual(calls, ["/v1/objects", "/v1/projects/project/objects", "/v1/projects/project/media-imports"]);
});

test("default fetch receives Blob directly", async () => {
  const previousFetch = globalThis.fetch;
  const blob = new Blob(["media"], { type: "image/png" });
  blob.arrayBuffer = async () => { throw new Error("whole file was buffered"); };
  globalThis.fetch = async (url, options) => {
    assert.equal(options.body, blob);
    return new Response(json({ data: { object_id: "sha256:media" }, receipt: { receipt_id: "receipt" } }), { status: 201 });
  };
  try {
    await new WorkspaceClient("http://runtime").importProjectMedia("project", blob, "image/png", "media");
  } finally {
    globalThis.fetch = previousFetch;
  }
});


test("persisted timeline view sends explicit key and preserves the plain view response", async () => {
  const options = { formats: ["md"], revision_id: "r1" };
  const result = { inspection: { revision_id: "r1" }, artifacts: { md: { object_id: "view-object" } } };
  const transport = async (method, path, headers, body) => {
    assert.equal(method, "POST");
    assert.equal(path, "/v1/projects/p%2Fone/timelines/t%2Ftwo/views");
    assert.equal(headers.Authorization, "Bearer writer");
    assert.equal(headers["Idempotency-Key"], "view-retry");
    assert.deepEqual(JSON.parse(new TextDecoder().decode(body)), options);
    return { status: 200, headers: {}, body: json(result) };
  };
  const client = new WorkspaceClient("http://runtime", "writer", transport);
  assert.deepEqual(await client.createTimelineView("p/one", "t/two", options, "view-retry"), result);
});

test("app-state client reads absent state, writes with a null receipt and rejects mismatched resources", async () => {
  const content = { version: 1, outcome: "completed", step: "finale", at: "2026-10-21T00:00:00Z" };
  const resource = { scope: "user", actor_id: "a", key: "editor-tour", content, version: 1, created_at: "t", updated_at: "t" };
  const calls = [];
  const transport = async (method, path, headers, body) => {
    calls.push({ method, path, headers, body: body ? JSON.parse(new TextDecoder().decode(body)) : undefined });
    if (path.endsWith("/other-key")) return { status: 200, headers: {}, body: json(resource) };
    if (method === "GET") return { status: 200, headers: {}, body: json({ ...resource, content: null, version: 0, created_at: null, updated_at: null }) };
    return { status: 200, headers: {}, body: json({ data: resource, receipt: null }) };
  };
  const client = new WorkspaceClient("http://runtime", "writer", transport);
  const empty = await client.getUserAppState("editor-tour");
  assert.equal(empty.content, null);
  assert.equal(calls[0].path, "/v1/app-state/user/editor-tour");
  const saved = await client.updateUserAppState("editor-tour", content, 0, "idem-1");
  assert.deepEqual(saved.content, content);
  assert.equal(calls[1].method, "PUT");
  assert.equal(calls[1].headers["Idempotency-Key"], "idem-1");
  assert.deepEqual(calls[1].body, { content, expected_version: 0 });
  await assert.rejects(client.getUserAppState("other-key"), /invalid app-state resource/);
});
