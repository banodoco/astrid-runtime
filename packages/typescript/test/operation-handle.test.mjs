import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, OperationHandle, OperationHost, OperationRetiredError, PROTOCOL } from "@astrid/runtime-client";

const identity = { actorId: "product", realmId: "realm" };
const connection = { baseUrl: "http://runtime.invalid/", token: "credential-one" };
const accepted = { status: "accepted", accepted_revision_id: "revision-A" };
const receipt = { data: accepted, receipt: { receipt_id: "receipt-A", command_kind: "timeline.commit", idempotency_key: "original-key", request_hash: `sha256:${"a".repeat(64)}`, project_id: "project", project_seq: [1, 1], event_ids: [], result: accepted, created_at: "2026-10-23T00:00:00Z" } };
const request = {
  api_version: 1, project_id: "project", timeline_id: "timeline",
  base_revision_id: "original-head", base_publication_id: "original-publication",
  commands: [{ schema_version: 1, op: "clip.move", version: "1", select: "clip", args: { start: [3, 1] } }],
};
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });

function fixture(t) {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  const calls = [];
  const replies = new Map();
  globalThis.fetch = async (url, options) => {
    const path = new URL(url).pathname;
    const call = { url, ...options };
    calls.push(call);
    if (replies.has(path)) return replies.get(path)(call);
    if (path === "/v1/health") return response({ status: "ok", protocol: PROTOCOL, schema_digest: "schema" });
    if (path === "/v1/handshake") return response({
      protocol: PROTOCOL, schema_digest: "schema", actor_id: identity.actorId,
      realm_id: identity.realmId, scopes: ["projects:write"],
    });
    if (path === "/v1/realm") return response({ realm_id: identity.realmId });
    if (path.endsWith("/commit")) return response(receipt);
    if (path === "/v1/tasks" && options.method === "POST") return response({ data: { task_id: "task" }, receipt: { receipt_id: "task-receipt" } });
    if (path.endsWith("/managed-outputs")) return response({ items: [], next_cursor: null });
    return response({ task_id: "task", state: "succeeded" });
  };
  const host = new OperationHost();
  t.after(() => host.dispose());
  return { host, calls, replies };
}

const negotiate = handle => handle.negotiate("test-client", "1", ["projects:write"]);
const transmit = handle => handle.client.commitTimeline("project", "timeline", request, "original-key");

test("one client, base, credential and fetch serve negotiation, task, read and transmit", async t => {
  const { host, calls } = fixture(t);
  const selected = { ...connection };
  const handle = host.bind(selected);
  const client = handle.client;
  assert.equal(handle.isCurrentIdentity(identity), false);
  await assert.rejects(handle.getRecoverableIdentity(), /has not negotiated/);
  assert.deepEqual(await negotiate(handle), identity);
  assert.equal(handle.isCurrentIdentity(identity), true);
  await assert.rejects(negotiate(handle), /requires a new operation binding/);
  assert.equal(handle.isCurrentIdentity({ ...identity, actorId: "other" }), false);
  assert.equal(handle.isCurrentIdentity({ ...identity, realmId: "" }), false);

  selected.baseUrl = "http://unused.invalid";
  selected.token = "unused";
  globalThis.fetch = () => { throw new Error("replacement fetch must not be selected"); };
  await handle.client.admitTask({ capability_id: "assemble", capability_digest: "digest", input_object_ids: [] }, "task-key");
  await handle.client.getTask("task");
  await handle.client.listManagedOutputs("task");
  await handle.client.getObject("object");
  assert.deepEqual(await transmit(handle), receipt);
  assert.equal(handle.client, client);
  assert.equal(calls.length, 8);
  for (const call of calls) {
    assert.equal(new URL(call.url).origin, "http://runtime.invalid");
    assert.equal(call.headers.Authorization, "Bearer credential-one");
    assert.equal(call.credentials, "omit");
    assert.equal(call.redirect, "error");
  }
  const recovered = await handle.getRecoverableIdentity();
  recovered.actorId = "changed copy";
  handle.client.handshakeInfo.actor_id = "changed public handshake";
  assert.equal(handle.isCurrentIdentity(identity), true);
});

test("retire blocks a continuation after an await at actual generated-client dispatch", async t => {
  const { host, calls } = fixture(t);
  const handle = host.bind(connection);
  await negotiate(handle);
  const gate = deferred();
  const stale = (async () => {
    await gate.promise;
    return transmit(handle);
  })();
  handle.retire();
  gate.resolve();
  await assert.rejects(stale, OperationRetiredError);
  assert.equal(calls.length, 3);
  assert.equal(handle.isCurrentIdentity(identity), false);
  await assert.rejects(handle.getRecoverableIdentity(), OperationRetiredError);
  await assert.rejects(negotiate(handle), OperationRetiredError);
});

for (const transition of ["base", "credential", "transport", "reconnect", "dispose"]) {
  test(`${transition} retires original callbacks even with equal identity`, async t => {
    const { host, calls } = fixture(t);
    const old = host.bind(connection);
    await negotiate(old);
    const isCurrent = old.isCurrentIdentity;
    const recover = old.getRecoverableIdentity;
    const send = () => transmit(old);
    if (transition === "dispose") host.dispose();
    else {
      if (transition === "transport") {
        const prior = globalThis.fetch;
        globalThis.fetch = (...args) => prior(...args);
      }
      const next = host.bind({
        baseUrl: transition === "base" ? "http://other.invalid" : connection.baseUrl,
        token: transition === "credential" ? "credential-two" : connection.token,
      });
      assert.equal(isCurrent(identity), false);
      assert.equal(next.isCurrentIdentity(identity), false);
      await negotiate(next);
      assert.equal(next.isCurrentIdentity(identity), true);
    }
    const count = calls.length;
    assert.equal(isCurrent(identity), false);
    await assert.rejects(recover(), OperationRetiredError);
    await assert.rejects(send(), OperationRetiredError);
    assert.equal(calls.length, count);
    if (transition === "dispose") assert.throws(() => host.bind(connection), OperationRetiredError);
  });
}

test("old negotiation completion cannot revive a retired binding", async t => {
  const { host, calls, replies } = fixture(t);
  const gate = deferred();
  const entered = deferred();
  replies.set("/v1/handshake", () => { entered.resolve(); return gate.promise; });
  const old = host.bind(connection);
  const opening = negotiate(old);
  await entered.promise;
  const next = host.bind(connection);
  replies.delete("/v1/handshake");
  await negotiate(next);
  gate.resolve(response({ protocol: PROTOCOL, schema_digest: "schema", actor_id: identity.actorId, realm_id: identity.realmId, scopes: ["projects:write"] }));
  await assert.rejects(opening, OperationRetiredError);
  assert.equal(old.isCurrentIdentity(identity), false);
  assert.equal(next.isCurrentIdentity(identity), true);
  assert.equal(calls.filter(call => new URL(call.url).pathname === "/v1/realm").length, 1);
});

test("retirement during response-body await refuses a stale ACK", async t => {
  const { host, replies } = fixture(t);
  const handle = host.bind(connection);
  await negotiate(handle);
  const reading = deferred();
  const body = deferred();
  replies.set("/v1/projects/project/timelines/timeline/commit", () => ({
    status: 200, headers: new Headers(),
    arrayBuffer: () => { reading.resolve(); return body.promise; },
  }));
  const pending = transmit(handle);
  await reading.promise;
  handle.retire();
  body.resolve(new TextEncoder().encode(JSON.stringify(receipt)).buffer);
  await assert.rejects(pending, OperationRetiredError);
});

test("equal-identity renewal retries exact original bytes/key after uncertain ACK", async t => {
  const { host, calls, replies } = fixture(t);
  const old = host.bind(connection);
  await negotiate(old);
  const gate = deferred();
  replies.set("/v1/projects/project/timelines/timeline/commit", () => gate.promise);
  const pending = transmit(old);
  const next = host.bind({ ...connection, token: "credential-two" });
  await negotiate(next);
  gate.resolve(response(receipt));
  await assert.rejects(pending, OperationRetiredError);
  replies.delete("/v1/projects/project/timelines/timeline/commit");
  assert.deepEqual(await transmit(next), receipt);
  const commits = calls.filter(call => call.url.endsWith("/commit"));
  assert.equal(commits.length, 2);
  assert.deepEqual(commits[0].body, commits[1].body);
  assert.equal(commits[0].headers["Idempotency-Key"], "original-key");
  assert.equal(commits[1].headers["Idempotency-Key"], "original-key");
  assert.equal(commits[0].headers.Authorization, "Bearer credential-one");
  assert.equal(commits[1].headers.Authorization, "Bearer credential-two");
  assert.equal(old.isCurrentIdentity(identity), false);
  assert.equal(next.isCurrentIdentity(identity), true);
});

for (const failure of [401, 403, 503, "disconnect"]) {
  test(`received ${failure} retires the binding`, async t => {
    const { host, calls, replies } = fixture(t);
    const handle = host.bind(connection);
    await negotiate(handle);
    replies.set("/v1/tasks/task", () => {
      if (failure === "disconnect") throw new TypeError("connection lost");
      return response({ code: "unavailable" }, failure);
    });
    await assert.rejects(handle.client.getTask("task"));
    assert.equal(handle.isCurrentIdentity(identity), false);
    const count = calls.length;
    await assert.rejects(transmit(handle), OperationRetiredError);
    assert.equal(calls.length, count);
  });
}

test("mismatched negotiation and missing owned credentials fail closed", async t => {
  const { host, replies } = fixture(t);
  assert.throws(() => new OperationHandle({ ...connection, token: "" }), /owned credential/);
  const old = host.bind(connection);
  await negotiate(old);
  assert.throws(() => host.bind({ ...connection, token: "" }), /owned credential/);
  assert.equal(old.isCurrentIdentity(identity), false);
  const handle = host.bind(connection);
  replies.set("/v1/realm", () => response({ realm_id: "wrong-realm" }));
  await assert.rejects(negotiate(handle), /did not establish/);
  assert.equal(handle.isCurrentIdentity(identity), false);
  await assert.rejects(transmit(handle), OperationRetiredError);
});

test("semantic conflict preserves the live binding and generated error", async t => {
  const { host, replies } = fixture(t);
  const handle = host.bind(connection);
  await negotiate(handle);
  replies.set("/v1/projects/project/timelines/timeline/commit", () => response({ code: "conflict", message: "original guards conflict" }, 409));
  await assert.rejects(transmit(handle), error => error instanceof ApiError && error.status === 409 && error.code === "conflict");
  assert.equal(handle.isCurrentIdentity(identity), true);
  assert.deepEqual(await handle.getRecoverableIdentity(), identity);
});

test("public handshake snapshot cannot forge actor/scopes during realm await", async t => {
  const { host, replies } = fixture(t);
  replies.set("/v1/handshake", () => response({
    protocol: PROTOCOL, schema_digest: "schema", actor_id: identity.actorId,
    realm_id: identity.realmId, scopes: [],
  }));
  const entered = deferred(), gate = deferred();
  replies.set("/v1/realm", () => { entered.resolve(); return gate.promise; });
  const handle = host.bind(connection);
  const opening = negotiate(handle);
  await entered.promise;
  assert.equal(handle.client.handshakeInfo.actor_id, identity.actorId);
  assert.deepEqual(handle.client.handshakeInfo.scopes, []);
  handle.client.handshakeInfo.actor_id = "forged-actor";
  handle.client.handshakeInfo.scopes.push("projects:write");
  gate.resolve(response({ realm_id: identity.realmId }));
  await assert.rejects(opening, /did not establish/);
  assert.equal(handle.isCurrentIdentity({ actorId: "forged-actor", realmId: identity.realmId }), false);
  await assert.rejects(transmit(handle), OperationRetiredError);
});

test("scope string containing requested scope must fail closed", async t => {
  const { host, replies } = fixture(t);
  replies.set("/v1/handshake", () => response({
    protocol: PROTOCOL, schema_digest: "schema", actor_id: identity.actorId,
    realm_id: identity.realmId, scopes: "not-projects:write-granted",
  }));
  const handle = host.bind(connection);
  await assert.rejects(negotiate(handle), /did not establish/);
  assert.equal(handle.isCurrentIdentity(identity), false);
  await assert.rejects(transmit(handle), OperationRetiredError);
});

test("non-string schema digest must fail closed", async t => {
  const { host, replies } = fixture(t);
  replies.set("/v1/health", () => response({ status: "ok", protocol: PROTOCOL, schema_digest: 42 }));
  replies.set("/v1/handshake", () => response({
    protocol: PROTOCOL, schema_digest: 42, actor_id: identity.actorId,
    realm_id: identity.realmId, scopes: ["projects:write"],
  }));
  const handle = host.bind(connection);
  await assert.rejects(negotiate(handle), /did not establish/);
  assert.equal(handle.isCurrentIdentity(identity), false);
});

test("handshake authority is captured before public assignment and promise propagation", async t => {
  const { host } = fixture(t);
  const handle = host.bind(connection);
  let snapshot;
  Object.defineProperty(handle.client, "handshakeInfo", {
    get: () => snapshot,
    set: value => {
      snapshot = value;
      value.actor_id = "forged-actor";
      value.realm_id = "forged-realm";
      value.schema_digest = "forged-schema";
      value.scopes.length = 0;
    },
  });
  assert.deepEqual(await negotiate(handle), identity);
  assert.equal(snapshot.actor_id, "forged-actor");
  assert.equal(handle.isCurrentIdentity(identity), true);
  assert.equal(handle.isCurrentIdentity({ actorId: "forged-actor", realmId: "forged-realm" }), false);
});

for (const [path, field, value] of [
  ["health", "schema_digest", ""], ["health", "schema_digest", "  "],
  ["handshake", "schema_digest", null], ["handshake", "schema_digest", "  "],
  ["handshake", "actor_id", 42], ["handshake", "actor_id", "  "],
  ["handshake", "realm_id", 42], ["handshake", "realm_id", ""],
  ["realm", "realm_id", 42], ["realm", "realm_id", "  "],
  ["handshake", "scopes", null], ["handshake", "scopes", ["projects:write", 42]],
  ["handshake", "scopes", ["not-projects:write-granted"]],
]) {
  test(`malformed ${path}.${field} ${JSON.stringify(value)} retires negotiation`, async t => {
    const { host, replies } = fixture(t);
    const valid = {
      health: { status: "ok", protocol: PROTOCOL, schema_digest: "schema" },
      handshake: {
        protocol: PROTOCOL, schema_digest: "schema", actor_id: identity.actorId,
        realm_id: identity.realmId, scopes: ["projects:write"],
      },
      realm: { realm_id: identity.realmId },
    };
    replies.set(`/v1/${path}`, () => response({ ...valid[path], [field]: value }));
    const handle = host.bind(connection);
    await assert.rejects(negotiate(handle), /did not establish/);
    assert.equal(handle.isCurrentIdentity(identity), false);
    await assert.rejects(transmit(handle), OperationRetiredError);
  });
}

for (const stage of ["health", "handshake", "getRealm"]) {
  test(`retirement during ${stage} promise propagation blocks negotiation continuation`, async t => {
    const { host, calls } = fixture(t);
    const handle = host.bind(connection);
    const original = handle.client[stage].bind(handle.client);
    handle.client[stage] = (...args) => {
      const pending = original(...args);
      pending.then(() => handle.retire());
      return pending;
    };
    await assert.rejects(negotiate(handle), OperationRetiredError);
    assert.equal(calls.length, ["health", "handshake", "getRealm"].indexOf(stage) + 1);
    assert.equal(handle.isCurrentIdentity(identity), false);
  });
}

for (const stage of ["health", "handshake", "realm"]) {
  for (const wait of ["response", "body"]) {
    test(`retirement during ${stage} ${wait} await blocks negotiation continuation`, async t => {
      const { host, calls, replies } = fixture(t);
      const handle = host.bind(connection);
      const entered = deferred(), gate = deferred();
      replies.set(`/v1/${stage}`, () => {
        if (wait === "response") { entered.resolve(); return gate.promise; }
        return {
          status: 200, headers: new Headers(),
          arrayBuffer: () => { entered.resolve(); return gate.promise; },
        };
      });
      const pending = negotiate(handle);
      await entered.promise;
      handle.retire();
      const body = {
        status: "ok", protocol: PROTOCOL, schema_digest: "schema", actor_id: identity.actorId,
        realm_id: identity.realmId, scopes: ["projects:write"],
      };
      gate.resolve(wait === "response" ? response(body) : new TextEncoder().encode(JSON.stringify(body)).buffer);
      await assert.rejects(pending, OperationRetiredError);
      assert.equal(calls.length, ["health", "handshake", "realm"].indexOf(stage) + 1);
      assert.equal(handle.isCurrentIdentity(identity), false);
    });
  }
}

test("unsupported fetch wrapper that awaits forwarding can dispatch after retirement", async t => {
  const { host, calls } = fixture(t);
  const direct = globalThis.fetch;
  const entered = deferred(), gate = deferred();
  globalThis.fetch = async (url, options) => {
    if (new URL(url).pathname === "/v1/tasks/task") { entered.resolve(); await gate.promise; }
    return direct(url, options);
  };
  const handle = host.bind(connection);
  await negotiate(handle);
  const pending = handle.client.getTask("task");
  await entered.promise;
  handle.retire();
  assert.equal(calls.some(call => call.url.endsWith("/v1/tasks/task")), false);
  gate.resolve();
  await assert.rejects(pending, OperationRetiredError);
  assert.equal(calls.some(call => call.url.endsWith("/v1/tasks/task")), true);
});
