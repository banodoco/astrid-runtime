// Driven by pytest over private pipes; all network responses come from Runtime.
import assert from "node:assert/strict";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const lines = createInterface({ input: process.stdin });
const input = lines[Symbol.asyncIterator]();
const next = async () => JSON.parse((await input.next()).value);
const emit = (event, extra = {}) => process.stdout.write(JSON.stringify({ event, ...extra }) + "\n");
const config = await next();
const { OperationHost, OperationRetiredError } = await import(pathToFileURL(config.client));
const { project_id: project, timeline_id: timeline } = config.body;
const path = `/v1/projects/${encodeURIComponent(project)}/timelines/${encodeURIComponent(timeline)}`;
const scopes = ["projects:read", "projects:write"];
const host = new OperationHost();
const calls = [];
let bodyWatch;
let freshToken;

// Observe the native transport only: dispatch immediately with the supplied
// options, return its actual Response and consume its actual response bytes.
const nativeFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (url, options) => {
  const pending = nativeFetch(url, options);
  const headers = new Headers(options.headers);
  calls.push({
    url, method: options.method, body: options.body && Buffer.from(options.body).toString(),
    key: headers.get("Idempotency-Key"),
    originalCredential: headers.get("Authorization") === `Bearer ${config.token}`,
    freshCredential: !!freshToken && headers.get("Authorization") === `Bearer ${freshToken}`,
    cookies: options.credentials, redirects: options.redirect,
  });
  return pending.then(response => {
    if (config.wait === "body" && new URL(url).pathname === bodyWatch) {
      bodyWatch = undefined;
      const arrayBuffer = response.arrayBuffer.bind(response);
      response.arrayBuffer = () => {
        const bytes = arrayBuffer();
        emit("body-await");
        return bytes;
      };
    }
    return response;
  });
};

const bind = token => host.bind({ baseUrl: config.base, token });
const negotiate = (handle, requested = scopes) => handle.negotiate("connector-integration", "1", requested);
const transmit = (handle, body = config.body) => handle.client.commitTimeline(project, timeline, body, config.key);
const retired = async (handle, identity, recover, current) => {
  const dispatched = calls.length;
  assert.equal(current(identity), false);
  await assert.rejects(recover(), OperationRetiredError);
  await assert.rejects(handle.client.getProjectTimeline(project, timeline), OperationRetiredError);
  await assert.rejects(transmit(handle), OperationRetiredError);
  assert.equal(calls.length, dispatched);
};

try {
  if (config.mode === "auth") {
    for (const operation of ["negotiate", "transmit"]) {
      const invalid = bind("not-a-runtime-credential");
      await assert.rejects(operation === "negotiate" ? negotiate(invalid) : transmit(invalid), OperationRetiredError);
      await assert.rejects(invalid.getRecoverableIdentity(), OperationRetiredError);
    }
    const excess = bind(config.token);
    await assert.rejects(negotiate(excess), OperationRetiredError);
    const reader = bind(config.token);
    const identity = await negotiate(reader, ["projects:read"]);
    await reader.client.getProjectTimeline(project, timeline);
    await assert.rejects(transmit(reader), OperationRetiredError);
    await retired(reader, identity, reader.getRecoverableIdentity, reader.isCurrentIdentity);
  } else {
    const old = bind(config.token);
    const identity = await negotiate(old);
    const recover = old.getRecoverableIdentity, current = old.isCurrentIdentity;
    assert.deepEqual(await recover(), identity);
    assert.equal(current(identity), true);
    const head = await old.client.getProjectTimeline(project, timeline);
    assert.equal(head.head_revision_id, config.body.base_revision_id);
    assert.equal(head.head_publication_id, config.body.base_publication_id);
    assert.deepEqual(calls.map(call => new URL(call.url).pathname), [
      "/v1/health", "/v1/handshake", "/v1/realm", path,
    ]);
    const originalBytes = JSON.stringify(config.body);
    let lateAckApplied = false;
    bodyWatch = path + "/commit";
    const lost = assert.rejects(transmit(old).then(result => {
      lateAckApplied = true;
      return result;
    }), OperationRetiredError);
    emit("ready");
    freshToken = (await next()).token;
    assert.ok(freshToken !== config.token);
    old.retire();
    const renewed = bind(freshToken);
    assert.notEqual(renewed, old);
    assert.notEqual(renewed.client, old.client);
    assert.deepEqual(await negotiate(renewed), identity);
    await retired(old, identity, recover, current);
    emit("rebound");
    await lost;
    assert.equal(lateAckApplied, false);
    assert.equal(current(identity), false);
    const replayed = await transmit(renewed, JSON.parse(originalBytes));
    assert.equal(replayed.data.status, "accepted");
    const commits = calls.filter(call => call.url.endsWith("/commit"));
    assert.equal(commits.length, 2);
    assert.equal(commits[0].body, originalBytes);
    assert.equal(commits[1].body, originalBytes);
    assert.equal(commits[0].key, config.key);
    assert.equal(commits[1].key, config.key);
    assert.equal(commits[0].originalCredential, true);
    assert.equal(commits[1].freshCredential, true);
    assert.ok(calls.slice(0, 5).every(call => call.originalCredential));
    assert.ok(calls.slice(5).every(call => call.freshCredential));
    emit("replayed", { result: replayed });
    await next();
    bodyWatch = path;
    let lateReadApplied = false;
    const read = assert.rejects(renewed.client.getProjectTimeline(project, timeline).then(value => {
      lateReadApplied = true;
      return value;
    }), OperationRetiredError);
    await next();
    host.dispose();
    await retired(renewed, identity, renewed.getRecoverableIdentity, renewed.isCurrentIdentity);
    emit("disposed");
    await read;
    assert.equal(lateReadApplied, false);
    await retired(old, identity, recover, current);
    assert.throws(() => bind(freshToken), OperationRetiredError);
  }
  assert.ok(calls.every(call => new URL(call.url).origin === config.base));
  assert.ok(calls.every(call => call.cookies === "omit" && call.redirects === "error"));
  emit("done");
} finally {
  host.dispose();
  globalThis.fetch = nativeFetch;
  lines.close();
  process.stdin.destroy();
}
