// Conformance tests for a Bonvoyage relay (SPEC.md section 6).
//
//   node --test test/                      in-process, against the Node storage
//   RELAY_URL=http://localhost:8787 node --test test/     against any running relay
//
// Tests that need to move the clock only run in-process.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64url, createRelay, requestSigningInput, sha256hex } from "../src/core.js";

const REMOTE = process.env.RELAY_URL;
let clock = Math.floor(Date.now() / 1000);
let relay;
if (!REMOTE) {
  const { NodeStore } = await import("../src/store-node.js");
  relay = createRelay(new NodeStore(":memory:"), { now: () => clock, maxMessages: 3 });
}

const send = (request) => (REMOTE ? fetch(request) : relay.fetch(request));
const url = (path) => (REMOTE || "http://relay.test") + path;

async function newIdentity() {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const id = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
  return { id, privateKey: keys.privateKey };
}

async function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return { token: b64url(bytes), id: await sha256hex(bytes) };
}

async function owner(identity, method, path, body, { time, signedPath, signedBody } = {}) {
  const bytes = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
  const t = String(time ?? (REMOTE ? Math.floor(Date.now() / 1000) : clock));
  const input = await requestSigningInput(method, signedPath ?? path, t, signedBody ?? bytes);
  const sig = b64url(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, identity.privateKey, input)));
  return send(new Request(url(path), {
    method,
    headers: { "bonvoyage-auth": `t=${t},sig=${sig}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : bytes,
  }));
}

const drop = (inboxId, token, body, headers = {}) => send(new Request(url(`/v1/inbox/${inboxId}/messages`), {
  method: "POST",
  headers: { "content-type": "application/octet-stream", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
  body,
}));

function sealed(size = 4144) { // stands in for a sealed message: the relay never looks inside
  const bytes = new Uint8Array(size);
  for (let at = 0; at < size; at += 65536) crypto.getRandomValues(bytes.subarray(at, Math.min(at + 65536, size)));
  return bytes;
}

async function inboxWithToken() {
  const me = await newIdentity();
  const tok = await newToken();
  const res = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [tok.id] });
  assert.equal(res.status, 200);
  return { me, tok };
}

test("relay information", async () => {
  const res = await send(new Request(url("/v1")));
  assert.equal(res.status, 200);
  const info = await res.json();
  assert.equal(info.bonvoyage, 1);
  assert.equal(info.max_message_bytes, 65536);
  for (const key of ["max_messages", "retention_seconds", "max_tokens", "registration"]) assert.ok(key in info, key);
});

test("create an inbox, drop, collect, delete", async () => {
  const { me, tok } = await inboxWithToken();
  const first = sealed();
  const second = sealed(8240);
  const dropped = await drop(me.id, tok.token, first);
  assert.equal(dropped.status, 201);
  const { id: firstId } = await dropped.json();
  assert.match(firstId, /^[A-Za-z0-9_-]{22}$/);
  assert.equal((await drop(me.id, tok.token, second)).status, 201);

  const collected = await owner(me, "GET", `/v1/inbox/${me.id}/messages`);
  assert.equal(collected.status, 200);
  const { messages } = await collected.json();
  assert.equal(messages.length, 2);
  assert.equal(messages[0].id, firstId, "oldest first");
  assert.equal(messages[0].body, b64url(first), "body comes back byte for byte");
  assert.equal(messages[1].body, b64url(second));
  assert.equal(messages[0].token, tok.id, "the token ID it arrived with is reported");
  assert.equal(typeof messages[0].received, "number");

  const again = await (await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).json();
  assert.equal(again.messages.length, 2, "collecting does not remove messages");

  const path = `/v1/inbox/${me.id}/messages/${firstId}`;
  assert.equal((await owner(me, "DELETE", path)).status, 204);
  assert.equal((await owner(me, "DELETE", path)).status, 204, "deleting twice is fine");
  const left = await (await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).json();
  assert.deepEqual(left.messages.map((m) => m.body), [b64url(second)]);
});

test("dropping needs a token the inbox accepts", async () => {
  const { me, tok } = await inboxWithToken();
  const stranger = await newToken();
  const nobody = await newIdentity();
  const refusals = [
    await drop(me.id, null, sealed()),
    await drop(me.id, stranger.token, sealed()),
    await drop(me.id, "not-a-token", sealed()),
    await drop(nobody.id, tok.token, sealed()), // inbox does not exist
  ];
  for (const res of refusals) assert.equal(res.status, 401);
  const bodies = await Promise.all(refusals.map((r) => r.text()));
  assert.equal(new Set(bodies).size, 1, "unknown inbox and unknown token look the same");
  assert.equal((await drop(me.id, tok.token, new Uint8Array())).status, 400);
});

test("message size limit", async () => {
  const { me, tok } = await inboxWithToken();
  assert.equal((await drop(me.id, tok.token, sealed(65536))).status, 201);
  assert.equal((await drop(me.id, tok.token, sealed(65537))).status, 413);
});

test("owner requests must be signed by the inbox key", async () => {
  const { me, tok } = await inboxWithToken();
  const other = await newIdentity();
  const path = `/v1/inbox/${me.id}/messages`;
  const now = Math.floor(Date.now() / 1000);
  assert.equal((await send(new Request(url(path)))).status, 401, "no signature");
  assert.equal((await owner(other, "GET", path)).status, 401, "someone else's key");
  assert.equal((await owner(me, "GET", path, undefined, { time: (REMOTE ? now : clock) - 301 })).status, 401, "too old");
  assert.equal((await owner(me, "GET", path, undefined, { time: (REMOTE ? now : clock) + 301 })).status, 401, "too far ahead");
  assert.equal((await owner(me, "GET", path, undefined, { signedPath: `/v1/inbox/${me.id}` })).status, 401, "signed for another path");
  const tampered = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { signedBody: new TextEncoder().encode('{"tokens":["x"]}') });
  assert.equal(tampered.status, 401, "signature covers the body");
  assert.equal((await owner(other, "DELETE", `/v1/inbox/${me.id}`)).status, 401);
  assert.equal((await drop(me.id, tok.token, sealed())).status, 201, "inbox untouched by all of that");
});

test("replacing the token list revokes tokens", async () => {
  const { me, tok } = await inboxWithToken();
  const second = await newToken();
  const res = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [second.id, second.id] });
  assert.deepEqual((await res.json()).tokens, [second.id], "duplicates collapse");
  assert.equal((await drop(me.id, tok.token, sealed())).status, 401, "old token no longer works");
  assert.equal((await drop(me.id, second.token, sealed())).status, 201);
  for (const bad of [{ tokens: ["abc"] }, { tokens: "x" }, {}]) {
    assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, bad)).status, 400);
  }
});

test("deleting an inbox removes its messages", async () => {
  const { me, tok } = await inboxWithToken();
  await drop(me.id, tok.token, sealed());
  assert.equal((await owner(me, "DELETE", `/v1/inbox/${me.id}`)).status, 204);
  assert.equal((await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).status, 404);
  assert.equal((await drop(me.id, tok.token, sealed())).status, 401);
  await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [tok.id] });
  const fresh = await (await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).json();
  assert.deepEqual(fresh.messages, [], "a recreated inbox starts empty");
});

test("unknown paths and methods", async () => {
  const me = await newIdentity();
  assert.equal((await send(new Request(url("/v1/nothing")))).status, 404);
  assert.equal((await send(new Request(url("/v1/inbox/too-short")))).status, 404);
  assert.equal((await send(new Request(url(`/v1/inbox/${me.id}`)))).status, 405);
  assert.equal((await send(new Request(url(`/v1/inbox/${me.id}/messages`), { method: "PUT", body: "x" }))).status, 405);
});

test("inbox quota, retention and cleanup", { skip: REMOTE ? "needs control of the clock" : false }, async () => {
  const { me, tok } = await inboxWithToken();
  for (let i = 0; i < 3; i++) assert.equal((await drop(me.id, tok.token, sealed())).status, 201);
  assert.equal((await drop(me.id, tok.token, sealed())).status, 429, "full at max_messages");

  clock += 7 * 24 * 3600 + 1; // everything above is now past retention
  assert.equal((await drop(me.id, tok.token, sealed())).status, 201, "expired messages no longer count");
  const { messages } = await (await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).json();
  assert.equal(messages.length, 1, "expired messages are not delivered");

  const idle = await inboxWithToken();
  clock += 180 * 24 * 3600 + 1;
  await owner(me, "GET", `/v1/inbox/${me.id}/messages`); // me stays active
  await relay.cleanup();
  assert.equal((await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).status, 200);
  assert.equal((await owner(idle.me, "GET", `/v1/inbox/${idle.me.id}/messages`)).status, 404, "unused inbox removed");
});

test("closed registration keeps existing inboxes working", { skip: REMOTE ? "in-process only" : false }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const store = new NodeStore(":memory:");
  const open = createRelay(store, { now: () => clock });
  const closed = createRelay(store, { now: () => clock, registration: "closed" });
  const sign = async (identity, r, body) => {
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    const path = `/v1/inbox/${identity.id}`;
    const input = await requestSigningInput("PUT", path, String(clock), bytes);
    const sig = b64url(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, identity.privateKey, input)));
    return r.fetch(new Request(`http://relay.test${path}`, { method: "PUT", headers: { "bonvoyage-auth": `t=${clock},sig=${sig}` }, body: bytes }));
  };
  const existing = await newIdentity();
  assert.equal((await sign(existing, open, { tokens: [] })).status, 200);
  assert.equal((await sign(existing, closed, { tokens: [] })).status, 200, "existing inbox can still be updated");
  assert.equal((await sign(await newIdentity(), closed, { tokens: [] })).status, 403, "no new inboxes");
});
