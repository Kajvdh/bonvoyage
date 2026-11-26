// Conformance tests for a Bonvoyage relay (SPEC.md section 6).
//
//   node --test test/                      in-process, against the Node storage
//   RELAY_URL=http://localhost:8787 node --test test/     against any running relay
//
// Tests that need to move the clock or change settings only run in-process.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64url, createRelay, requestSigningInput, sha256hex } from "../src/core.js";

const REMOTE = process.env.RELAY_URL;
const BASE = REMOTE || "http://relay.test";
const HOST = new URL(BASE).host;
const LOCAL = REMOTE ? "only in-process" : false;
let clock = Math.floor(Date.now() / 1000);
let relay;
if (!REMOTE) {
  const { NodeStore } = await import("../src/store-node.js");
  relay = createRelay(new NodeStore(":memory:"), { now: () => clock, maxNewInboxesPerHour: 1000 });
}

const send = (request, target = relay) => (REMOTE ? fetch(request) : target.fetch(request));
const url = (path) => BASE + path;
const now = () => (REMOTE ? Math.floor(Date.now() / 1000) : clock);

async function newIdentity() {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const id = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
  return { id, privateKey: keys.privateKey };
}

async function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return { token: b64url(bytes), id: await sha256hex(bytes) };
}

/** A signed owner request. `forge` overrides parts of what is signed or sent. */
async function ownerRequest(identity, method, path, body, forge = {}) {
  const bytes = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
  const t = String(forge.time ?? now());
  const input = await requestSigningInput(method, forge.host ?? HOST, forge.signedPath ?? path, t, forge.signedBody ?? bytes);
  const sig = b64url(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, identity.privateKey, input)));
  return new Request(url(path + (forge.query ?? "")), {
    method,
    headers: { "bonvoyage-auth": forge.header ?? `t=${t},sig=${sig}`, ...(forge.headers ?? {}) },
    body: body === undefined ? undefined : bytes,
  });
}

const owner = async (...args) => send(await ownerRequest(...args));

const drop = (inboxId, token, body, headers = {}) => send(new Request(url(`/v1/inbox/${inboxId}/messages`), {
  method: "POST",
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
  body,
}));

/** Stands in for a sealed message of n blocks: the relay never looks inside. */
function sealed(blocks = 1, extra = 0) {
  const bytes = new Uint8Array(48 + blocks * 4096 + extra);
  for (let at = 0; at < bytes.length; at += 65536) crypto.getRandomValues(bytes.subarray(at, Math.min(at + 65536, bytes.length)));
  return bytes;
}

async function inboxWithToken() {
  const me = await newIdentity();
  const tok = await newToken();
  const res = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [tok.id] });
  assert.equal(res.status, 200);
  return { me, tok };
}

const tick = () => (REMOTE ? new Promise((r) => setTimeout(r, 1100)) : void (clock += 1));

test("relay information", async () => {
  const res = await send(new Request(url("/v1")));
  assert.equal(res.status, 200);
  const info = await res.json();
  assert.equal(info.bonvoyage, 1);
  assert.equal(info.max_message_bytes, 61488);
  for (const key of ["max_messages", "max_messages_per_token", "retention_seconds", "max_tokens", "poll_seconds"]) {
    assert.equal(typeof info[key], "number", key);
  }
  assert.ok(["open", "invite", "closed"].includes(info.registration));
});

test("create an inbox, drop, collect, delete", async () => {
  const { me, tok } = await inboxWithToken();
  const first = sealed(1);
  const second = sealed(2);
  const dropped = await drop(me.id, tok.token, first);
  assert.equal(dropped.status, 201);
  const { id: firstId } = await dropped.json();
  assert.match(firstId, /^[A-Za-z0-9_-]{1,64}$/);
  assert.equal((await drop(me.id, tok.token, second, { "content-type": "application/octet-stream" })).status, 201);

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
    await drop(me.id, tok.token.slice(0, -1) + (tok.token.endsWith("B") ? "C" : "B"), sealed()),
    await drop(nobody.id, tok.token, sealed()), // inbox does not exist
  ];
  for (const res of refusals) assert.equal(res.status, 401);
  const bodies = await Promise.all(refusals.map((r) => r.text()));
  assert.equal(new Set(bodies).size, 1, "unknown inbox and unknown token look the same");
});

test("only sealed-message sizes are accepted", async () => {
  const { me, tok } = await inboxWithToken();
  assert.equal((await drop(me.id, tok.token, sealed(15))).status, 201, "the largest sealed message");
  assert.equal((await drop(me.id, tok.token, sealed(16))).status, 413, "one block more is too large");
  for (const wrong of [new Uint8Array(), new Uint8Array(48), sealed(1, 1), sealed(1, -1), new Uint8Array(5000)]) {
    assert.equal((await drop(me.id, tok.token, wrong)).status, 400, `length ${wrong.length} is not a sealed message`);
  }
});

test("owner requests must be signed by the inbox key, for this relay", async () => {
  const { me, tok } = await inboxWithToken();
  const other = await newIdentity();
  const path = `/v1/inbox/${me.id}/messages`;
  assert.equal((await send(new Request(url(path)))).status, 401, "no signature");
  assert.equal((await owner(other, "GET", path)).status, 401, "someone else's key");
  assert.equal((await owner(me, "GET", path, undefined, { time: now() - 301 })).status, 401, "too old");
  assert.equal((await owner(me, "GET", path, undefined, { time: now() + 301 })).status, 401, "too far ahead");
  assert.equal((await owner(me, "GET", path, undefined, { signedPath: `/v1/inbox/${me.id}` })).status, 401, "signed for another path");
  assert.equal((await owner(me, "GET", path, undefined, { host: "other-relay.example" })).status, 401, "signed for another relay");
  assert.equal((await owner(me, "GET", path, undefined, { header: `t=0${now()},sig=${"A".repeat(86)}` })).status, 401, "malformed header");
  const tampered = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { signedBody: new TextEncoder().encode('{"tokens":["x"]}') });
  assert.equal(tampered.status, 401, "signature covers the body");
  assert.equal((await owner(other, "DELETE", `/v1/inbox/${me.id}`)).status, 401);
  assert.equal((await drop(me.id, tok.token, sealed())).status, 201, "inbox untouched by all of that");
});

test("an inbox PUT or DELETE cannot be replayed", async () => {
  const me = await newIdentity();
  const first = await newToken();
  const put = await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [first.id] });
  const replay = put.clone();
  assert.equal((await send(put)).status, 200);
  await tick();
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] })).status, 200, "the owner revokes the token");
  assert.equal((await send(replay)).status, 409, "replaying the earlier PUT does not undo it");
  assert.equal((await drop(me.id, first.token, sealed())).status, 401);

  const del = await ownerRequest(me, "DELETE", `/v1/inbox/${me.id}`);
  const delReplay = del.clone();
  assert.equal((await send(del)).status, 204);
  await tick();
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] })).status, 200, "recreated");
  assert.equal((await send(delReplay)).status, 409, "the old DELETE cannot remove the new inbox");
  assert.equal((await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).status, 200);
});

test("replacing the token list revokes tokens", async () => {
  const { me, tok } = await inboxWithToken();
  const second = await newToken();
  await tick();
  const res = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [second.id, second.id] });
  assert.deepEqual(await res.json(), { id: me.id, tokens: [second.id] }, "duplicates collapse");
  assert.equal((await drop(me.id, tok.token, sealed())).status, 401, "old token no longer works");
  assert.equal((await drop(me.id, second.token, sealed())).status, 201);
  await tick();
  for (const bad of [{ tokens: ["abc"] }, { tokens: "x" }, {}, { tokens: Array(65).fill("0".repeat(64)) }]) {
    assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, bad)).status, 400);
  }
});

test("each contact has its own share of the inbox", async () => {
  const me = await newIdentity();
  const [kaj, jan] = [await newToken(), await newToken()];
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [kaj.id, jan.id] })).status, 200);
  for (let i = 0; i < 10; i++) assert.equal((await drop(me.id, kaj.token, sealed())).status, 201);
  const full = await drop(me.id, kaj.token, sealed());
  assert.equal(full.status, 429, "one token cannot hold more than max_messages_per_token");
  assert.ok(Number(full.headers.get("retry-after")) > 0, "429 carries Retry-After");
  assert.equal((await drop(me.id, jan.token, sealed())).status, 201, "another contact still gets through");
});

test("deleting an inbox removes its messages", async () => {
  const { me, tok } = await inboxWithToken();
  await drop(me.id, tok.token, sealed());
  await tick();
  assert.equal((await owner(me, "DELETE", `/v1/inbox/${me.id}`)).status, 204);
  assert.equal((await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).status, 404);
  assert.equal((await drop(me.id, tok.token, sealed())).status, 401);
  await tick();
  await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [tok.id] });
  const fresh = await (await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).json();
  assert.deepEqual(fresh.messages, [], "a recreated inbox starts empty");
});

test("unknown paths, methods, query strings and non-canonical IDs", async () => {
  const { me } = await inboxWithToken();
  assert.equal((await send(new Request(url("/v1/nothing")))).status, 404);
  assert.equal((await send(new Request(url("/v1/inbox/too-short")))).status, 404);
  assert.equal((await send(new Request(url(`/v1/inbox/${me.id}`)))).status, 405);
  assert.equal((await send(new Request(url(`/v1/inbox/${me.id}/messages`), { method: "PUT", body: "x" }))).status, 405);
  assert.equal((await send(new Request(url("/v1?x=1")))).status, 400, "no query strings");
  assert.equal((await owner(me, "GET", `/v1/inbox/${me.id}/messages`, undefined, { query: "?limit=1" })).status, 400);
  // The last character of an inbox ID has two unused bits; only the canonical spelling is an inbox.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const alias = me.id.slice(0, -1) + alphabet[alphabet.indexOf(me.id.at(-1)) + 1];
  assert.equal((await owner(me, "GET", `/v1/inbox/${alias}/messages`)).status, 404, "an alias of the same key is not an inbox");
});

test("inbox quota, retention and cleanup", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const small = createRelay(new NodeStore(":memory:"), { now: () => clock, maxMessages: 3, maxTotalMessages: 4 });
  const mk = async () => {
    const me = await newIdentity();
    const tokens = [await newToken(), await newToken(), await newToken(), await newToken()];
    assert.equal((await send(await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: tokens.map((t) => t.id) }), small)).status, 200);
    return { me, tokens };
  };
  const post = (id, token) => small.fetch(new Request(url(`/v1/inbox/${id}/messages`), { method: "POST", headers: { authorization: `Bearer ${token}` }, body: sealed() }));
  const get = async (me) => small.fetch(await ownerRequest(me, "GET", `/v1/inbox/${me.id}/messages`));

  const a = await mk();
  for (let i = 0; i < 3; i++) assert.equal((await post(a.me.id, a.tokens[i].token)).status, 201);
  assert.equal((await post(a.me.id, a.tokens[3].token)).status, 429, "inbox full at max_messages");
  assert.equal((await (await get(a.me)).json()).messages.length, 3, "a collects, so it counts as a used inbox");
  const b = await mk();
  assert.equal((await post(b.me.id, b.tokens[0].token)).status, 201);
  const relayFull = await post(b.me.id, b.tokens[1].token);
  assert.equal(relayFull.status, 503, "the relay as a whole is full");
  assert.ok(relayFull.headers.get("retry-after"));

  clock += 7 * 24 * 3600 + 1; // everything above is now past retention
  await small.cleanup();
  assert.equal((await post(a.me.id, a.tokens[0].token)).status, 201, "expired messages no longer count");
  assert.equal((await (await get(a.me)).json()).messages.length, 1, "expired messages are not delivered");

  // b never collected and is more than 7 days old: removed. a has collected: kept.
  assert.equal((await get(b.me)).status, 404, "an inbox that was never collected from is removed after 7 days");
  assert.equal((await get(a.me)).status, 200);
  clock += 179 * 24 * 3600;
  assert.equal((await get(a.me)).status, 200, "collecting keeps an inbox alive");
  clock += 179 * 24 * 3600;
  await small.cleanup();
  assert.equal((await get(a.me)).status, 200, "still there, 358 days after it was created");
  clock += 180 * 24 * 3600 + 1;
  await small.cleanup();
  assert.equal((await get(a.me)).status, 404, "an inbox unused for 180 days is removed");
});

test("registration modes and the new-inbox rate limit", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const store = new NodeStore(":memory:");
  const at = (options) => createRelay(store, { now: () => clock, ...options });
  const put = async (identity, target, headers) =>
    target.fetch(await ownerRequest(identity, "PUT", `/v1/inbox/${identity.id}`, { tokens: [] }, { headers }));

  const existing = await newIdentity();
  assert.equal((await put(existing, at({}))).status, 200);
  clock += 1;
  assert.equal((await put(existing, at({ registration: "closed" }))).status, 200, "existing inbox can still be updated");
  assert.equal((await put(await newIdentity(), at({ registration: "closed" }))).status, 403, "no new inboxes");

  const invite = at({ registration: "invite", inviteCode: "kom-binnen" });
  assert.equal((await (await invite.fetch(new Request(url("/v1")))).json()).registration, "invite");
  assert.equal((await put(await newIdentity(), invite)).status, 403, "no invitation");
  assert.equal((await put(await newIdentity(), invite, { "bonvoyage-invite": "fout" })).status, 403, "wrong invitation");
  assert.equal((await put(await newIdentity(), invite, { "bonvoyage-invite": "kom-binnen" })).status, 200);

  const limited = at({ maxNewInboxesPerHour: 3 }); // two exist already
  assert.equal((await put(await newIdentity(), limited)).status, 200);
  const refused = await put(await newIdentity(), limited);
  assert.equal(refused.status, 429, "too many new inboxes in the last hour");
  assert.ok(Number(refused.headers.get("retry-after")) > 0);
  clock += 3601;
  assert.equal((await put(await newIdentity(), limited)).status, 200, "allowed again an hour later");
  assert.equal((await put(await newIdentity(), at({ maxInboxes: 4 }))).status, 403, "relay is full");
});

test("a body is refused before it is read when it is too large or unauthorised", { skip: LOCAL }, async () => {
  const { me, tok } = await inboxWithToken();
  let pulled = 0;
  const endless = () => new ReadableStream({
    pull(controller) {
      pulled += 1;
      controller.enqueue(new Uint8Array(16384));
    },
  });
  const post = (headers) => relay.fetch(new Request(url(`/v1/inbox/${me.id}/messages`), { method: "POST", headers, body: endless(), duplex: "half" }));
  assert.equal((await post({})).status, 401);
  assert.ok(pulled <= 2, "an unauthorised body is not read");
  pulled = 0;
  assert.equal((await post({ authorization: `Bearer ${tok.token}` })).status, 413, "a body without a length is cut off at the limit");
  assert.ok(pulled < 10, `stopped reading after ${pulled} chunks`);
});
