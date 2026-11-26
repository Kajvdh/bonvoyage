// Conformance tests for a Bonvoyage relay (SPEC.md section 6).
//
//   node --test test/                      in-process, against the Node storage
//   RELAY_URL=http://localhost:8787 node --test test/     against any running relay
//   RELAY_URL=https://relay.example RELAY_DELAY_MS=700 node --test test/
//                                          the same, slowly, for a relay behind a rate limit
//
// Tests that need to move the clock or change settings only run in-process.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { b64url, createRelay, powBits, requestSigningInput, sha256hex } from "../src/core.js";

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

// RELAY_DELAY_MS spaces the requests out, for a relay that sits behind a rate limit.
const DELAY = Number(process.env.RELAY_DELAY_MS || 0);
async function send(request, target = relay) {
  if (!REMOTE) return target.fetch(request);
  if (DELAY) await new Promise((resolve) => setTimeout(resolve, DELAY));
  return fetch(request);
}
const url = (path) => BASE + path;
const now = () => (REMOTE ? Math.floor(Date.now() / 1000) : clock);
const INFO = await (await send(new Request(url("/v1")))).json();

/** Proof of work for a new inbox (SPEC 6.3): a nonce that gives `bits` leading zero bits. */
function work(inboxId, bits) {
  for (let nonce = 0; ; nonce++) {
    const digest = createHash("sha256").update(`bonvoyage-v1-pow\n${inboxId}\n${nonce}`).digest();
    let zeros = 0;
    for (const byte of digest) {
      if (byte === 0) { zeros += 8; continue; }
      zeros += Math.clz32(byte) - 24;
      break;
    }
    if (zeros >= bits) return String(nonce);
  }
}

async function newIdentity(bits = INFO.pow_bits) {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const id = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey)));
  return { id, privateKey: keys.privateKey, pow: bits > 0 ? work(id, bits) : null };
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
  const headers = { "bonvoyage-auth": forge.header ?? `t=${t},sig=${sig}`, ...(forge.headers ?? {}) };
  if (method === "PUT" && identity.pow && !("bonvoyage-pow" in headers)) headers["bonvoyage-pow"] = identity.pow;
  return new Request(url(path + (forge.query ?? "")), { method, headers, body: body === undefined ? undefined : bytes });
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
  assert.ok(Math.abs(Date.parse(res.headers.get("date")) / 1000 - Date.now() / 1000) < 120, "every response carries a Date header");
  const info = await res.json();
  assert.equal(info.bonvoyage, 1);
  assert.equal(info.max_message_bytes, 61488);
  for (const key of ["max_messages", "max_messages_per_token", "retention_seconds", "max_tokens", "poll_seconds", "pow_bits"]) {
    assert.equal(typeof info[key], "number", key);
  }
  assert.ok(info.poll_seconds >= 60, "relays never ask for faster polling than once a minute");
  assert.ok(info.pow_bits >= 0 && info.pow_bits <= 32);
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
  assert.ok(collected.headers.get("date"), "collect responses carry a Date header");
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
  const nobody = await newIdentity(0);
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
  const other = await newIdentity(0);
  const path = `/v1/inbox/${me.id}/messages`;
  assert.equal((await send(new Request(url(path)))).status, 401, "no signature");
  assert.equal((await owner(other, "GET", path)).status, 401, "someone else's key");
  // Against a real relay the two clocks differ a little, so stay well clear of the 300-second edge.
  const outside = REMOTE ? 400 : 301;
  assert.equal((await owner(me, "GET", path, undefined, { time: now() - outside })).status, 401, "too old");
  assert.equal((await owner(me, "GET", path, undefined, { time: now() + outside })).status, 401, "too far ahead");
  assert.equal((await owner(me, "GET", path, undefined, { signedPath: `/v1/inbox/${me.id}` })).status, 401, "signed for another path");
  assert.equal((await owner(me, "GET", path, undefined, { host: "other-relay.example" })).status, 401, "signed for another relay");
  assert.equal((await owner(me, "GET", path, undefined, { header: `t=0${now()},sig=${"A".repeat(86)}` })).status, 401, "malformed header");
  const tampered = await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { signedBody: new TextEncoder().encode('{"tokens":["x"]}') });
  assert.equal(tampered.status, 401, "signature covers the body");
  assert.equal((await owner(other, "DELETE", `/v1/inbox/${me.id}`)).status, 401);
  assert.equal((await drop(me.id, tok.token, sealed())).status, 201, "inbox untouched by all of that");
});

test("an inbox PUT or DELETE must be newer than the last accepted one", async () => {
  const me = await newIdentity();
  const first = await newToken();
  // Times are pinned explicitly: against a real relay, seconds pass between one request and the next.
  const t0 = now();
  const put = await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [first.id] }, { time: t0 });
  const replay = put.clone();
  const sameSecond = await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { time: t0 });
  assert.equal((await send(put)).status, 200);
  assert.equal((await send(sameSecond)).status, 409, "a second request in the same second is refused; the owner signs again later");
  await tick();
  const stale = await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [first.id] }); // signed now, delivered late
  await tick();
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] })).status, 200, "the owner revokes the token");
  assert.equal((await send(replay)).status, 409, "replaying the first PUT does not undo it");
  assert.equal((await send(stale)).status, 409, "neither does a request that was signed earlier and held back");
  assert.equal((await drop(me.id, first.token, sealed())).status, 401);

  await tick();
  const t1 = now();
  const del = await ownerRequest(me, "DELETE", `/v1/inbox/${me.id}`, undefined, { time: t1 });
  const delReplay = del.clone();
  assert.equal((await send(del)).status, 204);
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { time: t1 })).status, 409, "the deleted inbox remembers its last request time");
  await tick();
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] })).status, 200, "recreated with a later time");
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
  for (const bad of [{ tokens: ["abc"] }, { tokens: "x" }, {}, { tokens: Array(65).fill("0".repeat(64)) }, { tokens: [["0".repeat(64)]] }]) {
    assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, bad)).status, 400);
  }
});

test("each contact has its own share of the inbox", async () => {
  const me = await newIdentity();
  const [kaj, jan] = [await newToken(), await newToken()];
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [kaj.id, jan.id] })).status, 200);
  for (let i = 0; i < INFO.max_messages_per_token; i++) assert.equal((await drop(me.id, kaj.token, sealed())).status, 201);
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
  assert.equal((await owner(me, "GET", `/v1/inbox/${me.id}/messages`)).status, 404, "collecting from a missing inbox says so");
  assert.equal((await drop(me.id, tok.token, sealed())).status, 401);
  await tick();
  assert.equal((await owner(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [tok.id] })).status, 200, "the owner can simply create it again");
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

test("a new inbox needs proof of work when the relay asks for it", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const hard = createRelay(new NodeStore(":memory:"), { now: () => clock, powBits: 10 });
  assert.equal((await (await hard.fetch(new Request(url("/v1")))).json()).pow_bits, 10);
  const me = await newIdentity(0);
  const put = async (headers) => (await hard.fetch(await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { headers }))).status;
  assert.equal(await put({}), 403, "no proof of work");
  let weak = 0;
  while ((await powBits(me.id, String(weak))) >= 10) weak++;
  assert.equal(await put({ "bonvoyage-pow": String(weak) }), 403, "not enough work");
  const other = await newIdentity(0);
  assert.equal(await put({ "bonvoyage-pow": work(other.id, 10) }), 403, "work done for another inbox does not count");
  for (const malformed of ["", "01", "-1", "1e3", "x", "9".repeat(21)]) assert.equal(await put({ "bonvoyage-pow": malformed }), 403);
  const nonce = work(me.id, 10);
  assert.ok((await powBits(me.id, nonce)) >= 10);
  assert.equal(await put({ "bonvoyage-pow": nonce }), 200);
  clock += 1;
  assert.equal(await put({}), 200, "an existing inbox is updated without doing the work again");
});

test("retention, and making room when an inbox or the relay is full", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const small = createRelay(new NodeStore(":memory:"), { now: () => clock, maxMessages: 3, maxTotalMessages: 5, maxInboxes: 3 });
  const make = async () => {
    const me = await newIdentity(0);
    const tokens = [await newToken(), await newToken(), await newToken(), await newToken()];
    const res = await small.fetch(await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: tokens.map((t) => t.id) }));
    return { me, tokens, status: res.status };
  };
  const post = (who, i) => small.fetch(new Request(url(`/v1/inbox/${who.me.id}/messages`), { method: "POST", headers: { authorization: `Bearer ${who.tokens[i].token}` }, body: sealed() }));
  const get = async (who) => small.fetch(await ownerRequest(who.me, "GET", `/v1/inbox/${who.me.id}/messages`));
  const waiting = async (who) => (await (await get(who)).json()).messages;

  const a = await make();
  for (let i = 0; i < 3; i++) assert.equal((await post(a, i)).status, 201);
  assert.equal((await post(a, 3)).status, 429, "one inbox holds at most max_messages");
  const firstOfA = (await waiting(a))[0].id;

  // The relay holds 5 messages in total. a has 3; b gets 2; a sixth message makes room at the fullest inbox.
  const b = await make();
  assert.equal((await post(b, 0)).status, 201);
  assert.equal((await post(b, 1)).status, 201);
  assert.equal((await post(b, 2)).status, 201, "a full relay still accepts: it makes room instead of refusing");
  assert.equal((await waiting(b)).length, 3);
  const leftInA = await waiting(a);
  assert.equal(leftInA.length, 2, "the inbox that held the most lost one");
  assert.ok(!leftInA.some((m) => m.id === firstOfA), "namely its oldest");

  clock += 7 * 24 * 3600 + 1; // everything above is now past retention
  assert.equal((await waiting(a)).length, 0, "expired messages are not delivered");
  for (let i = 0; i < 3; i++) assert.equal((await post(a, i)).status, 201, "and no longer count");

  // Three inboxes fit. a and b were just used; c fills the relay. A fourth is refused while nobody has been idle for a day...
  await get(b);
  const c = await make();
  assert.equal(c.status, 200);
  assert.equal((await make()).status, 503, "full, and every inbox was used in the last day");
  // ...and takes the place of the inbox unused the longest once one has been.
  clock += 2 * 86400;
  await get(a);
  await get(c);
  const d = await make();
  assert.equal(d.status, 200, "a newcomer gets in");
  assert.equal((await get(b)).status, 404, "b, unused the longest, made room");
  assert.equal((await get(a)).status, 200);
  clock += 1;
  assert.equal((await small.fetch(await ownerRequest(b.me, "PUT", `/v1/inbox/${b.me.id}`, { tokens: [] }))).status, 503, "b cannot come back while the relay is full of active inboxes");

  // Cleanup: an inbox never collected from goes after 7 days, any inbox after 30 unused days.
  clock += 8 * 86400;
  await get(a);
  await small.cleanup();
  assert.equal((await get(d)).status, 404, "never collected from: removed after 7 days");
  assert.equal((await get(a)).status, 200);
  clock += 31 * 86400;
  await small.cleanup();
  assert.equal((await get(a)).status, 404, "unused for 30 days: removed");
});

test("registration modes and limits on new inboxes", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const store = new NodeStore(":memory:");
  const at = (options) => createRelay(store, { now: () => clock, ...options });
  const put = async (identity, target, headers, address) =>
    target.fetch(await ownerRequest(identity, "PUT", `/v1/inbox/${identity.id}`, { tokens: [] }, { headers }), address);
  const create = async (target, address) => (await put(await newIdentity(0), target, undefined, address)).status;

  const existing = await newIdentity(0);
  assert.equal((await put(existing, at({}))).status, 200);
  clock += 1;
  assert.equal((await put(existing, at({ registration: "closed" }))).status, 200, "existing inbox can still be updated");
  assert.equal(await create(at({ registration: "closed" })), 403, "no new inboxes");

  const invite = at({ registration: "invite", inviteCode: "kom-binnen" });
  assert.equal((await (await invite.fetch(new Request(url("/v1")))).json()).registration, "invite");
  assert.equal(await create(invite), 403, "no invitation");
  assert.equal((await put(await newIdentity(0), invite, { "bonvoyage-invite": "fout" })).status, 403, "wrong invitation");
  assert.equal((await put(await newIdentity(0), invite, { "bonvoyage-invite": "kom-binnen" })).status, 200);

  const perAddress = at({ maxNewInboxesPerAddressPerHour: 2 });
  assert.deepEqual([await create(perAddress, "203.0.113.9"), await create(perAddress, "203.0.113.9"), await create(perAddress, "203.0.113.9")], [200, 200, 429]);
  assert.equal(await create(perAddress, "203.0.113.10"), 200, "another address is not affected");
  const v6 = ["2001:db8:1:2::1", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::3"];
  assert.deepEqual([await create(perAddress, v6[0]), await create(perAddress, v6[1]), await create(perAddress, v6[2])], [200, 200, 429], "an IPv6 /64 counts as one address");
  assert.equal(await create(perAddress, "2001:db8:1:3::1"), 200);

  const hourly = at({ maxNewInboxesPerHour: 9 }); // eight exist by now
  assert.equal(await create(hourly), 200);
  const refused = await put(await newIdentity(0), hourly);
  assert.equal(refused.status, 429, "too many new inboxes in the last hour");
  assert.ok(Number(refused.headers.get("retry-after")) > 0);
  clock += 3601;
  assert.equal(await create(hourly), 200, "allowed again an hour later");
  assert.equal(await create(perAddress, "203.0.113.9"), 200, "and per address too");
});

test("the relay signs nothing for another host, and uses its own name when it is set", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const named = createRelay(new NodeStore(":memory:"), { now: () => clock, host: "relay.example:8443" });
  const me = await newIdentity(0);
  const viaProxy = async (signedFor) => {
    const signed = await ownerRequest(me, "PUT", `/v1/inbox/${me.id}`, { tokens: [] }, { host: signedFor });
    // The request arrives with whatever Host the proxy passed on; only the configured name counts.
    return (await named.fetch(new Request(`http://10.0.0.5:8787/v1/inbox/${me.id}`, { method: "PUT", headers: signed.headers, body: await signed.arrayBuffer() }))).status;
  };
  assert.equal(await viaProxy("10.0.0.5:8787"), 401, "signed for the name in the Host header: refused");
  assert.equal(await viaProxy("other-relay.example"), 401, "signed for another relay: refused");
  assert.equal(await viaProxy("relay.example:8443"), 200, "signed for the relay's own name: accepted");
});

test("two requests racing to change an inbox cannot both win", { skip: LOCAL }, async () => {
  const { NodeStore } = await import("../src/store-node.js");
  const store = new NodeStore(":memory:");
  assert.equal(await store.putInbox("x", ["a"], 100, 100), "created");
  assert.equal(await store.putInbox("x", [], 106, 106), "updated");
  assert.equal(await store.putInbox("x", ["a"], 107, 101), "stale", "the write itself refuses an older time, whatever was checked before");
  assert.deepEqual((await store.getInbox("x")).tokens, []);
  assert.equal(await store.deleteInbox("x", 105, 108), false, "so does the delete");
  assert.equal(await store.deleteInbox("x", 110, 110), true);
  assert.equal(await store.putInbox("x", [], 111, 110), "stale", "and a deleted inbox keeps its last time");
  assert.equal(await store.putInbox("x", [], 112, 111), "created");
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
