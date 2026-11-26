// Bonvoyage relay: the whole HTTP interface of SPEC.md section 6.
// Runtime-neutral: uses only Request/Response and WebCrypto, and talks to
// storage through a small async interface (see store-node.js, store-d1.js).

const ID = /^[A-Za-z0-9_-]{43}$/;
const TOKEN_ID = /^[0-9a-f]{64}$/;
const MESSAGE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const AUTH = /^t=([1-9]\d{0,11}),sig=([A-Za-z0-9_-]{86})$/;
const BEARER = /^Bearer ([A-Za-z0-9_-]{43})$/;
const BLOCK = 4096;
const SEAL_OVERHEAD = 48;
const encoder = new TextEncoder();

export const DEFAULTS = {
  maxMessageBytes: SEAL_OVERHEAD + 15 * BLOCK, // 61488, the largest sealed message (SPEC 5.3)
  maxMessages: 50,
  maxMessagesPerToken: 10,
  maxTotalMessages: 3000,          // across all inboxes: bounds the relay's storage
  retentionSeconds: 7 * 24 * 3600,
  maxTokens: 64,
  maxInboxes: 5000,
  maxNewInboxesPerHour: 60,
  neverCollectedSeconds: 7 * 24 * 3600,
  inactiveSeconds: 180 * 24 * 3600,
  clockSkewSeconds: 300,
  collectBatch: 20,
  registration: "open",            // "open" | "invite" | "closed"
  inviteCode: "",                  // required for new inboxes when registration is "invite"
  now: () => Math.floor(Date.now() / 1000),
};

export function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode canonical base64url; null for anything else (SPEC 1.2). */
export function unb64url(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return b64url(bytes) === text ? bytes : null;
  } catch {
    return null;
  }
}

export async function sha256hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The bytes an inbox owner signs for a request (SPEC 6.2). */
export async function requestSigningInput(method, host, path, time, body) {
  return encoder.encode(`bonvoyage-v1-request\n${method}\n${host}\n${path}\n${time}\n${await sha256hex(body)}`);
}

function json(status, data, headers = {}) {
  return new Response(data === null ? null : JSON.stringify(data), {
    status,
    headers: { "cache-control": "no-store", ...(data === null ? {} : { "content-type": "application/json" }), ...headers },
  });
}

const fail = (status, error, headers) => json(status, { error }, headers);
const busy = (error, seconds) => fail(429, error, { "retry-after": String(seconds) });
const EMPTY = new Uint8Array();

/** Read a body, never holding more than `limit` bytes. Returns null when it is larger. */
async function readBody(request, limit) {
  const declared = request.headers.get("content-length");
  if (declared !== null && !(Number(declared) <= limit)) return null;
  if (!request.body) return EMPTY;
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

export function createRelay(store, options = {}) {
  const cfg = { ...DEFAULTS, ...options };

  const info = () => json(200, {
    bonvoyage: 1,
    max_message_bytes: cfg.maxMessageBytes,
    max_messages: cfg.maxMessages,
    max_messages_per_token: cfg.maxMessagesPerToken,
    retention_seconds: cfg.retentionSeconds,
    max_tokens: cfg.maxTokens,
    registration: cfg.registration,
  });

  /** Cheap check, before any body is read: is the header even shaped like a signature? */
  const authShape = (request) => AUTH.exec(request.headers.get("bonvoyage-auth") || "");

  /** Returns the signature (hex hash) when the request is validly signed by the inbox key, else null. */
  async function ownerSignature(request, ctx, body) {
    const match = authShape(request);
    if (!match) return null;
    if (Math.abs(cfg.now() - Number(match[1])) > cfg.clockSkewSeconds) return null;
    const key = unb64url(ctx.id);
    const signature = unb64url(match[2]);
    if (!key || key.length !== 32 || !signature || signature.length !== 64) return null;
    try {
      const publicKey = await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
      const input = await requestSigningInput(request.method, ctx.host, ctx.path, match[1], body);
      if (!(await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, input))) return null;
      return await sha256hex(signature);
    } catch {
      return null;
    }
  }

  /** PUT and DELETE of an inbox may be accepted once per signature (SPEC 6.2). */
  async function firstUse(signatureHash) {
    const now = cfg.now();
    await store.purgeAuth(now - 2 * cfg.clockSkewSeconds - 60);
    return store.rememberAuth(signatureHash, now);
  }

  async function putInbox(request, ctx) {
    if (!authShape(request)) return fail(401, "not authorised");
    const body = await readBody(request, 16384);
    if (!body) return fail(413, "body too large");
    const signature = await ownerSignature(request, ctx, body);
    if (!signature) return fail(401, "not authorised");
    let tokens;
    try {
      tokens = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)).tokens;
    } catch {
      return fail(400, "body is not JSON");
    }
    if (!Array.isArray(tokens) || tokens.length > cfg.maxTokens || !tokens.every((t) => TOKEN_ID.test(t))) {
      return fail(400, `tokens must be a list of at most ${cfg.maxTokens} token IDs`);
    }
    tokens = [...new Set(tokens)];
    const now = cfg.now();
    if (!(await store.getInbox(ctx.id))) {
      if (cfg.registration === "closed") return fail(403, "registration is closed");
      if (cfg.registration === "invite" && (!cfg.inviteCode || request.headers.get("bonvoyage-invite") !== cfg.inviteCode)) {
        return fail(403, "an invitation is required");
      }
      if ((await store.countInboxes()) >= cfg.maxInboxes) return fail(403, "relay is full");
      if ((await store.countInboxesSince(now - 3600)) >= cfg.maxNewInboxesPerHour) {
        return busy("too many new inboxes, try later", 900);
      }
    }
    if (!(await firstUse(signature))) return fail(409, "request was already used");
    await store.putInbox(ctx.id, tokens, now);
    return json(200, { id: ctx.id, tokens });
  }

  async function deleteInbox(request, ctx) {
    const signature = await ownerSignature(request, ctx, EMPTY);
    if (!signature) return fail(401, "not authorised");
    if (!(await firstUse(signature))) return fail(409, "request was already used");
    await store.deleteInbox(ctx.id);
    return json(204, null);
  }

  async function drop(request, ctx) {
    // Credentials are checked for shape before a single body byte is read.
    const bearer = BEARER.exec(request.headers.get("authorization") || "");
    const token = bearer && unb64url(bearer[1]);
    if (!token || token.length !== 32) return fail(401, "not authorised");
    const body = await readBody(request, cfg.maxMessageBytes);
    if (!body) return fail(413, "message too large");
    // Every sealed message is 48 + n * 4096 bytes (SPEC 5.3); anything else leaks its length.
    if (body.length < SEAL_OVERHEAD + BLOCK || (body.length - SEAL_OVERHEAD) % BLOCK !== 0) {
      return fail(400, "not a sealed message");
    }
    const inbox = await store.getInbox(ctx.id);
    const tokenId = await sha256hex(token);
    // One answer for "no such inbox" and "token not accepted" (SPEC 6.4).
    if (!inbox || !inbox.tokens.includes(tokenId)) return fail(401, "not authorised");
    const now = cfg.now();
    await store.purgeMessages(now - cfg.retentionSeconds, ctx.id);
    if ((await store.countMessages(ctx.id, tokenId)) >= cfg.maxMessagesPerToken) return busy("too many waiting messages", 300);
    if ((await store.countMessages(ctx.id, null)) >= cfg.maxMessages) return busy("inbox is full", 300);
    if ((await store.countAllMessages()) >= cfg.maxTotalMessages) return fail(503, "relay is full", { "retry-after": "3600" });
    const messageId = b64url(crypto.getRandomValues(new Uint8Array(16)));
    await store.addMessage(ctx.id, messageId, tokenId, b64url(body), now);
    return json(201, { id: messageId });
  }

  async function collect(request, ctx) {
    if (!(await ownerSignature(request, ctx, EMPTY))) return fail(401, "not authorised");
    if (!(await store.getInbox(ctx.id))) return fail(404, "no such inbox");
    const now = cfg.now();
    await store.purgeMessages(now - cfg.retentionSeconds, ctx.id);
    await store.markCollected(ctx.id, now);
    return json(200, { messages: await store.listMessages(ctx.id, cfg.collectBatch) });
  }

  async function deleteMessage(request, ctx, messageId) {
    if (!(await ownerSignature(request, ctx, EMPTY))) return fail(401, "not authorised");
    await store.deleteMessage(ctx.id, messageId);
    return json(204, null);
  }

  async function handle(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (path === "/" && method === "GET") {
      return new Response("Bonvoyage relay. It carries sealed tickets between ticket printers and cannot read them.\n",
        { headers: { "content-type": "text/plain; charset=utf-8" } });
    }
    if (!path.startsWith("/v1")) return fail(404, "not found");
    if (url.search) return fail(400, "query strings are not allowed");
    if (path === "/v1" || path === "/v1/") return method === "GET" ? info() : fail(405, "method not allowed");

    const parts = path.split("/"); // "", "v1", "inbox", id, ["messages", [mid]]
    const id = parts[3] || "";
    const key = ID.test(id) ? unb64url(id) : null; // canonical encodings only: one inbox per key
    if (parts[1] !== "v1" || parts[2] !== "inbox" || !key || key.length !== 32) return fail(404, "not found");
    const ctx = { id, path, host: url.host.toLowerCase() };
    if (parts.length === 4) {
      if (method === "PUT") return putInbox(request, ctx);
      if (method === "DELETE") return deleteInbox(request, ctx);
      return fail(405, "method not allowed");
    }
    if (parts[4] !== "messages") return fail(404, "not found");
    if (parts.length === 5) {
      if (method === "POST") return drop(request, ctx);
      if (method === "GET") return collect(request, ctx);
      return fail(405, "method not allowed");
    }
    if (parts.length === 6 && MESSAGE_ID.test(parts[5])) {
      if (method === "DELETE") return deleteMessage(request, ctx, parts[5]);
      return fail(405, "method not allowed");
    }
    return fail(404, "not found");
  }

  return {
    fetch: async (request) => {
      try {
        return await handle(request);
      } catch {
        return fail(500, "relay error"); // details stay out of responses and logs
      }
    },
    /** Remove expired messages, unused inboxes and old replay records. Run it now and then. */
    cleanup: async () => {
      const now = cfg.now();
      await store.purgeMessages(now - cfg.retentionSeconds, null);
      await store.purgeInboxes(now - cfg.inactiveSeconds, now - cfg.neverCollectedSeconds);
      await store.purgeAuth(now - 2 * cfg.clockSkewSeconds - 60);
    },
  };
}
