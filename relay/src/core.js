// Bonvoyage relay: the whole HTTP interface of SPEC.md section 6.
// Runtime-neutral: uses only Request/Response and WebCrypto, and talks to
// storage through a small async interface (see store-node.js, store-d1.js).

const ID = /^[A-Za-z0-9_-]{43}$/;
const TOKEN_ID = /^[0-9a-f]{64}$/;
const MESSAGE_ID = /^[A-Za-z0-9_-]{22}$/;
const encoder = new TextEncoder();

export const DEFAULTS = {
  maxMessageBytes: 65536,
  maxMessages: 50,
  retentionSeconds: 7 * 24 * 3600,
  maxTokens: 64,
  maxInboxes: 20000,
  inactiveSeconds: 180 * 24 * 3600,
  clockSkewSeconds: 300,
  collectBatch: 20,
  registration: "open", // "open" | "closed"
  now: () => Math.floor(Date.now() / 1000),
};

export function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64url(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function sha256hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The bytes an inbox owner signs for a request (SPEC 6.2). */
export async function requestSigningInput(method, path, time, body) {
  return encoder.encode(`bonvoyage-v1-request\n${method}\n${path}\n${time}\n${await sha256hex(body)}`);
}

function json(status, data) {
  return new Response(data === null ? null : JSON.stringify(data), {
    status,
    headers: data === null ? { "cache-control": "no-store" }
      : { "content-type": "application/json", "cache-control": "no-store" },
  });
}

const fail = (status, error) => json(status, { error });

async function isOwner(request, path, inboxId, body, cfg) {
  const header = request.headers.get("bonvoyage-auth") || "";
  const match = /^t=(\d{1,12}),sig=([A-Za-z0-9_-]{86})$/.exec(header);
  if (!match) return false;
  const time = Number(match[1]);
  if (Math.abs(cfg.now() - time) > cfg.clockSkewSeconds) return false;
  const key = unb64url(inboxId);
  const signature = unb64url(match[2]);
  if (!key || key.length !== 32 || !signature || signature.length !== 64) return false;
  try {
    const publicKey = await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
    const input = await requestSigningInput(request.method, path, match[1], body);
    return await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, input);
  } catch {
    return false;
  }
}

/** Read a body, refusing anything larger than `limit` bytes. Returns null when too large. */
async function readBody(request, limit) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > limit) return null;
  const bytes = new Uint8Array(await request.arrayBuffer());
  return bytes.length > limit ? null : bytes;
}

export function createRelay(store, options = {}) {
  const cfg = { ...DEFAULTS, ...options };

  const info = () => json(200, {
    bonvoyage: 1,
    max_message_bytes: cfg.maxMessageBytes,
    max_messages: cfg.maxMessages,
    retention_seconds: cfg.retentionSeconds,
    max_tokens: cfg.maxTokens,
    registration: cfg.registration,
  });

  async function putInbox(request, path, id) {
    const body = await readBody(request, 16384);
    if (!body) return fail(413, "body too large");
    if (!(await isOwner(request, path, id, body, cfg))) return fail(401, "not authorised");
    let tokens;
    try {
      tokens = JSON.parse(new TextDecoder().decode(body)).tokens;
    } catch {
      return fail(400, "body is not JSON");
    }
    if (!Array.isArray(tokens) || tokens.length > cfg.maxTokens || !tokens.every((t) => TOKEN_ID.test(t))) {
      return fail(400, `tokens must be a list of at most ${cfg.maxTokens} token IDs`);
    }
    tokens = [...new Set(tokens)];
    const now = cfg.now();
    if (!(await store.getInbox(id))) {
      if (cfg.registration !== "open") return fail(403, "registration is closed");
      if ((await store.countInboxes()) >= cfg.maxInboxes) return fail(403, "relay is full");
    }
    await store.putInbox(id, tokens, now);
    return json(200, { id, tokens });
  }

  async function deleteInbox(request, path, id) {
    if (!(await isOwner(request, path, id, new Uint8Array(), cfg))) return fail(401, "not authorised");
    await store.deleteInbox(id);
    return json(204, null);
  }

  async function drop(request, id) {
    const body = await readBody(request, cfg.maxMessageBytes);
    if (!body) return fail(413, "message too large");
    if (body.length === 0) return fail(400, "empty message");
    const bearer = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(request.headers.get("authorization") || "");
    const token = bearer && unb64url(bearer[1]);
    const inbox = await store.getInbox(id);
    const tokenId = token && token.length === 32 ? await sha256hex(token) : null;
    // One answer for "no such inbox" and "token not accepted" (SPEC 6.4).
    if (!inbox || !tokenId || !inbox.tokens.includes(tokenId)) return fail(401, "not authorised");
    const now = cfg.now();
    await store.purgeMessages(now - cfg.retentionSeconds, id);
    if ((await store.countMessages(id)) >= cfg.maxMessages) return fail(429, "inbox is full");
    const messageId = b64url(crypto.getRandomValues(new Uint8Array(16)));
    await store.addMessage(id, messageId, tokenId, b64url(body), now);
    return json(201, { id: messageId });
  }

  async function collect(request, path, id) {
    if (!(await isOwner(request, path, id, new Uint8Array(), cfg))) return fail(401, "not authorised");
    if (!(await store.getInbox(id))) return fail(404, "no such inbox");
    const now = cfg.now();
    await store.purgeMessages(now - cfg.retentionSeconds, id);
    await store.touchInbox(id, now);
    return json(200, { messages: await store.listMessages(id, cfg.collectBatch) });
  }

  async function deleteMessage(request, path, id, messageId) {
    if (!(await isOwner(request, path, id, new Uint8Array(), cfg))) return fail(401, "not authorised");
    await store.deleteMessage(id, messageId);
    return json(204, null);
  }

  async function handle(request) {
    const path = new URL(request.url).pathname;
    const method = request.method;
    if (path === "/" && method === "GET") {
      return new Response("Bonvoyage relay. It carries sealed tickets between ticket printers and cannot read them.\n",
        { headers: { "content-type": "text/plain; charset=utf-8" } });
    }
    if ((path === "/v1" || path === "/v1/") && method === "GET") return info();

    const parts = path.split("/"); // "", "v1", "inbox", id, ["messages", [mid]]
    if (parts[1] !== "v1" || parts[2] !== "inbox" || !ID.test(parts[3] || "")) return fail(404, "not found");
    const id = parts[3];
    if (parts.length === 4) {
      if (method === "PUT") return putInbox(request, path, id);
      if (method === "DELETE") return deleteInbox(request, path, id);
      return fail(405, "method not allowed");
    }
    if (parts[4] !== "messages") return fail(404, "not found");
    if (parts.length === 5) {
      if (method === "POST") return drop(request, id);
      if (method === "GET") return collect(request, path, id);
      return fail(405, "method not allowed");
    }
    if (parts.length === 6 && MESSAGE_ID.test(parts[5])) {
      if (method === "DELETE") return deleteMessage(request, path, id, parts[5]);
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
    /** Remove expired messages and long-unused inboxes. Run it now and then. */
    cleanup: async () => {
      const now = cfg.now();
      await store.purgeMessages(now - cfg.retentionSeconds, null);
      await store.purgeInboxes(now - cfg.inactiveSeconds);
    },
  };
}
