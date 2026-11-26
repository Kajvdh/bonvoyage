// Self-hosted entry point: `node src/server.js`.
// Put it behind a reverse proxy that terminates HTTPS and does not log client addresses.
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRelay } from "./core.js";
import { NodeStore } from "./store-node.js";

const port = Number(process.env.PORT || 8787);
const relay = createRelay(new NodeStore(process.env.BONVOYAGE_DB || "bonvoyage.db"), {
  registration: ["closed", "invite"].includes(process.env.REGISTRATION) ? process.env.REGISTRATION : "open",
  inviteCode: process.env.INVITE_CODE || "",
});
const MAX_BODY = 65536;

// The landing page, rendered spec and test vectors: a fixed set of files read once at start.
const PUBLIC = new URL("../public/", import.meta.url);
const TYPES = { html: "text/html; charset=utf-8", json: "application/json", md: "text/markdown; charset=utf-8" };
const pages = new Map();
for (const [route, file] of [["/", "index.html"], ["/spec/", "spec/index.html"], ["/vectors/v1.json", "vectors/v1.json"], ["/SPEC.md", "SPEC.md"]]) {
  if (existsSync(new URL(file, PUBLIC))) pages.set(route, { type: TYPES[file.split(".").pop()], body: readFileSync(new URL(file, PUBLIC)) });
}

const METHODS = new Set(["GET", "PUT", "POST", "DELETE"]);
const reply = (res, status, error) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify({ error }));

async function serve(req, res) {
  const path = req.url.split("?")[0];
  if (req.method === "GET" && path === "/spec") {
    res.writeHead(308, { location: "/spec/" }).end();
    return;
  }
  if (req.method === "GET" && pages.has(path)) {
    const page = pages.get(path);
    res.writeHead(200, { "content-type": page.type, "cache-control": "public, max-age=300" }).end(page.body);
    return;
  }
  if (!METHODS.has(req.method)) return reply(res, 405, "method not allowed");
  // The host the client addressed us as is part of what owners sign (SPEC 6.2).
  const host = req.headers.host || "";
  const port = Number(host.split(":")[1] || 1);
  if (!/^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$/.test(host) || port < 1 || port > 65535) return reply(res, 400, "bad host");
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) return reply(res, 413, "message too large");
    chunks.push(chunk);
  }
  const request = new Request(`http://${host}${req.url}`, {
    method: req.method,
    headers: req.headers,
    body: req.method === "GET" ? undefined : Buffer.concat(chunks),
  });
  const response = await relay.fetch(request);
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}

// Nothing a client sends may take the process down: any failure becomes a 400.
const server = createServer((req, res) => {
  serve(req, res).catch(() => {
    if (!res.headersSent) reply(res, 400, "bad request");
    else res.destroy();
  });
});

setInterval(() => relay.cleanup().catch(() => {}), 6 * 3600 * 1000).unref();
server.listen(port, () => console.log(`bonvoyage relay listening on :${port}`));
