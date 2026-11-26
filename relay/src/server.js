// Self-hosted entry point: `node src/server.js`.
// Put it behind a reverse proxy that terminates HTTPS and does not log client addresses.
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createRelay } from "./core.js";
import { NodeStore } from "./store-node.js";

const port = Number(process.env.PORT || 8787);
const relay = createRelay(new NodeStore(process.env.BONVOYAGE_DB || "bonvoyage.db"), {
  registration: process.env.REGISTRATION === "closed" ? "closed" : "open",
});
const MAX_BODY = 65536 + 1024;

// The landing page, rendered spec and test vectors: a fixed set of files read once at start.
const PUBLIC = new URL("../public/", import.meta.url);
const TYPES = { html: "text/html; charset=utf-8", json: "application/json", md: "text/markdown; charset=utf-8" };
const pages = new Map();
for (const [route, file] of [["/", "index.html"], ["/spec/", "spec/index.html"], ["/vectors/v1.json", "vectors/v1.json"], ["/SPEC.md", "SPEC.md"]]) {
  if (existsSync(new URL(file, PUBLIC))) pages.set(route, { type: TYPES[file.split(".").pop()], body: readFileSync(new URL(file, PUBLIC)) });
}

const server = createServer(async (req, res) => {
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
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) {
      res.writeHead(413, { "content-type": "application/json" }).end('{"error":"message too large"}');
      return;
    }
    chunks.push(chunk);
  }
  const hasBody = !["GET", "HEAD"].includes(req.method);
  const request = new Request(`http://relay${req.url}`, {
    method: req.method,
    headers: req.headers,
    body: hasBody ? Buffer.concat(chunks) : undefined,
  });
  const response = await relay.fetch(request);
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
});

setInterval(() => relay.cleanup().catch(() => {}), 6 * 3600 * 1000).unref();
server.listen(port, () => console.log(`bonvoyage relay listening on :${port}`));
