// Cloudflare Workers entry point.
import { createRelay } from "./core.js";
import { D1Store } from "./store-d1.js";

const relayFor = (env) => createRelay(new D1Store(env.DB), {
  registration: ["closed", "invite"].includes(env.REGISTRATION) ? env.REGISTRATION : "open",
  inviteCode: env.INVITE_CODE || "",
});

const tooMany = () => new Response('{"error":"too many requests"}', {
  status: 429,
  headers: { "content-type": "application/json", "retry-after": "60", "cache-control": "no-store" },
});

export default {
  async fetch(request, env) {
    // Per-address rate limit (SPEC 6: allowed, and not logging). The address is only used as a
    // counter key inside Cloudflare's rate limiter for the length of the period; nothing is stored.
    if (env.LIMITER && new URL(request.url).pathname.startsWith("/v1")) {
      const address = request.headers.get("cf-connecting-ip") || "unknown";
      const { success } = await env.LIMITER.limit({ key: address });
      if (!success) return tooMany();
    }
    return relayFor(env).fetch(request);
  },
  scheduled: (event, env, ctx) => ctx.waitUntil(relayFor(env).cleanup()),
};
