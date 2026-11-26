// Cloudflare Workers entry point.
import { addressKey, createRelay } from "./core.js";
import { D1Store } from "./store-d1.js";

const relayFor = (env) => createRelay(new D1Store(env.DB), {
  host: (env.RELAY_HOST || "").toLowerCase(),
  registration: ["closed", "invite"].includes(env.REGISTRATION) ? env.REGISTRATION : "open",
  inviteCode: env.INVITE_CODE || "",
});

const tooMany = () => new Response('{"error":"too many requests"}', {
  status: 429,
  headers: { "content-type": "application/json", "retry-after": "60", "cache-control": "no-store" },
});

export default {
  async fetch(request, env) {
    // Per-address limits (SPEC 6: allowed, and not logging). The address is used as a counter key
    // for at most an hour, as a hash; it is never written to a log.
    const address = request.headers.get("cf-connecting-ip") || "";
    if (env.LIMITER && new URL(request.url).pathname.startsWith("/v1")) {
      const { success } = await env.LIMITER.limit({ key: addressKey(address) || "unknown" });
      if (!success) return tooMany();
    }
    return relayFor(env).fetch(request, address);
  },
  scheduled: (event, env, ctx) => ctx.waitUntil(relayFor(env).cleanup()),
};
