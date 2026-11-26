// Cloudflare Workers entry point.
import { createRelay } from "./core.js";
import { D1Store } from "./store-d1.js";

const relayFor = (env) => createRelay(new D1Store(env.DB), {
  registration: ["closed", "invite"].includes(env.REGISTRATION) ? env.REGISTRATION : "open",
  inviteCode: env.INVITE_CODE || "",
});

export default {
  fetch: (request, env) => relayFor(env).fetch(request),
  scheduled: (event, env, ctx) => ctx.waitUntil(relayFor(env).cleanup()),
};
