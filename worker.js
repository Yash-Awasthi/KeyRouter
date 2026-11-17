// The entry point: routing and nothing else. Every route, the metering, the admin API and the two Durable Objects
// live in src/, so this file only decides which of them answers a request.
//
// The re-exports below keep the modules reachable from the entry point for the tests and for anything that imports
// the worker directly; the Durable Object classes must be exported here for the runtime to find them.
import { admin, digest, join } from "./src/admin.js";
import { claimShare, proxy, rotate, usage } from "./src/proxy.js";

export { Admin } from "./src/auth.js";
export { Meter } from "./src/meter.js";
export { cost, DEFAULT_PRICES } from "./src/pricing.js";
export { inRange, parseIp, withinHours } from "./src/net.js";

/** The cron trigger's body: yesterday's numbers, to the webhook the deployment configured. */
async function daily(env) {
  if (!env?.ALERT_WEBHOOK) return;
  try {
    const report = await digest(env, 1);
    const res = await fetch(env.ALERT_WEBHOOK, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event: "digest", at: new Date().toISOString(), ...report }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) console.warn(`digest webhook answered ${res.status}`);
  } catch (e) {
    console.warn(`could not send the daily digest: ${/** @type {Error} */ (e).message}`);
  }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/")) return admin(req, env, url);
    if (url.pathname === "/join" || url.pathname.startsWith("/join/")) return join(req, env, url);
    if (url.pathname === "/usage") return usage(req, env, url);
    // Scraped by an external monitor, so it lives at the conventional path rather than under /admin.
    if (url.pathname === "/metrics") return admin(req, env, url);
    // Also scraped, and the one endpoint that needs no session: it answers with hosts and counts, nothing secret.
    if (url.pathname === "/status") return admin(req, env, url);
    if (url.pathname === "/usage/rotate") return rotate(req, env, url);
    const share = url.pathname.match(/^\/share\/([0-9a-f]{32})$/);
    if (share) return claimShare(req, env, url, share[1]);
    return proxy(req, env, url, ctx);
  },

  // A Cron Trigger, not a request: no client waits on this, so a failure is only logged.
  async scheduled(_event, env, ctx) {
    const work = daily(env);
    if (ctx?.waitUntil) ctx.waitUntil(work);
    else await work;
  },
};
