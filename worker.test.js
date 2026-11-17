import { test } from "node:test";
import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

// Workers-only API, and the bundler's text modules (see scripts/text_modules.mjs).
import "./scripts/text_modules.mjs";
crypto.subtle.timingSafeEqual = timingSafeEqual;
const { default: worker, Meter, Admin, cost, inRange, parseIp, withinHours, DEFAULT_PRICES } = await import("./worker.js");
// The Admin Durable Object is written to directly by the audit tests, to fill it past its cap.
const { adminStore } = await import("./src/auth.js");

const store = new Map();
// Durable Object namespace stand-in: one instance per name, each with in-memory storage and an alarm slot.
function namespace(Class) {
  const instances = new Map();
  return {
    idFromName: (name) => name,
    get(name) {
      if (!instances.has(name)) {
        const data = new Map();
        const storage = {
          alarmAt: null,
          get: async (k) => data.get(k),
          put: async (k, v) => void data.set(k, v),
          deleteAll: async () => data.clear(),
          delete: async (keys) => {
            for (const k of keys) data.delete(k);
          },
          setAlarm: async (t) => void (storage.alarmAt = t),
          deleteAlarm: async () => void (storage.alarmAt = null),
        };
        const meter = new Class({ storage }, env);
        instances.set(name, { meter, storage, fetch: (url, init) => meter.fetch(new Request(url, init)) });
      }
      return instances.get(name);
    },
  };
}
const env = {
  ADMIN_PASSWORD: "pw",
  ENCRYPTION_KEY: "test-encryption-secret",
  // The suite drives a password-only deployment, which has to opt in to key creation; the passkey test unsets it.
  ALLOW_PASSWORD: "true",
  KEYS: {
    async get(k) { return store.has(k) ? JSON.parse(store.get(k).value) : null; },
    async getWithMetadata(k) { return { value: await this.get(k), metadata: store.get(k)?.metadata ?? null }; },
    async put(k, value, opts) { store.set(k, { value, ...opts }); },
    async delete(k) { store.delete(k); },
    async list({ prefix = "", cursor = "0", limit = 1000 } = {}) {
      const all = [...store].filter(([name]) => name.startsWith(prefix));
      const at = Number(cursor);
      const keys = all.slice(at, at + limit).map(([name, v]) => ({ name, metadata: v.metadata }));
      return at + limit >= all.length ? { keys, list_complete: true } : { keys, list_complete: false, cursor: String(at + limit) };
    },
  },
};
env.METER = namespace(Meter);
env.ADMIN = namespace(Admin);

let sent;
globalThis.fetch = async (url, init) => {
  sent = { url, init, headers: init.headers };
  return new Response("ok");
};
const pending = [];
const ctx = { waitUntil: (p) => pending.push(p) };
// Every request carries the client address Cloudflare would send, so sign-in throttling has a bucket to count.
const req = (path, init = {}) => worker.fetch(new Request("https://gw.example" + path, { ...init, headers: { "cf-connecting-ip": "127.0.0.1", ...init.headers } }), env, ctx);
let attackers = 0;
const fromNewAddress = () => ({ "cf-connecting-ip": `203.0.113.${++attackers}` });
const adminAuth = { authorization: "Basic " + btoa("admin:pw") };
const create = (body) => req("/admin/keys", { method: "POST", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify(body) });
const inAnHour = new Date(Date.now() + 3600e3).toISOString();
const keyInfo = async (id) => (await req("/admin/keys/" + id, { headers: adminAuth })).json();
// A session cookie signed exactly as the worker signs it, so a test can tamper with one part and keep the rest.
const newSessionFor = async (e, role) => {
  const { newSession } = await import("./src/auth.js");
  return newSession(e, role);
};
async function listAll() {
  const all = [];
  let cursor = "";
  do {
    const page = await (await req("/admin/keys" + (cursor ? "?cursor=" + cursor : ""), { headers: adminAuth })).json();
    assert.ok(page.keys.length <= 20, "pages stay within the subrequest budget");
    all.push(...page.keys);
    cursor = page.cursor;
  } while (cursor);
  return all;
}

test("admin requires the password", async () => {
  assert.equal((await req("/admin")).status, 401);
  assert.equal((await req("/admin", { headers: { authorization: "Basic " + btoa("admin:wrong") } })).status, 401);
  assert.equal((await req("/admin", { headers: adminAuth })).status, 200);
});

test("admin sign-in is throttled per address", async () => {
  const at = (ip, headers) => req("/admin", { headers: { "cf-connecting-ip": ip, ...headers } });
  const wrong = { authorization: "Basic " + btoa("admin:wrong") };
  const tries = [];
  for (let i = 0; i < 5; i++) tries.push((await at("198.51.100.77", wrong)).status);
  assert.deepEqual(tries, [401, 401, 401, 401, 401]);
  const blocked = await at("198.51.100.77", wrong);
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get("retry-after")) > 0);
  assert.equal((await at("198.51.100.77", adminAuth)).status, 429, "the right password is refused while blocked");
  assert.equal((await at("198.51.100.78", adminAuth)).status, 200, "another address is unaffected");
  const stored = await env.ADMIN.get("admin").storage.get("throttle");
  assert.equal(Object.keys(stored.ips).length, 1, "only the failing address is kept");
  assert.ok(!JSON.stringify(stored).includes("198.51.100.77"), "the raw address is never stored");
});

test("sign-in failures share one body, are logged without the address, and are counted in admin status", async () => {
  const wrong = { authorization: "Basic " + btoa("admin:wrong") };
  const warned = [];
  const realWarn = console.warn;
  console.warn = (...a) => warned.push(a.join(" "));
  try {
    const unknown = await req("/admin/no-such-route", { headers: { "cf-connecting-ip": "198.51.100.90" } });
    const bad = await req("/admin", { headers: { "cf-connecting-ip": "198.51.100.90", ...wrong } });
    assert.deepEqual([unknown.status, bad.status], [401, 401]);
    const body = await bad.text();
    assert.equal(await unknown.text(), body, "an unknown route and a wrong password answer the same way");

    const tries = [];
    for (let i = 0; i < 5; i++) tries.push(await req("/admin", { headers: { "cf-connecting-ip": "198.51.100.91", ...wrong } }));
    const blocked = await req("/admin", { headers: { "cf-connecting-ip": "198.51.100.91", ...wrong } });
    assert.equal(blocked.status, 429);
    assert.equal(await blocked.text(), body, "a blocked address gets the same body, only the status differs");
  } finally {
    console.warn = realWarn;
  }
  const log = warned.join("\n");
  assert.match(log, /admin sign-in failed: password rejected/);
  assert.match(log, /address blocked for \d+s/);
  assert.ok(!/198\.51\.100\.\d+/.test(log), "the log names the reason, never the address");

  const status = await (await req("/admin/status", { headers: adminAuth })).json();
  assert.ok(status.blockedAddresses >= 1, "the status counts blocked addresses");
  assert.ok(Date.parse(status.lastSignInFailure) > Date.now() - 60e3);
});

test("the sign-in block clears, escalates and lives in Durable Object storage", async () => {
  const wrong = { authorization: "Basic " + btoa("admin:wrong") };
  const at = (ip) => req("/admin", { headers: { "cf-connecting-ip": ip, ...wrong } });
  const good = (ip) => req("/admin", { headers: { "cf-connecting-ip": ip, ...adminAuth } });

  for (let i = 0; i < 4; i++) assert.equal((await at("198.51.100.101")).status, 401);
  assert.equal((await good("198.51.100.101")).status, 200, "four failures then the right password still works");
  assert.equal((await at("198.51.100.101")).status, 401, "a success reset the counter, so one more failure does not block");
  assert.equal((await good("198.51.100.101")).status, 200);

  const tries = [];
  for (let i = 0; i < 6; i++) tries.push((await at("198.51.100.102")).status);
  assert.deepEqual(tries, [401, 401, 401, 401, 401, 429], "five failures block the sixth attempt");
  const firstBlock = (await at("198.51.100.102")).headers.get("retry-after");
  assert.equal(Number(firstBlock), 900, "the first block lasts 15 minutes");

  // The state lives in the Durable Object, so a fresh instance over the same storage still knows about it.
  const { storage } = env.ADMIN.get("admin");
  const hash = Object.entries((await storage.get("throttle")).ips).find(([, r]) => r.blockedUntil > Date.now())[0];
  const revived = new Admin({ storage }, env);
  const ask = (body) => revived.fetch(new Request("https://admin/throttle", { method: "POST", body: JSON.stringify(body) }));
  assert.equal((await (await ask({ ipHash: hash, outcome: "check" })).json()).blocked, true, "state survives an isolate restart");

  const now = Date.now;
  try {
    Date.now = () => now() + 16 * 60e3;
    assert.equal((await good("198.51.100.102")).status, 200, "the block expires after its window");
    for (let i = 0; i < 5; i++) assert.equal((await at("198.51.100.103")).status, 401);
    assert.equal((await at("198.51.100.103")).status, 429);
    Date.now = () => now() + 32 * 60e3;
    assert.equal((await at("198.51.100.103")).status, 401, "one failure after a served block is enough to re-block");
    assert.equal(Number((await at("198.51.100.103")).headers.get("retry-after")), 1800, "a repeat offender is blocked for twice as long");
  } finally {
    Date.now = now;
  }
  assert.equal((await good("198.51.100.104")).status, 200, "an untouched address is never affected");
});

test("a passkey is required before the first key can be created", async () => {
  delete env.ALLOW_PASSWORD;
  try {
    const refused = await create({ base: "https://x.example", key: "k", expires: inAnHour });
    assert.equal(refused.status, 403);
    assert.match((await refused.json()).error.message, /add a passkey before creating keys/);
    const status = await (await req("/admin/status", { headers: adminAuth })).json();
    assert.deepEqual([status.passkeys, status.passwordFallback], [0, false], "the page shows the banner from these two fields");
    for (const value of ["TRUE", "1", "yes", " true"]) {
      env.ALLOW_PASSWORD = value;
      assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour })).status, 403, `ALLOW_PASSWORD=${JSON.stringify(value)} is not an opt-in`);
    }
    env.ALLOW_PASSWORD = "true";
    assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour })).status, 200, "ALLOW_PASSWORD=true allows a password-only deployment");
    // Reading stays allowed without a passkey, so an operator can see what is at risk.
    assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 200);
  } finally {
    env.ALLOW_PASSWORD = "true";
  }
});

test("create validates input and needs a JSON content type", async () => {
  assert.equal((await create({ base: "http://x.example", key: "k", expires: inAnHour })).status, 400);
  assert.equal((await create({ base: "https://x.example", key: "", expires: inAnHour })).status, 400);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: "2020-01-01" })).status, 400);
  const form = await req("/admin/keys", { method: "POST", headers: { ...adminAuth, "content-type": "text/plain" }, body: "{}" });
  assert.equal(form.status, 404);
});

test("created key proxies to the provider base with the real key", async () => {
  const { id } = await (await create({ base: "https://open.bigmodel.cn/api/paas/v4/", key: "real", expires: inAnHour })).json();
  for (const h of [{ authorization: `Bearer ${id}` }, { "x-api-key": id }]) {
    assert.equal((await req("/v1/chat/completions?x=1", { method: "POST", headers: { ...h, "x-forwarded-for": "1.2.3.4" }, body: "{}" })).status, 200);
    assert.equal(sent.url, "https://open.bigmodel.cn/api/paas/v4/chat/completions?x=1");
    assert.equal(sent.headers.get("authorization"), "Bearer real");
    assert.equal(sent.headers.get("x-api-key"), null);
    assert.equal(sent.headers.get("x-forwarded-for"), null);
  }
  const listed = await listAll();
  assert.ok(listed.some((k) => k.id === id && !("key" in k)), "list must not expose real keys");
  assert.ok(!("key" in (await keyInfo(id))), "key details must not expose real keys");

  assert.equal((await req("/admin/keys/" + id, { method: "DELETE", headers: adminAuth })).status, 200);
  assert.equal((await req("/v1/models", { headers: { authorization: `Bearer ${id}` } })).status, 401);
});

test("rejects unknown, oversized and expired keys", async () => {
  const old = "sk-gw-" + "0".repeat(32);
  store.set(old, { value: JSON.stringify({ base: "https://x.example", key: "k", expires: "2020-01-01T00:00:00Z" }) });
  for (const k of ["nope", "x".repeat(600), old]) {
    assert.equal((await req("/v1/models", { headers: { authorization: `Bearer ${k}` } })).status, 401);
  }
});

test("upstream failure becomes 502", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const real = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("boom"); };
  assert.equal((await req("/v1/models", { headers: { authorization: `Bearer ${id}` } })).status, 502);
  globalThis.fetch = real;
});

test("messages calls are metered, streaming and not", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const real = globalThis.fetch;
  const call = async (body, type) => {
    globalThis.fetch = async () => new Response(body, { headers: { "content-type": type } });
    const res = await req("/v1/messages", { method: "POST", headers: { "x-api-key": id }, body: "{}" });
    assert.equal(await res.text(), body, "client gets the untouched body");
    await Promise.all(pending.splice(0));
  };
  await call(JSON.stringify({ model: "claude-opus-5-5", usage: { input_tokens: 1000, output_tokens: 500 } }), "application/json");
  await call([
    'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-5-5","usage":{"input_tokens":2000,"output_tokens":1}}}',
    'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":300}}',
  ].join("\n\n"), "text/event-stream");
  globalThis.fetch = real;
  const u = (await keyInfo(id)).usage.total;
  assert.ok(Math.abs(u["claude-opus-5-5"].cost - 0.014) < 1e-9);
  assert.ok(Math.abs(u["claude-sonnet-5-5"].cost - 0.007) < 1e-9);
  assert.equal(u["claude-sonnet-5-5"].output, 300);
});

const bearer = (id) => ({ authorization: `Bearer ${id}` });

test("auth style picks the header the real key travels in, and strips client identity", async () => {
  const { id } = await (await create({ base: "https://api.anthropic.com", key: "real", expires: inAnHour, auth: "x-api-key" })).json();
  const headers = { ...bearer(id), "cf-ipcountry": "IN", cookie: "a=b", origin: "https://site.example", "anthropic-version": "2023-06-01" };
  await req("/v1/messages", { method: "POST", headers, body: "{}" });
  assert.equal(sent.headers.get("x-api-key"), "real");
  assert.equal(sent.headers.get("authorization"), null, "the gateway key must not leak upstream");
  for (const h of ["cf-ipcountry", "cookie", "origin"]) assert.equal(sent.headers.get(h), null);
  assert.equal(sent.headers.get("anthropic-version"), "2023-06-01");
  assert.equal(sent.init.redirect, "manual");
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, auth: "cookie" })).status, 400);
});

test("proxy answers CORS preflight and tags responses", async () => {
  const pre = await req("/v1/chat/completions", { method: "OPTIONS", headers: { "access-control-request-headers": "authorization,content-type" } });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), "*");
  assert.equal(pre.headers.get("access-control-allow-headers"), "authorization,content-type");
  assert.equal((await req("/v1/models")).headers.get("access-control-allow-origin"), "*");
  assert.equal((await req("/admin/keys", { headers: adminAuth })).headers.get("access-control-allow-origin"), null);
});

test("the admin page is three files and its CSP allows no inline code", async () => {
  const shell = await req("/admin", { headers: adminAuth });
  const html = await shell.text();
  const csp = shell.headers.get("content-security-policy");
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /style-src 'self'/);
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /base-uri 'none'/);
  assert.ok(!csp.includes("'unsafe-inline'"), "no unsafe-inline");
  assert.ok(!/<script>/i.test(html), "no inline script block");
  assert.ok(!/<style>/i.test(html), "no inline style block");
  assert.ok(html.includes('<script src="/admin/admin.js" defer></script>'), "the shell names the script");
  assert.ok(html.includes('<link rel="stylesheet" href="/admin/admin.css">'), "and the stylesheet");

  // Both files are public, typed, and never cached. They are the only two things the policy allows to load.
  const css = await req("/admin/admin.css");
  assert.equal(css.status, 200);
  assert.equal(css.headers.get("content-type"), "text/css; charset=utf-8");
  assert.equal(css.headers.get("cache-control"), "no-store");
  assert.match(await css.text(), /--accent:/);

  const js = await req("/admin/admin.js");
  assert.equal(js.status, 200);
  assert.equal(js.headers.get("content-type"), "text/javascript; charset=utf-8");
  assert.equal(js.headers.get("cache-control"), "no-store");
  assert.match(await js.text(), /admin\/keys/);
});

test("a page with an inline block is served under a nonce, and nothing else", async () => {
  for (const path of ["/usage", "/share/" + "0".repeat(32)]) {
    const res = await req(path);
    assert.equal(res.status, 200, path);
    const html = await res.text();
    const csp = res.headers.get("content-security-policy");
    const nonce = /script-src 'nonce-([0-9a-f]+)'/.exec(csp)?.[1];
    assert.ok(nonce, `${path}: the policy names a nonce`);
    assert.ok(csp.includes(`style-src 'nonce-${nonce}'`), `${path}: the same nonce covers styles`);
    assert.ok(!csp.includes("'unsafe-inline'"), `${path}: no unsafe-inline`);
    assert.match(csp, /frame-ancestors 'none'/);
    // Every inline tag carries it, so an injected one has no way in.
    const tags = html.match(/<(script|style)(\s|>)/g) || [];
    assert.ok(tags.length > 0, `${path}: the page does have inline code`);
    assert.equal((html.match(new RegExp(`nonce="${nonce}"`, "g")) || []).length, tags.length, `${path}: every tag is stamped`);
    // A nonce must not repeat between two responses.
    const again = (await (await req(path)).text()).match(/nonce="([0-9a-f]+)"/)?.[1];
    assert.notEqual(again, nonce, `${path}: a fresh nonce per response`);
  }
});

test("admin page refuses framing and create accepts a charset", async () => {
  const page = await req("/admin", { headers: adminAuth });
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  const res = await req("/admin/keys", {
    method: "POST",
    headers: { ...adminAuth, "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify({ base: "https://x.example", key: "k", expires: inAnHour }),
  });
  assert.equal(res.status, 200);
});

test("model allowlist blocks other models", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, models: ["claude-haiku-*", "gpt-x"] })).json();
  const post = (model) => req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model }) });
  assert.equal((await post("claude-haiku-5-5")).status, 200);
  assert.equal((await post("gpt-x")).status, 200);
  assert.equal((await post("claude-opus-5-5")).status, 403);
  assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "not json" })).status, 403);
  assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 200);
});

test("rate limit and spend cap return 429", async () => {
  const limited = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour, rpm: 1 })).json()).id;
  assert.equal((await req("/v1/models", { headers: bearer(limited) })).status, 200);
  assert.equal((await req("/v1/models", { headers: bearer(limited) })).status, 429);

  const capped = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.01 })).json()).id;
  const real = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ model: "claude-opus-5-5", usage: { input_tokens: 1000, output_tokens: 500 } });
  assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(capped), body: "{}" })).status, 200);
  await Promise.all(pending.splice(0));
  globalThis.fetch = real;
  assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(capped), body: "{}" })).status, 429);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, rpm: 1.5 })).status, 400);
});

test("expiry can be extended while active", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "ci" })).json();
  const later = new Date(Date.now() + 7200e3).toISOString();
  const patch = (body) => req("/admin/keys/" + id, { method: "PATCH", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify(body) });
  const res = await (await patch({ expires: later, key: "" })).json();
  assert.equal(res.expires, later);
  assert.equal(res.label, "ci");
  assert.equal(env.METER.get(id).storage.alarmAt, Date.parse(later));
  const realKey = async () => {
    await withUpstream(replying({}), () => req("/v1/models", { headers: bearer(id) }));
    return sent.headers.get("authorization");
  };
  assert.equal(await realKey(), "Bearer k", "a blank key keeps the current one");
  await patch({ key: "rotated", base: "https://y.example/", capUsd: 5 });
  const route = JSON.parse(store.get(id).value);
  assert.deepEqual([await realKey(), route.base, route.capUsd, route.expires], ["Bearer rotated", "https://y.example", 5, later]);
  assert.equal((await patch({ capUsd: null })).status, 200);
  assert.equal(JSON.parse(store.get(id).value).capUsd, undefined, "null clears a limit");
  assert.equal((await patch({ base: "http://insecure.example" })).status, 400);
  assert.equal((await patch({ expires: "2020-01-01" })).status, 400);
});

test("at expiry the real key is wiped but spend stays listed, then everything is purged", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "secret", expires: inAnHour })).json();
  const { meter, storage } = env.METER.get(id);
  assert.equal(storage.alarmAt, Date.parse(inAnHour));
  const now = Date.now;
  try {
    Date.now = () => now() + 2 * 3600e3;
    await meter.alarm();
    assert.equal(JSON.parse(store.get(id).value).key, null);
    assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 401);
    const listed = (await listAll()).find((k) => k.id === id);
    assert.equal(listed.active, false, "an expired key is listed as inactive");
    Date.now = () => now() + 31 * 864e5;
    await meter.alarm();
    assert.equal(storage.alarmAt, null);
    assert.equal(await storage.get("key"), undefined);
  } finally {
    Date.now = now;
  }
});

test("OpenAI chat and responses calls are metered", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const real = globalThis.fetch;
  const call = async (path, body, type) => {
    globalThis.fetch = async () => new Response(body, { headers: { "content-type": type } });
    await req(path, { method: "POST", headers: bearer(id), body: "{}" });
    await Promise.all(pending.splice(0));
  };
  await call("/v1/chat/completions", [
    'data: {"model":"anthropic/claude-sonnet-5.5","choices":[{"delta":{"content":"hi"}}],"usage":null}',
    'data: {"model":"anthropic/claude-sonnet-5.5","choices":[],"usage":{"prompt_tokens":3000,"completion_tokens":100,"prompt_tokens_details":{"cached_tokens":1000}}}',
    "data: [DONE]",
  ].join("\n\n"), "text/event-stream");
  await call("/v1/responses", JSON.stringify({ object: "response", model: "gpt-x", usage: { input_tokens: 50, output_tokens: 7, input_tokens_details: { cached_tokens: 0 } } }), "application/json");
  globalThis.fetch = real;
  const u = (await keyInfo(id)).usage;
  const sonnet = u.total["anthropic/claude-sonnet-5.5"];
  assert.deepEqual([sonnet.input, sonnet.output], [3000, 100]);
  assert.ok(Math.abs(sonnet.cost - (2000 * 2 + 1000 * 0.1 + 100 * 10) / 1e6) < 1e-12);
  assert.deepEqual([u.total["gpt-x"].input, u.total["gpt-x"].output, u.total["gpt-x"].priced], [50, 7, false]);
  assert.deepEqual(u.months[new Date().toISOString().slice(0, 7)]["gpt-x"].requests, 1);
});

const replying = (body, type = "application/json") => async (url, init) => {
  sent = { url, init, headers: init.headers };
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { headers: { "content-type": type } });
};
async function withUpstream(fn, run) {
  const real = globalThis.fetch;
  globalThis.fetch = fn;
  try { return await run(); } finally { globalThis.fetch = real; }
}
const opusCall = { model: "claude-opus-5-5", usage: { input_tokens: 1000, output_tokens: 500 } };

test("token cap and monthly period", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capTokens: 1500, period: "month" })).json();
  const call = () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
  await withUpstream(replying(opusCall), async () => {
    assert.equal((await call()).status, 200);
    await Promise.all(pending.splice(0));
    const blocked = await call();
    assert.equal(blocked.status, 429);
    assert.match((await blocked.json()).error.message, /token cap of 1500 for this month/);
  });
  const { meter } = env.METER.get(id);
  const months = await meter.storage.get("months");
  months["2000-01"] = months[Object.keys(months)[0]];
  delete months[Object.keys(months)[0]];
  assert.equal((await withUpstream(replying(opusCall), call)).status, 200, "last month's usage does not count");
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, period: "week" })).status, 400);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, capTokens: 0.5 })).status, 400);
});

test("max output tokens are clamped or filled in", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, maxOutput: 100 })).json();
  const bodyFor = async (path, payload) => {
    await withUpstream(replying({}), () => req(path, { method: "POST", headers: bearer(id), body: JSON.stringify(payload) }));
    return JSON.parse(sent.init.body);
  };
  assert.equal((await bodyFor("/v1/messages", { model: "m", max_tokens: 32000 })).max_tokens, 100);
  assert.equal((await bodyFor("/v1/messages", { model: "m", max_tokens: 50 })).max_tokens, 50);
  assert.equal((await bodyFor("/v1/chat/completions", { model: "m", max_completion_tokens: 900 })).max_completion_tokens, 100);
  assert.equal((await bodyFor("/v1/chat/completions", { model: "m" })).max_tokens, 100);
  assert.equal((await bodyFor("/v1/responses", { model: "m" })).max_output_tokens, 100);
  assert.equal((await bodyFor("/v1/messages/count_tokens", { model: "m" })).max_tokens, undefined, "non-generation calls get no new field");
});

test("IP allowlist", async () => {
  assert.ok(inRange("203.0.113.9", "203.0.113.0/24"));
  assert.ok(!inRange("203.0.114.9", "203.0.113.0/24"));
  assert.ok(inRange("2001:db8::1", "2001:db8::/32"));
  assert.ok(inRange("::ffff:10.0.0.1", "::ffff:10.0.0.0/120"));
  assert.ok(!inRange("2001:db9::1", "2001:db8::/32"));
  assert.ok(!inRange("10.0.0.1", "2001:db8::/32"));
  assert.ok(inRange("10.1.2.3", "10.1.2.3"));
  for (const bad of ["1.2.3.256", "1::2::3", "zz::1", "1.2.3"]) assert.equal(parseIp(bad), null, bad);
  assert.equal(parseIp("1:2:3:4:5:6:7:8").bits, 128);

  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, ips: ["203.0.113.0/24", "2001:db8::/32"] })).json();
  const from = (ip) => req("/v1/models", { headers: { ...bearer(id), "cf-connecting-ip": ip } });
  assert.equal((await from("203.0.113.7")).status, 200);
  assert.equal((await from("2001:db8:0:1::5")).status, 200);
  assert.equal((await from("198.51.100.1")).status, 403);
  assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 403);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, ips: ["10.0.0.0/33"] })).status, 400);
});

test("model list endpoint uses the right auth and the stored key", async () => {
  const listModels = (body) => req("/admin/models", { method: "POST", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify(body) });
  const res = await withUpstream(replying({ data: [{ id: "claude-b" }, { id: "claude-a" }, { id: "claude-a" }] }), () =>
    listModels({ base: "https://api.anthropic.com/v1/", key: "real", auth: "x-api-key" }));
  assert.deepEqual((await res.json()).models, ["claude-a", "claude-b"]);
  assert.equal(sent.url, "https://api.anthropic.com/v1/models?limit=1000");
  assert.equal(sent.headers.get("x-api-key"), "real");
  assert.equal(sent.headers.get("anthropic-version"), "2023-06-01");

  const { id } = await (await create({ base: "https://y.example/v1", key: "stored", expires: inAnHour })).json();
  const byId = await withUpstream(replying({ models: [{ name: "gemma" }], object: "list" }), () => listModels({ id }));
  assert.deepEqual((await byId.json()).models, ["gemma"]);
  assert.equal(sent.url, "https://y.example/v1/models");
  assert.equal(sent.headers.get("authorization"), "Bearer stored");

  const failed = await withUpstream(async () => Response.json({ error: { message: "bad key" } }, { status: 401 }), () => listModels({ id }));
  assert.equal(failed.status, 502);
  assert.match((await failed.json()).error.message, /401: bad key/);
  assert.equal((await listModels({ base: "https://y.example" })).status, 400);
});

test("allowed models also filter the client's model list", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, models: ["claude-haiku-*"] })).json();
  const res = await withUpstream(replying({ data: [{ id: "claude-haiku-5-5" }, { id: "claude-opus-5-5" }] }), () =>
    req("/v1/models", { headers: bearer(id) }));
  assert.deepEqual((await res.json()).data.map((m) => m.id), ["claude-haiku-5-5"]);
});

test("prices are editable and used for metering", async () => {
  const put = (prices) => req("/admin/prices", { method: "PUT", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ prices }) });
  const got = await (await req("/admin/prices", { headers: adminAuth })).json();
  assert.deepEqual(got.defaults, DEFAULT_PRICES);
  assert.equal((await put([{ match: "", in: 1, out: 1, read: 1, write5m: 1, write1h: 1 }])).status, 400);
  assert.equal((await put([{ match: "x", in: -1, out: 1, read: 1, write5m: 1, write1h: 1 }])).status, 400);
  assert.equal((await put([{ match: "x", in: 1, out: 1, read: 1, write5m: 1, write1h: 1, fast: 0 }])).status, 400);
  assert.equal((await put([...DEFAULT_PRICES, { match: "deepseek-chat", in: "1", out: 2, read: 0.1, write5m: 1, write1h: 1, fast: "" }])).status, 200);
  assert.deepEqual(JSON.parse(store.get("config:prices").value).at(-1), { match: "deepseek-chat", in: 1, out: 2, read: 0.1, write5m: 1, write1h: 1 });

  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  await withUpstream(replying({ model: "deepseek-chat", usage: { prompt_tokens: 1e6, completion_tokens: 1e6 } }), () =>
    req("/v1/chat/completions", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));
  const u = (await keyInfo(id)).usage.total;
  assert.equal(u["deepseek-chat"].cost, 3);
  assert.ok(!(await listAll()).some((k) => k.id === "config:prices"));
  await put(DEFAULT_PRICES);
});

test("a key in the query string is refused unless ALLOW_QUERY_KEY is set", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const warned = [];
  const realWarn = console.warn;
  console.warn = (...a) => warned.push(a.join(" "));
  try {
    const posts = [`/v1/models?key=${id}`, `/usage?key=${id}`, `/v1/models/gemini:generateContent?key=${id}`];
    for (const path of posts) {
      const res = path.includes("generateContent") ? await req(path, { method: "POST", body: "{}" }) : await req(path);
      assert.equal(res.status, 400, path);
      assert.match((await res.json()).error.message, /authorization or x-api-key header/);
    }
  } finally {
    console.warn = realWarn;
  }
  assert.ok(!warned.join("\n").includes(id), "the refusal is logged without the key");

  env.ALLOW_QUERY_KEY = "true";
  const accepted = [];
  console.warn = (...a) => accepted.push(a.join(" "));
  try {
    assert.equal((await req(`/v1/models?key=${id}&x=1`)).status, 200);
    assert.equal(sent.url, "https://x.example/models?x=1", "the key is stripped from the forwarded URL in the opt-in path too");
    assert.equal(sent.headers.get("authorization"), "Bearer k");
    assert.equal((await req(`/v1/audio/transcriptions?key=${id}`, { method: "POST", body: "{}" })).status, 200);
    assert.equal(sent.url, "https://x.example/audio/transcriptions");
  } finally {
    console.warn = realWarn;
    delete env.ALLOW_QUERY_KEY;
  }
  assert.match(accepted.join("\n"), /\(sk-gw-[0-9a-f]{3}\.\.\.\)/, "every opt-in use is logged, with the prefix only");
  assert.ok(!accepted.join("\n").includes(id), "the log never carries a usable key");
});

test("a header-only key refuses a key in the URL", async () => {
  env.ALLOW_QUERY_KEY = "true";
  try {
    const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, headerOnly: true })).json();
    assert.equal((await req(`/v1/models?key=${id}`)).status, 401, "a leaked URL cannot authenticate");
    assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 200);
    assert.equal((await req(`/usage?key=${id}`)).status, 401);
    assert.equal((await req("/usage", { headers: bearer(id) })).status, 200);

    const edit = (body) => req("/admin/keys/" + id, { method: "PATCH", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify(body) });
    assert.equal((await edit({ label: "kept" })).status, 200);
    assert.equal(JSON.parse(store.get(id).value).headerOnly, true, "an unrelated edit keeps the flag");
    assert.match((await listAll()).find((k) => k.id === id).limits, /headers only/);
    assert.equal((await edit({ headerOnly: false })).status, 200);
    assert.equal(JSON.parse(store.get(id).value).headerOnly, undefined, "unticking clears it");
    assert.equal((await req(`/v1/models?key=${id}`)).status, 200);
  } finally {
    delete env.ALLOW_QUERY_KEY;
  }
});

test("Gemini-style query key, path model and binary bodies", async () => {
  env.ALLOW_QUERY_KEY = "true";
  try {
    const { id } = await (await create({ base: "https://g.example/v1beta", key: "real", expires: inAnHour, auth: "x-goog-api-key", models: ["gemini-pro"] })).json();
    await withUpstream(replying({}), () => req(`/v1/models/gemini-pro:generateContent?alt=sse&key=${id}`, { method: "POST", body: "{}" }));
    assert.equal(sent.url, "https://g.example/v1beta/models/gemini-pro:generateContent?alt=sse", "the gateway key stays out of the upstream URL");
    assert.equal(sent.headers.get("x-goog-api-key"), "real");
    assert.equal((await req(`/v1/models/gemini-ultra:generateContent?key=${id}`, { method: "POST", body: "{}" })).status, 403);
  } finally {
    delete env.ALLOW_QUERY_KEY;
  }

  const capped = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour, maxOutput: 10 })).json()).id;
  const bytes = new Uint8Array([0xff, 0x00, 0xc3, 0x28, 0x80]);
  await withUpstream(replying({}), () => req("/v1/audio/transcriptions", { method: "POST", headers: bearer(capped), body: bytes }));
  assert.deepEqual(new Uint8Array(sent.init.body), bytes);
});

test("usage can be reset and keys duplicated without resending the real key", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "secret", expires: inAnHour, capUsd: 0.01, label: "orig" })).json();
  await withUpstream(replying(opusCall), () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));
  assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 429);
  assert.equal((await req(`/admin/keys/${id}/usage`, { method: "DELETE", headers: adminAuth })).status, 200);
  assert.equal((await withUpstream(replying(opusCall), () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }))).status, 200);
  assert.equal(env.METER.get(id).storage.alarmAt, Date.parse(inAnHour), "reset keeps the expiry alarm");

  const copy = await (await create({ base: "https://x.example", from: id, expires: inAnHour, label: "copy" })).json();
  await withUpstream(replying({}), () => req("/v1/models", { headers: bearer(copy.id) }));
  assert.equal(sent.headers.get("authorization"), "Bearer secret");
  assert.equal((await create({ base: "https://x.example", from: "sk-gw-" + "f".repeat(32), expires: inAnHour })).status, 400);
});

test("real keys are encrypted at rest and bound to their id", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "plain-secret", expires: inAnHour })).json();
  const stored = JSON.parse(store.get(id).value).key;
  assert.match(stored, /^enc:v1:/);
  assert.ok(!store.get(id).value.includes("plain-secret"));
  await withUpstream(replying({}), () => req("/v1/models", { headers: bearer(id) }));
  assert.equal(sent.headers.get("authorization"), "Bearer plain-secret");

  const other = "sk-gw-" + "a".repeat(32);
  store.set(other, { value: store.get(id).value });
  assert.equal((await req("/v1/models", { headers: bearer(other) })).status, 500, "a copied ciphertext does not decrypt under another id");
  store.delete(other);
  const secret = env.ENCRYPTION_KEY;
  env.ENCRYPTION_KEY = "a different secret";
  assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 500);
  env.ENCRYPTION_KEY = secret;

  const legacy = "sk-gw-" + "b".repeat(32);
  store.set(legacy, { value: JSON.stringify({ base: "https://x.example", key: "legacy", expires: inAnHour }) });
  await withUpstream(replying({}), () => req("/v1/models", { headers: bearer(legacy) }));
  assert.equal(sent.headers.get("authorization"), "Bearer legacy", "keys stored before encryption still work");
  store.delete(legacy);
  assert.equal((await (await req("/admin/status", { headers: adminAuth })).json()).encrypted, true);
});

test("the key list shortens the limits string without cutting an address", async () => {
  const ips = Array.from({ length: 100 }, (_, i) => `203.0.113.${i}/32`);
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, ips })).json();
  const listed = (await listAll()).find((k) => k.id === id);
  assert.ok(JSON.stringify(store.get(id).metadata).length <= 1024, "KV metadata stays within its 1024-byte cap");
  assert.match(listed.limits, /open the key for the full settings$/, "the shortening is marked");
  const shown = listed.limits.match(/\d+\.\d+\.\d+\.\d+\/\d+/g);
  assert.ok(shown.length > 10 && shown.length < 100, `the list shows some addresses (${shown.length})`);
  assert.equal((await keyInfo(id)).ips.length, 100, "the detail view is authoritative");
});

test("Gemini's native generateContent usage is metered", async () => {
  env.ALLOW_QUERY_KEY = "true";
  try {
    const { id: key } = await (await create({ base: "https://g.example/v1beta", key: "k", expires: inAnHour, auth: "x-goog-api-key" })).json();
    const call = async (body, type) => {
      await withUpstream(replying(body, type), () => req(`/v1/models/gemini-pro:generateContent?key=${key}`, { method: "POST", body: "{}" }));
      await Promise.all(pending.splice(0));
    };
    await call({ usageMetadata: { promptTokenCount: 1000, cachedContentTokenCount: 200, candidatesTokenCount: 500 } }, "application/json");
    await call([
      'data: {"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":1}}',
      'data: {"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":7}}',
    ].join("\n\n"), "text/event-stream");
    const u = (await keyInfo(key)).usage.total;
    assert.deepEqual([u["gemini-pro"].input, u["gemini-pro"].output], [1000 + 10, 500 + 7], "prompt tokens include the cached part once, and the path names the model");
    assert.equal(u["gemini-pro"].priced, false, "no price row yet, so tokens only");
  } finally {
    delete env.ALLOW_QUERY_KEY;
  }
});

// One test per path: each metered path must record a usage row, each unmeterable one must be refused when capped.
const METERED_PATHS = [
  ["/v1/messages", { model: "claude-opus-5-5", usage: { input_tokens: 10, output_tokens: 5 } }],
  ["/v1/chat/completions", { model: "gpt-chat", usage: { prompt_tokens: 10, completion_tokens: 5 } }],
  ["/v1/responses", { model: "gpt-resp", usage: { input_tokens: 10, output_tokens: 5 } }],
  ["/v1/completions", { model: "gpt-legacy", usage: { prompt_tokens: 10, completion_tokens: 5 } }],
  ["/v1/embeddings", { model: "embed-1", usage: { prompt_tokens: 10 } }],
];
for (const [path, body] of METERED_PATHS) {
  test(`${path} records a usage row`, async () => {
    const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
    await withUpstream(replying(body), () => req(path, { method: "POST", headers: bearer(id), body: "{}" }));
    await Promise.all(pending.splice(0));
    const row = (await keyInfo(id)).usage.total[body.model];
    assert.ok(row, `${path} must record usage`);
    const [input, output] = [body.usage.prompt_tokens ?? body.usage.input_tokens, body.usage.completion_tokens ?? body.usage.output_tokens ?? 0];
    assert.deepEqual([row.input, row.output], [input, output]);
  });
}

for (const path of ["/v1/models/gemini-pro:generateContent", "/v1/models/gemini-pro:streamGenerateContent"]) {
  test(`${path} records a usage row`, async () => {
    env.ALLOW_QUERY_KEY = "true";
    try {
      const { id } = await (await create({ base: "https://g.example/v1beta", key: "k", expires: inAnHour, auth: "x-goog-api-key" })).json();
      await withUpstream(replying({ usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5 } }), () => req(`${path}?key=${id}`, { method: "POST", body: "{}" }));
      await Promise.all(pending.splice(0));
      const row = (await keyInfo(id)).usage.total["gemini-pro"];
      assert.ok(row, `${path} must record usage`);
      assert.deepEqual([row.input, row.output], [10, 5]);
    } finally {
      delete env.ALLOW_QUERY_KEY;
    }
  });
}

for (const path of ["/v1/audio/transcriptions", "/v1/audio/speech", "/v1/images/generations", "/v1/images/edits", "/v1/batches", "/v1/files", "/v1/moderations"]) {
  test(`a capped key is refused on ${path}, an uncapped key is not`, async () => {
    const capped = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capTokens: 1e6 })).json()).id;
    const free = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json()).id;
    const refused = await req(path, { method: "POST", headers: bearer(capped), body: "{}" });
    assert.equal(refused.status, 403);
    assert.match((await refused.json()).error.message, /returns no token usage/);
    const allowed = await withUpstream(replying({}), () => req(path, { method: "POST", headers: bearer(free), body: "{}" }));
    assert.equal(allowed.status, 200, "without a cap the call passes through unmetered");
    assert.deepEqual((await keyInfo(capped)).usage.total, {}, "a refused call records nothing");
    assert.deepEqual((await keyInfo(free)).usage.total, {}, "an unmeterable call records nothing");
  });
}

test("reading stays open to a capped key, because it cannot spend", async () => {
  const capped = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capTokens: 1e6 })).json()).id;
  for (const path of ["/v1/models", "/v1/files"]) {
    const res = await withUpstream(replying({ data: [] }), () => req(path, { headers: bearer(capped) }));
    assert.equal(res.status, 200, path);
  }
});


test("usage shows what was spent against the cap, and an overshoot is logged", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.01 })).json();
  const warned = [];
  const realWarn = console.warn;
  console.warn = (...a) => warned.push(a.join(" "));
  try {
    // One 1M/1M Opus call costs $24, far past a $0.01 cap, and the admit check cannot know that in advance.
    await withUpstream(replying({ model: "claude-opus-5-5", usage: { input_tokens: 1e6, output_tokens: 1e6 } }), () =>
      req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
    await Promise.all(pending.splice(0));
  } finally {
    console.warn = realWarn;
  }
  const u = await (await req("/usage", { headers: bearer(id) })).json();
  assert.equal(u.cap_usd, 0.01);
  assert.ok(u.spent_usd >= 24, `spent is reported as measured (${u.spent_usd})`);
  assert.equal(u.over_cap, true);
  assert.match(warned.join("\n"), /against a cap of \$0\.01/);
  assert.ok(!warned.join("\n").includes(id), "the log carries only the key prefix");

  const fresh = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1 })).json()).id;
  const clean = await (await req("/usage", { headers: bearer(fresh) })).json();
  assert.deepEqual([clean.spent_usd, clean.cap_usd, clean.over_cap], [0, 1, false]);
  const free = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json()).id;
  assert.deepEqual([(await (await req("/usage", { headers: bearer(free) })).json()).cap_usd], [null]);
});

test("ten concurrent requests cannot all pass a cap that fits five", async () => {
  // $0.005 fits five reservations of the $0.001 minimum, so the sixth simultaneous call is refused.
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.005 })).json();
  const results = await withUpstream(replying({}), () => Promise.all(Array.from({ length: 10 }, () => req("/v1/models", { headers: bearer(id) }))));
  assert.equal(results.filter((r) => r.status === 200).length, 5, "exactly five get through the admit gate");
  assert.equal(results.filter((r) => r.status === 429).length, 5);
  assert.match((await results.find((r) => r.status === 429).json()).error.message, /spend cap of \$0\.005 reached/);
  // The reservations expire, so a key is not wedged by a burst that recorded nothing.
  const { storage } = env.METER.get(id);
  const now = Date.now;
  try {
    Date.now = () => now() + 61e3;
    assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 200);
  } finally {
    Date.now = now;
    await storage.delete(["inflight"]);
  }
});

test("a revoked key is refused, keeps its spend, and cannot be revoked twice into a new stamp", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const before = JSON.parse(store.get(id).value);
  assert.ok(before.rev > 0, "every saved record carries a version stamp");
  await withUpstream(replying(opusCall), () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));

  const res = await req(`/admin/keys/${id}/revoke`, { method: "POST", headers: adminAuth });
  assert.equal(res.status, 200);
  const { revoked_at, rev } = await res.json();
  assert.ok(revoked_at && rev > before.rev);
  const after = JSON.parse(store.get(id).value);
  assert.equal(after.key, null, "the real key is wiped at once");
  assert.ok(after.revoked_at, "the record says when");
  assert.equal(after.expires, before.expires, "retention is unchanged");

  assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 401);
  assert.equal((await req("/usage", { headers: bearer(id) })).status, 401);
  assert.equal((await listAll()).find((k) => k.id === id).active, false, "the list shows it inactive");
  assert.equal((await keyInfo(id)).usage.total["claude-opus-5-5"].requests, 1, "the spend stays visible");

  const again = await (await req(`/admin/keys/${id}/revoke`, { method: "POST", headers: adminAuth })).json();
  assert.equal(again.revoked_at, revoked_at, "revoking twice keeps the first timestamp");
  const unknown = "sk-gw-" + crypto.randomUUID().replace(/-/g, "");
  assert.ok(!store.has(unknown));
  assert.equal((await req(`/admin/keys/${unknown}/revoke`, { method: "POST", headers: adminAuth })).status, 404);
});

test("revoke now marks the record revoked even when the KV delete does not land", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const realDelete = env.KEYS.delete;
  // A delete that never reaches a location leaves the old copy behind; it must already be revoked.
  env.KEYS.delete = async () => {};
  try {
    assert.equal((await req("/admin/keys/" + id, { method: "DELETE", headers: adminAuth })).status, 200);
  } finally {
    env.KEYS.delete = realDelete;
  }
  const left = JSON.parse(store.get(id).value);
  assert.equal(left.key, null, "the surviving copy has no real key");
  assert.ok(left.revoked_at, "the surviving copy is stamped revoked");
  assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 401);

  assert.equal((await req("/admin/keys/" + id, { method: "DELETE", headers: adminAuth })).status, 200);
  assert.ok(!store.has(id), "with a working delete the entry is gone");
  assert.equal((await req("/v1/models", { headers: bearer(id) })).status, 401);
});

test("the longest matching price wins, and an unknown model is unpriced", async () => {
  const million = { input_tokens: 1e6 };
  // Two shipped rows where one slug is the other plus a suffix: $5/1M against $4/1M.
  assert.equal(cost("claude-opus-5", million), 5);
  assert.equal(cost("claude-opus-5-5", million), 4);
  assert.equal(cost("claude-opus-5-5-20260501", million), 4, "a dated id takes the longer match");
  assert.equal(cost("claude-opus-5-20260501", million), 5, "and does not borrow the 5-5 row");
  assert.equal(cost("anthropic/claude-opus-4-1", million), 15, "a provider prefix does not break matching");

  // The same hazard with a prefix pair that is not in the shipped table, so the rule is testable in isolation.
  const prices = [
    { match: "gpt-4o", in: 2.5, out: 10, read: 1.25, write5m: 3, write1h: 4 },
    { match: "gpt-4o-mini", in: 0.15, out: 0.6, read: 0.075, write5m: 0.2, write1h: 0.3 },
  ];
  assert.equal(cost("gpt-4o", million, prices), 2.5);
  assert.equal(cost("gpt-4o-mini", million, prices), 0.15, "mini is not billed at the 4o rate");
  assert.equal(cost("openai/gpt-4o-mini-2024-07-18", million, prices), 0.15);
  assert.equal(cost("claude-opus-5", million, prices), null, "nothing matches, so there is no price");
  assert.equal(cost("something-else", million), null);

  // An unpriced model must still be counted, and flagged, rather than silently free.
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  await withUpstream(replying({ model: "nobody/knows-this", usage: { input_tokens: 7, output_tokens: 3 } }), () =>
    req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));
  const row = (await keyInfo(id)).usage.total["nobody/knows-this"];
  assert.deepEqual([row.cost, row.priced, row.input], [0, false, 7]);
});

test("OpenAI's inclusive prompt_tokens and Anthropic's split counters bill the same", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  // 600 fresh + 400 cached input, 500 out, written both ways: OpenAI folds the cached part into prompt_tokens.
  const openai = { model: "claude-opus-5-5", usage: { prompt_tokens: 1000, completion_tokens: 500, prompt_tokens_details: { cached_tokens: 400 } } };
  const anthropic = { model: "claude-opus-5-5", usage: { input_tokens: 600, cache_read_input_tokens: 400, output_tokens: 500 } };
  await withUpstream(replying(openai), () => req("/v1/chat/completions", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));
  await withUpstream(replying(anthropic), () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));

  const one = 600 * 4 / 1e6 + 400 * 0.2 / 1e6 + 500 * 20 / 1e6;
  const row = (await keyInfo(id)).usage.total["claude-opus-5-5"];
  assert.equal(row.requests, 2);
  assert.equal(row.input, 2000, "1000 prompt tokens per call: the cached part is neither lost nor double counted");
  assert.ok(Math.abs(row.cost - 2 * one) < 1e-12, `both shapes cost ${one} each, got ${row.cost / 2}`);
});

test("settings validation edges: a near expiry, 500 models, 100 addresses, a downgrade without a cap", async () => {
  const base = { base: "https://x.example", key: "k" };
  // 30 seconds is too close to the one-minute floor; 90 seconds is fine.
  const soon = new Date(Date.now() + 30e3).toISOString();
  const later = new Date(Date.now() + 90e3).toISOString();
  let res = await create({ ...base, expires: soon });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error.message, /at least a minute away/);
  assert.equal((await create({ ...base, expires: later })).status, 200);

  // The model list cap is 500, inclusive, and each name is capped at 200 characters.
  const models = (n) => Array.from({ length: n }, (_, i) => "model-" + i);
  assert.equal((await create({ ...base, expires: inAnHour, models: models(500) })).status, 200);
  res = await create({ ...base, expires: inAnHour, models: models(501) });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error.message, /up to 500/);
  assert.equal((await create({ ...base, expires: inAnHour, models: ["m".repeat(201)] })).status, 400);

  // The address cap is 100, inclusive.
  const ips = (n) => Array.from({ length: n }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`);
  assert.equal((await create({ ...base, expires: inAnHour, ips: ips(100) })).status, 200);
  res = await create({ ...base, expires: inAnHour, ips: ips(101) });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error.message, /up to 100 entries/);
  assert.equal((await create({ ...base, expires: inAnHour, ips: ["10.0.0.0/33"] })).status, 400);

  // A downgrade measures against a cap, so it cannot be set without one.
  res = await create({ ...base, expires: inAnHour, downgrade: { at: 50, map: [["a", "b"]] } });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error.message, /needs a spend or token cap/);
  assert.equal((await create({ ...base, expires: inAnHour, capUsd: 1, downgrade: { at: 50, map: [["a", "b"]] } })).status, 200);
});

test("a scripted brute-force loop is cut off after five tries and stays cut off", async () => {
  // What an attacker actually runs: a dictionary of passwords against /admin from one address.
  const attempt = (password, ip = "198.51.100.7") =>
    req("/admin/keys", { headers: { authorization: "Basic " + btoa(`admin:${password}`), "cf-connecting-ip": ip } });
  const statuses = [];
  for (let i = 0; i < 20; i++) statuses.push((await attempt(`guess-${i}`)).status);
  assert.deepEqual(statuses.slice(0, 5), [401, 401, 401, 401, 401], "five wrong passwords look the same as each other");
  assert.deepEqual(new Set(statuses.slice(5)), new Set([429]), "everything after that is refused without a comparison");
  // The correct password does not get through either while the address is blocked, which is what makes the block worth having.
  assert.equal((await attempt("pw")).status, 429);
  const blocked = await attempt("pw");
  assert.ok(Number(blocked.headers.get("retry-after")) > 0, "and the answer says when to try again");
  assert.equal((await blocked.text()).trim(), "login required", "with no hint that the password was the right one");
  // Another address is unaffected: the block is per address, not global.
  assert.equal((await attempt("pw", "198.51.100.8")).status, 200);
});

test("no client identity or gateway credential reaches the provider", async () => {
  const { id } = await (await create({ base: "https://api.anthropic.com", key: "real-secret", expires: inAnHour, auth: "x-api-key" })).json();
  // Everything a browser, a proxy or a curious client might attach.
  const client = {
    "cf-connecting-ip": "203.0.113.9",
    "cf-ipcountry": "DE",
    "cf-ray": "8a1b2c3d4e5f",
    "x-forwarded-for": "10.9.8.7",
    "x-forwarded-proto": "http",
    "x-real-ip": "10.9.8.6",
    cookie: "kr_session=stolen",
    origin: "https://evil.example",
    referer: "https://evil.example/page",
    authorization: `Bearer ${id}`,
    "x-api-key": id,
    "api-key": id,
    "x-goog-api-key": id,
    "anthropic-version": "2023-06-01",
    "content-type": "application/json",
  };
  await withUpstream(replying({ model: "claude-opus-5-5", usage: { input_tokens: 1, output_tokens: 1 } }), () =>
    req("/v1/messages", { method: "POST", headers: client, body: JSON.stringify({ model: "claude-opus-5-5" }) }));

  const sentNames = [...sent.headers.keys()];
  for (const name of ["cf-connecting-ip", "cf-ipcountry", "cf-ray", "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "cookie", "origin", "referer"]) {
    assert.ok(!sentNames.includes(name), `${name} must not be forwarded`);
  }
  // The real key replaces the gateway key in one header only, and the gateway key appears nowhere.
  assert.equal(sent.headers.get("x-api-key"), "real-secret");
  assert.equal(sent.headers.get("authorization"), null);
  assert.equal(sent.headers.get("api-key"), null);
  assert.equal(sent.headers.get("x-goog-api-key"), null);
  for (const [name, value] of sent.headers) assert.ok(!value.includes(id), `${name} carried the gateway key`);
  for (const [name, value] of sent.headers) assert.ok(!value.includes("stolen") && !value.includes("evil.example"), `${name} carried client state: ${value}`);
  // A header the client needs to keep still travels.
  assert.equal(sent.headers.get("anthropic-version"), "2023-06-01");
});

test("a redirect from the provider is handed back, never followed, so the real key stays put", async () => {
  const { id } = await (await create({ base: "https://api.provider.example", key: "real-secret", expires: inAnHour })).json();
  const calls = [];
  const redirecting = async (url, init) => {
    calls.push({ url, redirect: init.redirect, authorization: init.headers.get?.("authorization") ?? init.headers.authorization });
    return new Response(null, { status: 307, headers: { location: "https://evil.example/steal" } });
  };
  const res = await withUpstream(redirecting, () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  assert.equal(res.status, 307, "the client sees the redirect the provider sent");
  assert.equal(res.headers.get("location"), "https://evil.example/steal");
  assert.equal(calls.length, 1, "fetch ran once: nothing followed the redirect");
  assert.equal(calls[0].url, "https://api.provider.example/messages");
  assert.equal(calls[0].redirect, "manual", "the redirect mode is what stops the follow");
  assert.equal(calls[0].authorization, "Bearer real-secret");
});

test("a base URL cannot point inside the network the worker runs in", async () => {
  // Every one of these is a request the worker would make from Cloudflare's side, not the operator's.
  const refused = [
    "http://api.example.com",
    "file:///etc/passwd",
    "https://127.0.0.1",
    "https://127.0.0.1:8080/v1",
    "https://169.254.169.254/latest/meta-data",
    "https://10.1.2.3",
    "https://192.168.1.1",
    "https://172.16.0.1",
    "https://0.0.0.0",
    "https://[::1]",
    "https://[::ffff:127.0.0.1]",
    "https://localhost",
    "https://metadata.google.internal",
  ];
  for (const base of refused) {
    const res = await create({ base, key: "k", expires: inAnHour });
    assert.equal(res.status, 400, `${base} must be refused`);
    assert.match((await res.json()).error.message, /https endpoint/, base);
  }
  // Real provider endpoints, including a bare public address and a custom port and path, still work.
  for (const base of ["https://api.anthropic.com", "https://8.8.8.8", "https://api.example.com:8443/v1"]) {
    assert.equal((await create({ base, key: "k", expires: inAnHour })).status, 200, `${base} must be allowed`);
  }
});

test("a sign-in challenge expires after five minutes and is never reusable", async () => {
  delete env.ALLOW_PASSWORD;
  const post = (path, body, headers = adminAuth) => req(path, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) });
  const auth = await authenticator();
  const { challenge } = await (await post("/admin/passkeys/options", {})).json();
  const registration = { id: auth.id, clientDataJSON: b64u(enc(JSON.stringify({ type: "webauthn.create", challenge, origin: "https://gw.example" }))), publicKey: auth.spki, alg: -7, name: "laptop" };
  assert.equal((await post("/admin/passkeys", registration)).status, 200);
  const options = async () => (await (await req("/admin/login/options", { method: "POST" })).json()).challenge;

  const stale = await options();
  const staleAssertion = await assertion(auth, stale);
  const realNow = Date.now;
  try {
    // Six minutes later the challenge the client is still holding has expired.
    Date.now = () => realNow() + 6 * 60e3;
    assert.equal((await post("/admin/login", staleAssertion, fromNewAddress())).status, 401, "an expired challenge is refused");
  } finally {
    Date.now = realNow;
  }
  // A challenge issued now still works, so the refusal was the deadline and not the credential.
  const login = await post("/admin/login", await assertion(auth, await options()), fromNewAddress());
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie").split(";")[0];
  await req("/admin/passkeys/" + auth.id, { method: "DELETE", headers: { cookie } });
  env.ALLOW_PASSWORD = "true";
  assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 200, "the suite is back on the password");
});

test("a share link is capped at a day, is bound to its key and dies on its own", async () => {
  const week = new Date(Date.now() + 7 * 864e5).toISOString();
  const a = (await (await create({ base: "https://x.example", key: "k", expires: week, label: "a" })).json()).id;
  const b = (await (await create({ base: "https://x.example", key: "k", expires: week, label: "b" })).json()).id;
  const makeLink = async (key) => (await req(`/admin/keys/${key}/share`, { method: "POST", headers: { ...adminAuth, "content-type": "application/json" }, body: "{}" })).json();
  const forA = await makeLink(a);
  const inADay = Date.now() + 864e5;
  assert.ok(Math.abs(Date.parse(forA.expires) - inADay) < 5000, `a week-long key still gets a one-day link, got ${forA.expires}`);

  // The token names its key; a holder cannot trade it for another key's secret.
  const forB = new URL((await makeLink(b)).url).pathname;
  const revealedB = await (await req(forB, { method: "POST" })).json();
  assert.equal(revealedB.key, b);
  assert.equal((await req(forB, { method: "POST" })).status, 410, "and each link still works once");

  // Past its deadline the link is dead even though its key is alive.
  const realNow = Date.now;
  try {
    Date.now = () => realNow() + 864e5 + 60e3;
    assert.equal((await req(new URL(forA.url).pathname, { method: "POST" })).status, 410, "an expired link is refused");
    const shell = await req(new URL(forA.url).pathname);
    assert.equal(shell.status, 200, "the page shell is static");
    assert.match(await shell.text(), /Reveal key/);
  } finally {
    Date.now = realNow;
  }
  // A junk token is not a way in either.
  assert.equal((await req("/share/" + "0".repeat(32), { method: "POST" })).status, 410);
});

test("a simple-content-type POST cannot ride a valid session cookie", async () => {
  const json = (path, body, headers = adminAuth) => req(path, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) });
  const auth = await authenticator();
  const { challenge } = await (await json("/admin/passkeys/options", {})).json();
  const registration = { id: auth.id, clientDataJSON: b64u(enc(JSON.stringify({ type: "webauthn.create", challenge, origin: "https://gw.example" }))), publicKey: auth.spki, alg: -7, name: "laptop" };
  const reg = await json("/admin/passkeys", registration);
  assert.equal(reg.status, 200);
  const setCookie = reg.headers.get("set-cookie");
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/, "a browser never attaches this cookie to a cross-site request");
  assert.match(setCookie, /Secure/);
  const cookie = setCookie.split(";")[0];

  // The same body succeeds with the JSON content type the admin page sends...
  const before = (await listAll()).length;
  assert.equal((await json("/admin/keys", { base: "https://x.example", key: "k", expires: inAnHour, label: "json" }, { cookie })).status, 200);
  assert.equal((await listAll()).length, before + 1);
  // ...and is refused with a content type a cross-site form can send without a preflight.
  const payload = JSON.stringify({ base: "https://x.example", key: "k", expires: inAnHour, label: "csrf" });
  for (const type of ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"]) {
    const res = await req("/admin/keys", { method: "POST", headers: { cookie, "content-type": type }, body: payload });
    assert.notEqual(res.status, 200, `${type} must not create a key`);
  }
  assert.equal((await listAll()).length, before + 1, "no key was created by any of them");
  assert.ok(!(await listAll()).some((k) => k.id && (k.limits || "").includes("csrf")));
  // Reading with the cookie still works: the gate is on writes, not on the session.
  assert.equal((await req("/admin/keys", { headers: { cookie } })).status, 200);

  await req("/admin/passkeys/" + auth.id, { method: "DELETE", headers: { cookie } });
  env.ALLOW_PASSWORD = "true";
});

test("no admin response carries the real provider key", async () => {
  const canary = "sk-real-CANARY-0123456789abcdef";
  const { id } = await (await create({ base: "https://x.example", key: canary, expires: inAnHour, label: "canary" })).json();
  const seen = [];
  const record = async (name, res) => seen.push({ name, status: res.status, body: await res.text() });
  const h = (headers = {}) => ({ ...adminAuth, ...headers });

  // Every read an admin session can make.
  await record("GET /admin", await req("/admin", { headers: h() }));
  await record("GET /admin/status", await req("/admin/status", { headers: h() }));
  await record("GET /admin/keys", await req("/admin/keys", { headers: h() }));
  await record("GET /admin/keys/:id", await req("/admin/keys/" + id, { headers: h() }));
  await record("GET /admin/keys/:id/usage", await req("/admin/keys/" + id + "/usage", { headers: h() }));
  await record("GET /admin/passkeys", await req("/admin/passkeys", { headers: h() }));
  await record("GET /admin/prices", await req("/admin/prices", { headers: h() }));
  // And every write that echoes the record back, plus the paths that reuse the stored key.
  const j = (method, path, body) => req(path, { method, headers: h({ "content-type": "application/json" }), body: JSON.stringify(body || {}) });
  await record("POST /admin/keys", await j("POST", "/admin/keys", { base: "https://x.example", key: canary, expires: inAnHour, label: "canary 2" }));
  await record("PATCH /admin/keys/:id", await j("PATCH", "/admin/keys/" + id, { label: "canary renamed" }));
  await record("POST /admin/keys/:id/share", await j("POST", "/admin/keys/" + id + "/share", {}));
  await record("POST /admin/models", await withUpstream(replying({ data: [{ id: "claude-opus-5-5", display_name: "x" }] }), () => j("POST", "/admin/models", { id })));
  await record("POST /admin/keys/:id/revoke", await j("POST", "/admin/keys/" + id + "/revoke", {}));

  assert.ok(seen.length >= 11, "every route was exercised");
  for (const { name, status, body } of seen) {
    assert.notEqual(status, 500, name);
    assert.ok(!body.includes(canary), `${name} leaked the real key`);
    // Nor the sealed form, which would still be a copy of the secret worth stealing.
    assert.ok(!body.includes("enc:v1:"), `${name} leaked the sealed key`);
  }
  assert.ok(seen.some((r) => r.body.includes(id)), "and the gateway key is still shown, so the check is not vacuous");
});

test("an export carries every record and its usage, sealed, and nothing secret in the clear", async () => {
  const canary = "sk-real-EXPORT-canary-42";
  const made = [];
  for (const label of ["one", "two"]) {
    const { id } = await (await create({ base: "https://x.example", key: canary, expires: inAnHour, label })).json();
    made.push(id);
  }
  await withUpstream(replying({ model: "claude-opus-5-5", usage: { input_tokens: 10, output_tokens: 5 } }), () =>
    req("/v1/messages", { method: "POST", headers: bearer(made[0]), body: "{}" }));
  await Promise.all(pending.splice(0));

  const res = await req("/admin/export", { headers: adminAuth });
  assert.equal(res.status, 200);
  const text = await res.text();
  const dump = JSON.parse(text);
  assert.equal(dump.sealed, true);
  assert.ok(Date.parse(dump.exported) > Date.now() - 60e3, "the dump says when it was taken");
  assert.ok(Array.isArray(dump.prices) && dump.prices.length > 5, "prices travel with it, so a restore is self-contained");
  const exported = dump.keys.map((k) => k.id);
  for (const id of made) assert.ok(exported.includes(id), `${id} is in the dump`);
  for (const k of dump.keys.filter((k) => made.includes(k.id))) assert.ok(k.record.key.startsWith("enc:v1:"), `${k.id} is sealed`);
  // A record left over from before sealing is dumped as it is: the export is a faithful backup, not a filter.
  for (const k of dump.keys) assert.ok(typeof k.record === "object" && k.record && "expires" in k.record, `${k.id} has its record`);
  const first = dump.keys.find((k) => k.id === made[0]);
  assert.equal(first.record.key.slice(0, 7), "enc:v1:", "sealed, not plaintext");
  assert.equal(first.usage.total["claude-opus-5-5"].requests, 1, "usage travels too");
  assert.equal(dump.keys.find((k) => k.id === made[1]).usage.total["claude-opus-5-5"], undefined);
  // The dump is a backup of ciphertext: it must not be a way to read a provider key.
  assert.ok(!text.includes(canary));
  // And it is admin-only.
  assert.equal((await req("/admin/export")).status, 401);
});

test("a lost alarm is re-created by the next edit, and KV expires the record on its own", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const { storage } = env.METER.get(id);
  // KV carries its own deadline, so a lost alarm cannot leave a record behind for ever.
  const purgeAt = Date.parse(inAnHour) + 30 * 864e5;
  assert.equal(store.get(id).expiration, Math.floor(purgeAt / 1000), "the record expires 30 days after the key does");
  assert.equal(store.get(id).metadata.expires, inAnHour, "the listing metadata carries the expiry, not a flag");
  assert.equal(store.get(id).metadata.expired, undefined, "nothing is flagged expired before it is");

  await storage.deleteAlarm();
  assert.equal(storage.alarmAt, null, "the alarm is gone");
  const patch = (body) => req("/admin/keys/" + id, { method: "PATCH", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify(body) });
  assert.equal((await patch({ label: "re-armed" })).status, 200);
  assert.equal(storage.alarmAt, Date.parse(inAnHour), "saving the key schedules the wipe again");

  // Pushing the expiry out moves both deadlines together.
  const later = new Date(Date.now() + 48 * 3600e3).toISOString();
  assert.equal((await patch({ expires: later })).status, 200);
  assert.equal(storage.alarmAt, Date.parse(later));
  assert.equal(store.get(id).expiration, Math.floor((Date.parse(later) + 30 * 864e5) / 1000));

  // Running the alarm before the key expires does nothing but re-arm.
  const before = JSON.parse(store.get(id).value);
  await env.METER.get(id).meter.alarm();
  assert.deepEqual(JSON.parse(store.get(id).value), before, "not yet expired, so nothing was wiped");
  assert.equal(storage.alarmAt, Date.parse(later), "and the alarm is still set for the expiry");
});

test("a full KV write quota is reported, not swallowed as a 500", async () => {
  const realPut = env.KEYS.put;
  let writes = 0;
  // The free plan allows 1,000 writes a day; two spare writes here stand in for "the rest are refused".
  env.KEYS.put = async (...args) => {
    if (++writes > 2) throw new Error("KV PUT failed: 429 Too Many Requests");
    return realPut.apply(env.KEYS, args);
  };
  try {
    assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "first" })).status, 200);
    assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "second" })).status, 200);
    const before = (await listAll()).length;
    const refused = await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "third" });
    assert.equal(refused.status, 503, "a refused write is a limit, not a crash");
    const { error } = await refused.json();
    assert.match(error.message, /KV write limit/i);
    assert.match(error.message, /1,000 writes a day/);
    assert.match(error.message, /midnight UTC/);
    assert.equal((await listAll()).length, before, "nothing was half-created");

    // A batch stops at the first refusal and says how many made it.
    writes = 0;
    const batch = await create({ base: "https://x.example", key: "k", expires: inAnHour, count: 5 });
    assert.equal(batch.status, 503);
    assert.equal(batch.headers.get("x-keys-created"), "2");
  } finally {
    env.KEYS.put = realPut;
  }
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour })).status, 200, "and it recovers");
});

test("a long stream reaches the client byte for byte and is still metered", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const events = ['event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-5-5","usage":{"input_tokens":2000}}}'];
  for (let i = 0; i < 400; i++) events.push(`event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"chunk ${i} "}}`);
  events.push('event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":300}}');
  const fixture = events.join("\n\n");

  // A body that arrives in many pieces, so a reader that buffered the whole thing would still work but lose the point.
  const pieces = fixture.match(/[\s\S]{1,37}/g);
  let pulled = 0;
  const upstream = async () => new Response(new ReadableStream({
    pull(c) {
      if (pulled === pieces.length) return void c.close();
      c.enqueue(new TextEncoder().encode(pieces[pulled++]));
    },
  }), { headers: { "content-type": "text/event-stream" } });

  const res = await withUpstream(upstream, () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  assert.equal(res.status, 200);
  assert.equal(await res.text(), fixture, "the client sees exactly the bytes the provider sent");
  assert.equal(pulled, pieces.length, "all of them were read");
  await Promise.all(pending.splice(0));

  const row = (await keyInfo(id)).usage.total["claude-sonnet-5-5"];
  assert.deepEqual([row.requests, row.input, row.output], [1, 2000, 300], `${row.requests} request, ${row.input} in, ${row.output} out`);
});

test("saving prices bumps a version so other isolates stop serving the old table", async () => {
  const row = (match, rate) => ({ match, in: rate, out: rate, read: rate, write5m: rate, write1h: rate });
  const put = (prices) => req("/admin/prices", { method: "PUT", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ prices }) });

  const first = await (await put([row("price-probe-a", 7)])).json();
  assert.equal(typeof first.version, "string", "the save reports the version it wrote");
  assert.ok(store.has("config:prices:v"), "and stores it where every isolate looks");
  assert.deepEqual(store.get("config:prices").value, JSON.stringify([row("price-probe-a", 7)]), "the table is stored as JSON text");

  const second = await (await put([row("price-probe-b", 9)])).json();
  assert.notEqual(second.version, first.version, "a second save is a new version, not the same one");
  assert.equal(store.get("config:prices:v").value, second.version, "the version in KV is the one just reported");

  const listed = await (await req("/admin/prices", { headers: adminAuth })).json();
  assert.deepEqual(listed.prices.map((r) => r.match), ["price-probe-b"], "this isolate serves the new table at once");

  // Back to the shipped table, so the rest of the suite prices models the way it expects.
  await put([]);
  assert.deepEqual((await (await req("/admin/prices", { headers: adminAuth })).json()).prices, []);
  await req("/admin/prices", { method: "PUT", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ prices: DEFAULT_PRICES }) });
});

test("a key listing can be searched, filtered by state, and says how many it matched", async () => {
  await create({ base: "https://api.anthropic.com", key: "k", expires: inAnHour, label: "claude-prod" });
  await create({ base: "https://api.groq.com/openai", key: "k", expires: inAnHour, label: "groq-dev" });
  // A revoked key is the honest way to get an inactive listing entry: an expiry in the past is refused at creation.
  const { id: oldId } = await (await create({ base: "https://api.anthropic.com", key: "k", expires: inAnHour, label: "claude-old" })).json();
  await req("/admin/keys/" + oldId + "/revoke", { method: "POST", headers: adminAuth });
  const get = async (query) => (await req("/admin/keys" + query, { headers: adminAuth })).json();

  // The label and the provider base are both searched, and the match ignores case.
  const byLabel = await get("?q=claude");
  assert.deepEqual(byLabel.keys.map((k) => k.label).sort(), ["claude-old", "claude-prod"]);
  assert.equal(byLabel.total, 2);
  const byProvider = await get("?q=GROQ");
  assert.deepEqual(byProvider.keys.map((k) => k.label), ["groq-dev"]);

  // Active and expired are opposite halves of the same list, so nothing is dropped or counted twice.
  const active = await get("?q=claude&state=active");
  const expired = await get("?q=claude&state=expired");
  assert.ok(active.keys.every((k) => k.active));
  assert.deepEqual(expired.keys.map((k) => k.label), ["claude-old"]);
  assert.deepEqual(active.keys.map((k) => k.label), ["claude-prod"], "a revoked key is not active");
  assert.equal(active.total + expired.total, (await get("?q=claude")).total, "the two states add up to the whole search");
  assert.equal((await get("?q=nothing-matches-this")).total, 0);
  assert.deepEqual((await get("?q=nothing-matches-this")).keys, []);
});

test("a filtered listing pages over the matches, not over every key", async () => {
  // 22 keys share a label the other keys do not, so a page of 20 has to say "22" and offer a second page.
  await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "bulk", count: 20 });
  await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "bulk", count: 2 });
  const first = await (await req("/admin/keys?q=bulk", { headers: adminAuth })).json();
  assert.equal(first.keys.length, 20, "a page stays inside the subrequest budget");
  assert.equal(first.total, 22, "the count is every match, not the page");
  assert.equal(first.cursor, "20");
  const second = await (await req("/admin/keys?q=bulk&cursor=" + first.cursor, { headers: adminAuth })).json();
  assert.equal(second.keys.length, 2);
  assert.equal(second.cursor, null);
  assert.equal(new Set([...first.keys, ...second.keys].map((k) => k.id)).size, 22, "the two pages do not overlap");
  assert.equal(first.truncated, false);
});

test("a viewer account can read keys and usage and cannot change anything", async () => {
  env.VIEWER_PASSWORD = "look-only";
  const viewer = { authorization: "Basic " + btoa("someone:look-only") };
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();

  // Reading works, and the status says which account is asking.
  assert.equal((await req("/admin/keys", { headers: viewer })).status, 200);
  assert.equal((await req("/admin/keys/" + id, { headers: viewer })).status, 200);
  assert.equal((await req("/admin/prices", { headers: viewer })).status, 200);
  const status = await (await req("/admin/status", { headers: viewer })).json();
  assert.equal(status.role, "viewer");
  assert.equal(status.viewerAccount, true);

  // Everything that changes something, or hands out a sealed key, is refused with the same body.
  const refused = [
    ["POST", "/admin/keys"],
    ["PATCH", "/admin/keys/" + id],
    ["DELETE", "/admin/keys/" + id],
    ["POST", "/admin/keys/" + id + "/revoke"],
    ["POST", "/admin/keys/" + id + "/share"],
    ["DELETE", "/admin/keys/" + id + "/usage"],
    ["POST", "/admin/prices"],
    ["POST", "/admin/passkeys"],
    ["GET", "/admin/export"],
  ];
  for (const [method, path] of refused) {
    const res = await req(path, { method, headers: { ...viewer, "content-type": "application/json" }, body: method === "GET" || method === "DELETE" ? undefined : "{}" });
    assert.equal(res.status, 403, `${method} ${path} is refused for a viewer`);
    assert.match((await res.json()).error.message, /read-only/);
  }
  assert.equal((await req("/admin/keys/" + id + "/revoke", { method: "POST", headers: viewer })).status, 403);
  assert.equal((await keyInfo(id)).active, true, "nothing above changed the key");

  // The owner is unaffected by a viewer account existing.
  assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 200);
  assert.equal((await (await req("/admin/status", { headers: adminAuth })).json()).role, "owner");
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour })).status, 200);
  delete env.VIEWER_PASSWORD;
  // With no VIEWER_PASSWORD set, the same credentials are simply wrong.
  assert.equal((await req("/admin/keys", { headers: viewer })).status, 401);
});

test("a session cannot be re-labelled, because the role is inside the signature", async () => {
  env.VIEWER_PASSWORD = "look-only";
  const login = async (password) => (await req("/admin/keys", { headers: { authorization: "Basic " + btoa("u:" + password) } })).headers.get("set-cookie") || "";
  // A Basic-auth request mints no cookie, so take the cookie from the passkey-free path the page uses: silence is fine,
  // the point here is the signature, which is checked on a cookie this test builds itself from a real one.
  const mine = await newSessionFor(env, "viewer");
  assert.equal((await req("/admin/keys", { headers: { cookie: mine } })).status, 200);
  const [token] = mine.split(";");
  const [, exp, role, sig] = token.match(/=(\d+)\.([a-z]+)\.([\w-]+)$/);
  assert.equal(role, "viewer");
  // Changing the role while keeping the signature must fail: this is the promotion attempt.
  assert.equal((await req("/admin/keys", { headers: { cookie: `kr_session=${exp}.owner.${sig}` } })).status, 401);
  assert.equal((await req("/admin/keys", { headers: { cookie: `kr_session=${exp}.admin.${sig}` } })).status, 401, "only the two known roles are accepted");
  assert.equal((await req("/admin/keys", { headers: { cookie: token } })).status, 200, "the untouched cookie still works");
  assert.equal(await login("look-only"), "", "a read with Basic auth sets no cookie of its own");
  delete env.VIEWER_PASSWORD;
});
test("every change is written to an append-only audit log, with a CSV export", async () => {
  const before = (await (await req("/admin/audit", { headers: adminAuth })).json()).kept;
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "audited" })).json();
  const patch = await req("/admin/keys/" + id, { method: "PATCH", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ label: "audited twice" }) });
  assert.equal(patch.status, 200);
  assert.equal((await req("/admin/keys/" + id + "/share", { method: "POST", headers: { ...adminAuth, "content-type": "application/json" }, body: "{}" })).status, 200);
  assert.equal((await req("/admin/keys/" + id + "/revoke", { method: "POST", headers: adminAuth })).status, 200);
  assert.equal((await req("/admin/export", { headers: adminAuth })).status, 200);

  const log = await (await req("/admin/audit", { headers: adminAuth })).json();
  assert.equal(log.kept, before + 5, "five changes, five lines");
  // Newest first, and each line says who, what and which key.
  assert.deepEqual(log.entries.slice(0, 5).map((e) => e.action), ["export database", "revoke key", "share link", "edit key", "create key"]);
  assert.ok(log.entries.every((e) => e.role === "owner" && /^\d{4}-\d\d-\d\dT/.test(e.at)), "every line carries a role and a timestamp");
  assert.equal(log.entries[3].target, id, "an edit names the key it edited");
  assert.match(log.entries[0].target, /^\d+ keys$/, "the export says how much it exported");

  // Reading the log is not a change to it, and nothing in the API can remove a line.
  const again = await (await req("/admin/audit", { headers: adminAuth })).json();
  assert.equal(again.kept, log.kept);
  assert.deepEqual(again.entries[0], log.entries[0]);
  assert.equal((await req("/admin/audit", { method: "DELETE", headers: adminAuth })).status, 404);

  // The CSV has the same rows, with a header, and quotes what needs quoting.
  const csv = await (await req("/admin/audit.csv", { headers: adminAuth })).text();
  const lines = csv.trim().split("\n");
  assert.equal(lines[0], "at,role,action,target");
  assert.equal(lines.length - 1, Math.min(500, log.kept), "one row per entry, up to the cap");
  assert.ok(lines[1].includes("export database"), "newest first, like the JSON");

  // A target with a comma and a quote is escaped rather than splitting the row.
  await adminStore(env, "/audit", { add: { at: new Date().toISOString(), role: "owner", action: "odd", target: 'a,b "c"' } });
  const escaped = (await (await req("/admin/audit.csv", { headers: adminAuth })).text()).trim().split("\n")[1];
  assert.ok(escaped.endsWith('"a,b ""c"""'), `the row is quoted: ${escaped}`);

  // A viewer may not read the log: it names every key and every export.
  env.VIEWER_PASSWORD = "look-only";
  const viewer = { authorization: "Basic " + btoa("u:look-only") };
  assert.equal((await req("/admin/audit", { headers: viewer })).status, 403);
  assert.equal((await req("/admin/audit.csv", { headers: viewer })).status, 403);
  delete env.VIEWER_PASSWORD;
});

test("the audit log keeps the newest 500 entries and drops the oldest, so it cannot grow without bound", async () => {
  const start = (await (await req("/admin/audit", { headers: adminAuth })).json()).kept;
  // Fill past the cap in one write per entry, exactly as the routes do, and remember the last one written.
  let last = "";
  for (let i = 0; i < 500 - start + 3; i++) {
    last = `filler ${i}`;
    await adminStore(env, "/audit", { add: { at: new Date(Date.now() + i).toISOString(), role: "owner", action: last, target: "x" } });
  }
  const log = await (await req("/admin/audit?limit=1000", { headers: adminAuth })).json();
  assert.equal(log.kept, 500, "the log stops at its cap");
  assert.equal(log.entries.length, 500);
  assert.equal(log.entries[0].action, last, "the newest is first");
  assert.ok(!log.entries.some((e) => e.action === "create key" && e.target === "x"), "the older lines are the ones that went");
  // limit is honoured and bounded.
  assert.equal((await (await req("/admin/audit?limit=2", { headers: adminAuth })).json()).entries.length, 2);
  assert.equal((await (await req("/admin/audit?limit=0", { headers: adminAuth })).json()).entries.length, 100, "a missing or zero limit means the default 100");
});
test("a key holder sees what each model cost, and when the period resets", async () => {
  const { readFileSync } = await import("node:fs");
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, period: "month", capUsd: 5 })).json();
  // Two cheap models and one dear one, so the order is a fact and not an accident of insertion.
  for (const model of ["claude-haiku-4-5", "claude-sonnet-4-5", "claude-haiku-4-5"]) {
    await withUpstream(replying({ model, usage: { input_tokens: 1200, output_tokens: 300 } }), async () => {
      assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model }) })).status, 200);
      await Promise.all(pending.splice(0));
    });
  }
  const u = await (await req("/usage", { headers: bearer(id) })).json();
  assert.deepEqual(u.breakdown.map((m) => m.model), ["claude-sonnet-4-5", "claude-haiku-4-5"], "most expensive first");
  const haiku = u.breakdown[1];
  assert.equal(haiku.requests, 2, "two calls are one row, not two");
  assert.equal(haiku.input, 2400, "input tokens add up");
  assert.equal(haiku.output, 600);
  assert.ok(haiku.cost > 0 && haiku.cost < u.breakdown[0].cost, "the cheap model costs less than the dear one");
  assert.ok(Math.abs(u.breakdown.reduce((t, m) => t + m.cost, 0) - u.used.usd) < 1e-9, "the rows add up to the total");
  // A monthly key says when it rolls over: the 1st of next month, UTC midnight.
  const reset = new Date(u.reset);
  assert.equal(reset.getUTCDate(), 1);
  assert.equal(reset.getUTCHours(), 0);
  assert.ok(reset.getTime() > Date.now() && reset.getTime() - Date.now() < 32 * 864e5, "within the next month");
  assert.equal(u.period, "month");
  // A lifetime key never resets, and reports it that way rather than inventing a date.
  const plain = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  assert.equal((await (await req("/usage", { headers: bearer(plain.id) })).json()).reset, null);
  // The page renders the date and the table, never as markup.
  const page = readFileSync(new URL("./usage.html", import.meta.url), "utf8");
  assert.ok(page.includes('<table id="models" hidden>'));
  assert.ok(page.includes('<tbody id="modelRows"></tbody>'));
  for (const head of ["Model", "Requests", "Input", "Output", "Cost"]) assert.ok(page.includes(`<th scope="col">${head}</th>`), `a ${head} column`);
  assert.ok(page.includes("if (u.reset) row(\"Resets\""), "the page shows the reset date when there is one");
  assert.ok(!/innerHTML|insertAdjacentHTML/.test(page), "the rows are built from text, not markup");
  assert.ok(page.includes('$("models").hidden = !u.breakdown.length;'), "an empty table is hidden, not left blank");
});
test("a key that crosses its alert threshold says so once, to the webhook the deployment configured", async () => {
  const hook = [];
  // One stub for both hops: the provider, and the operator's webhook.
  await withUpstream(async (url, init) => {
    if (String(url).startsWith("https://x.example")) return new Response(JSON.stringify({ model: "claude-sonnet-4-5", usage: { input_tokens: 1000, output_tokens: 500 } }), { headers: { "content-type": "application/json" } });
    hook.push({ url: String(url), body: JSON.parse(init.body), type: init.headers["content-type"] });
    return new Response("ok");
  }, async () => {
    // Each call costs $0.0105; 60% of a $0.05 cap is $0.03, so the third call ($0.0315) is the one that crosses it.
    const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.05, alertAt: 60 })).json();
    env.ALERT_WEBHOOK = "https://hooks.example/keyrouter";
    const call = async () => {
      assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 200);
      await Promise.all(pending.splice(0));
    };
    await call();
    assert.equal(hook.filter((h) => h.body.event === "threshold").length, 0, "the first call is under the threshold");
    await call();
    assert.equal(hook.filter((h) => h.body.event === "threshold").length, 0, "the second call is still under it");
    await call();
    const thresholds = hook.filter((h) => h.body.event === "threshold");
    assert.equal(thresholds.length, 1, "the crossing call notifies");
    const sent = thresholds[0];
    assert.equal(sent.url, "https://hooks.example/keyrouter");
    assert.equal(sent.type, "application/json");
    assert.equal(sent.body.event, "threshold");
    assert.equal(sent.body.at, 60);
    assert.ok(sent.body.percent >= 60, `the payload says where the key is: ${sent.body.percent}`);
    assert.equal(sent.body.cap_usd, 0.05);
    assert.equal(sent.body.period, "total");
    assert.match(sent.body.key, /^sk-gw-[0-9a-f]{3}\.\.\.$/, "a prefix, not the key");
    // Nothing secret: no bearer, no provider key, no full gateway key.
    const text = JSON.stringify(sent.body);
    assert.ok(!text.includes(id), "the full key id never leaves the deployment");
    assert.ok(!/secret|authorization|x-api-key/i.test(text));
    await call();
    assert.equal(hook.filter((h) => h.body.event === "threshold").length, 1, "sitting over the threshold does not notify again");
    // With no webhook configured the crossing is logged, not an error, and the call still succeeds.
    delete env.ALERT_WEBHOOK;
    const other = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capTokens: 100, alertAt: 50 })).json();
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(other.id), body: "{}" })).status, 200);
    await Promise.all(pending.splice(0));
    assert.equal(hook.filter((h) => h.body.event === "threshold").length, 1, "no webhook, nothing sent");
  });
});

test("an alert needs a cap and a whole percentage, and the key list says when one is set", async () => {
  const noCap = await create({ base: "https://x.example", key: "k", expires: inAnHour, alertAt: 80 });
  assert.equal(noCap.status, 400);
  assert.match((await noCap.json()).error.message, /needs a spend or token cap/);
  for (const bad of [0, 101, 80.5, -5]) {
    const res = await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 5, alertAt: bad });
    assert.equal(res.status, 400, `alertAt ${bad} is refused`);
  }
  const ok = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 5, alertAt: 75 })).json();
  const listed = await (await req("/admin/keys/" + ok.id, { headers: adminAuth })).json();
  assert.equal(listed.alertAt, 75);
  const { id: fresh } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 5 })).json();
  assert.equal((await (await req("/admin/keys/" + fresh, { headers: adminAuth })).json()).alertAt, undefined, "no alert unless asked for");
  const page = await (await req("/admin", { headers: adminAuth })).text();
  assert.ok(page.includes('<input id="alertAt" type="number" min="1" max="100" step="1" placeholder="no alert">'));
});
test("the report says what a key spent today and this week, what stopped it, and what it was rerouted to", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.05, rpm: 60 })).json();
  const sonnet = { model: "claude-sonnet-4-5", usage: { input_tokens: 1000, output_tokens: 500 } };
  const haiku = { model: "claude-haiku-4-5", usage: { input_tokens: 2000, output_tokens: 1000 } };
  for (const body of [sonnet, haiku, sonnet]) {
    await withUpstream(replying(body), async () => {
      assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model: body.model }) })).status, 200);
      await Promise.all(pending.splice(0));
    });
  }
  const day = await (await req("/admin/keys/" + id + "/report?days=1", { headers: adminAuth })).json();
  assert.equal(day.requests, 3, "three calls today");
  assert.equal(day.days, 1);
  assert.ok(day.from === day.to && /^\d{4}-\d{2}-\d{2}$/.test(day.to), "one day, named in UTC");
  assert.deepEqual(day.models.map((m) => m.model), ["claude-sonnet-4-5", "claude-haiku-4-5"], "top models, most expensive first");
  assert.equal(day.models[0].requests, 2);
  assert.equal(day.tokens, 6000, "1500 + 3000 + 1500");
  // The same numbers the usage page shows, because both read the same meter.
  const u = await (await req("/usage", { headers: bearer(id) })).json();
  assert.ok(Math.abs(day.spend_usd - u.used.usd) < 1e-9, "the report and the usage page agree on spend");
  assert.equal(day.refused, 0);
  assert.equal(day.downgraded, 0);

  // A refusal is counted by the meter itself and reaches the report.
  const capped = await (await req("/admin/keys/" + id, { method: "PATCH", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ capUsd: 0.001 }) })).json();
  assert.equal(capped.capUsd, 0.001);
  const stopped = await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
  assert.equal(stopped.status, 429);
  assert.match((await stopped.json()).error.message, /spend cap/);
  const week = await (await req("/admin/keys/" + id + "/report", { headers: adminAuth })).json();
  assert.equal(week.span, 7, "a week by default");
  assert.equal(week.refused, 1, "the 429 is counted");

  // A downgrade is counted where it is applied: the first call sets the share, the second is rerouted.
  const { id: down } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1, downgrade: { at: 1, map: [["claude-opus-5-5", "claude-haiku-4-5"]] } })).json();
  await withUpstream(replying(opusCall), async () => {
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(down), body: JSON.stringify({ model: "claude-opus-5-5" }) })).status, 200);
    await Promise.all(pending.splice(0));
  });
  const second = await req("/v1/messages", { method: "POST", headers: bearer(down), body: JSON.stringify({ model: "claude-opus-5-5" }) });
  assert.equal(second.headers.get("x-gateway-downgrade"), "claude-opus-5-5 -> claude-haiku-4-5", "the second call was rerouted");
  await Promise.all(pending.splice(0));
  const rerouted = await (await req("/admin/keys/" + down + "/report?days=7", { headers: adminAuth })).json();
  assert.equal(rerouted.downgraded, 1, "the reroute is counted");

  // An older day is outside the window: the span really filters, it does not relabel everything as "today".
  const { meter: old } = env.METER.get(id);
  const days = await old.storage.get("days");
  const older = new Date(Date.now() - 3 * 864e5).toISOString().slice(0, 10);
  days[older] = { "claude-opus-5-5": { requests: 9, input: 900, output: 90, nano: 5000000000 } };
  await old.storage.put("days", days);
  assert.equal((await (await req("/admin/keys/" + id + "/report?days=1", { headers: adminAuth })).json()).requests, 3, "today only");
  const threeDays = await (await req("/admin/keys/" + id + "/report?days=4", { headers: adminAuth })).json();
  assert.equal(threeDays.requests, 12, "the four-day window includes it");
  assert.equal(threeDays.models[0].model, "claude-opus-5-5", "and it is now the most expensive model");
  assert.equal(threeDays.days, 2);

  // Boundaries: the span is clamped, and a viewer may read a report but not reset usage.
  assert.equal((await (await req("/admin/keys/" + id + "/report?days=0", { headers: adminAuth })).json()).span, 7, "zero means the default week");
  assert.equal((await (await req("/admin/keys/" + id + "/report?days=9999", { headers: adminAuth })).json()).span, 32);
  env.VIEWER_PASSWORD = "look-only";
  const viewer = { authorization: "Basic " + btoa("u:look-only") };
  assert.equal((await req("/admin/keys/" + id + "/report", { headers: viewer })).status, 200);
  assert.equal((await req("/admin/keys/" + id + "/usage", { method: "DELETE", headers: viewer })).status, 403);
  delete env.VIEWER_PASSWORD;
});
test("a key that spends five times its usual hour is flagged, and a steady one is not", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const { meter: store } = env.METER.get(id);
  const { anomalyOf, hourKey } = await import("./src/meter.js");

  // The arithmetic, without a Durable Object: a median of completed hours, and a five times rule.
  const hour = (n) => new Date(Date.now() - n * 3600e3);
  const same = (usd) => Object.fromEntries([1, 2, 3, 4, 5, 6, 7].map((n) => [hourKey(hour(n)), { requests: 1, nano: Math.round(usd * 1e9) }]));
  assert.equal(anomalyOf(same(0.001)).flagged, false, "an hour that matches the others is not an anomaly");
  assert.equal(anomalyOf({ ...same(0.001), [hourKey()]: { requests: 1, nano: 10e6 } }).flagged, true, "$0.01 against a $0.001 median");
  assert.equal(anomalyOf({ ...same(0.001), [hourKey()]: { requests: 1, nano: 2e6 } }).flagged, false, "twice the median is not five times it");
  assert.equal(anomalyOf({ [hourKey()]: { requests: 1, nano: 100e6 } }).flagged, false, "a brand-new key has no baseline, so nothing is an anomaly yet");
  assert.equal(anomalyOf({ ...same(0), [hourKey()]: { requests: 1, nano: 100000 } }).flagged, false, "below the floor it is noise");
  assert.equal(anomalyOf({}).ratio, 0);
  const flat = anomalyOf({ [hourKey(hour(1))]: { requests: 1, nano: 1e6 }, [hourKey(hour(2))]: { requests: 1, nano: 3e6 }, [hourKey()]: { requests: 1, nano: 4e6 } });
  assert.equal(flat.median_usd, 0.002, "the median of 0.001 and 0.003, not their mean");
  assert.equal(flat.ratio, 2);

  // A real call is recorded into an hourly bucket, and the report answers the check.
  await withUpstream(replying(opusCall), async () => {
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 200);
    await Promise.all(pending.splice(0));
  });
  const hours = await store.storage.get("hours");
  assert.equal(hours[hourKey()].requests, 1, "the call landed in this hour");
  assert.ok(hours[hourKey()].nano > 0, "with its cost");
  // Give the key a cheap week, then let this hour stand out.
  for (let n = 1; n <= 40; n++) hours[hourKey(hour(n))] = { requests: 1, nano: 100000 };
  await store.storage.put("hours", hours);
  const report = await (await req("/admin/keys/" + id + "/report", { headers: adminAuth })).json();
  assert.equal(report.anomaly.flagged, true, "one call at list price is five times a week of tenths of a cent");
  assert.ok(report.anomaly.hours >= 40);
  assert.ok(report.anomaly.ratio >= 5);
  // The window is a week of hours, so older ones are dropped rather than kept forever.
  const wide = { ...hours };
  for (let n = 1; n <= 300; n++) wide[hourKey(hour(n))] = { requests: 1, nano: 1 };
  const { pruneHours, HOURS_KEPT } = await import("./src/meter.js");
  assert.equal(Object.keys(pruneHours(wide)).length, HOURS_KEPT);
  assert.ok(pruneHours(wide)[hourKey()], "the newest hour survives the prune");
});
test("an anomalous hour reaches the same webhook, once for that hour and with no key in the body", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "spender" })).json();
  const { meter: store } = env.METER.get(id);
  const { hourKey } = await import("./src/meter.js");
  // A cheap week, so the next call is five times the median hour.
  const hours = {};
  for (let n = 1; n <= 30; n++) hours[hourKey(new Date(Date.now() - n * 3600e3))] = { requests: 1, nano: 100000 };
  await store.storage.put("hours", hours);
  const hook = [];
  await withUpstream(async (url, init) => {
    if (String(url).startsWith("https://x.example")) return new Response(JSON.stringify(opusCall), { headers: { "content-type": "application/json" } });
    hook.push(JSON.parse(init.body));
    return new Response("ok");
  }, async () => {
    env.ALERT_WEBHOOK = "https://hooks.example/keyrouter";
    const call = async () => {
      assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 200);
      await Promise.all(pending.splice(0));
    };
    await call();
    const spikes = hook.filter((h) => h.event === "anomaly");
    assert.equal(spikes.length, 1, "the spike is reported");
    const spike = spikes[0];
    assert.equal(spike.key, "sk-gw-" + id.slice(6, 9) + "...", "a prefix, not the key");
    assert.equal(spike.label, "spender");
    assert.equal(spike.hour, hourKey(), "it names the hour it was measured in");
    assert.ok(spike.ratio >= 5, `the ratio is reported: ${spike.ratio}`);
    assert.ok(spike.median_usd > 0 && spike.hour_usd > spike.median_usd);
    assert.ok(!JSON.stringify(spike).includes(id), "the full key never leaves the deployment");
    // The same hour does not report twice, however many calls it holds.
    await call();
    assert.equal(hook.filter((h) => h.event === "anomaly").length, 1);
    delete env.ALERT_WEBHOOK;
  });
});
test("a key holder can ask for a new key, and only an owner can issue one with an hour of grace", async () => {
  // Five days of life, so the hour of grace is a shortening and not just the expiry it already had.
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: new Date(Date.now() + 5 * 864e5).toISOString(), label: "worker", capUsd: 5 })).json();
  // The holder asks. Nothing secret comes back, and asking twice is one request.
  const asked = await req("/usage/rotate", { method: "POST", headers: bearer(id) });
  assert.equal(asked.status, 200);
  const answer = await asked.json();
  assert.equal(answer.ok, true);
  assert.equal(answer.pending, 1);
  assert.match(answer.note, /owner has to issue the new key/);
  assert.equal(JSON.stringify(answer).includes("sk-gw-" + id.slice(6)), false, "no key material in the answer");
  assert.equal((await (await req("/usage/rotate", { method: "POST", headers: bearer(id) })).json()).pending, 1, "one request per key");
  assert.equal((await req("/usage/rotate", { method: "POST", headers: bearer("sk-gw-" + "0".repeat(32)) })).status, 401, "an unknown key cannot ask");
  assert.equal((await req("/usage/rotate", { headers: bearer(id) })).status, 405, "asking is a POST");

  // The owner sees the request, and a viewer cannot act on it.
  const list = await (await req("/admin/rotations", { headers: adminAuth })).json();
  assert.equal(list.pending, 1);
  assert.equal(list.rotations[0].id, id);
  assert.equal(list.rotations[0].label, "worker");
  assert.equal(list.rotations[0].active, true);
  env.VIEWER_PASSWORD = "look-only";
  const viewer = { authorization: "Basic " + btoa("u:look-only") };
  assert.equal((await req("/admin/rotations/" + id + "/approve", { method: "POST", headers: viewer })).status, 403);
  assert.equal((await req("/admin/rotations", { headers: viewer })).status, 403, "the queue names every key, so it is owner-only");
  delete env.VIEWER_PASSWORD;

  // Approving: a new key with the same settings and the same real key, and the old one alive for an hour.
  const approved = await req("/admin/rotations/" + id + "/approve", { method: "POST", headers: adminAuth });
  assert.equal(approved.status, 200);
  const { old, new: fresh, url } = await approved.json();
  assert.match(fresh.id, /^sk-gw-[0-9a-f]{32}$/);
  assert.notEqual(fresh.id, id);
  assert.match(url, /\/share\/[0-9a-f]{32}$/, "the owner hands the new key over with a one-time link");
  const grace = Date.parse(old.expires) - Date.now();
  assert.ok(grace > 55 * 60e3 && grace <= 3600e3 + 5e3, `about an hour of grace, measured ${grace}`);
  assert.ok(grace < 2 * 3600e3, "the old key does not keep five days");
  // The record itself, not just the answer: the old key must really stop in an hour.
  const shortened = await (await req("/admin/keys/" + id, { headers: adminAuth })).json();
  const left = Date.parse(shortened.expires) - Date.now();
  assert.ok(left > 55 * 60e3 && left < 2 * 3600e3, `the stored old key stops within the hour, measured ${left}`);
  const copy = await (await req("/admin/keys/" + fresh.id, { headers: adminAuth })).json();
  assert.equal(copy.base, "https://x.example", "the new key points where the old one did");
  assert.equal(copy.capUsd, 5);
  assert.equal(copy.label, "worker");
  assert.ok(Date.parse(copy.expires) >= Date.now() + 864e5 - 5e3, "the new key lasts at least a day");
  // Both keys work while the grace window is open, and the shared link reveals the new one.
  await withUpstream(replying(opusCall), async () => {
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 200, "the old key still works");
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(fresh.id), body: "{}" })).status, 200, "and so does the new one");
    await Promise.all(pending.splice(0));
  });
  const shared = await req(url.replace(/^https:\/\/[^/]+/, ""), { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal((await shared.json()).key, fresh.id, "the share link hands over the new key");
  // The request is gone, so approving twice is not possible.
  assert.equal((await (await req("/admin/rotations", { headers: adminAuth })).json()).pending, 0);
  assert.equal((await req("/admin/rotations/" + fresh.id + "/approve", { method: "POST", headers: adminAuth })).status, 200, "an unrequested id is not a 404: it still rotates");
  const log = await (await req("/admin/audit?limit=20", { headers: adminAuth })).json();
  assert.ok(log.entries.some((e) => e.action === "rotate key" && e.target === id), "the rotation is in the audit log");
});

test("denying a rotation leaves the key exactly as it was", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "keep" })).json();
  const before = await (await req("/admin/keys/" + id, { headers: adminAuth })).json();
  assert.equal((await req("/usage/rotate", { method: "POST", headers: bearer(id) })).status, 200);
  const denied = await (await req("/admin/rotations/" + id + "/deny", { method: "POST", headers: adminAuth })).json();
  assert.deepEqual(denied, { ok: true, denied: id });
  const after = await (await req("/admin/keys/" + id, { headers: adminAuth })).json();
  assert.equal(after.expires, before.expires, "a denial does not shorten the key");
  assert.equal(after.active, true);
  assert.equal((await (await req("/admin/rotations", { headers: adminAuth })).json()).pending, 0);
});
test("the deployment report sums every key, and the cron digest posts it to the webhook", async () => {
  // A label of its own, so the report can be asked about exactly these two keys in a deployment full of others.
  const { id: a } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "report alpha", capUsd: 9 })).json();
  const { id: b } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "report beta" })).json();
  const before = (await (await req("/admin/report?days=1&q=report", { headers: adminAuth })).json()).totals;
  const sonnet = { model: "claude-sonnet-4-5", usage: { input_tokens: 1000, output_tokens: 500 } };
  await withUpstream(replying(sonnet), async () => {
    for (const id of [a, a, b]) {
      assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" })).status, 200);
      await Promise.all(pending.splice(0));
    }
  });
  const report = await (await req("/admin/report?days=1&q=report", { headers: adminAuth })).json();
  assert.equal(report.keys, 2, "both keys spent, so both are in it");
  assert.equal(report.q, "report");
  assert.equal(report.days, 1);
  assert.equal(report.totals.requests - before.requests, 3, "three calls across the two keys");
  assert.equal(report.totals.tokens - before.tokens, 4500);
  assert.ok(report.totals.spend_usd > before.spend_usd + 0.009);
  assert.equal(report.top[0].model, "claude-sonnet-4-5");
  assert.ok(report.top[0].requests >= 3);
  assert.equal(report.truncated, false);
  assert.equal(report.keys_by_spend.length, 2);
  assert.deepEqual(report.keys_by_spend[0].id, a, "the key that spent twice as much comes first");
  assert.ok(report.keys_by_spend[0].spend_usd > report.keys_by_spend[1].spend_usd);
  // A viewer may read the report: it is data they can already see key by key.
  env.VIEWER_PASSWORD = "look-only";
  assert.equal((await req("/admin/report?days=7", { headers: { authorization: "Basic " + btoa("u:look-only") } })).status, 200);
  delete env.VIEWER_PASSWORD;

  // The admin page shows the same report, with a window selector and an honest note when it is partial.
  const { readFileSync } = await import("node:fs");
  const shell = await (await req("/admin", { headers: adminAuth })).text();
  const script = readFileSync(new URL("./pages/admin.js.txt", import.meta.url), "utf8");
  assert.match(shell, /<h2>Report<\/h2>/);
  assert.ok(shell.includes('<select id="reportDays" aria-label="Report window">'));
  assert.ok(shell.includes('<tbody id="reportModels"></tbody>'));
  assert.ok(script.includes('fetch("/admin/report?days=" + days)'));
  assert.ok(script.includes('$("reportDays").onchange = () => loadReport();'), "changing the window reloads it");
  assert.ok(script.includes("these totals are a floor"), "a truncated report says so");
  assert.match(script, /loadReport\(\);\n    loadHealth\(\);\n    loadLog\(\)/, "a viewer sees the report too, and no queue");

  // The cron handler: one message, with the same numbers, and nothing at all when no webhook is set.
  const all = await (await req("/admin/report?days=1", { headers: adminAuth })).json();
  const { default: entry } = await import("./worker.js");
  const hook = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    hook.push({ url: String(url), body: JSON.parse(init.body) });
    return new Response("ok");
  };
  // The handler hands its work to waitUntil, so the test collects it the way the runtime would.
  const run = async () => {
    const work = [];
    await entry.scheduled({ cron: "0 7 * * *" }, env, { waitUntil: (p) => work.push(p) });
    await Promise.allSettled(work);
  };
  try {
    await run();
    assert.equal(hook.length, 0, "no ALERT_WEBHOOK, no message");
    env.ALERT_WEBHOOK = "https://hooks.example/digest";
    await run();
    assert.equal(hook.length, 1);
    assert.equal(hook[0].url, "https://hooks.example/digest");
    assert.equal(hook[0].body.event, "digest");
    assert.equal(hook[0].body.days, 1, "the digest is about yesterday");
    assert.equal(hook[0].body.totals.requests, all.totals.requests, "the same report the page shows");
    assert.ok(hook[0].body.top.some((m) => m.model === "claude-sonnet-4-5"));
    assert.match(hook[0].body.at, /^\d{4}-\d{2}-\d{2}T/);
    // A webhook that throws must not take the trigger down with it.
    globalThis.fetch = async () => { throw new Error("network down"); };
    await run();
    delete env.ALERT_WEBHOOK;
  } finally {
    globalThis.fetch = real;
  }
});

test("a host budget is shared by every key pointed at it, and refused at admit time", async () => {
  // Two keys on the same host, and one on another host that must not be affected.
  const base = "https://shared.example";
  const { id: one } = await (await create({ base, key: "k", expires: inAnHour, label: "group one", capUsd: 50 })).json();
  const { id: two } = await (await create({ base, key: "k", expires: inAnHour, label: "group two", capUsd: 50 })).json();
  const { id: other } = await (await create({ base: "https://elsewhere.example", key: "k", expires: inAnHour, label: "group other" })).json();

  // Setting the budget copies it onto the keys already pointed at the host, and nothing else changes.
  const set = await (await req("/admin/groups", { method: "POST", headers: adminAuth, body: JSON.stringify({ host: "shared.example", capUsd: 0.02 }) })).json();
  assert.equal(set.ok, true);
  assert.equal(set.capUsd, 0.02);
  assert.equal(set.updated, 2, "both keys on the host were updated, not the one elsewhere");
  assert.deepEqual(set.groups, ["shared.example"]);
  assert.equal((await keyInfo(one)).capUsd, 50, "a per-key cap is untouched by a host budget");
  const { groups } = await (await req("/admin/groups", { headers: adminAuth })).json();
  assert.equal(groups.length, 1);
  assert.equal(groups[0].host, "shared.example");
  assert.equal(groups[0].capUsd, 0.02);

  // A bad host or amount is refused, and a viewer may neither read nor set a budget.
  assert.equal((await req("/admin/groups", { method: "POST", headers: adminAuth, body: JSON.stringify({ host: "not a host", capUsd: 1 }) })).status, 400);
  assert.equal((await req("/admin/groups", { method: "POST", headers: adminAuth, body: JSON.stringify({ host: "x.example", capUsd: -1 }) })).status, 400);
  env.VIEWER_PASSWORD = "look-only";
  const asViewer = { authorization: "Basic " + btoa("u:look-only") };
  assert.equal((await req("/admin/groups", { headers: asViewer })).status, 200, "a viewer may see the budgets");
  assert.equal((await req("/admin/groups", { method: "POST", headers: asViewer, body: JSON.stringify({ host: "x.example", capUsd: 1 }) })).status, 403);
  delete env.VIEWER_PASSWORD;

  // Spend from both keys lands in one group, so the second key is refused once the first one used it up.
  const pricey = { model: "claude-opus-4-1", usage: { input_tokens: 2000, output_tokens: 1000 } };
  await withUpstream(replying(pricey), async () => {
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(one), body: "{}" })).status, 200);
    await Promise.all(pending.splice(0));
    // The first call already spent more than the whole host budget, so the other key on the same host is refused
    // even though its own cap is untouched, and a key on another host still works.
    const refused = await req("/v1/messages", { method: "POST", headers: bearer(two), body: "{}" });
    assert.equal(refused.status, 429);
    assert.match(await refused.text(), /shared budget for shared\.example is used up/);
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(other), body: "{}" })).status, 200);
    await Promise.all(pending.splice(0));
  });
  const after = (await (await req("/admin/groups", { headers: adminAuth })).json()).groups[0];
  assert.ok(after.usage.spent_usd > 0.02, "the group counts what both keys spent against it");

  // Clearing the budget lets the second key through again, and reaches the keys it was copied onto.
  assert.equal((await (await req("/admin/groups", { method: "POST", headers: adminAuth, body: JSON.stringify({ host: "shared.example", capUsd: 0 }) })).json()).updated, 2);
  await withUpstream(replying(pricey), async () => {
    assert.equal((await req("/v1/messages", { method: "POST", headers: bearer(two), body: "{}" })).status, 200);
    await Promise.all(pending.splice(0));
  });
  assert.deepEqual((await (await req("/admin/groups", { headers: adminAuth })).json()).groups, []);

  // Both changes are in the audit log, under the owner.
  const log = (await (await req("/admin/audit?limit=20", { headers: adminAuth })).json()).entries;
  const actions = log.map((e) => e.action);
  assert.ok(actions.indexOf("clear group budget") >= 0 && actions.indexOf("clear group budget") < actions.indexOf("set group budget"), "newest first");
  assert.match(log[actions.indexOf("clear group budget")].target, /shared\.example/);
  assert.match(log[actions.indexOf("set group budget")].target, /shared\.example \$0\.02/);

  // The page offers the form that calls all of this.
  const { readFileSync } = await import("node:fs");
  const shell = await (await req("/admin", { headers: adminAuth })).text();
  const script = readFileSync(new URL("./pages/admin.js.txt", import.meta.url), "utf8");
  assert.match(shell, /<h2>Host budgets<\/h2>/);
  assert.ok(shell.includes('<input id="groupHost" aria-label="Provider host"'), "the host field is labelled");
  assert.ok(shell.includes('<input id="groupCap" type="number" min="0" step="0.01" aria-label="Budget in dollars"'));
  assert.ok(shell.includes('<p class="err" id="groupErr" role="alert" hidden>'), "errors are announced");
  assert.ok(script.includes('fetch("/admin/groups")'), "the page reads the budgets");
  assert.ok(script.includes('method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ host, capUsd })'));
  assert.ok(script.includes('if (!viewerMode) loadInvites()'), "a viewer does not load the owner-only cards");
});
test("an invite link buys one viewer passkey, once, and that passkey can only read", async () => {
  // The password stays on so the owner can ask for a link with the same credentials as the rest of the suite.
  env.ALLOW_PASSWORD = "true";
  const json = (path, body, headers = adminAuth) => req(path, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) });
  const auth = await authenticator();
  const created = await (await json("/admin/invites", { label: "Sam" })).json();
  assert.match(created.code, /^[0-9a-f]{32}$/);
  assert.equal(created.label, "Sam");
  assert.equal(created.url, `https://gw.example/join?code=${created.code}`);
  assert.ok(Date.parse(created.expires) > Date.now() + 23 * 3600e3, "the link lasts a day");
  const listed = await (await req("/admin/invites", { headers: adminAuth })).json();
  assert.equal(listed.length >= 1, true);
  assert.equal(listed[0].code, created.code, "the owner sees the link, because the owner is who sends it");
  assert.equal(listed[0].label, "Sam");
  assert.match(listed[0].url, /\/join\?code=[0-9a-f]{32}$/);

  // The invitee page needs no session, and neither does asking what the invite is for.
  const pageRes = await req("/join?code=" + created.code);
  assert.equal(pageRes.status, 200);
  assert.match(pageRes.headers.get("content-security-policy"), /script-src 'nonce-[0-9a-f]{32}'/);
  const page = await pageRes.text();
  assert.match(page, /<h1>Join KeyRouter<\/h1>/);
  assert.ok(page.includes('<label for="name">Name this passkey</label>'), "the name field is labelled");
  assert.ok(page.includes('<p class="err" id="err" role="alert"></p>'), "a failure is announced");
  const options = await (await req("/join/options", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: created.code }) })).json();
  assert.match(options.challenge, /^[\w-]{16,}$/);
  assert.deepEqual(options.rp, { id: "gw.example", name: "KeyRouter" });
  assert.equal(options.label, "Sam");
  // A wrong code and a made-up one say the same thing: there is nothing here to probe.
  const wrong = await json("/join/options", { code: "f".repeat(32) }, {});
  assert.equal(wrong.status, 404);
  assert.match((await wrong.json()).error.message, /not valid/);
  assert.equal((await req("/join/options", { method: "POST", headers: { "content-type": "text/plain" }, body: "{}" })).status, 415);

  // A registration the worker cannot trust is refused before the invite is spent.
  assert.equal((await req("/join/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: created.code, id: auth.id, alg: -99, publicKey: auth.spki, clientDataJSON: "e30" }) })).status, 400);
  assert.equal((await req("/join/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code: created.code, id: auth.id, alg: -7, publicKey: "AAAA", clientDataJSON: "e30" }) })).status, 400);
  // A body that is not JSON at all is refused the same way, and an unknown /join path is a 404.
  assert.equal((await req("/join/register", { method: "POST", headers: { "content-type": "application/json" }, body: "{" })).status, 404);
  assert.equal((await req("/join/nope", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 404);
  assert.equal((await req("/join", { method: "POST" })).status, 404);
  assert.equal((await req("/admin/groups", { method: "POST", headers: adminAuth, body: "{" })).status, 400);

  // Registering: the code has to be the one just minted, and the passkey it produces is a viewer.
  const registration = { code: created.code, id: auth.id, clientDataJSON: b64u(enc(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin: "https://gw.example" }))), publicKey: auth.spki, alg: -7, name: "Sam laptop" };
  const registered = await req("/join/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(registration) });
  assert.equal(registered.status, 200);
  assert.equal((await registered.json()).role, "viewer");
  const cookie = registered.headers.get("set-cookie");
  assert.match(cookie, /kr_session=/);

  // That session can read and cannot write, and the passkey behind it is a viewer for good.
  assert.equal((await req("/admin/keys", { headers: { cookie } })).status, 200);
  assert.equal((await req("/admin/export", { headers: { cookie } })).status, 403);
  assert.equal((await req("/admin/keys", { method: "POST", headers: { ...adminAuth, cookie, "content-type": "application/json" }, body: JSON.stringify({ base: "https://x.example", key: "k", expires: inAnHour }) })).status, 403);
  const stored = (await passkeysOf(env)).find((k) => k.id === auth.id);
  assert.equal(stored.role, "viewer");

  // Signing in with that passkey gives a viewer session too, not an owner one.
  const { challenge: fresh } = await (await req("/admin/login/options", { method: "POST" })).json();
  const signed = await req("/admin/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(await assertion(auth, fresh)) });
  assert.equal(signed.status, 200);
  const viewerCookie = signed.headers.get("set-cookie");
  assert.match(decodeURIComponent(viewerCookie), /viewer/, "the role is in the signed session");
  assert.equal((await req("/admin/export", { headers: { cookie: viewerCookie } })).status, 403);

  // The code is spent: a second registration with the same one is refused, and it is gone from the list.
  const again = await req("/join/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...registration, id: b64u(crypto.getRandomValues(new Uint8Array(20))) }) });
  assert.equal(again.status, 404);
  assert.equal((await (await req("/admin/invites", { headers: adminAuth })).json()).some((i) => i.code === created.code), false);

  // Cancelling one removes it, and a viewer may do neither.
  const second = await (await json("/admin/invites", { label: "Alex" })).json();
  assert.equal((await req("/admin/invites/" + second.code, { method: "DELETE", headers: { cookie } })).status, 403);
  assert.equal((await req("/admin/invites/" + second.code, { method: "DELETE", headers: adminAuth })).status, 200);
  assert.equal((await (await req("/admin/invites", { headers: adminAuth })).json()).some((i) => i.code === second.code), false);

  // Both the mint and the join are in the audit log, and the log names the person, not the code.
  const log = (await (await req("/admin/audit?limit=20", { headers: adminAuth })).json()).entries;
  const actions = log.map((e) => e.action);
  assert.equal(log[actions.indexOf("cancel invite")].role, "owner");
  assert.equal(log[actions.indexOf("invite viewer")].target, "Alex");
  assert.equal(log[actions.indexOf("joined as viewer")].role, "viewer");
  assert.equal(log[actions.indexOf("joined as viewer")].target, "Sam laptop");

  // The admin page offers the form, and hides it from the viewer who cannot use it.
  const { readFileSync } = await import("node:fs");
  const shell = await (await req("/admin", { headers: adminAuth })).text();
  const script = readFileSync(new URL("./pages/admin.js.txt", import.meta.url), "utf8");
  assert.match(shell, /<h2>Viewers<\/h2>/);
  assert.ok(shell.includes('<input id="inviteLabel" aria-label="Who the invite is for"'), "the field is labelled");
  assert.ok(shell.includes('<p class="err" id="inviteErr" role="alert" hidden>'), "an error is announced");
  assert.ok(script.includes('fetch("/admin/invites")'), "the page lists pending invites");
  assert.ok(script.includes('$("inviteLink").textContent = "Send this link: " + invite.url'), "the link is shown once");
  assert.ok(script.includes('if (!viewerMode) loadInvites()'), "a viewer never loads the invite card");

  // Leave the shared store as it was found: a passkey left behind would change every later sign-in test.
  assert.equal((await req("/admin/passkeys/" + auth.id, { method: "DELETE", headers: adminAuth })).status, 200);
  assert.equal((await passkeysOf(env)).some((k) => k.id === auth.id), false);
  env.ALLOW_PASSWORD = "true";
});
test("Gemini's streaming endpoint is metered from the last chunk, where it reports usage", async () => {
  env.ALLOW_QUERY_KEY = "true";
  const { id } = await (await create({ base: "https://g.example/v1beta", key: "k", expires: inAnHour, auth: "x-goog-api-key", capUsd: 5 })).json();
  // Gemini streams `data: {...}` lines and only the final chunk carries usageMetadata.
  const chunks = [
    { candidates: [{ content: { parts: [{ text: "Hel" }] } }], modelVersion: "gemini-4-carbon" },
    { candidates: [{ content: { parts: [{ text: "lo" }] } }], modelVersion: "gemini-4-carbon" },
    { candidates: [{ content: { parts: [{ text: "" }] }, finishReason: "STOP" }], usageMetadata: { promptTokenCount: 1200, candidatesTokenCount: 300, totalTokenCount: 1500 } },
  ];
  const sse = chunks.map((c) => `data: ${JSON.stringify(c)}\r\n\r\n`).join("");
  const upstream = () => new Response(sse, { headers: { "content-type": "text/event-stream" } });
  let status;
  try {
    await withUpstream(upstream, async () => {
      const res = await req(`/v1/models/gemini-4-carbon:streamGenerateContent?alt=sse&key=${id}`, { method: "POST", body: JSON.stringify({ contents: [] }) });
      status = res.status;
      assert.equal(await res.text(), sse, "the client gets every byte the provider sent");
      await Promise.all(pending.splice(0));
    });
    assert.equal(status, 200);
    env.ALLOW_QUERY_KEY = "true";
    const usage = await (await req("/usage", { headers: bearer(id) })).json();
    // 1200 input at $2 per million and 300 output at $10 per million, from the imported Gemini table.
    const expected = (1200 * 2 + 300 * 10) / 1e6;
    assert.ok(Math.abs(usage.used.usd - expected) < 1e-9, `spent ${usage.used.usd} rather than ${expected}`);
    assert.equal(usage.used.tokens, 1500);
    assert.equal(usage.breakdown[0].model, "gemini-4-carbon");
    assert.equal(usage.breakdown[0].requests, 1);
  } finally {
    delete env.ALLOW_QUERY_KEY;
  }
});
test("an Azure key builds the deployment path and the api-version, and a client cannot override the deployment", async () => {
  const azure = { base: "https://res.openai.azure.com", key: "az-secret", expires: inAnHour, auth: "api-key", azure: { deployment: "gpt5-prod" } };
  const { id } = await (await create(azure)).json();
  let hit;
  await withUpstream(replying({ ok: true }), async () => {
    hit = await req("/v1/chat/completions", { method: "POST", headers: { ...bearer(id), "content-type": "application/json" }, body: JSON.stringify({ model: "gpt-5" }) });
  });
  assert.equal(sent.url, "https://res.openai.azure.com/openai/deployments/gpt5-prod/chat/completions?api-version=2024-10-21");
  assert.equal(sent.init.headers.get("api-key"), "az-secret");
  assert.equal(sent.init.headers.get("authorization"), null, "the gateway key does not travel to the provider");
  assert.equal(hit.status, 200);
  // The client cannot move the call to another deployment: the path is the key's own, and only the version may be named.
  await withUpstream(replying({ ok: true }), async () => {
    await req("/v1/chat/completions", { method: "POST", headers: { ...bearer(id), "content-type": "application/json" }, body: JSON.stringify({ model: "gpt-5" }) });
  });
  const withVersion = await (await create({ ...azure, azure: { deployment: "gpt5-prod", apiVersion: "2025-01-01-preview" } })).json();
  await withUpstream(replying({ ok: true }), async () => {
    await req("/v1/chat/completions", { method: "POST", headers: { ...bearer(withVersion.id), "content-type": "application/json" }, body: "{}" });
  });
  assert.equal(sent.url, "https://res.openai.azure.com/openai/deployments/gpt5-prod/chat/completions?api-version=2025-01-01-preview");
  // A mismatched pairing is refused at creation, where the message can still be acted on.
  assert.equal((await create({ ...azure, base: "https://api.openai.com" })).status, 400);
  assert.equal((await create({ ...azure, base: "https://api.openai.com" })).headers.get("content-type").includes("json"), true);
});

test("Azure settings are validated: a deployment and an api-version are named or the key is refused", async () => {
  const bad = async (azure) => (await create({ base: "https://res.openai.azure.com", key: "k", expires: inAnHour, azure })).json();
  assert.match((await bad({ deployment: "has spaces" })).error.message, /deployment name/);
  assert.match((await bad({ deployment: "" })).error.message, /deployment name/);
  assert.match((await bad({ deployment: "ok", apiVersion: "latest" })).error.message, /api-version/);
  const good = await bad({ deployment: "ok", apiVersion: "2024-10-21-preview" });
  assert.equal(good.azure.apiVersion, "2024-10-21-preview");
  assert.equal((await bad({ deployment: "ok" })).azure.apiVersion, "2024-10-21");
});

test("a Bedrock key signs the request with the stored secret and never sends the gateway key", async () => {
  const aws = { region: "us-west-2", accessKeyId: "AKIDEXAMPLE12345678" };
  const { id } = await (await create({ base: "https://bedrock-runtime.us-west-2.amazonaws.com", key: "aws-secret-key", expires: inAnHour, aws })).json();
  const body = JSON.stringify({ anthropic_version: "bedrock-2023-05-31", max_tokens: 8, messages: [] });
  await withUpstream(replying({ output: {} }), async () => {
    await req("/v1/model/anthropic.claude-5-sonnet/invoke", { method: "POST", headers: bearer(id), body });
  });
  const auth = sent.init.headers.get("authorization");
  assert.match(auth, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE12345678\/\d{8}\/us-west-2\/bedrock\/aws4_request, SignedHeaders=/);
  assert.equal(auth.includes("aws-secret-key"), false);
  assert.equal(auth.includes(id), false);
  assert.match(sent.init.headers.get("x-amz-date"), /^\d{8}T\d{6}Z$/);
  // The signature covers the bytes actually sent, so a re-encoded body would not have verified at AWS.
  const { sha256Hex } = await import("./src/sigv4.js");
  assert.equal(sent.init.headers.get("x-amz-content-sha256"), await sha256Hex(body));
});

test("a Bedrock key is refused at creation unless it points at Amazon, and its settings are checked", async () => {
  const make = (extra) => create({ base: "https://bedrock-runtime.us-west-2.amazonaws.com", key: "k", expires: inAnHour, ...extra });
  assert.match((await (await make({ aws: { region: "us-west-2", accessKeyId: "AKIDEXAMPLE12345678" }, base: "https://api.anthropic.com" })).json()).error.message, /amazonaws/);
  assert.match((await (await make({ aws: { region: "us west", accessKeyId: "AKIDEXAMPLE12345678" } })).json()).error.message, /AWS region/);
  assert.match((await (await make({ aws: { region: "us-west-2", accessKeyId: "lower-case-key-id" } })).json()).error.message, /access key id/);
  const ok = await (await make({ aws: { region: "us-east-1", accessKeyId: "AKIDEXAMPLE12345678", sessionToken: " tok " } })).json();
  assert.deepEqual(ok.aws, { region: "us-east-1", service: "bedrock", accessKeyId: "AKIDEXAMPLE12345678", sessionToken: "tok" });
  // An edit re-checks the pairing, so a key cannot be pointed somewhere its signature would be a leaked secret.
  const moved = await req("/admin/keys/" + ok.id, { method: "PATCH", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ base: "https://example.com" }) });
  assert.equal(moved.status, 400);
});
test("the health check probes each provider host once a minute, and only a 5xx or a silence is down", async () => {
  await create({ base: "https://up.example", key: "k", expires: inAnHour });
  await create({ base: "https://down.example", key: "k", expires: inAnHour });
  // The store holds keys from earlier tests too, so the test does not assume which host is probed first: it makes
  // the first one fail and asserts the report names exactly that host.
  const seen = [];
  const probe = async (url) => {
    seen.push(String(url));
    return seen.length === 1 ? new Response("no", { status: 503 }) : new Response(null, { status: 401 });
  };
  const first = await withUpstream(probe, async () => (await req("/admin/health", { headers: adminAuth })).json());
  const hosts = first.checks.map((c) => c.host);
  assert.equal(seen.length, hosts.length, "one HEAD per distinct host, not one per key");
  assert.equal(new Set(hosts).size, hosts.length, "no host is probed twice");
  assert.ok(hosts.length >= 2 && hosts.length <= 5, `bounded to five hosts, saw ${hosts.length}`);
  assert.deepEqual(first.down, [hosts[0]], "only the host that answered 5xx is named down");
  // A 401 is the host answering, which is the question being asked.
  assert.equal(first.down.includes(hosts[1]), false);
  // Reloading the page within the minute reuses the stored answer instead of spending a subrequest per host.
  const second = await withUpstream(probe, async () => (await req("/admin/health", { headers: adminAuth })).json());
  assert.equal(seen.length, hosts.length, "a reload within the minute probes nothing");
  assert.equal(second.at, first.at);
  // An explicit refresh asks again, which is what the reader of a stale banner wants.
  await withUpstream(probe, async () => (await req("/admin/health?refresh=1", { headers: adminAuth })).json());
  assert.equal(seen.length, hosts.length * 2, "an explicit refresh asks every host again");
  // A provider that cannot be reached at all is down, and the reason is kept for the reader.
  const broken = await withUpstream(async () => { throw new Error("connection refused"); }, async () => (await req("/admin/health?refresh=1", { headers: adminAuth })).json());
  assert.equal(broken.down.length, hosts.length, "every host is down when none can be reached");
  assert.match(broken.checks[0].error, /connection refused/);
  assert.equal(broken.checks[0].status, 0);
});

test("the health check is readable by a viewer, and the admin page carries the banner it fills", async () => {
  env.VIEWER_PASSWORD = "look-only";
  try {
    const viewer = { authorization: "Basic " + btoa("someone:look-only") };
    await create({ base: "https://up.example", key: "k", expires: inAnHour });
    assert.equal((await withUpstream(async () => new Response(null, { status: 200 }), () => req("/admin/health", { headers: viewer }))).status, 200);
    const { readFileSync } = await import("node:fs");
    const html = readFileSync(new URL("./admin.html", import.meta.url), "utf8");
    const js = readFileSync(new URL("./pages/admin.js.txt", import.meta.url), "utf8");
    assert.match(html, /id="healthBanner" hidden/);
    assert.match(html, /id="healthText"/);
    assert.match(js, /async function loadHealth\(\)/);
    assert.match(js, /\$\("healthBanner"\)\.hidden = !down\.length/);
    assert.match(js, /loadReport\(\);\n    loadHealth\(\);/);
  } finally {
    delete env.VIEWER_PASSWORD;
  }
});
test("the request log is empty until it is switched on, and then holds one line per metered call", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  assert.deepEqual(await (await req("/admin/log", { headers: adminAuth })).json(), { enabled: false, entries: [], kept: 0 });
  // A call with the log off writes nothing at all, which is the promise the opt-in makes.
  await withUpstream(replying(opusCall), async () => {
    await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
    await Promise.all(pending.splice(0));
  });
  assert.deepEqual((await (await req("/admin/log", { headers: adminAuth })).json()).entries, []);
  env.REQUEST_LOG = "true";
  try {
    await withUpstream(replying(opusCall), async () => {
      await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
      await Promise.all(pending.splice(0));
    });
    const log = await (await req("/admin/log?limit=10", { headers: adminAuth })).json();
    assert.equal(log.enabled, true);
    assert.equal(log.entries.length, 1);
    const [entry] = log.entries;
    assert.equal(entry.key, id.slice(0, 13));
    assert.equal(entry.model, "claude-opus-5-5");
    assert.equal(entry.status, 200);
    assert.equal(entry.tokens, 1500);
    assert.equal(typeof entry.ms, "number");
    assert.ok(entry.cost_usd > 0);
    // A log line names the call, not its content: these are all the fields there are.
    assert.deepEqual(Object.keys(entry).sort(), ["at", "cost_usd", "key", "model", "ms", "status", "tokens"]);
    // A listing is logged too, with no token count, because it never reaches the meter.
    await withUpstream(replying({ data: [] }), async () => {
      await req("/v1/models", { headers: bearer(id) });
      await Promise.all(pending.splice(0));
    });
    const after = await (await req("/admin/log?limit=10", { headers: adminAuth })).json();
    assert.equal(after.entries.length, 2);
    assert.deepEqual([after.entries[0].status, after.entries[0].tokens, after.entries[0].model], [200, null, null]);
    // A provider that cannot be reached is in the log as a 502, which is what a monitor should see.
    await withUpstream(async () => { throw new Error("boom"); }, async () => {
      await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
      await Promise.all(pending.splice(0));
    });
    const failed = await (await req("/admin/log?limit=1", { headers: adminAuth })).json();
    assert.equal(failed.entries[0].status, 502);
  } finally {
    delete env.REQUEST_LOG;
  }
});

test("the log is a ring of 500 that forgets anything older than a week", async () => {
  // Its own environment: the ring is the point, so it must not count entries other tests left behind.
  const { requestLog } = await import("./src/log.js");
  const { adminStore } = await import("./src/auth.js");
  const { env: own } = (await import("./scripts/harness.mjs")).makeEnv({ ADMIN_PASSWORD: "pw", ENCRYPTION_KEY: "x".repeat(32) });
  await requestLog(own, { at: Date.now() - 8 * 864e5, key: "stale", status: 200, ms: 1 });
  for (let i = 0; i < 505; i++) await requestLog(own, { at: Date.now(), key: "k" + i, status: 200, ms: 1 });
  const { entries, kept } = await (await adminStore(own, "/log", { get: 500 })).json();
  assert.equal(kept, 500, "the ring keeps 500 and drops the rest");
  assert.equal(entries.some((e) => e.key === "stale"), false, "an entry older than a week is gone");
  assert.equal(entries[0].key, "k504", "newest first, so the reader can take the tail");
  // The reader asks for a window and gets at most that many, never the whole ring by default.
  assert.equal((await (await adminStore(own, "/log", { get: 3 })).json()).entries.length, 3);
});

test("/metrics is Prometheus text derived from the log, and says so when the log is off", async () => {
  // Its own environment, so the counts are exactly the ones this test writes.
  const { requestLog } = await import("./src/log.js");
  const { env: own } = (await import("./scripts/harness.mjs")).makeEnv({ ADMIN_PASSWORD: "pw", ENCRYPTION_KEY: "x".repeat(32), REQUEST_LOG: "true" });
  const scrape = async () => (await worker.fetch(new Request("https://gw.example/metrics", { headers: { ...adminAuth, "cf-connecting-ip": "127.0.0.1" } }), own, ctx)).text();
  const now = Date.now();
  await requestLog(own, { at: now, key: "a", status: 200, ms: 5 });
  await requestLog(own, { at: now, key: "a", status: 200, ms: 5 });
  await requestLog(own, { at: now, key: "a", status: 404, ms: 5 });
  await requestLog(own, { at: now, key: "a", status: 500, ms: 5 });
  await requestLog(own, { at: now, key: "a", status: 429, event: "refused", ms: 5 });
  await requestLog(own, { at: now, key: "a", status: 200, event: "downgraded", ms: 5 });
  const text = await scrape();
  assert.match(text, /^# HELP keyrouter_requests_total/m);
  assert.match(text, /keyrouter_log_enabled 1/);
  assert.match(text, /keyrouter_requests_total 6/);
  assert.match(text, /keyrouter_responses_total\{class="2xx"\} 2/);
  assert.match(text, /keyrouter_responses_total\{class="4xx"\} 1/);
  assert.match(text, /keyrouter_responses_total\{class="5xx"\} 1/);
  assert.match(text, /keyrouter_refused_total 1/);
  assert.match(text, /keyrouter_downgraded_total 1/);
  assert.match(text, /keyrouter_admit_refusal_rate 0\.1667/);
  assert.match(text, /keyrouter_downgrade_rate 0\.1667/);
  // The latency histogram: all six calls took 5 ms, so every bucket from 5 up holds six and the ones below hold none.
  assert.match(text, /^# TYPE keyrouter_request_ms histogram$/m);
  assert.match(text, /keyrouter_request_ms_bucket\{le="1"\} 0/);
  assert.match(text, /keyrouter_request_ms_bucket\{le="5"\} 6/);
  assert.match(text, /keyrouter_request_ms_bucket\{le="50"\} 6/);
  assert.match(text, /keyrouter_request_ms_bucket\{le="\+Inf"\} 6/);
  assert.match(text, /keyrouter_request_ms_sum 30/);
  assert.match(text, /keyrouter_request_ms_count 6/);
  // With the log off there is nothing to derive, and the endpoint says that rather than reporting zeroes as truth.
  delete own.REQUEST_LOG;
  const off = await scrape();
  assert.match(off, /keyrouter_log_enabled 0/);
  assert.match(off, /keyrouter_requests_total 0/);
});

test("a call is stamped with the price table that charged it, and editing prices never rewrites past spend", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const call = () => withUpstream(replying(opusCall), async () => {
    await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
    await Promise.all(pending.splice(0));
  });
  const v0 = (await (await req("/admin/prices", { headers: adminAuth })).json()).version;
  await call();
  const before = (await (await req("/usage", { headers: bearer(id) })).json()).breakdown[0];
  assert.equal(before.price_version, v0, "the row names the table that charged it");
  const beforeCost = before.cost;
  // Halve the output rate and save, which mints a new version stamp.
  const table = (await (await req("/admin/prices", { headers: adminAuth })).json()).prices;
  const halved = table.map((r) => (String(r.match).includes("opus") ? { ...r, out: r.out / 2 } : r));
  const put = await req("/admin/prices", { method: "PUT", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ prices: halved }) });
  assert.equal(put.status, 200);
  const version = (await put.json()).version;
  assert.match(version, /^[0-9a-f]{16}$/);
  assert.notEqual(version, v0, "saving mints a new stamp");
  await call();
  const after = (await (await req("/usage", { headers: bearer(id) })).json()).breakdown[0];
  assert.equal(after.price_version, version, "new calls carry the new stamp");
  assert.equal(after.requests, 2);
  // The first call is still charged at the price it was made at: only the second one is cheaper.
  assert.ok(after.cost > beforeCost, "the total still holds both calls");
  assert.ok(after.cost < beforeCost * 2, "the second call cost less than the first");
  // The prices endpoint says which table is live, which is what an operator compares a stamp against.
  assert.equal((await (await req("/admin/prices", { headers: adminAuth })).json()).version, version);
  // Put the shipped table back: this test shares one environment with the rest of the file.
  await req("/admin/prices", { method: "PUT", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ prices: table }) });
  assert.equal((await (await req("/admin/prices", { headers: adminAuth })).json()).version === version, false, "restoring mints its own stamp");
});

test("cache tokens are accounted for per provider: read, five-minute write and one-hour write", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const rows = (await (await req("/admin/prices", { headers: adminAuth })).json()).prices;
  const rate = (match) => rows.find((r) => r.match === match);
  const send = (payload) => withUpstream(replying(payload), async () => {
    await req("/v1/chat/completions", { method: "POST", headers: bearer(id), body: "{}" });
    await Promise.all(pending.splice(0));
  });
  // Anthropic: 1M fresh, 1M cache reads, and 2M cache writes of which 1M lasts an hour.
  await send({ model: "claude-sonnet-5-5", usage: { input_tokens: 1e6, cache_read_input_tokens: 1e6, cache_creation_input_tokens: 2e6, cache_creation: { ephemeral_1h_input_tokens: 1e6 } } });
  // OpenAI: 2M prompt tokens, of which 1M came from the cache. No OpenAI row ships in the table yet, so this call
  // is counted exactly and flagged unpriced, which is what the page would show an operator.
  await send({ model: "gpt-5", usage: { prompt_tokens: 2e6, completion_tokens: 0, prompt_tokens_details: { cached_tokens: 1e6 } } });
  // Gemini: 2M prompt tokens counting 1M cached.
  await send({ model: "gemini-4-carbon", usageMetadata: { promptTokenCount: 2e6, candidatesTokenCount: 0, cachedContentTokenCount: 1e6 } });
  const shown = (await (await req("/usage", { headers: bearer(id) })).json()).breakdown;
  const row = (m) => shown.find((r) => r.model === m);
  const sonnet = rate("claude-sonnet-5-5");
  const expectedSonnet = (1e6 * sonnet.in + 1e6 * sonnet.read + 1e6 * sonnet.write5m + 1e6 * sonnet.write1h) / 1e6;
  assert.ok(Math.abs(row("claude-sonnet-5-5").cost - expectedSonnet) < 1e-9, `sonnet ${row("claude-sonnet-5-5").cost} rather than ${expectedSonnet}`);
  const gem = rate("gemini-4-carbon");
  const expectedGemini = (1e6 * gem.in + 1e6 * gem.read) / 1e6;
  assert.ok(Math.abs(row("gemini-4-carbon").cost - expectedGemini) < 1e-9, `gemini ${row("gemini-4-carbon").cost}`);
  // The counts add up to what each provider reported, so the usage page and the bill agree on volume.
  assert.deepEqual([row("claude-sonnet-5-5").input, row("claude-sonnet-5-5").output], [4e6, 0]);
  assert.deepEqual([row("gpt-5").input, row("gpt-5").priced], [2e6, false], "cached tokens are split out even when unpriced");
  assert.deepEqual([row("gemini-4-carbon").input, row("gemini-4-carbon").output], [2e6, 0]);
});

test("a long-context multiplier starts above the threshold, not at it, and only on models that have one", async () => {
  const { cost } = await import("./src/pricing.js");
  const usage = (n) => ({ input_tokens: n, output_tokens: 0 });
  // The only family with a threshold in the shipped table is haiku, which multiplies by five above 100k.
  const at = cost("claude-haiku-5-5", usage(100_000));
  const past = cost("claude-haiku-5-5", usage(100_001));
  assert.ok(Math.abs(at - (100_000 * 0.1) / 1e6) < 1e-12, `at the boundary: ${at}`);
  assert.ok(Math.abs(past - (100_001 * 0.1 * 5) / 1e6) < 1e-9, `one past the boundary: ${past}`);
  // A model without a threshold is linear all the way up.
  const plain = cost("claude-sonnet-5-5", usage(100_001));
  assert.ok(Math.abs(plain - (100_001 * 2) / 1e6) < 1e-12, `no threshold: ${plain}`);
  // The multiplier stacks with the cache rates rather than replacing them: a cached token is also scaled.
  const cached = cost("claude-haiku-5-5", { input_tokens: 0, cache_read_input_tokens: 100_001, output_tokens: 0 });
  assert.ok(Math.abs(cached - (100_001 * 0.01 * 5) / 1e6) < 1e-9, `cached and long: ${cached}`);
  // The threshold counts fresh input, cache reads and cache writes together, which is how providers bill it.
  const split = cost("claude-haiku-5-5", { input_tokens: 60_000, cache_read_input_tokens: 40_001, output_tokens: 0 });
  assert.ok(Math.abs(split - (60_000 * 0.1 * 5 + 40_001 * 0.01 * 5) / 1e6) < 1e-9, `split and long: ${split}`);
});

test("the gates run in a fixed order, and the first one that fails is the one the client hears about", async () => {
  // Every key below fails more than one gate on purpose; the assertion is which message wins.
  // 1. An unknown key is refused before anything about its address, hours or model is considered.
  const unknown = await req("/v1/messages", { method: "POST", headers: bearer("sk-gw-" + "0".repeat(32)), body: "{}" });
  assert.equal(unknown.status, 401);
  assert.match((await unknown.json()).error.message, /invalid or expired key/);
  // 2. Expiry comes before the address allowlist, so an expired key cannot probe which addresses are allowed.
  const expiring = await (await create({ base: "https://x.example", key: "k", expires: "2027-01-01T00:00:00.000Z", ips: ["10.0.0.0/8"], models: ["nope"] })).json();
  const RealDate = globalThis.Date;
  const at = (iso) => {
    const fixed = RealDate.parse(iso);
    class FakeDate extends RealDate {
      constructor(...args) { if (args.length) super(...args); else super(fixed); }
      static now() { return fixed; }
    }
    globalThis.Date = FakeDate;
  };
  try {
    at("2028-01-01T00:00:00.000Z");
    const expired = await req("/v1/messages", { method: "POST", headers: bearer(expiring.id), body: "{}" });
    assert.equal(expired.status, 401, "an expired key is 401 even from a disallowed address");
    assert.match((await expired.json()).error.message, /invalid or expired key/);
  } finally {
    globalThis.Date = RealDate;
  }
  // 3. The address allowlist comes before hours and the model allowlist.
  const wrongAddress = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, ips: ["203.0.113.9"], models: ["nope"], capUsd: 1 })).json();
  const refusedIp = await req("/v1/messages", { method: "POST", headers: bearer(wrongAddress.id), body: JSON.stringify({ model: "nope" }) });
  assert.equal(refusedIp.status, 403);
  assert.match((await refusedIp.json()).error.message, /cannot be used from 127\.0\.0\.1/);
  // 4. Hours come before the model allowlist and before the cap.
  const nowHour = new Date().getUTCHours();
  if (nowHour !== 0) {
    const closed = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, hours: { days: [0, 1, 2, 3, 4, 5, 6], start: "00:00", end: "00:01", tz: "UTC" }, models: ["nope"], capUsd: 1 })).json();
    const outOfHours = await req("/v1/messages", { method: "POST", headers: bearer(closed.id), body: JSON.stringify({ model: "nope" }) });
    assert.equal(outOfHours.status, 403);
    assert.match((await outOfHours.json()).error.message, /only works .* 00:00-00:01/);
  }
  // 5. The model allowlist comes before the cap: a refused model never spends, so it cannot be a 429.
  const capped = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, models: ["allowed-model"], capUsd: 0.0001 })).json();
  const wrongModel = await req("/v1/messages", { method: "POST", headers: bearer(capped.id), body: JSON.stringify({ model: "other-model" }) });
  assert.equal(wrongModel.status, 403);
  assert.match((await wrongModel.json()).error.message, /is not allowed for this key/);
  // 6. With the model allowed, the cap is the next gate.
  await withUpstream(replying(opusCall), async () => {
    await req("/v1/messages", { method: "POST", headers: bearer(capped.id), body: JSON.stringify({ model: "allowed-model", max_tokens: 5 }) });
    await Promise.all(pending.splice(0));
  });
  const stopped = await req("/v1/messages", { method: "POST", headers: bearer(capped.id), body: JSON.stringify({ model: "allowed-model" }) });
  assert.equal(stopped.status, 429);
  assert.match((await stopped.json()).error.message, /spend cap/);
});

test("the rate limit admits exactly rpm calls in a minute and refuses the next one", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, rpm: 3 })).json();
  const statuses = [];
  for (let i = 0; i < 4; i++) statuses.push((await req("/v1/models", { headers: bearer(id) })).status);
  assert.deepEqual(statuses, [200, 200, 200, 429], "the fourth call in the window is the first refusal");
  const refused = await req("/v1/models", { headers: bearer(id) });
  assert.match((await refused.json()).error.message, /rate limit reached \(3 per minute\)/);
  assert.equal(refused.headers.get("retry-after"), "60");
});

test("a downgrade rule chain applies one hop only, and the header names the hop that was applied", async () => {
  const map = [["claude-opus-5-5", "claude-sonnet-5-5"], ["claude-sonnet-5-5", "claude-haiku-4-5"]];
  // A cent of a twenty-cent cap is one percent, which the first call crosses.
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.2, downgrade: { at: 1, map } })).json();
  const call = (model) => withUpstream(replying({ model: "claude-opus-5-5", usage: { input_tokens: 1000, output_tokens: 1 } }), async () => {
    const res = await req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model }) });
    await Promise.all(pending.splice(0));
    return res;
  });
  await call("claude-opus-5-5");
  // "opus" matches the first rule and becomes "sonnet"; the second rule must not then fire on the result.
  const second = await call("claude-opus-5-5");
  assert.equal(second.headers.get("x-gateway-downgrade"), "claude-opus-5-5 -> claude-sonnet-5-5");
  const bodyOf = () => JSON.parse(typeof sent.init.body === "string" ? sent.init.body : new TextDecoder().decode(sent.init.body));
  assert.equal(bodyOf().model, "claude-sonnet-5-5", "one hop, not a walk down the chain");
  // A model that matches no rule is passed through untouched and carries no header.
  const third = await withUpstream(replying(opusCall), async () => {
    const res = await req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model: "gemini-4-carbon" }) });
    await Promise.all(pending.splice(0));
    return res;
  });
  assert.equal(third.headers.get("x-gateway-downgrade"), null);
  assert.equal(bodyOf().model, "gemini-4-carbon");
});
test("a monthly cap resets at UTC midnight on the first, including a request made at 23:59:59", async () => {
  // The clock is replaced for the span of this test, because the rollover is a calendar boundary and nothing else.
  const RealDate = globalThis.Date;
  const at = (iso) => {
    const fixed = RealDate.parse(iso);
    class FakeDate extends RealDate {
      constructor(...args) {
        if (args.length) super(...args);
        else super(fixed);
      }
      static now() { return fixed; }
    }
    globalThis.Date = FakeDate;
  };
  try {
    at("2026-01-31T23:59:59.000Z");
    const { id } = await (await create({ base: "https://x.example", key: "k", expires: "2027-01-01T00:00:00.000Z", capUsd: 0.01, period: "month" })).json();
    const call = () => withUpstream(replying(opusCall), async () => {
      const res = await req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" });
      await Promise.all(pending.splice(0));
      return res;
    });
    assert.equal((await call()).status, 200);
    // The cap is spent, and the key says when it comes back: the first instant of the next month.
    const before = await (await req("/usage", { headers: bearer(id) })).json();
    assert.equal(before.over_cap, true);
    assert.equal(before.reset, "2026-02-01T00:00:00.000Z");
    assert.equal((await call()).status, 429);
    // A second later the month has rolled: the same key is admitted again, and the reset date moves on.
    at("2026-02-01T00:00:00.000Z");
    assert.equal((await call()).status, 200);
    const after = await (await req("/usage", { headers: bearer(id) })).json();
    assert.equal(after.reset, "2026-03-01T00:00:00.000Z");
    assert.ok(after.spent_usd < before.spent_usd * 2, "the new month starts from zero");
    // The old month is still there, so nothing was lost by rolling over.
    const months = (await (await req("/admin/keys/" + id, { headers: adminAuth })).json()).usage.months;
    assert.deepEqual(Object.keys(months).sort(), ["2026-01", "2026-02"]);
  } finally {
    globalThis.Date = RealDate;
  }
});

test("a provider 5xx becomes one 502 body, is tried once, and bills nothing", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1 })).json();
  let calls = 0;
  const failing = async () => { calls++; return new Response("<html>internal error, trace 8f2a</html>", { status: 500, headers: { "content-type": "text/html" } }); };
  const res = await withUpstream(failing, () => req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model: "claude-opus-5-5" }) }));
  assert.equal(res.status, 502, "a provider fault is a gateway error, not a pass-through");
  assert.deepEqual(await res.json(), { error: { message: "the provider failed (500); nothing was counted" } }, "the gateway answers in its own words, so the provider page is not echoed");
  assert.equal(calls, 1, "a POST is never retried, because it may already have been charged for");
  await Promise.all(pending.splice(0));
  const usage = await (await req("/usage", { headers: bearer(id) })).json();
  assert.equal(usage.spent_usd, 0, "an error body carries no token count, so nothing is billed");
  assert.equal(usage.requests ?? 0, 0, "and no request is recorded either");
  assert.deepEqual(usage.breakdown, [], "nothing appears in the per-model table");
  // A provider that cannot be reached at all is the same shape, with the transport reason kept.
  const broken = await withUpstream(async () => { throw new Error("connection timed out"); }, () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  assert.equal(broken.status, 502);
  assert.match((await broken.json()).error.message, /^upstream unreachable: connection timed out$/);
});

test("a stream that breaks mid-answer is still billed once, whether the provider or the client hung up", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1 })).json();
  const head = 'event: message_start\ndata: {"type":"message_start","message":{"model":"claude-sonnet-5-5","usage":{"input_tokens":2000}}}\n\n';
  const use = 'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":250}}\n\n';
  // The provider sends the counts and then dies before the stream ends.
  // The two event chunks are delivered, and the third pull fails: a real disconnect after the counts arrived.
  const dies = () => new Response(new ReadableStream({
    pull(c) {
      const b = new TextEncoder();
      if ((dies.n = (dies.n ?? 0) + 1) === 1) c.enqueue(b.encode(head));
      else if (dies.n === 2) c.enqueue(b.encode(use));
      else c.error(new Error("provider hung up"));
    },
  }), { headers: { "content-type": "text/event-stream" } });
  const first = await withUpstream(dies, () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  await first.text().catch(() => "the client saw the stream break, which is the point");
  await Promise.all(pending.splice(0));
  const one = (await keyInfo(id)).usage.total["claude-sonnet-5-5"];
  assert.equal(one.requests, 1, "the broken stream is billed once, not twice and not never");
  assert.equal(one.input, 2000, "what did arrive is counted");
  // The client hanging up does not lose it either: the metered copy keeps reading to the end.
  const ok = () => new Response(new ReadableStream({
    start(c) {
      const b = new TextEncoder();
      c.enqueue(b.encode(head));
      c.enqueue(b.encode(use));
      c.close();
    },
  }), { headers: { "content-type": "text/event-stream" } });
  // The reader takes one chunk and walks away; the metered copy is not its business and keeps reading.
  const second = await withUpstream(ok, () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  const reader = second.body.getReader();
  await reader.read();
  await reader.cancel();
  await Promise.all(pending.splice(0));
  const two = (await keyInfo(id)).usage.total["claude-sonnet-5-5"];
  assert.equal(two.requests, 2, "the abandoned stream was billed as well, and only once");
  assert.equal(two.input, 4000, "the counts that arrived before the client left are kept");
});

test("when the meter cannot be reached a capped call is refused 503 instead of being admitted", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 5 })).json();
  const realGet = env.METER.get;
  env.METER.get = () => { throw new Error("Durable Object unavailable"); };
  try {
    const res = await withUpstream(replying(opusCall), () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
    assert.equal(res.status, 503, "the cap cannot be checked, so the call is not admitted");
    assert.match((await res.json()).error.message, /meter is unavailable/);
    assert.equal(res.headers.get("retry-after"), "30");
  } finally {
    env.METER.get = realGet;
  }
  // An uncapped key does not consult the meter to admit, so it keeps working while the meter is down.
  const free = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  env.METER.get = () => { throw new Error("Durable Object unavailable"); };
  try {
    const res = await withUpstream(replying(opusCall), () => req("/v1/messages", { method: "POST", headers: bearer(free.id), body: "{}" }));
    assert.equal(res.status, 200, "with no cap to enforce, an outage is not a refusal");
  } finally {
    env.METER.get = realGet;
    await Promise.all(pending.splice(0));
  }
});

test("a key that is missing from the KV store answers exactly like an unknown one", async () => {
  // 32 hex characters is the shape of a real id, so a miss here cannot be told apart from a made-up token.
  const absent = "sk-gw-" + "0123456789abcdef".repeat(2);
  const nonsense = "sk-gw-" + "zzzz";
  const a = await req("/v1/models", { headers: bearer(absent) });
  const b = await req("/v1/models", { headers: bearer(nonsense) });
  assert.equal(a.status, b.status, "same status");
  assert.equal(a.status, 401);
  assert.deepEqual(await a.json(), await b.json(), "same body, so there is no enumeration oracle");
  assert.equal(a.headers.get("cache-control"), b.headers.get("cache-control"), "and the same cache advice");
  // The same is true of a key that existed and was deleted, which is the case a probe would try.
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  await req("/admin/keys/" + id, { method: "DELETE", headers: adminAuth });
  const revoked = await req("/v1/models", { headers: bearer(id) });
  assert.equal(revoked.status, 401);
  assert.deepEqual(await revoked.json(), { error: { message: "invalid or expired key" } }, "a revoked key says the same thing as a made-up one");
});
test("every page and asset carries the same hardening headers", async () => {
  // The signed-out pages still answer the session gate, so they are asked with a session: the headers are the point here.
  // `/usage` reads a bearer key and `/join` is unsigned-in by design, so those two are asked without the session.
  const { id: shared } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const { url: shareUrl } = await (await req("/admin/keys/" + shared + "/share", { method: "POST", headers: { ...adminAuth, "content-type": "application/json" }, body: JSON.stringify({ expires: inAnHour }) })).json();
  const sharePath = new URL(shareUrl).pathname;
  const pages = [["/admin", adminAuth], ["/usage", undefined], ["/join", undefined], [sharePath, undefined], ["/admin/admin.js", adminAuth], ["/admin/admin.css", adminAuth]];
  for (const [path, headers] of pages) {
    const res = await req(path, { headers });
    assert.equal(res.status, 200, path);
    assert.equal(res.headers.get("strict-transport-security"), "max-age=15552000; includeSubDomains", `${path} pins HTTPS`);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff", `${path} is not sniffed`);
    assert.equal(res.headers.get("x-frame-options"), "DENY", `${path} cannot be framed`);
    assert.equal(res.headers.get("referrer-policy"), "no-referrer", `${path} leaks no referrer`);
    assert.match(res.headers.get("permissions-policy"), /camera=\(\)/, `${path} refuses the camera`);
    assert.match(res.headers.get("content-security-policy"), /default-src .none./, `${path} starts from nothing`);
  }
  // The policy differs by page kind, and neither kind allows inline code without the nonce on the tag it stamped.
  assert.match((await req("/admin", { headers: adminAuth })).headers.get("content-security-policy"), /script-src 'self'/);
  const usage = await req("/usage");
  const nonce = /script-src 'nonce-([0-9a-f]+)'/.exec(usage.headers.get("content-security-policy"))?.[1];
  assert.ok(nonce, "the inline page names a nonce");
  assert.ok((await usage.text()).includes(`nonce="${nonce}"`), "and every inline tag carries it");
});

test("a key id is a 128-bit capability, and a miss does not answer measurably slower than a hit", async () => {
  const { newId } = await import("./src/crypto.js");
  // 5,000 ids: no collision, and every one is 32 hex characters (128 bits) from the platform CSPRNG.
  const ids = Array.from({ length: 5000 }, () => newId());
  assert.equal(new Set(ids).size, 5000, "no two ids collide");
  assert.ok(ids.every((id) => /^sk-gw-[0-9a-f]{32}$/.test(id)), "every id is 128 bits of hex");
  assert.equal(ids[0].length, "sk-gw-".length + 32);
  // A lookup is by exact KV name, so a hit and a miss do the same work up to one read. No JavaScript test can prove
  // constant time; this one refuses an obvious early-exit oracle, where a miss answers orders of magnitude faster.
  const live = (await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json()).id;
  const absent = "sk-gw-" + "f".repeat(32);
  const time = async (token) => {
    const started = performance.now();
    await req("/v1/models", { headers: bearer(token) });
    return performance.now() - started;
  };
  const median = (xs) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)];
  await time(live);
  await time(absent);
  const hits = [];
  const misses = [];
  for (let i = 0; i < 60; i++) {
    hits.push(await time(live));
    misses.push(await time(absent));
  }
  const ratio = median(hits) / Math.max(median(misses), 0.001);
  assert.ok(ratio > 0.2 && ratio < 20, `hit and miss look alike (${ratio.toFixed(2)}x), so the answer is not the timing`);
});

test("ENCRYPTION_KEY can be rotated: every stored key is re-sealed and verified, and a wrong old passphrase changes nothing", async () => {
  // Its own store, so the count is the three keys this test made and not every key the suite has created.
  const { env: own } = (await import("./scripts/harness.mjs")).makeEnv({});
  const ownAuth = { authorization: "Basic " + btoa("admin:pw"), "content-type": "application/json" };
  const made = [];
  for (let i = 0; i < 3; i++) {
    const res = await worker.fetch(new Request("https://gw.example/admin/keys", { method: "POST", headers: ownAuth, body: JSON.stringify({ base: "https://x.example", key: "provider-secret-" + i, expires: new Date(Date.now() + 3600e3).toISOString() }) }), own, { waitUntil() {} });
    made.push((await res.json()).id);
  }
  const reseal = (body) => worker.fetch(new Request("https://gw.example/admin/reseal", { method: "POST", headers: ownAuth, body: JSON.stringify(body) }), own, { waitUntil() {} });
  // A wrong old passphrase re-seals nothing and leaves the rows readable under the key they already had.
  const wrong = await (await reseal({ from: "not-the-key", to: "a-much-longer-replacement-passphrase" })).json();
  assert.equal(wrong.resealed, 0);
  assert.equal(wrong.failed.length, 3, "every row is reported as unreadable under the wrong passphrase");
  assert.ok((await (await reseal({ from: "not-the-key", to: "short" })).json()).error, "a too-short new passphrase is refused before anything is touched");
  // The real rotation.
  const next = "a-much-longer-replacement-passphrase";
  const done = await (await reseal({ from: own.ENCRYPTION_KEY, to: next })).json();
  assert.deepEqual([done.resealed, done.failed.length, done.skipped], [3, 0, 0]);
  // The deployment now has to use the new secret, and the secret inside every row is unchanged.
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async () => { seen.push(1); return new Response(JSON.stringify({ data: [] }), { headers: { "content-type": "application/json" } }); };
  try {
    own.ENCRYPTION_KEY = "the-old-one";
    const broken = await worker.fetch(new Request("https://gw.example/v1/models", { headers: { authorization: "Bearer " + made[0] } }), own, { waitUntil() {} });
    assert.equal(broken.status, 500, "the old secret no longer opens the rows");
    own.ENCRYPTION_KEY = next;
    for (const id of made) {
      const res = await worker.fetch(new Request("https://gw.example/v1/models", { headers: { authorization: "Bearer " + id } }), own, { waitUntil() {} });
      assert.equal(res.status, 200);
    }
    assert.equal(seen.length, 3, "all three keys reached the provider under the new secret");
  } finally {
    globalThis.fetch = real;
  }
  // The audit log names the action and never the secret.
  const audited = await (await worker.fetch(new Request("https://gw.example/admin/audit?limit=5", { headers: ownAuth }), own, { waitUntil() {} })).json();
  assert.ok(audited.entries.some((e) => e.action === "reseal keys" && e.target === "3 re-sealed, 0 failed"));
  assert.ok(!JSON.stringify(audited).includes(next), "the audit log names the action, not the passphrase");
});
test("/status answers a monitor without a session, with the deploy time, the version and provider reachability", async () => {
  const { env: own } = (await import("./scripts/harness.mjs")).makeEnv({ BUILD: "2026-11-25T10:00:00.000Z:abc1234" });
  const ownAuth = { authorization: "Basic " + btoa("admin:pw"), "content-type": "application/json" };
  await worker.fetch(new Request("https://gw.example/admin/keys", { method: "POST", headers: ownAuth, body: JSON.stringify({ base: "https://api.example", key: "sk-provider-secret", expires: new Date(Date.now() + 3600e3).toISOString(), label: "a-label" }) }), own, { waitUntil() {} });
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => (String(url).includes("api.example") ? new Response(null, { status: 401 }) : new Response(null, { status: 503 }));
  let doc;
  try {
    const res = await worker.fetch(new Request("https://gw.example/status"), own, { waitUntil() {} });
    assert.equal(res.status, 200, "no session is needed, because a monitor has none");
    assert.equal(res.headers.get("cache-control"), "no-store");
    doc = await res.json();
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(doc.ok, true);
  assert.equal(doc.deployed_at, "2026-11-25T10:00:00.000Z", "the deploy time from the BUILD var, not the request time");
  assert.equal(doc.version, "abc1234", "the short sha of that deploy");
  assert.deepEqual(doc.providers, [{ host: "api.example", up: true, ms: doc.providers[0].ms }], "a 401 from a host means the host is up");
  assert.deepEqual(doc.down, []);
  assert.ok(doc.checked_at, "and when the probe ran");
  // The document is public, so it must not carry anything that is not already public.
  const text = JSON.stringify(doc);
  assert.ok(!text.includes("sk-provider-secret"), "no provider key");
  assert.ok(!text.includes("a-label"), "no key label");
  assert.ok(!text.includes("sk-gw-"), "no gateway key id");
  // Without BUILD the deploy time is honestly unknown rather than invented.
  const { env: bare } = (await import("./scripts/harness.mjs")).makeEnv({});
  const plain = await (await worker.fetch(new Request("https://gw.example/status"), bare, { waitUntil() {} })).json();
  assert.equal(plain.deployed_at, null);
  assert.equal(plain.version, null);
});

test("batch create and paged listing", async () => {
  const res = await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "team", count: 20 });
  const { keys } = await res.json();
  assert.deepEqual(keys.slice(0, 3).map((k) => k.label), ["team 1", "team 2", "team 3"]);
  assert.equal(new Set(keys.map((k) => k.id)).size, 20);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, count: 21 })).status, 400);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, count: 0 })).status, 400);

  const first = await (await req("/admin/keys", { headers: adminAuth })).json();
  assert.equal(first.keys.length, 20);
  assert.ok(first.cursor);
  const all = await listAll();
  assert.ok(keys.every((k) => all.some((l) => l.id === k.id)));
  assert.equal(all.find((l) => l.id === keys[0].id).limits, "none");
});

test("downgrade reroutes only new requests once a cap passes the threshold", async () => {
  const downgrade = { at: 50, map: [["claude-opus-*", "claude-sonnet-5-5"]] };
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 0.02, downgrade })).json();
  const call = (model) => req("/v1/messages", { method: "POST", headers: bearer(id), body: JSON.stringify({ model, max_tokens: 10 }) });
  const sentModel = () => JSON.parse(typeof sent.init.body === "string" ? sent.init.body : new TextDecoder().decode(sent.init.body)).model;
  let res = await withUpstream(replying(opusCall), () => call("claude-opus-5-5"));
  assert.equal(sentModel(), "claude-opus-5-5");
  assert.equal(res.headers.get("x-gateway-downgrade"), null);
  await Promise.all(pending.splice(0));

  res = await withUpstream(replying({}), () => call("claude-opus-5-5"));
  assert.equal(sentModel(), "claude-sonnet-5-5");
  assert.equal(res.headers.get("x-gateway-downgrade"), "claude-opus-5-5 -> claude-sonnet-5-5");
  await withUpstream(replying({}), () => call("claude-haiku-5-5"));
  assert.equal(sentModel(), "claude-haiku-5-5", "models without a rule are untouched");

  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, downgrade })).status, 400, "needs a cap");
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1, downgrade: { at: 0, map: downgrade.map } })).status, 400);
  assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1, downgrade: { at: 80, map: [["only-one"]] } })).status, 400);
});

test("time windows", async () => {
  const office = { days: [1, 2, 3, 4, 5], start: "09:00", end: "18:00", tz: "Asia/Kolkata" };
  assert.ok(withinHours(office, new Date("2026-10-12T04:00:00Z")), "Monday 09:30 in Kolkata");
  assert.ok(!withinHours(office, new Date("2026-10-12T03:00:00Z")), "Monday 08:30 in Kolkata");
  assert.ok(!withinHours(office, new Date("2026-10-11T04:00:00Z")), "Sunday");
  const night = { days: [5], start: "22:00", end: "02:00", tz: "UTC" };
  assert.ok(withinHours(night, new Date("2026-10-16T23:00:00Z")), "Friday night");
  assert.ok(withinHours(night, new Date("2026-10-17T01:00:00Z")), "early Saturday belongs to Friday's window");
  assert.ok(!withinHours(night, new Date("2026-10-17T03:00:00Z")));
  assert.ok(!withinHours(night, new Date("2026-10-15T23:00:00Z")), "Thursday night");
  assert.ok(withinHours({ days: [1], start: "00:00", end: "00:00", tz: "UTC" }, new Date("2026-10-12T23:59:00Z")), "same start and end is the whole day");

  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, hours: { days: [1], start: "09:00", end: "10:00", tz: "UTC" } })).json();
  const now = Date.now;
  try {
    Date.now = () => Date.parse("2026-10-12T09:30:00Z");
    assert.equal((await withUpstream(replying({}), () => req("/v1/models", { headers: bearer(id) }))).status, 200);
    Date.now = () => Date.parse("2026-10-12T10:30:00Z");
    const shut = await req("/v1/models", { headers: bearer(id) });
    assert.equal(shut.status, 403);
    assert.match((await shut.json()).error.message, /only works Mon 09:00-10:00 \(UTC\)/);
  } finally {
    Date.now = now;
  }
  for (const hours of [{ days: [], start: "09:00", end: "10:00", tz: "UTC" }, { days: [1], start: "9:00", end: "10:00", tz: "UTC" }, { days: [1], start: "09:00", end: "10:00", tz: "Mars/Base" }]) {
    assert.equal((await create({ base: "https://x.example", key: "k", expires: inAnHour, hours })).status, 400, JSON.stringify(hours));
  }
});

test("key holders can check their own usage", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, capUsd: 1, capTokens: 10000, period: "month", label: "mine" })).json();
  await withUpstream(replying(opusCall), () => req("/v1/messages", { method: "POST", headers: bearer(id), body: "{}" }));
  await Promise.all(pending.splice(0));
  const u = await (await req("/usage", { headers: bearer(id) })).json();
  assert.deepEqual([u.label, u.active, u.period, u.used.tokens, u.remaining.tokens], ["mine", true, "month", 1500, 8500]);
  assert.ok(Math.abs(u.remaining.usd - 0.986) < 1e-9);
  assert.equal((await (await req(`/usage?key=${id}`)).json()).error.message !== undefined, true, "a key in the URL is refused here too");
  env.ALLOW_QUERY_KEY = "true";
  try {
    assert.equal((await (await req(`/usage?key=${id}`)).json()).label, "mine");
  } finally {
    delete env.ALLOW_QUERY_KEY;
  }
  const html = await req("/usage");
  assert.match(html.headers.get("content-type"), /text\/html/);
  assert.equal((await req("/usage", { headers: bearer("sk-gw-" + "c".repeat(32)) })).status, 401);
});

test("one-time share links", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour, label: "shared", models: ["m"] })).json();
  const makeLink = async (key) => (await req(`/admin/keys/${key}/share`, { method: "POST", headers: { ...adminAuth, "content-type": "application/json" }, body: "{}" })).json();
  const { url, expires } = await makeLink(id);
  assert.equal(expires, inAnHour, "a link never outlives its key");
  const path = new URL(url).pathname;
  const pageRes = await req(path);
  assert.match(await pageRes.text(), /Reveal key/);
  assert.equal(pageRes.headers.get("referrer-policy"), "no-referrer");
  const revealed = await req(path, { method: "POST" });
  assert.deepEqual(await revealed.json(), { key: id, endpoint: "https://gw.example/v1", origin: "https://gw.example", label: "shared", expires: inAnHour, models: ["m"] });
  assert.equal((await req(path, { method: "POST" })).status, 410, "a link works once");

  const second = new URL((await makeLink(id)).url).pathname;
  await req("/admin/keys/" + id, { method: "DELETE", headers: adminAuth });
  assert.equal((await req(second, { method: "POST" })).status, 410, "revoking the key kills its links");
});

test("OpenRouter's reported cost wins and its prices can be imported", async () => {
  const body = JSON.stringify({ model: "anthropic/claude-opus-5.5", usage: { prompt_tokens: 1e6, completion_tokens: 0, cost: 0.5 } });
  const run = async (base) => {
    const { id } = await (await create({ base, key: "k", expires: inAnHour })).json();
    await withUpstream(replying(body), () => req("/v1/chat/completions", { method: "POST", headers: bearer(id), body: "{}" }));
    await Promise.all(pending.splice(0));
    return (await keyInfo(id)).usage.total["anthropic/claude-opus-5.5"].cost;
  };
  assert.equal(await run("https://openrouter.ai/api/v1"), 0.5);
  assert.equal(await run("https://x.example"), 0.5, "any provider that reports a cost is believed, not only OpenRouter");
  // A cost that is not a real number is ignored, and the list price applies.
  for (const bogus of ["0.5", -1, null]) {
    const body = JSON.stringify({ model: "anthropic/claude-opus-5.5", usage: { prompt_tokens: 1e6, completion_tokens: 0, cost: bogus } });
    const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
    await withUpstream(replying(body), () => req("/v1/chat/completions", { method: "POST", headers: bearer(id), body: "{}" }));
    await Promise.all(pending.splice(0));
    assert.equal((await keyInfo(id)).usage.total["anthropic/claude-opus-5.5"].cost, 4, `cost ${JSON.stringify(bogus)} is not a bill`);
  }

  const list = { data: [
    { id: "a/b", pricing: { prompt: "0.000003", completion: "0.000015", input_cache_read: "0.0000003" } },
    { id: "openrouter/auto", pricing: { prompt: "-1", completion: "-1" } },
    { id: "c/free", pricing: { prompt: "0", completion: "0" } },
  ] };
  const res = await withUpstream(replying(list), () => req("/admin/prices/openrouter", { headers: adminAuth }));
  assert.equal(sent.url, "https://openrouter.ai/api/v1/models");
  assert.deepEqual((await res.json()).prices, [
    { match: "a/b", in: 3, out: 15, read: 0.3, write5m: 3, write1h: 3 },
    { match: "c/free", in: 0, out: 0, read: 0, write5m: 0, write1h: 0 },
  ]);
});

const enc = (s) => new TextEncoder().encode(s);
const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sha = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));
// WebAuthn sends ECDSA signatures DER-encoded; WebCrypto produces raw r||s.
function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    return [2, ...(b[0] & 0x80 ? [b.length + 1, 0] : [b.length]), ...b];
  };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}
const passkeysOf = async (e) => (await import("./src/auth.js")).passkeys(e);

async function authenticator() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { id: b64u(crypto.getRandomValues(new Uint8Array(20))), pair, spki: b64u(await crypto.subtle.exportKey("spki", pair.publicKey)) };
}
async function assertion(auth, challenge, { origin = "https://gw.example", flags = 5, rpId = "gw.example" } = {}) {
  const clientData = enc(JSON.stringify({ type: "webauthn.get", challenge, origin }));
  const authData = new Uint8Array([...(await sha(enc(rpId))), flags, 0, 0, 0, 1]);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, auth.pair.privateKey, new Uint8Array([...authData, ...(await sha(clientData))])));
  return { id: auth.id, clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(rawToDer(raw)) };
}

test("passkeys replace the password", async () => {
  delete env.ALLOW_PASSWORD;
  const post = (path, body, headers = adminAuth) => req(path, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(body) });
  const auth = await authenticator();
  const { challenge, rp } = await (await post("/admin/passkeys/options", {})).json();
  assert.equal(rp.id, "gw.example");
  const registration = { id: auth.id, clientDataJSON: b64u(enc(JSON.stringify({ type: "webauthn.create", challenge, origin: "https://gw.example" }))), publicKey: auth.spki, alg: -7, name: "laptop" };
  const reg = await post("/admin/passkeys", registration);
  assert.equal(reg.status, 200);
  const cookie = reg.headers.get("set-cookie").split(";")[0];
  assert.equal((await post("/admin/passkeys", registration, { cookie })).status, 400, "a registration challenge works once");

  const loginPage = await req("/admin", { headers: adminAuth });
  assert.match(await loginPage.text(), /Sign in with a passkey/, "the password stops working once a passkey exists");
  assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 401);
  assert.equal((await req("/admin/keys", { headers: { cookie } })).status, 200);

  const options = async () => (await (await req("/admin/login/options", { method: "POST" })).json()).challenge;
  const good = await assertion(auth, await options());
  const login = await post("/admin/login", good, {});
  assert.equal(login.status, 200);
  const session = login.headers.get("set-cookie").split(";")[0];
  assert.equal((await req("/admin/keys", { headers: { cookie: session } })).status, 200);
  assert.equal((await post("/admin/login", good, fromNewAddress())).status, 401, "an assertion cannot be replayed");
  assert.equal((await post("/admin/login", await assertion(auth, await options(), { origin: "https://evil.example" }), fromNewAddress())).status, 401);
  assert.equal((await post("/admin/login", await assertion(auth, await options(), { rpId: "evil.example" }), fromNewAddress())).status, 401);
  assert.equal((await post("/admin/login", await assertion(auth, await options(), { flags: 1 }), fromNewAddress())).status, 401, "user verification is required");
  const stranger = await authenticator();
  assert.equal((await post("/admin/login", { ...(await assertion(stranger, await options())), id: auth.id }, fromNewAddress())).status, 401, "another key's signature fails");
  const [, exp, sig] = session.match(/=(\d+)\.(.+)$/);
  assert.equal((await req("/admin/keys", { headers: { cookie: `kr_session=${Number(exp) + 1}.${sig}` } })).status, 401, "a tampered session fails");

  env.ALLOW_PASSWORD = "true";
  assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 200, "ALLOW_PASSWORD brings the password back");
  for (const value of ["TRUE", "1", " on"]) {
    env.ALLOW_PASSWORD = value;
    assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 401, `ALLOW_PASSWORD=${JSON.stringify(value)} is ignored`);
  }
  env.ALLOW_PASSWORD = "true";
  assert.deepEqual((await (await req("/admin/passkeys", { headers: { cookie: session } })).json()).map((p) => p.name), ["laptop"]);
  await req("/admin/passkeys/" + auth.id, { method: "DELETE", headers: { cookie: session } });
  assert.equal((await req("/admin/keys", { headers: adminAuth })).status, 200, "removing the last passkey restores the password");
});

test("streamed chat completions ask the provider for usage, so they are metered", async () => {
  const { id } = await (await create({ base: "https://x.example", key: "k", expires: inAnHour })).json();
  const bodyFor = async (payload) => {
    await withUpstream(replying({}), () => req("/v1/chat/completions", { method: "POST", headers: bearer(id), body: JSON.stringify(payload) }));
    return JSON.parse(typeof sent.init.body === "string" ? sent.init.body : new TextDecoder().decode(sent.init.body));
  };
  assert.deepEqual((await bodyFor({ model: "m", stream: true })).stream_options, { include_usage: true });
  assert.deepEqual((await bodyFor({ model: "m", stream: true, stream_options: { foo: 1 } })).stream_options, { foo: 1, include_usage: true });
  assert.equal((await bodyFor({ model: "m" })).stream_options, undefined);
});

test("Gemini's native output limit is clamped", async () => {
  env.ALLOW_QUERY_KEY = "true";
  const { id } = await (await create({ base: "https://g.example/v1beta", key: "k", expires: inAnHour, auth: "x-goog-api-key", maxOutput: 100 })).json();
  const bodyFor = async (payload) => {
    await withUpstream(replying({}), () => req(`/v1/models/gemini-pro:generateContent?key=${id}`, { method: "POST", body: JSON.stringify(payload) }));
    return JSON.parse(sent.init.body);
  };
  try {
    assert.equal((await bodyFor({ generationConfig: { maxOutputTokens: 5000, temperature: 1 } })).generationConfig.maxOutputTokens, 100);
    assert.equal((await bodyFor({ contents: [] })).generationConfig.maxOutputTokens, 100);
  } finally {
    delete env.ALLOW_QUERY_KEY;
  }
});
// The pages are markup and browser script, so there is nothing here to execute: this is the one place that checks
// the controls every feature needs are actually served, instead of repeating a markup assertion inside each feature.
test("every feature's controls are served in the page that needs them, under a strict policy", async () => {
  const read = (f) => readFileSync(new URL("./" + f, import.meta.url), "utf8");
  const shell = read("admin.html");
  const script = read("pages/admin.js.txt");
  const css = read("pages/admin.css.txt");
  const usage = read("usage.html");
  const join = read("join.html");
  /** @type {[string, string, string][]} */
  const need = [
    // [file, name, what it is for]
    [shell, 'id="q"', "search box"],
    [shell, 'id="state"', "active/expired filter"],
    [shell, 'id="count"', "how many keys matched"],
    [shell, 'id="headerOnly"', "a key that refuses a URL credential"],
    [shell, 'id="passkeyWarning"', "the banner until a passkey exists"],
    [shell, 'id="limitsHint"', "which limits apply to which paths"],
    [shell, 'id="logCard"', "the recent-requests card"],
    [shell, 'id="healthBanner"', "the provider-down banner"],
    [shell, 'id="formTitle"', "the focus target after Escape"],
    [shell, "data-write", "the surfaces a viewer must not see"],
    [script, "history.replaceState", "the filter written back to the URL"],
    [script, "MODELS_PER_PAGE = 20", "the usage table page size"],
    [script, "loadAuth", "the viewer mode read before the first load"],
    [script, "loadAudit", "the audit card"],
    [script, "loadHealth", "the health probe"],
    [script, "LOG_EVERY", "the live tail poll"],
    [usage, 'id="rotate"', "the request-a-new-key button"],
    [css, "@media (max-width: 640px)", "the phone layout"],
    [css, "min-height: 44px", "thumb-sized controls"],
    [css, "position: sticky", "the sticky primary action"],
    [css, "content: attr(data-label)", "table cells that read as cards"],
    [css, "body.viewer [data-write]", "the rule that hides a viewer's write controls"],
    [usage, "Resets", "when a monthly key resets"],
    [usage, "breakdown", "what each model cost"],
    [join, 'id="name"', "the invitee's name field"],
  ];
  for (const [text, needle, what] of need) assert.ok(text.includes(needle), `${what} is present (${needle})`);
  // A nonce or 'self' policy, never an inline allowance.
  assert.ok(!shell.includes("unsafe-inline") && !usage.includes("unsafe-inline"));
});

