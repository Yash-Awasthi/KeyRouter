// The two tools that ship beside the worker: the npx CLI, the restore script and the end-to-end smoke journey.
import assert from "node:assert/strict";
import { PROVIDERS, parse, request, run } from "../bin/keyrouter.mjs";
import { makeEnv, worker } from "../scripts/harness.mjs";
import { putFor, audit } from "../scripts/restore.mjs";
import { smoke, stubProvider } from "../scripts/smoke.mjs";
import { test } from "node:test";
import { timingSafeEqual } from "node:crypto";

// The CLI turns arguments into one request and one readable answer. Both are pure enough to check here, and the
// request it builds is replayed against the real worker in worker.test.js via the same handler.
import "../scripts/text_modules.mjs";

const NOW = Date.UTC(2026, 10, 25, 12);
const base = ["--url", "https://gw.example", "--password", "pw"];

test("the CLI builds a key request from a provider name, a cap and a duration", () => {
  const plan = parse([...base, "--provider", "openai", "--key", "sk-real", "--cap", "20", "--days", "7", "--label", "cli"], {}, NOW);
  assert.equal(plan.error, undefined);
  assert.equal(plan.url, "https://gw.example");
  assert.deepEqual(plan.body, {
    base: PROVIDERS.openai,
    key: "sk-real",
    capUsd: 20,
    label: "cli",
    expires: new Date(NOW + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });
  const req = request(plan);
  assert.equal(req.url, "https://gw.example/admin/keys");
  assert.equal(req.method, "POST");
  assert.equal(req.headers.get("content-type"), "application/json");
  // HTTP Basic with a made-up user name: only the password half matters to the worker.
  assert.equal(atob(req.headers.get("authorization").slice(6)), "cli:pw");
});

test("the environment can carry the deployment, the password and the provider key", () => {
  const env = { KEYROUTER_URL: "https://env.example/", KEYROUTER_PASSWORD: "pw", KEYROUTER_PROVIDER_KEY: "sk-env" };
  const plan = parse(["--provider", "anthropic"], env, NOW);
  assert.equal(plan.url, "https://env.example", "a trailing slash is trimmed");
  assert.equal(plan.body.base, "https://api.anthropic.com");
  assert.equal(plan.body.key, "sk-env");
  assert.equal(plan.body.expires, new Date(NOW + 7 * 24 * 3600e3).toISOString(), "a week by default");
  assert.equal(plan.body.capUsd, undefined, "no cap unless asked for");
});

test("every way to get it wrong says what to do instead", () => {
  const bad = (args, env = {}) => parse(args, env, NOW).error;
  assert.match(bad([], {}), /--url/);
  assert.match(bad(["--url", "gw.example"], {}), /--url/, "a bare host is not a URL");
  assert.match(bad(["--url", "https://gw.example", "--provider", "openai", "--key", "k"], {}), /admin password/);
  assert.match(bad([...base, "--key", "k"], {}), /pick a provider/);
  assert.match(bad([...base, "--key", "k", "--provider", "nope"], {}), /pick a provider/);
  assert.match(bad([...base, "--key", "k", "--base", "not a url"], {}), /not a URL/);
  assert.match(bad([...base, "--provider", "openai"], {}), /provider key/);
  assert.match(bad([...base, "--provider", "openai", "--key", "k", "--days", "0"], {}), /--days/);
  assert.match(bad([...base, "--provider", "openai", "--key", "k", "--days", "400"], {}), /--days/);
  assert.match(bad([...base, "--provider", "openai", "--key", "k", "--cap", "-5"], {}), /--cap/);
  assert.equal(bad(["rotate"], {}), 'unknown command "rotate"; the only one is create');
  assert.equal(parse(["--help"], {}, NOW).help, true);
});

test("a created key is printed once, and a refusal is reported with its reason", async () => {
  const lines = [];
  const log = (...a) => lines.push(a.join(" "));
  const errors = [];
  const error = (...a) => errors.push(a.join(" "));
  const ok = {
    id: "sk-gw-" + "a".repeat(32),
    key: "sk-gw-" + "a".repeat(32),
    base: "https://api.openai.com",
    label: "cli",
    expires: "2026-12-02T12:00:00.000Z",
    capUsd: 20,
  };
  const fetchIt = async () => Response.json(ok);
  const argv = [...base, "--provider", "openai", "--key", "sk-real", "--cap", "20", "--label", "cli"];
  assert.equal(await run(argv, { log, error, fetchIt, now: NOW }), 0);
  const text = lines.join("\n");
  assert.match(text, /created sk-gw-a{32}/);
  assert.match(text, /label {4}cli/);
  assert.match(text, /expires {2}2026-12-02T12:00:00.000Z/);
  assert.match(text, /cap {6}\$20/);
  assert.match(text, /key {6}sk-gw-a{32}/);

  // --json prints the worker's answer verbatim, so a script can read it.
  lines.length = 0;
  assert.equal(await run([...argv, "--json"], { log, error, fetchIt: async () => Response.json(ok), now: NOW }), 0);
  assert.deepEqual(JSON.parse(lines.join("\n")), ok);

  // A 403 from the worker carries its message through, and the exit code is not zero.
  const refused = async () => Response.json({ error: { message: "add a passkey before creating keys" } }, { status: 403 });
  assert.equal(await run(argv, { log, error, fetchIt: refused, now: NOW }), 1);
  assert.match(errors.at(-1), /the gateway said 403: add a passkey before creating keys/);

  // A usage error never reaches the network.
  let called = false;
  assert.equal(await run([], { log, error, fetchIt: async () => { called = true; return Response.json({}); } }), 2);
  assert.equal(called, false, "nothing is sent without a deployment and a password");
  assert.match(errors.at(-1), /--url/);

  // Someone who asks for help gets the help, not an error.
  lines.length = 0;
  assert.equal(await run(["--help"], { log, error }), 0);
  assert.match(lines.join("\n"), /npx keyrouter create --provider/);
});

test("the request the CLI builds is one the worker accepts", async () => {
  const { env } = makeEnv({ ADMIN_PASSWORD: "pw", ENCRYPTION_KEY: "k" });
  // HTTP Basic with the password half, exactly as the CLI sends it.
  const plan = parse(["create", "--url", "https://gw.example", "--password", "pw", "--provider", "anthropic", "--key", "sk-ant-real", "--cap", "20", "--days", "7", "--label", "from the cli"], {}, NOW);
  assert.equal(plan.error, undefined);
  const created = worker.fetch(request(plan), env, { waitUntil() {} });
  const res = await created;
  assert.equal(res.status, 200);
  const answer = await res.json();
  assert.match(answer.id, /^sk-gw-[0-9a-f]{32}$/);
  assert.equal(answer.base, "https://api.anthropic.com");
  assert.equal(answer.label, "from the cli");
  assert.equal(answer.capUsd, 20);
  // The provider key was sealed, not echoed back: the answer carries the gateway key, never the real one.
  assert.equal(typeof answer.key, "undefined", "no field carries the provider key");
  assert.equal(JSON.stringify(answer).includes("sk-ant-real"), false);
  const stored = await env.KEYS.get(answer.id, "json");
  assert.ok(stored.key && stored.key !== "sk-ant-real", "the real key is stored sealed");
  assert.equal(Date.parse(answer.expires) - Date.parse(plan.body.expires), 0, "the expiry the CLI chose is the expiry stored");
});

// The DR drill the plan asked for, proved by logic instead of by deleting a real namespace: export, wipe every KV
// row, restore from the dump with the same puts `scripts/restore.mjs` issues, and check that a key still works,
// that the listing still shows its label and limits, and that the restored row expires when it did.

test("export carries everything a restore needs, and the restore puts all of it back", async () => {
  const { makeEnv } = await import("../scripts/harness.mjs");
  const { worker } = await import("../scripts/harness.mjs");
  // Its own deployment, so the wipe is total and does not disturb the rest of the suite.
  const { env, store } = makeEnv({});
  const auth = { authorization: "Basic " + btoa("admin:pw"), "content-type": "application/json" };
  const call = (path, init = {}) => worker.fetch(new Request("https://gw.example" + path, init), env, { waitUntil() {} });

  const created = await (await call("/admin/keys", { method: "POST", headers: auth, body: JSON.stringify({ base: "https://api.example", key: "the-real-provider-key", expires: new Date(Date.now() + 3600e3).toISOString(), label: "restored key", capUsd: 2, models: ["claude-opus-5-5"] }) })).json();
  const before = await (await call("/admin/keys/" + created.id, { headers: auth })).json();
  const dump = await (await call("/admin/export", { headers: auth })).json();
  assert.equal(dump.sealed, true, "the dump holds sealed keys");
  assert.equal(dump.keys.length, 1);
  const entry = dump.keys[0];
  assert.equal(entry.id, created.id);
  assert.equal(entry.metadata.label, "restored key", "the listing metadata is in the dump, or the restore loses it");
  assert.ok(entry.expiration > Date.now() / 1000 - 60, "and the KV expiry, or a restored row would never be deleted");
  assert.deepEqual(audit(dump.keys), [], "the dump passes the restore script's own audit");

  // The disaster: every KV row is gone. Nothing else is touched, which is exactly what a namespace loss means.
  store.clear();
  assert.equal((await call("/admin/keys", { headers: auth })).status, 200);
  assert.deepEqual((await (await call("/admin/keys", { headers: auth })).json()).keys, [], "the listing is empty");

  // The restore, with the same arguments the script prints.
  for (const e of dump.keys) {
    const put = putFor(e, { binding: "KEYS" });
    const i = put.indexOf(e.id);
    const [, value] = [put[i], put[i + 1]];
    const expiration = Number(put[put.indexOf("--expiration") + 1]);
    const metadata = JSON.parse(put[put.indexOf("--metadata") + 1]);
    await env.KEYS.put(e.id, value, { expiration, metadata });
  }

  const listed = await (await call("/admin/keys", { headers: auth })).json();
  assert.equal(listed.keys.length, 1, "the key is listed again");
  assert.equal(listed.keys[0].label, "restored key", "with its label, which the record alone would not give the list");
  assert.match(listed.keys[0].limits, /cap \$2/, `and its limits, which came from the metadata: ${JSON.stringify(listed.keys[0].limits)}`);
  assert.equal(store.get(created.id).expiration, entry.expiration, "the KV expiry was restored, not dropped");

  const record = await (await call("/admin/keys/" + created.id, { headers: auth })).json();
  assert.deepEqual(record.usage, before.usage, "usage came back with the dump");
  assert.equal(record.active, true);

  // And the key still works: same sealed provider key, opened with the same ENCRYPTION_KEY, sent upstream.
  const real = globalThis.fetch;
  let sentKey = null;
  globalThis.fetch = async (_url, init) => {
    sentKey = new Headers(init.headers).get("authorization");
    return Response.json({ model: "claude-opus-5-5", usage: { input_tokens: 10, output_tokens: 5 } });
  };
  try {
    const res = await call("/v1/messages", { method: "POST", headers: { authorization: "Bearer " + created.id }, body: JSON.stringify({ model: "claude-opus-5-5" }) });
    assert.equal(res.status, 200, "a restored key proxies");
    assert.equal(sentKey, "Bearer the-real-provider-key", "and the provider key came back intact, not corrupted by the round trip");
  } finally {
    globalThis.fetch = real;
  }
});

test("a dump that predates the fix is refused instead of restoring a deployment that looks fine", () => {
  const id = "sk-gw-" + "a".repeat(32);
  const older = [
    { id, record: { expires: "2027-01-01T00:00:00.000Z" } },
    { id: "sk-gw-" + "b".repeat(32), record: {}, expiration: 1 },
    { id: "sk-gw-" + "c".repeat(32), expiration: 1, metadata: {} },
    { id: "sk-gw-" + "d".repeat(32), record: {}, expiration: 1, metadata: {} },
    { id: "not-a-key", record: {} },
  ];
  const problems = audit(older);
  assert.equal(problems.length, 4, "each incomplete entry is named");
  assert.match(problems[0], /no expiry/, "an entry without an expiry restores a row that never goes away");
  assert.match(problems[1], /no metadata/, "an entry without metadata restores a key with no label or limits in the list");
  assert.match(problems[2], /no record/);
  assert.match(problems[3], /not a gateway id/);
  assert.deepEqual(audit([{ id, record: {}, expiration: 1, metadata: {} }]), [], "a complete entry passes");
});

// The smoke script drives the worker over HTTP, so this runs it against the worker itself with a stub transport:
// the same journey a `wrangler dev` run would take, without needing a browser, a deploy or a network.
crypto.subtle.timingSafeEqual = timingSafeEqual;
const { Meter, Admin } = await import("../worker.js");

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
          delete: async (keys) => {
            for (const k of keys) data.delete(k);
          },
          deleteAll: async () => void data.clear(),
          setAlarm: async (t) => void (storage.alarmAt = t),
          deleteAlarm: async () => void (storage.alarmAt = null),
        };
        const instance = new Class({ storage }, env);
        instances.set(name, { meter: instance, storage, fetch: (input, init) => instance.fetch(new Request(typeof input === "string" ? input : input.url, init)) });
      }
      return instances.get(name);
    },
  };
}

const store = new Map();
const env = {
  ADMIN_PASSWORD: "pw",
  ALLOW_PASSWORD: "true",
  ALLOW_LOCAL_BASE: "true",
  ENCRYPTION_KEY: "smoke-encryption-secret",
  KEYS: {
    async get(k) { return store.has(k) ? JSON.parse(store.get(k).value) : null; },
    async getWithMetadata(k) { return { value: await this.get(k), metadata: store.get(k)?.metadata ?? null }; },
    async put(k, value, opts) { store.set(k, { value, ...opts }); },
    async delete(k) { store.delete(k); },
    async list({ prefix = "" } = {}) {
      const keys = [...store].filter(([n]) => n.startsWith(prefix)).map(([name, v]) => ({ name, metadata: v.metadata }));
      return { keys, list_complete: true };
    },
  },
};
env.METER = namespace(Meter);
env.ADMIN = namespace(Admin);

// The worker dials the provider through the global fetch, so the stub lives there; everything else is the worker.
const providerReply = new Response(JSON.stringify({ model: "claude-opus-5-5", usage: { input_tokens: 120, output_tokens: 30 } }), { headers: { "content-type": "application/json" } });
const realFetch = globalThis.fetch;
const transport = async (input, init) => {
  const url = typeof input === "string" ? input : input.url;
  if (url.startsWith("http://127.0.0.1:")) return providerReply.clone();
  const pending = [];
  const res = await worker.fetch(new Request(url, init), env, { waitUntil: (p) => pending.push(p) });
  // The worker records spend after it answers; the script reads it next, so let that work finish first.
  if (url.includes("/v1/chat/completions")) await Promise.all(pending);
  return res;
};

test("the smoke journey passes against a stub provider, and catches a key that still works", async () => {
  globalThis.fetch = transport;
  let result;
  try {
    result = await smoke({ url: "https://gw.example", admin: "pw", provider: "http://127.0.0.1:9999/v1", fetchImpl: transport });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.match(result.id, /^sk-gw-[0-9a-f]{32}$/);
  assert.equal(result.usd, Math.round((120 * 4 / 1e6 + 30 * 20 / 1e6) * 1e6) / 1e6, "120 in + 30 out at opus-5-5 rates");
  // The run cleaned up after itself.
  assert.ok(!store.has(result.id));
});

test("the stub provider answers with the usage the script expects", async () => {
  const provider = stubProvider();
  const base = await provider.listen();
  try {
    assert.match(base, /^http:\/\/127\.0\.0\.1:\d+\/v1$/);
    const res = await fetch(base + "/chat/completions", { method: "POST", body: "{}" });
    const body = await res.json();
    assert.deepEqual(body.usage, { input_tokens: 120, output_tokens: 30 });
  } finally {
    await provider.close();
  }
});
