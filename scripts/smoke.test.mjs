import { test } from "node:test";
import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import "./text_modules.mjs";
import { smoke, stubProvider } from "./smoke.mjs";

// The smoke script drives the worker over HTTP, so this runs it against the worker itself with a stub transport:
// the same journey a `wrangler dev` run would take, without needing a browser, a deploy or a network.
crypto.subtle.timingSafeEqual = timingSafeEqual;
const { default: worker, Meter, Admin } = await import("../worker.js");

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
