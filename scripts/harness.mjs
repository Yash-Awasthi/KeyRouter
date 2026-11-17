// A local stand-in for the deployed worker: the real `worker.js`, the real Durable Object classes, and an
// in-memory KV. Used by the tests, the smoke script's in-process run and the CPU measurement.
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import "./text_modules.mjs";

crypto.subtle.timingSafeEqual ??= timingSafeEqual;

const { default: worker, Meter, Admin } = await import("../worker.js");
export { worker, Meter, Admin };

function namespace(Class, getEnv) {
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
        const instance = new Class({ storage }, getEnv());
        instances.set(name, { meter: instance, storage, fetch: (input, init) => instance.fetch(new Request(typeof input === "string" ? input : input.url, init)) });
      }
      return instances.get(name);
    },
  };
}

/** A fresh gateway with an empty store. `extra` overrides the environment (a secret, a quota stub). */
export function makeEnv(extra = {}) {
  const store = new Map();
  const env = {
    ADMIN_PASSWORD: "pw",
    ALLOW_PASSWORD: "true",
    ENCRYPTION_KEY: "harness-encryption-secret-key",
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
    ...extra,
  };
  env.METER = namespace(Meter, () => env);
  env.ADMIN = namespace(Admin, () => env);
  return { env, store };
}

/** The provider's answer to one chat completion, with the token usage the meter reads. */
export const completion = (input = 120, output = 30) =>
  new Response(JSON.stringify({ model: "claude-opus-5-5", usage: { input_tokens: input, output_tokens: output } }), { headers: { "content-type": "application/json" } });

/**
 * A `fetch` that sends anything other than a provider URL to the worker itself, and answers provider calls
 * with `completion()`. The spend is recorded in `ctx.waitUntil`, so the promise is awaited before it returns:
 * a caller that reads `/usage` next always sees the row.
 */
function transportFor(env, { onProvider = () => completion() } = {}) {
  return async (input, init) => {
    const url = typeof input === "string" ? input : input.url;
    if (url.startsWith("http://127.0.0.1:")) return onProvider(url);
    const pending = [];
    const res = await worker.fetch(new Request(url, init), env, { waitUntil: (p) => pending.push(p) });
    await Promise.all(pending);
    return res;
  };
}
