import { randomHex } from "./crypto.js";

// What a call costs, and where the table comes from. `cost()` is pure, so its arithmetic can be checked
// against a sample invoice without a worker or a network.

// USD per million tokens from platform.claude.com/docs/en/about-claude/pricing and ai.google.dev/gemini-api/docs/pricing.
// The longest matching name wins, so "claude-opus-5" does not price claude-opus-5-5.
export const DEFAULT_PRICES = [
  { match: "claude-fable-5-2", in: 8, out: 40, read: 0.2, write5m: 10, write1h: 16 },
  { match: "claude-fable-5-1", in: 10, out: 50, read: 0.25, write5m: 12.5, write1h: 20 },
  { match: "claude-mythos-5-2", in: 8, out: 40, read: 0.2, write5m: 10, write1h: 16 },
  { match: "claude-mythos-5-1", in: 10, out: 50, read: 0.25, write5m: 12.5, write1h: 20 },
  { match: "claude-fable-5", in: 10, out: 50, read: 1, write5m: 12.5, write1h: 20 },
  { match: "claude-mythos-5", in: 10, out: 50, read: 1, write5m: 12.5, write1h: 20 },
  { match: "claude-opus-5-5", in: 4, out: 20, read: 0.2, write5m: 5, write1h: 8, fast: 2 },
  { match: "claude-opus-5", in: 5, out: 25, read: 0.5, write5m: 6.25, write1h: 10, fast: 2 },
  { match: "claude-opus-4-8", in: 5, out: 25, read: 0.5, write5m: 6.25, write1h: 10, fast: 2 },
  { match: "claude-opus-4-7", in: 5, out: 25, read: 0.5, write5m: 6.25, write1h: 10 },
  { match: "claude-opus-4-6", in: 5, out: 25, read: 0.5, write5m: 6.25, write1h: 10 },
  { match: "claude-opus-4-5", in: 5, out: 25, read: 0.5, write5m: 6.25, write1h: 10 },
  { match: "claude-opus-4-1", in: 15, out: 75, read: 1.5, write5m: 18.75, write1h: 30 },
  { match: "claude-opus-4", in: 15, out: 75, read: 1.5, write5m: 18.75, write1h: 30 },
  { match: "claude-sonnet-5-5", in: 2, out: 10, read: 0.1, write5m: 2.5, write1h: 4 },
  { match: "claude-sonnet-5", in: 2, out: 10, read: 0.2, write5m: 2.5, write1h: 4 },
  { match: "claude-sonnet-4-6", in: 3, out: 15, read: 0.3, write5m: 3.75, write1h: 6 },
  { match: "claude-sonnet-4-5", in: 3, out: 15, read: 0.3, write5m: 3.75, write1h: 6 },
  { match: "claude-sonnet-4", in: 3, out: 15, read: 0.3, write5m: 3.75, write1h: 6 },
  { match: "claude-haiku-5-5", in: 0.1, out: 0.5, read: 0.01, write5m: 0.125, write1h: 0.2, longAbove: 100e3, longScale: 5 },
  { match: "claude-haiku-4-5", in: 1, out: 5, read: 0.1, write5m: 1.25, write1h: 2 },
  // USD per million tokens from ai.google.dev/gemini-api/docs/pricing as read on 2026-11-25. Gemini charges no
  // separate cache-write rate: the row's write prices are its input price. Models priced per image or per second, and
  // the Live and Batch variants, are left out on purpose.
  { match: "gemini-4-carbon", in: 2, out: 10, read: 0.1, write5m: 2, write1h: 2 },
  { match: "gemini-4-argon", in: 2, out: 10, read: 0.1, write5m: 2, write1h: 2 },
  { match: "gemini-4-neon", in: 3, out: 15, read: 0.15, write5m: 3, write1h: 3 },
  { match: "gemini-4-hydrogen", in: 1.5, out: 7.5, read: 0.075, write5m: 1.5, write1h: 1.5 },
  { match: "gemini-3.8-flash", in: 0.75, out: 3.75, read: 0.075, write5m: 0.75, write1h: 0.75 },
  { match: "gemini-3.6-flash", in: 0.75, out: 3.75, read: 0.075, write5m: 0.75, write1h: 0.75 },
  { match: "gemini-3.1-pro-preview", in: 2, out: 12, read: 0.2, write5m: 2, write1h: 2 },
  { match: "gemini-3.8-flash-tts", in: 0.5, out: 9, read: 0.05, write5m: 0.5, write1h: 0.5 },
  { match: "gemini-3.8-flash-lite-tts", in: 0.5, out: 6, read: 0.05, write5m: 0.5, write1h: 0.5 },
  { match: "gemini-3.1-flash-tts-preview", in: 1, out: 20, read: 0.1, write5m: 1, write1h: 1 },
  { match: "gemini-2.5-pro", in: 1.25, out: 10, read: 0.125, write5m: 1.25, write1h: 1.25 },
  { match: "gemini-2.5-flash-preview-tts", in: 0.5, out: 10, read: 0.05, write5m: 0.5, write1h: 0.5 },
  { match: "gemini-2.5-pro-preview-tts", in: 1, out: 20, read: 0.1, write5m: 1, write1h: 1 },
];
const PRICE_FIELDS = ["in", "out", "read", "write5m", "write1h"];
const PRICE_OPTIONAL = ["longAbove", "longScale", "fast"];
const slug = (s) => String(s).toLowerCase().replaceAll(".", "-");

export function cost(model, usage, prices = DEFAULT_PRICES) {
  const id = slug(model);
  const p = prices.filter((r) => id.includes(slug(r.match))).sort((a, b) => b.match.length - a.match.length)[0];
  if (!p) return null;
  const fresh = usage.input_tokens || 0;
  const read = usage.cache_read_input_tokens || 0;
  const write = usage.cache_creation_input_tokens || 0;
  const write1h = usage.cache_creation?.ephemeral_1h_input_tokens || 0;
  // Long-context, fast-mode and US-residency multipliers stack on every rate, cache included.
  let scale = p.longAbove && fresh + read + write > p.longAbove ? p.longScale || 1 : 1;
  if (usage.speed === "fast") scale *= p.fast || 1;
  if (usage.inference_geo === "us") scale *= 1.1;
  const usd = fresh * p.in + read * p.read + (write - write1h) * p.write5m + write1h * p.write1h + (usage.output_tokens || 0) * p.out;
  return (usd * scale) / 1e6;
}


// Prices are read on every metered call, so each isolate keeps them for a minute instead of reading KV each time.
// The version key is the ETag: the minute only costs one small read, and the table itself is re-read when the version
// moved, which is exactly when a saved table has changed.
const PRICE_VERSION = "config:prices:v";
let priceCache = /** @type {{ at: number, version: string, rows: any[] | null }} */ ({ at: 0, version: "", rows: null });

/** @returns {Promise<any[]>} */
/** A saved table reaches this isolate at once, without waiting for the minute to run out. */
export function rememberPrices(rows, version = "") {
  priceCache = { at: Date.now(), version, rows };
}

/** Write the table and bump the version, so every other isolate re-reads it on its next check. */
export async function savePrices(env, rows) {
  const version = randomHex(8);
  await env.KEYS.put("config:prices", JSON.stringify(rows));
  await env.KEYS.put(PRICE_VERSION, version);
  rememberPrices(rows, version);
  return version;
}

export async function prices(env) {
  if (Date.now() - priceCache.at > 60e3) {
    const version = await env.KEYS.get(PRICE_VERSION);
    if (version && version === priceCache.version) priceCache = { at: Date.now(), version, rows: priceCache.rows };
    else priceCache = { at: Date.now(), version: version ?? "", rows: (await env.KEYS.get("config:prices", "json")) || DEFAULT_PRICES };
  }
  return /** @type {any[]} */ (priceCache.rows || DEFAULT_PRICES);
}

/** The stamp of the table the last `prices()` call read: the saved table's version, or "default" for the built-in one. */
export const priceVersion = () => priceCache.version || "default";

export function checkPrices(rows) {
  if (!Array.isArray(rows) || rows.length > 2000) return "prices must be a list of up to 2000 rows";
  const blank = (v) => v == null || v === "";
  for (const r of rows) {
    if (typeof r?.match !== "string" || !r.match.trim()) return "every price row needs a model name";
    if (!PRICE_FIELDS.every((f) => !blank(r[f]) && Number(r[f]) >= 0)) return `${r.match}: every rate must be a number of 0 or more`;
    if (!PRICE_OPTIONAL.every((f) => blank(r[f]) || Number(r[f]) > 0)) return `${r.match}: optional fields must be positive numbers`;
  }
  return null;
}

export function tidyPrice(r) {
  const out = { match: r.match.trim() };
  for (const f of [...PRICE_FIELDS, ...PRICE_OPTIONAL]) if (r[f] != null && r[f] !== "") out[f] = Number(r[f]);
  return out;
}

// OpenRouter lists USD per token as strings; rows here are USD per million tokens.
export async function openRouterPrices() {
  const res = await fetch("https://openrouter.ai/api/v1/models", { signal: AbortSignal.timeout(15e3) }).catch(() => null);
  const data = await res?.json().catch(() => null);
  if (!res?.ok || !Array.isArray(data?.data)) return null;
  const perMillion = (v) => {
    const n = Number(v);
    return v != null && v !== "" && Number.isFinite(n) && n >= 0 ? Math.round(n * 1e12) / 1e6 : null;
  };
  return data.data.flatMap((m) => {
    const p = m.pricing || {};
    const [inp, out] = [perMillion(p.prompt), perMillion(p.completion)];
    if (typeof m.id !== "string" || inp == null || out == null) return [];
    const write = perMillion(p.input_cache_write) ?? inp;
    return [{ match: m.id, in: inp, out, read: perMillion(p.input_cache_read) ?? inp, write5m: write, write1h: write }];
  });
}

