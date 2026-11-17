// Metering: what a call used, what it cost, and the per-key Durable Object that remembers it. One object per
// gateway key means concurrent calls on a key cannot lose an update the way a KV read-modify-write would.
import { json } from "./http.js";
import { requestLog } from "./log.js";
import { cost, priceVersion, prices } from "./pricing.js";

const METERED = new Set(["/messages", "/chat/completions", "/responses", "/completions", "/embeddings"]);
// Gemini's native API names the model in the path: /models/<name>:generateContent or :streamGenerateContent.
const GEMINI_GENERATE = /^\/models\/[^/]+:(stream)?[Gg]enerateContent$/;
export const meterable = (path) => METERED.has(path) || GEMINI_GENERATE.test(path);
export const modelInPath = (path) => path.match(/\/models\/([^/:]+)/)?.[1];
export const OUTPUT_FIELDS = ["max_tokens", "max_completion_tokens", "max_output_tokens"];
export const LIMITS = { capUsd: "spend cap", capTokens: "token cap", rpm: "rate limit", maxOutput: "max output tokens" };

const RESERVE_TTL = 60e3;
const RESERVE_MIN = 0.001;

export const RETAIN = 30 * 864e5;

export function normalize(u) {
  if (!u) return {};
  if (u.promptTokenCount != null || u.candidatesTokenCount != null) {
    const cached = u.cachedContentTokenCount || 0;
    return { input_tokens: (u.promptTokenCount || 0) - cached, cache_read_input_tokens: cached, output_tokens: u.candidatesTokenCount || 0 };
  }
  if (u.prompt_tokens == null && !u.input_tokens_details) return u;
  const total = u.prompt_tokens ?? u.input_tokens ?? 0;
  const cached = (u.prompt_tokens_details || u.input_tokens_details)?.cached_tokens || 0;
  return { input_tokens: total - cached, cache_read_input_tokens: cached, output_tokens: u.completion_tokens ?? u.output_tokens, cost: u.cost };
}

// Handles Anthropic Messages, OpenAI Chat Completions and Responses, and Gemini's native bodies, streamed or not.
function extract(text, type) {
  // Only events carrying a usage object are parsed: a long stream parsed in full would exceed the free plan's 10 ms of CPU.
  const chunks = type?.includes("event-stream")
    ? text.split("\n").filter((l) => l.startsWith("data:") && /"usage(Metadata)?"\s*:\s*\{/.test(l)).map((l) => l.slice(5))
    : [text];
  let model;
  const usage = {};
  for (const raw of chunks) {
    let ev;
    try { ev = JSON.parse(raw); } catch { continue; }
    const o = ev.message || ev.response || ev;
    model ||= o.model;
    for (const [k, v] of Object.entries(normalize(o.usage || ev.usage || o.usageMetadata || ev.usageMetadata))) if (v != null) usage[k] = v;
  }
  return { model, usage };
}

export const month = () => new Date().toISOString().slice(0, 7);
/** The UTC day a call happened on, which is the grain of the usage report. */
const dayKey = (d = new Date()) => d.toISOString().slice(0, 10);
/** How many days of per-day buckets are kept: enough for a weekly report with a month of context. */
const DAYS_KEPT = 32;
/** The hour a call happened in, which is the grain of the anomaly check. */
export const hourKey = (d = new Date()) => d.toISOString().slice(0, 13);
/** A week of hourly buckets: enough for a median that is not moved by one busy afternoon. */
export const HOURS_KEPT = 168;
/** Below this, a spike is a handful of cheap calls and not worth a flag. */
const ANOMALY_FLOOR = 0.001;
/** A median of one or two hours is not a baseline: a new key must have run for a few hours before it can spike. */
const ANOMALY_MIN_HOURS = 3;

// Money is stored as whole nano-dollars, because a float total drifts: adding $0.0000123 ten thousand times gives
// 0.12299999999999998 in floating point and 0.123000000 in integers. The public shape stays USD.
/** @param {any} m a stored model bucket */
const nanoOf = (m) => m?.nano ?? Math.round((m?.cost || 0) * 1e9);
/** One stored bucket as the API shows it: USD with nine decimal places of headroom. */
export const view = (bucket = {}) =>
  Object.fromEntries(Object.entries(bucket).map(([name, m]) => [name, {
    requests: m.requests,
    input: m.input,
    output: m.output,
    cost: nanoOf(m) / 1e9,
    priced: m.priced !== false,
    // Which price table charged these calls. A row keeps the newest one it saw, so an edited table leaves older
    // spend alone and only stamps the calls made after the edit.
    price_version: m.pv ?? null,
  }]));
/** Every month's buckets, as the API shows them. */
const viewMonths = (months = {}) =>
  Object.fromEntries(Object.entries(months).map(([k, bucket]) => [k, view(bucket)]));

/** Add one call to a bucket in place. Exported so the arithmetic can be checked without a Durable Object. */
export function addCall(bucket, { model, input, output, usd, pv }) {
  const m = (bucket[model] ||= { requests: 0, input: 0, output: 0, nano: 0, priced: true });
  if (pv) m.pv = pv;
  m.requests++;
  m.input += input;
  m.output += output;
  if (usd == null) m.priced = false;
  else m.nano = nanoOf(m) + Math.round(usd * 1e9);
  return bucket;
}

const sum = (bucket = {}) =>
  Object.values(bucket).reduce((s, m) => ({ usd: s.usd + nanoOf(m) / 1e9, tokens: s.tokens + m.input + m.output }), { usd: 0, tokens: 0 });
export const usedIn = (u, period) => sum(period === "month" ? u.months?.[month()] : u.total);

/** The per-model rows of the period a key is metered on, most expensive first. */
export const modelRows = (u, period) => {
  const bucket = period === "month" ? u.months?.[month()] : u.total;
  // A bucket arrives either raw (nano) or already viewed (cost), and the price stamp survives both shapes.
  const rows = Object.entries(bucket || {}).map(([model, row]) => {
    const v = view({ [model]: row })[model];
    return { model, ...v, price_version: row.price_version ?? v.price_version };
  });
  return rows.sort((a, b) => b.cost - a.cost || b.requests - a.requests || a.model.localeCompare(b.model));
};

/** When a period next rolls over, or null for a key with no period. A month resets at UTC midnight on the 1st. */
export const resetAt = (period, now = new Date()) =>
  period === "month" ? new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString() : null;

/** The share of the period's cap a key has used, as a percentage: the bigger of the spend and the token share. */
const capShare = (used, { capUsd, capTokens }) =>
  Math.max(capUsd ? (used.usd / capUsd) * 100 : 0, capTokens ? (used.tokens / capTokens) * 100 : 0);

/** Keep the newest `DAYS_KEPT` day buckets, so a long-lived key cannot grow its storage without bound. */
function pruneDays(days) {
  const dates = Object.keys(days).sort();
  for (const old of dates.slice(0, Math.max(0, dates.length - DAYS_KEPT))) delete days[old];
  return days;
}

/**
 * The usage report over the last `span` days, from the per-day buckets and counters.
 * Pure, so the arithmetic can be checked without a Durable Object.
 */
function reportOf(days = {}, counters = {}, span = 7, now = new Date()) {
  const since = dayKey(new Date(now.getTime() - (span - 1) * 864e5));
  const dates = Object.keys(days).filter((d) => d >= since).sort();
  const merged = {};
  for (const date of dates) for (const [model, row] of Object.entries(days[date] || {})) {
    const m = (merged[model] ||= { requests: 0, input: 0, output: 0, nano: 0, priced: true });
    m.requests += row.requests;
    m.input += row.input;
    m.output += row.output;
    m.nano += row.nano ?? Math.round((row.cost || 0) * 1e9);
    if (row.priced === false) m.priced = false;
  }
  const models = Object.entries(merged)
    .map(([model, row]) => ({ model, ...view({ [model]: row })[model] }))
    .sort((a, b) => b.cost - a.cost || b.requests - a.requests || a.model.localeCompare(b.model));
  const refused = dates.reduce((s, d) => s + (counters[d]?.refused || 0), 0);
  const downgraded = dates.reduce((s, d) => s + (counters[d]?.downgraded || 0), 0);
  return {
    from: dates[0] ?? null,
    to: dates.at(-1) ?? null,
    days: dates.length,
    span,
    requests: models.reduce((s, m) => s + m.requests, 0),
    spend_usd: Math.round(models.reduce((s, m) => s + m.cost, 0) * 1e9) / 1e9,
    tokens: models.reduce((s, m) => s + m.input + m.output, 0),
    refused,
    downgraded,
    models,
  };
}

/**
 * Whether the call just recorded is the one that crossed the key's alert threshold, and what to say about it.
 * A threshold fires once per period: the meter stores the share it alerted at, so a key that sits over 80%
 * does not send an alert on every request. Purely arithmetic, so it can be checked without a Durable Object.
 */
function crossedAlert(after, before, route, alertedAt) {
  const at = route?.alertAt;
  if (!at || (alertedAt || 0) >= at) return null;
  const share = capShare(after, route);
  if (share < at) return null;
  return {
    at,
    percent: Math.round(share * 10) / 10,
    was: Math.round(capShare(before, route) * 10) / 10,
    spent_usd: Math.round(after.usd * 1e6) / 1e6,
    tokens: after.tokens,
    cap_usd: route.capUsd ?? null,
    cap_tokens: route.capTokens ?? null,
    period: route.period || "total",
  };
}

/** Keep the newest `HOURS_KEPT` hourly buckets. */
export function pruneHours(hours) {
  const keys = Object.keys(hours).sort();
  for (const old of keys.slice(0, Math.max(0, keys.length - HOURS_KEPT))) delete hours[old];
  return hours;
}

/** The middle value of a list of numbers: the median, so one busy hour cannot raise the bar. */
export function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * Is this hour's spend an anomaly? A key is flagged when the current hour is at least five times the median
 * of its own completed hours over the last week, and when that spend is big enough to matter.
 * Pure, so the arithmetic is checked without a Durable Object.
 */
export function anomalyOf(hours = {}, now = new Date()) {
  const current = hourKey(now);
  const past = Object.keys(hours).filter((h) => h < current).sort();
  const usd = (h) => (hours[h]?.nano ?? 0) / 1e9;
  const hour_usd = usd(current);
  const base = median(past.map(usd));
  const ratio = base > 0 ? hour_usd / base : hour_usd > 0 ? Infinity : 0;
  return {
    flagged: past.length >= ANOMALY_MIN_HOURS && hour_usd >= ANOMALY_FLOOR && ratio >= 5,
    hour_usd: Math.round(hour_usd * 1e9) / 1e9,
    median_usd: Math.round(base * 1e9) / 1e9,
    ratio: Number.isFinite(ratio) ? Math.round(ratio * 10) / 10 : null,
    hours: past.length,
  };
}

export class Meter {
  constructor(state, env) {
    this.storage = state.storage;
    this.env = env;
  }

  async fetch(req) {
    const path = new URL(req.url).pathname;
    if (req.method === "DELETE") return Response.json(await this.wipe());
    if (path === "/reset") {
      await this.storage.delete(["models", "months", "hits", "alerted", "days", "counters", "hours", "spiked"]);
      return Response.json({ ok: true });
    }
    if (path === "/count") {
      const { field } = await req.json();
      await this.count(field === "downgraded" ? "downgraded" : "refused");
      return Response.json({ ok: true });
    }
    if (path === "/report") {
      const span = Math.min(DAYS_KEPT, Math.max(1, Number(new URL(req.url).searchParams.get("days")) || 7));
      const hours = (await this.storage.get("hours")) || {};
      return Response.json({ ...reportOf((await this.storage.get("days")) || {}, (await this.storage.get("counters")) || {}, span), anomaly: anomalyOf(hours) });
    }
    if (path === "/schedule") {
      const { id, expires } = await req.json();
      await this.storage.put("key", { id, expires });
      await this.storage.setAlarm(Date.parse(expires));
      return Response.json({ ok: true });
    }
    const total = (await this.storage.get("models")) || {};
    const months = (await this.storage.get("months")) || {};
    // Calls that were admitted but have not recorded their cost yet, so concurrency cannot slip past a cap.
    const inflight = ((await this.storage.get("inflight")) || []).filter((r) => r.until > Date.now());
    if (path === "/admit") {
      const { capUsd, capTokens, period, rpm } = await req.json();
      const used = usedIn({ total, months }, period);
      const when = period === "month" ? " for this month" : "";
      const reserved = inflight.reduce((s, r) => s + r.usd, 0);
      // A refusal is the report's business, so the meter counts its own: these two are the only refusals it makes.
      const refuse = async (body) => {
        await this.count("refused");
        return json(429, body);
      };
      if (capUsd && used.usd + reserved >= capUsd) return refuse(`spend cap of $${capUsd}${when} reached`);
      if (capTokens && used.tokens >= capTokens) return refuse(`token cap of ${capTokens}${when} reached`);
      if (capUsd) {
        // Reserve this call's likely cost: the key's average so far, never less than a tenth of a cent.
        const lifetime = Object.values(total).reduce((s, m) => s + nanoOf(m), 0) / 1e9;
        const calls = Object.values(total).reduce((s, m) => s + m.requests, 0);
        inflight.push({ until: Date.now() + RESERVE_TTL, usd: Math.max(lifetime / Math.max(calls, 1), RESERVE_MIN) });
        await this.storage.put("inflight", inflight);
      }
      if (rpm) {
        const now = Date.now();
        const hits = ((await this.storage.get("hits")) || []).filter((t) => t > now - 60e3);
        // The window is a sliding sixty seconds, so that is exactly how long a refused caller has to wait. The
        // refusal is still counted in the report, as every other refusal is.
        if (hits.length >= rpm) {
          await this.count("refused");
          return json(429, `rate limit reached (${rpm} per minute)`, { "retry-after": "60" });
        }
        hits.push(now);
        await this.storage.put("hits", hits);
      }
      return Response.json({ ok: true, used: Math.max(capUsd ? (used.usd + reserved) / capUsd : 0, capTokens ? used.tokens / capTokens : 0) });
    }
    if (req.method === "POST") {
      const { model, input, output, cost: usd, release, alert, pv } = await req.json();
      // A call that ends without a usage object still frees the slot it reserved.
      if (release) {
        if (inflight.length) await this.storage.put("inflight", inflight.slice(1));
        return Response.json({ total: view(total), months: viewMonths(months) });
      }
      const before = alert ? usedIn({ total, months }, alert.period) : null;
      for (const bucket of [total, (months[month()] ||= {})]) addCall(bucket, { model, input, output, usd, pv });
      await this.storage.put("models", total);
      await this.storage.put("months", months);
      // The same call in a per-day bucket, so the report can answer "today" and "this week" and not just "this month".
      const days = (await this.storage.get("days")) || {};
      addCall((days[dayKey()] ||= {}), { model, input, output, usd, pv });
      await this.storage.put("days", pruneDays(days));
      // And in an hourly bucket, which is what the anomaly check compares against.
      const hours = (await this.storage.get("hours")) || {};
      const hour = (hours[hourKey()] ||= { requests: 0, nano: 0 });
      hour.requests++;
      hour.nano += Math.round((usd || 0) * 1e9);
      await this.storage.put("hours", pruneHours(hours));
      // An anomaly is worth one message per hour: the meter remembers the hour it already reported.
      const anomaly = anomalyOf(hours, new Date());
      /** @type {any} */
      let spike = null;
      if (anomaly.flagged && (await this.storage.get("spiked")) !== hourKey()) {
        const spiked = hourKey();
        await this.storage.put("spiked", spiked);
        spike = { ...anomaly, hour: spiked };
      }
      // The recorded cost replaces the reservation this call made.
      if (inflight.length) await this.storage.put("inflight", inflight.slice(1));
      // One alert per period per key: the meter remembers the share it already reported.
      /** @type {any} */
      let fired = null;
      if (alert) {
        const alerted = (await this.storage.get("alerted")) || {};
        const stamp = alert.period === "month" ? month() : "total";
        fired = crossedAlert(usedIn({ total, months }, alert.period), before, alert, alerted[stamp]);
        if (fired) {
          alerted[stamp] = fired.at;
          await this.storage.put("alerted", alerted);
        }
      }
      return Response.json({ total: view(total), months: viewMonths(months), alert: fired, spike });
    }
    return Response.json({ total: view(total), months: viewMonths(months) });
  }

  // Fires at expiry to wipe the real key, then again at the end of retention to drop the record.
  async alarm() {
    const { id, expires } = (await this.storage.get("key")) || {};
    if (!id) return;
    const expiry = Date.parse(expires);
    const purge = expiry + RETAIN;
    // An alarm can fire early (a retry, a restored DO, a clock that moved): never wipe a key that is still live.
    if (Date.now() < expiry) return void (await this.storage.setAlarm(expiry));
    if (Date.now() >= purge) return void (await this.wipe());
    const { value, metadata } = await this.env.KEYS.getWithMetadata(id, "json");
    if (value?.key) {
      await this.env.KEYS.put(id, JSON.stringify({ ...value, key: null }), { expiration: Math.floor(purge / 1000), metadata: { ...metadata, expired: true } });
    }
    await this.storage.setAlarm(purge);
  }

  /** Count one refusal or downgrade for today, so the report can say how often a key was stopped or rerouted. */
  async count(field) {
    const counters = (await this.storage.get("counters")) || {};
    const today = (counters[dayKey()] ||= { refused: 0, downgraded: 0 });
    today[field] = (today[field] || 0) + 1;
    await this.storage.put("counters", pruneDays(counters));
  }

  async wipe() {
    await this.storage.deleteAlarm();
    await this.storage.deleteAll();
    return { ok: true };
  }
}

export const meter = (env, id, path, init) => env.METER.get(env.METER.idFromName(id)).fetch("https://meter" + path, init);

// The reply is read once as it passes the client: only the events that carry a model or a usage count
// are kept, so a long completion costs the same CPU and the same memory as a short one and the client is never
// held up waiting for it to end.
const INTEREST = /"(usage|usageMetadata|model)"\s*:/;

/**
 * Read a stream to its end and return only the lines that matter, in the shape `extract()` expects.
 * @param {ReadableStream<Uint8Array>} stream
 * @param {number} [keep] how many trailing interesting lines to hold
 */
export async function tail(stream, keep = 3) {
  const decoder = new TextDecoder();
  const lines = [];
  let model = "";
  let partial = "";
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      partial += decoder.decode(value, { stream: true });
      const parts = partial.split("\n");
      partial = parts.pop() ?? "";
      for (const line of parts) {
        if (!INTEREST.test(line)) continue;
        if (!model && /"model"\s*:/.test(line)) model = line;
        lines.push(line);
        if (lines.length > keep) lines.shift();
      }
    }
  } catch {
    // The stream broke — the client hung up, or the provider stopped mid-answer. What arrived is still what to bill,
    // and a partial answer that was already charged for must not be free: the kept lines are returned as they are.
  }
  if (INTEREST.test(partial)) lines.push(partial);
  return [model, ...lines].filter(Boolean).join("\n");
}

/**
 * Read the tail of a streamed answer, record it against the key, and against `group` when the key carries a
 * host budget.
 *
 * @param {any} env
 * @param {string} id
 * @param {ReadableStream} stream
 * @param {string} base
 * @param {string} path
 * @param {any} route
 * @param {string | null} type
 * @param {string | null} [group]
 * @param {any} [log] a request-log line to finish once the usage is known, or null when the log is off
 */
export async function recordStream(env, id, stream, base, path, route, type, group = null, log = null) {
  try {
    await applyUsage(env, id, await tail(stream), type, base, path, route, group, log);
  } catch {
    // Metering must never break proxying.
  }
}

/** @param {string | null} type @param {string | null} [group] @param {any} [log] */
async function applyUsage(env, id, text, type, base, path, route, group = null, log = null) {
  const body = extract(text, type);
  // Gemini's native API reports no model in the body, so the path supplies it.
  const model = body.model || modelInPath(path);
  const usage = body.usage;
  // A provider that reports what it charged is authoritative, whatever host it is: a numeric `cost` in the usage
  // object wins over the list price. A base URL decides where a key may be pointed, not whether to believe the bill.
  const charged = typeof usage.cost === "number" && Number.isFinite(usage.cost) && usage.cost >= 0 ? usage.cost : null;
  const counted = model && Object.keys(usage).length;
  const alert = route?.alertAt ? { alertAt: route.alertAt, capUsd: route.capUsd ?? null, capTokens: route.capTokens ?? null, period: route.period || "total" } : null;
  const chargedCost = charged ?? cost(model, usage, await prices(env));
  const { total, months, alert: fired, spike } = await (await meter(env, id, "/", {
    method: "POST",
    body: JSON.stringify(counted ? {
      model,
      input: (usage.input_tokens || 0) + (usage.cache_read_input_tokens || 0) + (usage.cache_creation_input_tokens || 0),
      output: usage.output_tokens || 0,
      cost: chargedCost,
      alert,
      pv: priceVersion(),
    } : { release: true }),
  })).json();
  if (!counted) return;
  // The host budget counts the same call, with the same cost, and nothing else: no alert, no anomaly, no cap math
  // of its own, because the spend it holds is a sum across keys rather than a key's own history.
  if (group) {
    await meter(env, group, "/", { method: "POST", body: JSON.stringify({ model, input: 0, output: 0, cost: chargedCost }) }).catch(() => {});
  }
  // The admit check ran before the previous calls were counted, so the true-up reports any overshoot instead of hiding it.
  const used = usedIn({ total, months }, route?.period);
  if (route?.capUsd && used.usd >= route.capUsd) console.warn(`key ${id.slice(0, 9)}... is at ${used.usd.toFixed(4)} against a cap of $${route.capUsd}`);
  if (route?.capTokens && used.tokens >= route.capTokens) console.warn(`key ${id.slice(0, 9)}... is at ${used.tokens} tokens against a cap of ${route.capTokens}`);
  if (log) await requestLog(env, { at: log.at, key: id.slice(0, 13), model: model ?? null, status: log.status, ms: log.ms, tokens: counted ? (usage.input_tokens || 0) + (usage.cache_read_input_tokens || 0) + (usage.cache_creation_input_tokens || 0) + (usage.output_tokens || 0) : null, cost_usd: counted ? chargedCost : null });
  if (fired) await notify(env, id, route, { at: fired.at, ...fired }, "threshold");
  if (spike) await notify(env, id, route, spike, "anomaly");
}

/**
 * Tell the operator a key has crossed its alert threshold. The webhook is optional: without `ALERT_WEBHOOK` the
 * crossing is only logged. The body carries the key's label and numbers, never the key or the provider secret,
 * and a failure to deliver is logged rather than allowed to break metering.
 */
async function notify(env, id, route, detail, event = "threshold") {
  const prefix = `${id.slice(0, 9)}...`;
  const what = event === "threshold" ? `crossed ${detail.at}% of its cap at ${detail.percent}%` : `spent ${detail.hour_usd} in an hour against a median of ${detail.median_usd}`;
  console.warn(`key ${prefix} ${what}`);
  if (!env?.ALERT_WEBHOOK) return;
  try {
    const res = await fetch(env.ALERT_WEBHOOK, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event, key: prefix, label: route?.label || "", at: new Date().toISOString(), ...detail }),
      // A slow webhook must not hold metering open behind a client that has already had its answer.
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) console.warn(`alert webhook answered ${res.status}`);
  } catch (e) {
    console.warn(`alert webhook failed: ${/** @type {Error} */ (e).message}`);
  }
}
