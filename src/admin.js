// The admin API: what the dashboard calls. Every write is JSON-only (a cross-site form cannot send that with a
// session cookie), and no response here ever carries a real provider key.
import { ALGS, INVITE_TTL, INVITES_MAX, LOGIN_REQUIRED, adminStore, clientData, ipHash, newSession, passkeys, passwordRole, sessionKey, sessionRole, throttled, tooMany, verifyAssertion, wrongPassword } from "./auth.js";
import { newId, randomHex, seal, unb64u, unseal } from "./crypto.js";
import { cors, isJson, json } from "./http.js";
import { LIMITS, RETAIN, meter, modelInPath, usedIn } from "./meter.js";
import { requestLog } from "./log.js";
import { DAYS, baseOk, groupId, hostOf, parseRange, validBase } from "./net.js";
import { ADMIN_PAGE, ADMIN_CSS, ADMIN_JS, JOIN_PAGE, LOGIN_PAGE, asset, inlinePage, page } from "./pages.js";
import { DEFAULT_PRICES as PRICES, checkPrices, openRouterPrices, priceVersion, prices, savePrices, tidyPrice } from "./pricing.js";
import { AUTH_STYLES, KEY_ID, authHeader, validAuth } from "./proxy.js";

const PAGE_SIZE = 20;
// How many keys a filtered listing will look at before it reports the answer as partial.
const SCAN_MAX = 1000;
// How many keys one aggregate report reads: one Durable Object call each, and a request has 50 subrequests.
const REPORT_MAX = 25;
const BATCH_MAX = 20;

/**
 * A signing style only means something against the host that verifies it: an AWS signature sent to OpenAI is a
 * credential in the clear, and an api-version sent to anything but Azure is a key that looks configured but is not.
 */
function signingFits(base, s) {
  const host = hostOf(base);
  if (s.aws && !/\.amazonaws\.com$/i.test(host) && !/\.amazonaws\.com\.cn$/i.test(host)) return "an AWS-signed key must point at an amazonaws.com endpoint";
  if (s.azure && !/(^|\.)(openai|services|cognitiveservices)\.azure\.com$/i.test(host)) return "an Azure key must point at an openai.azure.com or cognitiveservices.azure.com endpoint";
  return null;
}

/** The Prometheus exposition an external monitor scrapes, computed from the request log. */
export async function metrics(env) {
  const { entries = [], kept = 0 } = env.REQUEST_LOG === "true" ? await (await adminStore(env, "/log", { get: 500 })).json() : {};
  const count = { ok: 0, client: 0, server: 0, refused: 0, downgraded: 0 };
  for (const e of entries) {
    if (e.event === "refused") count.refused++;
    else if (e.event === "downgraded") count.downgraded++;
    else if (e.status >= 500) count.server++;
    else if (e.status >= 400) count.client++;
    else count.ok++;
  }
  const total = entries.length;
  const rate = (n) => (total ? (n / total).toFixed(4) : "0");
  // A cumulative histogram of the per-call millisecond count, so p95 can be read straight off the exposition instead
  // of exported by hand. The buckets are the ones a 50 ms SLO needs to distinguish: well under, around, and far over.
  const BUCKETS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
  const ms = entries.map((e) => Number(e.ms) || 0);
  const hist = BUCKETS.map((le) => `keyrouter_request_ms_bucket{le="${le}"} ${ms.filter((v) => v <= le).length}`);
  hist.push(`keyrouter_request_ms_bucket{le="+Inf"} ${ms.length}`);
  const sum = ms.reduce((a, b) => a + b, 0);
  return [
    "# HELP keyrouter_requests_total Calls in the request log window.",
    "# TYPE keyrouter_requests_total gauge",
    `keyrouter_requests_total ${total}`,
    `keyrouter_log_kept ${kept}`,
    `keyrouter_log_enabled ${env.REQUEST_LOG === "true" ? 1 : 0}`,
    "# HELP keyrouter_responses_total Responses by class.",
    "# TYPE keyrouter_responses_total gauge",
    `keyrouter_responses_total{class="2xx"} ${count.ok}`,
    `keyrouter_responses_total{class="4xx"} ${count.client}`,
    `keyrouter_responses_total{class="5xx"} ${count.server}`,
    "# HELP keyrouter_refused_total Calls stopped at the door by the shared budget.",
    "# TYPE keyrouter_refused_total gauge",
    `keyrouter_refused_total ${count.refused}`,
    "# HELP keyrouter_downgraded_total Calls rerouted to a cheaper model.",
    "# TYPE keyrouter_downgraded_total gauge",
    `keyrouter_downgraded_total ${count.downgraded}`,
    "# HELP keyrouter_admit_refusal_rate Refusals divided by logged calls.",
    "# TYPE keyrouter_admit_refusal_rate gauge",
    `keyrouter_admit_refusal_rate ${rate(count.refused)}`,
    "# HELP keyrouter_downgrade_rate Downgrades divided by logged calls.",
    "# TYPE keyrouter_downgrade_rate gauge",
    `keyrouter_downgrade_rate ${rate(count.downgraded)}`,
    "# HELP keyrouter_request_ms Gateway time per call, from the request log (first byte for a stream).",
    "# TYPE keyrouter_request_ms histogram",
    ...hist,
    `keyrouter_request_ms_sum ${sum}`,
    `keyrouter_request_ms_count ${ms.length}`,
  ].join("\n") + "\n";
}

/** A probe result is reused for this long: a page reload must not turn into a subrequest per host. */
const HEALTH_TTL = 60e3;
/** One subrequest per host, and Workers Free allows 50 per request, so the list of probed hosts is bounded. */
const HEALTH_MAX = 5;
const HEALTH_TIMEOUT = 2000;

/** The distinct provider hosts the stored keys point at, newest first: that is where a failure would be felt. */
async function keyHosts(env, limit = HEALTH_MAX) {
  const list = await env.KEYS.list({ limit: 100 });
  const seen = [];
  // The namespace also holds config values such as the price table, which are not key records.
  for (const k of list.keys.filter((k) => KEY_ID.test(k.name))) {
    const route = await env.KEYS.get(k.name, "json");
    const host = route?.base ? hostOf(route.base) : "";
    if (host && !seen.includes(host)) seen.push(host);
    if (seen.length >= limit) break;
  }
  return seen;
}

/**
 * One HEAD per provider host, unless a result from the last minute is already stored. A 401 or a 404 means the host
 * answered, which is the question; only a transport failure or a 5xx is "down".
 */
export async function health(env, { refresh = false } = {}) {
  let cached = null;
  try {
    cached = await (await adminStore(env, "/health")).json();
  } catch {}
  if (!refresh && cached?.at && Date.now() - cached.at < HEALTH_TTL) return cached;
  const hosts = await keyHosts(env);
  const checks = await Promise.all(
    hosts.map(async (host) => {
      const started = Date.now();
      try {
        const res = await fetch(`https://${host}/`, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(HEALTH_TIMEOUT) });
        return { host, up: res.status < 500, status: res.status, ms: Date.now() - started };
      } catch (e) {
        return { host, up: false, status: 0, ms: Date.now() - started, error: String(/** @type {Error} */ (e).message).slice(0, 200) };
      }
    }),
  );
  const result = { at: Date.now(), checks, down: checks.filter((c) => !c.up).map((c) => c.host) };
  if (checks.length) {
    // A failed cache write only costs the next reader a probe, so it is not an error the caller has to handle.
    try {
      await adminStore(env, "/health", { put: result });
    } catch {}
  }
  return result;
}

export function settings(s) {
  const { expires, auth = "bearer", label = "", models = [], ips = [], period = "total", hours = null, downgrade = null } = s;
  const exp = Date.parse(expires);
  if (!(exp > Date.now() + 60e3)) return { error: "expiry must be at least a minute away" };
  if (!validAuth(auth)) return { error: `auth must be one of ${AUTH_STYLES.join(", ")}, a header name, or header:Scheme` };
  if (period !== "total" && period !== "month") return { error: "cap period must be total or month" };
  const names = (list, max) => Array.isArray(list) && list.length <= max && list.every((m) => typeof m === "string" && m && m.length <= 200);
  if (!names(models, 500)) return { error: "models must be a list of up to 500 model names" };
  if (!Array.isArray(ips) || ips.length > 100) return { error: "the IP allowlist must be a list of up to 100 entries" };
  const bad = ips.find((r) => !parseRange(r));
  if (bad !== undefined) return { error: `${bad} is not an IP address or CIDR range` };
  const out = { expires: new Date(exp).toISOString(), auth, label: String(label).slice(0, 100), models, ips: ips.map((r) => r.trim()), period };
  // A host-level budget travels with the key, so the proxy can enforce it without reading the config on every call.
  if (s.groupCap > 0) out.groupCap = Number(s.groupCap);
  // Opt-in: this key may only ever be presented in a header, so a leaked URL cannot authenticate.
  if (s.headerOnly) out.headerOnly = true;
  for (const [name, what] of Object.entries(LIMITS)) {
    if (s[name] == null || s[name] === "") continue;
    const n = Number(s[name]);
    const whole = name !== "capUsd";
    if (!(n > 0) || (whole && !Number.isInteger(n))) return { error: `${what} must be a positive ${whole ? "whole number" : "number"}` };
    out[name] = n;
  }
  if (hours) {
    const time = /^([01]\d|2[0-3]):[0-5]\d$/;
    const { days, start, end, tz } = hours;
    if (!Array.isArray(days) || !days.length || !days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6)) return { error: "pick at least one day for the time window" };
    if (!time.test(start) || !time.test(end)) return { error: "time window start and end must be HH:MM" };
    try { new Intl.DateTimeFormat("en-US", { timeZone: tz }); } catch { return { error: `${tz} is not a time zone` }; }
    out.hours = { days: [...new Set(days)].sort(), start, end, tz };
  }
  if (downgrade) {
    const { at, map } = downgrade;
    if (!out.capUsd && !out.capTokens) return { error: "a downgrade needs a spend or token cap to measure against" };
    if (!(Number(at) > 0 && Number(at) <= 100)) return { error: "the downgrade threshold must be a percentage from 1 to 100" };
    if (!Array.isArray(map) || !map.length || map.length > 50 || !map.every((p) => names(p, 2) && p.length === 2)) {
      return { error: "downgrade rules must be pairs of model names" };
    }
    out.downgrade = { at: Number(at), map };
  }
  // Azure names the deployment in the path and requires an api-version; the deployment lives in the key, not the base.
  if (s.azure) {
    const { deployment, apiVersion = "2024-10-21" } = s.azure;
    if (typeof deployment !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(deployment)) return { error: "an Azure deployment name is 1-64 letters, digits, dots, dashes or underscores" };
    if (!/^\d{4}-\d{2}-\d{2}(-preview)?$/.test(apiVersion)) return { error: "an Azure api-version looks like 2024-10-21 or 2024-10-21-preview" };
    out.azure = { deployment, apiVersion };
  }
  // Bedrock is signed with the caller's AWS credentials, so the secret in the vault is an AWS secret access key.
  if (s.aws) {
    const { region, service = "bedrock", accessKeyId, sessionToken = null } = s.aws;
    if (typeof accessKeyId !== "string" || !/^[A-Z0-9]{16,32}$/.test(accessKeyId)) return { error: "an AWS access key id is 16-32 upper-case letters and digits" };
    if (typeof region !== "string" || !/^[a-z]{2}(-[a-z]+)+-\d$/.test(region)) return { error: "an AWS region looks like us-east-1" };
    if (!/^[a-z0-9.-]{1,64}$/.test(service)) return { error: "an AWS service name is lower-case letters, digits, dots and dashes" };
    if (sessionToken !== null && (typeof sessionToken !== "string" || !sessionToken.trim() || sessionToken.length > 4096)) return { error: "an AWS session token is a non-empty string" };
    out.aws = { region, service, accessKeyId, sessionToken: sessionToken?.trim() || null };
  }
  // An alert is a percentage of an existing cap, so it says something only when there is a cap to measure against.
  if (s.alertAt != null && s.alertAt !== "") {
    const at = Number(s.alertAt);
    if (!out.capUsd && !out.capTokens) return { error: "an alert needs a spend or token cap to measure against" };
    if (!(Number.isInteger(at) && at >= 1 && at <= 100)) return { error: "the alert threshold must be a whole percentage from 1 to 100" };
    out.alertAt = at;
  }
  return out;
}

function limitsText(k) {
  const per = k.period === "month" ? " per month" : "";
  const models = k.models || [];
  const n = (x) => x.toLocaleString("en-US");
  return [
    k.auth && k.auth !== "bearer" ? "header " + k.auth : "",
    k.headerOnly ? "headers only" : "",
    k.capUsd ? `cap $${k.capUsd}${per}` : "",
    k.capTokens ? `cap ${n(k.capTokens)} tokens${per}` : "",
    k.downgrade ? `past ${k.downgrade.at}%: ` + k.downgrade.map.map(([a, b]) => `${a} -> ${b}`).join(", ") : "",
    k.alertAt ? `alert at ${k.alertAt}%` : "",
    k.rpm ? `${k.rpm} requests/min` : "",
    k.maxOutput ? `max ${n(k.maxOutput)} output tokens` : "",
    models.length ? "models: " + (models.length > 3 ? models.slice(0, 3).join(", ") + ` +${models.length - 3} more` : models.join(", ")) : "",
    k.ips?.length ? "IPs: " + k.ips.join(", ") : "",
    k.hours ? `${k.hours.days.map((d) => DAYS[d]).join(" ")} ${k.hours.start}-${k.hours.end} ${k.hours.tz}` : "",
  ].filter(Boolean).join("\n") || "none";
}

// The listing reads KV metadata only, which is capped at 1024 bytes, so it holds a summary of the settings.
// Whole lines are kept and a marker is added, so the list never shows half an address or half a CIDR.
const MORE = "...open the key for the full settings";
export function summary(route) {
  const meta = { base: route.base, expires: route.expires, label: route.label, rev: route.rev };
  const all = limitsText(route).split("\n");
  const size = (lines) => JSON.stringify({ ...meta, limits: lines.join("\n") }).length;
  let lines = all;
  if (size(lines) > 1000) {
    lines = [...all];
    while (lines.length > 1 && size([...lines, MORE]) > 1000) lines.pop();
    if (size([...lines, MORE]) > 1000) {
      // One line can still be too long (a long IP list), so it is cut at its commas, never inside an address.
      const parts = lines[0].split(", ");
      while (parts.length > 1 && size([parts.join(", ") + ", " + MORE]) > 1000) parts.pop();
      lines = [parts.join(", ") + ", " + MORE];
    } else {
      lines.push(MORE);
    }
  }
  return { ...meta, limits: lines.join("\n") };
}

// Wipes the real key and stamps when, keeping the record so the spend stays visible.
async function markRevoked(env, id, route) {
  const revoked_at = route.revoked_at || new Date().toISOString();
  const rev = Date.now();
  const { key, ...visible } = { ...route, key: null, revoked_at, rev };
  await env.KEYS.put(id, JSON.stringify({ ...route, key: null, revoked_at, rev }), { expiration: Math.floor((Date.parse(route.expires) + RETAIN) / 1000), metadata: { ...summary({ ...visible, expired: true }), expired: true } });
  return { id, revoked_at, rev };
}

// The free plan allows 1,000 KV writes a day. A refused write must say so; a bare 500 hides the only cause an operator can fix.
const QUOTA = "the KV write limit for this namespace is used up for today (the free plan allows 1,000 writes a day); try again after midnight UTC or raise the limit in the Cloudflare dashboard";

export async function save(env, id, route) {
  // Schedule the wipe first, so a stored real key always has one.
  await meter(env, id, "/schedule", { method: "POST", body: JSON.stringify({ id, expires: route.expires }) });
  const { key, ...visible } = { ...route, rev: Date.now() };
  try {
    await env.KEYS.put(id, JSON.stringify({ ...route, rev: visible.rev }), { expiration: Math.floor((Date.parse(route.expires) + RETAIN) / 1000), metadata: summary({ ...visible, expired: !!route.revoked_at || visible.expired }) });
  } catch (e) {
    // Anything a put can refuse (quota, a 1,024-byte metadata cap, a body over 25 MiB) is about the write itself.
    const err = /** @type {Error} */ (e);
    console.warn(`could not store key ${id.slice(0, 9)}...: ${err.message}`);
    throw new Error(QUOTA);
  }
  return { id, ...visible };
}

/**
 * The one page an external monitor can read without a session: is this deployment alive, when was it deployed, and
 * are the provider hosts its keys point at answering? It names hosts, never keys, and never a token or an address.
 * `BUILD` is a var the release script sets (`<iso date>:<sha>`); without it the deploy time is honestly unknown.
 */
export async function status(env) {
  /** @type {{ at: number|null, checks: Array<{host: string, up: boolean, ms: number}>, down: string[] }} */
  let checks = { at: null, checks: [], down: [] };
  try {
    checks = await health(env);
  } catch {
    // A health probe that cannot run is reported as unknown reachability, not as an outage of the gateway itself.
  }
  const build = String(env.BUILD || "");
  // `<iso date>:<sha>` — split on the last colon, because the date carries colons of its own.
  const cut = build.lastIndexOf(":");
  const [at, sha] = cut > 0 ? [build.slice(0, cut), build.slice(cut + 1)] : [null, build || null];
  return {
    ok: true,
    deployed_at: at && !Number.isNaN(Date.parse(at)) ? new Date(Date.parse(at)).toISOString() : null,
    version: sha || null,
    providers: checks.checks.map((c) => ({ host: c.host, up: c.up, ms: c.ms })),
    down: checks.down,
    checked_at: checks.at ? new Date(checks.at).toISOString() : null,
  };
}

/**
 * Re-encrypt every stored provider key from one ENCRYPTION_KEY to another. Each row is opened with the old secret,
 * sealed with the new one, then opened again and compared before it is stored, so a wrong passphrase cannot leave a
 * row that nothing can read. Returns counts, never the secrets.
 */
export async function reseal(env, from, to, role = "owner") {
  const list = await env.KEYS.list({ prefix: "sk-gw-", limit: 1000 });
  const failed = [];
  let resealed = 0;
  let skipped = 0;
  for (const k of list.keys) {
    const route = await env.KEYS.get(k.name, "json");
    if (!route) continue;
    // A row that was already revoked keeps no secret, so there is nothing to re-seal.
    if (typeof route.key !== "string" || !route.key.startsWith("enc:v1:")) {
      skipped++;
      continue;
    }
    const plain = await unseal({ ENCRYPTION_KEY: from }, k.name, route.key);
    if (plain == null) {
      failed.push(k.name.slice(0, 13));
      continue;
    }
    const sealed = await seal({ ENCRYPTION_KEY: to }, k.name, plain);
    if ((await unseal({ ENCRYPTION_KEY: to }, k.name, sealed)) !== plain) {
      failed.push(k.name.slice(0, 13));
      continue;
    }
    const { key, ...visible } = { ...route, key: sealed };
    await env.KEYS.put(k.name, JSON.stringify({ ...route, key: sealed }), { expiration: Math.floor((Date.parse(route.expires) + RETAIN) / 1000), metadata: summary({ ...visible, expired: !!route.revoked_at || Date.now() > Date.parse(route.expires) }) });
    resealed++;
  }
  await audit(env, role, "reseal keys", resealed + " re-sealed, " + failed.length + " failed");
  return { resealed, skipped, failed, total: list.keys.length };
}

const BASE_HINT = "need an https endpoint and an API key";
/** Records who did what, for the questions a bill or an incident asks later. The log never blocks the change. */
export const audit = (env, role, action, target) =>
  adminStore(env, "/audit", { add: { at: new Date().toISOString(), role, action, target: String(target || "").slice(0, 80) } }).catch((e) => {
    console.warn(`could not write the audit log: ${/** @type {Error} */ (e).message}`);
  });

// One message for every refused viewer call, so it never matters which route was tried.
const VIEWER_READONLY = "this session is read-only: a viewer can see keys and usage, and only an owner can change anything";

// Sessions are HMAC-signed expiry times; the signing key lives in the Admin Durable Object.

/**
 * Spend, tokens, top models, refusals, downgrades and anomalies across every key, over the last `days` days.
 * Bounded by REPORT_MAX keys: a report is worth a page of them, and a request cannot make 50 subrequests.
 */
export async function digest(env, days = 7, { q = "" } = {}) {
  const keys = [];
  let cursor;
  do {
    const page = await env.KEYS.list({ prefix: "sk-gw-", cursor, limit: 200 });
    keys.push(...page.keys);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor && keys.length < SCAN_MAX);
  const needle = String(q).toLowerCase();
  const wanted = needle ? keys.filter((k) => String(k.metadata?.label || "").toLowerCase().includes(needle)) : keys;
  // Newest first, so a truncated report covers the keys an operator is most likely asking about.
  const picked = wanted.sort((x, y) => (y.metadata?.rev || 0) - (x.metadata?.rev || 0)).slice(0, REPORT_MAX);
  keys.length = 0;
  keys.push(...picked);
  const reports = [];
  const models = {};
  const totals = { requests: 0, spend_usd: 0, tokens: 0, refused: 0, downgraded: 0 };
  const anomalies = [];
  for (const key of keys.slice(0, REPORT_MAX)) {
    const report = await (await meter(env, key.name, "/report?days=" + days)).json();
    if (report.anomaly?.flagged) anomalies.push({ id: key.name, label: key.metadata?.label || "", ...report.anomaly });
    if (!report.requests) continue;
    for (const row of report.models) {
      const m = (models[row.model] ||= { model: row.model, requests: 0, input: 0, output: 0, cost: 0, priced: true });
      m.requests += row.requests;
      m.input += row.input;
      m.output += row.output;
      m.cost += row.cost;
      if (!row.priced) m.priced = false;
    }
    reports.push({ id: key.name, label: key.metadata?.label || "", requests: report.requests, spend_usd: report.spend_usd });
    for (const field of Object.keys(totals)) totals[field] += report[field];
  }
  return {
    days,
    q: needle ? String(q) : "",
    keys: reports.length,
    scanned: keys.length,
    truncated: wanted.length > REPORT_MAX,
    totals: { ...totals, spend_usd: Math.round(totals.spend_usd * 1e9) / 1e9 },
    top: Object.values(models).sort((a, b) => b.cost - a.cost || b.requests - a.requests || a.model.localeCompare(b.model)).slice(0, 10),
    anomalies,
    keys_by_spend: reports.sort((a, b) => b.spend_usd - a.spend_usd).slice(0, 10),
  };
}

const GROUP_KEY = "config:groups";
const HOST = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d{1,5})?$/;

/** The budgets by host, as stored. A missing or broken config means no budget anywhere, never a silent default. */
async function groupCaps(env) {
  try {
    const stored = await env.KEYS.get(GROUP_KEY, "json");
    if (!stored || typeof stored !== "object") return {};
    const out = {};
    for (const [host, cap] of Object.entries(stored)) if (HOST.test(host) && Number(cap) > 0) out[host] = Number(cap);
    return out;
  } catch {
    return {};
  }
}

/**
 * Every key pointed at a host with a budget carries that budget on its own record, so the proxy needs no extra KV
 * read per request. This is the only place the copy is refreshed: setting a budget rewrites the keys on that host.
 */
async function applyGroupCaps(env, caps) {
  const touched = {};
  let cursor;
  do {
    const page = await env.KEYS.list({ prefix: "sk-gw-", cursor, limit: 200 });
    for (const k of page.keys) {
      const route = await env.KEYS.get(k.name, "json");
      if (!route || route.revoked_at) continue;
      const host = hostOf(route.base);
      const capUsd = caps[host] ?? null;
      if ((route.groupCap ?? null) === capUsd) continue;
      await save(env, k.name, { ...route, groupCap: capUsd ?? undefined });
      touched[host] = (touched[host] || 0) + 1;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return touched;
}

/**
 * The invitee's side: no session and no password, just the one code from the link. The code buys exactly one
 * registration, and what it registers is a viewer passkey: it can read keys and usage and change nothing.
 */
export async function join(req, env, url) {
  if (url.pathname === "/join" && req.method === "GET") return inlinePage(JOIN_PAGE);
  if (url.pathname !== "/join/options" && url.pathname !== "/join/register") return json(404, "not found");
  // Writes need a JSON content type, which forces a CORS preflight, so another site cannot spend someone's invite.
  if (!isJson(req)) return json(415, "send JSON");
  const body = await req.json().catch(() => ({}));
  const code = String(body.code || "");
  if (!/^[0-9a-f]{32}$/.test(code)) return json(404, "this invite is not valid; ask the owner for a new link");
  const open = (await (await adminStore(env, "/invites", {})).json()).find((i) => i.code === code);
  if (!open) return json(404, "this invite is not valid; ask the owner for a new link");

  if (url.pathname === "/join/options" && req.method === "POST") {
    const { challenge } = await (await adminStore(env, "/challenge", {})).json();
    return Response.json({ challenge, rp: { id: url.hostname, name: "KeyRouter" }, label: open.label || "" });
  }
  const alg = Number(body.alg);
  if (!ALGS[alg] || !/^[\w-]{16,1400}$/.test(body.id || "")) return json(400, "this passkey type is not supported");
  try {
    if (!(await clientData(env, url, body.clientDataJSON, "webauthn.create"))) return json(400, "passkey registration expired or came from another site");
    await crypto.subtle.importKey("spki", unb64u(body.publicKey), ALGS[alg][0], false, ["verify"]);
  } catch {
    return json(400, "the passkey's public key could not be read");
  }
  // Spend the invite first: two browsers racing on one link cannot both end up registered.
  const taken = await (await adminStore(env, "/invites", { take: code })).json();
  if (!taken.invite) return json(404, "this invite was already used; ask the owner for a new link");
  const name = String(body.name || taken.invite.label || "Viewer passkey").slice(0, 60);
  await adminStore(env, "/passkeys", { add: { id: body.id, publicKey: body.publicKey, alg, name, role: "viewer", created: new Date().toISOString() } });
  await audit(env, "viewer", "joined as viewer", name);
  return Response.json({ ok: true, role: "viewer" }, { headers: { "set-cookie": await newSession(env, "viewer") } });
}

export async function admin(req, env, url) {
  // The admin page's own files: public, static and identical for everyone, so no session is needed to fetch them.
  if (url.pathname === "/admin/admin.css") return asset(ADMIN_CSS, "text/css; charset=utf-8");
  if (url.pathname === "/admin/admin.js") return asset(ADMIN_JS, "text/javascript; charset=utf-8");
  // Writes require a JSON content type, which forces a CORS preflight, so other sites cannot use stored credentials.
  const body = isJson(req) ? await req.json().catch(() => ({})) : null;
  const path = url.pathname;

  if (path === "/admin/login/options" && req.method === "POST") {
    return Response.json({ ...(await (await adminStore(env, "/challenge", {})).json()), rpId: url.hostname });
  }
  if (path === "/admin/login" && req.method === "POST" && body) {
    const gate = await throttled(req, env, "check");
    if (gate.blocked) {
      console.warn(`admin sign-in refused: address blocked for ${gate.retryAfter}s`);
      return tooMany(gate.retryAfter);
    }
    const cred = (await passkeys(env)).find((p) => p.id === body.id);
    if (!cred || !(await verifyAssertion(env, url, cred, body))) {
      const { blocked } = await throttled(req, env, "fail");
      console.warn(`admin sign-in failed: passkey assertion rejected${blocked ? ", address now blocked" : ""}`);
      return json(401, "passkey sign-in failed");
    }
    await throttled(req, env, "pass");
    return Response.json({ ok: true }, { headers: { "set-cookie": await newSession(env, cred.role === "viewer" ? "viewer" : "owner") } });
  }
  if (path === "/admin/logout" && req.method === "POST") {
    return Response.json({ ok: true }, { headers: { "set-cookie": "kr_session=; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0" } });
  }

  // The status document and the metrics are for an external monitor, which has no session and must not need one.
  if (req.method === "GET" && (path === "/status" || path === "/metrics")) {
    if (path === "/status") return Response.json(await status(env), { headers: { "cache-control": "no-store" } });
    return new Response(await metrics(env), { headers: { "content-type": "text/plain; version=0.0.4; charset=utf-8" } });
  }

  let role = await sessionRole(req, env);
  if (!role) {
    const gate = await throttled(req, env, "check");
    if (gate.blocked) {
      console.warn(`admin sign-in refused: address blocked for ${gate.retryAfter}s`);
      return tooMany(gate.retryAfter);
    }
    // The password works until a passkey exists; ALLOW_PASSWORD=true brings it back if every passkey is lost.
    const passwordAllowed = env.ALLOW_PASSWORD === "true" || !(await passkeys(env)).length;
    if (!passwordAllowed) return path === "/admin" ? inlinePage(LOGIN_PAGE) : json(401, "sign in with a passkey");
    role = await passwordRole(req, env);
    if (!role) {
      const { blocked } = await throttled(req, env, "fail");
      console.warn(`admin sign-in failed: password rejected${blocked ? ", address now blocked" : ""}`);
      return wrongPassword();
    }
    await throttled(req, env, "pass");
  }
  // A viewer reads keys and usage and changes nothing. Anything that writes, or that hands out a sealed key, is the
  // owner's: a read-only account that could export the database would not be read-only.
  const viewerRead = (path === "/admin" || path === "/admin/status" || path === "/admin/health" || path === "/admin/log" || path === "/metrics" || path === "/admin/prices" || path === "/admin/report" || path === "/admin/groups" || /^\/admin\/keys(\/[\w-]+)?(\/report)?$/.test(path)) && req.method === "GET";
  if (role === "viewer" && !viewerRead) return json(403, VIEWER_READONLY);
  if (path === "/admin") return page(ADMIN_PAGE);

  if (path === "/admin/status" && req.method === "GET") {
    const failures = await (await adminStore(env, "/throttle/status")).json();
    return Response.json({
      encrypted: !!env.ENCRYPTION_KEY,
      passkeys: (await passkeys(env)).length,
      passwordFallback: env.ALLOW_PASSWORD === "true",
      role,
      viewerAccount: !!env.VIEWER_PASSWORD,
      blockedAddresses: failures.blocked,
      lastSignInFailure: failures.lastFailAt ? new Date(failures.lastFailAt).toISOString() : null,
    });
  }

  // The opt-in request log: key prefix, model, status, tokens and latency, and never a prompt or a response body.
  if (path === "/admin/log" && req.method === "GET") {
    const limit = Number(url.searchParams.get("limit")) || 50;
    const log = await (await adminStore(env, "/log", { get: limit })).json();
    return Response.json({ enabled: env.REQUEST_LOG === "true", ...log });
  }

  // Prometheus text for an external monitor. Everything here is derived from the request log, so a deployment with
  // the log switched off reports that rather than inventing zeroes.
  if (path === "/metrics" && req.method === "GET") {
    return new Response(await metrics(env), { headers: { "content-type": "text/plain; version=0.0.4; charset=utf-8" } });
  }

  // Is every provider the stored keys point at still answering? One HEAD per host, cached for a minute in the DO.
  if (path === "/admin/health" && req.method === "GET") {
    return Response.json(await health(env, { refresh: url.searchParams.get("refresh") === "1" }));
  }

  // The whole set of key records (sealed keys included) and their usage, for a Disaster Recovery dump.
  // Restore with `node scripts/restore.mjs dump.json`. Everything a restore needs is here: the record, the KV
  // expiry (derived exactly as `save()` derives it) and the listing metadata, which the record alone cannot rebuild.
  if (path === "/admin/export" && req.method === "GET") {
    const keys = [];
    let cursor;
    do {
      const page = await env.KEYS.list({ prefix: "sk-gw-", cursor, limit: PAGE_SIZE });
      keys.push(...(await Promise.all(page.keys.map(async (k) => {
        const record = await env.KEYS.get(k.name, "json");
        return {
          id: k.name,
          record,
          metadata: k.metadata ?? null,
          expiration: record?.expires ? Math.floor((Date.parse(record.expires) + RETAIN) / 1000) : null,
          usage: await (await meter(env, k.name, "/")).json(),
        };
      }))));
      cursor = page.list_complete ? null : page.cursor;
    } while (cursor);
    await audit(env, role, "export database", `${keys.length} keys`);
    return Response.json({ exported: new Date().toISOString(), prices: await prices(env), sealed: true, keys });
  }

  if (path === "/admin/audit" && req.method === "GET") {
    const limit = Number(url.searchParams.get("limit")) || 100;
    const skip = Number(url.searchParams.get("skip")) || 0;
    return Response.json(await (await adminStore(env, "/audit", { limit, skip })).json());
  }
  if (path === "/admin/audit.csv" && req.method === "GET") {
    const { entries } = await (await adminStore(env, "/audit", { limit: 500 })).json();
    const cell = (v) => (/[",\r\n]/.test(String(v)) ? '"' + String(v).replaceAll('"', '""') + '"' : String(v));
    const rows = [["at", "role", "action", "target"], ...entries.map((e) => [e.at, e.role, e.action, e.target])];
    return new Response(rows.map((r) => r.map(cell).join(",")).join("\n") + "\n", {
      headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="keyrouter-audit.csv"', "cache-control": "no-store" },
    });
  }
  if (path === "/admin/export" && req.method === "GET") {
    const keys = [];
    let cursor;
    do {
      const page = await env.KEYS.list({ prefix: "sk-gw-", cursor, limit: PAGE_SIZE });
      keys.push(...(await Promise.all(page.keys.map(async (k) => ({
        id: k.name,
        record: await env.KEYS.get(k.name, "json"),
        usage: await (await meter(env, k.name, "/")).json(),
      })))));
      cursor = page.list_complete ? null : page.cursor;
    } while (cursor);
    await audit(env, role, "export database", `${keys.length} keys`);
    return Response.json({ exported: new Date().toISOString(), prices: await prices(env), sealed: true, keys });
  }

  if (path === "/admin/keys" && req.method === "GET") {
    // Search and state filter over the listing. Metadata carries the label, the provider base and the expiry, so a
    // filter needs no record read — only the page it lands on costs one meter request per key.
    const q = (url.searchParams.get("q") || "").trim().toLowerCase();
    const state = url.searchParams.get("state") || "all";
    const active = (md) => !md?.expired && Date.now() < Date.parse(md?.expires || 0);
    const hits = (md) => (!q ? true : [md?.label, md?.base].some((v) => String(v || "").toLowerCase().includes(q))) &&
      (state === "active" ? active(md) : state === "expired" ? !active(md) : true);

    // A filtered page can only be honest if it knows the whole list, so the scan walks the keys (bounded) and the
    // page is a slice of that. `cursor` in the request is this page's offset in the matched list, not a KV cursor:
    // a keyspace scan is cheap (one list call per 200 keys) and an offset is the only paging that survives filtering.
    const matched = [];
    let kvCursor;
    let scanned = 0;
    let complete = false;
    do {
      const list = await env.KEYS.list({ prefix: "sk-gw-", cursor: kvCursor, limit: 200 });
      for (const k of list.keys) {
        scanned++;
        if (hits(k.metadata)) matched.push(k);
        if (scanned >= SCAN_MAX) break;
      }
      kvCursor = list.list_complete ? undefined : list.cursor;
      complete = list.list_complete === true;
    } while (kvCursor && scanned < SCAN_MAX);

    const from = Math.max(0, Number(url.searchParams.get("cursor")) || 0);
    const slice = matched.slice(from, from + PAGE_SIZE);
    const keys = await Promise.all(slice.map(async (k) => {
      // `rev` is a storage stamp for ordering the report, not something a caller needs.
      const { rev, ...listed } = k.metadata || {};
      void rev;
      return {
      id: k.name,
      ...listed,
      active: active(k.metadata),
      usage: await (await meter(env, k.name, "/")).json(),
      };
    }));
    return Response.json({
      keys,
      total: matched.length,
      scanned,
      truncated: !complete,
      cursor: from + PAGE_SIZE < matched.length ? String(from + PAGE_SIZE) : null,
    });
  }

  // Re-sealing every stored provider key under a new ENCRYPTION_KEY. The old secret is only ever in this request
  // and is never echoed back; the new one is verified by opening each row again before it is written.
  if (path === "/admin/reseal" && req.method === "POST" && body) {
    const from = typeof body.from === "string" && body.from ? body.from : env.ENCRYPTION_KEY;
    const to = typeof body.to === "string" ? body.to : "";
    if (!from) return json(400, "there is no old passphrase: set ENCRYPTION_KEY, or send { from }");
    if (to.length < 16) return json(400, "the new passphrase must be at least 16 characters");
    if (from === to) return json(400, "the new passphrase must differ from the old one");
    return Response.json(await reseal(env, from, to, role));
  }

  if (path === "/admin/keys" && req.method === "POST" && body) {
    // The password alone must not be able to mint keys; a passkey is the only factor that cannot be guessed.
    if (env.ALLOW_PASSWORD !== "true" && !(await passkeys(env)).length) {
      return json(403, "add a passkey before creating keys: use the passkeys card below, or set the ALLOW_PASSWORD secret to true for a password-only deployment");
    }
    // A duplicate may reuse the real key of the key it copies, so the browser never needs it.
    const source = !body.key && KEY_ID.test(body.from || "") ? await env.KEYS.get(body.from, "json") : null;
    const plain = body.key || (source && (await unseal(env, body.from, source.key)));
    if (!baseOk(env, body.base) || !plain) return json(400, BASE_HINT);
    const count = body.count ?? 1;
    if (!Number.isInteger(count) || count < 1 || count > BATCH_MAX) return json(400, `you can create 1 to ${BATCH_MAX} keys at once`);
    const s = settings(body);
    if (s.error) return json(400, s.error);
    const misfit = signingFits(body.base, s);
    if (misfit) return json(400, misfit);
    const made = [];
    for (let i = 1; i <= count; i++) {
      const id = newId();
      const label = count > 1 ? `${s.label || "key"} ${i}` : s.label;
      try {
        made.push(await save(env, id, { base: body.base.replace(/\/+$/, ""), key: await seal(env, id, plain), ...s, label }));
      } catch (e) {
        // A refused storage write is a limit, not a bug: say which limit, and hand back whatever did get stored.
        return json(503, /** @type {Error} */ (e).message, count > 1 && made.length ? { "x-keys-created": String(made.length) } : undefined);
      }
    }
    await audit(env, role, count > 1 ? "create batch" : "create key", count > 1 ? `${count} keys` : made[0].id);
    return Response.json(count > 1 ? { keys: made } : made[0]);
  }

  const one = path.match(/^\/admin\/keys\/(sk-gw-[0-9a-f]{32})(\/usage|\/share|\/revoke|\/report)?$/);
  const id = one?.[1];
  if (one && !one[2] && req.method === "GET") {
    const route = await env.KEYS.get(id, "json");
    if (!route) return json(404, "no key with that id");
    const { key, ...visible } = route;
    return Response.json({ id, ...visible, active: !!key && Date.now() < Date.parse(route.expires), usage: await (await meter(env, id, "/")).json() });
  }
  if (one && !one[2] && req.method === "PATCH" && body) {
    const route = await env.KEYS.get(id, "json");
    if (!route?.key || !(Date.now() < Date.parse(route.expires))) return json(404, "no active key with that id");
    if (body.base && !baseOk(env, body.base)) return json(400, "the endpoint must be an https URL");
    const plain = body.key || (await unseal(env, id, route.key));
    if (!plain) return json(400, "the stored key cannot be decrypted; enter the real key again");
    const s = settings({ ...route, ...body });
    if (s.error) return json(400, s.error);
    const misfit = signingFits(body.base || route.base, s);
    if (misfit) return json(400, misfit);
    const saved = await save(env, id, { base: body.base ? body.base.replace(/\/+$/, "") : route.base, key: await seal(env, id, plain), ...s });
    await audit(env, role, "edit key", id);
    return Response.json(saved);
  }
  if (one?.[2] === "/revoke" && req.method === "POST") {
    const route = await env.KEYS.get(id, "json");
    if (!route) return json(404, "no key with that id");
    await audit(env, role, "revoke key", id);
    return Response.json(await markRevoked(env, id, route));
  }
  if (one && !one[2] && req.method === "DELETE") {
    // Revoke now: mark the record first, then drop the entry, so any location still holding a copy is already refused.
    const route = await env.KEYS.get(id, "json");
    if (route) await markRevoked(env, id, route);
    await env.KEYS.delete(id);
    await meter(env, id, "/", { method: "DELETE" });
    await audit(env, role, "delete key", id);
    return Response.json({ ok: true });
  }
  // Group budgets: one spend cap shared by every key pointed at the same host.
  if (path === "/admin/groups" && req.method === "GET") {
    const caps = await groupCaps(env);
    const groups = [];
    for (const [host, capUsd] of Object.entries(caps)) {
      const stored = await (await meter(env, groupId(host), "/")).json();
      const used = usedIn(stored, "lifetime");
      const requests = Object.values(stored.total || {}).reduce((s, m) => s + m.requests, 0);
      groups.push({ host, capUsd, usage: { requests, spent_usd: used.usd } });
    }
    return Response.json({ groups });
  }
  if (path === "/admin/groups" && req.method === "POST") {
    if (role !== "owner") return json(403, VIEWER_READONLY);
    const body = await req.json().catch(() => null);
    const host = String(body?.host || "").trim().toLowerCase();
    if (!HOST.test(host)) return json(400, "give the provider's host name, such as api.anthropic.com");
    const amount = Number(body?.capUsd);
    if (!(amount >= 0) || !Number.isFinite(amount)) return json(400, "the budget must be a number of dollars, or 0 to remove it");
    const caps = await groupCaps(env);
    if (amount > 0) caps[host] = amount;
    else delete caps[host];
    await env.KEYS.put(GROUP_KEY, JSON.stringify(caps));
    const touched = await applyGroupCaps(env, caps);
    await audit(env, role, amount > 0 ? "set group budget" : "clear group budget", `${host} ${amount > 0 ? "$" + amount : ""}`.trim());
    return Response.json({ ok: true, host, capUsd: caps[host] ?? null, updated: touched[host] || 0, groups: Object.keys(caps) });
  }

  // The whole deployment's report: the same numbers per key, summed. Bounded like the listing, because each
  // key costs one Durable Object call and a request has 50 subrequests.
  if (path === "/admin/report" && req.method === "GET") {
    const days = Math.max(1, Number(url.searchParams.get("days")) || 7);
    return Response.json(await digest(env, days, { q: url.searchParams.get("q") || "" }));
  }

  // The daily/weekly report: spend, tokens, top models, refusals and downgrades over the last N days.
  if (one?.[2] === "/report" && req.method === "GET") {
    const days = Math.max(1, Number(url.searchParams.get("days")) || 7);
    return Response.json(await (await meter(env, id, "/report?days=" + days)).json());
  }
  if (one?.[2] === "/usage" && req.method === "DELETE") {
    await audit(env, role, "reset usage", id);
    return meter(env, id, "/reset", { method: "POST" });
  }
  if (one?.[2] === "/share" && req.method === "POST" && body) {
    const route = await env.KEYS.get(id, "json");
    if (!route?.key || !(Date.now() < Date.parse(route.expires))) return json(404, "no active key with that id");
    const exp = Math.min(Date.now() + 864e5, Date.parse(route.expires));
    const { token } = await (await adminStore(env, "/share/create", { id, exp })).json();
    await audit(env, role, "share link", id);
    return Response.json({ url: `${url.origin}/share/${token}`, expires: new Date(exp).toISOString() });
  }

  // Lists a provider's models. Given an existing key id, the stored real key is used and never reaches the browser.
  if (path === "/admin/models" && req.method === "POST" && body) {
    const stored = KEY_ID.test(body.id || "") ? await env.KEYS.get(body.id, "json") : null;
    const route = body.key ? body : stored && { ...stored, key: await unseal(env, body.id, stored.key), ...(body.base && { base: body.base }), ...(body.auth && { auth: body.auth }) };
    if (!route?.key || !baseOk(env, route.base) || !validAuth(route.auth ?? "bearer")) return json(400, "need an https endpoint, an API key and a valid auth style");
    const base = route.base.replace(/\/+$/, "");
    const anthropic = route.auth === "x-api-key";
    const headers = new Headers([authHeader(route.auth, route.key)]);
    if (anthropic) headers.set("anthropic-version", "2023-06-01");
    let res;
    try {
      res = await fetch(base + "/models" + (anthropic ? "?limit=1000" : ""), { headers, redirect: "manual", signal: AbortSignal.timeout(15e3) });
    } catch (e) {
      const err = /** @type {Error} */ (e);
      return json(502, `could not reach ${base}: ${err.message}`);
    }
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      const why = data?.error?.message || (typeof data?.error === "string" && data.error) || `no model list at ${base}/models`;
      return json(502, `provider answered ${res.status}: ${why}`);
    }
    const list = data.data || data.models || (Array.isArray(data) ? data : []);
    const ids = list.map((m) => (typeof m === "string" ? m : m?.id ?? m?.name)).filter((m) => typeof m === "string");
    return Response.json({ models: [...new Set(ids)].sort() });
  }

  // Rotation: a holder asks, an owner issues. Approving mints a new key with the same settings and real key, and
  // leaves the old one alive for one hour so a running client has time to pick up the new value.
  if (path === "/admin/rotations" && req.method === "GET") {
    const { rotations, pending } = await (await adminStore(env, "/rotation", {})).json();
    return Response.json({
      pending,
      rotations: await Promise.all(rotations.map(async (r) => {
        const route = await env.KEYS.get(r.id, "json");
        return { ...r, label: r.label || route?.label || "", active: !!route?.key && Date.now() < Date.parse(route?.expires || 0) };
      })),
    });
  }
  const rotation = path.match(/^\/admin\/rotations\/(sk-gw-[0-9a-f]{32})(\/approve|\/deny)?$/);
  if (rotation && req.method === "POST") {
    const [, oldId, what = "/approve"] = rotation;
    const route = await env.KEYS.get(oldId, "json");
    if (!route) return json(404, "no key with that id");
    await adminStore(env, "/rotation", { done: oldId });
    if (what === "/deny") {
      await audit(env, role, "deny rotation", oldId);
      return Response.json({ ok: true, denied: oldId });
    }
    // The new key is the same key with a new value: every setting and the sealed real key carry over.
    const grace = Date.now() + 3600e3;
    const kept = Math.max(Date.parse(route.expires), Date.now() + 864e5);
    const next = newId();
    const plain = await unseal(env, oldId, route.key);
    if (!plain) return json(400, "the stored key cannot be decrypted; enter the real key again");
    const { rev, revoked_at, expired, ...carried } = route;
    await save(env, next, { ...carried, key: await seal(env, next, plain), expires: new Date(kept).toISOString() });
    // The old key stops an hour from now, whatever its own expiry was: a rotation is a change of secret.
    await save(env, oldId, { ...route, expires: new Date(Math.min(grace, Date.parse(route.expires))).toISOString() });
    const exp = Math.min(grace, Date.parse(route.expires));
    const { token } = await (await adminStore(env, "/share/create", { id: next, exp: kept })).json();
    await audit(env, role, "rotate key", oldId);
    return Response.json({
      old: { id: oldId, expires: new Date(exp).toISOString() },
      new: { id: next, expires: new Date(kept).toISOString() },
      url: `${url.origin}/share/${token}`,
    });
  }

  if (path === "/admin/prices" && req.method === "GET") return Response.json({ prices: await prices(env), defaults: PRICES, version: priceVersion() });
  if (path === "/admin/prices/openrouter" && req.method === "GET") {
    const rows = await openRouterPrices();
    return rows ? Response.json({ prices: rows }) : json(502, "could not read OpenRouter's model list");
  }
  if (path === "/admin/prices" && req.method === "PUT" && body) {
    const error = checkPrices(body.prices);
    if (error) return json(400, error);
    const rows = body.prices.map(tidyPrice);
    const version = await savePrices(env, rows);
    return Response.json({ prices: rows, version });
  }

  // One-time invite links: the owner mints one, the invitee registers a passkey and becomes a viewer.
  if (path === "/admin/invites" && req.method === "GET") {
    const invites = await (await adminStore(env, "/invites", {})).json();
    return Response.json(invites.slice().reverse().map((i) => ({ code: i.code, label: i.label, expires: i.expires, url: `${url.origin}/join?code=${i.code}` })));
  }
  if (path === "/admin/invites" && req.method === "POST" && body) {
    const code = randomHex(16);
    const label = String(body.label || "").trim().slice(0, 60);
    const expires = new Date(Date.now() + INVITE_TTL).toISOString();
    await adminStore(env, "/invites", { add: { code, label, expires } });
    await audit(env, role, "invite viewer", label || "(no name)");
    // The link is the secret; it is returned once, to the owner who asked for it.
    return Response.json({ code, label, expires, url: `${url.origin}/join?code=${code}`, max: INVITES_MAX });
  }
  const invite = path.match(/^\/admin\/invites\/([0-9a-f]{32})$/);
  if (invite && req.method === "DELETE") {
    await adminStore(env, "/invites", { remove: invite[1] });
    await audit(env, role, "cancel invite", invite[1].slice(0, 8) + "...");
    return Response.json({ ok: true });
  }
  if (path === "/admin/passkeys" && req.method === "GET") {
    return Response.json((await passkeys(env)).map(({ id, name, created }) => ({ id, name, created })));
  }
  if (path === "/admin/passkeys/options" && req.method === "POST" && body) {
    const { challenge } = await (await adminStore(env, "/challenge", {})).json();
    return Response.json({ challenge, rp: { id: url.hostname, name: "KeyRouter" }, exclude: (await passkeys(env)).map((p) => p.id) });
  }
  if (path === "/admin/passkeys" && req.method === "POST" && body) {
    const alg = Number(body.alg);
    if (!ALGS[alg] || !/^[\w-]{16,1400}$/.test(body.id || "")) return json(400, "this passkey type is not supported");
    try {
      if (!(await clientData(env, url, body.clientDataJSON, "webauthn.create"))) return json(400, "passkey registration expired or came from another site");
      await crypto.subtle.importKey("spki", unb64u(body.publicKey), ALGS[alg][0], false, ["verify"]);
    } catch {
      return json(400, "the passkey's public key could not be read");
    }
    const name = String(body.name || "Passkey").slice(0, 60);
    await adminStore(env, "/passkeys", { add: { id: body.id, publicKey: body.publicKey, alg, name, created: new Date().toISOString() } });
    // The password stops working once a passkey exists, so the current browser gets a session right away.
    return Response.json({ ok: true }, { headers: { "set-cookie": await newSession(env) } });
  }
  const pk = path.match(/^\/admin\/passkeys\/([\w-]{16,1400})$/);
  if (pk && req.method === "DELETE") {
    await adminStore(env, "/passkeys", { remove: pk[1] });
    return Response.json({ ok: true });
  }
  return json(404, "not found");
}

