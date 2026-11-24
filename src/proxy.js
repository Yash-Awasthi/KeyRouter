// The client-facing side: the proxy itself, the key holder's own usage page and share links.
import { adminStore } from "./auth.js";
import { SHARE_PAGE, USAGE_PAGE, inlinePage } from "./pages.js";
import { unseal } from "./crypto.js";
import { requestLog } from "./log.js";
import { sigv4 } from "./sigv4.js";
import { cors, json } from "./http.js";
import { LIMITS, OUTPUT_FIELDS, RETAIN, meter, meterable, modelInPath, modelRows, recordStream, resetAt, usedIn } from "./meter.js";
import { DAYS, baseOk, groupId, hostOf, inRange, validBase, withinHours } from "./net.js";
import { prices, rememberPrices } from "./pricing.js";

export const KEY_ID = /^sk-gw-[0-9a-f]{32}$/;
// Header the real key travels in: Bearer (OpenAI style), Anthropic, Azure, Gemini.
export const AUTH_STYLES = ["bearer", "x-api-key", "api-key", "x-goog-api-key"];
// Client identity, cookies and the gateway key itself must never reach the provider.
const STRIP = /^(cf-|x-forwarded-|x-real-ip$|cookie$|origin$|referer$|authorization$|x-api-key$|api-key$|x-goog-api-key$)/;
// Workers Free allows 50 subrequests per request; each listed key costs one, each created key two.

export const allowed = (patterns, model) =>
  typeof model === "string" && patterns.some((p) => (p.endsWith("*") ? model.startsWith(p.slice(0, -1)) : p === model));

// A style is "bearer", a header name ("x-token"), or "header:Scheme" ("authorization:Token") for a prefixed value.
const AUTH_CUSTOM = /^[a-z0-9-]{1,64}(:[\w.-]{1,32})?$/i;
const NOT_AUTH = /^(host|content-length|content-type|transfer-encoding|connection|accept|accept-encoding|anthropic-version|cookie|origin|referer|cf-|x-forwarded-|x-real-ip)/i;
export const validAuth = (s) => AUTH_STYLES.includes(s) || (typeof s === "string" && AUTH_CUSTOM.test(s) && !NOT_AUTH.test(s));
/** @returns {[string, string]} */
export function authHeader(style = "bearer", key) {
  if (style === "bearer") return ["authorization", `Bearer ${key}`];
  const [name, scheme] = style.split(":");
  return [name, scheme ? `${scheme} ${key}` : key];
}


function presentedKey(req, url) {
  const h = req.headers;
  // Gemini clients may send the key as ?key=, which must not travel on to the provider.
  const query = new URLSearchParams(url.search);
  const queryKey = query.get("key");
  query.delete("key");
  const search = queryKey === null ? url.search : query.size ? "?" + query : "";
  const presented = h.get("authorization")?.replace(/^Bearer\s+/i, "") || h.get("x-api-key") || h.get("api-key") || h.get("x-goog-api-key") || queryKey || "";
  return { presented, search, queryKey };
}

// A key in the URL lands in proxy logs, browser history and Referer headers, so it is refused unless opted in.
const QUERY_KEY_HINT = "send the gateway key in the authorization or x-api-key header; a key in the query string leaks through logs, history and referrers";
function queryKeyRefused(env, queryKey) {
  if (queryKey === null) return null;
  if (env.ALLOW_QUERY_KEY === "true") {
    // Only the prefix is logged: enough to find the call, useless as a credential.
    console.warn(`accepted a gateway key from the query string (${String(queryKey).slice(0, 9)}...): URLs leak through logs, history and referrers`);
    return null;
  }
  console.warn("refused a gateway key in the query string; set ALLOW_QUERY_KEY=true only for Gemini clients that cannot send a header");
  return json(400, QUERY_KEY_HINT);
}

/**
 * Where the request actually goes. Azure OpenAI names the deployment in the path — /openai/deployments/<name>/chat/completions —
 * and refuses a call without an api-version, so both are added here from the key's own settings rather than trusted from
 * the client. Every other provider gets base + path, unchanged.
 */
function upstreamUrl(route, path, search) {
  if (!route.azure) return route.base + path + search;
  const { deployment, apiVersion } = route.azure;
  const query = new URLSearchParams(search);
  if (!query.get("api-version")) query.set("api-version", apiVersion);
  return `${route.base}/openai/deployments/${deployment}${path}?${query}`;
}

/**
 * AWS refuses an unsigned request, and the signature is computed over the exact body bytes, so signing happens after
 * every rewrite — the model may have been swapped and max_tokens clamped. The stored secret is the AWS secret access
 * key and the access key id travels in the key's settings.
 */
async function awsSigned(route, method, target, headers, body, secret) {
  const { region, service, accessKeyId, sessionToken } = route.aws;
  const bytes = body == null ? "" : body instanceof ArrayBuffer ? new Uint8Array(body) : body;
  const signed = await sigv4({ method, url: target, headers: Object.fromEntries(headers), body: bytes, region, service, accessKeyId, secretKey: secret, sessionToken });
  headers.delete("authorization");
  // `host` is forbidden on a Headers object: fetch sets it from the URL, and it is already in the signature.
  for (const [k, v] of Object.entries(signed)) if (k !== "host") headers.set(k, v);
  return headers;
}

/**
 * Ask the meter for a verdict. A meter that cannot answer is not permission to spend: the caller gets null and
 * the request is refused, so an unreachable Durable Object can never turn a cap into a bypass.
 * @returns {Promise<Response|null>}
 */
async function admit(env, id, body) {
  try {
    return await meter(env, id, "/admit", { method: "POST", body: JSON.stringify(body) });
  } catch {
    return null;
  }
}

/**
 * The meter could not be reached. Refusing is the whole point: a cap that cannot be checked must not be assumed
 * to have room, or an outage becomes a spending spree.
 */
function refuseMeter(req, presented, started, note) {
  note({ key: presented.slice(0, 13), status: 503, event: "refused", model: null, ms: Date.now() - started });
  return cors(json(503, "the meter is unavailable, so this call is refused rather than admitted uncounted", { "retry-after": "30" }), req);
}

export async function proxy(req, env, url, ctx) {
  if (req.method === "OPTIONS") return cors(new Response(null, { status: 204 }), req);
  const started = Date.now();
  // Opt-in: one request-log line per call, and nothing at all when it is off.
  const logging = env.REQUEST_LOG === "true";
  const note = (entry) => {
    if (logging && ctx?.waitUntil) ctx.waitUntil(requestLog(env, { at: started, ...entry }));
  };
  const { presented, search, queryKey } = presentedKey(req, url);
  const refused = queryKeyRefused(env, queryKey);
  if (refused) return cors(refused, req);
  // Only well-formed ids reach KV, so random tokens cannot burn the daily KV read quota.
  const route = KEY_ID.test(presented) ? await env.KEYS.get(presented, "json") : null;
  // A revoked key is refused even when a stale copy still carries the real key.
  if (route?.revoked_at || !route?.key || !(Date.now() < Date.parse(route.expires))) return cors(json(401, "invalid or expired key"), req);
  if (route.headerOnly && queryKey !== null) return cors(json(401, "this key only works in a header, never in a URL"), req);

  if (route.ips?.length) {
    const ip = req.headers.get("cf-connecting-ip") || "";
    if (!route.ips.some((r) => inRange(ip, r))) return cors(json(403, `this key cannot be used from ${ip || "an unknown address"}`), req);
  }
  if (route.hours && !withinHours(route.hours, new Date(Date.now()))) {
    const { days, start, end, tz } = route.hours;
    return cors(json(403, `this key only works ${days.map((d) => DAYS[d]).join(", ")} ${start}-${end} (${tz})`), req);
  }
  const realKey = await unseal(env, presented, route.key);
  if (!realKey) return cors(json(500, "the stored provider key cannot be decrypted; check ENCRYPTION_KEY"), req);

  // Clients use <gateway>/v1; the stored base is the provider's own base URL, which may end in /v1, /v4 or nothing.
  const path = url.pathname.replace(/^\/v1(?=\/|$)/, "");
  // A cap that silently does not apply is worse than no cap: refuse what cannot be counted.
  // Only requests that can cost money are refused; listing models or files stays free.
  if (req.method === "POST" && (route.capUsd || route.capTokens) && !meterable(path)) {
    return cors(json(403, `${path} returns no token usage, so this key's cap cannot be enforced on it; use a key without a cap for this endpoint`), req);
  }
  let body = req.body;
  let parsed;
  if (req.method === "POST" && (route.models?.length || route.maxOutput || route.downgrade || path === "/chat/completions")) {
    // Bytes, not text, so non-JSON uploads such as audio pass through unchanged.
    body = await req.arrayBuffer();
    try { parsed = JSON.parse(new TextDecoder().decode(body)); } catch {}
    if (typeof parsed !== "object" || parsed === null) parsed = undefined;
    // Gemini's native API names the model in the path: /models/<name>:generateContent.
    const model = parsed?.model ?? modelInPath(path);
    if (route.models?.length && !allowed(route.models, model) && !allowed(route.models, "models/" + model)) {
      return cors(json(403, `model ${model ?? "(none)"} is not allowed for this key`), req);
    }
  }
  let changed = false;
  let downgraded;
  // A budget on the host is shared by every key pointed at it, so it is admitted against the group's own meter.
  const group = route.groupCap > 0 && req.method === "POST" && meterable(path) ? groupId(hostOf(route.base)) : null;
  if (group) {
    const verdict = await admit(env, group, { capUsd: route.groupCap, period: "lifetime" });
    if (!verdict) return refuseMeter(req, presented, started, note);
    if (!verdict.ok) {
      const used = await verdict.json();
      note({ key: presented.slice(0, 13), status: 429, event: "refused", model: null, ms: Date.now() - started });
      return cors(json(429, `the shared budget for ${hostOf(route.base)} is used up (${used.spent_usd ?? "?"} of ${route.groupCap} USD)`, { "retry-after": String(used.retryAfter ?? 60) }), req);
    }
  }
  if (route.capUsd || route.capTokens || route.rpm) {
    const { capUsd, capTokens, period, rpm } = route;
    const verdict = await admit(env, presented, { capUsd, capTokens, period, rpm });
    if (!verdict) return refuseMeter(req, presented, started, note);
    if (!verdict.ok) return cors(verdict, req);
    const { used } = await verdict.json();
    // Requests already running keep their model; only requests starting past the threshold are rerouted.
    const rule = route.downgrade && used >= route.downgrade.at / 100 && route.downgrade.map.find(([from]) => allowed([from], parsed?.model));
    if (rule) {
      downgraded = `${parsed.model} -> ${rule[1]}`;
      bump(env, ctx, presented, "downgraded");
      parsed.model = rule[1];
      changed = true;
    }
  }
  if (route.maxOutput && parsed) {
    const present = OUTPUT_FIELDS.filter((f) => typeof parsed[f] === "number");
    for (const f of present) parsed[f] = Math.min(parsed[f], route.maxOutput);
    if (!present.length && path === "/responses") parsed.max_output_tokens = route.maxOutput;
    else if (!present.length && (path === "/chat/completions" || path === "/completions")) parsed.max_tokens = route.maxOutput;
    else if (/:(stream)?[Gg]enerateContent$/.test(path)) {
      const g = (parsed.generationConfig ||= {});
      g.maxOutputTokens = Math.min(typeof g.maxOutputTokens === "number" ? g.maxOutputTokens : Infinity, route.maxOutput);
    }
    changed = true;
  }
  // OpenAI-style streams carry no token counts unless asked, and an unmetered call would slip past every cap.
  if (path === "/chat/completions" && parsed?.stream === true && parsed.stream_options?.include_usage !== true) {
    parsed.stream_options = { ...parsed.stream_options, include_usage: true };
    changed = true;
  }
  if (changed) body = JSON.stringify(parsed);

  const headers = new Headers();
  for (const [k, v] of req.headers) if (!STRIP.test(k)) headers.set(k, v);
  headers.set(...authHeader(route.auth, realKey));
  try {
    // A followed redirect would carry the real key to whatever host the provider names.
    const target = upstreamUrl(route, path, search);
    // A signature covers the exact bytes, so a body still streamed has to be in hand before it is signed.
    if (route.aws && body instanceof ReadableStream) body = await new Response(body).arrayBuffer();
    if (route.aws) await awsSigned(route, req.method, target, headers, body, realKey);
    let res = await fetch(target, { method: req.method, headers, body, redirect: "manual" });
    // A provider fault becomes one shape the caller can act on, and it is never metered: no token count is trusted
    // out of an error body, so the call costs nothing here even though the provider may still bill it.
    if (res.status >= 500) {
      note({ key: presented.slice(0, 13), model: parsed?.model ?? null, status: 502, ms: Date.now() - started, tokens: null });
      return cors(json(502, `the provider failed (${res.status}); nothing was counted`), req);
    }
    // The metered copy leaves through a tee, so the client gets its bytes as they arrive and only the few events
    // that carry a model or a usage count are ever held.
    if (ctx && req.method === "POST" && meterable(path) && res.ok && res.body) {
      const type = res.headers.get("content-type");
      const [toClient, toMeter] = res.body.tee();
      ctx.waitUntil(recordStream(env, presented, toMeter, route.base, path, route, type, group, logging ? { at: started, status: res.status, ms: 0 } : null));
      res = new Response(toClient, res);
    }
    let out = cors(res, req);
    // Clients that list models only see the ones this key may use.
    if (route.models?.length && req.method === "GET" && path === "/models" && res.ok) {
      const data = await res.clone().json().catch(() => null);
      for (const k of ["data", "models"]) if (Array.isArray(data?.[k])) data[k] = data[k].filter((m) => allowed(route.models, m.id ?? m.name));
      if (data) out = cors(Response.json(data), req);
    }
    if (downgraded) out.headers.set("x-gateway-downgrade", downgraded);
    // Everything that is not read by the meter is logged here: listings, refusals by model, and providers that say no.
    if (logging && !(req.method === "POST" && meterable(path) && res.ok && res.body)) {
      note({ key: presented.slice(0, 13), model: parsed?.model ?? null, status: res.status, ms: Date.now() - started, tokens: null });
    }
    return out;
  } catch (e) {
    const err = /** @type {Error} */ (e);
    note({ key: presented.slice(0, 13), model: parsed?.model ?? null, status: 502, ms: Date.now() - started, tokens: null });
    return cors(json(502, `upstream unreachable: ${err.message}`), req);
  }
}

// A report counter is not worth failing a request over, and the client should not wait for it.
const bump = (env, ctx, id, field) => {
  const call = meter(env, id, "/count", { method: "POST", body: JSON.stringify({ field }) }).catch(() => {});
  if (ctx?.waitUntil) ctx.waitUntil(call);
};

// Lets a key holder check their own budget, either as JSON (with the key) or through a small page (without).
/**
 * A key holder asks for a new key. Nothing secret is returned: the request only queues work for the owner, who is
 * the one who can mint a key. The real provider key is never touched or copied here.
 */
export async function rotate(req, env, url) {
  if (req.method === "OPTIONS") return cors(new Response(null, { status: 204 }), req);
  if (req.method !== "POST") return cors(json(405, "use POST to ask for a new key"), req);
  const { presented, queryKey } = presentedKey(req, url);
  const refused = queryKeyRefused(env, queryKey);
  if (refused) return cors(refused, req);
  const route = presented && KEY_ID.test(presented) ? await env.KEYS.get(presented, "json") : null;
  if (!route || route.revoked_at || !(Date.now() < Date.parse(route.expires))) return cors(json(401, "invalid key"), req);
  if (route.headerOnly && queryKey !== null) return cors(json(401, "this key only works in a header, never in a URL"), req);
  const answer = await (await adminStore(env, "/rotation", { request: presented, label: route.label || "" })).json();
  return cors(Response.json({
    ok: true,
    requested: answer.at,
    pending: answer.pending,
    note: "an owner has to issue the new key. This key keeps working for an hour after they approve, then stops.",
  }, { headers: { "cache-control": "no-store" } }), req);
}

export async function usage(req, env, url) {
  if (req.method === "OPTIONS") return cors(new Response(null, { status: 204 }), req);
  const { presented, queryKey } = presentedKey(req, url);
  const refused = queryKeyRefused(env, queryKey);
  if (refused) return cors(refused, req);
  if (!presented) return inlinePage(USAGE_PAGE);
  const route = KEY_ID.test(presented) ? await env.KEYS.get(presented, "json") : null;
  if (!route || route.revoked_at) return cors(json(401, "invalid key"), req);
  if (route.headerOnly && queryKey !== null) return cors(json(401, "this key only works in a header, never in a URL"), req);
  const metered = await (await meter(env, presented, "/")).json();
  const used = usedIn(metered, route.period);
  const { capUsd = null, capTokens = null, rpm = null, maxOutput = null, period = "total" } = route;
  return cors(Response.json({
    label: route.label || "",
    active: !!route.key && Date.now() < Date.parse(route.expires),
    expires: route.expires,
    period,
    used,
    spent_usd: used.usd,
    cap_usd: capUsd,
    over_cap: !!capUsd && used.usd >= capUsd,
    remaining: { usd: capUsd && Math.max(0, capUsd - used.usd), tokens: capTokens && Math.max(0, capTokens - used.tokens) },
    reset: resetAt(period),
    breakdown: modelRows(metered, period),
    limits: { capUsd, capTokens, rpm, maxOutput },
    models: route.models || [],
    hours: route.hours || null,
    downgrade: route.downgrade ? { at: route.downgrade.at, map: route.downgrade.map } : null,
  }, { headers: { "cache-control": "no-store" } }), req);
}

export async function claimShare(req, env, url, token) {
  if (req.method === "GET") return inlinePage(SHARE_PAGE);
  if (req.method !== "POST") return json(405, "use POST to reveal the key");
  const share = await (await adminStore(env, "/share/claim", { token })).json();
  const route = share && (await env.KEYS.get(share.id, "json"));
  if (!route?.key || !(Date.now() < Date.parse(route.expires))) return json(410, "this link was already used, has expired, or its key was revoked");
  return Response.json(
    { key: share.id, endpoint: url.origin + "/v1", origin: url.origin, label: route.label || "", expires: route.expires, models: route.models || [] },
    { headers: { "cache-control": "no-store" } },
  );
}

// Validates every non-secret setting of a key.
