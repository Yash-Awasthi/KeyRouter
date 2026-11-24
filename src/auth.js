// Admin identity: the password, passkeys, invites, sessions and the sign-in throttle. The Admin Durable Object owns the
// state, because its single-use checks (a share token, a challenge) must not race and it holds the signing key.
import { b64u, enc, randomHex, sha256, unb64u, unseal } from "./crypto.js";
import { json } from "./http.js";

// Sessions are HMAC-signed expiry times; the signing key lives in the Admin Durable Object.
let sessionKeyCache = null;

const SESSION_TTL = 12 * 3600e3;

const THROTTLE = { window: 15 * 60e3, fails: 5, block: 15 * 60e3, maxBlock: 864e5, buckets: 1000 };
// How many audit entries are kept; the newest win and the oldest are dropped.
const AUDIT_MAX = 500;

export class Admin {
  constructor(state) {
    this.storage = state.storage;
  }

  async fetch(req) {
    const path = new URL(req.url).pathname;
    const body = req.method === "POST" ? await req.json() : {};
    if (path === "/share/create") {
      const shares = await this.live("shares");
      const token = randomHex(16);
      shares[token] = { id: body.id, exp: body.exp };
      await this.storage.put("shares", shares);
      return Response.json({ token });
    }
    if (path === "/share/claim") {
      const shares = await this.live("shares");
      const share = Object.hasOwn(shares, body.token) ? shares[body.token] : null;
      delete shares[body.token];
      await this.storage.put("shares", shares);
      return Response.json(share);
    }
    if (path === "/challenge") {
      // Anyone can ask for a sign-in challenge, so only the newest few are kept.
      const recent = Object.entries(await this.live("challenges")).sort((a, b) => b[1].exp - a[1].exp).slice(0, 19);
      const challenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
      await this.storage.put("challenges", { ...Object.fromEntries(recent), [challenge]: { exp: Date.now() + 5 * 60e3 } });
      return Response.json({ challenge });
    }
    if (path === "/consume") {
      const challenges = await this.live("challenges");
      const ok = Object.hasOwn(challenges, body.challenge);
      delete challenges[body.challenge];
      await this.storage.put("challenges", challenges);
      return Response.json({ ok });
    }
    // An invite is a code that lets one person register one passkey, with the role the owner chose. It expires,
    // and registering consumes it, so a leaked link stops working both when it is used and when it goes stale.
    if (path === "/invites") {
      let invites = (await this.storage.get("invites")) || [];
      const now = Date.now();
      invites = invites.filter((i) => Date.parse(i.expires) > now);
      if (body.add) {
        invites = [...invites.filter((i) => i.code !== body.add.code), body.add].slice(-INVITES_MAX);
        await this.storage.put("invites", invites);
      }
      if (body.take) {
        const found = invites.find((i) => i.code === body.take);
        invites = invites.filter((i) => i.code !== body.take);
        if (found) await this.storage.put("invites", invites);
        return Response.json({ invite: found || null });
      }
      if (body.remove) {
        invites = invites.filter((i) => i.code !== body.remove);
        await this.storage.put("invites", invites);
      }
      return Response.json(invites);
    }
    if (path === "/passkeys") {
      let passkeys = (await this.storage.get("passkeys")) || [];
      if (body.add) passkeys = [...passkeys.filter((p) => p.id !== body.add.id), body.add];
      if (body.remove) passkeys = passkeys.filter((p) => p.id !== body.remove);
      if (body.add || body.remove) await this.storage.put("passkeys", passkeys);
      return Response.json(passkeys);
    }
    if (path === "/session-key") {
      let key = await this.storage.get("sessionKey");
      if (!key) await this.storage.put("sessionKey", (key = b64u(crypto.getRandomValues(new Uint8Array(32)))));
      return Response.json({ key });
    }
    if (path === "/audit") {
      // Append-only in the sense that matters: no route rewrites or deletes an entry. The log keeps the newest
      // AUDIT_MAX entries and drops the oldest, so a busy deployment cannot fill Durable Object storage with it.
      const log = (await this.storage.get("audit")) || [];
      if (body.add) {
        log.push(body.add);
        if (log.length > AUDIT_MAX) log.splice(0, log.length - AUDIT_MAX);
        await this.storage.put("audit", log);
        return Response.json({ ok: true, kept: log.length });
      }
      const limit = Math.min(AUDIT_MAX, Math.max(1, Number(body.limit) || 100));
      // Newest first, and `skip` walks that order, so a page of the log is a page of the newest entries.
      const skip = Math.max(0, Number(body.skip) || 0);
      return Response.json({ entries: log.slice().reverse().slice(skip, skip + limit), kept: log.length });
    }
    if (path === "/rotation") {
      // A key holder can ask for a new key; only an owner can issue one. Requests are a small map, newest last,
      // bounded like the other lists here, and one request per key: asking twice is the same as asking once.
      const requests = (await this.storage.get("rotations")) || {};
      if (body.request) {
        requests[body.request] = { id: body.request, at: new Date().toISOString(), label: String(body.label || "").slice(0, 100) };
        const kept = Object.entries(requests).sort((a, b) => b[1].at.localeCompare(a[1].at)).slice(0, 100);
        await this.storage.put("rotations", Object.fromEntries(kept));
        return Response.json({ ok: true, at: requests[body.request].at, pending: kept.length });
      }
      if (body.done) {
        const at = requests[body.done]?.at ?? null;
        delete requests[body.done];
        await this.storage.put("rotations", requests);
        return Response.json({ ok: true, at, pending: Object.keys(requests).length });
      }
      return Response.json({ rotations: Object.values(requests).sort((a, b) => b.at.localeCompare(a.at)), pending: Object.keys(requests).length });
    }
    if (path === "/log") {
      // Opt-in and bounded twice: by count, because storage is not free, and by age, because the promise is a week.
      const entries = (await this.storage.get("log")) || [];
      if (body.add) {
        entries.push(body.add);
        const cutoff = Date.now() - LOG_TTL;
        await this.storage.put("log", entries.filter((e) => e.at >= cutoff).slice(-LOG_MAX));
        return Response.json({ ok: true });
      }
      // The reader gets the newest first, and only as many as it asked for.
      const limit = Math.min(Math.max(Number(body.get) || 50, 1), LOG_MAX);
      return Response.json({ entries: entries.slice(-limit).reverse(), kept: entries.length });
    }
    if (path === "/health") {
      // The last probe result, so an admin page that is reloaded during an outage does not probe the providers again.
      if (body.put) {
        await this.storage.put("health", body.put);
        return Response.json({ ok: true });
      }
      return Response.json((await this.storage.get("health")) || { at: 0, checks: [] });
    }
    if (path === "/throttle") return Response.json(await this.throttle(body));
    if (path === "/throttle/status") {
      const { ips = {}, lastFailAt = 0 } = (await this.storage.get("throttle")) || {};
      const now = Date.now();
      return Response.json({ blocked: Object.values(ips).filter((r) => r.blockedUntil > now).length, lastFailAt: lastFailAt || null });
    }
    return json(404, "not found");
  }

  // Sign-in attempts per hashed address. The address itself never reaches this Durable Object.
  async throttle({ ipHash, outcome }) {
    const now = Date.now();
    const state = (await this.storage.get("throttle")) || { ips: {}, lastFailAt: 0 };
    let rec = state.ips[ipHash] || { fails: 0, firstAt: now, blockedUntil: 0 };
    // A block ends on time and the window restarts, but the failure count stays so repeat offenders escalate.
    if (rec.blockedUntil && now >= rec.blockedUntil) {
      rec.blockedUntil = 0;
      rec.firstAt = now;
    }
    if (now - rec.firstAt > THROTTLE.window) {
      rec.fails = 0;
      rec.firstAt = now;
    }
    if (outcome === "fail" && !rec.blockedUntil) {
      rec.fails++;
      if (rec.fails >= THROTTLE.fails) rec.blockedUntil = now + Math.min(THROTTLE.block * 2 ** (rec.fails - THROTTLE.fails), THROTTLE.maxBlock);
      state.lastFailAt = now;
    }
    if (outcome === "pass") rec = { fails: 0, firstAt: now, blockedUntil: 0 };
    if (rec.fails || rec.blockedUntil) state.ips[ipHash] = rec;
    else delete state.ips[ipHash];
    // Only the newest buckets are kept, so a flood of addresses cannot grow storage without bound.
    const entries = Object.entries(state.ips).sort((a, b) => b[1].firstAt - a[1].firstAt).slice(0, THROTTLE.buckets);
    state.ips = Object.fromEntries(entries);
    await this.storage.put("throttle", state);
    const blocked = rec.blockedUntil > now;
    return { blocked, retryAfter: blocked ? Math.ceil((rec.blockedUntil - now) / 1000) : 0 };
  }

  async live(name) {
    const all = (await this.storage.get(name)) || {};
    return Object.fromEntries(Object.entries(all).filter(([, v]) => v.exp > Date.now()));
  }
}

/** A request log entry lives for a week: long enough to explain an incident, short enough to forget about. */
const LOG_TTL = 7 * 864e5;
/** The log is a ring: the newest entries win, and a busy deployment cannot grow storage without limit. */
const LOG_MAX = 500;

export const adminStore = (env, path, body) =>
  env.ADMIN.get(env.ADMIN.idFromName("admin")).fetch("https://admin" + path, body && { method: "POST", body: JSON.stringify(body) });

export function sessionKey(env) {
  sessionKeyCache ||= adminStore(env, "/session-key")
    .then((r) => r.json())
    .then(({ key }) => crypto.subtle.importKey("raw", unb64u(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]))
    .catch((err) => {
      sessionKeyCache = null;
    });
  return sessionKeyCache;
}

// The address is hashed with a server secret, so a storage dump cannot be turned back into a list of visitors.
export async function ipHash(req, env) {
  const ip = req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";
  return b64u(await crypto.subtle.sign("HMAC", await sessionKey(env), enc("throttle:" + ip)));
}

// Records or checks a sign-in attempt; "check" never changes the bucket.
export async function throttled(req, env, outcome) {
  return (await (await adminStore(env, "/throttle", { ipHash: await ipHash(req, env), outcome })).json());
}

// One body for every unauthenticated answer, so a caller cannot tell a bad password from a block. The reason goes to the log.
export const LOGIN_REQUIRED = "login required";
export const tooMany = (retryAfter) => new Response(LOGIN_REQUIRED, { status: 429, headers: { "retry-after": String(retryAfter), "cache-control": "no-store" } });
export const wrongPassword = () => new Response(LOGIN_REQUIRED, { status: 401, headers: { "www-authenticate": 'Basic realm="KeyRouter admin"' } });

// A session carries its role in the signed text, so a viewer cannot promote itself by editing a cookie.
const ROLES = ["owner", "viewer"];

export async function newSession(env, role = "owner") {
  const exp = String(Date.now() + SESSION_TTL);
  const body = `${exp}.${role}`;
  const sig = b64u(await crypto.subtle.sign("HMAC", await sessionKey(env), enc(body)));
  return `kr_session=${body}.${sig}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL / 1000}`;
}

/** The role this request's session carries, or null when there is no valid session. */
export async function sessionRole(req, env) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)kr_session=(\d+)\.([a-z]+)\.([\w-]+)/);
  if (!m || Number(m[1]) < Date.now() || !ROLES.includes(m[2])) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await sessionKey(env), unb64u(m[3]), enc(`${m[1]}.${m[2]}`));
    return ok ? m[2] : null;
  } catch {
    return null;
  }
}

export const passkeys = async (env) => (await adminStore(env, "/passkeys", {})).json();

// WebAuthn algorithm ids: ES256, Ed25519 and RS256.
export const ALGS = {
  "-7": [{ name: "ECDSA", namedCurve: "P-256" }, { name: "ECDSA", hash: "SHA-256" }],
  "-8": [{ name: "Ed25519" }, { name: "Ed25519" }],
  "-257": [{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, { name: "RSASSA-PKCS1-v1_5" }],
};

// WebAuthn ECDSA signatures are DER sequences; WebCrypto wants the raw 64-byte r||s form.
function derToRaw(der) {
  let i = 2;
  const part = () => {
    if (der[i++] !== 2) throw new Error("bad signature");
    const v = der.slice(i + 1, (i += 1 + der[i]));
    const out = new Uint8Array(32);
    out.set(v.slice(Math.max(0, v.length - 32)), 32 - Math.min(32, v.length));
    return out;
  };
  return new Uint8Array([...part(), ...part()]);
}

export async function clientData(env, url, encoded, type) {
  const raw = unb64u(encoded);
  const data = JSON.parse(new TextDecoder().decode(raw));
  if (data.type !== type || data.origin !== url.origin) return null;
  return (await (await adminStore(env, "/consume", { challenge: data.challenge })).json()).ok ? raw : null;
}

export async function verifyAssertion(env, url, cred, a) {
  try {
    const raw = await clientData(env, url, a.clientDataJSON, "webauthn.get");
    const auth = unb64u(a.authenticatorData);
    const rpHash = await sha256(enc(url.hostname));
    // Flag bit 0 is user presence and bit 2 is user verification; both are required.
    if (!raw || !rpHash.every((b, i) => b === auth[i]) || (auth[32] & 5) !== 5) return false;
    const [importAlg, verifyAlg] = ALGS[cred.alg];
    const key = await crypto.subtle.importKey("spki", unb64u(cred.publicKey), importAlg, false, ["verify"]);
    const sig = cred.alg === -7 ? derToRaw(unb64u(a.signature)) : unb64u(a.signature);
    return await crypto.subtle.verify(verifyAlg, key, sig, new Uint8Array([...auth, ...(await sha256(raw))]));
  } catch {
    return false;
  }
}

const matches = (given, secret) => {
  const a = enc(given);
  const b = enc(secret);
  return a.length === b.length && crypto.subtle.timingSafeEqual(a, b);
};

/**
 * The role a Basic-auth password unlocks: "owner" for ADMIN_PASSWORD, "viewer" when VIEWER_PASSWORD is set and matches,
 * or null. Both comparisons run so the answer does not take a different amount of time for the two secrets.
 */
export async function passwordRole(req, env) {
  const [scheme, encoded] = (req.headers.get("authorization") || "").split(" ");
  if (scheme !== "Basic" || !encoded) return null;
  let password;
  try {
    password = atob(encoded).split(":").slice(1).join(":");
  } catch {
    return null;
  }
  const owner = !!env.ADMIN_PASSWORD && matches(password, env.ADMIN_PASSWORD);
  const viewer = !!env.VIEWER_PASSWORD && matches(password, env.VIEWER_PASSWORD);
  return owner ? "owner" : viewer ? "viewer" : null;
}


/** How many invites may wait at once, and how long one lasts. A link that sits unused for a day is a liability. */
export const INVITES_MAX = 20;
export const INVITE_TTL = 24 * 60 * 60 * 1000;
