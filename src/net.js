// Address and URL rules: everything here decides whether the worker will dial a host, so it has no side
// effects and no dependency beyond the standard library.

export const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

// Returns { bits, n } for an IPv4 or IPv6 address, or null when the text is not one.
export function parseIp(s) {
  s = String(s).trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    const parts = s.split(".").map(Number);
    return parts.every((x) => x <= 255) ? { bits: 32, n: parts.reduce((a, x) => (a << 8n) | BigInt(x), 0n) } : null;
  }
  const halves = s.split("::");
  if (!s.includes(":") || halves.length > 2) return null;
  const [head, tail] = halves.map((h) => (h ? h.split(":") : []));
  const last = tail || head;
  if (last.at(-1)?.includes(".")) {
    const v4 = parseIp(last.pop());
    if (v4?.bits !== 32) return null;
    last.push((v4.n >> 16n).toString(16), (v4.n & 0xffffn).toString(16));
  }
  const groups = tail ? [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill("0"), ...tail] : head;
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { bits: 128, n: groups.reduce((a, g) => (a << 16n) | BigInt("0x" + g), 0n) };
}

export function parseRange(range) {
  const [addr, len, extra] = String(range).trim().split("/");
  const ip = parseIp(addr);
  const bits = Number(len === undefined ? ip?.bits : len);
  if (!ip || extra !== undefined || !Number.isInteger(bits) || bits < 0 || bits > ip.bits) return null;
  return { ...ip, len: bits };
}

export function inRange(addr, range) {
  const ip = parseIp(addr);
  const r = parseRange(range);
  if (!ip || !r || ip.bits !== r.bits) return false;
  const shift = BigInt(/** @type {number} */ (r.bits) - /** @type {number} */ (r.len));
  return ip.n >> shift === r.n >> shift;
}

const minutes = (hhmm) => Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3));

// True when the date falls inside the key's weekly window. A window ending before it starts runs past midnight
// and belongs to the day it starts on.
export function withinHours(hours, date) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: hours.tz, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" })
    .formatToParts(date).map((p) => [p.type, p.value]));
  const day = DAYS.indexOf(parts.weekday);
  const now = Number(parts.hour) * 60 + Number(parts.minute);
  const [start, end] = [minutes(hours.start), minutes(hours.end)];
  if (start === end) return hours.days.includes(day);
  if (start < end) return hours.days.includes(day) && now >= start && now < end;
  return (hours.days.includes(day) && now >= start) || (hours.days.includes((day + 6) % 7) && now < end);
}


// A base URL is operator input, but it decides where the worker dials from: refuse anything inside its own network.
const PRIVATE_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4"];
const PRIVATE_V6 = ["::/128", "::1/128", "fc00::/7", "fe80::/10"];
const INTERNAL_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|metadata|instance-data)$/i;
function internalAddress(host) {
  const ip = parseIp(host);
  if (!ip) return INTERNAL_HOST.test(host);
  if (ip.bits === 32) return PRIVATE_V4.some((r) => inRange(host, r));
  // An IPv4-mapped address is judged as the IPv4 address it wraps.
  if (inRange(host, "::ffff:0:0/96")) return internalAddress([24n, 16n, 8n, 0n].map((s) => String((ip.n >> s) & 255n)).join("."));
  return PRIVATE_V6.some((r) => inRange(host, r));
}
export const validBase = (b) => {
  if (!/^https:\/\/\S+$/.test(b || "") || b.length > 300) return false;
  let host;
  try { host = new URL(b).hostname.replace(/^\[|\]$/g, ""); } catch { return false; }
  return !!host && !internalAddress(host);
};
// Development only: ALLOW_LOCAL_BASE=true lets a key point at a stub provider on the same machine, which
// `wrangler dev` cannot otherwise reach. Anything else in the URL rules above still applies.
const localBase = (env, b) => env.ALLOW_LOCAL_BASE === "true" && /^https?:\/\/\S+$/.test(b || "") && b.length <= 300;
export const baseOk = (env, b) => validBase(b) || localBase(env, b);

/** The host a base URL points at, or "" when it is not a URL at all. */
export function hostOf(base) {
  try {
    return new URL(base).host;
  } catch {
    return "";
  }
}

/** A group is a meter with no key behind it: the same admit, record and report code counts what the keys on a host
 * spend together, so a host budget needs no counter of its own. */
export const groupId = (host) => "group:" + host;
