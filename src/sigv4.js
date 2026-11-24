// AWS Signature Version 4, for provider bases that require it (Bedrock). The algorithm is small enough to keep here
// in full, and the test checks it against the worked example in AWS's own documentation, so a change that breaks
// signing fails a test rather than a customer call.

const enc = (s) => new TextEncoder().encode(String(s));
const hexOf = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

/** @param {string | Uint8Array | ArrayBuffer} text */
export async function sha256Hex(text) {
  const bytes = /** @type {BufferSource} */ (typeof text === "string" ? enc(text) : text);
  return hexOf(await crypto.subtle.digest("SHA-256", bytes));
}

async function hmac(key, text) {
  const k = await crypto.subtle.importKey("raw", typeof key === "string" ? enc(key) : key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc(text)));
}

/** RFC 3986 quoting as SigV4 wants it: everything but unreserved characters, and no `+` for a space. */
export const uriEncode = (s) =>
  String(s).replace(/[^A-Za-z0-9\-._~]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"));

/** The canonical query string: sorted by encoded key, then encoded value, empty values kept as `key=`. */
export function canonicalQuery(search) {
  const params = [];
  new URLSearchParams(search).forEach((v, k) => {
    params.push([uriEncode(k), uriEncode(v)]);
  });
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return params.map(([k, v]) => `${k}=${v}`).join("&");
}

/** `20150830T123600Z` and `20150830`, from a Date. */
export const amzDates = (now) => {
  const iso = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  return { date: iso.slice(0, 8), stamp: iso.slice(0, 15) + "Z" };
};

/**
 * The headers that make a request SigV4-signed. `body` is the exact bytes that will be sent, because its hash is part
 * of the signature: signing a re-encoded body would not verify.
 *
 * @param {{ method: string, url: string, headers?: Record<string, string>, body?: string | Uint8Array | null,
 *   region: string, service: string, accessKeyId: string, secretKey: string, sessionToken?: string | null,
 *   now?: Date }} req
 */
export async function sigv4({ method, url, headers = {}, body = null, region, service, accessKeyId, secretKey, sessionToken = null, now = new Date() }) {
  const u = new URL(url);
  const { date, stamp } = amzDates(now);
  const payload = body == null ? "" : typeof body === "string" ? body : body;
  const payloadHash = await sha256Hex(payload);

  const signed = { host: u.host, "x-amz-date": stamp, ...(sessionToken ? { "x-amz-security-token": sessionToken } : {}) };
  for (const [k, v] of Object.entries(headers)) {
    const name = k.toLowerCase();
    // A header that is not signed must not be claimed by the signature, and the signature headers are set here.
    if (name === "authorization" || name === "x-amz-date" || name.startsWith("x-amz-security-token")) continue;
    signed[name] = v;
  }
  const names = Object.keys(signed).sort();
  const canonicalHeaders = names.map((n) => `${n}:${String(signed[n]).trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  // The URL's path is already percent-encoded as the service expects; re-encoding a `%2F` would break it.
  const canonicalUri = u.pathname || "/";
  const canonicalRequest = [method.toUpperCase(), canonicalUri, canonicalQuery(u.search), canonicalHeaders, signedHeaders, payloadHash].join("\n");

  const scope = `${date}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", stamp, scope, await sha256Hex(canonicalRequest)].join("\n");
  let key = enc("AWS4" + secretKey);
  for (const part of [date, region, service, "aws4_request"]) key = await hmac(key, part);
  const signature = hexOf(await hmac(key, stringToSign));

  return {
    ...signed,
    "x-amz-content-sha256": payloadHash,
    authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}
