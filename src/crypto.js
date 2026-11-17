// Every secret in the store goes through here: a real provider key is sealed with AES-GCM and bound to the
// gateway key id as associated data, so a copied KV value is useless on its own.

export const enc = (s) => new TextEncoder().encode(s);
export const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
export const unb64u = (s) => Uint8Array.from(atob(String(s).replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
export const randomHex = (bytes) => [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
export const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));

// Real keys are encrypted with ENCRYPTION_KEY and bound to their gateway id, so a copied KV value is useless alone.
const sealKeys = new Map();
function sealKey(secret) {
  if (!sealKeys.has(secret)) {
    sealKeys.set(secret, sha256(enc(secret)).then((raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"])));
  }
  return sealKeys.get(secret);
}

export async function seal(env, id, plain) {
  if (!env.ENCRYPTION_KEY || plain == null) return plain;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc(id) }, await sealKey(env.ENCRYPTION_KEY), enc(plain));
  return `enc:v1:${b64u(iv)}:${b64u(data)}`;
}

export async function unseal(env, id, stored) {
  if (typeof stored !== "string" || !stored.startsWith("enc:v1:")) return stored;
  const [, , iv, data] = stored.split(":");
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(iv), additionalData: enc(id) }, await sealKey(env.ENCRYPTION_KEY || ""), unb64u(data));
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

export const newId = () => "sk-gw-" + randomHex(16);
