// End-to-end smoke test: create a key, spend against a stub provider, read the usage, revoke, and prove the
// key is dead. Runs against a deployed worker or against `wrangler dev`.
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

const STUB_REPLY = {
  model: "claude-opus-5-5",
  usage: { input_tokens: 120, output_tokens: 30 },
  content: [{ type: "text", text: "smoke" }],
};

/**
 * The whole journey, with no assumptions about the transport: `fetchImpl` is called with a URL string.
 * Throws on the first step that does not do what the gateway promises.
 */
export async function smoke({ url, admin, provider, fetchImpl = fetch, log = () => {} }) {
  const adminHeaders = { authorization: "Basic " + btoa(`admin:${admin}`), "content-type": "application/json" };
  const send = (path, init = {}) => fetchImpl(url.replace(/\/+$/, "") + path, init);
  const step = async (what, res, want) => {
    if (res.status !== want) throw new Error(`${what}: expected ${want}, got ${res.status} ${(await res.text().catch(() => "")).slice(0, 200)}`);
    log(`ok ${what} (${res.status})`);
    return res;
  };
  const json = async (res) => JSON.parse(await res.text());

  // 1. Create a key bound to the stub provider.
  const created = await step("create a key", await send("/admin/keys", {
    method: "POST",
    headers: adminHeaders,
    body: JSON.stringify({ base: provider, key: "smoke-real-key", expires: new Date(Date.now() + 3600e3).toISOString(), label: "smoke" }),
  }), 200);
  const { id } = await json(created);
  if (!/^sk-gw-[0-9a-f]{32}$/.test(id)) throw new Error(`create a key: got an odd id ${id}`);

  // 2. Spend against it through the proxy.
  const call = await send("/v1/chat/completions", {
    method: "POST",
    headers: { authorization: `Bearer ${id}`, "content-type": "application/json" },
    body: JSON.stringify({ model: "claude-opus-5-5", messages: [{ role: "user", content: "hi" }] }),
  });
  await step("proxy a call", call, 200);

  // 3. The spend shows up in the key's own usage: 120 in + 30 out, priced from the price table.
  const usage = await json(await step("read usage", await send("/usage", { headers: { authorization: `Bearer ${id}` } }), 200));
  const used = usage.used || {};
  if (used.tokens !== 150) throw new Error(`read usage: expected 150 tokens, got ${used.tokens}`);
  if (!(used.usd > 0)) throw new Error(`read usage: expected a cost, got ${used.usd}`);
  log(`ok read usage (150 tokens, $${used.usd})`);

  // 4. Revoke, and the same call must now be refused.
  await step("revoke", await send(`/admin/keys/${id}/revoke`, { method: "POST", headers: adminHeaders, body: "{}" }), 200);
  await step("call a revoked key", await send("/v1/chat/completions", { method: "POST", headers: { authorization: `Bearer ${id}`, "content-type": "application/json" }, body: "{}" }), 401);
  await step("read a revoked key's usage", await send("/usage", { headers: { authorization: `Bearer ${id}` } }), 401);

  // 5. Tidy up so a second run starts clean.
  await step("delete the record", await send(`/admin/keys/${id}`, { method: "DELETE", headers: adminHeaders }), 200);
  return { id, usd: used.usd };
}

/** A provider stand-in: answers one chat completion with token usage. */
export function stubProvider() {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(STUB_REPLY));
    });
  });
  return {
    listen: () => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}/v1`))),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, "").split("=")));
  const url = args.url || process.env.SMOKE_URL || "http://localhost:8787";
  const admin = args.admin || process.env.ADMIN_PASSWORD;
  if (!admin) {
    console.error("set ADMIN_PASSWORD (or --admin=...) to the password the dev worker was started with");
    process.exit(2);
  }
  const provider = stubProvider();
  const base = await provider.listen();
  try {
    console.log(`smoke: ${url} against a stub provider at ${base}`);
    const { usd } = await smoke({ url, admin, provider: base, log: console.log });
    console.log(`smoke: pass (recorded $${usd}); a 127.0.0.1 provider needs ALLOW_LOCAL_BASE=true on the dev worker`);
  } catch (e) {
    console.error(`smoke: fail — ${e.message}`);
    process.exit(1);
  } finally {
    await provider.close();
  }
}
