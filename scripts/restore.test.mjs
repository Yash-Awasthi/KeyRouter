// The DR drill the plan asked for, proved by logic instead of by deleting a real namespace: export, wipe every KV
// row, restore from the dump with the same puts `scripts/restore.mjs` issues, and check that a key still works,
// that the listing still shows its label and limits, and that the restored row expires when it did.
import { test } from "node:test";
import assert from "node:assert/strict";
import { putFor, audit } from "./restore.mjs";

test("export carries everything a restore needs, and the restore puts all of it back", async () => {
  const { makeEnv } = await import("./harness.mjs");
  const { worker } = await import("./harness.mjs");
  // Its own deployment, so the wipe is total and does not disturb the rest of the suite.
  const { env, store } = makeEnv({});
  const auth = { authorization: "Basic " + btoa("admin:pw"), "content-type": "application/json" };
  const call = (path, init = {}) => worker.fetch(new Request("https://gw.example" + path, init), env, { waitUntil() {} });

  const created = await (await call("/admin/keys", { method: "POST", headers: auth, body: JSON.stringify({ base: "https://api.example", key: "the-real-provider-key", expires: new Date(Date.now() + 3600e3).toISOString(), label: "restored key", capUsd: 2, models: ["claude-opus-5-5"] }) })).json();
  const before = await (await call("/admin/keys/" + created.id, { headers: auth })).json();
  const dump = await (await call("/admin/export", { headers: auth })).json();
  assert.equal(dump.sealed, true, "the dump holds sealed keys");
  assert.equal(dump.keys.length, 1);
  const entry = dump.keys[0];
  assert.equal(entry.id, created.id);
  assert.equal(entry.metadata.label, "restored key", "the listing metadata is in the dump, or the restore loses it");
  assert.ok(entry.expiration > Date.now() / 1000 - 60, "and the KV expiry, or a restored row would never be deleted");
  assert.deepEqual(audit(dump.keys), [], "the dump passes the restore script's own audit");

  // The disaster: every KV row is gone. Nothing else is touched, which is exactly what a namespace loss means.
  store.clear();
  assert.equal((await call("/admin/keys", { headers: auth })).status, 200);
  assert.deepEqual((await (await call("/admin/keys", { headers: auth })).json()).keys, [], "the listing is empty");

  // The restore, with the same arguments the script prints.
  for (const e of dump.keys) {
    const put = putFor(e, { binding: "KEYS" });
    const i = put.indexOf(e.id);
    const [, value] = [put[i], put[i + 1]];
    const expiration = Number(put[put.indexOf("--expiration") + 1]);
    const metadata = JSON.parse(put[put.indexOf("--metadata") + 1]);
    await env.KEYS.put(e.id, value, { expiration, metadata });
  }

  const listed = await (await call("/admin/keys", { headers: auth })).json();
  assert.equal(listed.keys.length, 1, "the key is listed again");
  assert.equal(listed.keys[0].label, "restored key", "with its label, which the record alone would not give the list");
  assert.match(listed.keys[0].limits, /cap \$2/, `and its limits, which came from the metadata: ${JSON.stringify(listed.keys[0].limits)}`);
  assert.equal(store.get(created.id).expiration, entry.expiration, "the KV expiry was restored, not dropped");

  const record = await (await call("/admin/keys/" + created.id, { headers: auth })).json();
  assert.deepEqual(record.usage, before.usage, "usage came back with the dump");
  assert.equal(record.active, true);

  // And the key still works: same sealed provider key, opened with the same ENCRYPTION_KEY, sent upstream.
  const real = globalThis.fetch;
  let sentKey = null;
  globalThis.fetch = async (_url, init) => {
    sentKey = new Headers(init.headers).get("authorization");
    return Response.json({ model: "claude-opus-5-5", usage: { input_tokens: 10, output_tokens: 5 } });
  };
  try {
    const res = await call("/v1/messages", { method: "POST", headers: { authorization: "Bearer " + created.id }, body: JSON.stringify({ model: "claude-opus-5-5" }) });
    assert.equal(res.status, 200, "a restored key proxies");
    assert.equal(sentKey, "Bearer the-real-provider-key", "and the provider key came back intact, not corrupted by the round trip");
  } finally {
    globalThis.fetch = real;
  }
});

test("a dump that predates the fix is refused instead of restoring a deployment that looks fine", () => {
  const id = "sk-gw-" + "a".repeat(32);
  const older = [
    { id, record: { expires: "2027-01-01T00:00:00.000Z" } },
    { id: "sk-gw-" + "b".repeat(32), record: {}, expiration: 1 },
    { id: "sk-gw-" + "c".repeat(32), expiration: 1, metadata: {} },
    { id: "sk-gw-" + "d".repeat(32), record: {}, expiration: 1, metadata: {} },
    { id: "not-a-key", record: {} },
  ];
  const problems = audit(older);
  assert.equal(problems.length, 4, "each incomplete entry is named");
  assert.match(problems[0], /no expiry/, "an entry without an expiry restores a row that never goes away");
  assert.match(problems[1], /no metadata/, "an entry without metadata restores a key with no label or limits in the list");
  assert.match(problems[2], /no record/);
  assert.match(problems[3], /not a gateway id/);
  assert.deepEqual(audit([{ id, record: {}, expiration: 1, metadata: {} }]), [], "a complete entry passes");
});
