// The price table and the cost model, tested directly: no worker, no storage, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_PRICES, cost, prices } from "./pricing.js";

test("cost follows Anthropic list prices", () => {
  const M = 1e6;
  assert.equal(cost("claude-opus-5-5", { input_tokens: M, output_tokens: M }), 24);
  assert.equal(cost("claude-sonnet-5-5", { input_tokens: M, output_tokens: M }), 12);
  assert.equal(cost("anthropic/claude-haiku-5.5", { input_tokens: M, output_tokens: M }), 3);
  assert.equal(cost("claude-opus-5-5", { cache_read_input_tokens: M, cache_creation_input_tokens: M }), 5.2);
  assert.equal(cost("claude-opus-5-5", { cache_creation_input_tokens: M, cache_creation: { ephemeral_1h_input_tokens: M } }), 8);
  assert.equal(cost("gpt-x", { input_tokens: 5 }), null);
  assert.equal(cost("claude-sonnet-5-5", { cache_read_input_tokens: M }), 0.1, "Sonnet 5.5 cache reads are 0.05x");
  assert.equal(cost("claude-sonnet-5", { cache_read_input_tokens: M }), 0.2, "the longest matching name wins");
  assert.equal(cost("claude-opus-5-5", { input_tokens: M, speed: "fast" }), 8);
  assert.ok(Math.abs(cost("claude-opus-5-5", { input_tokens: M, inference_geo: "us" }) - 4.4) < 1e-9);
  assert.equal(cost("claude-haiku-5-5", { input_tokens: 50e3, cache_read_input_tokens: 60e3 }), (50e3 * 0.5 + 60e3 * 0.05) / M, "cache tokens count toward the 100K threshold");
  // Every model the price check reports must have a row: in + out per million tokens.
  const [M1, M2] = [M, M];
  assert.equal(cost("claude-fable-5-2", { input_tokens: M1, output_tokens: M2 }), 48);
  assert.equal(cost("claude-mythos-5-2", { input_tokens: M1, output_tokens: M2 }), 48);
  assert.equal(cost("claude-opus-4-5", { input_tokens: M1, output_tokens: M2 }), 30);
  assert.equal(cost("claude-opus-4-1", { input_tokens: M1, output_tokens: M2 }), 90);
  assert.equal(cost("claude-opus-4", { input_tokens: M1, output_tokens: M2 }), 90);
  assert.equal(cost("claude-sonnet-4-5", { input_tokens: M1, output_tokens: M2 }), 18);
  assert.equal(cost("claude-sonnet-4", { input_tokens: M1, output_tokens: M2 }), 18);
});


test("the long-context, fast-mode and residency multipliers each apply, and they stack", async () => {
  const close = (a, b, why) => assert.ok(Math.abs(a - b) < 1e-12, `${why}: expected ${b}, got ${a}`);
  // claude-haiku-5-5 is the one shipped row with a long-context multiplier: 5x above 100k prompt tokens.
  close(cost("claude-haiku-5-5", { input_tokens: 100e3 }), 0.01, "exactly at the threshold is the normal rate");
  close(cost("claude-haiku-5-5", { input_tokens: 100e3 + 1 }), 0.0500005, "one token over costs five times as much");
  // claude-opus-5-5 is the shipped row with a fast-mode multiplier: 2x.
  close(cost("claude-opus-5-5", { input_tokens: 1000 }), 0.004, "the base rate");
  close(cost("claude-opus-5-5", { input_tokens: 1000, speed: "fast" }), 0.008, "fast mode doubles it");
  // US residency is 1.1x on every row.
  close(cost("claude-opus-5-5", { input_tokens: 1000, inference_geo: "us" }), 0.0044, "US residency adds a tenth");
  close(cost("claude-haiku-5-5", { input_tokens: 100e3, inference_geo: "us" }), 0.011, "and it applies to the input rate");
  // A row with all three, to prove the factors multiply rather than replace each other.
  const prices = [{ match: "test-model", in: 1, out: 1, read: 1, write5m: 1, write1h: 1, longAbove: 10, longScale: 5, fast: 2 }];
  close(cost("test-model", { input_tokens: 11, speed: "fast", inference_geo: "us" }, prices), (11 * 1e-6) * 5 * 2 * 1.1, "5 x 2 x 1.1");
  close(cost("test-model", { input_tokens: 10, speed: "fast", inference_geo: "us" }, prices), (10 * 1e-6) * 2 * 1.1, "under the threshold only two apply");
});

test("a saved table reaches every isolate on its next check, and an unchanged one is not re-read", async () => {
  const rows = [{ match: "m1", in: 1, out: 2, read: 1, write5m: 1, write1h: 1 }];
  const other = [{ match: "m2", in: 3, out: 4, read: 3, write5m: 3, write1h: 3 }];
  const kv = { "config:prices": JSON.stringify(rows), "config:prices:v": "v1" };
  const reads = [];
  const env = { KEYS: { get: async (k, type) => (reads.push(k), kv[k] == null ? null : type === "json" ? JSON.parse(kv[k]) : kv[k]) } };

  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    assert.deepEqual(await prices(env), rows);
    assert.deepEqual(reads, ["config:prices:v", "config:prices"], "the first read takes the version and the table");

    // A minute later, with the version unchanged: only the version is read, which is the whole point of the ETag.
    reads.length = 0;
    now += 61e3;
    assert.deepEqual(await prices(env), rows);
    assert.deepEqual(reads, ["config:prices:v"], "an unchanged table is not re-read");

    // Another isolate saves: the version moves, so the table is read again and the new rows are used.
    kv["config:prices"] = JSON.stringify(other);
    kv["config:prices:v"] = "v2";
    reads.length = 0;
    now += 61e3;
    assert.deepEqual(await prices(env), other);
    assert.deepEqual(reads, ["config:prices:v", "config:prices"], "a new version re-reads the table");

    // No version key at all (a namespace saved before this existed): read the table rather than serve a stale default.
    delete kv["config:prices:v"];
    delete kv["config:prices"];
    reads.length = 0;
    now += 61e3;
    assert.deepEqual(await prices(env), DEFAULT_PRICES);
    assert.ok(reads.includes("config:prices"), "the table is read when there is no version");
  } finally {
    Date.now = realNow;
  }
});
