// The pure parts, tested without a Worker or a network: stream metering, address and time-window rules, the price
// table and its multipliers, and AWS SigV4 against Amazon's own worked example.
import assert from "node:assert/strict";
import { DEFAULT_PRICES, cost, prices } from "../src/pricing.js";
import { amzDates, canonicalQuery, sha256Hex, sigv4, uriEncode } from "../src/sigv4.js";
import { inRange, parseIp, withinHours } from "../src/net.js";
import { tail } from "../src/meter.js";
import { test } from "node:test";

// The streamed metering path: the client's bytes must be untouched, and only the events that carry a usage count may
// be held in memory, however long the completion is.

const encoder = new TextEncoder();
const streamOf = (chunks) => new ReadableStream({
  start(c) {
    for (const chunk of chunks) c.enqueue(encoder.encode(chunk));
    c.close();
  },
});
const sse = (event, data) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

test("only the events with a model or a usage count survive the pass, however long the stream is", async () => {
  // Gemini sends a usageMetadata object with every chunk, so this is the case where a reader that kept them all
  // would hold the whole reply.
  const chunks = ['data: {"candidates":[{"content":{"parts":[{"text":"start"}]}}],"model":"claude-sonnet-5-5","usageMetadata":{"promptTokenCount":2000}}'];
  for (let i = 0; i < 500; i++) {
    chunks.push(`data: {"candidates":[{"content":{"parts":[{"text":"word word ${i}"}]}}],"usageMetadata":{"promptTokenCount":2000,"candidatesTokenCount":${i}}}`);
  }
  const body = chunks.join("\n");

  const kept = await tail(streamOf([body]));
  const lines = kept.split("\n");
  assert.ok(lines.length <= 5, `a ${chunks.length}-event stream keeps ${lines.length} lines`);
  assert.ok(kept.includes("claude-sonnet-5-5"), "the model survives, even though it came first");
  assert.ok(kept.includes('"candidatesTokenCount":499'), "and so does the last usage event");
  assert.ok(kept.length < 1000, `the kept text is ${kept.length} bytes, not the ${body.length} read`);
});

test("a chunk boundary in the middle of a line does not lose the event", async () => {
  const whole = sse("message_delta", { type: "message_delta", usage: { output_tokens: 42 } });
  // Split every line into one-byte chunks, the worst case for a line-oriented reader.
  const kept = await tail(streamOf([...whole]));
  assert.ok(kept.includes('"output_tokens":42'), kept);
});

test("a body that is not a stream is still handled", async () => {
  const kept = await tail(streamOf(['{"model":"claude-opus-5-5","usage":{"input_tokens":5}}']));
  assert.ok(kept.includes("claude-opus-5-5"));
});

test("ten thousand calls add up exactly, where floats would drift", async () => {
  const { addCall, view } = await import("../src/meter.js");
  const bucket = {};
  const rate = 0.0000123;
  for (let i = 0; i < 10_000; i++) addCall(bucket, { model: "m", input: 1, output: 1, usd: rate });
  const shown = view(bucket).m;
  assert.equal(shown.cost, 0.123, `stored as nano-dollars: ${shown.cost}`);
  assert.equal(shown.requests, 10_000);
  assert.equal(shown.input, 10_000);

  // The same additions in floating point do drift, which is why the storage is an integer.
  let float = 0;
  for (let i = 0; i < 10_000; i++) float += rate;
  assert.notEqual(float, 0.123);

  // A bucket written before this change carries only a float `cost`; it still reads back at full value.
  assert.deepEqual(view({ old: { requests: 2, input: 4, output: 6, cost: 0.5 } }).old, { requests: 2, input: 4, output: 6, cost: 0.5, priced: true, price_version: null });
  // A row records which table charged it, so an edited price list cannot rewrite history.
  addCall(bucket, { model: "m", input: 1, output: 1, usd: rate, pv: "v2" });
  assert.equal(view(bucket).m.price_version, "v2");
  // An unpriced model is counted but flagged, exactly as before.
  addCall(bucket, { model: "free", input: 7, output: 3, usd: null });
  assert.deepEqual([view(bucket).free.cost, view(bucket).free.priced], [0, false]);
});

test("each provider's cache shape is split into fresh, read and written tokens", async () => {
  const { normalize } = await import("../src/meter.js");
  // OpenAI folds the cache into prompt_tokens and reports the cached part separately.
  assert.deepEqual(normalize({ prompt_tokens: 2e6, completion_tokens: 5, prompt_tokens_details: { cached_tokens: 1e6 } }), {
    input_tokens: 1e6,
    cache_read_input_tokens: 1e6,
    output_tokens: 5,
    cost: undefined,
  });
  // Gemini names its counts differently and has no write concept.
  assert.deepEqual(normalize({ promptTokenCount: 2e6, candidatesTokenCount: 5, cachedContentTokenCount: 1e6 }), {
    input_tokens: 1e6,
    cache_read_input_tokens: 1e6,
    output_tokens: 5,
  });
  // Anthropic already reports the pieces, and price.js decides what a five-minute and a one-hour write cost.
  assert.deepEqual(normalize({ input_tokens: 7, cache_read_input_tokens: 3, cache_creation_input_tokens: 5, output_tokens: 2 }), {
    input_tokens: 7,
    cache_read_input_tokens: 3,
    cache_creation_input_tokens: 5,
    output_tokens: 2,
  });
  // A body with no cache at all is left alone rather than gaining zero fields.
  assert.deepEqual(normalize({ input_tokens: 7, output_tokens: 2 }), { input_tokens: 7, output_tokens: 2 });
});

test("money is USD in integer nano-dollars, and it is displayed to four or six decimals, never two", async () => {
  const { addCall, view } = await import("../src/meter.js");
  // Storage: an integer count of 1e-9 USD, so ten thousand small calls cannot drift.
  const bucket = addCall({}, { model: "m", input: 1, output: 1, usd: 0.000000001 });
  assert.equal(bucket.m.nano, 1);
  // nanoOf is private, so the round trip through view() is the observable proof: 1 nano reads back as 1e-9 USD.
  assert.equal(Math.round(view(bucket).m.cost * 1e9), 1);
  assert.equal(view(bucket).m.cost, 1e-9);
  // A fractional nano-dollar rounds to the nearest nano rather than being truncated.
  assert.equal(addCall({}, { model: "m", input: 1, output: 1, usd: 0.0000000005 }).m.nano, 1);
  // Display: the page adds the currency and picks the precision. Above a cent, four decimals; below it, six.
  const usd = (n) => "$" + n.toFixed(n && n < 0.01 ? 6 : 4);
  assert.deepEqual([usd(1), usd(0.0123), usd(0.004), usd(0.0000004), usd(0)], ["$1.0000", "$0.0123", "$0.004000", "$0.000000", "$0.0000"]);
});

// Address and time-window rules, tested directly: no worker, no storage, no network.

test("an overnight window survives a daylight-saving change in both directions", async () => {
  const night = { days: [0, 6], start: "22:00", end: "06:00", tz: "America/New_York" };
  // 2026-11-01 falls back at 02:00, so 01:30 local happens twice; both must count the same way.
  assert.ok(withinHours(night, new Date("2026-11-01T05:30:00Z")), "01:30 on the first pass");
  assert.ok(withinHours(night, new Date("2026-11-01T06:30:00Z")), "01:30 on the second pass");
  assert.ok(!withinHours(night, new Date("2026-11-01T11:00:00Z")), "06:00 local is the exclusive end, whatever the offset");
  // 2026-03-08 skips 02:00 entirely; 01:59 and 03:00 are both inside the window.
  assert.ok(withinHours(night, new Date("2026-03-08T06:59:00Z")), "01:59 EST");
  assert.ok(withinHours(night, new Date("2026-03-08T07:00:00Z")), "03:00 EDT, an hour later by the clock and the same minute of the window");
  // start == end means the whole day, and still respects the day list.
  const allDay = { days: [1], start: "00:00", end: "00:00", tz: "America/New_York" };
  assert.ok(withinHours(allDay, new Date("2026-11-02T12:00:00Z")), "Monday, any minute");
  assert.ok(!withinHours(allDay, new Date("2026-11-01T12:00:00Z")), "Sunday is not in the list");
});

test("address matching handles /0, ::1, mapped IPv4 and malformed CIDRs", async () => {
  // /0 matches everything of its own family and nothing of the other.
  assert.ok(inRange("1.2.3.4", "0.0.0.0/0"));
  assert.ok(!inRange("2001:db8::1", "0.0.0.0/0"));
  assert.ok(inRange("2001:db8::1", "::/0"));
  assert.ok(!inRange("1.2.3.4", "::/0"));
  // The loopback address in both spellings.
  assert.equal(parseIp("::1").n, 1n);
  assert.ok(inRange("::1", "::1"));
  assert.ok(inRange("::1", "::1/128"));
  assert.ok(!inRange("::2", "::1/128"));
  assert.ok(inRange("127.0.0.1", "127.0.0.0/8"));
  // A mapped address is an IPv6 address: it only matches an IPv6 range, never the bare IPv4 one.
  assert.equal(parseIp("::ffff:10.0.0.1").bits, 128);
  assert.ok(!inRange("::ffff:10.0.0.1", "10.0.0.0/8"), "mapped is not the same family");
  assert.ok(inRange("::ffff:10.0.0.1", "::ffff:10.0.0.0/104"));
  assert.ok(!inRange("10.0.0.1", "::ffff:10.0.0.0/120"));
  // A malformed range never matches, so a bad allowlist entry cannot accidentally allow everything.
  for (const bad of ["10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/abc", "10.0.0.0//24", "10.0.0.0/24/1", "::/129", "not-an-ip", ""]) {
    assert.equal(inRange("10.0.0.1", bad), false, bad);
  }
});

// The price table and the cost model, tested directly: no worker, no storage, no network.

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

test("SigV4 reproduces the worked example in AWS's own documentation", async () => {
  // The example prints the expected signature, so this is a known-answer test, not a self-consistency check:
  // a change to the canonical request, the scope or the key derivation changes the result and fails here.
  const headers = await sigv4({
    method: "GET",
    url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
    headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
    region: "us-east-1",
    service: "iam",
    accessKeyId: "AKIDEXAMPLE",
    secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    now: new Date("2015-08-30T12:36:00Z"),
  });
  assert.equal(
    headers.authorization,
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
  );
  assert.equal(headers["x-amz-date"], "20150830T123600Z");
  assert.equal(headers["x-amz-content-sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("a session token is signed, and a body changes the payload hash", async () => {
  const base = { method: "POST", url: "https://bedrock-runtime.us-west-2.amazonaws.com/model/x/invoke", region: "us-west-2", service: "bedrock", accessKeyId: "AKIDEXAMPLE", secretKey: "secret", now: new Date("2026-01-02T03:04:05Z") };
  const plain = await sigv4({ ...base, body: '{"a":1}' });
  const sts = await sigv4({ ...base, body: '{"a":1}', sessionToken: "tok" });
  assert.equal(plain["x-amz-security-token"], undefined);
  assert.equal(sts["x-amz-security-token"], "tok");
  assert.match(sts.authorization, /SignedHeaders=host;x-amz-date;x-amz-security-token/);
  assert.notEqual(plain.authorization, sts.authorization);
  assert.equal(plain["x-amz-content-sha256"], await sha256Hex('{"a":1}'));
  assert.notEqual((await sigv4({ ...base, body: '{"a":2}' })).authorization, plain.authorization);
});

test("a header the caller set is signed, but an authorization header is replaced rather than trusted", async () => {
  const h = await sigv4({
    method: "GET",
    url: "https://s3.us-east-1.amazonaws.com/b/k",
    headers: { Authorization: "Bearer stale", "X-Amz-Meta-Thing": "  a   b  ", accept: "application/json" },
    region: "us-east-1",
    service: "s3",
    accessKeyId: "AKIDEXAMPLE",
    secretKey: "secret",
  });
  assert.match(h.authorization, /SignedHeaders=accept;host;x-amz-date;x-amz-meta-thing/);
  assert.equal(h.authorization.includes("Bearer"), false);
});

test("queries are sorted by encoded key and spaces are never a plus", async () => {
  assert.equal(uriEncode("a b/c~d.e-f_g"), "a%20b%2Fc~d.e-f_g");
  assert.equal(canonicalQuery("?b=2&a=1&a=0&c"), "a=0&a=1&b=2&c=");
  assert.equal(canonicalQuery(""), "");
  assert.deepEqual(amzDates(new Date("2026-12-31T23:59:59.999Z")), { date: "20261231", stamp: "20261231T235959Z" });
});
