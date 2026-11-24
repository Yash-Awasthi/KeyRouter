// The streamed metering path: the client's bytes must be untouched, and only the events that carry a usage count may
// be held in memory, however long the completion is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { tail } from "./meter.js";

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
  const { addCall, view } = await import("./meter.js");
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
  const { normalize } = await import("./meter.js");
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
  const { addCall, view } = await import("./meter.js");
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
