import { test } from "node:test";
import assert from "node:assert/strict";
import { amzDates, canonicalQuery, sha256Hex, sigv4, uriEncode } from "./sigv4.js";

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
