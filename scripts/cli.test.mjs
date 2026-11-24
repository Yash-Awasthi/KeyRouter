// The CLI turns arguments into one request and one readable answer. Both are pure enough to check here, and the
// request it builds is replayed against the real worker in worker.test.js via the same handler.
import { test } from "node:test";
import "./text_modules.mjs";
import assert from "node:assert/strict";
import { PROVIDERS, parse, request, run } from "../bin/keyrouter.mjs";
import { makeEnv, worker } from "./harness.mjs";

const NOW = Date.UTC(2026, 10, 25, 12);
const base = ["--url", "https://gw.example", "--password", "pw"];

test("the CLI builds a key request from a provider name, a cap and a duration", () => {
  const plan = parse([...base, "--provider", "openai", "--key", "sk-real", "--cap", "20", "--days", "7", "--label", "cli"], {}, NOW);
  assert.equal(plan.error, undefined);
  assert.equal(plan.url, "https://gw.example");
  assert.deepEqual(plan.body, {
    base: PROVIDERS.openai,
    key: "sk-real",
    capUsd: 20,
    label: "cli",
    expires: new Date(NOW + 7 * 24 * 60 * 60 * 1000).toISOString(),
  });
  const req = request(plan);
  assert.equal(req.url, "https://gw.example/admin/keys");
  assert.equal(req.method, "POST");
  assert.equal(req.headers.get("content-type"), "application/json");
  // HTTP Basic with a made-up user name: only the password half matters to the worker.
  assert.equal(atob(req.headers.get("authorization").slice(6)), "cli:pw");
});

test("the environment can carry the deployment, the password and the provider key", () => {
  const env = { KEYROUTER_URL: "https://env.example/", KEYROUTER_PASSWORD: "pw", KEYROUTER_PROVIDER_KEY: "sk-env" };
  const plan = parse(["--provider", "anthropic"], env, NOW);
  assert.equal(plan.url, "https://env.example", "a trailing slash is trimmed");
  assert.equal(plan.body.base, "https://api.anthropic.com");
  assert.equal(plan.body.key, "sk-env");
  assert.equal(plan.body.expires, new Date(NOW + 7 * 24 * 3600e3).toISOString(), "a week by default");
  assert.equal(plan.body.capUsd, undefined, "no cap unless asked for");
});

test("every way to get it wrong says what to do instead", () => {
  const bad = (args, env = {}) => parse(args, env, NOW).error;
  assert.match(bad([], {}), /--url/);
  assert.match(bad(["--url", "gw.example"], {}), /--url/, "a bare host is not a URL");
  assert.match(bad(["--url", "https://gw.example", "--provider", "openai", "--key", "k"], {}), /admin password/);
  assert.match(bad([...base, "--key", "k"], {}), /pick a provider/);
  assert.match(bad([...base, "--key", "k", "--provider", "nope"], {}), /pick a provider/);
  assert.match(bad([...base, "--key", "k", "--base", "not a url"], {}), /not a URL/);
  assert.match(bad([...base, "--provider", "openai"], {}), /provider key/);
  assert.match(bad([...base, "--provider", "openai", "--key", "k", "--days", "0"], {}), /--days/);
  assert.match(bad([...base, "--provider", "openai", "--key", "k", "--days", "400"], {}), /--days/);
  assert.match(bad([...base, "--provider", "openai", "--key", "k", "--cap", "-5"], {}), /--cap/);
  assert.equal(bad(["rotate"], {}), 'unknown command "rotate"; the only one is create');
  assert.equal(parse(["--help"], {}, NOW).help, true);
});

test("a created key is printed once, and a refusal is reported with its reason", async () => {
  const lines = [];
  const log = (...a) => lines.push(a.join(" "));
  const errors = [];
  const error = (...a) => errors.push(a.join(" "));
  const ok = {
    id: "sk-gw-" + "a".repeat(32),
    key: "sk-gw-" + "a".repeat(32),
    base: "https://api.openai.com",
    label: "cli",
    expires: "2026-12-02T12:00:00.000Z",
    capUsd: 20,
  };
  const fetchIt = async () => Response.json(ok);
  const argv = [...base, "--provider", "openai", "--key", "sk-real", "--cap", "20", "--label", "cli"];
  assert.equal(await run(argv, { log, error, fetchIt, now: NOW }), 0);
  const text = lines.join("\n");
  assert.match(text, /created sk-gw-a{32}/);
  assert.match(text, /label {4}cli/);
  assert.match(text, /expires {2}2026-12-02T12:00:00.000Z/);
  assert.match(text, /cap {6}\$20/);
  assert.match(text, /key {6}sk-gw-a{32}/);

  // --json prints the worker's answer verbatim, so a script can read it.
  lines.length = 0;
  assert.equal(await run([...argv, "--json"], { log, error, fetchIt: async () => Response.json(ok), now: NOW }), 0);
  assert.deepEqual(JSON.parse(lines.join("\n")), ok);

  // A 403 from the worker carries its message through, and the exit code is not zero.
  const refused = async () => Response.json({ error: { message: "add a passkey before creating keys" } }, { status: 403 });
  assert.equal(await run(argv, { log, error, fetchIt: refused, now: NOW }), 1);
  assert.match(errors.at(-1), /the gateway said 403: add a passkey before creating keys/);

  // A usage error never reaches the network.
  let called = false;
  assert.equal(await run([], { log, error, fetchIt: async () => { called = true; return Response.json({}); } }), 2);
  assert.equal(called, false, "nothing is sent without a deployment and a password");
  assert.match(errors.at(-1), /--url/);

  // Someone who asks for help gets the help, not an error.
  lines.length = 0;
  assert.equal(await run(["--help"], { log, error }), 0);
  assert.match(lines.join("\n"), /npx keyrouter create --provider/);
});

test("the request the CLI builds is one the worker accepts", async () => {
  const { env } = makeEnv({ ADMIN_PASSWORD: "pw", ENCRYPTION_KEY: "k" });
  // HTTP Basic with the password half, exactly as the CLI sends it.
  const plan = parse(["create", "--url", "https://gw.example", "--password", "pw", "--provider", "anthropic", "--key", "sk-ant-real", "--cap", "20", "--days", "7", "--label", "from the cli"], {}, NOW);
  assert.equal(plan.error, undefined);
  const created = worker.fetch(request(plan), env, { waitUntil() {} });
  const res = await created;
  assert.equal(res.status, 200);
  const answer = await res.json();
  assert.match(answer.id, /^sk-gw-[0-9a-f]{32}$/);
  assert.equal(answer.base, "https://api.anthropic.com");
  assert.equal(answer.label, "from the cli");
  assert.equal(answer.capUsd, 20);
  // The provider key was sealed, not echoed back: the answer carries the gateway key, never the real one.
  assert.equal(typeof answer.key, "undefined", "no field carries the provider key");
  assert.equal(JSON.stringify(answer).includes("sk-ant-real"), false);
  const stored = await env.KEYS.get(answer.id, "json");
  assert.ok(stored.key && stored.key !== "sk-ant-real", "the real key is stored sealed");
  assert.equal(Date.parse(answer.expires) - Date.parse(plan.body.expires), 0, "the expiry the CLI chose is the expiry stored");
});
