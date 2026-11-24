#!/usr/bin/env node
// Create a gateway key from a terminal, so a first key does not need the admin page.
//
//   npx keyrouter create --url https://gw.example --provider openai --key sk-... --cap 20 --days 7
//
// The URL and the admin password can come from the environment (KEYROUTER_URL, KEYROUTER_PASSWORD) instead, which
// keeps the password out of the shell history. Nothing is stored: the key is printed once and the provider key is
// sent straight to the worker, which seals it.
import { pathToFileURL } from "node:url";

/** The base URL each provider's API answers on, as the gateway expects to forward to it. */
export const PROVIDERS = {
  openai: "https://api.openai.com",
  anthropic: "https://api.anthropic.com",
  openrouter: "https://openrouter.ai/api",
  gemini: "https://generativelanguage.googleapis.com",
  groq: "https://api.groq.com/openai",
  deepseek: "https://api.deepseek.com",
};

const USAGE = `npx keyrouter create --provider <${Object.keys(PROVIDERS).join("|")}> [options]

  --url <origin>      the deployed gateway, or KEYROUTER_URL
  --password <pw>     the admin password, or KEYROUTER_PASSWORD
  --provider <name>   picks the base URL (see the list above)
  --base <url>        an explicit base URL instead of a provider name
  --key <provider-key> the real provider key to seal, or KEYROUTER_PROVIDER_KEY
  --cap <usd>         a spend cap for the key
  --days <n>          how long the key lasts (default 7)
  --label <text>      what the key is for
  --json              print the answer as JSON

The CLI signs in with the admin password, so it cannot mint keys on a deployment where a passkey exists and
ALLOW_PASSWORD is not set.`;

const DAY = 24 * 60 * 60 * 1000;

/**
 * Turn argv into a request, or into an error message a person can act on. Pure: no network, no clock unless it is
 * passed in, so every rule here can be checked without a deployment.
 */
export function parse(argv, env = process.env, now = Date.now()) {
  const args = [...argv];
  const flag = (name) => {
    const at = args.indexOf(`--${name}`);
    return at >= 0 ? args[at + 1] : undefined;
  };
  if (args.includes("--help") || args.includes("-h") || args[0] === "help") return { help: true };
  if (args[0] && !args[0].startsWith("-") && args[0] !== "create") return { error: `unknown command "${args[0]}"; the only one is create` };

  const url = (flag("url") || env.KEYROUTER_URL || "").replace(/\/+$/, "");
  if (!/^https?:\/\/[^/\s]+$/.test(url)) return { error: "give the gateway with --url https://your-worker.workers.dev" };
  const password = flag("password") || env.KEYROUTER_PASSWORD || "";
  if (!password) return { error: "give the admin password with --password or KEYROUTER_PASSWORD" };

  const provider = flag("provider");
  const base = flag("base") || (provider && PROVIDERS[provider]);
  if (!base) return { error: `pick a provider (${Object.keys(PROVIDERS).join(", ")}) or pass --base` };
  try {
    new URL(base);
  } catch {
    return { error: `${base} is not a URL` };
  }

  const providerKey = flag("key") || env.KEYROUTER_PROVIDER_KEY || "";
  if (!providerKey) return { error: "give the real provider key with --key or KEYROUTER_PROVIDER_KEY" };

  const days = Number(flag("days") ?? 7);
  if (!(days > 0) || days > 365) return { error: "--days must be between 1 and 365" };
  const cap = flag("cap");
  const body = {
    base,
    key: providerKey,
    expires: new Date(now + days * DAY).toISOString(),
    label: flag("label") || `${provider || "custom"} key`,
  };
  if (cap !== undefined) {
    const amount = Number(cap);
    if (!(amount > 0)) return { error: "--cap must be a positive number of dollars" };
    body.capUsd = amount;
  }
  return { url, password, body, json: args.includes("--json") };
}

/** The request the CLI makes: one POST, HTTP Basic, JSON. */
export function request({ url, password, body }) {
  return new Request(`${url}/admin/keys`, {
    method: "POST",
    headers: { authorization: "Basic " + btoa("cli:" + password), "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function run(argv, { env = process.env, log = console.log, error = console.error, fetchIt = globalThis.fetch, now = Date.now() } = {}) {
  const plan = parse(argv, env, now);
  if (plan.help) return log(USAGE), 0;
  if (plan.error) return error(plan.error), 2;
  const res = await fetchIt(request(plan));
  const answer = await res.json().catch(() => null);
  if (!res.ok) return error(`the gateway said ${res.status}: ${answer?.error?.message || "no message"}`), 1;
  if (plan.json) return log(JSON.stringify(answer, null, 2)), 0;
  log(`created ${answer.id}`);
  log(`  label    ${answer.label || plan.body.label}`);
  log(`  base     ${answer.base}`);
  log(`  expires  ${answer.expires}`);
  if (answer.capUsd) log(`  cap      $${answer.capUsd}`);
  // The gateway key is the id: it is what a client sends, and the real provider key never comes back.
  log(`  key      ${answer.id}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(await run(process.argv.slice(2)));
