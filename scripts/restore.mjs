// Restore a dump written by GET /admin/export into a KV namespace.
//
//   node scripts/restore.mjs dump.json --dry-run          print the writes, touch nothing
//   node scripts/restore.mjs dump.json --namespace-id <id>  write them with wrangler
//
// A record alone is not enough: KV also wants the expiry (or the key never goes away) and the metadata (or the
// listing loses every label, base URL and limit string). The export carries both; this script puts all three back.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/** The wrangler arguments for one exported key, so the shape can be tested without a network. */
export function putFor(entry, { binding = "KEYS", namespaceId } = {}) {
  const args = ["wrangler", "kv", "key", "put", "--binding=" + binding];
  if (namespaceId) args.push("--namespace-id", namespaceId);
  args.push(entry.id, JSON.stringify(entry.record));
  if (entry.expiration) args.push("--expiration", String(entry.expiration));
  if (entry.metadata) args.push("--metadata", JSON.stringify(entry.metadata));
  return args;
}

/** What a restore needs, and what it would silently lose if the dump predates the fix that added it. */
export function audit(entries) {
  const problems = [];
  for (const e of entries) {
    if (!e?.id || !/^sk-gw-[0-9a-f]{32}$/.test(e.id)) problems.push("a key id is not a gateway id: " + String(e?.id));
    else if (!e.record) problems.push(e.id.slice(0, 13) + " has no record");
    else if (!e.expiration) problems.push(e.id.slice(0, 13) + " has no expiry, so the restored row would never be deleted");
    else if (!e.metadata) problems.push(e.id.slice(0, 13) + " has no metadata, so the key list would lose its label and limits");
  }
  return problems;
}

function parseArgs(argv) {
  const out = { file: "", namespaceId: "", dryRun: false, binding: "KEYS" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") out.dryRun = true;
    else if (a === "--namespace-id") out.namespaceId = argv[++i] ?? "";
    else if (a === "--binding") out.binding = argv[++i] ?? "KEYS";
    else if (a.startsWith("--")) throw new Error("unknown argument: " + a);
    else out.file = a;
  }
  return out;
}

export function run(argv = process.argv.slice(2), { log = console.log } = {}) {
  const args = parseArgs(argv);
  if (!args.file) throw new Error("usage: node scripts/restore.mjs <dump.json> [--namespace-id <id>] [--dry-run]");
  const dump = JSON.parse(readFileSync(args.file, "utf8"));
  const entries = Array.isArray(dump.keys) ? dump.keys : [];
  if (!entries.length) throw new Error("the dump holds no keys");
  const problems = audit(entries);
  if (problems.length) {
    // Refusing is the point: a dump without metadata or expiry restores a deployment that looks fine and is not.
    throw new Error("this dump cannot restore everything:\n  " + problems.slice(0, 10).join("\n  "));
  }
  let written = 0;
  for (const entry of entries) {
    const cmd = putFor(entry, { binding: args.binding, namespaceId: args.namespaceId });
    if (args.dryRun) {
      log("would run: npx " + cmd.join(" ").slice(0, 120) + " ...");
      continue;
    }
    execFileSync("npx", cmd, { stdio: "pipe" });
    written++;
  }
  log(args.dryRun ? `${entries.length} keys ready to restore (dry run)` : `${written} keys restored`);
  if (dump.prices) log("the price table is not restored by this script: open /admin/prices and paste it back");
  return { ok: true, dryRun: args.dryRun, count: entries.length, written };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    run();
  } catch (e) {
    console.error(/** @type {Error} */ (e).message);
    process.exitCode = 1;
  }
}
