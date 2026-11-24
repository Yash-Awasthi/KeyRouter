// `node --check` stops at one file and does not follow imports, so after the split every module needs its own pass.
// This is the first gate in CI: a syntax error in a module would otherwise only appear when the tests import it.
import { readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("..", import.meta.url));
// The shipped code, the CLI, and the operator scripts that are run by hand rather than by the tests.
const files = [
  "worker.js",
  "bin/keyrouter.mjs",
  ...readdirSync(join(root, "src")).filter((f) => f.endsWith(".js")).map((f) => join("src", f)),
  ...readdirSync(join(root, "scripts")).filter((f) => f.endsWith(".mjs") && !f.endsWith(".test.mjs")).map((f) => join("scripts", f)),
];
let failed = 0;
for (const file of files) {
  try {
    execFileSync(process.execPath, ["--check", join(root, file)], { stdio: "pipe" });
  } catch (e) {
    failed++;
    console.error(`${file}: ${e.stderr?.toString().trim() || e.message}`);
  }
}
console.log(`${files.length} files: ${failed ? `${failed} do not parse` : "all parse"}`);
if (failed) process.exit(1);
