// Wrangler bundles .html and the admin page's .css/.js as text modules — see "rules" in wrangler.jsonc — so their
// default export is the file's text. Node does not, so every test that reaches the worker imports this file first and
// gets the same behaviour the bundle has. Keeping it in one place means the three importers cannot drift apart.
import { registerHooks } from "node:module";
import { readFileSync } from "node:fs";

/** True for the files wrangler's Text rule covers. */
const isTextModule = (url) => url.endsWith(".html") || url.endsWith(".css") || url.includes("/pages/");

registerHooks({
  load(url, context, next) {
    if (!isTextModule(url)) return next(url, context);
    return { format: "module", shortCircuit: true, source: `export default ${JSON.stringify(readFileSync(new URL(url), "utf8"))};` };
  },
});
