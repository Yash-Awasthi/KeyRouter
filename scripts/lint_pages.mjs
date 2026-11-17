// The pages build DOM nodes with textContent; a raw HTML sink would turn any provider-controlled
// string (a label, a model name) into markup. This keeps that rule instead of trusting review.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const PAGES = ["admin.html", "usage.html", "login.html", "share.html", "join.html"];
// The admin page's script and stylesheet are separate files now, so they are checked too.
const ASSETS = ["pages/admin.js.txt", "pages/admin.css.txt"];
// The files that carry markup and styles: the label and focus rules only apply to these.
const MARKUP = [...PAGES, "pages/admin.css.txt"];

const BANNED = [
  [/\.innerHTML\s*(\+?=)/, "assigns to innerHTML"],
  [/insertAdjacentHTML\s*\(/, "calls insertAdjacentHTML"],
  [/document\.write\s*\(/, "calls document.write"],
  [/\.outerHTML\s*(\+?=)/, "assigns to outerHTML"],
];

/** Every raw HTML sink in one page's source, as readable lines. */
export function pageProblems(name, text) {
  return BANNED.filter(([pattern]) => pattern.test(text)).map(([, why]) => `${name} ${why}`);
}

const CONTROL = /<(input|select|textarea)\b[^>]*\bid="([^"]+)"[^>]*>/g;

/**
 * Every form control that would be announced without a name: no `<label for>`, no `aria-label`, not wrapped in a label.
 * A control with a placeholder is not labelled — a placeholder disappears as soon as someone types.
 */
export function unlabelled(name, html) {
  const labelled = new Set([
    ...[...html.matchAll(/<label[^>]*\bfor="([^"]+)"/g)].map((m) => m[1]),
    // Anything inside a <label> element is named by it, whatever text comes before the control.
    ...[...html.matchAll(/<label\b[^>]*>([\s\S]*?)<\/label>/g)].flatMap(([, inner]) => [...inner.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1])),
  ]);
  return [...html.matchAll(CONTROL)]
    .filter(([tag, , id]) => !labelled.has(id) && !/\baria-label(?:ledby)?=/.test(tag))
    .map(([, kind, id]) => `${name} <${kind} id="${id}"> has no label`);
}

/** Every error block that would fill silently: a message a screen reader never announces is not an error message. */
export function silentErrors(name, html) {
  return [...html.matchAll(/<div class="err" id="([^"]+)"([^>]*)>/g)]
    .filter(([, , attrs]) => !/role="alert"|aria-live=/.test(attrs))
    .map(([, id]) => `${name} #${id} has no role="alert"`);
}

/** The pages must show where the keyboard is; a ring that is never drawn is invisible to anyone not using a mouse. */
export function noFocusRing(name, css) {
  return /:focus-visible|:focus\b/.test(css) ? [] : [`${name} has no visible focus style`];
}

/** The accessibility problems in one file, chosen by what kind of file it is. */
export function a11yProblems(name, text) {
  if (!MARKUP.includes(name)) return [];
  const html = name.endsWith(".html");
  // The admin page's styles live in its own file, so its markup is not asked for a focus ring and its stylesheet is.
  const styles = name.endsWith(".css.txt") || text.includes("<style>");
  return [
    ...(html ? unlabelled(name, text) : []),
    ...(html ? silentErrors(name, text) : []),
    ...(styles ? noFocusRing(name, text) : []),
  ];
}

/** The problems across every page in a directory. */
export function allProblems(dir) {
  return [...PAGES, ...ASSETS].flatMap((page) => pageProblems(page, readFileSync(join(dir, page), "utf8")));
}

/** The accessibility problems across every page in a directory. */
export function allA11yProblems(dir) {
  return MARKUP.flatMap((page) => a11yProblems(page, readFileSync(join(dir, page), "utf8")));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const problems = [...allProblems(root), ...allA11yProblems(root)];
  for (const problem of problems) console.error(problem);
  if (problems.length) {
    console.error(`${problems.length} problem(s): no raw HTML sinks, and every control named, every error announced, every focus ring drawn`);
    process.exit(1);
  }
  console.log(`${PAGES.length} pages: no raw HTML sinks, every control labelled and every error announced`);
}
