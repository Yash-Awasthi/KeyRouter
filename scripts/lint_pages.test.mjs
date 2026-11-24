import { test } from "node:test";
import assert from "node:assert/strict";
import { pageProblems, allProblems, allA11yProblems, a11yProblems, unlabelled, silentErrors, noFocusRing, PAGES } from "./lint_pages.mjs";

test("no page assigns raw HTML, and the check would catch it if one did", () => {
  // The real pages are clean, which is the claim the README makes about rendering.
  assert.deepEqual(allProblems(new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1").replace(/\/$/, "")), []);
  // And the detector is not vacuous.
  assert.deepEqual(pageProblems("x.html", 'el.innerHTML = "a"'), ["x.html assigns to innerHTML"]);
  assert.deepEqual(pageProblems("x.html", 'el.innerHTML += "<b>"'), ["x.html assigns to innerHTML"]);
  assert.deepEqual(pageProblems("x.html", 'el.insertAdjacentHTML("beforeend", s)'), ["x.html calls insertAdjacentHTML"]);
  assert.deepEqual(pageProblems("x.html", 'document.write(s)'), ["x.html calls document.write"]);
  assert.deepEqual(pageProblems("x.html", "el.textContent = \"<b>\"".replace("textContent", "outerHTML")), ["x.html assigns to outerHTML"]);
  assert.deepEqual(pageProblems("x.html", 'el.textContent = "<b>safe</b>"'), []);
  assert.equal(PAGES.length, 5);
});

test("every control is labelled, every error announced, every page shows the focus ring", () => {
  const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1").replace(/\/$/, "");
  assert.deepEqual(allA11yProblems(root), []);
  // And the checks are not vacuous: each one names the file and the control it is unhappy about.
  assert.deepEqual(unlabelled("x.html", '<input id="q" placeholder="search">'), ['x.html <input id="q"> has no label']);
  assert.deepEqual(unlabelled("x.html", '<label for="q">Search</label><input id="q">'), []);
  assert.deepEqual(unlabelled("x.html", '<input id="q" aria-label="Search">'), []);
  assert.deepEqual(unlabelled("x.html", '<label>Search <input id="q"></label>'), []);
  // A placeholder is not a label: it vanishes the moment someone types.
  assert.deepEqual(unlabelled("x.html", '<select id="s" placeholder="pick"></select>'), ['x.html <select id="s"> has no label']);
  assert.deepEqual(silentErrors("x.html", '<div class="err" id="err"></div>'), ['x.html #err has no role="alert"']);
  assert.deepEqual(silentErrors("x.html", '<div class="err" id="err" role="alert"></div>'), []);
  assert.deepEqual(silentErrors("x.html", '<div class="err" id="err" aria-live="polite"></div>'), []);
  assert.deepEqual(noFocusRing("x.css", "button { color: red; }"), ["x.css has no visible focus style"]);
  assert.deepEqual(noFocusRing("x.css", ":focus-visible { outline: 2px solid; }"), []);
  // The stylesheet is asked for a ring; the markup that has no styles of its own is not.
  assert.deepEqual(a11yProblems("pages/admin.css.txt", "button { color: red; }"), ["pages/admin.css.txt has no visible focus style"]);
  assert.deepEqual(a11yProblems("pages/admin.js.txt", "const a = 1;"), []);
});
