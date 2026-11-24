// The five pages, the admin page's two asset files, and the headers they are served with. Pages are static: the
// browser fetches its data from the admin and usage endpoints with the session cookie, so no token or key is ever
// templated into the HTML.
//
// The CSP is strict: no inline code at all. The admin page loads `/admin/admin.css` and `/admin/admin.js`; the other
// four still carry one inline block each, so they are served with a per-response nonce that is put on the tags the
// worker finds. Either way the browser refuses anything the worker did not stamp.
import { randomHex } from "./crypto.js";
import ADMIN_CSS from "../pages/admin.css.txt";
import ADMIN_JS from "../pages/admin.js.txt";
import ADMIN_PAGE from "../admin.html";
import JOIN_PAGE from "../join.html";
import LOGIN_PAGE from "../login.html";
import SHARE_PAGE from "../share.html";
import USAGE_PAGE from "../usage.html";

export { ADMIN_CSS, ADMIN_JS, ADMIN_PAGE, JOIN_PAGE, LOGIN_PAGE, SHARE_PAGE, USAGE_PAGE };

// Every page and asset gets the same hardening, so no route can be the one that forgot. The HSTS header is
// ignored over plain HTTP, so it costs nothing on a local deployment and pins the real one for six months.
const HEADERS = {
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  "strict-transport-security": "max-age=15552000; includeSubDomains",
  "permissions-policy": "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()",
};

/** The policy for a page with no inline code: only the two files the shell names may load. */
const externalPolicy = () => ["default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "img-src 'self' data:", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"].join("; ");

/** The policy for a page whose inline block is stamped with a nonce. */
const noncePolicy = (nonce) => ["default-src 'none'", `script-src 'nonce-${nonce}'`, `style-src 'nonce-${nonce}'`, "connect-src 'self'", "img-src 'self' data:", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"].join("; ");

/** A page with no inline code (the admin page): its assets are separate files under a `'self'` policy. */
export const page = (html) =>
  new Response(html, {
    headers: {
      ...HEADERS,
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": externalPolicy(),
    },
  });

/**
 * A page that carries its script and style inline: every `<script>`/`<style>` gets this response's nonce, and the
 * policy names that nonce and nothing else, so an injected tag cannot run.
 */
export const inlinePage = (html) => {
  const nonce = randomHex(16);
  const stamped = html
    .replace(/<script(\s|>)/g, `<script nonce="${nonce}"$1`)
    .replace(/<style(\s|>)/g, `<style nonce="${nonce}"$1`);
  return new Response(stamped, {
    headers: {
      ...HEADERS,
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": noncePolicy(nonce),
    },
  });
};

/** The two files the admin page's CSP allows: text, from this origin, never cached. */
export const asset = (body, type) =>
  new Response(body, {
    headers: { ...HEADERS, "content-type": type, "content-security-policy": "default-src 'none'; frame-ancestors 'none'" },
  });
