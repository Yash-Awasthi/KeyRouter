// Wrangler imports .html, and the admin page's .css/.js.txt, as text modules ("rules" in wrangler.jsonc); tsc needs
// to know each one is a string. The page script keeps a .txt suffix so tsc never tries to type-check browser code and
// never reads it as a module; the worker still serves it at /admin/admin.js.
declare module "*.html" {
  const body: string;
  export default body;
}

declare module "*.css" {
  const body: string;
  export default body;
}

declare module "*.txt" {
  const body: string;
  export default body;
}
