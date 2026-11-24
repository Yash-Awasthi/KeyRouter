// Response helpers shared by the router and both Durable Objects.

export const isJson = (req) => req.headers.get("content-type")?.split(";")[0].trim().toLowerCase() === "application/json";

export function json(status, message, headers) {
  return Response.json({ error: { message } }, { status, headers });
}

export function cors(res, req) {
  const out = new Response(res.body, res);
  out.headers.set("access-control-allow-origin", "*");
  if (req.method === "OPTIONS") {
    out.headers.set("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE");
    out.headers.set("access-control-allow-headers", req.headers.get("access-control-request-headers") || "*");
    out.headers.set("access-control-max-age", "86400");
  }
  return out;
}
