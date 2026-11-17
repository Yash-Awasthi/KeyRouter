// The opt-in request log lives in its own module so that the meter can finish a log line without importing the admin
// routes, which import the meter.
import { adminStore } from "./auth.js";

/** One line in the request log: key prefix, model, status, tokens, latency — never a prompt or a response body. */
export async function requestLog(env, entry) {
  try {
    await adminStore(env, "/log", { add: entry });
  } catch {
    // Observability must never break proxying.
  }
}
