import { readBounded } from "./response";

const base = import.meta.env.DEV ? "http://127.0.0.1:8000" : "";
let token: string | undefined;
let revision = 0;
const listeners = new Set<() => void>();

export class ClientError extends Error {
  constructor(message: string, readonly status = 0) { super(message); }
}
export const hasSession = () => token !== undefined;
export const sessionRevision = () => revision;
export function subscribeSession(listener: () => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
export function clearSession() {
  token = undefined; revision += 1;
  listeners.forEach((listener) => listener());
}
export function compatible(response: Response, stream = false) {
  if (response.headers.get("X-Incident-API-Schema") !== "1.0.0" ||
      (stream && response.headers.get("X-Incident-Event-Schema") !== "1.0.0")) {
    clearSession();
    throw new ClientError("Console and API versions do not match. Install matching builds.");
  }
}
export async function pair(secret: string): Promise<void> {
  clearSession();
  const attempt = revision;
  const response = await fetch(`${base}/api/v1/session`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret }), credentials: "omit", cache: "no-store",
    redirect: "error", signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new ClientError("Pairing failed. Request a new code in the app terminal.");
  compatible(response);
  const result: unknown = JSON.parse(await readBounded(response, 4096));
  if (!result || typeof result !== "object" || !("token" in result) ||
      typeof result.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(result.token) || attempt !== revision) {
    throw new ClientError("Invalid or expired pairing response.");
  }
  token = result.token;
  listeners.forEach((listener) => listener());
}
export async function sessionRequest(path: string, method = "GET",
  options: { body?: string; signal?: AbortSignal; cursor?: number } = {}): Promise<Response> {
  if (!token || !/^\/api\/v1\/(session|investigations)(\/[a-z0-9/-]+)?$/.test(path)) {
    throw new ClientError("A valid local session is required.");
  }
  const credential = token;
  const headers: Record<string, string> = { Authorization: `Bearer ${credential}` };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.cursor) headers["Last-Event-ID"] = String(options.cursor);
  const timeout = AbortSignal.timeout(path.endsWith("/events") ? 40_000 : 10_000);
  const response = await fetch(`${base}${path}`, {
    method, headers, body: options.body, credentials: "omit", cache: "no-store", redirect: "error",
    signal: options.signal ? AbortSignal.any([timeout, options.signal]) : timeout,
  });
  if (credential !== token) throw new ClientError("Session changed. Pair again to continue.");
  if (response.status === 401) {
    clearSession(); throw new ClientError("Session expired. Pair again to continue.", 401);
  }
  compatible(response);
  if (!response.ok) {
    const messages: Record<number, string> = {
      403: "Access blocked by the current security policy.", 404: "Investigation not found.",
      409: "This action is no longer available. Refresh the investigation.",
      422: "The incident input is invalid. Use a supported synthetic fixture.",
      429: "Request limit reached. Wait a minute before retrying.",
      503: "The local service is unavailable or contained. Check the app terminal.",
    };
    throw new ClientError(messages[response.status] ?? "The request could not be completed.", response.status);
  }
  return response;
}
export async function logout(): Promise<void> {
  const request = sessionRequest("/api/v1/session", "DELETE");
  clearSession();
  await request.catch(() => undefined);
}
