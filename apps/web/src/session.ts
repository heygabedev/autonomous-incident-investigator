const base = import.meta.env.DEV ? "http://127.0.0.1:8000" : "";
let token: string | undefined;

export async function pair(secret: string): Promise<void> {
  const response = await fetch(`${base}/api/v1/session`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret }), credentials: "omit", cache: "no-store",
  });
  if (!response.ok) throw new Error("Pairing failed. Request a new code in the app terminal.");
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || !("token" in result) ||
      typeof result.token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(result.token)) {
    throw new Error("Invalid session response.");
  }
  token = result.token;
}

export async function sessionRequest(path: string, method = "GET"): Promise<Response> {
  if (!token || !path.startsWith("/api/v1/") || /[?#\\]/.test(path) || path.includes("..")) {
    throw new Error("A valid local session is required.");
  }
  const response = await fetch(`${base}${path}`, {
    method, headers: { Authorization: `Bearer ${token}` }, credentials: "omit", cache: "no-store",
  });
  if (response.status === 401) token = undefined;
  return response;
}

export async function logout(): Promise<void> {
  try { await sessionRequest("/api/v1/session", "DELETE"); }
  finally { token = undefined; }
}
