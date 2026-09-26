import { afterEach, expect, test, vi } from "vitest";
import { clearSession, hasSession, logout, pair, sessionRequest } from "./session";

const headers = { "X-Incident-API-Schema": "1.0.0" };

afterEach(() => { clearSession(); vi.unstubAllGlobals(); });

test("keeps credentials out of URLs and browser storage", async () => {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ token: "a".repeat(43) }), { headers })));
  vi.stubGlobal("fetch", fetchMock);
  const storage = vi.spyOn(Storage.prototype, "setItem");
  await pair("pairing-secret");
  await sessionRequest("/api/v1/session");
  const [url, options] = fetchMock.mock.calls[1]!;
  expect(url).toBe("http://127.0.0.1:8000/api/v1/session");
  expect(new Headers(options?.headers).get("Authorization")).toBe(`Bearer ${"a".repeat(43)}`);
  expect(options?.credentials).toBe("omit");
  expect(storage).not.toHaveBeenCalled();
  await logout();
  await expect(sessionRequest("/api/v1/session")).rejects.toThrow();
  storage.mockRestore();
});

test("forgets expired sessions and rejects external URLs", async () => {
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(JSON.stringify({ token: "b".repeat(43) }), { headers }))
    .mockResolvedValue(new Response(null, { status: 401 }));
  vi.stubGlobal("fetch", fetchMock);
  await pair("pairing-secret");
  await expect(sessionRequest("https://evil.example")).rejects.toThrow();
  await expect(sessionRequest("/api/v1/../../outside")).rejects.toThrow();
  await expect(sessionRequest("/api/v1/session")).rejects.toThrow("expired");
  await expect(sessionRequest("/api/v1/session")).rejects.toThrow();
});

test("rejects incompatible builds and late pairing responses", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ token: "a".repeat(43) }))));
  await expect(pair("secret")).rejects.toThrow("versions");
  let complete!: (response: Response) => void;
  vi.stubGlobal("fetch", vi.fn().mockReturnValue(new Promise<Response>((resolve) => { complete = resolve; })));
  const pending = pair("secret");
  clearSession();
  complete(new Response(JSON.stringify({ token: "a".repeat(43) }), { headers }));
  await expect(pending).rejects.toThrow("expired");
  expect(hasSession()).toBe(false);
});
