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

test("a late unauthorized response cannot revoke a newer session", async () => {
  const mock = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(JSON.stringify({ token: "a".repeat(43) }), { headers }));
  vi.stubGlobal("fetch", mock); await pair("first");
  let complete!: (response: Response) => void;
  mock.mockReturnValueOnce(new Promise<Response>((resolve) => { complete = resolve; }));
  const pending = sessionRequest("/api/v1/session");
  mock.mockResolvedValueOnce(new Response(JSON.stringify({ token: "b".repeat(43) }), { headers }));
  await pair("second");
  complete(new Response(null, { status: 401, headers }));
  await expect(pending).rejects.toThrow("changed");
  expect(hasSession()).toBe(true);
});

test("version mismatches lock the console and server error payloads stay private", async () => {
  const mock = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(JSON.stringify({ token: "a".repeat(43) }), { headers }));
  vi.stubGlobal("fetch", mock); await pair("secret");
  mock.mockResolvedValueOnce(new Response("sensitive exception", { status: 503, headers }));
  await expect(sessionRequest("/api/v1/session")).rejects.toThrow("unavailable");
  mock.mockResolvedValueOnce(new Response("{}", { headers: { "X-Incident-API-Schema": "2.0.0" } }));
  await expect(sessionRequest("/api/v1/session")).rejects.toThrow("versions");
  expect(hasSession()).toBe(false);
});

test("bounds pairing response bodies before decoding JSON", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("x".repeat(4097), { headers })));
  await expect(pair("secret")).rejects.toThrow("Oversized");
  expect(hasSession()).toBe(false);
});
