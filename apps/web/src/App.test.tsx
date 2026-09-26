import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import * as api from "./api";
import { clearSession, hasSession, pair } from "./session";

import { App } from "./App";

afterEach(() => { cleanup(); clearSession(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

test("requires pairing before showing investigations", () => {
  render(<App />);

  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "Autonomous Incident Investigator",
  );
  expect(screen.getByLabelText("Pairing code from the app terminal")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Start investigation" })).not.toBeInTheDocument();
});

test("background refresh does not extend browser idle expiry", async () => {
  vi.useFakeTimers();
  vi.spyOn(api, "listJobs").mockResolvedValue([]);
  vi.stubGlobal("fetch", vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ token: "a".repeat(43) }),
    { headers: { "X-Incident-API-Schema": "1.0.0" } }))));
  await pair("secret");
  render(<App />);
  await act(() => vi.advanceTimersByTimeAsync(29 * 60 * 1000));
  expect(hasSession()).toBe(true);
  fireEvent.keyDown(window, { key: "Tab" });
  await act(() => vi.advanceTimersByTimeAsync(29 * 60 * 1000));
  expect(hasSession()).toBe(true);
  await act(() => vi.advanceTimersByTimeAsync(60 * 1000));
  expect(screen.getByRole("button", { name: "Unlock console" })).toBeInTheDocument();
  expect(hasSession()).toBe(false);
});
