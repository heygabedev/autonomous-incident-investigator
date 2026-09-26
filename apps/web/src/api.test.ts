import { afterEach, expect, test, vi } from "vitest";
import { EventDecoder, getReport, listJobs, submitJob, watchJob } from "./api";
import { jobSchema, reportSchema, validateReport } from "./contracts";
import { clearSession, pair } from "./session";
import { evidence, id, job, report } from "./test/factories";

const headers = { "X-Incident-API-Schema": "1.0.0" };
afterEach(() => { clearSession(); vi.unstubAllGlobals(); });
async function connected() {
  const mock = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(JSON.stringify({ token: "a".repeat(43) }), { headers }));
  vi.stubGlobal("fetch", mock); await pair("secret"); return mock;
}
test("validates report provenance and every evidence reference", () => {
  expect(validateReport(jobSchema.parse(job), [evidence], reportSchema.parse(report))).toEqual(report);
  expect(() => validateReport(job, [], report)).toThrow();
  expect(() => validateReport(job, [evidence, evidence], report)).toThrow();
  expect(() => validateReport(job, [evidence], { ...report, attempt_id: "b".repeat(32) })).toThrow();
  expect(() => validateReport(job, [evidence], { ...report, pin: { ...job.pin, candidate_id: "other" } })).toThrow();
  expect(() => validateReport(job, [evidence], { ...report, evidence_ids: [] })).toThrow();
  expect(() => reportSchema.parse({ ...report, model_calls: 1 })).toThrow();
});
test("streams split frames, validates cursors and rejects wrong investigations", () => {
  const parser = new EventDecoder(id);
  const frame = `id: 4\nevent: progress\ndata: ${JSON.stringify({ schema_version: "1.0.0", sequence: 4, job })}\n\n`;
  expect(parser.push(": keep-alive\n\n" + frame.slice(0, 12))).toEqual([]);
  expect(parser.push(frame.slice(12))[0]?.job).toEqual(job);
  parser.finish();
  expect(() => parser.push(frame)).toThrow();
  expect(() => new EventDecoder("b".repeat(32)).push(frame)).toThrow();
  expect(() => new EventDecoder(id).push(frame.replace("id: 4", "id: 5"))).toThrow();
  expect(() => new EventDecoder(id).push("x".repeat(1024 * 1024 + 1))).toThrow();
  const truncated = new EventDecoder(id); truncated.push("id: 1");
  expect(() => truncated.finish()).toThrow();
});
test("validates bounded responses and keeps original input JSON", async () => {
  const mock = await connected();
  mock.mockResolvedValueOnce(new Response(JSON.stringify(job), { headers }));
  await submitJob('{"case_id":"first","case_id":"second"}', id);
  expect(mock.mock.calls[1]?.[1]?.body).toContain('"case_id":"first","case_id":"second"');
  mock.mockResolvedValueOnce(new Response(JSON.stringify([job]), { headers }));
  expect(await listJobs()).toEqual([job]);
  mock.mockResolvedValueOnce(new Response("x".repeat(1024 * 1024 + 1), { headers }));
  await expect(getReport(id)).rejects.toThrow("Oversized");
  mock.mockResolvedValueOnce(new Response(JSON.stringify({ ...report, schema_version: "2.0.0" }), { headers }));
  await expect(getReport(id)).rejects.toThrow();
});
test("uses authenticated fetch for events and closes on terminal state", async () => {
  const mock = await connected();
  mock.mockResolvedValueOnce(new Response(`id: 1\nevent: progress\ndata: ${JSON.stringify({ schema_version: "1.0.0", sequence: 1, job })}\n\n`,
    { headers: { ...headers, "X-Incident-Event-Schema": "1.0.0", "Content-Type": "text/event-stream" } }));
  const update = vi.fn(), connection = vi.fn();
  await watchJob(id, new AbortController().signal, update, connection);
  expect(update).toHaveBeenCalledWith(job);
  expect(connection).toHaveBeenLastCalledWith("Complete");
  expect(new Headers(mock.mock.calls[1]?.[1]?.headers).get("Authorization")).toMatch(/^Bearer /);
});

test("reconnects from the last event and aborts without delivering stale data", async () => {
  vi.useFakeTimers();
  try {
    const mock = await connected();
    const streamHeaders = { ...headers, "X-Incident-Event-Schema": "1.0.0", "Content-Type": "text/event-stream" };
    const frame = (sequence: number, status: string) => `id: ${sequence}\nevent: progress\ndata: ${JSON.stringify({ schema_version: "1.0.0", sequence, job: { ...job, status } })}\n\n`;
    mock.mockResolvedValueOnce(new Response(frame(5, "running"), { headers: streamHeaders }));
    mock.mockResolvedValueOnce(new Response(frame(7, "succeeded"), { headers: streamHeaders }));
    const update = vi.fn();
    const pending = watchJob(id, new AbortController().signal, update, vi.fn());
    await vi.advanceTimersByTimeAsync(1001); await pending;
    expect(new Headers(mock.mock.calls[2]?.[1]?.headers).get("Last-Event-ID")).toBe("5");
    expect(update).toHaveBeenCalledTimes(2);
    const abort = new AbortController(); abort.abort();
    await watchJob(id, abort.signal, update, vi.fn());
    expect(update).toHaveBeenCalledTimes(2);
  } finally { vi.useRealTimers(); }
});
