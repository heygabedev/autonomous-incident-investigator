import { z } from "zod";
import { evidenceSchema, eventSchema, jobId, jobSchema, reportSchema, terminal } from "./contracts";
import type { Job, RecallReason } from "./contracts";
import { ClientError, compatible, sessionRequest, sessionRevision } from "./session";

const root = "/api/v1/investigations";
const limit = 1024 * 1024;
const path = (id: string) => `${root}/${jobId.parse(id)}`;
export const newKey = () => crypto.randomUUID().replaceAll("-", "");
export const explain = (error: unknown) => error instanceof ClientError ? error.message :
  "Could not verify the response. Refresh or check the local service.";
async function bounded(response: Response) {
  if (!response.body) throw new Error("Missing body");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "", size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error("Oversized response");
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
}
async function request<T>(route: string, schema: z.ZodType<T>, signal?: AbortSignal, method = "GET", body?: string) {
  const revision = sessionRevision();
  const response = await sessionRequest(route, method, { signal, body });
  const raw = await bounded(response);
  if (revision !== sessionRevision() || signal?.aborted) throw new Error("Stale response");
  return schema.parse(JSON.parse(raw));
}
export const listJobs = (signal?: AbortSignal) => request(root, z.array(jobSchema).max(50), signal);
export const getJob = (id: string, signal?: AbortSignal) => request(path(id), jobSchema, signal);
export const getEvidence = (id: string, signal?: AbortSignal) => request(`${path(id)}/evidence`, z.array(evidenceSchema).max(100), signal);
export const getReport = (id: string, signal?: AbortSignal, download = false) => request(`${path(id)}/report${download ? "/export" : ""}`, reportSchema, signal);
export const cancelJob = (id: string, signal?: AbortSignal) => request(path(id), jobSchema, signal, "DELETE");
export const recallReport = (id: string, reason: RecallReason, signal?: AbortSignal) => request(`${path(id)}/report/recall`, jobSchema, signal, "POST", JSON.stringify({ reason }));
export const replayJob = (id: string, key: string, signal?: AbortSignal) => request(`${path(id)}/replays`, jobSchema, signal, "POST", JSON.stringify({ idempotency_key: jobId.parse(key), mode: "candidate" }));
export function submitJob(raw: string, key: string, signal?: AbortSignal) {
  // Keep the original JSON so duplicate keys reach the strict server decoder.
  const body = `{"idempotency_key":${JSON.stringify(jobId.parse(key))},"incident":${raw}}`;
  if (new TextEncoder().encode(body).byteLength > limit) throw new ClientError("Input exceeds the 1 MiB limit.");
  return request(root, jobSchema, signal, "POST", body);
}
export class EventDecoder {
  private buffer = "";
  constructor(private readonly id: string, public cursor = 0) {}
  push(chunk: string) {
    this.buffer += chunk;
    if (this.buffer.length > limit) throw new Error("Oversized event");
    const results: z.infer<typeof eventSchema>[] = [];
    let boundary;
    while ((boundary = this.buffer.indexOf("\n\n")) >= 0) {
      const frame = this.buffer.slice(0, boundary); this.buffer = this.buffer.slice(boundary + 2);
      const lines = frame.split("\n").filter((line) => line && !line.startsWith(":"));
      if (!lines.length) continue;
      if (lines.length !== 3 || !/^id: [1-9][0-9]*$/.test(lines[0] ?? "") ||
          lines[1] !== "event: progress" || !lines[2]?.startsWith("data: ")) throw new Error("Invalid event");
      const event = eventSchema.parse(JSON.parse(lines[2].slice(6)));
      if (event.job.id !== this.id || event.sequence <= this.cursor || lines[0] !== `id: ${event.sequence}`) throw new Error("Invalid cursor");
      this.cursor = event.sequence; results.push(event);
    }
    return results;
  }
  finish() { if (this.buffer.trim()) throw new Error("Truncated stream"); }
}
function pause(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const stop = () => { clearTimeout(timer); reject(new Error("Aborted")); };
    const timer = setTimeout(() => { signal.removeEventListener("abort", stop); resolve(); }, ms);
    signal.addEventListener("abort", stop, { once: true });
    if (signal.aborted) stop();
  });
}
export async function watchJob(id: string, signal: AbortSignal, update: (job: Job) => void,
  connection: (state: string) => void) {
  const revision = sessionRevision();
  let cursor = 0, failures = 0;
  while (!signal.aborted) {
    try {
      const response = await sessionRequest(`${path(id)}/events`, "GET", { signal, cursor });
      compatible(response, true);
      if (!response.headers.get("Content-Type")?.startsWith("text/event-stream") || !response.body) throw new Error("Invalid stream");
      const reader = response.body.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
      const frames = new EventDecoder(id, cursor);
      connection("Connected");
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (signal.aborted || revision !== sessionRevision()) return;
          const events = frames.push(done ? decoder.decode() : decoder.decode(value, { stream: true }));
          for (const event of events) {
            cursor = event.sequence; update(event.job); failures = 0;
            if (terminal(event.job)) { connection("Complete"); return; }
          }
          if (done) { frames.finish(); break; }
        }
      } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
    } catch (error) {
      if (signal.aborted) return;
      if (error instanceof ClientError || ++failures >= 3) throw error;
      connection("Reconnecting");
    }
    await pause(Math.min(1000 * 2 ** failures, 8000), signal);
  }
}
