import { z } from "zod";

const version = z.literal("1.0.0");
const identifier = z.string().min(1).max(128);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
export const jobId = z.string().regex(/^[0-9a-f]{32}$/);
const evidenceId = z.string().regex(/^ev-[0-9a-f]{64}$/);
const cause = z.enum(["missing_required_environment_variable", "dynamodb_write_throttling",
  "target_group_port_mismatch", "execution_role_permission_removed"]);
export const recallReason = z.enum(["operator_request", "invalidated_evidence", "defective_runtime", "security_review"]);
export type RecallReason = z.infer<typeof recallReason>;
const pin = z.object({ release_id: identifier, candidate_id: identifier, candidate_digest: digest,
  graph_digest: digest, policy_digest: digest, graph_version: version, state_version: version,
  report_version: version, mode: z.literal("fixture") });
export const jobSchema = z.object({ schema_version: version, id: jobId,
  status: z.enum(["queued", "running", "succeeded", "failed", "cancelled"]), pin,
  input_digest: digest, revision: z.number().int().min(1), created_at: z.number().int().min(0),
  updated_at: z.number().int().min(0),
  stage: z.enum(["scope", "collect", "correlate", "hypothesize", "verify", "request", "history", "plan", "report", "done"]),
  completed_steps: z.number().int().min(0).max(20), dispatch_attempts: z.number().int().min(0).max(3),
  failure: z.enum(["cancelled", "restricted", "incompatible_runtime", "execution_failed"]).nullable(),
  replay_of: jobId.nullable(), report_status: z.enum(["none", "available", "recalled", "superseded"]),
  recall_reason: recallReason.nullable(), replacement_id: jobId.nullable(),
});
export const evidenceSchema = z.object({ id: evidenceId, sanitizer_version: version,
  account_id: z.literal("000000000000"), region: z.literal("eu-central-1"), resource: identifier,
  fields: z.array(z.object({ name: z.enum(["error_code", "operation", "status", "metric_name", "value", "unit"]),
    value: z.string().max(256) })).min(1).max(6),
});
const citations = z.array(evidenceId).min(1).max(100);
const prose = z.string().min(1).max(4096);
export const reportSchema = z.object({ schema_version: version, attempt_id: jobId, pin,
  status: z.enum(["resolved", "degraded", "unresolved"]),
  hypotheses: z.array(z.object({ cause, evidence_ids: citations,
    verdict: z.enum(["pending", "supported", "insufficient", "contradicted"]) })).max(4),
  recommendations: z.array(z.object({ cause, instruction: prose, prerequisites: prose, risk: prose,
    rollback: prose, validation: prose, evidence_ids: citations, execution: z.literal("operator_only"),
    source: z.literal("reviewed_template") })).max(3),
  gaps: z.array(z.object({ source_id: identifier, modality: z.enum(["log", "metric", "trace", "change"]),
    reason: z.enum(["permission_denied", "unavailable", "unsupported_payload"]) })).max(100),
  evidence_ids: z.array(evidenceId).max(100), history_status: z.literal("disabled"),
  confidence: z.literal("uncalibrated_fixture_rules"), model_calls: z.literal(0), cost_microdollars: z.literal(0),
});
export const eventSchema = z.object({ schema_version: version, sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), job: jobSchema });
export type Job = z.infer<typeof jobSchema>;
export type Evidence = z.infer<typeof evidenceSchema>;
export type Report = z.infer<typeof reportSchema>;
export const terminal = (job: Job) => ["succeeded", "failed", "cancelled"].includes(job.status);
export function validateReport(job: Job, evidence: Evidence[], report: Report): Report {
  const ids = new Set(evidence.map((item) => item.id));
  const declared = new Set(report.evidence_ids);
  if (report.attempt_id !== job.id || JSON.stringify(report.pin) !== JSON.stringify(job.pin) ||
      ids.size !== evidence.length || report.evidence_ids.some((id) => !ids.has(id)) ||
      [...report.hypotheses, ...report.recommendations].some((item) =>
        item.evidence_ids.some((id) => !ids.has(id) || !declared.has(id)))) {
    throw new Error("Report integrity check failed.");
  }
  return report;
}
