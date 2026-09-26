import type { Evidence, Job, Report } from "../contracts";
export const id = "a".repeat(32);
export const digest = `sha256:${"a".repeat(64)}`;
export const ev = `ev-${"b".repeat(64)}`;
export const job: Job = { schema_version: "1.0.0", id, status: "succeeded",
  pin: { release_id: "development", candidate_id: "offline", candidate_digest: digest,
    graph_digest: digest, policy_digest: digest, graph_version: "1.0.0", state_version: "1.0.0",
    report_version: "1.0.0", mode: "fixture" }, input_digest: digest, revision: 2,
  created_at: 1, updated_at: 2, stage: "done", completed_steps: 10, dispatch_attempts: 1,
  failure: null, replay_of: null, report_status: "available", recall_reason: null, replacement_id: null };
export const evidence: Evidence = { id: ev, sanitizer_version: "1.0.0", account_id: "000000000000",
  region: "eu-central-1", resource: "synthetic-checkout", fields: [{ name: "status", value: "env_removed" }] };
export const report: Report = { schema_version: "1.0.0", attempt_id: id, pin: job.pin,
  status: "resolved", hypotheses: [{ cause: "missing_required_environment_variable", evidence_ids: [ev], verdict: "supported" }],
  recommendations: [], gaps: [], evidence_ids: [ev], history_status: "disabled",
  confidence: "uncalibrated_fixture_rules", model_calls: 0, cost_microdollars: 0 };
