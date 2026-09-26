import { useEffect, useRef, useState } from "react";
import { cancelJob, explain, getEvidence, getJob, getReport, newKey, recallReport, replayJob, watchJob } from "./api";
import { recallReason, terminal, validateReport } from "./contracts";
import type { Evidence, Job, RecallReason, Report } from "./contracts";

const readable = (value: string) => value.replaceAll("_", " ");
type Snapshot = { job: Job; evidence: Evidence[]; report?: Report };
export function Investigation({ id, open }: { id: string; open: (job: Job) => void }) {
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [error, setError] = useState("");
  const [connection, setConnection] = useState("Connecting");
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState<RecallReason>("operator_request");
  const [confirm, setConfirm] = useState(false);
  const action = useRef<AbortController | null>(null);
  const acting = useRef(false);
  const replayKey = useRef(newKey());
  useEffect(() => () => { action.current?.abort(); }, []);
  useEffect(() => {
    const abort = new AbortController();
    let loading = false, pending = false;
    const load = async () => {
      if (loading) { pending = true; return; }
      loading = true;
      try {
        const job = await getJob(id, abort.signal);
        const evidence = await getEvidence(id, abort.signal);
        const report = job.report_status === "available" ? validateReport(job, evidence, await getReport(id, abort.signal)) : undefined;
        if (!abort.signal.aborted && !acting.current) {
          setSnapshot((current) => current && current.job.revision > job.revision ? current : { job, evidence, report });
          setError("");
        }
      } catch (error) { if (!abort.signal.aborted) { setSnapshot(undefined); setError(explain(error)); } }
      finally { loading = false; if (pending && !abort.signal.aborted) { pending = false; void load(); } }
    };
    void load();
    void watchJob(id, abort.signal, (job) => {
      setSnapshot((current) => !acting.current && current && job.revision >= current.job.revision ?
        { ...current, job, report: job.report_status === "available" ? current.report : undefined } : current);
      if (terminal(job)) void load();
    }, setConnection).catch((error: unknown) => {
      if (!abort.signal.aborted) { setConnection("Disconnected"); setError(explain(error)); }
    });
    const timer = setInterval(() => { void load(); }, 15_000);
    return () => { abort.abort(); clearInterval(timer); };
  }, [id, refresh]);

  const perform = (operation: (signal: AbortSignal) => Promise<void>) => {
    const controller = new AbortController(); action.current = controller;
    acting.current = true;
    setBusy(true); setError("");
    void operation(controller.signal).catch((error: unknown) => {
      if (!controller.signal.aborted) { setSnapshot(undefined); setError(explain(error)); }
    }).finally(() => { acting.current = false; if (!controller.signal.aborted) { setBusy(false); setConfirm(false); } });
  };
  const download = async (signal: AbortSignal) => {
    const job = await getJob(id, signal), evidence = await getEvidence(id, signal);
    const report = validateReport(job, evidence, await getReport(id, signal, true));
    if (signal.aborted) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `investigation-${id}.json`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const job = snapshot?.job, report = snapshot?.report;
  return <>
    <p className="eyebrow">INVESTIGATIONS / {id.slice(0, 8)}</p>
    <div className="page-heading"><h1>Investigation</h1><button disabled={busy} onClick={() => setRefresh((value) => value + 1)}>Refresh investigation</button></div>
    <p className="mono muted full-id">{id}</p>
    {error && <p className="error" role="alert">{error}</p>}
    {!snapshot && !error && <p role="status">Loading verified evidence…</p>}
    {job && <>
      <section className="panel run-summary" aria-label="Run status">
        <div><span className={`badge ${job.status}`}>{job.status}</span><p>{readable(job.stage)} · {job.completed_steps} steps completed</p></div>
        <div><span className="eyebrow">PROGRESS FEED</span><p role="status">{connection}</p></div>
        <div><span className="eyebrow">REPORT</span><p>{readable(job.report_status)}</p></div>
      </section>
      {job.failure && <p className="error">Run stopped: {readable(job.failure)}. No cause is inferred from a failed run.</p>}
      {job.recall_reason && <p className="notice">Report withdrawn: {readable(job.recall_reason)}. Previously downloaded copies cannot be recalled from disk.</p>}
      {job.replay_of && <p className="footnote">Replay of <code>{job.replay_of}</code> using captured evidence, not a fresh collection.</p>}
      {job.replacement_id && <p className="footnote">Replacement investigation: <code>{job.replacement_id}</code></p>}
      <div className="toolbar actions">
        {!terminal(job) && <button disabled={busy} onClick={() => perform(async (signal) => { await cancelJob(id, signal); setRefresh((value) => value + 1); })}>Cancel investigation</button>}
        {terminal(job) && <button disabled={busy || job.recall_reason === "security_review" || job.recall_reason === "invalidated_evidence"}
          onClick={() => perform(async (signal) => { const replay = await replayJob(id, replayKey.current, signal); if (!signal.aborted) open(replay); })}>Replay captured evidence</button>}
        {report && <><button disabled={busy} onClick={() => perform(download)}>Export verified report</button><button disabled={busy} onClick={() => setConfirm(!confirm)} aria-expanded={confirm}>Recall report</button></>}
      </div>
      {confirm && <form className="panel recall" onSubmit={(event) => {
        event.preventDefault(); setSnapshot((current) => current ? { ...current, report: undefined } : current);
        perform(async (signal) => { await recallReport(id, reason, signal); setRefresh((value) => value + 1); });
      }}><h2>Withdraw this report?</h2><p>Publication and export will be blocked. Security review also restricts evidence access and replay.</p>
        <label htmlFor="recall-reason">Recall reason</label><select id="recall-reason" value={reason} disabled={busy} onChange={(event) => setReason(recallReason.parse(event.target.value))}>
          {recallReason.options.map((value) => <option key={value} value={value}>{readable(value)}</option>)}
        </select><div className="toolbar"><button disabled={busy} className="danger" type="submit">Confirm recall</button><button disabled={busy} type="button" onClick={() => setConfirm(false)}>Keep report</button></div>
      </form>}
      {report && <ReportView report={report} />}
      {snapshot && <section className="panel" aria-labelledby="evidence-title"><h2 id="evidence-title">Evidence register <span className="muted">/ {snapshot.evidence.length}</span></h2>
        <p className="footnote">Sanitized structured observations only. Citations refer to stable content identifiers.</p>
        {!snapshot.evidence.length && <p>No evidence is available for this attempt.</p>}
        {snapshot.evidence.map((item, index) => <article className="evidence" id={item.id} key={item.id} tabIndex={-1}>
          <h3>Evidence {index + 1} <span className="muted">· {item.resource}</span></h3><code className="evidence-id">{item.id}</code>
          <dl>{item.fields.map((field) => <div key={field.name}><dt>{readable(field.name)}</dt><dd>{field.value}</dd></div>)}</dl>
        </article>)}
      </section>}
      <details className="panel provenance"><summary>Runtime provenance</summary><p className="footnote">Development fixture identity, not an approved production release. Historical matching and model reasoning are disabled.</p>
        <dl>{Object.entries(job.pin).map(([name, value]) => <div key={name}><dt>{readable(name)}</dt><dd><code>{value}</code></dd></div>)}</dl>
      </details>
    </>}
  </>;
}
function Citations({ ids }: { ids: string[] }) {
  return <div className="citations" aria-label="Evidence citations">{ids.map((id, index) => <a href={`#${id}`} key={id} onClick={() => document.getElementById(id)?.focus()}>
    Source {index + 1} <span className="mono">{id.slice(3, 11)}</span></a>)}</div>;
}
export function ReportView({ report }: { report: Report }) {
  return <>
    <section className="panel" aria-labelledby="assessment-title"><div className="section-heading"><h2 id="assessment-title">Cause assessment</h2><span className={`badge ${report.status}`}>{report.status}</span></div>
      <p className="footnote">Deterministic fixture rules · uncalibrated · no probability estimate</p>
      {!report.hypotheses.length && <p>No supported cause could be established from the available evidence.</p>}
      {report.hypotheses.map((item) => <article className="hypothesis" key={item.cause}><h3>{readable(item.cause)}</h3><p className="muted">{item.verdict}</p><Citations ids={item.evidence_ids} /></article>)}
      {!!report.gaps.length && <div className="notice"><h3>Coverage gaps</h3><ul>{report.gaps.map((gap) => <li key={gap.source_id}>{gap.modality} / {gap.source_id}: {readable(gap.reason)}</li>)}</ul></div>}
    </section>
    <section className="panel" aria-labelledby="remediation-title"><h2 id="remediation-title">Remediation plan</h2><p className="notice">Operator review required. This console cannot execute remediation.</p>
      {!report.recommendations.length && <p>No action is recommended with the current evidence.</p>}
      {report.recommendations.map((item) => <article className="recommendation" key={item.cause}><h3>{item.instruction}</h3>
        <dl>{(["prerequisites", "risk", "rollback", "validation"] as const).map((field) => <div key={field}><dt>{readable(field)}</dt><dd>{item[field]}</dd></div>)}</dl><Citations ids={item.evidence_ids} />
        <p className="footnote">Source: reviewed template · no historical actions included</p>
      </article>)}
    </section>
  </>;
}
