import { useCallback, useEffect, useRef, useState } from "react";
import ecs from "../../../fixtures/evaluation/golden/v1/inputs/case-001.json";
import lambda from "../../../fixtures/evaluation/golden/v1/inputs/case-002.json";
import limited from "../../../fixtures/evaluation/golden/v1/inputs/case-005.json";
import { explain, listJobs, newKey, submitJob } from "./api";
import type { Job } from "./contracts";
import { Investigation } from "./Investigation";

const samples = [
  { title: "ECS deployment", description: "Task revisions, application startup, and target health.", input: ecs },
  { title: "Lambda errors", description: "Function errors and downstream database telemetry.", input: lambda },
  { title: "Limited telemetry", description: "An incident with unavailable evidence sources.", input: limited },
];
const readable = (value: string) => value.replaceAll("_", " ");
const timestamp = (seconds: number) => new Date(seconds * 1000).toLocaleString();

export function Workspace() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selected, setSelected] = useState<string>();
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const updateJob = useCallback((job: Job) => {
    setJobs((current) => {
      const previous = current.find((item) => item.id === job.id);
      if (previous && previous.revision >= job.revision) return current;
      return [job, ...current.filter((item) => item.id !== job.id)]
        .sort((left, right) => right.created_at - left.created_at).slice(0, 50);
    });
  }, []);
  useEffect(() => {
    const abort = new AbortController();
    let loading = false;
    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const result = await listJobs(abort.signal);
        if (!abort.signal.aborted) {
          setJobs((current) => result.map((job) => {
            const newer = current.find((item) => item.id === job.id && item.revision > job.revision);
            return newer ?? job;
          }));
          setError("");
        }
      }
      catch (error) { if (!abort.signal.aborted) setError(explain(error)); }
      finally { loading = false; }
    };
    void load(); const timer = setInterval(() => { void load(); }, 15_000);
    return () => { abort.abort(); clearInterval(timer); };
  }, [refresh]);
  const open = (job: Job) => { setSelected(job.id); setRefresh((value) => value + 1); };
  return <div className="workspace">
    <aside className="sidebar" aria-label="Investigation history">
      <button className="primary new-investigation" onClick={() => setSelected(undefined)}>+ New investigation</button>
      <div className="section-heading"><h2>Recent investigations</h2><button aria-label="Refresh history" onClick={() => setRefresh((value) => value + 1)}>↻</button></div>
      <p className="footnote">Latest 50 · refreshes every 15 seconds</p>
      {error && <p role="alert" className="error">{error}</p>}
      {!jobs.length && <p className="empty">No investigations yet. Start with a synthetic fixture.</p>}
      <ul className="history">{jobs.map((job) => <li key={job.id}>
        <button className={selected === job.id ? "selected" : ""} aria-current={selected === job.id ? "true" : undefined} onClick={() => setSelected(job.id)}>
          <span className="history-row"><code>{job.id.slice(0, 8)}</code><span className={`badge ${job.status}`}>{job.status}</span></span>
          <span className="footnote">{timestamp(job.created_at)}</span>
          <span className="footnote">{job.replay_of ? "Replay · " : "Fixture · "}{job.report_status === "none" ? readable(job.stage) : job.report_status}</span>
        </button>
      </li>)}</ul>
    </aside>
    <main id="main" className="main-content">
      <div className="mode-note">OFFLINE WORKSPACE <span>Read-only investigation · recommendations require operator review</span></div>
      {selected ? <Investigation key={selected} id={selected} open={open} updateJob={updateJob} /> : <Launcher open={open} />}
    </main>
  </div>;
}

function Launcher({ open }: { open: (job: Job) => void }) {
  const [sample, setSample] = useState(0);
  const [custom, setCustom] = useState(false);
  const [raw, setRaw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const key = useRef(newKey());
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => { abort.current?.abort(); }, []);
  const changed = () => { key.current = newKey(); setError(""); };
  return <>
    <p className="eyebrow">INVESTIGATIONS / NEW</p><h1>Start with the evidence.</h1>
    <p className="lede">Replay a captured incident through scope, correlation, hypothesis review, and a cited report.</p>
    <form onSubmit={(event) => {
      event.preventDefault(); setBusy(true); setError("");
      const controller = new AbortController(); abort.current = controller;
      void (async () => {
        try {
          const job = await submitJob(custom ? raw : JSON.stringify(samples[sample]?.input), key.current, controller.signal);
          if (!controller.signal.aborted) open(job);
        } catch (error) { if (!controller.signal.aborted) setError(explain(error)); }
        finally { if (!controller.signal.aborted) setBusy(false); }
      })();
    }}>
      <fieldset disabled={busy}><legend>Choose a synthetic incident</legend>
        <div className="sample-grid">{samples.map((item, index) => <label className={`sample ${!custom && sample === index ? "active" : ""}`} key={item.title}>
          <input type="radio" name="fixture" checked={!custom && sample === index} onChange={() => { setSample(index); setCustom(false); changed(); }} />
          <strong>{item.title}</strong><span>{item.description}</span><small>{item.input.workload === "ecs_fargate" ? "ECS / Fargate" : "Lambda / DynamoDB"}</small>
        </label>)}</div>
        <label className="custom-choice"><input type="radio" name="fixture" checked={custom} onChange={() => { setCustom(true); changed(); }} /> Paste a synthetic incident JSON</label>
        {custom && <><label htmlFor="incident-json">Incident input · maximum 1 MiB</label><textarea id="incident-json" spellCheck={false} required value={raw} maxLength={1024 * 1024}
          onChange={(event) => { setRaw(event.target.value); changed(); }} /><p className="footnote">Use the fixture input schema. No credentials, raw production data, or gold labels.</p></>}
      </fieldset>
      <div className="launch-footer"><div><strong>Deterministic fixture runtime</strong><p className="footnote">No AWS credentials needed. Historical matching is disabled.</p></div>
        <button className="primary" disabled={busy} type="submit">{busy ? "Starting…" : "Start investigation"}</button></div>
      {error && <p role="alert" className="error">{error}</p>}
    </form>
    <section className="panel expectations"><h2>What this run produces</h2><div className="three-columns">
      <div><span className="step-number">01</span><h3>Evidence trail</h3><p>Sanitized observations and explicit gaps in telemetry coverage.</p></div>
      <div><span className="step-number">02</span><h3>Reviewed hypotheses</h3><p>Supported, contradicted, or unresolved causes with source citations.</p></div>
      <div><span className="step-number">03</span><h3>Remediation plan</h3><p>Operator-only recommendations with risk, rollback, and validation.</p></div>
    </div></section>
  </>;
}
