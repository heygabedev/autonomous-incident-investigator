import { useEffect, useState, useSyncExternalStore } from "react";
import { hasSession, logout, pair, subscribeSession } from "./session";
import { explain } from "./api";
import { Workspace } from "./Workspace";

export function App() {
  const unlocked = useSyncExternalStore(subscribeSession, hasSession);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!unlocked) return;
    // Polling and stream reconnects must not keep an unattended browser unlocked.
    let timer = setTimeout(() => { void logout(); }, 30 * 60 * 1000);
    const activity = () => {
      clearTimeout(timer);
      timer = setTimeout(() => { void logout(); }, 30 * 60 * 1000);
    };
    window.addEventListener("pointerdown", activity);
    window.addEventListener("keydown", activity);
    return () => {
      clearTimeout(timer); window.removeEventListener("pointerdown", activity);
      window.removeEventListener("keydown", activity);
    };
  }, [unlocked]);
  return <>
    <a className="skip-link" href="#main">Skip to workspace</a>
    <header className="topbar">
      <span className="brand"><span aria-hidden="true" className="brand-mark">I /</span> INCIDENT INVESTIGATOR</span>
      <div className="toolbar"><span className="badge">Local · fixture mode</span>
        {unlocked && <button onClick={() => { void logout(); }}>Lock console</button>}</div>
    </header>
    {unlocked ? <Workspace /> : <main id="main" className="pairing">
      <p className="eyebrow">LOCAL OPERATIONS CONSOLE</p>
      <h1>Autonomous Incident Investigator</h1>
      <p className="muted">Reconstruct an incident from captured evidence. Review the cause, inspect citations, and assess a remediation plan.</p>
      <form className="panel" onSubmit={(event) => {
        event.preventDefault(); setBusy(true); setError("");
        const code = secret; setSecret("");
        void pair(code).catch((error: unknown) => setError(explain(error))).finally(() => setBusy(false));
      }}>
        <h2>Pair this browser</h2>
        <p className="muted">Use the one-time code printed in the app terminal. Reloading or locking the console ends this browser session.</p>
        <label htmlFor="pairing">Pairing code from the app terminal</label>
        <input id="pairing" type="password" autoComplete="off" maxLength={128} required value={secret}
          onChange={(event) => setSecret(event.target.value)} />
        <button className="primary" disabled={busy} type="submit">{busy ? "Pairing…" : "Unlock console"}</button>
        {error && <p role="alert" className="error">{error}</p>}
      </form>
      <p className="footnote">Synthetic fixtures only. No live collection, model calls, or remediation execution.</p>
    </main>}
  </>;
}
