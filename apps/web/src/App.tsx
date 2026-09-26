import { useState } from "react";
import { logout, pair } from "./session";

export function App() {
  const [secret, setSecret] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <main className="shell">
      <p className="eyebrow">OPERATIONS CONSOLE</p>
      <h1>Autonomous Incident Investigator</h1>
      <p className="summary">
        Evidence-first investigation for AWS workloads. The console is being assembled from a
        deterministic offline core outward.
      </p>
      {!unlocked ? <form onSubmit={(event) => {
        event.preventDefault();
        setBusy(true); setError("");
        void pair(secret).then(() => setUnlocked(true))
          .catch(() => setError("Pairing failed. Request a new code in the app terminal."))
          .finally(() => { setSecret(""); setBusy(false); });
      }}>
        <label htmlFor="pairing">Pairing code from the app terminal</label>
        <input id="pairing" type="password" autoComplete="off" maxLength={128} required
          value={secret} onChange={(event) => setSecret(event.target.value)} />
        <button disabled={busy} type="submit">Unlock console</button>
        {error && <p role="alert">{error}</p>}
      </form> : <>
      <section className="status-card" aria-labelledby="build-status">
        <div className="status-dot" aria-hidden="true" />
        <div>
          <h2 id="build-status">Foundation ready</h2>
          <p>Runtime, evaluation, and recovery components will appear here as they are enabled.</p>
        </div>
      </section>
      <button type="button" onClick={() => {
        void logout().catch(() => undefined).finally(() => setUnlocked(false));
      }}>Lock console</button>
      </>}
    </main>
  );
}
