export function App() {
  return (
    <main className="shell">
      <p className="eyebrow">OPERATIONS CONSOLE</p>
      <h1>Autonomous Incident Investigator</h1>
      <p className="summary">
        Evidence-first investigation for AWS workloads. The console is being assembled from a
        deterministic offline core outward.
      </p>
      <section className="status-card" aria-labelledby="build-status">
        <div className="status-dot" aria-hidden="true" />
        <div>
          <h2 id="build-status">Foundation ready</h2>
          <p>Runtime, evaluation, and recovery components will appear here as they are enabled.</p>
        </div>
      </section>
    </main>
  );
}
