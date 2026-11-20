import { useEffect, useState } from "react";
import AuthPanel from "./AuthPanel";

type ApiState = "checking" | "live" | "unavailable";

function useApiLiveness(): ApiState {
  const [state, setState] = useState<ApiState>("checking");

  useEffect(() => {
    const controller = new AbortController();

    async function check() {
      try {
        const response = await fetch("/v1/health/live", {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("unavailable");
        const body: unknown = await response.json();
        if (
          typeof body !== "object" ||
          body === null ||
          !("status" in body) ||
          body.status !== "live" ||
          !("mode" in body) ||
          body.mode !== "shadow"
        ) {
          throw new Error("unexpected response");
        }
        setState("live");
      } catch {
        if (!controller.signal.aborted) setState("unavailable");
      }
    }

    void check();
    return () => controller.abort();
  }, []);

  return state;
}

const planned = [
  { stage: "S1", name: "Secure foundation", detail: "Manifest constraints, explicit coverage, schema and tests", status: "In progress" },
  { stage: "S2", name: "Static evidence", detail: "Offline parser, independent verifier, immutable evidence", status: "Not started" },
  { stage: "S3", name: "Protected release", detail: "Endorsement, witness, publish and serving boundaries", status: "Not started" },
  { stage: "S4", name: "Qualification", detail: "Isolation, recovery, threat tests, independent review", status: "Not started" },
];

export default function App() {
  const api = useApiLiveness();
  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand"><span className="brand-mark" aria-hidden="true">◆</span> Aegentra</div>
        <span className="phase">S1 · Shadow foundation</span>
      </header>

      <main>
        <section className="hero">
          <p className="eyebrow">Evidence-first security engineering</p>
          <h1>Trust is a claim.<br /><span>Evidence is the requirement.</span></h1>
          <p className="hero-copy">
            Aegentra is being built to investigate software changes and eventually
            verify release integrity. Security enforcement is not available in this preview.
          </p>
        </section>

        <section className="status-section" aria-label="Development status">
          <div className="status-card">
            <div className="label">Backend connectivity</div>
            <div className="value" aria-live="polite">{api === "checking" ? "Checking…" : api === "live" ? "Connected" : "Unavailable"}</div>
            <p>Minimal liveness only. This does not indicate readiness or security coverage.</p>
          </div>
          <div className="status-card">
            <div className="label">Release authority</div>
            <div className="value muted">Not enabled</div>
            <p>No deployment approval, signing, or protected serving exists yet.</p>
          </div>
          <div className="status-card">
            <div className="label">Analysis coverage</div>
            <div className="value muted">Not measured</div>
            <p>No scans have been executed or qualified in this application.</p>
          </div>
        </section>

        <AuthPanel />

        <section className="roadmap">
          <div className="section-heading">
            <h2>Engineering milestones</h2>
            <p>Implementation status, not a simulated threat feed.</p>
          </div>
          <ol>
            {planned.map((item) => (
              <li key={item.stage}>
                <span className="stage">{item.stage}</span>
                <div><h3>{item.name}</h3><p>{item.detail}</p></div>
                <span className="milestone-state">{item.status}</span>
              </li>
            ))}
          </ol>
        </section>
      </main>
      <footer>Built for verifiable security decisions · No live customer protection</footer>
    </div>
  );
}
