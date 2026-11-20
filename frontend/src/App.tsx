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
  { stage: "S1", name: "Secure foundation", detail: "Authenticated cases, tenant isolation, intake and audit/outbox", status: "Native CI tested" },
  { stage: "S2", name: "Static evidence", detail: "Offline guest protocol and independent verification contracts", status: "AWS qualification pending" },
  { stage: "S3", name: "Protected release", detail: "Review, witness, publication and fail-closed gateway prototypes", status: "Not deployed" },
  { stage: "S4", name: "Qualification", detail: "Incident containment, recovery and negative-test evidence", status: "Independent sign-off pending" },
];

export default function App() {
  const api = useApiLiveness();
  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand"><span className="brand-mark" aria-hidden="true">◆</span> Aegentra</div>
        <span className="phase">Shadow · No protected serving</span>
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
            <p>No customer-enrolled release authority or protected serving is deployed.</p>
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
