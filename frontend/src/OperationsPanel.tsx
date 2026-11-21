import { useEffect, useRef, useState } from "react";

type Scan = {
  id: string;
  asset_id: string;
  status: "QUEUED" | "LEASED" | "PENDING_TRUSTED_VALIDATION" | "UNKNOWN";
  attempts: number;
  created_at: string;
};

type ScanPage = { items: Scan[]; truncated: boolean };

const interpretation: Record<Scan["status"], string> = {
  QUEUED: "Waiting for a worker",
  LEASED: "Attempt claimed; external isolation not verified here",
  PENDING_TRUSTED_VALIDATION: "Untrusted result awaiting independent validation",
  UNKNOWN: "Attempt outcome unknown; investigation required",
};

function validPage(data: unknown): data is ScanPage {
  if (!data || typeof data !== "object" || !("items" in data) ||
      !("truncated" in data) || typeof data.truncated !== "boolean" ||
      !Array.isArray(data.items)) return false;
  return data.items.length <= 100 && data.items.every((item: unknown) =>
    typeof item === "object" && item !== null &&
    "id" in item && typeof item.id === "string" &&
    "asset_id" in item && typeof item.asset_id === "string" &&
    "status" in item && typeof item.status === "string" &&
    Object.hasOwn(interpretation, item.status) &&
    "attempts" in item && typeof item.attempts === "number" &&
    Number.isInteger(item.attempts) && item.attempts >= 0 && item.attempts <= 3 &&
    "created_at" in item && typeof item.created_at === "string"
  );
}

export default function OperationsPanel({ onAccessLost }: { onAccessLost: () => void }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);

  async function refresh() {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setLoading(true);
    setError("");
    setScans([]);
    setTruncated(false);
    try {
      const response = await fetch("/v1/operations/scans", {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      if (response.status === 401 || response.status === 403) {
        onAccessLost();
        return;
      }
      if (!response.ok) throw new Error("Scan job status unavailable.");
      const payload: unknown = await response.json();
      if (!validPage(payload)) throw new Error("Invalid scan status response.");
      if (!controller.signal.aborted) {
        setScans(payload.items);
        setTruncated(payload.truncated);
      }
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(reason instanceof Error ? reason.message : "Scan status unavailable.");
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    return () => request.current?.abort();
  }, []);

  return (
    <section className="operations-panel" aria-label="Scan operations">
      <div className="section-heading">
        <h3>Scan job operations</h3>
        <p>Read-only database projection · not live AWS or release authority status</p>
      </div>
      <button type="button" onClick={() => void refresh()} disabled={loading}>
        {loading ? "Loading…" : "Refresh statuses"}
      </button>
      {loading && <p className="workspace-note" aria-live="polite">Checking queued scans…</p>}
      {!loading && !error && scans.length === 0 &&
        <p className="workspace-note">No scan jobs are recorded for this organization.</p>}
      <ul className="operations-list">
        {scans.map((scan) => (
          <li key={scan.id}>
            <strong>{scan.status}</strong>
            <span>{interpretation[scan.status]}</span>
            <small>Asset: {scan.asset_id} · Attempts: {scan.attempts} · Job: {scan.id}</small>
          </li>
        ))}
      </ul>
      {truncated && <p className="workspace-note">Only the 100 latest scan jobs are displayed.</p>}
      <p className="workspace-note">No scan status grants protected serving or confirms a qualified worker.</p>
      {error && <p className="workspace-error" role="alert">{error}</p>}
    </section>
  );
}
