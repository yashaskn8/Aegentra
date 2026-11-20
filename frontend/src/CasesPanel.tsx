import { useEffect, useState } from "react";
import type { FormEvent } from "react";

type Asset = { id: string; slug: string };
type User = { role: string; csrf_token: string };
type CaseSummary = {
  id: string;
  asset_id: string;
  title: string;
  status: string;
  revision: number;
};

export default function CasesPanel({ user, assets }: { user: User; assets: Asset[] }) {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [assetId, setAssetId] = useState("");
  const [title, setTitle] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [transitioning, setTransitioning] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/v1/cases", {
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    }).then(async (response) => {
      if (!response.ok) throw new Error("Could not load assigned cases");
      const value: { items: CaseSummary[]; truncated?: boolean } = await response.json();
      if (!Array.isArray(value.items)) throw new Error("Invalid case response");
      setCases(value.items);
      setTruncated(Boolean(value.truncated));
    }).catch(() => {
      if (!controller.signal.aborted) setError("Assigned cases are unavailable.");
    });
    return () => controller.abort();
  }, []);

  async function createCase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !assetId || title.trim().length < 3) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/v1/cases", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": user.csrf_token,
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({ asset_id: assetId, title: title.trim() }),
      });
      if (!response.ok) throw new Error(
        response.status === 403 ? "Your role cannot create cases." :
        response.status === 404 ? "Selected asset is unavailable." : "Could not create case."
      );
      const created: CaseSummary = await response.json();
      setCases((current) => [...current, created]);
      setTitle("");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Could not create case.");
    } finally {
      setBusy(false);
    }
  }

  async function moveCase(
    item: CaseSummary,
    nextStatus: "TRIAGED" | "CONTAINMENT_REQUESTED",
  ) {
    if (transitioning !== null || busy) return;
    setTransitioning(item.id);
    setError("");
    try {
      const response = await fetch(`/v1/cases/${item.id}/transition`, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": user.csrf_token,
        },
        body: JSON.stringify({
          status: nextStatus,
          expected_revision: item.revision,
        }),
      });
      if (!response.ok) {
        throw new Error(
          response.status === 409
            ? "The incident changed. Refresh this page before trying again."
            : response.status === 403
              ? "Incident transition is not permitted for your identity."
              : response.status === 404
                ? "This incident is no longer assigned to you."
                : "Incident transition could not be recorded.",
        );
      }
      const changed: unknown = await response.json();
      if (
        typeof changed !== "object" || changed === null
        || !("id" in changed) || changed.id !== item.id
        || !("status" in changed) || changed.status !== nextStatus
        || !("revision" in changed) || changed.revision !== item.revision + 1
        || !("enforcement_effect" in changed)
        || changed.enforcement_effect !== "NONE"
      ) {
        throw new Error("Unexpected incident result; refresh before continuing.");
      }
      setCases((existing) => existing.map((record) =>
        record.id === item.id
          ? { ...record, status: nextStatus, revision: item.revision + 1 }
          : record
      ));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Incident transition failed.");
    } finally {
      setTransitioning(null);
    }
  }

  return (
    <section className="cases-panel" aria-label="Investigation cases">
      <h3>Assigned investigation cases</h3>
      <p className="workspace-note">Access requires an explicit case membership. Triage and containment requests only record incident workflow intent; they do not stop protected traffic or confirm containment.</p>
      {cases.length === 0 && <p className="workspace-note">No assigned cases.</p>}
      <ul className="asset-list">
        {cases.map((item) => (
          <li key={item.id}>
            <div className="case-information">
              <span>{item.title}</span>
              <small>{item.status} · revision {item.revision}</small>
            </div>
            {(user.role === "ANALYST" || user.role === "ADMIN") && (
              <div className="case-actions">
                {item.status === "OPEN" && (
                  <button type="button" disabled={transitioning !== null || busy}
                    onClick={() => { void moveCase(item, "TRIAGED"); }}>
                    {transitioning === item.id ? "Recording…" : "Mark triaged"}
                  </button>
                )}
                {item.status === "TRIAGED" && (
                  <button type="button" disabled={transitioning !== null || busy}
                    onClick={() => { void moveCase(item, "CONTAINMENT_REQUESTED"); }}>
                    {transitioning === item.id ? "Recording…" : "Request containment"}
                  </button>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
      {truncated && <p className="workspace-note">Showing the first 100 assigned cases.</p>}
      {(user.role === "ANALYST" || user.role === "ADMIN") && (
        <form onSubmit={(event) => { void createCase(event); }} className="asset-form">
          <label htmlFor="case-asset">Asset</label>
          <select
            id="case-asset" value={assetId} required
            onChange={(event) => setAssetId(event.target.value)}
          >
            <option value="">Select asset</option>
            {assets.map((asset) => (
              <option value={asset.id} key={asset.id}>{asset.slug}</option>
            ))}
          </select>
          <label htmlFor="case-title">Case title</label>
          <input
            id="case-title" value={title}
            onChange={(event) => setTitle(event.target.value)}
            minLength={3} maxLength={140}
            required placeholder="Review a suspicious change"
            autoComplete="off"
          />
          <button type="submit" disabled={busy || assets.length === 0}>
            {busy ? "Creating…" : "Create case"}
          </button>
        </form>
      )}
      {error && <p className="workspace-error" role="alert">{error}</p>}
    </section>
  );
}
