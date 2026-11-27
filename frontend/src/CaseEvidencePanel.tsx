import { useEffect, useRef, useState } from "react";

type Evidence = {
  id: string;
  kind: string;
  sha256: string;
  linked_at: string;
};

type Page = { items: Evidence[]; next_cursor: string | null };

export default function CaseEvidencePanel({
  caseId, onAccessLost,
}: {
  caseId: string;
  onAccessLost: () => void;
}) {
  const [items, setItems] = useState<Evidence[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const request = useRef<AbortController | null>(null);

  async function load(cursor: string | null) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setError("");
    setLoading(true);
    const params = new URLSearchParams({ page_size: "25" });
    if (cursor) params.set("cursor", cursor);
    try {
      const response = await fetch(
        `/v1/cases/${encodeURIComponent(caseId)}/evidence?${params}`,
        { credentials: "same-origin", cache: "no-store", signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      if (response.status === 401 || response.status === 403) {
        onAccessLost();
        return;
      }
      if (response.status === 404) {
        setItems([]);
        setNextCursor(null);
        setError("This case is no longer assigned to your identity.");
        return;
      }
      if (!response.ok) throw new Error("Evidence metadata could not be loaded.");
      const data: Page = await response.json();
      if (!Array.isArray(data.items) ||
          !(data.next_cursor === null || typeof data.next_cursor === "string") ||
          !data.items.every((item) =>
            typeof item.id === "string" &&
            typeof item.kind === "string" &&
            typeof item.sha256 === "string" &&
            /^[0-9a-f]{64}$/.test(item.sha256) &&
            typeof item.linked_at === "string"
          )) {
        throw new Error("Invalid scoped evidence response.");
      }
      if (controller.signal.aborted) return;
      setItems((current) => cursor === null ? data.items : [...current, ...data.items]);
      setNextCursor(data.next_cursor);
    } catch (reason) {
      if (!controller.signal.aborted) {
        setError(reason instanceof Error ? reason.message : "Evidence metadata unavailable.");
      }
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }

  useEffect(() => {
    void load(null);
    return () => { request.current?.abort(); };
  }, [caseId]);

  return (
    <section aria-label="Scoped case evidence">
      <h4>Linked evidence metadata</h4>
      <p className="workspace-note">Digests are evidence identifiers, not safety or publication approval.</p>
      <p className="workspace-note" role="status">
        {loading ? "Loading linked evidence…" : items.length > 0 ? (
          <>{items.length} linked evidence {items.length === 1 ? "record" : "records"} loaded.
            {nextCursor && " More records are available."}</>
        ) : !error && "No evidence linked to this case."}
      </p>
      <ul className="case-evidence-list">
        {items.map((evidence) => (
          <li key={evidence.id}>
            <div><strong>{evidence.kind}</strong> · <time dateTime={evidence.linked_at}>
              {new Date(evidence.linked_at).toLocaleString()}
            </time></div>
            <div className="evidence-digest">SHA-256: <code>{evidence.sha256}</code></div>
            <small>Evidence ID: {evidence.id}</small>
          </li>
        ))}
      </ul>
      {nextCursor && (
        <button type="button" disabled={loading} onClick={() => { void load(nextCursor); }}>
          {loading ? "Loading…" : "Load more evidence"}
        </button>
      )}
      {error && <p className="workspace-error" role="alert">{error}</p>}
    </section>
  );
}
