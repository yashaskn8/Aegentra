import { useEffect, useRef, useState } from "react";

const labels = {
  CASE_CREATED: "Case created",
  CASE_EVIDENCE_LINKED: "Evidence linked",
  INCIDENT_TRIAGED: "Incident triaged",
  INCIDENT_CONTAINMENT_REQUESTED: "Containment requested",
  INCIDENT_CONTAINMENT_VERIFIED: "Verified containment recorded",
};

type TimelineEvent = {
  id: string;
  occurred_at: string;
  kind: keyof typeof labels;
  evidence_id: string | null;
  revision: number | null;
};

type TimelinePage = { items: TimelineEvent[]; next_cursor: string | null };

function isTimelineEvent(value: unknown): value is TimelineEvent {
  if (typeof value !== "object" || value === null ||
      !("id" in value) || typeof value.id !== "string" || !/^[0-9a-f]{64}$/.test(value.id) ||
      !("occurred_at" in value) || typeof value.occurred_at !== "string" ||
      !Number.isFinite(Date.parse(value.occurred_at)) ||
      !("kind" in value) || typeof value.kind !== "string" || !Object.hasOwn(labels, value.kind) ||
      !("evidence_id" in value) || !("revision" in value)) return false;

  if (value.kind === "CASE_EVIDENCE_LINKED") {
    return typeof value.evidence_id === "string" &&
      /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value.evidence_id) && value.revision === null;
  }
  if (value.evidence_id !== null) return false;
  return value.kind === "CASE_CREATED" ? value.revision === null :
    typeof value.revision === "number" && Number.isInteger(value.revision) && value.revision > 0;
}

function isTimelinePage(value: unknown): value is TimelinePage {
  return typeof value === "object" && value !== null &&
    "items" in value && Array.isArray(value.items) && value.items.length <= 25 && value.items.every(isTimelineEvent) &&
    "next_cursor" in value && (value.next_cursor === null ||
      (typeof value.next_cursor === "string" && /^[A-Za-z0-9_-]{1,300}$/.test(value.next_cursor)));
}

export default function CaseTimelinePanel({
  caseId, onAccessLost, onCaseUnavailable,
}: {
  caseId: string;
  onAccessLost: () => void;
  onCaseUnavailable: () => void;
}) {
  const [items, setItems] = useState<TimelineEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const activeRequest = useRef<AbortController | null>(null);
  const status = useRef<HTMLParagraphElement>(null);
  const pageButton = useRef<HTMLButtonElement>(null);

  async function load(after: string | null) {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setLoading(true);
    const params = new URLSearchParams({ page_size: "25" });
    if (after) params.set("cursor", after);
    try {
      const response = await fetch(`/v1/cases/${encodeURIComponent(caseId)}/timeline?${params}`, {
        credentials: "same-origin", cache: "no-store", signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      if (response.status === 401 || response.status === 403) {
        onAccessLost();
        return;
      }
      if (response.status === 404) {
        onCaseUnavailable();
        return;
      }
      if (response.status === 503) throw new Error("Some timeline records are temporarily unavailable.");
      if (!response.ok) throw new Error("The case timeline could not be loaded.");
      const data: unknown = await response.json();
      if (controller.signal.aborted) return;
      if (!isTimelinePage(data) || (after !== null && data.next_cursor === after)) {
        throw new Error("The timeline response was invalid.");
      }
      setItems((current) => after === null ? data.items : [...current, ...data.items]);
      setCursor(data.next_cursor);
      setError("");
      if (data.next_cursor === null && pageButton.current === document.activeElement) status.current?.focus();
    } catch (reason) {
      if (!controller.signal.aborted) {
        setError(reason instanceof Error ? reason.message : "The case timeline could not be loaded.");
      }
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }

  useEffect(() => {
    void load(null);
    return () => activeRequest.current?.abort();
  }, [caseId]);

  return (
    <section aria-label="Case timeline">
      <h4>Investigation timeline</h4>
      <p className="workspace-note">Shows available case records. Older records may be missing.</p>
      <p className="workspace-note" role="status" tabIndex={-1} ref={status}>
        {loading ? "Loading timeline events…" : error ? null : items.length === 0 ? "No timeline events are available." :
          `${items.length} timeline ${items.length === 1 ? "event" : "events"} loaded.${cursor ? " More events are available." : ""}`}
      </p>
      <ol className="case-evidence-list">
        {items.map((event) => (
          <li key={event.id}>
            <div><strong>{labels[event.kind]}</strong> · <time dateTime={event.occurred_at}>
              {new Date(event.occurred_at).toLocaleString()}
            </time></div>
            {event.evidence_id && <div className="evidence-digest">Evidence ID <code>{event.evidence_id}</code></div>}
            {event.revision !== null && <small>Case revision {event.revision}</small>}
          </li>
        ))}
      </ol>
      {error && !loading && <p className="workspace-error" role="alert">{error}</p>}
      {(cursor || error) && (
        <button type="button" ref={pageButton} aria-disabled={loading} onClick={() => { if (!loading) void load(cursor); }}>
          {error ? "Retry timeline" : "Load more timeline events"}
        </button>
      )}
    </section>
  );
}
