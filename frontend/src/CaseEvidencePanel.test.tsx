// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import CaseEvidencePanel from "./CaseEvidencePanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const CASE_ID = "1a3a287f-f571-4f62-beda-c1cdbe4b8811";
const first = {
  id: "130a7c24-ebf5-40b8-8b13-bf5eb3044b10",
  kind: "<img src=x onerror=alert(1)>",
  sha256: "a".repeat(64),
  linked_at: "2026-11-20T14:00:00+00:00",
};
const second = {
  id: "75bbecfc-9085-4ee0-b176-a36a16c133ff",
  kind: "source-review",
  sha256: "b".repeat(64),
  linked_at: "2026-11-20T14:00:01+00:00",
};

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

it("renders malicious-looking evidence as inert text without fetching source", async () => {
  const fetchMock = vi.fn().mockResolvedValue(json({ items: [first], next_cursor: null }));
  vi.stubGlobal("fetch", fetchMock);
  const onAccessLost = vi.fn();
  const { container } = render(
    <CaseEvidencePanel caseId={CASE_ID} onAccessLost={onAccessLost} />,
  );

  expect(await screen.findByText(first.kind)).toBeTruthy();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.getByText(first.sha256)).toBeTruthy();
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(String(fetchMock.mock.calls[0][0])).toContain(`/v1/cases/${CASE_ID}/evidence?`);
  expect(fetchMock.mock.calls[0][1]).toMatchObject({ cache: "no-store", credentials: "same-origin" });
  expect(onAccessLost).not.toHaveBeenCalled();
});

it("fetches a second metadata page without duplicating the first", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(json({ items: [first], next_cursor: "opaque-cursor" }))
    .mockResolvedValueOnce(json({ items: [second], next_cursor: null }));
  vi.stubGlobal("fetch", fetchMock);
  render(<CaseEvidencePanel caseId={CASE_ID} onAccessLost={vi.fn()} />);
  await screen.findByText(first.kind);
  fireEvent.click(screen.getByRole("button", { name: "Load more evidence" }));
  await screen.findByText("source-review");
  expect(screen.getAllByText(first.sha256)).toHaveLength(1);
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(String(fetchMock.mock.calls[1][0])).toContain("cursor=opaque-cursor");
});

it("fails closed on revoked access instead of displaying protected evidence", async () => {
  const onAccessLost = vi.fn();
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json({ detail: "forbidden" }, 403)));
  render(<CaseEvidencePanel caseId={CASE_ID} onAccessLost={onAccessLost} />);
  await waitFor(() => expect(onAccessLost).toHaveBeenCalledTimes(1));
  expect(screen.queryByText(first.kind)).toBeNull();
});

it("clears an existing page when case membership disappears", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(json({ items: [first], next_cursor: "next" }))
    .mockResolvedValueOnce(json({ detail: "not found" }, 404));
  vi.stubGlobal("fetch", fetchMock);
  render(<CaseEvidencePanel caseId={CASE_ID} onAccessLost={vi.fn()} />);
  await screen.findByText(first.kind);
  fireEvent.click(screen.getByRole("button", { name: "Load more evidence" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent",
    "This case is no longer assigned to your identity.");
  expect(screen.queryByText(first.kind)).toBeNull();
});
