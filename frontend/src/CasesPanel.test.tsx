// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import CasesPanel from "./CasesPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("finishes loading assigned cases before allowing a case creation", async () => {
  let resolveInitial!: (response: Response) => void;
  const initial = new Promise<Response>((resolve) => { resolveInitial = resolve; });
  const created = { id: "case-new", asset_id: "asset-1", title: "Review source", status: "OPEN", revision: 1 };
  const fetchMock = vi.fn().mockReturnValueOnce(initial)
    .mockResolvedValueOnce(Response.json(created, { status: 201 }));
  vi.stubGlobal("fetch", fetchMock);
  render(<CasesPanel user={{ role: "ANALYST", csrf_token: "synthetic" }}
    assets={[{ id: "asset-1", slug: "fixture" }]} onAccessLost={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("Asset"), { target: { value: "asset-1" } });
  fireEvent.change(screen.getByLabelText("Case title"), { target: { value: created.title } });
  const submit = screen.getByRole("button", { name: "Create case" });
  fireEvent.click(submit);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("status").textContent).toBe("Loading assigned cases…");
  expect(screen.queryByText("No assigned cases.")).toBeNull();

  await act(async () => resolveInitial(Response.json({ items: [] })));
  expect(screen.getByText("No assigned cases.")).toBeTruthy();
  fireEvent.click(submit);
  expect(await screen.findByText(created.title)).toBeTruthy();
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it("keeps the case list error visible when a new case can still be created", async () => {
  const created = { id: "case-new", asset_id: "asset-1", title: "Review source", status: "OPEN", revision: 1 };
  const fetchMock = vi.fn().mockResolvedValueOnce(Response.json({}, { status: 503 }))
    .mockResolvedValueOnce(Response.json(created, { status: 201 }));
  vi.stubGlobal("fetch", fetchMock);
  render(<CasesPanel user={{ role: "ANALYST", csrf_token: "synthetic" }}
    assets={[{ id: "asset-1", slug: "fixture" }]} onAccessLost={vi.fn()} />);

  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Assigned cases are unavailable.");
  fireEvent.change(screen.getByLabelText("Asset"), { target: { value: "asset-1" } });
  fireEvent.change(screen.getByLabelText("Case title"), { target: { value: created.title } });
  fireEvent.click(screen.getByRole("button", { name: "Create case" }));
  expect(await screen.findByText(created.title)).toBeTruthy();
  expect(screen.getByRole("alert")).toHaveProperty("textContent", "Assigned cases are unavailable.");
});

it("clears the case workspace when a timeline page loses its membership", async () => {
  const item = { id: "case-a", asset_id: "asset-1", title: "First investigation", status: "OPEN", revision: 1 };
  const next = "synthetic-next";
  const fetchMock = vi.fn().mockResolvedValueOnce(Response.json({ items: [item] }))
    .mockResolvedValueOnce(Response.json({ items: [{
      id: "a".repeat(64), occurred_at: "2026-01-01T00:00:00Z", kind: "CASE_CREATED",
      evidence_id: null, revision: null,
    }], next_cursor: next }))
    .mockResolvedValueOnce(Response.json({}, { status: 404 }));
  vi.stubGlobal("fetch", fetchMock);
  const onAccessLost = vi.fn();
  render(<CasesPanel user={{ role: "ANALYST", csrf_token: "synthetic" }} assets={[]} onAccessLost={onAccessLost} />);

  fireEvent.click(await screen.findByRole("button", { name: "View timeline" }));
  expect(await screen.findByText("Case created")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Load more timeline events" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "This case is no longer assigned to your identity.");
  expect(screen.queryByText("First investigation")).toBeNull();
  expect(screen.queryByRole("region", { name: "Case timeline" })).toBeNull();
  expect(onAccessLost).not.toHaveBeenCalled();
  expect(fetchMock.mock.calls[2][0]).toContain(`cursor=${next}`);
});

it("reloads authorized case state after a stale transition without retrying it", async () => {
  const item = { id: "case-a", asset_id: "asset-1", title: "First investigation", status: "OPEN", revision: 1 };
  const fetchMock = vi.fn().mockResolvedValueOnce(Response.json({ items: [item] }))
    .mockResolvedValueOnce(Response.json({}, { status: 412 }))
    .mockResolvedValueOnce(Response.json({ items: [{ ...item, status: "TRIAGED", revision: 2 }] }));
  vi.stubGlobal("fetch", fetchMock);
  render(<CasesPanel user={{ role: "ANALYST", csrf_token: "synthetic" }} assets={[]} onAccessLost={vi.fn()} />);

  fireEvent.click(await screen.findByRole("button", { name: "Mark triaged" }));
  expect(await screen.findByText("TRIAGED · revision 2")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Mark triaged" })).toBeNull();
  expect(fetchMock.mock.calls[1][1]).toMatchObject({
    method: "POST", headers: { "If-Match": '"case-a:1"' },
  });
  expect(fetchMock.mock.calls[2][0]).toBe("/v1/cases");
  expect(fetchMock).toHaveBeenCalledTimes(3);
});
