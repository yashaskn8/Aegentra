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
