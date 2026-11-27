// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import AuthPanel from "./AuthPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("finishes the current asset list before accepting an asset creation", async () => {
  let resolveInitial!: (response: Response) => void;
  const initial = new Promise<Response>((resolve) => { resolveInitial = resolve; });
  const create = vi.fn(() => Response.json({ id: "asset-new", slug: "synthetic-asset", criticality: "LOW" }, { status: 201 }));
  vi.stubGlobal("fetch", vi.fn(async (path: string, options?: RequestInit) => {
    if (path === "/v1/me") {
      return Response.json({ identity_id: "fixture", org_id: "example", role: "EDITOR", csrf_token: "synthetic" });
    }
    if (path === "/v1/cases") return Response.json({ items: [] });
    if (path === "/v1/assets") return options?.method === "POST" ? create() : initial;
    throw new Error(`Unexpected request to ${path}`);
  }));

  render(<AuthPanel />);
  fireEvent.change(await screen.findByLabelText("Asset name"), { target: { value: "synthetic-asset" } });
  const submit = screen.getByRole("button", { name: "Add asset" });
  fireEvent.click(submit);
  expect(create).not.toHaveBeenCalled();
  expect(screen.getByText("Loading registered assets…")).toBeTruthy();
  expect(screen.queryByText("No assets are currently displayed.")).toBeNull();

  await act(async () => resolveInitial(Response.json({ items: [], truncated: false })));
  fireEvent.click(submit);
  expect(await screen.findByText("synthetic-asset")).toBeTruthy();
  expect(create).toHaveBeenCalledTimes(1);
});
