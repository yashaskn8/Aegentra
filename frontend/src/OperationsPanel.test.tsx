// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import OperationsPanel from "./OperationsPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("displays database scan status without claiming verified authorization", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
    items: [{
      id: "1", asset_id: "asset-1", status: "PENDING_TRUSTED_VALIDATION",
      attempts: 1, created_at: "2026-11-21T12:00:00Z",
    }],
    truncated: false,
  }), { status: 200 })));
  render(<OperationsPanel onAccessLost={vi.fn()} />);
  expect(await screen.findByText("PENDING_TRUSTED_VALIDATION")).toBeTruthy();
  expect(screen.getByText("Untrusted result awaiting independent validation")).toBeTruthy();
  expect(screen.getByText(/No scan status grants protected serving/)).toBeTruthy();
});

it("rejects a forged CLEAN status instead of rendering a false green signal", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
    items: [{
      id: "1", asset_id: "asset-1", status: "CLEAN",
      attempts: 0, created_at: "2026-11-21T12:00:00Z",
    }],
    truncated: false,
  }), { status: 200 })));
  render(<OperationsPanel onAccessLost={vi.fn()} />);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Invalid scan status response.");
  expect(screen.queryByText("CLEAN")).toBeNull();
});

it("revoked operations access forces session revalidation", async () => {
  const lost = vi.fn();
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 403 })));
  render(<OperationsPanel onAccessLost={lost} />);
  await waitFor(() => expect(lost).toHaveBeenCalledTimes(1));
});
