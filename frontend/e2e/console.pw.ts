import { expect, test } from "@playwright/test";

const ASSET = "3cf79a38-7a1f-49f7-962d-b83a75de651e";
const CASE = "5cc2c064-b670-4313-8bef-e40a4f39a92d";
const OTHER_CASE = "50497499-a5a6-46de-922a-80f6791759e9";

async function configuredPage(page: import("@playwright/test").Page, status: () => number, role = "ANALYST") {
  await page.route("**/v1/health/live", (route) =>
    route.fulfill({ json: { status: "live", mode: "shadow" } }),
  );
  await page.route("**/v1/me", (route) =>
    status() === 200
      ? route.fulfill({ json: {
          identity_id: "user-1", org_id: "org-1", role, csrf_token: "test-token",
        } })
      : route.fulfill({ status: 401, json: { detail: "unauthorized" } }),
  );
  await page.route("**/v1/assets", (route) =>
    route.fulfill({ json: {
      items: [{ id: ASSET, slug: "private-asset", criticality: "HIGH" }],
      truncated: false,
    } }),
  );
  await page.route("**/v1/operations/scans", (route) =>
    route.fulfill({ json: { items: [], truncated: false } }),
  );
}

test("external session revocation clears old asset data on focus", async ({ page }) => {
  let sessionStatus = 200;
  await configuredPage(page, () => sessionStatus);
  await page.route("**/v1/cases", (route) =>
    route.fulfill({ json: { items: [], truncated: false } }),
  );
  await page.goto("/");
  await expect(page.locator("ul.asset-list > li > span").filter({ hasText: "private-asset" })).toBeVisible();

  sessionStatus = 401;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByText(/Sign in with an enrolled identity provider/)).toBeVisible();
  await expect(page.locator("ul.asset-list > li > span").filter({ hasText: "private-asset" })).toHaveCount(0);
});

test("browser Back revalidates session instead of restoring scoped evidence", async ({ page }) => {
  let sessionStatus = 200;
  await configuredPage(page, () => sessionStatus);
  await page.route("**/v1/cases", (route) =>
    route.fulfill({ json: { items: [], truncated: false } }),
  );
  await page.goto("/");
  await expect(page.locator("ul.asset-list > li > span").filter({ hasText: "private-asset" })).toBeVisible();
  await page.goto("about:blank");
  sessionStatus = 401;
  await page.goBack();
  await expect(page.getByText(/Sign in with an enrolled identity provider/)).toBeVisible();
  await expect(page.locator("ul.asset-list > li > span").filter({ hasText: "private-asset" })).toHaveCount(0);
});

test("stale incident actions reload current grants without replay", async ({ page }) => {
  await configuredPage(page, () => 200);
  let changed = false;
  let transitions = 0;
  await page.route("**/v1/cases", (route) => route.fulfill({ json: { items: [{
    id: CASE, asset_id: ASSET, title: "Synthetic investigation",
    status: changed ? "TRIAGED" : "OPEN", revision: changed ? 2 : 1,
  }] } }));
  await page.route(`**/v1/cases/${CASE}/transition`, (route) => {
    expect(route.request().headers()["if-match"]).toBe(`"${CASE}:1"`);
    expect(route.request().postDataJSON()).toEqual({ status: "TRIAGED" });
    transitions += 1;
    changed = true;
    return route.fulfill({ status: 412, json: { detail: "stale incident revision" } });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Mark triaged" }).press("Enter");
  await expect(page.getByText("TRIAGED · revision 2")).toBeVisible();
  await expect(page.getByRole("alert").getByText(/The incident changed/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Mark triaged" })).toHaveCount(0);
  expect(transitions).toBe(1);
});

test("injected-looking case titles and evidence remain plain text", async ({ page }) => {
  await configuredPage(page, () => 200);
  const hostileTitle = '<img src=x onerror="window.pwned=1">';
  const hostileKind = '<svg onload="window.pwned=1">';
  await page.route("**/v1/cases", (route) =>
    route.fulfill({ json: { items: [{
      id: CASE, asset_id: ASSET, title: hostileTitle, status: "OPEN", revision: 1,
    }], truncated: false } }),
  );
  await page.route("**/v1/cases/*/evidence?*", (route) =>
    route.fulfill({ json: { items: [{
      id: "evidence-1", kind: hostileKind, sha256: "a".repeat(64),
      linked_at: "2026-11-21T00:00:00Z",
    }], next_cursor: null } }),
  );
  await page.goto("/");
  await expect(page.getByText(hostileTitle)).toBeVisible();
  await page.getByRole("button", { name: "View evidence" }).click();
  await expect(page.getByText(hostileKind)).toBeVisible();
  await expect(page.locator("img")).toHaveCount(0);
  await expect(page.locator("svg")).toHaveCount(0);
  expect(await page.evaluate(() => "pwned" in window)).toBe(false);
});

test("timeline scopes delayed pages, keyboard pagination, retry and empty states", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await configuredPage(page, () => 200, "VIEWER");
  await page.route("**/v1/cases", (route) => route.fulfill({ json: { items: [
    { id: CASE, asset_id: ASSET, title: "First case", status: "OPEN", revision: 1 },
    { id: OTHER_CASE, asset_id: ASSET, title: "Second case", status: "OPEN", revision: 1 },
  ], truncated: false } }));
  let completeLatePage!: () => void;
  const latePage = new Promise<void>((resolve) => { completeLatePage = resolve; });
  let releaseFirstPage!: () => void;
  const firstPage = new Promise<void>((resolve) => { releaseFirstPage = resolve; });
  let pageReads = 0;
  let secondUnavailable = true;
  const occurred_at = "2026-01-01T00:00:00Z";
  await page.route(`**/v1/cases/${CASE}/timeline?*`, async (route) => {
    const cursor = new URL(route.request().url()).searchParams.get("cursor");
    if (cursor === null) {
      await firstPage;
      await route.fulfill({ json: { items: [{ id: "a".repeat(64), occurred_at, kind: "CASE_CREATED",
        evidence_id: null, revision: null }], next_cursor: "fixture-next" } });
    } else {
      expect(cursor).toBe("fixture-next");
      if (++pageReads === 2) await latePage;
      await route.fulfill({ json: { items: [{ id: "b".repeat(64), occurred_at, kind: "INCIDENT_TRIAGED",
        evidence_id: null, revision: 2 }], next_cursor: null } });
    }
  });
  await page.route(`**/v1/cases/${OTHER_CASE}/timeline?*`, (route) => secondUnavailable
    ? route.fulfill({ status: 503, json: { detail: "fixture unavailable" } })
    : route.fulfill({ json: { items: [], next_cursor: null } }));

  await page.goto("/");
  const firstCase = page.getByRole("listitem").filter({ hasText: "First case" });
  const secondCase = page.getByRole("listitem").filter({ hasText: "Second case" });
  const region = page.getByRole("region", { name: "Case timeline" });
  await firstCase.getByRole("button", { name: "View timeline" }).press("Enter");
  await expect(region.getByRole("status")).toHaveText("Loading timeline events…");
  releaseFirstPage();
  await expect(region.getByText("Case created")).toBeVisible();
  await region.getByRole("button", { name: "Load more timeline events" }).press("Enter");
  await expect(region.getByRole("status")).toHaveText("2 timeline events loaded.");
  await expect(region.getByRole("status")).toBeFocused();

  await firstCase.getByRole("button", { name: "Hide timeline" }).click();
  await firstCase.getByRole("button", { name: "View timeline" }).click();
  await region.getByRole("button", { name: "Load more timeline events" }).click();
  await expect.poll(() => pageReads).toBe(2);
  await secondCase.getByRole("button", { name: "View timeline" }).click();
  await expect(region.getByRole("alert")).toHaveText("Some timeline records are temporarily unavailable.");
  completeLatePage();
  secondUnavailable = false;
  await region.getByRole("button", { name: "Retry timeline" }).press("Enter");
  await expect(region.getByRole("status")).toHaveText("No timeline events are available.");
  await expect(page.getByText("Incident triaged")).toHaveCount(0);
  await expect(page.getByText("Case created")).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
