import { expect, test } from "@playwright/test";

const ASSET = "3cf79a38-7a1f-49f7-962d-b83a75de651e";
const CASE = "5cc2c064-b670-4313-8bef-e40a4f39a92d";

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
