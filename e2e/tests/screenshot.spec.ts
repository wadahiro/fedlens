import { test, expect, Page } from "@playwright/test";

const OIDC_URL = "http://oidc.example.com:3000";
const KC_USERNAME = "testuser";
const KC_PASSWORD = "password";

async function keycloakLogin(page: Page) {
  await page.fill("#username", KC_USERNAME);
  await page.fill("#password", KC_PASSWORD);
  await page.click("#kc-login");
}

test.describe("Screenshot capture", () => {
  test("OIDC post-login full page", async ({ page }) => {
    await page.goto(OIDC_URL);
    await page.click('a[role="button"]:has-text("Login")');
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    // Wait for content to fully render
    await expect(page.locator("text=ID Token Claims")).toBeVisible();

    // Full page screenshot
    await page.screenshot({
      path: "screenshots/oidc-post-login-full.png",
      fullPage: true,
    });

    // Sidebar only
    await page.locator(".sidebar").screenshot({
      path: "screenshots/oidc-sidebar.png",
    });

    // Timeline area only
    await page.locator(".results-timeline").screenshot({
      path: "screenshots/oidc-timeline.png",
    });

    // Expand all subsections and screenshot
    const subsections = page.locator("details.result-subsection");
    const count = await subsections.count();
    for (let i = 0; i < count; i++) {
      const el = subsections.nth(i);
      const isOpen = await el.getAttribute("open");
      if (isOpen === null) {
        await el.locator("> summary").click();
      }
    }
    await page.screenshot({
      path: "screenshots/oidc-all-expanded.png",
      fullPage: true,
    });
  });
});
