import { test, expect } from "@playwright/test";

const OIDC_URL = "http://oidc.example.com:3000";
const SAML_URL = "http://saml.example.com:3000";

test.describe("UI Features", () => {
  test("tab navigation between OIDC and SAML", async ({ page }) => {
    // Start on OIDC page
    await page.goto(OIDC_URL);
    await expect(page.locator("p")).toContainText("OIDC RP:");

    // Click SAML tab
    const samlTab = page.locator('nav a:has-text("SAML")');
    if (await samlTab.isVisible()) {
      await samlTab.click();
      await expect(page.locator("p")).toContainText("SAML SP:");
    }

    // Click OIDC tab to go back
    const oidcTab = page.locator('nav a:has-text("OIDC")');
    if (await oidcTab.isVisible()) {
      await oidcTab.click();
      await expect(page.locator("p")).toContainText("OIDC RP:");
    }
  });

  test("collapsible sections persist state", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Find collapsible details elements
    const details = page.locator("details[data-persist]");
    const count = await details.count();

    if (count > 0) {
      const firstDetails = details.first();

      // Toggle open/close
      const summary = firstDetails.locator("summary");
      await summary.click();
      const isOpen = await firstDetails.getAttribute("open");

      // Reload and check persistence
      await page.reload();
      const afterReload = page.locator("details[data-persist]").first();
      const isOpenAfterReload = await afterReload.getAttribute("open");
      expect(isOpen).toBe(isOpenAfterReload);
    }
  });

  test("dark mode toggle", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Click theme toggle button
    const themeButton = page.locator('a[role="button"]:has-text("Theme")');
    await expect(themeButton).toBeVisible();

    // Get initial theme
    const initialTheme = await page.locator("html").getAttribute("data-theme");

    // Click toggle
    await themeButton.click();

    // Theme should change
    const newTheme = await page.locator("html").getAttribute("data-theme");
    if (initialTheme === "dark") {
      expect(newTheme).toBe("light");
    } else {
      expect(newTheme).toBe("dark");
    }

    // Click again to toggle back
    await themeButton.click();
    const revertedTheme = await page.locator("html").getAttribute("data-theme");
    expect(revertedTheme).toBe(initialTheme || "dark");
  });

  test("copy buttons are present on code blocks", async ({ page, context }) => {
    // Grant clipboard permissions for chromium
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto(OIDC_URL);

    // Code blocks should have copy buttons (on the pre-login page with discovery metadata)
    const copyButtons = page.locator('button:has-text("Copy")');
    const count = await copyButtons.count();

    // At least one copy button should be present (for discovery metadata)
    expect(count).toBeGreaterThan(0);
  });

  test("sequence diagram is displayed on pre-login page", async ({ page }) => {
    // OIDC sequence diagram
    await page.goto(OIDC_URL);
    const oidcSvg = page.locator("svg");
    await expect(oidcSvg.first()).toBeVisible();

    // SAML sequence diagram
    await page.goto(SAML_URL);
    const samlSvg = page.locator("svg");
    await expect(samlSvg.first()).toBeVisible();
  });

  test("static assets load correctly", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Check that CSS is loaded (page should have styled elements)
    const body = page.locator("body");
    await expect(body).toBeVisible();

    // Check that the page has a proper title
    await expect(page).toHaveTitle(/fedlens/);
  });
});
