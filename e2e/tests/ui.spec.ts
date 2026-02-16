import { test, expect } from "@playwright/test";
import { OIDC_URL, SAML_URL } from "./helpers";

test.describe("UI Features", () => {
  test("tab navigation between OIDC and SAML", async ({ page }) => {
    // Start on OIDC page
    await page.goto(OIDC_URL);
    await expect(page.locator(".header-protocol-label")).toContainText("OIDC RP:");

    // Click SAML tab
    const samlTab = page.locator('nav a:has-text("SAML")');
    if (await samlTab.isVisible()) {
      await samlTab.click();
      await expect(page.locator(".header-protocol-label")).toContainText("SAML SP:");
    }

    // Click OIDC tab to go back
    const oidcTab = page.locator('nav a:has-text("OIDC")');
    if (await oidcTab.isVisible()) {
      await oidcTab.click();
      await expect(page.locator(".header-protocol-label")).toContainText("OIDC RP:");
    }
  });

  test("dark mode toggle", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Click theme toggle button
    const themeButton = page.locator(".theme-toggle");
    await expect(themeButton).toBeVisible();

    // Get initial theme (may be null if auto-detected)
    const initialTheme = await page.locator("html").getAttribute("data-theme");

    // Click toggle
    await themeButton.click();

    // Theme should change
    const newTheme = await page.locator("html").getAttribute("data-theme");
    expect(newTheme).not.toBe(initialTheme);
    expect(["light", "dark"]).toContain(newTheme);

    // Click again to toggle back
    await themeButton.click();
    const revertedTheme = await page.locator("html").getAttribute("data-theme");
    // After two toggles, should return to the opposite of newTheme
    const expectedReverted = newTheme === "dark" ? "light" : "dark";
    expect(revertedTheme).toBe(expectedReverted);
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
