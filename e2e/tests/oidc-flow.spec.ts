import { test, expect } from "@playwright/test";
import { OIDC_URL, keycloakLogin } from "./helpers";

test.describe("OIDC Flow", () => {
  test("shows pre-login page with discovery metadata", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Should show "No Session"
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // Login button should be visible
    await expect(page.locator('a[role="button"]', { hasText: "Login" })).toBeVisible();

    // Should show OpenID Provider
    await expect(page.locator("text=OpenID Provider")).toBeVisible();
  });

  test("login → claims display → logout", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Click Login
    await page.click('a[role="button"]:has-text("Login")');

    // Should redirect to Keycloak login form
    await expect(page.locator("#kc-login")).toBeVisible();

    // Enter credentials and submit
    await keycloakLogin(page);

    // Should be redirected back to fedlens with claims
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");
    await expect(page.locator("text=ID Token Claims")).toBeVisible();

    // Should show signature verification
    await expect(page.locator("text=Signature Verification")).toBeVisible();

    // Should show protocol details
    await expect(page.locator("text=Authorization Request")).toBeVisible();
    await expect(page.locator("text=Token Response")).toBeVisible();

    // Click Logout
    await page.click('a[role="button"]:has-text("Logout")');

    // Should return to pre-login page
    await expect(page.locator(".status-indicator")).toHaveText("No Session");
  });

  test("token refresh flow", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Login
    await page.click('a[role="button"]:has-text("Login")');
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    // Check if Refresh Token button exists
    const refreshButton = page.locator('a[role="button"]:has-text("Refresh Token")');
    if (await refreshButton.isVisible()) {
      await refreshButton.click();

      // Should still show logged in page after refresh
      await expect(page.locator(".status-indicator")).toHaveText("Active Session");
      await expect(page.locator("text=ID Token Claims")).toBeVisible();
    }

    // Cleanup: logout
    await page.click('a[role="button"]:has-text("Logout")');
  });

  test("navigation tabs are displayed", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Nav should contain tabs
    const nav = page.locator("nav");
    await expect(nav).toBeVisible();

    // Should have at least the OIDC tab
    await expect(nav.locator("text=OIDC")).toBeVisible();
  });
});
