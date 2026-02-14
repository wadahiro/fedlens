import { test, expect, Page } from "@playwright/test";

const OIDC_URL = "http://oidc.example.com:3000";
const KC_USERNAME = "testuser";
const KC_PASSWORD = "password";

async function keycloakLogin(page: Page) {
  await page.fill("#username", KC_USERNAME);
  await page.fill("#password", KC_PASSWORD);
  await page.click("#kc-login");
}

test.describe("OIDC Flow", () => {
  test("shows pre-login page with discovery metadata", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Should show "Not logged in"
    await expect(page.locator("h1")).toHaveText("Not logged in");
    await expect(page.locator("p")).toContainText("OIDC RP:");

    // Login button should be visible
    await expect(page.locator('a[role="button"]', { hasText: "Login" })).toBeVisible();

    // Should show OpenID Provider Configuration
    await expect(page.locator("text=OpenID Provider Configuration")).toBeVisible();
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
    await expect(page.locator("h1")).toHaveText("Logged in");
    await expect(page.locator("text=ID Token Claims")).toBeVisible();

    // Should show signature verification
    await expect(page.locator("text=Signature Verification")).toBeVisible();

    // Should show protocol details
    await expect(page.locator("text=Authorization Request")).toBeVisible();
    await expect(page.locator("text=Token Response")).toBeVisible();

    // Click Logout
    await page.click('a[role="button"]:has-text("Logout")');

    // Should return to pre-login page
    await expect(page.locator("h1")).toHaveText("Not logged in");
  });

  test("token refresh flow", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Login
    await page.click('a[role="button"]:has-text("Login")');
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator("h1")).toHaveText("Logged in");

    // Check if Refresh Token button exists
    const refreshButton = page.locator('a[role="button"]:has-text("Refresh Token")');
    if (await refreshButton.isVisible()) {
      await refreshButton.click();

      // Should still show logged in page after refresh
      await expect(page.locator("h1")).toHaveText("Logged in");
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
