import { test, expect } from "@playwright/test";
import { OIDC_URL, keycloakLogin } from "./helpers";

test.describe("OIDC Flow", () => {
  test("shows pre-login page with discovery metadata", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Should show "No Session"
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // Login button should be visible
    await expect(page.getByTestId("login-btn")).toBeVisible();

    // Should show OpenID Provider section
    await expect(page.locator("#sec-provider")).toBeVisible();
  });

  test("login → claims display → logout", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Click Login
    await page.getByTestId("login-btn").click();

    // Should redirect to Keycloak login form
    await expect(page.locator("#kc-login")).toBeVisible();

    // Enter credentials and submit
    await keycloakLogin(page);

    // Should be redirected back to fedlens with claims
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");
    await expect(page.locator("summary:has-text('Identity & Claims')").first()).toBeVisible();

    // Should show signature verification
    await expect(page.locator("summary:has-text('Signature Verification')").first()).toBeVisible();

    // Should show protocol details
    await expect(page.locator("summary:has-text('Protocol Messages')").first()).toBeVisible();

    // Verify claims via data-testid
    const claims = page.locator('#result-0-claims');

    // Subject (sub) — Keycloak UUID, just verify it's not empty
    await expect(claims.getByTestId('subject')).not.toBeEmpty();

    // ID Token Claims (scoped to specific table to avoid ambiguity with Access Token / UserInfo)
    const idTokenClaims = page.locator('#result-0-id-token-claims');
    await expect(idTokenClaims.getByTestId('preferred_username')).toHaveText('testuser');
    await expect(idTokenClaims.getByTestId('email')).toHaveText('testuser@example.com');

    // Signature verification (multiple sig tables: ID Token + Access Token)
    const sigs = page.locator('#result-0-sigs');
    await expect(sigs.getByTestId('verified').first()).toHaveText('true');

    // Click Logout
    await page.getByTestId("logout-btn").click();

    // Should return to pre-login page
    await expect(page.locator(".status-indicator")).toHaveText("No Session");
  });

  test("token refresh flow", async ({ page }) => {
    await page.goto(OIDC_URL);

    // Login
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    // Check if Refresh Token button exists
    const refreshButton = page.getByTestId("refresh-btn");
    if (await refreshButton.isVisible()) {
      await refreshButton.click();

      // Should still show logged in page after refresh
      await expect(page.locator(".status-indicator")).toHaveText("Active Session");
      await expect(page.locator("summary:has-text('Identity & Claims')").first()).toBeVisible();
    }

    // Cleanup: logout
    await page.getByTestId("logout-btn").click();
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
