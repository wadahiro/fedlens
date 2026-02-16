import { test, expect } from "@playwright/test";
import { SAML_URL, keycloakLogin } from "./helpers";

test.describe("SAML Flow", () => {
  test("shows pre-login page with IdP metadata", async ({ page }) => {
    await page.goto(SAML_URL);

    // Should show "No Session"
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // Login button should be visible
    await expect(page.locator('a[role="button"]', { hasText: "Login" })).toBeVisible();

    // Should show Identity Provider section
    await expect(page.locator("#sec-idp")).toBeVisible();
  });

  test("login → attributes display → logout", async ({ page }) => {
    await page.goto(SAML_URL);

    // Click Login
    await page.click('a[role="button"]:has-text("Login")');

    // Should redirect to Keycloak login form
    await expect(page.locator("#kc-login")).toBeVisible();

    // Enter credentials and submit
    await keycloakLogin(page);

    // Should be redirected back to fedlens with attributes
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");
    await expect(page.locator("summary:has-text('Identity & Claims')").first()).toBeVisible();

    // Should show signature verification
    await expect(page.locator("summary:has-text('Signature Verification')").first()).toBeVisible();

    // Should show protocol messages
    await expect(page.locator("summary:has-text('Protocol Messages')").first()).toBeVisible();

    // Click Logout
    await page.click('a[role="button"]:has-text("Logout")');

    // Should return to pre-login page
    await expect(page.locator(".status-indicator")).toHaveText("No Session");
  });

  test("navigation tabs are displayed", async ({ page }) => {
    await page.goto(SAML_URL);

    // Nav should contain tabs
    const nav = page.locator("nav");
    await expect(nav).toBeVisible();

    // Should have at least the SAML tab
    await expect(nav.locator("text=SAML")).toBeVisible();
  });
});
