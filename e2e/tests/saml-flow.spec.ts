import { test, expect, Page } from "@playwright/test";

const SAML_URL = "http://saml.example.com:3000";
const KC_USERNAME = "testuser";
const KC_PASSWORD = "password";

async function keycloakLogin(page: Page) {
  await page.fill("#username", KC_USERNAME);
  await page.fill("#password", KC_PASSWORD);
  await page.click("#kc-login");
}

test.describe("SAML Flow", () => {
  test("shows pre-login page with IdP metadata", async ({ page }) => {
    await page.goto(SAML_URL);

    // Should show "No Session"
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // Login button should be visible
    await expect(page.locator('a[role="button"]', { hasText: "Login" })).toBeVisible();

    // Should show IdP Metadata
    await expect(page.locator("text=IdP Metadata")).toBeVisible();
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
    await expect(page.locator("text=Attributes")).toBeVisible();

    // Should show signature verification
    await expect(page.locator("text=Signature Verification")).toBeVisible();

    // Should show SAML Response XML
    await expect(page.locator("text=SAML Response")).toBeVisible();

    // Should show AuthnRequest XML
    await expect(page.locator("text=AuthnRequest")).toBeVisible();

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
