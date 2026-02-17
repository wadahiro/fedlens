import { test, expect } from "@playwright/test";
import { OAUTH2_URL, keycloakLogin } from "./helpers";

test.describe("OAuth2 Flow", () => {
  test("shows pre-login page with authorization server info", async ({
    page,
  }) => {
    await page.goto(OAUTH2_URL);

    // Should show "No Session"
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // Login button should be visible
    await expect(page.getByTestId("login-btn")).toBeVisible();

    // Should show Authorization Server section
    await expect(page.locator("#sec-provider")).toBeVisible();
  });

  test("login → token display → clear", async ({ page }) => {
    await page.goto(OAUTH2_URL);

    // Click Login
    await page.getByTestId("login-btn").click();

    // Should redirect to Keycloak login form
    await expect(page.locator("#kc-login")).toBeVisible();

    // Enter credentials and submit
    await keycloakLogin(page);

    // Should be redirected back to fedlens with tokens
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    // Should show protocol messages
    await expect(
      page.locator("summary:has-text('Protocol Messages')").first()
    ).toBeVisible();

    // Should NOT show ID Token sections (OAuth2, not OIDC)
    await expect(page.locator("text=ID Token Claims")).not.toBeVisible();

    // Should NOT show Logout button (OAuth2 has no logout spec)
    await expect(page.getByTestId("logout-btn")).not.toBeVisible();

    // Click Clear to reset results
    await page.getByTestId("clear-btn").click();

    // Should still show Active Session (Clear only removes results)
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");
  });

  test("token refresh flow", async ({ page }) => {
    await page.goto(OAUTH2_URL);

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
      await expect(page.locator(".status-indicator")).toHaveText(
        "Active Session"
      );
    }

    // Cleanup: clear results
    await page.getByTestId("clear-btn").click();
  });

  test("token introspection flow", async ({ page }) => {
    await page.goto(OAUTH2_URL);

    // Login
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    // Check if Introspection button exists
    const introspectionButton = page.getByTestId("introspection-btn");
    if (await introspectionButton.isVisible()) {
      await introspectionButton.click();

      // Should still show logged in page after introspection
      await expect(page.locator(".status-indicator")).toHaveText(
        "Active Session"
      );

      // Should show Token Info section
      await expect(
        page.locator("summary:has-text('Token Info')").first()
      ).toBeVisible();
    }

    // Cleanup: clear results
    await page.getByTestId("clear-btn").click();
  });

  test("navigation tabs show OAuth2 badge", async ({ page }) => {
    await page.goto(OAUTH2_URL);

    // Nav should contain tabs
    const nav = page.locator("nav");
    await expect(nav).toBeVisible();

    // Should have the OAuth2 tab
    await expect(nav.locator("text=OAuth2")).toBeVisible();
  });
});
