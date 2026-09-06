import { test, expect } from "@playwright/test";
import { SAML_URL, keycloakLogin } from "./helpers";

test.describe("SAML Flow", () => {
  test("shows pre-login page with IdP metadata", async ({ page }) => {
    await page.goto(SAML_URL);

    // Should show "No Session"
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // Login button should be visible
    await expect(page.getByTestId("login-btn")).toBeVisible();

    // Should show Identity Provider section
    await expect(page.locator("#sec-idp")).toBeVisible();
  });

  test("login → attributes display → logout", async ({ page }) => {
    await page.goto(SAML_URL);

    // Click Login
    await page.getByTestId("login-btn").click();

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

    // Verify claims via data-testid
    const claims = page.locator('#result-0-claims');

    // Subject (NameID) — format depends on Keycloak config, just verify it's not empty
    await expect(claims.getByTestId('subject')).not.toBeEmpty();

    // SAML Attributes (scoped to specific table)
    const attributes = page.locator('#result-0-attributes');
    await expect(attributes.getByTestId('urn:oid:1.2.840.113549.1.9.1')).toHaveText('testuser@example.com');

    // Signature verification (multiple sig tables: Response + Assertion)
    const sigs = page.locator('#result-0-sigs');
    await expect(sigs.getByTestId('verified').first()).toHaveText('true');

    // Click Logout
    await page.getByTestId("logout-btn").click();

    // Should return to pre-login page
    await expect(page.locator(".status-indicator")).toHaveText("No Session");
  });

  test("InResponseTo failure explains that no AuthnRequest was tracked", async ({ page, context }) => {
    await page.goto(SAML_URL);
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();

    // Drop samlsp's request-tracking cookie while we are "on the login screen".
    // That is what an expired cookie, or one the browser withheld from the
    // cross-site POST, looks like to the ACS: a SAML Response arrives with no
    // AuthnRequest ID to validate InResponseTo against.
    const tracking = (await context.cookies()).filter(
      (c) =>
        c.name.startsWith("saml_") &&
        c.name !== "saml_debug_id" &&
        c.name !== "saml_reauth_name",
    );
    expect(tracking.length).toBeGreaterThan(0);
    for (const cookie of tracking) {
      await context.clearCookies({ name: cookie.name });
    }

    await keycloakLogin(page);

    // The login itself succeeds at the IdP; fedlens rejects the response.
    const error = page.locator("#result-0-error");
    await expect(error.getByTestId("StatusCode")).toHaveText("saml_validation_failed");

    // crewjam's own message is kept...
    const detail = error.getByTestId("Detail");
    await expect(detail).toContainText("InResponseTo");
    // ...and fedlens explains which of the two causes this was.
    await expect(detail).toContainText("no tracked AuthnRequest was found");
    await expect(detail).toContainText("authn_request_max_age");
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
