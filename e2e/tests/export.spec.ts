import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { OIDC_URL, SAML_URL, keycloakLogin } from "./helpers";

test("Export downloads a standalone copy of the timeline", async ({ page }) => {
  await page.goto(SAML_URL);
  await page.getByTestId("login-btn").click();
  await keycloakLogin(page);
  await expect(page.locator(".status-indicator")).toHaveText("Active Session");

  // The Export link only appears once there is a timeline to export.
  const exportLink = page.getByTestId("export-btn");
  await expect(exportLink).toBeVisible();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    exportLink.click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^fedlens-.*\.html$/);

  const html = readFileSync(await download.path(), "utf8");

  // Standalone: nothing left to fetch from the server.
  expect(html).not.toContain('href="/static');
  expect(html).not.toContain('src="/static');
  expect(html).toContain("<style>");

  // The evidence survived the round trip.
  expect(html).toContain("testuser@example.com");

  // Controls that would post back to a server are gone, and the warning is not.
  expect(html).toContain("Exported from fedlens");
  expect(html).not.toContain('data-testid="login-btn"');
  expect(html).not.toContain('data-testid="logout-btn"');
  expect(html).not.toContain('data-testid="export-btn"');
});

test("Export is scoped to the SP it was taken from", async ({ page }) => {
  // Log into OIDC and SAML in the same browser, then export from SAML. Each
  // entry keeps its own store behind its own cookie, so the SAML export must
  // carry no trace of the OIDC session — including the app tabs, which named
  // the other entries and made an export look like it held their results too.
  await page.goto(OIDC_URL);
  await page.getByTestId("login-btn").click();
  await keycloakLogin(page);
  await expect(page.locator(".status-indicator")).toHaveText("Active Session");

  await page.goto(SAML_URL);
  await page.getByTestId("login-btn").click();
  await expect(page.locator(".status-indicator")).toHaveText("Active Session");

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("export-btn").click(),
  ]);
  const html = readFileSync(await download.path(), "utf8");

  expect(html).toContain("SAMLResponse");
  expect(html).not.toContain("Keycloak OIDC");
  expect(html).not.toContain("Keycloak OAuth2");
  expect(html).not.toContain("ID Token");
  expect(html).not.toContain("access_token");
});
