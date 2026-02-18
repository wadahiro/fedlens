import { test, expect } from "@playwright/test";
import { OIDC_URL, OAUTH2_URL, SAML_URL, keycloakLogin } from "./helpers";

const screenshotDir = "../docs/screenshots";

test.describe("Screenshots for README", () => {
  test.use({ viewport: { width: 1280, height: 900 } });

  test("OIDC post-login", async ({ page }) => {
    await page.goto(OIDC_URL);
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    await page.locator("html").evaluate((el) => el.setAttribute("data-theme", "light"));

    await page.screenshot({ path: `${screenshotDir}/oidc-post-login.png` });

    await page.getByTestId("logout-btn").click();
  });

  test("OAuth2 post-login", async ({ page }) => {
    await page.goto(OAUTH2_URL);
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    await page.locator("html").evaluate((el) => el.setAttribute("data-theme", "light"));

    await page.screenshot({ path: `${screenshotDir}/oauth2-post-login.png` });
  });

  test("SAML post-login", async ({ page }) => {
    await page.goto(SAML_URL);
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    await page.locator("html").evaluate((el) => el.setAttribute("data-theme", "light"));

    await page.screenshot({ path: `${screenshotDir}/saml-post-login.png` });

    await page.getByTestId("logout-btn").click();
  });
});
