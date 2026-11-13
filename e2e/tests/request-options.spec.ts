import { test, expect, Page } from "@playwright/test";
import { OIDC_URL, OAUTH2_URL, SAML_URL, keycloakLogin } from "./helpers";

// The options form behind each action button changes one request. These tests
// drive the forms the way a user does and check what the IdP actually receives.

async function openOptions(page: Page, button: string) {
  await page.getByTestId(`${button}-options-toggle`).click();
  await expect(page.getByTestId(`${button}-options-panel`)).toBeVisible();
}

async function oidcLogin(page: Page) {
  await page.goto(OIDC_URL);
  await page.getByTestId("login-btn").click();
  await expect(page.locator("#kc-login")).toBeVisible();
  await keycloakLogin(page);
  await expect(page.locator(".status-indicator")).toHaveText("Active Session");
}

test.describe("Request options: OIDC", () => {
  test("Login options start with the config and count only what is changed", async ({ page }) => {
    await page.goto(OIDC_URL);
    await openOptions(page, "login");

    // [oidc.auth_request] scopes, as a real value rather than a hint
    await expect(page.getByTestId("login-opt-scope")).toHaveValue("openid profile email");
    await expect(page.getByTestId("login-options-toggle").locator(".ro-count")).toBeHidden();

    await page.getByTestId("login-opt-login_hint").fill("testuser");
    await expect(page.getByTestId("login-options-toggle").locator(".ro-count")).toHaveText("1");
    await expect(page.getByTestId("login-options-summary")).toContainText("login_hint=testuser");

    await page.getByTestId("login-options-reset").click();
    await expect(page.getByTestId("login-opt-login_hint")).toHaveValue("");
    await expect(page.getByTestId("login-options-toggle").locator(".ro-count")).toBeHidden();
  });

  test("login_hint from the Login options reaches Keycloak", async ({ page }) => {
    await page.goto(OIDC_URL);
    await openOptions(page, "login");
    await page.getByTestId("login-opt-login_hint").fill("testuser");
    await page.getByTestId("login-btn").click();

    // Keycloak puts login_hint into the username field.
    await expect(page.locator("#username")).toHaveValue("testuser");
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    await page.getByTestId("logout-btn").click();
    await expect(page.locator(".status-indicator")).toHaveText("No Session");
  });

  test("Refresh options send scope and extra parameters, and show them", async ({ page }) => {
    await oidcLogin(page);

    const refresh = page.getByTestId("refresh-btn");
    test.skip(!(await refresh.isVisible()), "the IdP issued no refresh token");

    await openOptions(page, "refresh");
    // a refresh adds nothing by default
    await expect(page.getByTestId("refresh-opt-scope")).toHaveValue("");

    await page.getByTestId("refresh-opt-scope").fill("openid");
    await page.getByTestId("refresh-opt-extra").fill("audience=fedlens-oidc");
    const [request] = await Promise.all([
      page.waitForRequest((r) => r.url().includes("/refresh")),
      refresh.click(),
    ]);
    const sent = new URL(request.url()).searchParams;
    expect(sent.get("scope")).toBe("openid");

    await expect(page.locator(".status-indicator")).toHaveText("Active Session");
    // what the token request carried is part of the result
    const protocol = page.locator("#result-0-protocol");
    await expect(protocol).toContainText("grant_type=refresh_token");
    await expect(protocol).toContainText("scope=openid");
    await expect(protocol).toContainText("audience=fedlens-oidc");

    await page.getByTestId("logout-btn").click();
  });

  test("an emptied Logout redirect is left out of the logout request", async ({ page }) => {
    await oidcLogin(page);
    await openOptions(page, "logout");
    await expect(page.getByTestId("logout-opt-post_logout_redirect_uri")).toHaveValue(`${OIDC_URL}/`);

    await page.getByTestId("logout-opt-post_logout_redirect_uri").fill("");
    await expect(page.getByTestId("logout-options-summary")).toContainText("post_logout_redirect_uri removed");

    const [request] = await Promise.all([
      page.waitForRequest((r) => r.url().includes("/protocol/openid-connect/logout")),
      page.getByTestId("logout-btn").click(),
    ]);
    const sent = new URL(request.url()).searchParams;
    expect(sent.has("post_logout_redirect_uri")).toBe(false);
    expect(sent.get("client_id")).toBe("fedlens-oidc");
  });
});

test.describe("Request options: OAuth2", () => {
  test("Login options offer only what OAuth2 has", async ({ page }) => {
    await page.goto(OAUTH2_URL);
    await openOptions(page, "login");
    await expect(page.getByTestId("login-opt-scope")).toHaveValue("profile email");
    await expect(page.getByTestId("login-opt-response_mode")).toBeVisible();
    // prompt, login_hint and the rest are OpenID Connect parameters
    await expect(page.getByTestId("login-opt-login_hint")).toHaveCount(0);
  });
});

test.describe("Request options: SAML", () => {
  test("Login options start with the library's NameIDPolicy as real values", async ({ page }) => {
    await page.goto(SAML_URL);
    await openOptions(page, "login");

    await expect(page.getByTestId("login-opt-name_id_format")).toHaveValue(
      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    );
    await expect(page.getByTestId("login-opt-allow_create")).toHaveValue("true");
    await expect(page.getByTestId("login-opt-assertion_consumer_service_url")).toHaveValue(
      `${SAML_URL}/saml/acs`,
    );
    await expect(page.getByTestId("login-options-toggle").locator(".ro-count")).toBeHidden();
  });

  test("the requested NameID format is compared with the one received", async ({ page }) => {
    const emailFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    await page.goto(SAML_URL);
    await openOptions(page, "login");
    await page.getByTestId("login-opt-name_id_format").fill(emailFormat);
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    const nameId = page.locator("#result-0-nameid");
    await expect(nameId.getByTestId("Format")).toHaveText(emailFormat);
    await expect(nameId.getByTestId("Requested")).toHaveText(emailFormat);
    await expect(nameId.getByTestId("Result")).toHaveText("matches the requested Format");
  });

  test("an emptied NameIDPolicy Format is left out of the AuthnRequest", async ({ page }) => {
    await page.goto(SAML_URL);
    await openOptions(page, "login");
    await page.getByTestId("login-opt-name_id_format").fill("");
    await page.getByTestId("login-opt-allow_create").selectOption("");
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    // What was sent is in the result: no Format and no AllowCreate on the NameIDPolicy.
    const protocol = page.locator("#result-0-protocol");
    await expect(protocol).toContainText("SAMLRequest");
    const nameId = page.locator("#result-0-nameid");
    await expect(nameId.getByTestId("Requested")).toContainText("without Format");
  });

  test("Logout options start with the NameID the assertion carried, and can leave parts out", async ({ page }) => {
    await page.goto(SAML_URL);
    await page.getByTestId("login-btn").click();
    await expect(page.locator("#kc-login")).toBeVisible();
    await keycloakLogin(page);
    await expect(page.locator(".status-indicator")).toHaveText("Active Session");

    const received = await page.locator("#result-0-nameid").getByTestId("NameID").innerText();
    await openOptions(page, "logout");
    await expect(page.getByTestId("logout-opt-name_id")).toHaveValue(received);

    // what the IdP issued is what the form starts with
    await expect(page.getByTestId("logout-opt-name_id_format")).not.toHaveValue("");

    await page.getByTestId("logout-opt-name_id").fill("someone-else");
    await page.getByTestId("logout-opt-name_id_format").fill("");
    await expect(page.getByTestId("logout-options-summary")).toContainText("name_id_format removed");

    await page.getByTestId("logout-btn").click();
    await expect(page.locator(".status-indicator")).toHaveText("No Session");

    // The LogoutRequest that was sent is shown, with what the form changed.
    const sent = page.locator("#result-0-protocol");
    await expect(sent).toContainText("someone-else");
    // the Issuer has a Format of its own; it is the NameID that must not
    expect(await sent.innerText()).not.toMatch(/<NameID[^>]*Format=/);
  });
});
