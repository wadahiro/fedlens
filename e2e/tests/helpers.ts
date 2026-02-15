import { Page } from "@playwright/test";

export const OIDC_URL = "http://oidc.example.com:3000";
export const SAML_URL = "http://saml.example.com:3000";

export async function keycloakLogin(page: Page) {
  await page.fill("#username", "testuser");
  await page.fill("#password", "password");
  await page.click("#kc-login");
}
