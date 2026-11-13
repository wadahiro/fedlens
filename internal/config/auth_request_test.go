package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadString(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

const oidcHead = `
[[oidc]]
name = "A"
base_url = "http://a.test:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://a.test:3000/callback"
`

func TestAuthRequestTableOverridesDefaults(t *testing.T) {
	cfg, err := loadString(t, oidcHead+`
[oidc.auth_request]
response_type = "id_token"
scopes = ["openid"]
pkce = true
extra_auth_params = { prompt = "login" }
`)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.OIDC[0]
	if c.ResponseType != "id_token" {
		t.Errorf("ResponseType = %q, want id_token (a default must not mask the table)", c.ResponseType)
	}
	if len(c.Scopes) != 1 || c.Scopes[0] != "openid" || !c.PKCE || c.ExtraAuthParams["prompt"] != "login" {
		t.Errorf("auth_request table not applied: %+v", c)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", cfg.Warnings)
	}
}

func TestLegacyDirectKeysStillWorkAndWarn(t *testing.T) {
	cfg, err := loadString(t, oidcHead+`pkce = true
response_mode = "form_post"
`)
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.OIDC[0]
	if !c.PKCE || c.ResponseMode != "form_post" {
		t.Errorf("legacy keys lost: %+v", c)
	}
	if len(cfg.Warnings) != 2 {
		t.Errorf("warnings = %v, want 2 deprecations", cfg.Warnings)
	}
}

func TestLegacyWarningAttachesToOwningEntry(t *testing.T) {
	cfg, err := loadString(t, oidcHead+`
[[oidc]]
name = "B"
base_url = "http://b.test:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://b.test:3000/callback"
pkce = true
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "oidc[1]") {
		t.Errorf("warnings = %v, want one for oidc[1]", cfg.Warnings)
	}
}

func TestLegacyAndTableConflictIsError(t *testing.T) {
	_, err := loadString(t, oidcHead+`pkce = false
[oidc.auth_request]
pkce = true
`)
	if err == nil || !strings.Contains(err.Error(), "pkce") {
		t.Fatalf("err = %v, want a pkce conflict", err)
	}
}

func TestLegacyAndTableEqualValuesAreAccepted(t *testing.T) {
	cfg, err := loadString(t, oidcHead+`pkce = true
[oidc.auth_request]
pkce = true
`)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OIDC[0].PKCE {
		t.Error("PKCE should be true")
	}
}

func TestOAuth2AuthRequestTable(t *testing.T) {
	cfg, err := loadString(t, `
[[oauth2]]
name = "O"
base_url = "http://o.test:3000"
authorization_url = "https://as.test/auth"
token_url = "https://as.test/token"
client_id = "c"
client_secret = "s"
redirect_uri = "http://o.test:3000/callback"

[oauth2.auth_request]
scopes = ["read"]
response_mode = "query"
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.OAuth2[0]; len(got.Scopes) != 1 || got.Scopes[0] != "read" || got.ResponseMode != "query" {
		t.Errorf("oauth2 auth_request not applied: %+v", got)
	}
}

func TestKeyBelowAuthRequestHeaderIsReported(t *testing.T) {
	cfg, err := loadString(t, oidcHead+`
[oidc.auth_request]
pkce = true
introspection_url = "https://idp.test/introspect"
`)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "introspection_url") && strings.Contains(w, "auth_request") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want the misplaced key reported", cfg.Warnings)
	}
}

const samlHead = `
[[saml]]
name = "S"
base_url = "http://s.test:3000"
idp_metadata_url = "https://idp.test/metadata"
entity_id = "http://s.test:3000/saml/metadata"
root_url = "http://s.test:3000"
`

func TestSAMLReauthOverridesDefaultsIncludingFalse(t *testing.T) {
	cfg, err := loadString(t, samlHead+`
[saml.auth_request]
name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
force_authn = true
allow_create = true

[[saml.reauth]]
name = "soft"
force_authn = false
authn_context_class_ref = "urn:acr:mfa"
`)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.SAML[0]
	got := s.AuthRequest.Overlay(s.Reauth[0].SAMLAuthRequestConfig)
	if got.ForceAuthn == nil || *got.ForceAuthn {
		t.Errorf("ForceAuthn = %v, want explicit false from the profile", got.ForceAuthn)
	}
	if got.AllowCreate == nil || !*got.AllowCreate {
		t.Errorf("AllowCreate = %v, want inherited true", got.AllowCreate)
	}
	if got.NameIDFormat == "" || got.AuthnContextClassRef != "urn:acr:mfa" {
		t.Errorf("overlay result wrong: %+v", got)
	}
}

func TestSAMLAuthRequestUnsetStaysNil(t *testing.T) {
	cfg, err := loadString(t, samlHead)
	if err != nil {
		t.Fatal(err)
	}
	ar := cfg.SAML[0].AuthRequest
	if ar.AllowCreate != nil || ar.ForceAuthn != nil || ar.IsPassive != nil {
		t.Errorf("unset booleans must stay nil so they are omitted from the request: %+v", ar)
	}
}

func TestSAMLOverlayNameIDAndSubjectFields(t *testing.T) {
	yes, no := true, false
	base := SAMLAuthRequestConfig{
		NameIDFormat:     "urn:base",
		OmitNameIDPolicy: &yes,
		SubjectNameID:    "base@example.com",
	}
	got := base.Overlay(SAMLAuthRequestConfig{
		OmitNameIDPolicy:    &no,
		SubjectNameIDFormat: "urn:fmt",
	})
	if got.OmitNameIDPolicy == nil || *got.OmitNameIDPolicy {
		t.Errorf("OmitNameIDPolicy = %v, want explicit false from override", got.OmitNameIDPolicy)
	}
	if got.NameIDFormat != "urn:base" || got.SubjectNameID != "base@example.com" || got.SubjectNameIDFormat != "urn:fmt" {
		t.Errorf("overlay result wrong: %+v", got)
	}
}
