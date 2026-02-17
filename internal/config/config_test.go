package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNonExistent(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("Load(nonexistent) should return error")
	}
}

func TestLoadTOML(t *testing.T) {
	toml := `
listen_addr = ":8080"
insecure_skip_verify = true
log_level = "debug"

[[oidc]]
name = "Test OIDC"
base_url = "http://oidc.test:8080"
issuer = "https://idp.test/realms/test"
client_id = "test-client"
client_secret = "secret"
redirect_uri = "http://oidc.test:8080/callback"
pkce = true
pkce_method = "S256"
extra_auth_params = { prompt = "consent" }

[[oidc]]
name = "Second OIDC"
base_url = "http://oidc2.test:8080"
issuer = "https://idp2.test"
client_id = "client2"
client_secret = "secret2"
redirect_uri = "http://oidc2.test:8080/callback"

[[saml]]
name = "Test SAML"
base_url = "http://saml.test:8080"
idp_metadata_url = "https://idp.test/saml/metadata"
entity_id = "http://saml.test:8080/saml/metadata"
root_url = "http://saml.test:8080"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}

	// OIDC
	if len(cfg.OIDC) != 2 {
		t.Fatalf("len(OIDC) = %d, want 2", len(cfg.OIDC))
	}
	oidc := cfg.OIDC[0]
	if oidc.Name != "Test OIDC" {
		t.Errorf("OIDC[0].Name = %q", oidc.Name)
	}
	if oidc.BaseURL != "http://oidc.test:8080" {
		t.Errorf("OIDC[0].BaseURL = %q", oidc.BaseURL)
	}
	if oidc.ParsedHost != "oidc.test:8080" {
		t.Errorf("OIDC[0].ParsedHost = %q, want oidc.test:8080", oidc.ParsedHost)
	}
	if oidc.BasePath != "" {
		t.Errorf("OIDC[0].BasePath = %q, want empty (host-based)", oidc.BasePath)
	}
	if !oidc.PKCE {
		t.Error("OIDC[0].PKCE should be true")
	}
	if oidc.PKCEMethod != "S256" {
		t.Errorf("OIDC[0].PKCEMethod = %q, want S256", oidc.PKCEMethod)
	}
	if oidc.ExtraAuthParams["prompt"] != "consent" {
		t.Errorf("OIDC[0].ExtraAuthParams[prompt] = %q", oidc.ExtraAuthParams["prompt"])
	}

	// Defaults applied to second OIDC
	oidc2 := cfg.OIDC[1]
	if len(oidc2.Scopes) != 3 {
		t.Errorf("OIDC[1].Scopes = %v, want default scopes", oidc2.Scopes)
	}
	if oidc2.PKCEMethod != "S256" {
		t.Errorf("OIDC[1].PKCEMethod = %q, want S256 (default)", oidc2.PKCEMethod)
	}
	if oidc2.CallbackPath != "/callback" {
		t.Errorf("OIDC[1].CallbackPath = %q, want /callback (default)", oidc2.CallbackPath)
	}

	// SAML
	if len(cfg.SAML) != 1 {
		t.Fatalf("len(SAML) = %d, want 1", len(cfg.SAML))
	}
	if cfg.SAML[0].Name != "Test SAML" {
		t.Errorf("SAML[0].Name = %q", cfg.SAML[0].Name)
	}
	if cfg.SAML[0].ParsedHost != "saml.test:8080" {
		t.Errorf("SAML[0].ParsedHost = %q, want saml.test:8080", cfg.SAML[0].ParsedHost)
	}
	if cfg.SAML[0].BasePath != "" {
		t.Errorf("SAML[0].BasePath = %q, want empty (host-based)", cfg.SAML[0].BasePath)
	}
	if cfg.SAML[0].ACSPath != "/saml/acs" {
		t.Errorf("SAML[0].ACSPath = %q, want /saml/acs (default)", cfg.SAML[0].ACSPath)
	}
	if cfg.SAML[0].SLOPath != "/saml/slo" {
		t.Errorf("SAML[0].SLOPath = %q, want /saml/slo (default)", cfg.SAML[0].SLOPath)
	}
	if cfg.SAML[0].MetadataPath != "/saml/metadata" {
		t.Errorf("SAML[0].MetadataPath = %q, want /saml/metadata (default)", cfg.SAML[0].MetadataPath)
	}
}

func TestLoadCustomPaths(t *testing.T) {
	toml := `
[[oidc]]
name = "Custom OIDC"
base_url = "http://oidc.test:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oidc.test:3000/services/oauth2/callback"
callback_path = "/services/oauth2/callback"

[[saml]]
name = "Custom SAML"
base_url = "http://saml.test:3000"
idp_metadata_url = "https://idp.test/saml/metadata"
entity_id = "http://saml.test:3000/sso/saml/metadata"
root_url = "http://saml.test:3000"
acs_path = "/sso/saml/consume"
slo_path = "/sso/saml/logout"
metadata_path = "/sso/saml/metadata"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OIDC[0].CallbackPath != "/services/oauth2/callback" {
		t.Errorf("CallbackPath = %q, want /services/oauth2/callback", cfg.OIDC[0].CallbackPath)
	}
	if cfg.SAML[0].ACSPath != "/sso/saml/consume" {
		t.Errorf("ACSPath = %q, want /sso/saml/consume", cfg.SAML[0].ACSPath)
	}
	if cfg.SAML[0].SLOPath != "/sso/saml/logout" {
		t.Errorf("SLOPath = %q, want /sso/saml/logout", cfg.SAML[0].SLOPath)
	}
	if cfg.SAML[0].MetadataPath != "/sso/saml/metadata" {
		t.Errorf("MetadataPath = %q, want /sso/saml/metadata", cfg.SAML[0].MetadataPath)
	}
}

func TestLoadDefaults(t *testing.T) {
	toml := `
[[oidc]]
name = "Minimal"
base_url = "http://oidc.test:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oidc.test:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.ListenAddr != ":3000" {
		t.Errorf("ListenAddr = %q, want :3000", cfg.ListenAddr)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}

	oidc := cfg.OIDC[0]
	if len(oidc.Scopes) != 3 {
		t.Errorf("Scopes = %v, want 3 default scopes", oidc.Scopes)
	}
	if oidc.PKCEMethod != "S256" {
		t.Errorf("PKCEMethod = %q, want S256", oidc.PKCEMethod)
	}
	if oidc.ResponseType != "code" {
		t.Errorf("ResponseType = %q, want code", oidc.ResponseType)
	}
}

func TestLoadPathBasedRouting(t *testing.T) {
	toml := `
[[oidc]]
name = "OIDC on path"
base_url = "http://localhost:3000/keycloak"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://localhost:3000/keycloak/callback"

[[saml]]
name = "SAML on path"
base_url = "http://localhost:3000/keycloak-saml"
idp_metadata_url = "https://idp.test/saml/metadata"
entity_id = "http://localhost:3000/keycloak-saml/saml/metadata"
root_url = "http://localhost:3000/keycloak-saml"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	oidc := cfg.OIDC[0]
	if oidc.ParsedHost != "localhost:3000" {
		t.Errorf("OIDC ParsedHost = %q, want localhost:3000", oidc.ParsedHost)
	}
	if oidc.BasePath != "/keycloak" {
		t.Errorf("OIDC BasePath = %q, want /keycloak", oidc.BasePath)
	}
	if oidc.BaseURL != "http://localhost:3000/keycloak" {
		t.Errorf("OIDC BaseURL = %q, want http://localhost:3000/keycloak", oidc.BaseURL)
	}

	saml := cfg.SAML[0]
	if saml.ParsedHost != "localhost:3000" {
		t.Errorf("SAML ParsedHost = %q, want localhost:3000", saml.ParsedHost)
	}
	if saml.BasePath != "/keycloak-saml" {
		t.Errorf("SAML BasePath = %q, want /keycloak-saml", saml.BasePath)
	}
}

func TestLoadBaseURLTrailingSlashNormalized(t *testing.T) {
	toml := `
[[oidc]]
name = "Trailing Slash"
base_url = "http://localhost:3000/app/"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://localhost:3000/app/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OIDC[0].BaseURL != "http://localhost:3000/app" {
		t.Errorf("BaseURL = %q, want http://localhost:3000/app (trailing slash removed)", cfg.OIDC[0].BaseURL)
	}
	if cfg.OIDC[0].BasePath != "/app" {
		t.Errorf("BasePath = %q, want /app", cfg.OIDC[0].BasePath)
	}
}

func TestLoadBaseURLMissingScheme(t *testing.T) {
	toml := `
[[oidc]]
name = "No Scheme"
base_url = "localhost:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://localhost:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should fail for base_url without scheme")
	}
}

func TestLoadBaseURLMissing(t *testing.T) {
	toml := `
[[oidc]]
name = "No BaseURL"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://localhost:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should fail for missing base_url")
	}
}

func TestLoadOAuth2Defaults(t *testing.T) {
	toml := `
[[oauth2]]
name = "Minimal OAuth2"
base_url = "http://oauth2.test:3000"
authorization_url = "https://as.test/authorize"
token_url = "https://as.test/token"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oauth2.test:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.OAuth2) != 1 {
		t.Fatalf("len(OAuth2) = %d, want 1", len(cfg.OAuth2))
	}
	oa := cfg.OAuth2[0]
	if oa.CallbackPath != "/callback" {
		t.Errorf("CallbackPath = %q, want /callback (default)", oa.CallbackPath)
	}
	if oa.PKCEMethod != "S256" {
		t.Errorf("PKCEMethod = %q, want S256 (default)", oa.PKCEMethod)
	}
	if len(oa.Scopes) != 2 || oa.Scopes[0] != "profile" || oa.Scopes[1] != "email" {
		t.Errorf("Scopes = %v, want [profile email]", oa.Scopes)
	}
	if oa.ParsedHost != "oauth2.test:3000" {
		t.Errorf("ParsedHost = %q, want oauth2.test:3000", oa.ParsedHost)
	}
	if oa.BasePath != "" {
		t.Errorf("BasePath = %q, want empty (host-based)", oa.BasePath)
	}
}

func TestLoadOAuth2ManualEndpoints(t *testing.T) {
	toml := `
[[oauth2]]
name = "Manual OAuth2"
base_url = "http://oauth2.test:3000"
authorization_url = "https://as.test/authorize"
token_url = "https://as.test/token"
introspection_url = "https://as.test/introspect"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oauth2.test:3000/callback"
scopes = ["read", "write"]
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	oa := cfg.OAuth2[0]
	if oa.AuthorizationURL != "https://as.test/authorize" {
		t.Errorf("AuthorizationURL = %q", oa.AuthorizationURL)
	}
	if oa.TokenURL != "https://as.test/token" {
		t.Errorf("TokenURL = %q", oa.TokenURL)
	}
	if oa.IntrospectionURL != "https://as.test/introspect" {
		t.Errorf("IntrospectionURL = %q", oa.IntrospectionURL)
	}
	if len(oa.Scopes) != 2 || oa.Scopes[0] != "read" {
		t.Errorf("Scopes = %v, want [read write]", oa.Scopes)
	}
}

func TestLoadOAuth2ValidationError(t *testing.T) {
	toml := `
[[oauth2]]
name = "Bad OAuth2"
base_url = "http://oauth2.test:3000"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oauth2.test:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should fail when neither issuer nor authorization_url+token_url are specified")
	}
}

func TestLoadOAuth2WithIssuer(t *testing.T) {
	toml := `
[[oauth2]]
name = "Discovery OAuth2"
base_url = "http://oauth2.test:3000"
issuer = "https://as.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oauth2.test:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.OAuth2[0].Issuer != "https://as.test" {
		t.Errorf("Issuer = %q, want https://as.test", cfg.OAuth2[0].Issuer)
	}
}

func TestLoadDefinitionOrder(t *testing.T) {
	toml := `
[[oidc]]
name = "First OIDC"
base_url = "http://oidc1.test:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oidc1.test:3000/callback"

[[saml]]
name = "Second SAML"
base_url = "http://saml.test:3000"
idp_metadata_url = "https://idp.test/saml/metadata"
entity_id = "http://saml.test:3000/saml/metadata"
root_url = "http://saml.test:3000"

[[oauth2]]
name = "Third OAuth2"
base_url = "http://oauth2.test:3000"
authorization_url = "https://as.test/authorize"
token_url = "https://as.test/token"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oauth2.test:3000/callback"

[[oidc]]
name = "Fourth OIDC"
base_url = "http://oidc2.test:3000"
issuer = "https://idp2.test"
client_id = "c2"
client_secret = "s2"
redirect_uri = "http://oidc2.test:3000/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// OIDC[0] = "First OIDC" should be order 0
	if cfg.OIDC[0].Order != 0 {
		t.Errorf("OIDC[0].Order = %d, want 0", cfg.OIDC[0].Order)
	}
	// OIDC[1] = "Fourth OIDC" should be order 3
	if cfg.OIDC[1].Order != 3 {
		t.Errorf("OIDC[1].Order = %d, want 3", cfg.OIDC[1].Order)
	}
	// SAML[0] = "Second SAML" should be order 1
	if cfg.SAML[0].Order != 1 {
		t.Errorf("SAML[0].Order = %d, want 1", cfg.SAML[0].Order)
	}
	// OAuth2[0] = "Third OAuth2" should be order 2
	if cfg.OAuth2[0].Order != 2 {
		t.Errorf("OAuth2[0].Order = %d, want 2", cfg.OAuth2[0].Order)
	}
}

func TestLoadBaseURLDuplicate(t *testing.T) {
	toml := `
[[oidc]]
name = "First"
base_url = "http://localhost:3000/app"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://localhost:3000/app/callback"

[[saml]]
name = "Duplicate"
base_url = "http://localhost:3000/app"
idp_metadata_url = "https://idp.test/saml/metadata"
entity_id = "http://localhost:3000/app/saml/metadata"
root_url = "http://localhost:3000/app"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should fail for duplicate base_url routes")
	}
}

func TestLoadBaseURLDuplicateOAuth2(t *testing.T) {
	toml := `
[[oidc]]
name = "OIDC"
base_url = "http://localhost:3000/app"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://localhost:3000/app/callback"

[[oauth2]]
name = "OAuth2 Duplicate"
base_url = "http://localhost:3000/app"
authorization_url = "https://as.test/authorize"
token_url = "https://as.test/token"
client_id = "c2"
client_secret = "s2"
redirect_uri = "http://localhost:3000/app/callback"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load should fail for duplicate base_url routes between OIDC and OAuth2")
	}
}

func TestLoadOAuth2ResourceURLs(t *testing.T) {
	toml := `
[[oauth2]]
name = "OAuth2 with RS"
base_url = "http://oauth2.test:3000"
authorization_url = "https://as.test/authorize"
token_url = "https://as.test/token"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oauth2.test:3000/callback"
resource_urls = ["https://api.example.com/resource", "https://api2.example.com/data"]
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(toml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	oa := cfg.OAuth2[0]
	if len(oa.ResourceURLs) != 2 {
		t.Fatalf("len(ResourceURLs) = %d, want 2", len(oa.ResourceURLs))
	}
	if oa.ResourceURLs[0] != "https://api.example.com/resource" {
		t.Errorf("ResourceURLs[0] = %q", oa.ResourceURLs[0])
	}
	if oa.ResourceURLs[1] != "https://api2.example.com/data" {
		t.Errorf("ResourceURLs[1] = %q", oa.ResourceURLs[1])
	}
}
