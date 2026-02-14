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
host = "oidc.test:8080"
issuer = "https://idp.test/realms/test"
client_id = "test-client"
client_secret = "secret"
redirect_uri = "http://oidc.test:8080/callback"
pkce = true
pkce_method = "S256"
extra_auth_params = { prompt = "consent" }

[[oidc]]
name = "Second OIDC"
host = "oidc2.test:8080"
issuer = "https://idp2.test"
client_id = "client2"
client_secret = "secret2"
redirect_uri = "http://oidc2.test:8080/callback"

[[saml]]
name = "Test SAML"
host = "saml.test:8080"
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
host = "oidc.test:3000"
issuer = "https://idp.test"
client_id = "c"
client_secret = "s"
redirect_uri = "http://oidc.test:3000/services/oauth2/callback"
callback_path = "/services/oauth2/callback"

[[saml]]
name = "Custom SAML"
host = "saml.test:3000"
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
host = "oidc.test:3000"
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
