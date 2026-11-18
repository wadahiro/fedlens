package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The multi-provider example in the README is what people copy first, so it has to
// load without warnings (a legacy flat key would log a deprecation warning).
func TestReadmeMultiProviderExampleLoads(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, found := strings.Cut(string(readme), "#### Example: Multiple SP/RP")
	if !found {
		t.Fatal("README lost the Multiple SP/RP example")
	}
	m := regexp.MustCompile("(?s)```toml\n(.*?)```").FindStringSubmatch(after)
	if m == nil {
		t.Fatal("no toml block after the Multiple SP/RP heading")
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(m[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
	if !cfg.OIDC[0].PKCE || cfg.OIDC[1].ExtraAuthParams["login_hint"] == "" || len(cfg.OAuth2[0].Scopes) != 2 {
		t.Errorf("auth_request values were not picked up: %+v", cfg)
	}
}
