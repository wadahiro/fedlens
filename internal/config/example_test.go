package config

import "testing"

// The example file is what docker-compose and the e2e suite run on, and what
// people copy: it must load without a warning.
func TestExampleConfigLoadsCleanly(t *testing.T) {
	cfg, err := Load("../../config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("config.example.toml gives warnings: %v", cfg.Warnings)
	}
	if len(cfg.OIDC) != 1 || len(cfg.OIDC[0].Scopes) != 3 {
		t.Errorf("the OIDC example lost its scopes: %+v", cfg.OIDC)
	}
	if len(cfg.OAuth2) != 1 || len(cfg.OAuth2[0].Scopes) != 2 || cfg.OAuth2[0].ResourceServerClientID == "" {
		t.Errorf("the OAuth2 example lost its scopes or resource server: %+v", cfg.OAuth2)
	}
}
