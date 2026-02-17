package oidc

import (
	"encoding/json"
	"testing"

	"github.com/wadahiro/fedlens/internal/config"
	"golang.org/x/oauth2"
)

func TestBuildWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name        string
		errCode     string
		errDesc     string
		metadataURL string
		want        string
	}{
		{
			name: "no params",
			want: "Bearer",
		},
		{
			name:    "error only",
			errCode: "invalid_token",
			want:    `Bearer error="invalid_token"`,
		},
		{
			name:    "error and description",
			errCode: "invalid_token",
			errDesc: "Token expired",
			want:    `Bearer error="invalid_token", error_description="Token expired"`,
		},
		{
			name:        "all params",
			errCode:     "invalid_token",
			errDesc:     "Token is not active",
			metadataURL: "http://localhost:3000/.well-known/oauth-protected-resource/oauth2/resource",
			want:        `Bearer error="invalid_token", error_description="Token is not active", resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/oauth2/resource"`,
		},
		{
			name:        "metadata only",
			metadataURL: "http://localhost:3000/.well-known/oauth-protected-resource/resource",
			want:        `Bearer resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/resource"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildWWWAuthenticate(tt.errCode, tt.errDesc, tt.metadataURL)
			if got != tt.want {
				t.Errorf("buildWWWAuthenticate(%q, %q, %q) = %q, want %q",
					tt.errCode, tt.errDesc, tt.metadataURL, got, tt.want)
			}
		})
	}
}

func TestResourceMetadataJSON(t *testing.T) {
	h := &Handler{
		Config: config.OIDCConfig{
			Name:    "Test OAuth2",
			BaseURL: "http://localhost:3000/oauth2",
		},
		oauth2Cfg: &config.OAuth2Config{
			Issuer: "https://idp.example.com/realms/test",
			Scopes: []string{"profile", "email"},
		},
		basePath: "/oauth2",
		oauth2Config: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://idp.example.com/realms/test/protocol/openid-connect/token",
			},
		},
	}

	data := h.ResourceMetadataJSON()

	var metadata map[string]any
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal metadata JSON: %v", err)
	}

	if metadata["resource"] != "http://localhost:3000/oauth2/resource" {
		t.Errorf("resource = %v, want http://localhost:3000/oauth2/resource", metadata["resource"])
	}

	authServers, ok := metadata["authorization_servers"].([]any)
	if !ok || len(authServers) != 1 || authServers[0] != "https://idp.example.com/realms/test" {
		t.Errorf("authorization_servers = %v, want [https://idp.example.com/realms/test]", metadata["authorization_servers"])
	}

	scopes, ok := metadata["scopes_supported"].([]any)
	if !ok || len(scopes) != 2 {
		t.Errorf("scopes_supported = %v, want [profile email]", metadata["scopes_supported"])
	}

	bearerMethods, ok := metadata["bearer_methods_supported"].([]any)
	if !ok || len(bearerMethods) != 1 || bearerMethods[0] != "header" {
		t.Errorf("bearer_methods_supported = %v, want [header]", metadata["bearer_methods_supported"])
	}

	resourceName, ok := metadata["resource_name"].(string)
	if !ok || resourceName != "fedlens Built-in Resource Server (Test OAuth2)" {
		t.Errorf("resource_name = %v, want fedlens Built-in Resource Server (Test OAuth2)", metadata["resource_name"])
	}
}

func TestResourceMetadataJSONDeriveFromTokenURL(t *testing.T) {
	h := &Handler{
		Config: config.OIDCConfig{
			Name:    "Manual OAuth2",
			BaseURL: "http://localhost:3000",
		},
		oauth2Cfg: &config.OAuth2Config{
			Scopes: []string{"read"},
		},
		basePath: "",
		oauth2Config: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://auth.example.com/token",
			},
		},
	}

	data := h.ResourceMetadataJSON()

	var metadata map[string]any
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal metadata JSON: %v", err)
	}

	authServers, ok := metadata["authorization_servers"].([]any)
	if !ok || len(authServers) != 1 || authServers[0] != "https://auth.example.com" {
		t.Errorf("authorization_servers = %v, want [https://auth.example.com]", metadata["authorization_servers"])
	}
}

func TestResourceMetadataPath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		want     string
	}{
		{
			name:     "host-based (no basePath)",
			basePath: "",
			want:     "/.well-known/oauth-protected-resource/resource",
		},
		{
			name:     "path-based /oauth2",
			basePath: "/oauth2",
			want:     "/.well-known/oauth-protected-resource/oauth2/resource",
		},
		{
			name:     "path-based /myapp",
			basePath: "/myapp",
			want:     "/.well-known/oauth-protected-resource/myapp/resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{basePath: tt.basePath}
			got := h.ResourceMetadataPath()
			if got != tt.want {
				t.Errorf("ResourceMetadataPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
