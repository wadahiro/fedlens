package protocol

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestIsJWT(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"a.b.c", true},
		{"eyJ.eyJ.sig", true},
		{"not-a-jwt", false},
		{"a.b", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsJWT(tt.input); got != tt.want {
			t.Errorf("IsJWT(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDecodeJWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user1","iss":"https://example.com"}`))
	token := header + "." + payload + ".signature"

	h, p := DecodeJWT(token)
	if h == "" || p == "" {
		t.Fatal("DecodeJWT returned empty header or payload")
	}

	// Verify it contains expected fields
	if !contains(h, "RS256") {
		t.Errorf("header should contain RS256, got: %s", h)
	}
	if !contains(p, "user1") {
		t.Errorf("payload should contain user1, got: %s", p)
	}
}

func TestExtractJWTHeaderInfo(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"my-key-id"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	token := header + "." + payload + ".sig"

	alg, kid := ExtractJWTHeaderInfo(token)
	if alg != "RS256" {
		t.Errorf("alg = %q, want RS256", alg)
	}
	if kid != "my-key-id" {
		t.Errorf("kid = %q, want my-key-id", kid)
	}
}

func TestBuildJWTSignatureInfo(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
	token := header + "." + payload + ".sig"

	jwks := json.RawMessage(`{"keys":[{"kid":"key1","kty":"RSA","use":"sig","alg":"RS256"}]}`)

	info := BuildJWTSignatureInfo(token, jwks, true)
	if info == nil {
		t.Fatal("BuildJWTSignatureInfo returned nil")
	}
	if info.Algorithm != "RS256" {
		t.Errorf("Algorithm = %q, want RS256", info.Algorithm)
	}
	if info.KeyType != "RSA" {
		t.Errorf("KeyType = %q, want RSA", info.KeyType)
	}
	if !info.Verified {
		t.Error("Verified should be true")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
