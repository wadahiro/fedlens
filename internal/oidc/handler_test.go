package oidc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/wadahiro/fedlens/internal/protocol"
)

func TestBuildEndpointRows(t *testing.T) {
	t.Run("full fields", func(t *testing.T) {
		oauth2Cfg := &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.example.com/auth",
				TokenURL: "https://idp.example.com/token",
			},
		}
		providerInfo := struct {
			EndSessionEndpoint string
			UserinfoEndpoint   string
			JwksURI            string
		}{
			EndSessionEndpoint: "https://idp.example.com/logout",
			UserinfoEndpoint:   "https://idp.example.com/userinfo",
			JwksURI:            "https://idp.example.com/jwks",
		}
		rows := buildEndpointRows(oauth2Cfg, providerInfo)
		if len(rows) != 5 {
			t.Errorf("got %d rows, want 5", len(rows))
		}
	})

	t.Run("some empty fields omitted", func(t *testing.T) {
		oauth2Cfg := &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.example.com/auth",
				TokenURL: "https://idp.example.com/token",
			},
		}
		providerInfo := struct {
			EndSessionEndpoint string
			UserinfoEndpoint   string
			JwksURI            string
		}{
			UserinfoEndpoint: "https://idp.example.com/userinfo",
		}
		rows := buildEndpointRows(oauth2Cfg, providerInfo)
		if len(rows) != 3 {
			t.Errorf("got %d rows, want 3", len(rows))
		}
	})
}

func TestBuildJWKSKeyRows(t *testing.T) {
	t.Run("all fields present", func(t *testing.T) {
		keys := []protocol.JWKSKeyInfo{
			{Kid: "k1", Kty: "RSA", Alg: "RS256", Use: "sig"},
		}
		result := buildJWKSKeyRows(keys)
		if len(result) != 1 {
			t.Fatalf("got %d key groups, want 1", len(result))
		}
		if len(result[0].Rows) != 4 {
			t.Errorf("got %d rows, want 4", len(result[0].Rows))
		}
	})

	t.Run("missing fields produce fewer rows", func(t *testing.T) {
		keys := []protocol.JWKSKeyInfo{
			{Kid: "k2", Kty: "RSA"},
		}
		result := buildJWKSKeyRows(keys)
		if len(result) != 1 {
			t.Fatalf("got %d key groups, want 1", len(result))
		}
		if len(result[0].Rows) != 2 {
			t.Errorf("got %d rows, want 2 (Kid + Kty)", len(result[0].Rows))
		}
	})

	t.Run("empty input", func(t *testing.T) {
		result := buildJWKSKeyRows(nil)
		if len(result) != 0 {
			t.Errorf("got %d key groups, want 0", len(result))
		}
	})
}

func TestBuildJWTSigRows(t *testing.T) {
	t.Run("full info", func(t *testing.T) {
		info := &protocol.JWTSignatureInfo{
			Algorithm: "RS256",
			KeyID:     "kid1",
			KeyType:   "RSA",
			KeyUse:    "sig",
			KeyAlg:    "RS256",
			Verified:  true,
		}
		rows := buildJWTSigRows(info)
		// All 6 fields should be present (Algorithm, KeyID, KeyType, KeyUse, KeyAlg, Verified)
		if len(rows) != 6 {
			t.Errorf("got %d rows, want 6", len(rows))
		}
	})

	t.Run("empty fields omitted", func(t *testing.T) {
		info := &protocol.JWTSignatureInfo{
			Algorithm: "RS256",
			Verified:  false,
		}
		rows := buildJWTSigRows(info)
		// Algorithm + Verified("false") = 2 rows
		if len(rows) != 2 {
			t.Errorf("got %d rows, want 2", len(rows))
		}
	})
}

func TestParseToClaimRows(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := parseToClaimRows(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		result := parseToClaimRows([]protocol.KeyValue{})
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("two params", func(t *testing.T) {
		params := []protocol.KeyValue{
			{Key: "code", Value: "abc123"},
			{Key: "state", Value: "xyz789"},
		}
		result := parseToClaimRows(params)
		if len(result) != 2 {
			t.Fatalf("got %d rows, want 2", len(result))
		}
		if result[0].Key != "code" || result[0].Value != "abc123" {
			t.Errorf("rows[0] = %+v", result[0])
		}
	})
}

func TestMarshalTokenResponse(t *testing.T) {
	token := &oauth2.Token{
		AccessToken: "access-123",
		TokenType:   "Bearer",
		Expiry:      time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	result := marshalTokenResponse(token)
	var m map[string]any
	if err := json.Unmarshal(result, &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if m["access_token"] != "access-123" {
		t.Errorf("access_token = %v", m["access_token"])
	}
	if m["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", m["token_type"])
	}
}

func TestExtractOAuthError(t *testing.T) {
	t.Run("oauth2.RetrieveError", func(t *testing.T) {
		re := &oauth2.RetrieveError{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "Token expired",
			ErrorURI:         "https://example.com/error",
			Body:             []byte(`{"error":"invalid_grant"}`),
		}
		code, desc, uri, detail := extractOAuthError(re)
		if code != "invalid_grant" {
			t.Errorf("code = %q, want invalid_grant", code)
		}
		if desc != "Token expired" {
			t.Errorf("desc = %q, want Token expired", desc)
		}
		if uri != "https://example.com/error" {
			t.Errorf("uri = %q", uri)
		}
		if detail != `{"error":"invalid_grant"}` {
			t.Errorf("detail = %q", detail)
		}
	})

	t.Run("generic error", func(t *testing.T) {
		err := errors.New("connection refused")
		code, desc, uri, detail := extractOAuthError(err)
		if code != "" || desc != "" || uri != "" {
			t.Errorf("expected empty code/desc/uri, got code=%q desc=%q uri=%q", code, desc, uri)
		}
		if detail != "connection refused" {
			t.Errorf("detail = %q, want 'connection refused'", detail)
		}
	})
}

func TestFormatTimestamp_OIDC(t *testing.T) {
	origLoc := protocol.DisplayLocation
	t.Cleanup(func() { protocol.DisplayLocation = origLoc })

	t.Run("nil DisplayLocation uses UTC", func(t *testing.T) {
		protocol.DisplayLocation = nil
		now := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
		result := formatTimestamp(now)
		if !strings.Contains(result, "2024/01/15") {
			t.Errorf("result = %q, expected date format", result)
		}
	})

	t.Run("JST DisplayLocation", func(t *testing.T) {
		jst, err := time.LoadLocation("Asia/Tokyo")
		if err != nil {
			t.Skip("Asia/Tokyo timezone not available")
		}
		protocol.DisplayLocation = jst
		now := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
		result := formatTimestamp(now)
		if !strings.Contains(result, "JST") {
			t.Errorf("result = %q, expected JST", result)
		}
	})
}

func TestFormatSidebarTimestamp(t *testing.T) {
	origLoc := protocol.DisplayLocation
	t.Cleanup(func() { protocol.DisplayLocation = origLoc })

	protocol.DisplayLocation = nil
	now := time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC)
	result := formatSidebarTimestamp(now)
	if result != "01/15 10:30:45" {
		t.Errorf("result = %q, want '01/15 10:30:45'", result)
	}
}
