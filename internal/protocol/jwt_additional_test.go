package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDecodeJWTRaw(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantHeader  bool
		wantPayload bool
	}{
		{
			name:        "valid 3-part JWT",
			token:       base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user1"}`)) + ".sig",
			wantHeader:  true,
			wantPayload: true,
		},
		{
			name:        "2-part token (no signature)",
			token:       base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user2"}`)),
			wantHeader:  true,
			wantPayload: true,
		},
		{
			name:        "less than 2 parts",
			token:       "single-part",
			wantHeader:  true,
			wantPayload: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, payload := DecodeJWTRaw(tt.token)
			if tt.wantHeader && len(header) == 0 {
				t.Error("expected non-empty header")
			}
			if tt.wantPayload && len(payload) == 0 {
				t.Error("expected non-empty payload")
			}
			if !tt.wantPayload && payload != nil {
				t.Errorf("expected nil payload, got %v", payload)
			}
		})
	}
}

func TestParseJWKSKeys(t *testing.T) {
	tests := []struct {
		name      string
		input     json.RawMessage
		wantCount int
		check     func(t *testing.T, keys []JWKSKeyInfo)
	}{
		{
			name:      "two keys",
			input:     json.RawMessage(`{"keys":[{"kid":"k1","kty":"RSA","use":"sig","alg":"RS256"},{"kid":"k2","kty":"EC","use":"sig","alg":"ES256"}]}`),
			wantCount: 2,
			check: func(t *testing.T, keys []JWKSKeyInfo) {
				if keys[0].Kid != "k1" || keys[0].Kty != "RSA" {
					t.Errorf("keys[0] = %+v", keys[0])
				}
				if keys[1].Kid != "k2" || keys[1].Kty != "EC" {
					t.Errorf("keys[1] = %+v", keys[1])
				}
			},
		},
		{
			name:      "nil input",
			input:     nil,
			wantCount: 0,
		},
		{
			name:      "invalid JSON",
			input:     json.RawMessage(`{invalid`),
			wantCount: 0,
		},
		{
			name:      "empty keys array",
			input:     json.RawMessage(`{"keys":[]}`),
			wantCount: 0,
		},
		{
			name:      "missing optional fields",
			input:     json.RawMessage(`{"keys":[{"kid":"k3","kty":"RSA"}]}`),
			wantCount: 1,
			check: func(t *testing.T, keys []JWKSKeyInfo) {
				if keys[0].Alg != "" {
					t.Errorf("Alg should be empty, got %q", keys[0].Alg)
				}
				if keys[0].Use != "" {
					t.Errorf("Use should be empty, got %q", keys[0].Use)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := ParseJWKSKeys(tt.input)
			if len(keys) != tt.wantCount {
				t.Fatalf("got %d keys, want %d", len(keys), tt.wantCount)
			}
			if tt.check != nil {
				tt.check(t, keys)
			}
		})
	}
}

func TestParseCertificateInfo(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	info := ParseCertificateInfo(cert)
	if info.SerialNumber != "42" {
		t.Errorf("SerialNumber = %q, want 42", info.SerialNumber)
	}
	if info.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
	// SHA-256 fingerprint: 32 bytes = 64 hex chars + 31 colons = 95 chars
	if strings.Count(info.Fingerprint, ":") != 31 {
		t.Errorf("Fingerprint should have 31 colons, got %d", strings.Count(info.Fingerprint, ":"))
	}
}

func TestFormatTimestamp(t *testing.T) {
	origLoc := DisplayLocation
	t.Cleanup(func() { DisplayLocation = origLoc })

	t.Run("nil DisplayLocation", func(t *testing.T) {
		DisplayLocation = nil
		result := FormatTimestamp("2024-01-15T10:00:00Z")
		if result != "2024-01-15T10:00:00Z" {
			t.Errorf("expected original string, got %q", result)
		}
	})

	t.Run("UTC DisplayLocation", func(t *testing.T) {
		DisplayLocation = time.UTC
		result := FormatTimestamp("2024-01-15T10:00:00Z")
		if result != "2024-01-15T10:00:00Z" {
			t.Errorf("expected original string, got %q", result)
		}
	})

	t.Run("non-UTC DisplayLocation (JST)", func(t *testing.T) {
		jst, err := time.LoadLocation("Asia/Tokyo")
		if err != nil {
			t.Skip("Asia/Tokyo timezone not available")
		}
		DisplayLocation = jst
		result := FormatTimestamp("2024-01-15T10:00:00Z")
		if !strings.Contains(result, "2024-01-15T10:00:00Z") {
			t.Errorf("result should contain original timestamp, got %q", result)
		}
		if !strings.Contains(result, "JST") {
			t.Errorf("result should contain JST, got %q", result)
		}
	})

	t.Run("invalid time string", func(t *testing.T) {
		jst, err := time.LoadLocation("Asia/Tokyo")
		if err != nil {
			t.Skip("Asia/Tokyo timezone not available")
		}
		DisplayLocation = jst
		result := FormatTimestamp("not-a-time")
		if result != "not-a-time" {
			t.Errorf("invalid time should return original, got %q", result)
		}
	})
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"integer float64", float64(42), "42"},
		{"non-integer float64", float64(3.14), "3.14"},
		{"json.Number", json.Number("12345"), "12345"},
		{"string", "hello", "hello"},
		{"bool", true, "true"},
		{"map", map[string]any{"active": true, "sub": "user1"}, `{"active":true,"sub":"user1"}`},
		{"slice", []any{"a", "b"}, `["a","b"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatValue(tt.input); got != tt.want {
				t.Errorf("FormatValue(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
