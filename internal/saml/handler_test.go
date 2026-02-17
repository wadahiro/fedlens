package saml

import (
	"strings"
	"testing"
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

func TestToStringMap(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string][]string
		wantCount int
		check     func(t *testing.T, m map[string]string)
	}{
		{
			name: "multi-value attrs use first value",
			input: map[string][]string{
				"email": {"alice@example.com", "bob@example.com"},
				"role":  {"admin"},
			},
			wantCount: 2,
			check: func(t *testing.T, m map[string]string) {
				if m["email"] != "alice@example.com" {
					t.Errorf("email = %q, want alice@example.com", m["email"])
				}
				if m["role"] != "admin" {
					t.Errorf("role = %q, want admin", m["role"])
				}
			},
		},
		{
			name:      "empty input",
			input:     map[string][]string{},
			wantCount: 0,
		},
		{
			name: "empty value slice is skipped",
			input: map[string][]string{
				"empty": {},
				"ok":    {"value"},
			},
			wantCount: 1,
			check: func(t *testing.T, m map[string]string) {
				if _, ok := m["empty"]; ok {
					t.Error("empty key should not be present")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toStringMap(tt.input)
			if len(result) != tt.wantCount {
				t.Errorf("got %d entries, want %d", len(result), tt.wantCount)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestToStringMapFromSlice(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string][]string
		wantCount int
		check     func(t *testing.T, m map[string]string)
	}{
		{
			name: "multi-value attrs use first value",
			input: map[string][]string{
				"name":  {"Alice"},
				"roles": {"admin", "user"},
			},
			wantCount: 2,
			check: func(t *testing.T, m map[string]string) {
				if m["name"] != "Alice" {
					t.Errorf("name = %q, want Alice", m["name"])
				}
				if m["roles"] != "admin" {
					t.Errorf("roles = %q, want admin", m["roles"])
				}
			},
		},
		{
			name:      "empty input",
			input:     map[string][]string{},
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toStringMapFromSlice(tt.input)
			if len(result) != tt.wantCount {
				t.Errorf("got %d entries, want %d", len(result), tt.wantCount)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestParseToClaimRows_SAML(t *testing.T) {
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
			{Key: "SAMLRequest", Value: "base64data"},
			{Key: "RelayState", Value: "relay123"},
		}
		result := parseToClaimRows(params)
		if len(result) != 2 {
			t.Fatalf("got %d rows, want 2", len(result))
		}
		if result[0].Key != "SAMLRequest" {
			t.Errorf("rows[0].Key = %q, want SAMLRequest", result[0].Key)
		}
	})
}

func TestFormatTimestamp_SAML(t *testing.T) {
	origLoc := protocol.DisplayLocation
	t.Cleanup(func() { protocol.DisplayLocation = origLoc })

	t.Run("nil DisplayLocation uses UTC", func(t *testing.T) {
		protocol.DisplayLocation = nil
		now := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
		result := formatTimestamp(now)
		if !strings.Contains(result, "2024/01/15") {
			t.Errorf("result = %q, expected date format", result)
		}
		if !strings.Contains(result, "UTC") {
			t.Errorf("result = %q, expected UTC", result)
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
		if !strings.Contains(result, "19:00:00") {
			t.Errorf("result = %q, expected 19:00:00 (UTC+9)", result)
		}
	})
}

func TestFormatSidebarTimestamp_SAML(t *testing.T) {
	origLoc := protocol.DisplayLocation
	t.Cleanup(func() { protocol.DisplayLocation = origLoc })

	protocol.DisplayLocation = nil
	now := time.Date(2024, 3, 20, 14, 30, 45, 0, time.UTC)
	result := formatSidebarTimestamp(now)
	if result != "03/20 14:30:45" {
		t.Errorf("result = %q, want '03/20 14:30:45'", result)
	}
}
