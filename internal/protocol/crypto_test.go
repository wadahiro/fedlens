package protocol

import (
	"encoding/json"
	"testing"
)

func TestRandomHex(t *testing.T) {
	hex, err := RandomHex(16)
	if err != nil {
		t.Fatalf("RandomHex failed: %v", err)
	}
	if len(hex) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("RandomHex(16) length = %d, want 32", len(hex))
	}

	// Ensure two calls produce different values
	hex2, _ := RandomHex(16)
	if hex == hex2 {
		t.Error("RandomHex produced identical values")
	}
}

func TestHTMLEscape(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{`"hello" & 'world'`, "&quot;hello&quot; &amp; &#39;world&#39;"},
		{"normal text", "normal text"},
	}
	for _, tt := range tests {
		got := HTMLEscape(tt.input)
		if got != tt.want {
			t.Errorf("HTMLEscape(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]int{"c": 3, "a": 1, "b": 2}
	keys := SortedKeys(m)
	if len(keys) != 3 || keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Errorf("SortedKeys = %v, want [a b c]", keys)
	}
}

func TestPrettyJSON(t *testing.T) {
	raw := json.RawMessage(`{"b":2,"a":1}`)
	result := PrettyJSON(raw)
	if result == "" {
		t.Error("PrettyJSON returned empty string")
	}
	// Should contain indentation
	if !containsStr(result, "\n") {
		t.Error("PrettyJSON should produce indented output")
	}
}

func TestFormatClaimValue(t *testing.T) {
	// Non-timestamp claim
	if got := FormatClaimValue("sub", "user1"); got != "user1" {
		t.Errorf("FormatClaimValue(sub, user1) = %q", got)
	}

	// Timestamp claim
	got := FormatClaimValue("iat", float64(1700000000))
	if got == "1700000000" {
		t.Error("FormatClaimValue should append human-readable timestamp for iat")
	}
}
