package protocol

import (
	"testing"
)

func TestParseURLParams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []KeyValue
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "full URL with query",
			input: "https://idp.example.com/auth?client_id=fedlens&response_type=code&scope=openid+profile",
			expected: []KeyValue{
				{Key: "client_id", Value: "fedlens"},
				{Key: "response_type", Value: "code"},
				{Key: "scope", Value: "openid profile"},
			},
		},
		{
			name:  "bare query string",
			input: "code=abc123&state=xyz",
			expected: []KeyValue{
				{Key: "code", Value: "abc123"},
				{Key: "state", Value: "xyz"},
			},
		},
		{
			name:  "URL-encoded values",
			input: "redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid+email",
			expected: []KeyValue{
				{Key: "redirect_uri", Value: "http://localhost:3000/callback"},
				{Key: "scope", Value: "openid email"},
			},
		},
		{
			name:  "string without equals parsed as key with empty value",
			input: "just-a-string-no-equals",
			expected: []KeyValue{
				{Key: "just-a-string-no-equals", Value: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseURLParams(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d params, got %d: %v", len(tt.expected), len(result), result)
			}
			for i, kv := range result {
				if kv.Key != tt.expected[i].Key || kv.Value != tt.expected[i].Value {
					t.Errorf("param[%d]: expected {%s: %s}, got {%s: %s}", i, tt.expected[i].Key, tt.expected[i].Value, kv.Key, kv.Value)
				}
			}
		})
	}
}
