package protocol

import (
	"net/http"
	"testing"
)

func TestCleanGoErrorMessage(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "Get prefix",
			msg:  `Get "http://idp.example.com/token": dial tcp: lookup idp.example.com: no such host`,
			want: "dial tcp: lookup idp.example.com: no such host",
		},
		{
			name: "Post prefix",
			msg:  `Post "https://idp.example.com/token": context deadline exceeded`,
			want: "context deadline exceeded",
		},
		{
			name: "no prefix",
			msg:  "connection refused",
			want: "connection refused",
		},
		{
			name: "partial match no colon-space",
			msg:  `Get "http://example.com"`,
			want: `Get "http://example.com"`,
		},
		{
			name: "empty string",
			msg:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CleanGoErrorMessage(tt.msg)
			if got != tt.want {
				t.Errorf("CleanGoErrorMessage(%q) = %q, want %q", tt.msg, got, tt.want)
			}
		})
	}
}

func TestFormatHTTPStatusLine(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{200, "HTTP/1.1 200 OK"},
		{401, "HTTP/1.1 401 Unauthorized"},
		{500, "HTTP/1.1 500 Internal Server Error"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := FormatHTTPStatusLine(tt.code)
			if got != tt.want {
				t.Errorf("FormatHTTPStatusLine(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestFormatHTTPHeaders(t *testing.T) {
	t.Run("sorted output", func(t *testing.T) {
		headers := http.Header{
			"Content-Type":  {"application/json"},
			"Cache-Control": {"no-store"},
		}
		got := FormatHTTPHeaders(headers)
		want := "Cache-Control: no-store\nContent-Type: application/json"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("multiple values", func(t *testing.T) {
		headers := http.Header{
			"Set-Cookie": {"a=1", "b=2"},
		}
		got := FormatHTTPHeaders(headers)
		want := "Set-Cookie: a=1\nSet-Cookie: b=2"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("empty headers", func(t *testing.T) {
		got := FormatHTTPHeaders(http.Header{})
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("nil headers", func(t *testing.T) {
		got := FormatHTTPHeaders(nil)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestParseWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantCode string
		wantDesc string
		wantURI  string
	}{
		{
			name:     "error and description",
			value:    `Bearer error="invalid_token", error_description="expired"`,
			wantCode: "invalid_token",
			wantDesc: "expired",
		},
		{
			name:     "with error_uri",
			value:    `Bearer error="insufficient_scope", error_description="need admin", error_uri="https://example.com/help"`,
			wantCode: "insufficient_scope",
			wantDesc: "need admin",
			wantURI:  "https://example.com/help",
		},
		{
			name:     "realm only no error",
			value:    `Bearer realm="example"`,
			wantCode: "",
			wantDesc: "",
			wantURI:  "",
		},
		{
			name:     "empty string",
			value:    "",
			wantCode: "",
			wantDesc: "",
			wantURI:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, desc, uri := ParseWWWAuthenticate(tt.value)
			if code != tt.wantCode {
				t.Errorf("code = %q, want %q", code, tt.wantCode)
			}
			if desc != tt.wantDesc {
				t.Errorf("desc = %q, want %q", desc, tt.wantDesc)
			}
			if uri != tt.wantURI {
				t.Errorf("uri = %q, want %q", uri, tt.wantURI)
			}
		})
	}
}

func TestDetectContentLanguage(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        string
	}{
		{"json", "application/json", "json"},
		{"json with charset", "application/json; charset=utf-8", "json"},
		{"json suffix", "application/hal+json", "json"},
		{"xml", "application/xml", "markup"},
		{"text xml", "text/xml", "markup"},
		{"xml suffix", "application/saml+xml", "markup"},
		{"html", "text/html", "markup"},
		{"plain text", "text/plain", ""},
		{"octet-stream", "application/octet-stream", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectContentLanguage(tt.contentType)
			if got != tt.want {
				t.Errorf("DetectContentLanguage(%q) = %q, want %q", tt.contentType, got, tt.want)
			}
		})
	}
}
