package oidc

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockRoundTripper is a test helper that returns a fixed response or error.
type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return m.resp, m.err
}

func TestCapturingTransport_Success(t *testing.T) {
	body := `{"access_token":"abc"}`
	mock := &mockRoundTripper{
		resp: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": {"application/json"},
			},
			Body: io.NopCloser(strings.NewReader(body)),
		},
	}

	ct := newCapturingTransport(mock)
	req, _ := http.NewRequest("POST", "https://example.com/token", nil)
	resp, err := ct.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Response body should still be readable
	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != body {
		t.Errorf("response body = %q, want %q", string(respBody), body)
	}

	capture := ct.LastCapture()
	if capture == nil {
		t.Fatal("expected capture, got nil")
	}
	if capture.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", capture.StatusCode)
	}
	if capture.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", capture.Headers.Get("Content-Type"))
	}
	if string(capture.Body) != body {
		t.Errorf("Body = %q, want %q", string(capture.Body), body)
	}

	// LastCapture should clear
	if ct.LastCapture() != nil {
		t.Error("expected nil after second LastCapture call")
	}
}

func TestCapturingTransport_ConnectionError(t *testing.T) {
	mock := &mockRoundTripper{
		err: errors.New("dial tcp: connection refused"),
	}

	ct := newCapturingTransport(mock)
	req, _ := http.NewRequest("GET", "https://example.com/userinfo", nil)
	_, err := ct.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	capture := ct.LastCapture()
	if capture != nil {
		t.Errorf("expected nil capture on connection error, got %+v", capture)
	}
}

func TestCapturingTransport_NilBase(t *testing.T) {
	ct := newCapturingTransport(nil)
	if ct.base == nil {
		t.Error("base should default to http.DefaultTransport")
	}
}
