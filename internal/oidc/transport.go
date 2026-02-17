package oidc

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// HTTPCapture holds captured HTTP response data.
type HTTPCapture struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// capturingTransport wraps an http.RoundTripper to capture response data.
type capturingTransport struct {
	base    http.RoundTripper
	mu      sync.Mutex
	capture *HTTPCapture
}

func newCapturingTransport(base http.RoundTripper) *capturingTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &capturingTransport{base: base}
}

func (t *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		t.mu.Lock()
		t.capture = nil
		t.mu.Unlock()
		return nil, err
	}

	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	t.mu.Lock()
	t.capture = &HTTPCapture{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       body,
	}
	t.mu.Unlock()

	return resp, nil
}

// LastCapture returns and clears the last captured response.
func (t *capturingTransport) LastCapture() *HTTPCapture {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.capture
	t.capture = nil
	return c
}
