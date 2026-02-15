package oidc

import (
	"encoding/json"
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// ResultEntry holds data from a single authentication event (Login, Refresh, Re-auth, Error).
type ResultEntry struct {
	Type               string    // "Login", "Refresh", "Re-auth: <name>", "Error"
	Timestamp          time.Time
	Claims             map[string]any
	AuthRequestURL     string          // Login/Re-auth/Error
	AuthResponseCode   string          // Login/Re-auth only
	AuthResponseRaw    string          // Login/Re-auth/Error
	TokenResponse      json.RawMessage
	IDTokenRaw         string
	AccessTokenRaw     string
	UserInfoResponse   json.RawMessage // Login/Re-auth only
	IDTokenSigInfo     *protocol.JWTSignatureInfo
	AccessTokenSigInfo *protocol.JWTSignatureInfo
	JWKSResponse       json.RawMessage // Login/Re-auth only
	// Error fields
	ErrorCode        string // OIDC error code (e.g. "access_denied")
	ErrorDescription string // Human-readable error description
	ErrorURI         string // Error URI
	ErrorDetail      string // Additional info (e.g. "Token exchange failed")
}

// Session holds all debug data for an OIDC authentication session.
type Session struct {
	Results         []ResultEntry // Reverse chronological (newest at [0])
	RefreshTokenRaw string        // Refresh token maintained at session level
}
