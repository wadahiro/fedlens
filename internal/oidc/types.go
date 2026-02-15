package oidc

import (
	"encoding/json"
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// ResultEntry holds data from a single authentication event (Login, Refresh, Re-auth, Logout, Error).
type ResultEntry struct {
	Type               string    // "Login", "Refresh", "Re-auth: <name>", "Logout", "Error"
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
	// Logout fields
	LogoutRequestURL string // Full end_session_endpoint URL with params
	LogoutIDTokenRaw string // id_token_hint value sent in logout request
}

// Session holds auth state only (destroyed on logout).
type Session struct {
	IDTokenRaw      string
	RefreshTokenRaw string
}

// DebugSession holds all debug data (survives logout).
type DebugSession struct {
	Results []ResultEntry // Reverse chronological (newest at [0])
}
