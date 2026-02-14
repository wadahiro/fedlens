package oidc

import (
	"encoding/json"
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// Session holds all debug data for an OIDC authentication session.
type Session struct {
	Claims             map[string]any
	AuthRequestURL     string
	AuthResponseCode   string
	AuthResponseRaw    string
	TokenResponse      json.RawMessage
	IDTokenRaw         string
	AccessTokenRaw     string
	RefreshTokenRaw    string
	UserInfoResponse   json.RawMessage
	IDTokenSigInfo     *protocol.JWTSignatureInfo
	AccessTokenSigInfo *protocol.JWTSignatureInfo
	JWKSResponse       json.RawMessage
	RefreshResult      *RefreshResult
}

// RefreshResult holds data from a token refresh, kept separate from original session.
type RefreshResult struct {
	Timestamp          time.Time
	TokenResponse      json.RawMessage
	Claims             map[string]any
	IDTokenRaw         string
	AccessTokenRaw     string
	IDTokenSigInfo     *protocol.JWTSignatureInfo
	AccessTokenSigInfo *protocol.JWTSignatureInfo
}
