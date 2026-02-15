package saml

import (
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// SAMLResultEntry holds data from a single SAML authentication event.
type SAMLResultEntry struct {
	Type            string    // "Login", "Re-auth: <name>", "Logout", "Error"
	Timestamp       time.Time
	Subject         string
	Attributes      map[string][]string
	AuthnRequestXML string
	SAMLResponseXML string
	SignatureInfos  []protocol.SAMLSignatureInfo
	ResponseInfo    *protocol.SAMLResponseInfo
	// Error fields
	ErrorCode   string // SAML StatusCode (e.g. "urn:oasis:names:tc:SAML:2.0:status:Requester")
	ErrorDetail string // Additional info
	// Logout fields
	LogoutRequestURL  string // SP-initiated: outgoing LogoutRequest URL
	LogoutRequestXML  string // IdP-initiated: incoming LogoutRequest XML
	LogoutResponseURL string // IdP-initiated: outgoing LogoutResponse URL (Redirect binding)
	LogoutResponseXML string // LogoutResponse XML (SP-initiated: received from IdP, IdP-initiated: sent to IdP)
}

// DebugSession holds all debug data for a SAML authentication session.
type DebugSession struct {
	Results []SAMLResultEntry // Reverse chronological (newest at [0])
}
