package saml

import (
	"time"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// SAMLResultEntry holds data from a single SAML authentication event.
type SAMLResultEntry struct {
	Type            string // "Login", "Re-auth: <name>", "Logout", "Error"
	Timestamp       time.Time
	Subject         string
	Attributes      map[string][]string
	AuthnRequestXML string
	SAMLResponseXML string // as received
	// DecryptedResponseXML is the response with encrypted elements decrypted; empty when nothing was encrypted.
	DecryptedResponseXML string
	SignatureInfos       []protocol.SAMLSignatureInfo
	ResponseInfo         *protocol.SAMLResponseInfo
	// RelayState fields
	RelayStateSent     string // outgoing RelayState (sent with AuthnRequest)
	RelayStateReceived string // incoming RelayState (received at ACS)
	SAMLResponseBase64 string // raw base64-encoded SAMLResponse from ACS POST
	AuthnRequestURL    string // full redirect URL (HTTP-Redirect binding only)
	// Error fields
	ErrorCode   string // SAML StatusCode (e.g. "urn:oasis:names:tc:SAML:2.0:status:Requester")
	ErrorDetail string // Additional info
	// Logout fields
	LogoutRequestURL     string // SP-initiated: outgoing LogoutRequest URL
	LogoutRequestXML     string // IdP-initiated: incoming LogoutRequest XML
	LogoutRequestSentXML string // SP-initiated: the LogoutRequest XML that was sent
	LogoutResponseURL    string // IdP-initiated: outgoing LogoutResponse URL (Redirect binding)
	LogoutResponseXML    string // LogoutResponse XML (SP-initiated: received from IdP, IdP-initiated: sent to IdP)
}

// DebugSession holds all debug data for a SAML authentication session.
type DebugSession struct {
	Results []SAMLResultEntry // Reverse chronological (newest at [0])
}

// readableResponseXML is the response the views read the NameID, attributes and
// signatures from: the decrypted form when there is one, as received otherwise.
func (e SAMLResultEntry) readableResponseXML() string {
	if e.DecryptedResponseXML != "" {
		return e.DecryptedResponseXML
	}
	return e.SAMLResponseXML
}
