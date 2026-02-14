package saml

import (
	"github.com/wadahiro/fedlens/internal/protocol"
)

// DebugSession holds all debug data for a SAML authentication session.
type DebugSession struct {
	AuthnRequestXML string
	SAMLResponseXML string
	SignatureInfos  []protocol.SAMLSignatureInfo
	ResponseInfo    *protocol.SAMLResponseInfo
}
