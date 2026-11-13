package saml

import (
	"strings"

	"github.com/beevik/etree"
	samlpkg "github.com/crewjam/saml"

	"github.com/wadahiro/fedlens/internal/protocol"
)

// makeLogoutRequest builds the SP-initiated LogoutRequest.
//
// crewjam/saml fills the NameID with the SP's configured format and fixed
// qualifiers, which is only right when the IdP happened to issue that format.
// SAML 2.0 Core 3.7.1 has the request name the principal exactly as the assertion
// did, so when the received NameID is known its attributes are echoed as they
// came, and absent ones are left out rather than invented. Without it the
// library's request is kept.
func makeLogoutRequest(sp *samlpkg.ServiceProvider, destination, fallbackNameID string, received *protocol.SAMLNameID, sessionIndex string) (*samlpkg.LogoutRequest, error) {
	value := fallbackNameID
	if received != nil {
		value = received.Value
	}
	req, err := sp.MakeLogoutRequest(destination, value)
	if err != nil {
		return nil, err
	}
	if received == nil && sessionIndex == "" {
		return req, nil
	}
	if received != nil {
		req.NameID = &samlpkg.NameID{
			Value:           received.Value,
			Format:          received.Format,
			NameQualifier:   received.NameQualifier,
			SPNameQualifier: received.SPNameQualifier,
			SPProvidedID:    received.SPProvidedID,
		}
	}
	if sessionIndex != "" {
		req.SessionIndex = &samlpkg.SessionIndex{Value: sessionIndex}
	}
	// The library signed the request it built; changing it invalidates that.
	if sp.SignatureMethod != "" {
		req.Signature = nil
		if err := sp.SignLogoutRequest(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// receivedNameID is the NameID of the most recent successful login in the debug
// session, which is the one the IdP's session for this user was opened with.
func receivedNameID(ds *DebugSession) *protocol.SAMLNameID {
	if ds == nil {
		return nil
	}
	for _, e := range ds.Results {
		if e.Type != "Login" && !strings.HasPrefix(e.Type, "Re-auth") {
			continue
		}
		if id, ok := protocol.ExtractSAMLNameID(e.readableResponseXML()); ok && id.Value != "" {
			return &id
		}
	}
	return nil
}

// logoutRequestXML serialises the request for the debug view.
func logoutRequestXML(req *samlpkg.LogoutRequest) string {
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	out, err := doc.WriteToString()
	if err != nil {
		return ""
	}
	return out
}
