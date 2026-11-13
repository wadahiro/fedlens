package saml

import (
	"net/url"
	"strings"

	"github.com/beevik/etree"
	samlpkg "github.com/crewjam/saml"

	"github.com/wadahiro/fedlens/internal/protocol"
	"github.com/wadahiro/fedlens/internal/ui/templates/components"
)

// logoutParams are the values of the LogoutRequest the form can set. An empty
// value leaves the element or attribute out of the request, which is how a sloppy
// SP that omits them is emulated.
type logoutParams struct {
	NameID          string
	Format          string
	NameQualifier   string
	SPNameQualifier string
	SPProvidedID    string
	SessionIndex    string
}

const (
	fieldLogoutNameID          = "name_id"
	fieldLogoutFormat          = "name_id_format"
	fieldLogoutNameQualifier   = "name_qualifier"
	fieldLogoutSPNameQualifier = "sp_name_qualifier"
	fieldLogoutSPProvidedID    = "sp_provided_id"
	fieldLogoutSessionIndex    = "session_index"
)

// logoutDefaults are the values a correct SP sends.
//
// crewjam/saml fills the NameID with the SP's configured format and fixed
// qualifiers, which is only right when the IdP happened to issue that format.
// SAML 2.0 Core 3.7.1 has the request name the principal exactly as the assertion
// did, so when the received NameID is known its attributes are echoed as they
// came, and absent ones are left out rather than invented. Without it the
// library's own NameID is the default.
func logoutDefaults(sp *samlpkg.ServiceProvider, subject, sessionIndex string, received *protocol.SAMLNameID) logoutParams {
	p := logoutParams{NameID: subject, SessionIndex: sessionIndex}
	if received != nil {
		p.NameID = received.Value
		p.Format = received.Format
		p.NameQualifier = received.NameQualifier
		p.SPNameQualifier = received.SPNameQualifier
		p.SPProvidedID = received.SPProvidedID
		return p
	}
	if req, err := sp.MakeLogoutRequest("", subject); err == nil && req.NameID != nil {
		p.Format = req.NameID.Format
		p.NameQualifier = req.NameID.NameQualifier
		p.SPNameQualifier = req.NameID.SPNameQualifier
	}
	return p
}

// parseLogoutParams reads the submitted form. A field the form has takes the
// form's value, an empty one meaning "do not send it"; a field it lacks (a plain
// link) keeps the default.
func parseLogoutParams(q url.Values, d logoutParams) logoutParams {
	pick := func(name, def string) string {
		if q.Has(name) {
			return strings.TrimSpace(q.Get(name))
		}
		return def
	}
	return logoutParams{
		NameID:          pick(fieldLogoutNameID, d.NameID),
		Format:          pick(fieldLogoutFormat, d.Format),
		NameQualifier:   pick(fieldLogoutNameQualifier, d.NameQualifier),
		SPNameQualifier: pick(fieldLogoutSPNameQualifier, d.SPNameQualifier),
		SPProvidedID:    pick(fieldLogoutSPProvidedID, d.SPProvidedID),
		SessionIndex:    pick(fieldLogoutSessionIndex, d.SessionIndex),
	}
}

// logoutOptions builds the options of the Logout button. Its fields start with
// the values a correct SP would send, so the form shows the request as it will go.
func (h *Handler) logoutOptions(d logoutParams) *components.RequestOptions {
	return &components.RequestOptions{
		ID:     "logout",
		Label:  "Logout",
		Style:  "danger",
		Action: h.basePath + "/logout",
		Origin: "login",
		Fields: []components.RequestField{
			{Name: fieldLogoutNameID, Label: "NameID", Kind: "text", Value: d.NameID, Help: "Empty sends no NameID element."},
			{Name: fieldLogoutFormat, Label: "NameID Format", Kind: "text", Value: d.Format, Options: nameIDFormatSuggestions(), Help: "Empty leaves the attribute out."},
			{Name: fieldLogoutNameQualifier, Label: "NameQualifier", Kind: "text", Value: d.NameQualifier},
			{Name: fieldLogoutSPNameQualifier, Label: "SPNameQualifier", Kind: "text", Value: d.SPNameQualifier},
			{Name: fieldLogoutSPProvidedID, Label: "SPProvidedID", Kind: "text", Value: d.SPProvidedID},
			{Name: fieldLogoutSessionIndex, Label: "SessionIndex", Kind: "text", Value: d.SessionIndex, Help: "Empty sends no SessionIndex, which asks the IdP to end every session."},
		},
	}
}

// makeLogoutRequest builds the SP-initiated LogoutRequest from p.
func makeLogoutRequest(sp *samlpkg.ServiceProvider, destination string, p logoutParams) (*samlpkg.LogoutRequest, error) {
	req, err := sp.MakeLogoutRequest(destination, p.NameID)
	if err != nil {
		return nil, err
	}
	req.NameID = nil
	if p != (logoutParams{SessionIndex: p.SessionIndex}) {
		req.NameID = &samlpkg.NameID{
			Value:           p.NameID,
			Format:          p.Format,
			NameQualifier:   p.NameQualifier,
			SPNameQualifier: p.SPNameQualifier,
			SPProvidedID:    p.SPProvidedID,
		}
	}
	req.SessionIndex = nil
	if p.SessionIndex != "" {
		req.SessionIndex = &samlpkg.SessionIndex{Value: p.SessionIndex}
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
