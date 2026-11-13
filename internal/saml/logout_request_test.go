package saml

import (
	"testing"

	samlpkg "github.com/crewjam/saml"

	"github.com/wadahiro/fedlens/internal/protocol"
)

func testSP() *samlpkg.ServiceProvider {
	return &samlpkg.ServiceProvider{
		EntityID:          "https://sp.example/metadata",
		AuthnNameIDFormat: samlpkg.EmailAddressNameIDFormat,
		IDPMetadata:       &samlpkg.EntityDescriptor{EntityID: "https://idp.example/metadata"},
	}
}

func TestMakeLogoutRequestEchoesReceivedNameID(t *testing.T) {
	got := &protocol.SAMLNameID{Value: "p-1", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", SPNameQualifier: "https://sp.example/metadata"}
	req, err := makeLogoutRequest(testSP(), "https://idp.example/slo", "ignored", got, "idx-9")
	if err != nil {
		t.Fatal(err)
	}
	n := req.NameID
	if n.Value != "p-1" || n.Format != got.Format || n.SPNameQualifier != got.SPNameQualifier {
		t.Errorf("NameID = %+v", n)
	}
	if n.NameQualifier != "" {
		t.Errorf("NameQualifier %q was not in the assertion and must not be invented", n.NameQualifier)
	}
	if req.SessionIndex == nil || req.SessionIndex.Value != "idx-9" {
		t.Errorf("SessionIndex = %+v", req.SessionIndex)
	}
}

func TestMakeLogoutRequestWithoutReceivedNameIDKeepsLibraryRequest(t *testing.T) {
	req, err := makeLogoutRequest(testSP(), "https://idp.example/slo", "alice", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if req.NameID.Value != "alice" || req.NameID.Format != string(samlpkg.EmailAddressNameIDFormat) || req.SessionIndex != nil {
		t.Errorf("request = %+v / %+v", req.NameID, req.SessionIndex)
	}
}

func TestReceivedNameIDTakesLatestLogin(t *testing.T) {
	resp := func(v string) string {
		return `<Response><Assertion><Subject><NameID Format="f">` + v + `</NameID></Subject></Assertion></Response>`
	}
	ds := &DebugSession{Results: []SAMLResultEntry{
		{Type: "Logout (SP)"},
		{Type: "Re-auth: step", SAMLResponseXML: resp("new")},
		{Type: "Login", SAMLResponseXML: resp("old")},
	}}
	if id := receivedNameID(ds); id == nil || id.Value != "new" {
		t.Errorf("got %+v", id)
	}
	if receivedNameID(&DebugSession{}) != nil || receivedNameID(nil) != nil {
		t.Error("no login must give no NameID")
	}
}
