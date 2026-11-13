package saml

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	samlpkg "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/wadahiro/fedlens/internal/protocol"
)

func testSP() *samlpkg.ServiceProvider {
	return &samlpkg.ServiceProvider{
		EntityID:          "https://sp.example/metadata",
		AuthnNameIDFormat: samlpkg.EmailAddressNameIDFormat,
		IDPMetadata:       &samlpkg.EntityDescriptor{EntityID: "https://idp.example/metadata"},
	}
}

func TestLogoutDefaultsEchoReceivedNameID(t *testing.T) {
	got := &protocol.SAMLNameID{Value: "p-1", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", SPNameQualifier: "https://sp.example/metadata"}
	d := logoutDefaults(testSP(), "ignored", "idx-9", got)
	want := logoutParams{NameID: "p-1", Format: got.Format, SPNameQualifier: got.SPNameQualifier, SessionIndex: "idx-9"}
	if d != want {
		t.Errorf("defaults = %+v, want %+v (NameQualifier was not in the assertion and must not be invented)", d, want)
	}
}

func TestLogoutDefaultsWithoutReceivedNameIDKeepLibraryNameID(t *testing.T) {
	d := logoutDefaults(testSP(), "alice", "", nil)
	if d.NameID != "alice" || d.Format != string(samlpkg.EmailAddressNameIDFormat) || d.SessionIndex != "" {
		t.Errorf("defaults = %+v", d)
	}
}

func TestParseLogoutParamsFormWinsAndEmptyOmits(t *testing.T) {
	d := logoutParams{NameID: "p-1", Format: "persistent", SPNameQualifier: "sp", SessionIndex: "idx"}
	// A plain link carries no fields: the defaults stand.
	if got := parseLogoutParams(url.Values{}, d); got != d {
		t.Errorf("plain link = %+v", got)
	}
	q := url.Values{"name_id": {"bob"}, "name_id_format": {""}, "sp_name_qualifier": {"sp"}, "session_index": {""}}
	got := parseLogoutParams(q, d)
	want := logoutParams{NameID: "bob", SPNameQualifier: "sp"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestMakeLogoutRequestOmitsEmptyValues(t *testing.T) {
	req, err := makeLogoutRequest(testSP(), "https://idp.example/slo", logoutParams{NameID: "p-1", Format: "f", SessionIndex: "idx"})
	if err != nil {
		t.Fatal(err)
	}
	if n := req.NameID; n == nil || n.Value != "p-1" || n.Format != "f" || n.NameQualifier != "" || n.SPNameQualifier != "" {
		t.Errorf("NameID = %+v", n)
	}
	if req.SessionIndex == nil || req.SessionIndex.Value != "idx" {
		t.Errorf("SessionIndex = %+v", req.SessionIndex)
	}

	bare, err := makeLogoutRequest(testSP(), "https://idp.example/slo", logoutParams{})
	if err != nil {
		t.Fatal(err)
	}
	if bare.NameID != nil || bare.SessionIndex != nil {
		t.Errorf("an empty form must send neither: %+v / %+v", bare.NameID, bare.SessionIndex)
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

func signingSP(t *testing.T) (*samlpkg.ServiceProvider, *x509.Certificate) {
	t.Helper()
	key, cert := testKey(t)
	sp := testSP()
	sp.Key = key
	sp.Certificate = cert
	sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	return sp, cert
}

// validSignature reports whether the request's signature verifies against cert for
// the content it now has.
func validSignature(t *testing.T, req *samlpkg.LogoutRequest, cert *x509.Certificate) bool {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	parsed := etree.NewDocument()
	if err := parsed.ReadFromString(s); err != nil {
		t.Fatal(err)
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	_, err = ctx.Validate(parsed.Root())
	return err == nil
}

func TestMakeLogoutRequestResignsAfterOverride(t *testing.T) {
	sp, cert := signingSP(t)

	// The library's own request is signed, and stops verifying as soon as it is changed:
	// that is why makeLogoutRequest has to sign again.
	stale, err := sp.MakeLogoutRequest("https://idp.example/slo", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !validSignature(t, stale, cert) {
		t.Fatal("the library's request must verify before it is changed")
	}
	stale.NameID.Value = "bob"
	if validSignature(t, stale, cert) {
		t.Fatal("a changed request must not verify under the old signature")
	}

	req, err := makeLogoutRequest(sp, "https://idp.example/slo", logoutParams{NameID: "bob", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", SessionIndex: "idx"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Signature == nil {
		t.Fatal("the request must carry a signature")
	}
	if !validSignature(t, req, cert) {
		t.Error("the signature must verify for the overridden content")
	}
	if n := req.NameID; n == nil || n.Value != "bob" || req.SessionIndex == nil {
		t.Errorf("the overrides were lost: %+v / %+v", n, req.SessionIndex)
	}
}

func TestMakeLogoutRequestResignsWhenElementsAreOmitted(t *testing.T) {
	sp, cert := signingSP(t)
	req, err := makeLogoutRequest(sp, "https://idp.example/slo", logoutParams{})
	if err != nil {
		t.Fatal(err)
	}
	if req.NameID != nil || req.SessionIndex != nil {
		t.Fatalf("an empty form sends neither: %+v / %+v", req.NameID, req.SessionIndex)
	}
	if !validSignature(t, req, cert) {
		t.Error("the signature must verify for the request with the elements removed")
	}
}

func TestMakeLogoutRequestIsUnsignedWithoutSignatureMethod(t *testing.T) {
	req, err := makeLogoutRequest(testSP(), "https://idp.example/slo", logoutParams{NameID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Signature != nil {
		t.Error("signing is off, so the request must not be signed")
	}
}
