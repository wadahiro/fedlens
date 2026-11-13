package saml

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
	samlpkg "github.com/crewjam/saml"

	"github.com/wadahiro/fedlens/internal/config"
)

func boolPtr(b bool) *bool { return &b }

// newRequest mimics what MakeAuthenticationRequest hands back for a default SP.
func newRequest() *samlpkg.AuthnRequest {
	format := string(samlpkg.TransientNameIDFormat)
	return &samlpkg.AuthnRequest{
		NameIDPolicy: &samlpkg.NameIDPolicy{Format: &format, AllowCreate: boolPtr(true)},
	}
}

func requestXML(t *testing.T, req *samlpkg.AuthnRequest) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApplyAuthRequestEmptyOptionsKeepLibraryDefaults(t *testing.T) {
	req := newRequest()
	applyAuthRequest(req, config.SAMLAuthRequestConfig{})

	p := req.NameIDPolicy
	if p == nil || *p.Format != string(samlpkg.TransientNameIDFormat) || !*p.AllowCreate {
		t.Errorf("default NameIDPolicy changed: %+v", p)
	}
	if req.Subject != nil || req.ForceAuthn != nil || req.IsPassive != nil || req.RequestedAuthnContext != nil {
		t.Errorf("unset options must not add anything: %+v", req)
	}
}

func TestApplyAuthRequestNameIDPolicy(t *testing.T) {
	req := newRequest()
	applyAuthRequest(req, config.SAMLAuthRequestConfig{
		NameIDFormat:    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		AllowCreate:     boolPtr(false),
		SPNameQualifier: "https://sp.example.com",
	})

	p := req.NameIDPolicy
	if *p.Format != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
		t.Errorf("Format = %q", *p.Format)
	}
	if p.AllowCreate == nil || *p.AllowCreate {
		t.Errorf("AllowCreate = %v, want explicit false", p.AllowCreate)
	}
	if p.SPNameQualifier == nil || *p.SPNameQualifier != "https://sp.example.com" {
		t.Errorf("SPNameQualifier = %v", p.SPNameQualifier)
	}
	xml := requestXML(t, req)
	for _, want := range []string{`AllowCreate="false"`, `SPNameQualifier="https://sp.example.com"`} {
		if !strings.Contains(xml, want) {
			t.Errorf("XML lacks %s:\n%s", want, xml)
		}
	}
}

func TestApplyAuthRequestOmitNameIDPolicy(t *testing.T) {
	req := newRequest()
	applyAuthRequest(req, config.SAMLAuthRequestConfig{
		OmitNameIDPolicy: boolPtr(true),
		NameIDFormat:     "urn:ignored",
	})

	if req.NameIDPolicy != nil {
		t.Errorf("NameIDPolicy = %+v, want removed", req.NameIDPolicy)
	}
	if strings.Contains(requestXML(t, req), "NameIDPolicy") {
		t.Error("serialized request still contains NameIDPolicy")
	}
}

func TestApplyAuthRequestOmitFalseKeepsPolicy(t *testing.T) {
	req := newRequest()
	applyAuthRequest(req, config.SAMLAuthRequestConfig{OmitNameIDPolicy: boolPtr(false)})
	if req.NameIDPolicy == nil {
		t.Error("omit=false must keep the policy")
	}
}

func TestApplyAuthRequestSubjectHint(t *testing.T) {
	req := newRequest()
	applyAuthRequest(req, config.SAMLAuthRequestConfig{
		SubjectNameID:       "alice@example.com",
		SubjectNameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	})

	xml := requestXML(t, req)
	for _, want := range []string{"<saml:Subject>", "alice@example.com", `Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"`} {
		if !strings.Contains(xml, want) {
			t.Errorf("XML lacks %s:\n%s", want, xml)
		}
	}
}

func TestApplyAuthRequestFlagsAndContext(t *testing.T) {
	req := newRequest()
	applyAuthRequest(req, config.SAMLAuthRequestConfig{
		ForceAuthn:           boolPtr(true),
		IsPassive:            boolPtr(false),
		AuthnContextClassRef: "urn:acr:mfa",
	})

	if req.ForceAuthn == nil || !*req.ForceAuthn {
		t.Errorf("ForceAuthn = %v", req.ForceAuthn)
	}
	if req.IsPassive == nil || *req.IsPassive {
		t.Errorf("IsPassive = %v, want explicit false", req.IsPassive)
	}
	if rac := req.RequestedAuthnContext; rac == nil || rac.AuthnContextClassRef != "urn:acr:mfa" || rac.Comparison != "exact" {
		t.Errorf("RequestedAuthnContext = %+v", rac)
	}
}

func TestOmitSettingsTakesOutWhatTheLibraryFillsIn(t *testing.T) {
	req := newRequest() // Format transient and AllowCreate true, as the library generates it

	omitSettings(req, []string{"name_id_format", "allow_create"})

	if req.NameIDPolicy.Format != nil || req.NameIDPolicy.AllowCreate != nil {
		t.Errorf("NameIDPolicy = %+v, want the library's defaults taken out", req.NameIDPolicy)
	}
	xml := requestXML(t, req)
	if strings.Contains(xml, "AllowCreate") || strings.Contains(xml, `Format="`+string(samlpkg.TransientNameIDFormat)+`"`) {
		t.Errorf("the serialized request still carries them:\n%s", xml)
	}
}

func TestOmitSettingsLeavesWhatWasNotEmptied(t *testing.T) {
	req := newRequest()

	omitSettings(req, []string{"force_authn"}) // not a NameIDPolicy setting: nothing to take out

	if req.NameIDPolicy.Format == nil || req.NameIDPolicy.AllowCreate == nil {
		t.Error("only the emptied settings may be taken out")
	}
	omitSettings(&samlpkg.AuthnRequest{}, []string{"allow_create"}) // no policy at all: must not panic
}

func TestApplyAuthRequestAssertionConsumerServiceURL(t *testing.T) {
	req := newRequest()
	req.AssertionConsumerServiceURL = "http://localhost:3000/saml/acs" // what the library fills in

	applyAuthRequest(req, config.SAMLAuthRequestConfig{AssertionConsumerServiceURL: "https://evil.example/acs"})

	if req.AssertionConsumerServiceURL != "https://evil.example/acs" {
		t.Errorf("AssertionConsumerServiceURL = %q", req.AssertionConsumerServiceURL)
	}
	if !strings.Contains(requestXML(t, req), `AssertionConsumerServiceURL="https://evil.example/acs"`) {
		t.Error("the URL must reach the XML")
	}
}

func TestApplyAuthRequestKeepsLibraryACSURLWhenUnset(t *testing.T) {
	req := newRequest()
	req.AssertionConsumerServiceURL = "http://localhost:3000/saml/acs"
	applyAuthRequest(req, config.SAMLAuthRequestConfig{})
	if req.AssertionConsumerServiceURL != "http://localhost:3000/saml/acs" {
		t.Errorf("AssertionConsumerServiceURL = %q, want the library's", req.AssertionConsumerServiceURL)
	}
}

func TestOmitSettingsTakesOutTheACSURL(t *testing.T) {
	req := newRequest()
	req.AssertionConsumerServiceURL = "http://localhost:3000/saml/acs"
	omitSettings(req, []string{"assertion_consumer_service_url"})
	if req.AssertionConsumerServiceURL != "" || strings.Contains(requestXML(t, req), "AssertionConsumerServiceURL") {
		t.Errorf("an emptied field must leave the attribute out: %q", req.AssertionConsumerServiceURL)
	}

	// With no NameIDPolicy there is nothing to take out of it, and the ACS URL still goes.
	bare := &samlpkg.AuthnRequest{AssertionConsumerServiceURL: "x"}
	omitSettings(bare, []string{"assertion_consumer_service_url", "name_id_format"})
	if bare.AssertionConsumerServiceURL != "" {
		t.Error("the ACS URL must be removed even when the request has no NameIDPolicy")
	}
}
