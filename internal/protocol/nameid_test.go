package protocol

import "testing"

func TestExtractSAMLNameID(t *testing.T) {
	xml := `<Response><Assertion><Subject><NameID Format="f" NameQualifier="idp" SPNameQualifier="sp" SPProvidedID="p">u</NameID></Subject></Assertion></Response>`
	got, ok := ExtractSAMLNameID(xml)
	want := SAMLNameID{Value: "u", Format: "f", NameQualifier: "idp", SPNameQualifier: "sp", SPProvidedID: "p"}
	if !ok || got != want {
		t.Errorf("got %+v ok=%v", got, ok)
	}
	if _, ok := ExtractSAMLNameID(`<Response><Assertion><Subject><EncryptedID/></Subject></Assertion></Response>`); ok {
		t.Error("EncryptedID must not report a NameID")
	}
}

func TestExtractSAMLNameIDPolicy(t *testing.T) {
	p := ExtractSAMLNameIDPolicy(`<AuthnRequest><NameIDPolicy Format="f" AllowCreate="true"/></AuthnRequest>`)
	if !p.Present || p.Format != "f" || p.AllowCreate != "true" {
		t.Errorf("got %+v", p)
	}
	if ExtractSAMLNameIDPolicy(`<AuthnRequest/>`).Present {
		t.Error("a request without NameIDPolicy must not be Present")
	}
}
