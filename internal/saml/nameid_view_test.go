package saml

import (
	"fmt"
	"testing"
)

const (
	reqWithFormat = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="sp"/></samlp:AuthnRequest>`
	reqNoPolicy   = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`
	respWith      = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID Format="%s" SPNameQualifier="sp">u1</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`
)

func rowMap(t *testing.T, req, resp string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, r := range nameIDRows(req, resp) {
		m[r.Key] = r.Value
	}
	return m
}

func TestNameIDRowsMatchesRequestedFormat(t *testing.T) {
	resp := fmt.Sprintf(respWith, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	m := rowMap(t, reqWithFormat, resp)
	if m["NameID"] != "u1" || m["Result"] != "matches the requested Format" || m["SPNameQualifier result"] != "matches the requested SPNameQualifier" {
		t.Errorf("rows = %v", m)
	}
}

func TestNameIDRowsReportsDifferingFormat(t *testing.T) {
	resp := fmt.Sprintf(respWith, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
	m := rowMap(t, reqWithFormat, resp)
	if m["Result"] != "differs from the requested Format" {
		t.Errorf("rows = %v", m)
	}
}

func TestNameIDRowsWithoutPolicy(t *testing.T) {
	resp := fmt.Sprintf(respWith, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
	m := rowMap(t, reqNoPolicy, resp)
	if _, ok := m["Result"]; ok || m["Requested"] == "" {
		t.Errorf("rows = %v", m)
	}
}

func TestNameIDRowsEmptyWithoutNameID(t *testing.T) {
	if rows := nameIDRows(reqWithFormat, `<Response/>`); rows != nil {
		t.Errorf("rows = %v", rows)
	}
}
