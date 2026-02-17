package protocol

import (
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func TestFormatXML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, result string)
	}{
		{
			name:  "empty string",
			input: "",
			check: func(t *testing.T, result string) {
				if result != "" {
					t.Errorf("expected empty string, got %q", result)
				}
			},
		},
		{
			name:  "valid XML gets formatted",
			input: `<root><child>text</child></root>`,
			check: func(t *testing.T, result string) {
				if !strings.Contains(result, "<root>") {
					t.Errorf("result should contain <root>, got %q", result)
				}
				if !strings.Contains(result, "text") {
					t.Errorf("result should contain text, got %q", result)
				}
			},
		},
		{
			name:  "re-format produces valid XML",
			input: `<root><child>text</child></root>`,
			check: func(t *testing.T, result string) {
				result2 := FormatXML(result)
				// Both should contain the same elements
				if !strings.Contains(result2, "<root>") || !strings.Contains(result2, "text") {
					t.Errorf("re-formatted XML lost content: %q", result2)
				}
			},
		},
		{
			name:  "XML with namespaces",
			input: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="Success"/></samlp:Status></samlp:Response>`,
			check: func(t *testing.T, result string) {
				// Go's encoding/xml normalizes namespace prefixes; just verify content is preserved
				if !strings.Contains(result, "Response") {
					t.Errorf("result should contain Response, got %q", result)
				}
				if !strings.Contains(result, "Success") {
					t.Errorf("result should contain Success, got %q", result)
				}
			},
		},
		{
			name:  "XML with attributes",
			input: `<root id="123" name="test"/>`,
			check: func(t *testing.T, result string) {
				if !strings.Contains(result, `id="123"`) {
					t.Errorf("result should contain id attribute, got %q", result)
				}
			},
		},
		{
			name:  "partially invalid XML returns fallback",
			input: `not xml at all <><>`,
			check: func(t *testing.T, result string) {
				// FormatXML may partially parse or return the original;
				// at minimum, it should not panic and should return non-empty
				if result == "" {
					t.Error("result should not be empty")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatXML(tt.input)
			tt.check(t, result)
		})
	}
}

func TestShortenAlgorithmURI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "rsa-sha256"},
		{"http://www.w3.org/2000/09/xmldsig#sha1", "sha1"},
		{"no-fragment-here", "no-fragment-here"},
		{"", ""},
		{"#just-fragment", "just-fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ShortenAlgorithmURI(tt.input); got != tt.want {
				t.Errorf("ShortenAlgorithmURI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

const samlResponseWithResponseSig = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </Reference>
    </SignedInfo>
    <KeyInfo>
      <KeyName>my-key</KeyName>
    </KeyInfo>
  </Signature>
</samlp:Response>`

const samlResponseWithAssertionSig = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp2">
  <Assertion ID="_assert1">
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <Reference>
          <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        </Reference>
      </SignedInfo>
    </Signature>
  </Assertion>
</samlp:Response>`

const samlResponseWithBothSigs = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp3">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </Reference>
    </SignedInfo>
  </Signature>
  <Assertion ID="_assert2">
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
        <Reference>
          <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        </Reference>
      </SignedInfo>
    </Signature>
  </Assertion>
</samlp:Response>`

const samlResponseNoSig = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp4">
  <Assertion ID="_assert3">
    <Subject>
      <NameID>user@example.com</NameID>
    </Subject>
  </Assertion>
</samlp:Response>`

func TestExtractSAMLSignatureInfos(t *testing.T) {
	tests := []struct {
		name      string
		xml       string
		wantCount int
		checks    func(t *testing.T, infos []SAMLSignatureInfo)
	}{
		{
			name:      "response-level signature",
			xml:       samlResponseWithResponseSig,
			wantCount: 1,
			checks: func(t *testing.T, infos []SAMLSignatureInfo) {
				if infos[0].Target != "Response" {
					t.Errorf("Target = %q, want Response", infos[0].Target)
				}
				if infos[0].AlgorithmShort != "rsa-sha256" {
					t.Errorf("AlgorithmShort = %q, want rsa-sha256", infos[0].AlgorithmShort)
				}
				if infos[0].KeyName != "my-key" {
					t.Errorf("KeyName = %q, want my-key", infos[0].KeyName)
				}
			},
		},
		{
			name:      "assertion-level signature",
			xml:       samlResponseWithAssertionSig,
			wantCount: 1,
			checks: func(t *testing.T, infos []SAMLSignatureInfo) {
				if infos[0].Target != "Assertion" {
					t.Errorf("Target = %q, want Assertion", infos[0].Target)
				}
			},
		},
		{
			name:      "both response and assertion signatures",
			xml:       samlResponseWithBothSigs,
			wantCount: 2,
			checks: func(t *testing.T, infos []SAMLSignatureInfo) {
				if infos[0].Target != "Response" {
					t.Errorf("infos[0].Target = %q, want Response", infos[0].Target)
				}
				if infos[1].Target != "Assertion" {
					t.Errorf("infos[1].Target = %q, want Assertion", infos[1].Target)
				}
				if infos[1].AlgorithmShort != "ecdsa-sha256" {
					t.Errorf("infos[1].AlgorithmShort = %q, want ecdsa-sha256", infos[1].AlgorithmShort)
				}
			},
		},
		{
			name:      "no signature",
			xml:       samlResponseNoSig,
			wantCount: 0,
			checks:    nil,
		},
		{
			name:      "invalid XML",
			xml:       "not xml",
			wantCount: 0,
			checks:    nil,
		},
		{
			name:      "empty string",
			xml:       "",
			wantCount: 0,
			checks:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infos := ExtractSAMLSignatureInfos(tt.xml)
			if len(infos) != tt.wantCount {
				t.Fatalf("got %d infos, want %d", len(infos), tt.wantCount)
			}
			if tt.checks != nil {
				tt.checks(t, infos)
			}
		})
	}
}

const samlResponseFull = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_resp_full" IssueInstant="2024-01-15T10:00:00Z" InResponseTo="_req1" Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <Assertion ID="_assert_full">
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</NameID>
      <SubjectConfirmation>
        <SubjectConfirmationData Recipient="https://sp.example.com/acs" NotOnOrAfter="2024-01-15T10:05:00Z"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2024-01-15T09:55:00Z" NotOnOrAfter="2024-01-15T10:05:00Z">
      <AudienceRestriction>
        <Audience>https://sp.example.com</Audience>
      </AudienceRestriction>
    </Conditions>
    <AuthnStatement AuthnInstant="2024-01-15T10:00:00Z" SessionIndex="_session1">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>`

func TestExtractSAMLResponseInfo(t *testing.T) {
	// Save and restore DisplayLocation
	origLoc := DisplayLocation
	DisplayLocation = nil
	t.Cleanup(func() { DisplayLocation = origLoc })

	tests := []struct {
		name       string
		xml        string
		wantNil    bool
		wantGroups int
		checks     func(t *testing.T, info *SAMLResponseInfo)
	}{
		{
			name:       "full response with 4 groups",
			xml:        samlResponseFull,
			wantGroups: 4,
			checks: func(t *testing.T, info *SAMLResponseInfo) {
				// Response group
				if info.Groups[0].Name != "Response" {
					t.Errorf("Groups[0].Name = %q, want Response", info.Groups[0].Name)
				}
				// Check Issuer row exists
				found := false
				for _, row := range info.Groups[0].Rows {
					if row.Label == "Issuer" && row.Value == "https://idp.example.com" {
						found = true
					}
				}
				if !found {
					t.Error("Response group should contain Issuer row")
				}

				// Subject group
				if info.Groups[1].Name != "Subject" {
					t.Errorf("Groups[1].Name = %q, want Subject", info.Groups[1].Name)
				}

				// Conditions group with AudienceRestriction
				if info.Groups[2].Name != "Conditions" {
					t.Errorf("Groups[2].Name = %q, want Conditions", info.Groups[2].Name)
				}
				foundAudience := false
				for _, row := range info.Groups[2].Rows {
					if row.Label == "Audience" && row.Value == "https://sp.example.com" {
						foundAudience = true
					}
				}
				if !foundAudience {
					t.Error("Conditions group should contain Audience row")
				}

				// AuthnStatement group
				if info.Groups[3].Name != "AuthnStatement" {
					t.Errorf("Groups[3].Name = %q, want AuthnStatement", info.Groups[3].Name)
				}
			},
		},
		{
			name: "response only (no assertion)",
			xml: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_resp_only" IssueInstant="2024-01-15T10:00:00Z">
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>
</samlp:Response>`,
			wantGroups: 1,
			checks: func(t *testing.T, info *SAMLResponseInfo) {
				if info.Groups[0].Name != "Response" {
					t.Errorf("Groups[0].Name = %q, want Response", info.Groups[0].Name)
				}
			},
		},
		{
			name:    "empty string",
			xml:     "",
			wantNil: true,
		},
		{
			name:    "invalid XML",
			xml:     "<<<not xml>>>",
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ExtractSAMLResponseInfo(tt.xml)
			if tt.wantNil {
				if info != nil {
					t.Errorf("expected nil, got %+v", info)
				}
				return
			}
			if info == nil {
				t.Fatal("expected non-nil result")
			}
			if len(info.Groups) != tt.wantGroups {
				t.Fatalf("got %d groups, want %d", len(info.Groups), tt.wantGroups)
			}
			if tt.checks != nil {
				tt.checks(t, info)
			}
		})
	}
}

const samlResponseWithAttrs = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion ID="_a1">
    <Subject>
      <NameID>alice@example.com</NameID>
    </Subject>
    <AttributeStatement>
      <Attribute Name="email">
        <AttributeValue>alice@example.com</AttributeValue>
      </Attribute>
      <Attribute Name="roles">
        <AttributeValue>admin</AttributeValue>
        <AttributeValue>user</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
</samlp:Response>`

func TestExtractSAMLSubjectAndAttributes(t *testing.T) {
	tests := []struct {
		name       string
		xml        string
		wantSubj   string
		wantAttrs  int
		checkAttrs func(t *testing.T, attrs map[string][]string)
	}{
		{
			name:      "full assertion with multi-valued attributes",
			xml:       samlResponseWithAttrs,
			wantSubj:  "alice@example.com",
			wantAttrs: 2,
			checkAttrs: func(t *testing.T, attrs map[string][]string) {
				if roles, ok := attrs["roles"]; !ok || len(roles) != 2 {
					t.Errorf("roles = %v, want 2 values", roles)
				}
				if email, ok := attrs["email"]; !ok || email[0] != "alice@example.com" {
					t.Errorf("email = %v, want [alice@example.com]", email)
				}
			},
		},
		{
			name: "no assertion",
			xml:  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
		},
		{
			name: "assertion without subject",
			xml: `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion ID="_a2">
    <AttributeStatement>
      <Attribute Name="email"><AttributeValue>bob@example.com</AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
</samlp:Response>`,
			wantAttrs: 1,
		},
		{
			name: "empty string",
			xml:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, attrs := ExtractSAMLSubjectAndAttributes(tt.xml)
			if subject != tt.wantSubj {
				t.Errorf("subject = %q, want %q", subject, tt.wantSubj)
			}
			if len(attrs) != tt.wantAttrs {
				t.Errorf("got %d attributes, want %d", len(attrs), tt.wantAttrs)
			}
			if tt.checkAttrs != nil {
				tt.checkAttrs(t, attrs)
			}
		})
	}
}

func TestExtractSAMLLogoutRequestSignatureInfos(t *testing.T) {
	tests := []struct {
		name      string
		xml       string
		wantCount int
	}{
		{
			name: "with signature",
			xml: `<LogoutRequest ID="_lr1">
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </Reference>
    </SignedInfo>
  </Signature>
</LogoutRequest>`,
			wantCount: 1,
		},
		{
			name:      "without signature",
			xml:       `<LogoutRequest ID="_lr2"><NameID>user@example.com</NameID></LogoutRequest>`,
			wantCount: 0,
		},
		{
			name:      "invalid XML",
			xml:       "not xml",
			wantCount: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infos := ExtractSAMLLogoutRequestSignatureInfos(tt.xml)
			if len(infos) != tt.wantCount {
				t.Errorf("got %d infos, want %d", len(infos), tt.wantCount)
			}
			if tt.wantCount > 0 && infos[0].Target != "Logout Request" {
				t.Errorf("Target = %q, want 'Logout Request'", infos[0].Target)
			}
		})
	}
}

func deflateBase64(data []byte) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(data)
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestDecodeSAMLRedirectBinding(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name:  "valid DEFLATE+base64 round-trip",
			input: deflateBase64([]byte(`<AuthnRequest ID="_123"/>`)),
			check: func(t *testing.T, result []byte) {
				if !strings.Contains(string(result), "AuthnRequest") {
					t.Errorf("result should contain AuthnRequest, got %q", string(result))
				}
			},
		},
		{
			name:    "invalid base64",
			input:   "!!!not-base64!!!",
			wantErr: true,
		},
		{
			name:    "valid base64 but invalid deflate",
			input:   base64.StdEncoding.EncodeToString([]byte("not deflated data")),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeSAMLRedirectBinding(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestVerifyXMLSignature(t *testing.T) {
	tests := []struct {
		name         string
		xml          string
		trustedCerts []*x509.Certificate
		want         bool
	}{
		{
			name:         "no trusted certs",
			xml:          samlResponseWithResponseSig,
			trustedCerts: nil,
			want:         false,
		},
		{
			name:         "invalid XML",
			xml:          "not xml",
			trustedCerts: []*x509.Certificate{{}},
			want:         false,
		},
		{
			name:         "empty XML",
			xml:          "",
			trustedCerts: []*x509.Certificate{{}},
			want:         false,
		},
		{
			name:         "valid XML but unsigned (verification fails)",
			xml:          samlResponseNoSig,
			trustedCerts: []*x509.Certificate{generateTestCert(t)},
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyXMLSignature(tt.xml, tt.trustedCerts); got != tt.want {
				t.Errorf("VerifyXMLSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCertDetails(t *testing.T) {
	cert := generateTestCert(t)
	b64Cert := base64.StdEncoding.EncodeToString(cert.Raw)

	t.Run("valid certificate", func(t *testing.T) {
		info := &SAMLSignatureInfo{}
		parseCertDetails(b64Cert, info)
		// CertSerialNumber is always set from the template
		if info.CertSerialNumber == "" {
			t.Error("CertSerialNumber should not be empty")
		}
		if info.CertFingerprint == "" {
			t.Error("CertFingerprint should not be empty")
		}
		// Fingerprint should be colon-separated hex (32 bytes = 95 chars: 32*2 + 31 colons)
		if strings.Count(info.CertFingerprint, ":") != 31 {
			t.Errorf("CertFingerprint should have 31 colons, got %d", strings.Count(info.CertFingerprint, ":"))
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		info := &SAMLSignatureInfo{}
		parseCertDetails("!!!not-base64!!!", info)
		if info.CertSubject != "" {
			t.Error("CertSubject should be empty for invalid base64")
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		info := &SAMLSignatureInfo{}
		parseCertDetails(base64.StdEncoding.EncodeToString([]byte("not a cert")), info)
		if info.CertSubject != "" {
			t.Error("CertSubject should be empty for invalid DER")
		}
	})
}

func TestFindChildElement(t *testing.T) {
	parent := etree.NewElement("Parent")
	child1 := parent.CreateElement("Child1")
	child1.SetText("value1")
	parent.CreateElement("Child2")

	t.Run("found", func(t *testing.T) {
		found := findChildElement(parent, "Child1")
		if found == nil {
			t.Fatal("expected to find Child1")
		}
		if found.Text() != "value1" {
			t.Errorf("text = %q, want value1", found.Text())
		}
	})

	t.Run("not found", func(t *testing.T) {
		found := findChildElement(parent, "NonExistent")
		if found != nil {
			t.Error("expected nil for non-existent element")
		}
	})
}

// generateTestCert creates a self-signed ECDSA certificate for testing.
func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
