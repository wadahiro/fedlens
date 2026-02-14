package protocol

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"time"
	xmlpkg "encoding/xml"

	"github.com/beevik/etree"
)

// SAMLSignatureInfo holds SAML signature verification details.
type SAMLSignatureInfo struct {
	Target               string // "Response" or "Assertion"
	Algorithm            string // SignatureMethod URI
	AlgorithmShort       string // e.g. "rsa-sha256"
	DigestAlgorithm      string // DigestMethod URI
	DigestAlgorithmShort string
	CertSubject          string
	CertIssuer           string
	CertSerialNumber     string
	CertNotBefore        string
	CertNotAfter         string
	CertFingerprint      string // SHA-256 colon-separated hex
	Verified             bool
}

// FormatXML reformats an XML string with indentation.
func FormatXML(s string) string {
	if s == "" {
		return ""
	}
	var buf strings.Builder
	decoder := xmlpkg.NewDecoder(strings.NewReader(s))
	encoder := xmlpkg.NewEncoder(&buf)
	encoder.Indent("", "  ")
	for {
		t, err := decoder.Token()
		if err != nil {
			break
		}
		encoder.EncodeToken(t)
	}
	encoder.Flush()
	if buf.Len() > 0 {
		return buf.String()
	}
	return s
}

// ExtractSAMLSignatureInfos parses a SAML XML and extracts signature info
// from Response and Assertion levels.
func ExtractSAMLSignatureInfos(xmlStr string) []SAMLSignatureInfo {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		log.Printf("Failed to parse SAML XML: %v", err)
		return nil
	}
	root := doc.Root()
	if root == nil {
		return nil
	}

	var infos []SAMLSignatureInfo

	// Check Response-level signature
	if info := parseSAMLSignature("Response", root); info != nil {
		infos = append(infos, *info)
	}

	// Check Assertion-level signature(s)
	for _, assertion := range root.SelectElements("Assertion") {
		if info := parseSAMLSignature("Assertion", assertion); info != nil {
			infos = append(infos, *info)
		}
	}
	// Also check with namespace prefix
	for _, assertion := range root.FindElements("//saml:Assertion") {
		if info := parseSAMLSignature("Assertion", assertion); info != nil {
			// Avoid duplicates
			dup := false
			for _, existing := range infos {
				if existing.Target == "Assertion" {
					dup = true
					break
				}
			}
			if !dup {
				infos = append(infos, *info)
			}
		}
	}

	return infos
}

func parseSAMLSignature(target string, elem *etree.Element) *SAMLSignatureInfo {
	// Look for ds:Signature or Signature as direct child
	var sigElem *etree.Element
	for _, child := range elem.ChildElements() {
		if child.Tag == "Signature" {
			sigElem = child
			break
		}
	}
	if sigElem == nil {
		return nil
	}

	info := &SAMLSignatureInfo{
		Target:   target,
		Verified: true, // If we got here, crewjam/saml already validated
	}

	// Extract SignatureMethod
	if signedInfo := findChildElement(sigElem, "SignedInfo"); signedInfo != nil {
		if sigMethod := findChildElement(signedInfo, "SignatureMethod"); sigMethod != nil {
			info.Algorithm = sigMethod.SelectAttrValue("Algorithm", "")
			info.AlgorithmShort = ShortenAlgorithmURI(info.Algorithm)
		}
		// Extract DigestMethod from Reference
		if ref := findChildElement(signedInfo, "Reference"); ref != nil {
			if digestMethod := findChildElement(ref, "DigestMethod"); digestMethod != nil {
				info.DigestAlgorithm = digestMethod.SelectAttrValue("Algorithm", "")
				info.DigestAlgorithmShort = ShortenAlgorithmURI(info.DigestAlgorithm)
			}
		}
	}

	// Extract X509Certificate
	if keyInfo := findChildElement(sigElem, "KeyInfo"); keyInfo != nil {
		if x509Data := findChildElement(keyInfo, "X509Data"); x509Data != nil {
			if x509Cert := findChildElement(x509Data, "X509Certificate"); x509Cert != nil {
				parseCertDetails(x509Cert.Text(), info)
			}
		}
	}

	return info
}

func findChildElement(parent *etree.Element, localName string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == localName {
			return child
		}
	}
	return nil
}

func parseCertDetails(b64Cert string, info *SAMLSignatureInfo) {
	cleaned := strings.Join(strings.Fields(b64Cert), "")
	certDER, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		log.Printf("Failed to decode X509Certificate: %v", err)
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Printf("Failed to parse X509Certificate: %v", err)
		return
	}
	info.CertSubject = cert.Subject.String()
	info.CertIssuer = cert.Issuer.String()
	info.CertSerialNumber = cert.SerialNumber.String()
	info.CertNotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	info.CertNotAfter = cert.NotAfter.UTC().Format(time.RFC3339)

	// SHA-256 fingerprint
	fingerprint := sha256.Sum256(certDER)
	parts := make([]string, len(fingerprint))
	for i, b := range fingerprint {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	info.CertFingerprint = strings.Join(parts, ":")
}

// ShortenAlgorithmURI extracts the fragment from an algorithm URI.
func ShortenAlgorithmURI(uri string) string {
	if idx := strings.LastIndex(uri, "#"); idx >= 0 {
		return uri[idx+1:]
	}
	return uri
}
