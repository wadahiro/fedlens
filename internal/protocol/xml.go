package protocol

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
	xmlpkg "encoding/xml"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAMLSignatureInfo holds SAML signature verification details.
type SAMLSignatureInfo struct {
	Target               string // "Response" or "Assertion"
	Algorithm            string // SignatureMethod URI
	AlgorithmShort       string // e.g. "rsa-sha256"
	DigestAlgorithm      string // DigestMethod URI
	DigestAlgorithmShort string
	KeyName              string // ds:KeyName value (if present)
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
		info.Verified = true // crewjam/saml already validated
		infos = append(infos, *info)
	}

	// Check Assertion-level signature(s)
	for _, assertion := range root.SelectElements("Assertion") {
		if info := parseSAMLSignature("Assertion", assertion); info != nil {
			info.Verified = true // crewjam/saml already validated
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
				info.Verified = true // crewjam/saml already validated
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
		Target: target,
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

	// Extract KeyName and X509Certificate
	if keyInfo := findChildElement(sigElem, "KeyInfo"); keyInfo != nil {
		if keyName := findChildElement(keyInfo, "KeyName"); keyName != nil {
			info.KeyName = keyName.Text()
		}
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
	info.CertNotBefore = FormatTimestamp(cert.NotBefore.UTC().Format(time.RFC3339))
	info.CertNotAfter = FormatTimestamp(cert.NotAfter.UTC().Format(time.RFC3339))

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

// SAMLResponseInfoRow is a single key-value row within a group.
type SAMLResponseInfoRow struct {
	Label string
	Value string
}

// SAMLResponseInfoGroup is a named group of rows.
type SAMLResponseInfoGroup struct {
	Name string
	Rows []SAMLResponseInfoRow
}

// SAMLResponseInfo holds structured metadata extracted from a SAML Response XML.
type SAMLResponseInfo struct {
	Groups []SAMLResponseInfoGroup
}

// ExtractSAMLResponseInfo parses a SAML Response XML and extracts structured metadata.
func ExtractSAMLResponseInfo(xmlStr string) *SAMLResponseInfo {
	if xmlStr == "" {
		return nil
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		log.Printf("Failed to parse SAML Response XML for info extraction: %v", err)
		return nil
	}
	root := doc.Root()
	if root == nil {
		return nil
	}

	info := &SAMLResponseInfo{}

	// Response group
	var responseRows []SAMLResponseInfoRow
	if v := root.SelectAttrValue("ID", ""); v != "" {
		responseRows = append(responseRows, SAMLResponseInfoRow{Label: "ID", Value: v})
	}
	if issuer := findChildElement(root, "Issuer"); issuer != nil {
		responseRows = append(responseRows, SAMLResponseInfoRow{Label: "Issuer", Value: issuer.Text()})
	}
	if v := root.SelectAttrValue("IssueInstant", ""); v != "" {
		responseRows = append(responseRows, SAMLResponseInfoRow{Label: "IssueInstant", Value: FormatTimestamp(v)})
	}
	if v := root.SelectAttrValue("InResponseTo", ""); v != "" {
		responseRows = append(responseRows, SAMLResponseInfoRow{Label: "InResponseTo", Value: v})
	}
	if v := root.SelectAttrValue("Destination", ""); v != "" {
		responseRows = append(responseRows, SAMLResponseInfoRow{Label: "Destination", Value: v})
	}
	if status := findChildElement(root, "Status"); status != nil {
		if statusCode := findChildElement(status, "StatusCode"); statusCode != nil {
			if v := statusCode.SelectAttrValue("Value", ""); v != "" {
				responseRows = append(responseRows, SAMLResponseInfoRow{Label: "Status", Value: v})
			}
		}
	}
	if len(responseRows) > 0 {
		info.Groups = append(info.Groups, SAMLResponseInfoGroup{Name: "Response", Rows: responseRows})
	}

	// Find Assertion (with or without namespace prefix)
	assertion := findChildElement(root, "Assertion")
	if assertion == nil {
		for _, child := range root.ChildElements() {
			if child.Tag == "Assertion" {
				assertion = child
				break
			}
		}
	}
	if assertion == nil {
		return info
	}

	// Subject group
	var subjectRows []SAMLResponseInfoRow
	if subject := findChildElement(assertion, "Subject"); subject != nil {
		if nameID := findChildElement(subject, "NameID"); nameID != nil {
			subjectRows = append(subjectRows, SAMLResponseInfoRow{Label: "NameID", Value: nameID.Text()})
			if v := nameID.SelectAttrValue("Format", ""); v != "" {
				subjectRows = append(subjectRows, SAMLResponseInfoRow{Label: "NameID Format", Value: v})
			}
		}
		if subConf := findChildElement(subject, "SubjectConfirmation"); subConf != nil {
			if subConfData := findChildElement(subConf, "SubjectConfirmationData"); subConfData != nil {
				if v := subConfData.SelectAttrValue("Recipient", ""); v != "" {
					subjectRows = append(subjectRows, SAMLResponseInfoRow{Label: "Recipient", Value: v})
				}
				if v := subConfData.SelectAttrValue("NotOnOrAfter", ""); v != "" {
					subjectRows = append(subjectRows, SAMLResponseInfoRow{Label: "NotOnOrAfter", Value: FormatTimestamp(v)})
				}
			}
		}
	}
	if len(subjectRows) > 0 {
		info.Groups = append(info.Groups, SAMLResponseInfoGroup{Name: "Subject", Rows: subjectRows})
	}

	// Conditions group
	var conditionsRows []SAMLResponseInfoRow
	if conditions := findChildElement(assertion, "Conditions"); conditions != nil {
		if v := conditions.SelectAttrValue("NotBefore", ""); v != "" {
			conditionsRows = append(conditionsRows, SAMLResponseInfoRow{Label: "NotBefore", Value: FormatTimestamp(v)})
		}
		if v := conditions.SelectAttrValue("NotOnOrAfter", ""); v != "" {
			conditionsRows = append(conditionsRows, SAMLResponseInfoRow{Label: "NotOnOrAfter", Value: FormatTimestamp(v)})
		}
		if ar := findChildElement(conditions, "AudienceRestriction"); ar != nil {
			if audience := findChildElement(ar, "Audience"); audience != nil {
				conditionsRows = append(conditionsRows, SAMLResponseInfoRow{Label: "Audience", Value: audience.Text()})
			}
		}
	}
	if len(conditionsRows) > 0 {
		info.Groups = append(info.Groups, SAMLResponseInfoGroup{Name: "Conditions", Rows: conditionsRows})
	}

	// AuthnStatement group
	var authnRows []SAMLResponseInfoRow
	if authnStmt := findChildElement(assertion, "AuthnStatement"); authnStmt != nil {
		if v := authnStmt.SelectAttrValue("AuthnInstant", ""); v != "" {
			authnRows = append(authnRows, SAMLResponseInfoRow{Label: "AuthnInstant", Value: FormatTimestamp(v)})
		}
		if v := authnStmt.SelectAttrValue("SessionIndex", ""); v != "" {
			authnRows = append(authnRows, SAMLResponseInfoRow{Label: "SessionIndex", Value: v})
		}
		if authnCtx := findChildElement(authnStmt, "AuthnContext"); authnCtx != nil {
			if classRef := findChildElement(authnCtx, "AuthnContextClassRef"); classRef != nil {
				authnRows = append(authnRows, SAMLResponseInfoRow{Label: "AuthnContextClassRef", Value: classRef.Text()})
			}
		}
	}
	if len(authnRows) > 0 {
		info.Groups = append(info.Groups, SAMLResponseInfoGroup{Name: "AuthnStatement", Rows: authnRows})
	}

	return info
}

// ExtractSAMLSubjectAndAttributes parses a SAML Response XML and extracts
// the NameID (Subject) and Attributes from the first Assertion.
func ExtractSAMLSubjectAndAttributes(xmlStr string) (subject string, attributes map[string][]string) {
	if xmlStr == "" {
		return "", nil
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		return "", nil
	}
	root := doc.Root()
	if root == nil {
		return "", nil
	}

	// Find Assertion (with or without namespace prefix)
	assertion := findChildElement(root, "Assertion")
	if assertion == nil {
		for _, child := range root.ChildElements() {
			if child.Tag == "Assertion" {
				assertion = child
				break
			}
		}
	}
	if assertion == nil {
		return "", nil
	}

	// Extract NameID from Subject
	if subjectElem := findChildElement(assertion, "Subject"); subjectElem != nil {
		if nameID := findChildElement(subjectElem, "NameID"); nameID != nil {
			subject = nameID.Text()
		}
	}

	// Extract Attributes from AttributeStatement
	if attrStmt := findChildElement(assertion, "AttributeStatement"); attrStmt != nil {
		attributes = make(map[string][]string)
		for _, attr := range attrStmt.ChildElements() {
			if attr.Tag != "Attribute" {
				continue
			}
			name := attr.SelectAttrValue("Name", "")
			if name == "" {
				continue
			}
			var values []string
			for _, attrVal := range attr.ChildElements() {
				if attrVal.Tag == "AttributeValue" {
					values = append(values, attrVal.Text())
				}
			}
			attributes[name] = values
		}
	}

	return subject, attributes
}

// ExtractSAMLLogoutRequestSignatureInfos parses a SAML LogoutRequest XML
// and extracts signature info from the root element.
func ExtractSAMLLogoutRequestSignatureInfos(xmlStr string) []SAMLSignatureInfo {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		return nil
	}
	root := doc.Root()
	if root == nil {
		return nil
	}
	var infos []SAMLSignatureInfo
	if info := parseSAMLSignature("Logout Request", root); info != nil {
		infos = append(infos, *info)
	}
	return infos
}

// VerifyXMLSignature verifies the XML signature of a SAML message using
// the provided trusted certificates (from IdP metadata).
func VerifyXMLSignature(xmlStr string, trustedCerts []*x509.Certificate) bool {
	if len(trustedCerts) == 0 {
		return false
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		return false
	}
	root := doc.Root()
	if root == nil {
		return false
	}
	certStore := &dsig.MemoryX509CertificateStore{Roots: trustedCerts}
	validationCtx := dsig.NewDefaultValidationContext(certStore)
	validationCtx.IdAttribute = "ID"
	_, err := validationCtx.Validate(root)
	return err == nil
}

// DecodeSAMLRedirectBinding decodes a SAML message from HTTP-Redirect binding.
// The message is base64-encoded and DEFLATE-compressed.
func DecodeSAMLRedirectBinding(encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	reader := flate.NewReader(bytes.NewReader(raw))
	defer reader.Close()
	xmlBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("deflate decompress: %w", err)
	}
	return xmlBytes, nil
}
