package protocol

import "github.com/beevik/etree"

// SAMLNameID is the NameID of an assertion's Subject with the attributes that
// say how the IdP chose to identify the user.
type SAMLNameID struct {
	Value           string
	Format          string
	NameQualifier   string
	SPNameQualifier string
	SPProvidedID    string
}

// SAMLNameIDPolicy is what an AuthnRequest asked for. Present is false when the
// request carried no NameIDPolicy at all, which differs from one without a Format.
type SAMLNameIDPolicy struct {
	Present         bool
	Format          string
	AllowCreate     string
	SPNameQualifier string
}

// ExtractSAMLNameID reads the Subject NameID of the first Assertion. ok is false
// when there is none, for example when the IdP sent an EncryptedID.
func ExtractSAMLNameID(responseXML string) (id SAMLNameID, ok bool) {
	root := parseRoot(responseXML)
	if root == nil {
		return id, false
	}
	assertion := findChildElement(root, "Assertion")
	if assertion == nil && root.Tag == "Assertion" {
		assertion = root
	}
	if assertion == nil {
		return id, false
	}
	subject := findChildElement(assertion, "Subject")
	if subject == nil {
		return id, false
	}
	n := findChildElement(subject, "NameID")
	if n == nil {
		return id, false
	}
	return SAMLNameID{
		Value:           n.Text(),
		Format:          n.SelectAttrValue("Format", ""),
		NameQualifier:   n.SelectAttrValue("NameQualifier", ""),
		SPNameQualifier: n.SelectAttrValue("SPNameQualifier", ""),
		SPProvidedID:    n.SelectAttrValue("SPProvidedID", ""),
	}, true
}

// ExtractSAMLNameIDPolicy reads the NameIDPolicy of an AuthnRequest.
func ExtractSAMLNameIDPolicy(authnRequestXML string) SAMLNameIDPolicy {
	root := parseRoot(authnRequestXML)
	if root == nil {
		return SAMLNameIDPolicy{}
	}
	p := findChildElement(root, "NameIDPolicy")
	if p == nil {
		return SAMLNameIDPolicy{}
	}
	return SAMLNameIDPolicy{
		Present:         true,
		Format:          p.SelectAttrValue("Format", ""),
		AllowCreate:     p.SelectAttrValue("AllowCreate", ""),
		SPNameQualifier: p.SelectAttrValue("SPNameQualifier", ""),
	}
}

func parseRoot(xmlStr string) *etree.Element {
	if xmlStr == "" {
		return nil
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		return nil
	}
	return doc.Root()
}
