package saml

import (
	"crypto"
	"fmt"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
)

const (
	nsEncrypted = "http://www.w3.org/2001/04/xmlenc#"
	typeElement = "http://www.w3.org/2001/04/xmlenc#Element"
)

// decryptResponse returns the SAML Response with every EncryptedAssertion and
// EncryptedID replaced by its plaintext, so the debug views can read the NameID
// and attributes. It is shown beside the response as received, never in place of it. ok is false when nothing was encrypted, and a
// failure leaves the response as received, since the login itself can still
// succeed or fail on its own terms.
func decryptResponse(responseXML string, key crypto.PrivateKey) (plain string, ok bool, err error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		return "", false, err
	}
	if doc.Root() == nil {
		return "", false, nil
	}
	var targets []*etree.Element
	collectEncrypted(doc.Root(), &targets)
	if len(targets) == 0 {
		return "", false, nil
	}
	for _, el := range targets {
		plainEl, err := decryptElement(el, key)
		if err != nil {
			return "", false, fmt.Errorf("decrypt %s: %w", el.Tag, err)
		}
		parent := el.Parent()
		idx := el.Index()
		parent.RemoveChildAt(idx)
		parent.InsertChildAt(idx, plainEl)
	}
	out, err := doc.WriteToString()
	if err != nil {
		return "", false, err
	}
	return out, true, nil
}

// collectEncrypted finds the encrypted elements without descending into them:
// a plaintext assertion may itself hold an EncryptedID, which is found only once
// the outer element is decrypted, so those are handled by a second pass.
func collectEncrypted(el *etree.Element, out *[]*etree.Element) {
	for _, c := range el.ChildElements() {
		switch c.Tag {
		case "EncryptedAssertion", "EncryptedID", "EncryptedAttribute":
			*out = append(*out, c)
		default:
			collectEncrypted(c, out)
		}
	}
}

// decryptElement follows what crewjam/saml does for an EncryptedAssertion: the
// session key is either an EncryptedKey beside the data, or wrapped inside the
// data's own KeyInfo, which xmlenc.Decrypt resolves itself.
func decryptElement(encrypted *etree.Element, key crypto.PrivateKey) (*etree.Element, error) {
	data := encrypted.FindElement("./EncryptedData")
	if data == nil {
		return nil, fmt.Errorf("no EncryptedData")
	}
	var k interface{} = key
	if keyEl := encrypted.FindElement("./EncryptedKey"); keyEl != nil {
		var err error
		if k, err = xmlenc.Decrypt(key, keyEl); err != nil {
			return nil, fmt.Errorf("decrypt key: %w", err)
		}
	}
	plain, err := xmlenc.Decrypt(k, data)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plain); err != nil {
		return nil, err
	}
	return doc.Root(), nil
}
