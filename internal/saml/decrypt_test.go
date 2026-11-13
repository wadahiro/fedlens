package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
)

func encryptTo(t *testing.T, cert *x509.Certificate, plaintext, tag string) string {
	t.Helper()
	enc := xmlenc.OAEP()
	enc.BlockCipher = xmlenc.AES128CBC
	enc.DigestMethod = &xmlenc.SHA1
	data, err := enc.Encrypt(cert, []byte(plaintext), nil)
	if err != nil {
		t.Fatal(err)
	}
	data.CreateAttr("Type", typeElement)
	wrap := etree.NewElement(tag)
	wrap.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	wrap.AddChild(data)
	doc := etree.NewDocument()
	doc.SetRoot(wrap)
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testKey(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func TestDecryptResponseReplacesEncryptedAssertion(t *testing.T) {
	key, cert := testKey(t)
	assertion := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>`
	resp := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + encryptTo(t, cert, assertion, "saml:EncryptedAssertion") + `</samlp:Response>`

	plain, ok, err := decryptResponse(resp, key)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if strings.Contains(plain, "EncryptedAssertion") || !strings.Contains(plain, "alice") {
		t.Errorf("not decrypted:\n%s", plain)
	}
}

func TestDecryptResponseReplacesEncryptedID(t *testing.T) {
	key, cert := testKey(t)
	nameID := `<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">bob</saml:NameID>`
	resp := `<Response><Assertion><Subject>` + encryptTo(t, cert, nameID, "saml:EncryptedID") + `</Subject></Assertion></Response>`

	plain, ok, err := decryptResponse(resp, key)
	if err != nil || !ok || !strings.Contains(plain, "bob") || strings.Contains(plain, "EncryptedID") {
		t.Errorf("ok=%v err=%v\n%s", ok, err, plain)
	}
}

func TestDecryptResponseLeavesPlainResponseAlone(t *testing.T) {
	key, _ := testKey(t)
	if _, ok, err := decryptResponse(`<Response><Assertion/></Response>`, key); ok || err != nil {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestDecryptResponseWithWrongKeyFails(t *testing.T) {
	_, cert := testKey(t)
	other, _ := testKey(t)
	resp := `<Response>` + encryptTo(t, cert, `<A/>`, "saml:EncryptedAssertion") + `</Response>`
	if _, ok, err := decryptResponse(resp, other); ok || err == nil {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}
