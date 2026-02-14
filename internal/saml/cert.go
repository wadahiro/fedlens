package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// KeyPair holds a private key and certificate for SAML SP.
type KeyPair struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
}

// GenerateSelfSignedCert generates a self-signed certificate for SAML SP.
func GenerateSelfSignedCert() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return &KeyPair{Key: key, Cert: cert}, nil
}

// LoadCertFromFiles loads a certificate and private key from PEM files.
func LoadCertFromFiles(certPath, keyPath string) (*KeyPair, error) {
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load X509 key pair: %w", err)
	}

	rsaKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return &KeyPair{Key: rsaKey, Cert: cert}, nil
}
