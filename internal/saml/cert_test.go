package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	kp, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() error: %v", err)
	}

	t.Run("non-nil key and cert", func(t *testing.T) {
		if kp.Key == nil {
			t.Error("Key should not be nil")
		}
		if kp.Cert == nil {
			t.Error("Cert should not be nil")
		}
	})

	t.Run("self-signed", func(t *testing.T) {
		if kp.Cert.Issuer.String() != kp.Cert.Subject.String() {
			t.Errorf("Issuer (%s) != Subject (%s), expected self-signed", kp.Cert.Issuer, kp.Cert.Subject)
		}
	})

	t.Run("2048-bit key", func(t *testing.T) {
		if kp.Key.N.BitLen() != 2048 {
			t.Errorf("key size = %d bits, want 2048", kp.Key.N.BitLen())
		}
	})

	t.Run("different keys on repeated calls", func(t *testing.T) {
		kp2, err := GenerateSelfSignedCert()
		if err != nil {
			t.Fatalf("second GenerateSelfSignedCert() error: %v", err)
		}
		if kp.Key.N.Cmp(kp2.Key.N) == 0 {
			t.Error("two calls should produce different keys")
		}
	})
}

func TestLoadCertFromFiles(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Generate a test cert and write PEM files
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	t.Run("load valid cert and key", func(t *testing.T) {
		kp, err := LoadCertFromFiles(certPath, keyPath)
		if err != nil {
			t.Fatalf("LoadCertFromFiles() error: %v", err)
		}
		if kp.Key == nil {
			t.Error("Key should not be nil")
		}
		if kp.Cert == nil {
			t.Error("Cert should not be nil")
		}
		if kp.Cert.SerialNumber.Int64() != 99 {
			t.Errorf("SerialNumber = %d, want 99", kp.Cert.SerialNumber.Int64())
		}
	})
}

func TestLoadCertFromFiles_Errors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("nonexistent files", func(t *testing.T) {
		_, err := LoadCertFromFiles(
			filepath.Join(tmpDir, "no-cert.pem"),
			filepath.Join(tmpDir, "no-key.pem"),
		)
		if err == nil {
			t.Error("expected error for nonexistent files")
		}
	})

	t.Run("invalid cert content", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "bad-cert.pem")
		keyPath := filepath.Join(tmpDir, "bad-key.pem")
		os.WriteFile(certPath, []byte("not a cert"), 0644)
		os.WriteFile(keyPath, []byte("not a key"), 0644)

		_, err := LoadCertFromFiles(certPath, keyPath)
		if err == nil {
			t.Error("expected error for invalid cert content")
		}
	})
}
