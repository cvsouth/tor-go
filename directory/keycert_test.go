package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"
)

// buildTestKeyCert generates a test key certificate text with the given parameters.
func buildTestKeyCert(fingerprint string, expires time.Time, key *rsa.PublicKey) string {
	derBytes := x509.MarshalPKCS1PublicKey(key)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	})

	return fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-published 2025-01-01 00:00:00
dir-key-expires %s
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIIB... (fake identity key, not parsed)
-----END RSA PUBLIC KEY-----
dir-signing-key
%sdir-key-crosscert
-----BEGIN ID SIGNATURE-----
fake-crosscert
-----END ID SIGNATURE-----
dir-key-certification
-----BEGIN SIGNATURE-----
fake-certification
-----END SIGNATURE-----
`, fingerprint, expires.UTC().Format("2006-01-02 15:04:05"), string(pemBlock))
}

func TestParseKeyCertsValid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Use a real authority fingerprint
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232" // moria1
	expires := time.Now().Add(365 * 24 * time.Hour)
	certText := buildTestKeyCert(fp, expires, &key.PublicKey)

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("ParseKeyCerts: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].IdentityFingerprint != fp {
		t.Fatalf("fingerprint = %q, want %q", certs[0].IdentityFingerprint, fp)
	}
	if certs[0].SigningKey == nil {
		t.Fatal("signing key is nil")
	}
	if certs[0].SigningKeyDigest == "" {
		t.Fatal("signing key digest is empty")
	}

	// Verify signing key digest is correct
	derBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	expectedDigest := sha1.Sum(derBytes)
	expectedHex := strings.ToUpper(hex.EncodeToString(expectedDigest[:]))
	if certs[0].SigningKeyDigest != expectedHex {
		t.Fatalf("signing key digest = %q, want %q", certs[0].SigningKeyDigest, expectedHex)
	}
}

func TestParseKeyCertsExpiredFiltered(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232"
	expires := time.Now().Add(-24 * time.Hour) // expired yesterday
	certText := buildTestKeyCert(fp, expires, &key.PublicKey)

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("ParseKeyCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (expired), got %d", len(certs))
	}
}

func TestParseKeyCertsUnknownAuthorityFiltered(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // not a real authority
	expires := time.Now().Add(365 * 24 * time.Hour)
	certText := buildTestKeyCert(fp, expires, &key.PublicKey)

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("ParseKeyCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (unknown authority), got %d", len(certs))
	}
}

func TestParseKeyCertsMultiple(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	expires := time.Now().Add(365 * 24 * time.Hour)

	fp1 := "F533C81CEF0BC0267857C99B2F471ADF249FA232" // moria1
	fp2 := "ED03BB616EB2F60BEC80151114BB25CEF515B226" // gabelmoo

	text := buildTestKeyCert(fp1, expires, &key1.PublicKey) + "\n" +
		buildTestKeyCert(fp2, expires, &key2.PublicKey)

	certs, err := ParseKeyCerts(text)
	if err != nil {
		t.Fatalf("ParseKeyCerts: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	fps := map[string]bool{certs[0].IdentityFingerprint: true, certs[1].IdentityFingerprint: true}
	if !fps[fp1] || !fps[fp2] {
		t.Fatalf("unexpected fingerprints: %v", fps)
	}
}

func TestParseKeyCertsIdentityFingerprintMismatch(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232" // moria1
	expires := time.Now().Add(365 * 24 * time.Hour)

	// Build cert with a real identity key whose fingerprint won't match the claimed fp
	idDER := x509.MarshalPKCS1PublicKey(&identityKey.PublicKey)
	idPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: idDER})

	sigDER := x509.MarshalPKCS1PublicKey(&signingKey.PublicKey)
	sigPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: sigDER})

	certText := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-published 2025-01-01 00:00:00
dir-key-expires %s
dir-identity-key
%sdir-signing-key
%sdir-key-certification
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
`, fp, expires.UTC().Format("2006-01-02 15:04:05"), string(idPEM), string(sigPEM))

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatal("expected 0 certs — identity key fingerprint should not match claimed fingerprint")
	}
}

func TestParseKeyCertsEmptyInput(t *testing.T) {
	certs, err := ParseKeyCerts("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs, got %d", len(certs))
	}
}

func TestParseKeyCertsMalformedSkipped(t *testing.T) {
	// Malformed cert (no signing key) should be skipped, not error
	text := `dir-key-certificate-version 3
fingerprint F533C81CEF0BC0267857C99B2F471ADF249FA232
dir-key-expires 2030-01-01 00:00:00
`
	certs, err := ParseKeyCerts(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (malformed), got %d", len(certs))
	}
}
