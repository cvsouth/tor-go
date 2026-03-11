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

// registerTestFingerprint adds a fingerprint to dirAuthorityFingerprints for
// testing and returns a cleanup function that removes it.
func registerTestFingerprint(t *testing.T, fp string) {
	t.Helper()
	dirAuthorityFingerprints[fp] = true
	t.Cleanup(func() {
		delete(dirAuthorityFingerprints, fp)
	})
}

// fingerprintFromKey computes the SHA-1 fingerprint of an RSA public key's
// PKCS#1 DER encoding, returned as uppercase hex.
func fingerprintFromKey(pub *rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(pub)
	digest := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

// buildTestKeyCert generates a test key certificate text with the given parameters.
// signingKey is used as the dir-signing-key. identityKey is used as the
// dir-identity-key; its DER SHA-1 must equal fingerprint for the cert to be valid.
func buildTestKeyCert(fingerprint string, expires time.Time, signingKey, identityKey *rsa.PublicKey) string {
	sigDER := x509.MarshalPKCS1PublicKey(signingKey)
	sigPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: sigDER})

	idDER := x509.MarshalPKCS1PublicKey(identityKey)
	idPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: idDER})

	return fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-published 2025-01-01 00:00:00
dir-key-expires %s
dir-identity-key
%sdir-signing-key
%sdir-key-crosscert
-----BEGIN ID SIGNATURE-----
fake-crosscert
-----END ID SIGNATURE-----
dir-key-certification
-----BEGIN SIGNATURE-----
fake-certification
-----END SIGNATURE-----
`, fingerprint, expires.UTC().Format("2006-01-02 15:04:05"), string(idPEM), string(sigPEM))
}

func TestParseKeyCertsValid(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	identityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fp := fingerprintFromKey(&identityKey.PublicKey)
	registerTestFingerprint(t, fp)

	expires := time.Now().Add(365 * 24 * time.Hour)
	certText := buildTestKeyCert(fp, expires, &signingKey.PublicKey, &identityKey.PublicKey)

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
	derBytes := x509.MarshalPKCS1PublicKey(&signingKey.PublicKey)
	expectedDigest := sha1.Sum(derBytes)
	expectedHex := strings.ToUpper(hex.EncodeToString(expectedDigest[:]))
	if certs[0].SigningKeyDigest != expectedHex {
		t.Fatalf("signing key digest = %q, want %q", certs[0].SigningKeyDigest, expectedHex)
	}
}

func TestParseKeyCertsExpiredFiltered(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := fingerprintFromKey(&identityKey.PublicKey)
	registerTestFingerprint(t, fp)

	expires := time.Now().Add(-24 * time.Hour) // expired yesterday
	certText := buildTestKeyCert(fp, expires, &signingKey.PublicKey, &identityKey.PublicKey)

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("ParseKeyCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (expired), got %d", len(certs))
	}
}

func TestParseKeyCertsUnknownAuthorityFiltered(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Don't register the fingerprint — it should be rejected as unknown
	fp := fingerprintFromKey(&identityKey.PublicKey)

	expires := time.Now().Add(365 * 24 * time.Hour)
	certText := buildTestKeyCert(fp, expires, &signingKey.PublicKey, &identityKey.PublicKey)

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("ParseKeyCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (unknown authority), got %d", len(certs))
	}
}

func TestParseKeyCertsMultiple(t *testing.T) {
	signingKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	signingKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey2, _ := rsa.GenerateKey(rand.Reader, 2048)

	fp1 := fingerprintFromKey(&identityKey1.PublicKey)
	fp2 := fingerprintFromKey(&identityKey2.PublicKey)
	registerTestFingerprint(t, fp1)
	registerTestFingerprint(t, fp2)

	expires := time.Now().Add(365 * 24 * time.Hour)
	text := buildTestKeyCert(fp1, expires, &signingKey1.PublicKey, &identityKey1.PublicKey) + "\n" +
		buildTestKeyCert(fp2, expires, &signingKey2.PublicKey, &identityKey2.PublicKey)

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

	// Use a known authority fingerprint that does NOT match identityKey
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232" // moria1
	expires := time.Now().Add(365 * 24 * time.Hour)

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
		t.Fatal("expected 0 certs - identity key fingerprint should not match claimed fingerprint")
	}
}

func TestParseKeyCertsMissingIdentityKey(t *testing.T) {
	// A cert with a valid signing key but NO dir-identity-key section.
	// This is the bypass scenario: without an identity key, the fingerprint
	// cross-check cannot be performed. Must be rejected.
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232" // moria1

	sigDER := x509.MarshalPKCS1PublicKey(&signingKey.PublicKey)
	sigPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: sigDER})

	certText := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-published 2025-01-01 00:00:00
dir-key-expires 2030-01-01 00:00:00
dir-signing-key
%sdir-key-certification
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
`, fp, string(sigPEM))

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatal("expected 0 certs - missing identity key should be rejected")
	}
}

func TestParseKeyCertsMissingExpiry(t *testing.T) {
	// A cert with no dir-key-expires line should be rejected.
	// Without expiry, the cert would never expire — treat as error.
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := fingerprintFromKey(&identityKey.PublicKey)
	registerTestFingerprint(t, fp)

	idDER := x509.MarshalPKCS1PublicKey(&identityKey.PublicKey)
	idPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: idDER})

	sigDER := x509.MarshalPKCS1PublicKey(&signingKey.PublicKey)
	sigPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: sigDER})

	certText := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-published 2025-01-01 00:00:00
dir-identity-key
%sdir-signing-key
%sdir-key-certification
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
`, fp, string(idPEM), string(sigPEM))

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatal("expected 0 certs - missing dir-key-expires should be rejected")
	}
}

func TestParseKeyCertsUnparseableExpiry(t *testing.T) {
	// A cert with a malformed dir-key-expires should be rejected.
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := fingerprintFromKey(&identityKey.PublicKey)
	registerTestFingerprint(t, fp)

	idDER := x509.MarshalPKCS1PublicKey(&identityKey.PublicKey)
	idPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: idDER})

	sigDER := x509.MarshalPKCS1PublicKey(&signingKey.PublicKey)
	sigPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: sigDER})

	certText := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-published 2025-01-01 00:00:00
dir-key-expires not-a-date
dir-identity-key
%sdir-signing-key
%sdir-key-certification
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
`, fp, string(idPEM), string(sigPEM))

	certs, err := ParseKeyCerts(certText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatal("expected 0 certs - unparseable dir-key-expires should be rejected")
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
	// Malformed cert (no signing key, no identity key) should be skipped
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

func TestParseKeyCertsMissingFingerprint(t *testing.T) {
	// Cert without fingerprint line should be skipped
	text := `dir-key-certificate-version 3
dir-key-expires 2030-01-01 00:00:00
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA...
-----END RSA PUBLIC KEY-----
`
	certs, err := ParseKeyCerts(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (missing fingerprint), got %d", len(certs))
	}
}

func TestParseKeyCertsBadSigningKeyPEM(t *testing.T) {
	// Cert with invalid PEM for signing key should be skipped
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232"
	text := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-expires 2030-01-01 00:00:00
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
not-valid-base64!!!
-----END RSA PUBLIC KEY-----
`, fp)
	certs, err := ParseKeyCerts(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (bad signing key PEM), got %d", len(certs))
	}
}

func TestParseKeyCertsBadIdentityKeyPEM(t *testing.T) {
	// Cert with corrupted identity key PEM (valid PEM structure but bad content)
	// should be rejected: identity key fingerprint won't match claimed fingerprint
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232"
	expires := time.Now().Add(365 * 24 * time.Hour)

	sigDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	sigPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: sigDER})

	badIDPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: []byte("garbage-der-content"),
	})

	text := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-expires %s
dir-identity-key
%sdir-signing-key
%sdir-key-certification
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
`, fp, expires.UTC().Format("2006-01-02 15:04:05"), string(badIDPEM), string(sigPEM))

	certs, err := ParseKeyCerts(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (identity fingerprint mismatch), got %d", len(certs))
	}
}

func TestParseKeyCertsInvalidSigningKeyDER(t *testing.T) {
	// Valid PEM but invalid DER content for signing key
	fp := "F533C81CEF0BC0267857C99B2F471ADF249FA232"
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: []byte("not-valid-der-content"),
	})
	text := fmt.Sprintf(`dir-key-certificate-version 3
fingerprint %s
dir-key-expires 2030-01-01 00:00:00
dir-signing-key
%sdir-key-certification
-----BEGIN SIGNATURE-----
fake
-----END SIGNATURE-----
`, fp, string(badPEM))

	certs, err := ParseKeyCerts(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected 0 certs (invalid DER), got %d", len(certs))
	}
}

func TestSplitCertBlocksSingle(t *testing.T) {
	text := "dir-key-certificate-version 3\nfingerprint ABC\n"
	blocks := splitCertBlocks(text)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
}

func TestSplitCertBlocksEmpty(t *testing.T) {
	blocks := splitCertBlocks("")
	if len(blocks) != 0 {
		t.Fatalf("expected 0 blocks, got %d", len(blocks))
	}
}

func TestSplitCertBlocksNoMarker(t *testing.T) {
	blocks := splitCertBlocks("some random text without markers")
	if len(blocks) != 0 {
		t.Fatalf("expected 0 blocks, got %d", len(blocks))
	}
}

func TestExtractPEMBlock(t *testing.T) {
	lines := []string{
		"-----BEGIN RSA PUBLIC KEY-----",
		"MIIB...",
		"-----END RSA PUBLIC KEY-----",
		"extra line",
	}
	result := extractPEMBlock(lines)
	if !strings.Contains(result, "-----BEGIN RSA PUBLIC KEY-----") {
		t.Fatal("missing BEGIN marker")
	}
	if !strings.Contains(result, "-----END RSA PUBLIC KEY-----") {
		t.Fatal("missing END marker")
	}
	if strings.Contains(result, "extra line") {
		t.Fatal("should not include lines after END marker")
	}
}

func TestExtractKeyCertFieldsCarriageReturn(t *testing.T) {
	// Test that \r in lines is handled
	block := "fingerprint ABCD\r\ndir-key-expires 2030-01-01 00:00:00\r\n"
	fields := extractKeyCertFields(block)
	if fields.fingerprint != "ABCD" {
		t.Fatalf("fingerprint = %q, want %q", fields.fingerprint, "ABCD")
	}
	if fields.expires.IsZero() {
		t.Fatal("expires should not be zero")
	}
}

func TestFetchKeyCertsNilCircuit(t *testing.T) {
	_, err := FetchKeyCerts(nil)
	if err == nil {
		t.Fatal("expected error for nil circuit")
	}
}
