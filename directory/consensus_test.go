package directory

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	csha1 "crypto/sha1"
)

const testConsensus = `network-status-version 3 microdesc
vote-status consensus
consensus-method 32
valid-after 2025-01-15 12:00:00
fresh-until 2025-01-15 13:00:00
valid-until 2025-01-15 15:00:00
shared-rand-current-value 12 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
r TestRelay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA 2025-01-15 11:30:00 1.2.3.4 9001 0
m sha256=abcdefghijklmnopqrstuvwxyz012345678901234567
s Exit Fast Guard Running Stable Valid
w Bandwidth=5000
r TestRelay2 BBBBBBBBBBBBBBBBBBBBBBBBBBB 2025-01-15 11:31:00 5.6.7.8 443 9030
m sha256=zyxwvutsrqponmlkjihgfedcba987654321098765432
s Fast Running Stable Valid HSDir
w Bandwidth=3000
r BadRelay CCCCCCCCCCCCCCCCCCCCCCCCCCC 2025-01-15 11:32:00 9.10.11.12 9001 0
m sha256=badrelaydigest000000000000000000000000000000
s BadExit Exit Running Valid
w Bandwidth=100
bandwidth-weights Wbd=0 Wbe=0 Wbg=4131 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5869 Wgm=5869 Wmb=10000 Wmd=0 Wme=0 Wmg=4131 Wmm=10000
`

func TestParseConsensus(t *testing.T) {
	c, err := ParseConsensus(testConsensus)
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}

	// Check timestamps
	if c.ValidAfter.Year() != 2025 || c.ValidAfter.Hour() != 12 {
		t.Fatalf("ValidAfter = %v", c.ValidAfter)
	}
	if c.FreshUntil.Hour() != 13 {
		t.Fatalf("FreshUntil = %v", c.FreshUntil)
	}
	if c.ValidUntil.Hour() != 15 {
		t.Fatalf("ValidUntil = %v", c.ValidUntil)
	}

	// Check relay count
	if len(c.Relays) != 3 {
		t.Fatalf("got %d relays, want 3", len(c.Relays))
	}

	// Check first relay
	r1 := c.Relays[0]
	if r1.Nickname != "TestRelay1" {
		t.Fatalf("relay 0 nickname = %q", r1.Nickname)
	}
	if r1.Address != "1.2.3.4" {
		t.Fatalf("relay 0 address = %q", r1.Address)
	}
	if r1.ORPort != 9001 {
		t.Fatalf("relay 0 ORPort = %d", r1.ORPort)
	}
	if !r1.Flags.Exit || !r1.Flags.Fast || !r1.Flags.Guard || !r1.Flags.Running {
		t.Fatalf("relay 0 flags wrong: %+v", r1.Flags)
	}
	if r1.Bandwidth != 5000 {
		t.Fatalf("relay 0 bandwidth = %d", r1.Bandwidth)
	}

	// Check identity decode — 20 zero bytes
	expectedID := make([]byte, 20)
	for i := 0; i < 20; i++ {
		if r1.Identity[i] != expectedID[i] {
			t.Fatalf("relay 0 identity mismatch at byte %d", i)
			break
		}
	}

	// Check second relay
	r2 := c.Relays[1]
	if r2.Nickname != "TestRelay2" {
		t.Fatalf("relay 1 nickname = %q", r2.Nickname)
	}
	if r2.DirPort != 9030 {
		t.Fatalf("relay 1 DirPort = %d", r2.DirPort)
	}
	if !r2.Flags.HSDir {
		t.Fatal("relay 1 should have HSDir flag")
	}
	if r2.Flags.Exit {
		t.Fatal("relay 1 should not have Exit flag")
	}

	// Check bad relay
	r3 := c.Relays[2]
	if !r3.Flags.BadExit {
		t.Fatal("relay 2 should have BadExit flag")
	}

	// Check bandwidth weights
	if c.BandwidthWeights["Wgg"] != 5869 {
		t.Fatalf("Wgg = %d, want 5869", c.BandwidthWeights["Wgg"])
	}
	if c.BandwidthWeights["Wbm"] != 10000 {
		t.Fatalf("Wbm = %d, want 10000", c.BandwidthWeights["Wbm"])
	}
}

func TestValidateFreshness(t *testing.T) {
	now := time.Now().UTC()

	// Valid consensus
	c := &Consensus{
		ValidAfter: now.Add(-1 * time.Hour),
		ValidUntil: now.Add(1 * time.Hour),
	}
	if err := ValidateFreshness(c); err != nil {
		t.Fatalf("expected valid: %v", err)
	}

	// Expired consensus
	c.ValidUntil = now.Add(-10 * time.Minute)
	if err := ValidateFreshness(c); err == nil {
		t.Fatal("expected error for expired consensus")
	}

	// Future consensus
	c.ValidAfter = now.Add(10 * time.Minute)
	c.ValidUntil = now.Add(2 * time.Hour)
	if err := ValidateFreshness(c); err == nil {
		t.Fatal("expected error for future consensus")
	}

	// Missing timestamps
	c2 := &Consensus{}
	if err := ValidateFreshness(c2); err == nil {
		t.Fatal("expected error for missing timestamps")
	}
}

func TestValidateSignaturesStructural(t *testing.T) {
	// Build a fake consensus with 5 authority signatures
	var sigs []string
	i := 0
	for fp := range dirAuthorityFingerprints {
		sigs = append(sigs, "directory-signature sha256 "+strings.ToUpper(fp)+" AABBCCDD\n-----BEGIN SIGNATURE-----\nfake\n-----END SIGNATURE-----")
		i++
		if i >= 5 {
			break
		}
	}
	text := "network-status-version 3 microdesc\n" + strings.Join(sigs, "\n") + "\n"
	if err := ValidateSignaturesStructural(text); err != nil {
		t.Fatalf("expected valid with 5 sigs: %v", err)
	}

	// Only 3 signatures — should fail
	text3 := "network-status-version 3 microdesc\n" + strings.Join(sigs[:3], "\n") + "\n"
	if err := ValidateSignaturesStructural(text3); err == nil {
		t.Fatal("expected error with only 3 sigs")
	}

	// No signatures
	if err := ValidateSignaturesStructural("network-status-version 3 microdesc\n"); err == nil {
		t.Fatal("expected error with no sigs")
	}
}

func TestValidateSignaturesFallbackWhenNoCerts(t *testing.T) {
	// When certs is nil, should fall back to structural validation
	var sigs []string
	i := 0
	for fp := range dirAuthorityFingerprints {
		sigs = append(sigs, "directory-signature sha256 "+strings.ToUpper(fp)+" AABBCCDD\n-----BEGIN SIGNATURE-----\nfake\n-----END SIGNATURE-----")
		i++
		if i >= 5 {
			break
		}
	}
	text := "network-status-version 3 microdesc\n" + strings.Join(sigs, "\n") + "\n"
	if err := ValidateSignatures(text, nil); err != nil {
		t.Fatalf("expected structural fallback to pass: %v", err)
	}
}

// buildSignedConsensus creates a test consensus signed by the given keys.
// Returns the full consensus text and the list of KeyCerts.
func buildSignedConsensus(t *testing.T, numSigners int) (string, []KeyCert) {
	t.Helper()

	// Collect authority fingerprints
	var fps []string
	for fp := range dirAuthorityFingerprints {
		fps = append(fps, fp)
		if len(fps) >= numSigners {
			break
		}
	}

	// Generate keys and certs
	var certs []KeyCert
	type signer struct {
		fp      string
		privKey *rsa.PrivateKey
		cert    KeyCert
	}
	var signers []signer
	for _, fp := range fps {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
		digest := csha1.Sum(derBytes)
		skDigest := strings.ToUpper(hex.EncodeToString(digest[:]))

		kc := KeyCert{
			IdentityFingerprint: fp,
			SigningKeyDigest:    skDigest,
			SigningKey:          &privKey.PublicKey,
			Expires:            time.Now().Add(365 * 24 * time.Hour),
		}
		certs = append(certs, kc)
		signers = append(signers, signer{fp: fp, privKey: privKey, cert: kc})
	}

	// Build consensus body (everything before signatures)
	preamble := "network-status-version 3 microdesc\nvote-status consensus\nvalid-after 2025-01-15 12:00:00\n"

	// The signed content is: preamble + "\ndirectory-signature " (with leading newline before first sig)
	// But the first directory-signature starts after the preamble, so the signed content is:
	// preamble + "directory-signature " — wait, per spec it's from "network-status-version" through
	// the space after "directory-signature". The text has "\ndirectory-signature " and we search for that.
	// So the signed content = everything up to and including "\ndirectory-signature "

	// All signers sign the same content: everything before the first signature block + "directory-signature "
	signedContent := preamble + "directory-signature "
	h := sha256.Sum256([]byte(signedContent))

	// Build signature blocks
	var sigBlocks []string
	for _, s := range signers {
		// Tor uses PKCS#1 v1.5 padding without ASN.1 DigestInfo prefix
		sigBytes, err := rsa.SignPKCS1v15(rand.Reader, s.privKey, crypto.Hash(0), h[:])
		if err != nil {
			t.Fatal(err)
		}
		b64Sig := base64.StdEncoding.EncodeToString(sigBytes)
		sigBlocks = append(sigBlocks, fmt.Sprintf("directory-signature sha256 %s %s\n-----BEGIN SIGNATURE-----\n%s\n-----END SIGNATURE-----",
			s.fp, s.cert.SigningKeyDigest, b64Sig))
	}

	body := preamble + strings.Join(sigBlocks, "\n") + "\n"
	return body, certs
}

func TestValidateSignaturesCryptoValid(t *testing.T) {
	text, certs := buildSignedConsensus(t, 5)
	if err := ValidateSignatures(text, certs); err != nil {
		t.Fatalf("ValidateSignatures: %v", err)
	}
}

func TestValidateSignaturesCryptoTooFew(t *testing.T) {
	text, certs := buildSignedConsensus(t, 3)
	if err := ValidateSignatures(text, certs); err == nil {
		t.Fatal("expected error with only 3 valid signatures")
	}
}

func TestValidateSignaturesCryptoWrongSig(t *testing.T) {
	text, certs := buildSignedConsensus(t, 5)
	// Corrupt one signature in the text
	text = strings.Replace(text, "-----BEGIN SIGNATURE-----\n", "-----BEGIN SIGNATURE-----\nAAAA", 1)
	// Now we have at most 4 valid sigs
	if err := ValidateSignatures(text, certs); err == nil {
		t.Fatal("expected error with corrupted signature")
	}
}

func TestValidateSignaturesIgnoresUnknownAlgorithm(t *testing.T) {
	// Build 5 signatures but with unknown algorithm — should all be ignored
	var sigs []string
	i := 0
	for fp := range dirAuthorityFingerprints {
		sigs = append(sigs, fmt.Sprintf("directory-signature blake2b %s AABBCCDD\n-----BEGIN SIGNATURE-----\nfake\n-----END SIGNATURE-----", fp))
		i++
		if i >= 5 {
			break
		}
	}
	text := "network-status-version 3 microdesc\n" + strings.Join(sigs, "\n") + "\n"
	// Even with certs, unknown algorithm sigs should be ignored
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certs := []KeyCert{{SigningKey: &key.PublicKey, IdentityFingerprint: "AAAA", SigningKeyDigest: "BBBB"}}
	if err := ValidateSignatures(text, certs); err == nil {
		t.Fatal("expected error — unknown algorithm sigs should be ignored")
	}
}

func TestParseConsensusEmpty(t *testing.T) {
	c, err := ParseConsensus("")
	if err != nil {
		t.Fatalf("ParseConsensus empty: %v", err)
	}
	if len(c.Relays) != 0 {
		t.Fatalf("expected 0 relays, got %d", len(c.Relays))
	}
}
