package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"net"
	"testing"
	"time"
)

// buildTestTorCert creates a valid Ed25519 Tor certificate for testing.
func buildTestTorCert(certType uint8, keyType uint8, certifiedKey [32]byte, signingPrivKey ed25519.PrivateKey) []byte {
	// Header: version(1) + cert_type(1) + expiration(4) + key_type(1) + certified_key(32) = 39
	// Extensions: n_ext(1) + ext(2+1+1+32 = 36) = 37
	// Signature: 64
	// Total: 39 + 37 + 64 = 140
	buf := make([]byte, 0, 140)
	buf = append(buf, 0x01)     // version
	buf = append(buf, certType) // cert type
	// Expiration: 1 year from now in hours
	expHours := uint32(time.Now().Add(365*24*time.Hour).Unix() / 3600)
	var expBuf [4]byte
	binary.BigEndian.PutUint32(expBuf[:], expHours)
	buf = append(buf, expBuf[:]...)
	buf = append(buf, keyType) // key type
	buf = append(buf, certifiedKey[:]...)

	// Extensions: 1 extension (signed-with-ed25519-key, type 0x04)
	buf = append(buf, 0x01) // n_extensions = 1
	// ExtLen = 32 (ed25519 key), ExtType = 0x04, ExtFlags = 0x00
	var extLenBuf [2]byte
	binary.BigEndian.PutUint16(extLenBuf[:], 32)
	buf = append(buf, extLenBuf[:]...)
	buf = append(buf, 0x04) // ExtType
	buf = append(buf, 0x00) // ExtFlags
	signingPubKey := signingPrivKey.Public().(ed25519.PublicKey)
	buf = append(buf, signingPubKey...)

	// Sign everything so far
	sig := ed25519.Sign(signingPrivKey, buf)
	buf = append(buf, sig...)
	return buf
}

func TestParseTorCertValid(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	var certifiedKey [32]byte
	copy(certifiedKey[:], "test-certified-key-32-bytes!!!!!")
	certData := buildTestTorCert(0x04, 0x01, certifiedKey, privKey)

	tc, err := parseTorCert(certData)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if tc.CertType != 0x04 {
		t.Fatalf("cert type: got %d, want 4", tc.CertType)
	}
	if tc.CertifiedKey != certifiedKey {
		t.Fatal("certified key mismatch")
	}
	if err := tc.verify(nil); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestParseTorCertExpired(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	var certifiedKey [32]byte
	certData := buildTestTorCert(0x04, 0x01, certifiedKey, privKey)
	// Set expiration to the past
	binary.BigEndian.PutUint32(certData[2:6], 1) // hour 1 since epoch = 1970
	// Re-sign
	sig := ed25519.Sign(privKey, certData[:len(certData)-64])
	copy(certData[len(certData)-64:], sig)

	tc, err := parseTorCert(certData)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if err := tc.verify(nil); err == nil {
		t.Fatal("expected expiration error")
	}
}

func TestParseTorCertBadSignature(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	var certifiedKey [32]byte
	certData := buildTestTorCert(0x04, 0x01, certifiedKey, privKey)
	// Corrupt signature
	certData[len(certData)-1] ^= 0xFF

	tc, err := parseTorCert(certData)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if err := tc.verify(nil); err == nil {
		t.Fatal("expected signature error")
	}
}

func TestValidateCertsChain(t *testing.T) {
	// Generate identity and signing keypairs
	identityPub, identityPriv, _ := ed25519.GenerateKey(rand.Reader)
	signingPub, signingPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Fake TLS cert DER
	fakeTLSDER := []byte("fake-tls-certificate-der-data-for-testing")
	tlsHash := sha256.Sum256(fakeTLSDER)

	// CertType 4: identity signs signing key
	var signingKey32 [32]byte
	copy(signingKey32[:], signingPub)
	cert4Data := buildTestTorCert(0x04, 0x01, signingKey32, identityPriv)

	// CertType 5: signing key certifies TLS cert hash (no extension needed, signing key provided externally)
	cert5Data := buildTestTorCertNoExtension(0x05, 0x03, tlsHash, signingPriv)

	// Build CERTS cell payload
	payload := buildCertsPayload([]certEntry{
		{certType: 4, data: cert4Data},
		{certType: 5, data: cert5Data},
	})

	idKey, err := validateCerts(payload, tlsHash[:], newTestLogger())
	if err != nil {
		t.Fatalf("validateCerts failed: %v", err)
	}
	if !equal(idKey, identityPub) {
		t.Fatal("identity key mismatch")
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildTestTorCertNoExtension creates a cert without extension 0x04.
func buildTestTorCertNoExtension(certType uint8, keyType uint8, certifiedKey [32]byte, signingPrivKey ed25519.PrivateKey) []byte {
	buf := make([]byte, 0, 104) // 39 + 1 (no extensions) + 64
	buf = append(buf, 0x01)
	buf = append(buf, certType)
	expHours := uint32(time.Now().Add(365*24*time.Hour).Unix() / 3600)
	var expBuf [4]byte
	binary.BigEndian.PutUint32(expBuf[:], expHours)
	buf = append(buf, expBuf[:]...)
	buf = append(buf, keyType)
	buf = append(buf, certifiedKey[:]...)
	buf = append(buf, 0x00) // n_extensions = 0
	sig := ed25519.Sign(signingPrivKey, buf)
	buf = append(buf, sig...)
	return buf
}

type certEntry struct {
	certType uint8
	data     []byte
}

func buildCertsPayload(certs []certEntry) []byte {
	var buf []byte
	buf = append(buf, uint8(len(certs)))
	for _, c := range certs {
		buf = append(buf, c.certType)
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(c.data)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, c.data...)
	}
	return buf
}

func TestParseTorCertRejectsUnrecognizedCriticalExtension(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	var certifiedKey [32]byte
	copy(certifiedKey[:], "test-certified-key-32-bytes!!!!!")

	// Build cert with an unrecognized extension (type 0xFF) with AFFECTS_VALIDATION flag set
	buf := make([]byte, 0, 160)
	buf = append(buf, 0x01) // version
	buf = append(buf, 0x04) // cert type
	expHours := uint32(time.Now().Add(365*24*time.Hour).Unix() / 3600)
	var expBuf [4]byte
	binary.BigEndian.PutUint32(expBuf[:], expHours)
	buf = append(buf, expBuf[:]...)
	buf = append(buf, 0x01) // key type
	buf = append(buf, certifiedKey[:]...)
	buf = append(buf, 0x01) // n_extensions = 1
	// Unknown extension with AFFECTS_VALIDATION
	var extLenBuf [2]byte
	binary.BigEndian.PutUint16(extLenBuf[:], 4) // 4 bytes of data
	buf = append(buf, extLenBuf[:]...)
	buf = append(buf, 0xFF)                   // ExtType = unknown
	buf = append(buf, 0x01)                   // ExtFlags = AFFECTS_VALIDATION
	buf = append(buf, 0xDE, 0xAD, 0xBE, 0xEF) // ExtData
	sig := ed25519.Sign(privKey, buf)
	buf = append(buf, sig...)

	_, err := parseTorCert(buf)
	if err == nil {
		t.Fatal("expected rejection of unrecognized critical extension, got nil")
	}
}

func TestParseTorCertAllowsUnrecognizedNonCriticalExtension(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	var certifiedKey [32]byte
	copy(certifiedKey[:], "test-certified-key-32-bytes!!!!!")

	// Build cert with unrecognized extension WITHOUT AFFECTS_VALIDATION
	buf := make([]byte, 0, 160)
	buf = append(buf, 0x01)
	buf = append(buf, 0x04)
	expHours := uint32(time.Now().Add(365*24*time.Hour).Unix() / 3600)
	var expBuf [4]byte
	binary.BigEndian.PutUint32(expBuf[:], expHours)
	buf = append(buf, expBuf[:]...)
	buf = append(buf, 0x01)
	buf = append(buf, certifiedKey[:]...)
	buf = append(buf, 0x02) // n_extensions = 2
	// Extension 1: signing key (type 0x04)
	var extLenBuf [2]byte
	binary.BigEndian.PutUint16(extLenBuf[:], 32)
	buf = append(buf, extLenBuf[:]...)
	buf = append(buf, 0x04)
	buf = append(buf, 0x00)
	signingPubKey := privKey.Public().(ed25519.PublicKey)
	buf = append(buf, signingPubKey...)
	// Extension 2: unknown type, no AFFECTS_VALIDATION
	binary.BigEndian.PutUint16(extLenBuf[:], 4)
	buf = append(buf, extLenBuf[:]...)
	buf = append(buf, 0xFE) // ExtType = unknown
	buf = append(buf, 0x00) // ExtFlags = 0 (not critical)
	buf = append(buf, 0xDE, 0xAD, 0xBE, 0xEF)
	sig := ed25519.Sign(privKey, buf)
	buf = append(buf, sig...)

	tc, err := parseTorCert(buf)
	if err != nil {
		t.Fatalf("expected non-critical extension to be allowed, got: %v", err)
	}
	if err := tc.verify(nil); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func newTestLogger() *slog.Logger {
	return slog.Default()
}

func TestClaimAndReleaseCircID(t *testing.T) {
	l := &Link{}

	// First claim should succeed
	if !l.ClaimCircID(0x80000001) {
		t.Fatal("first claim should succeed")
	}
	// Duplicate claim should fail
	if l.ClaimCircID(0x80000001) {
		t.Fatal("duplicate claim should fail")
	}
	// Different ID should succeed
	if !l.ClaimCircID(0x80000002) {
		t.Fatal("different ID claim should succeed")
	}

	// Release and re-claim
	l.ReleaseCircID(0x80000001)
	if !l.ClaimCircID(0x80000001) {
		t.Fatal("re-claim after release should succeed")
	}
}

func TestNegotiateVersion(t *testing.T) {
	tests := []struct {
		name     string
		server   []uint16
		expected uint16
	}{
		{"both v4 and v5", []uint16{3, 4, 5}, 5},
		{"only v4", []uint16{3, 4}, 4},
		{"no common", []uint16{1, 2, 3}, 0},
		{"empty", []uint16{}, 0},
		{"v5 only", []uint16{5}, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := negotiateVersion(tt.server)
			if got != tt.expected {
				t.Fatalf("negotiateVersion(%v) = %d, want %d", tt.server, got, tt.expected)
			}
		})
	}
}

func TestBuildNetInfo(t *testing.T) {
	ip := net.ParseIP("1.2.3.4").To4()
	c := buildNetInfo(ip)

	p := c.Payload()
	// Timestamp should be zero (avoid fingerprinting)
	if p[0] != 0 || p[1] != 0 || p[2] != 0 || p[3] != 0 {
		t.Fatal("timestamp should be zero")
	}
	// ATYPE = IPv4 (0x04)
	if p[4] != 0x04 {
		t.Fatalf("ATYPE = %d, want 4", p[4])
	}
	// ALEN = 4
	if p[5] != 0x04 {
		t.Fatalf("ALEN = %d, want 4", p[5])
	}
	// IP address
	if p[6] != 1 || p[7] != 2 || p[8] != 3 || p[9] != 4 {
		t.Fatalf("IP = %d.%d.%d.%d, want 1.2.3.4", p[6], p[7], p[8], p[9])
	}
	// NMYADDR = 0
	if p[10] != 0 {
		t.Fatalf("NMYADDR = %d, want 0", p[10])
	}
}
