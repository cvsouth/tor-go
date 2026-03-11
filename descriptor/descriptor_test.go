package descriptor

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

// buildSignedDescriptor generates a relay descriptor with a valid RSA-2048
// signing key, SHA-1 fingerprint, and PKCS#1 v1.5 signature. The signed
// content spans from "router " through "router-signature\n" (inclusive).
// Returns the descriptor text and the private key used for signing.
func buildSignedDescriptor(t testing.TB) (string, *rsa.PrivateKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Encode the public key as PKCS#1 PEM (what Tor uses for signing-key)
	derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	})

	// Compute SHA-1 fingerprint of the DER-encoded public key
	fpHash := sha1.Sum(derBytes)
	fpHex := strings.ToUpper(hex.EncodeToString(fpHash[:]))

	// Format fingerprint with spaces (4-char groups)
	var fpParts []string
	for i := 0; i < len(fpHex); i += 4 {
		fpParts = append(fpParts, fpHex[i:i+4])
	}
	fpSpaced := strings.Join(fpParts, " ")

	// Generate a fake ntor onion key (32 random bytes, base64-encoded)
	var ntorKey [32]byte
	if _, err := rand.Read(ntorKey[:]); err != nil {
		t.Fatalf("generate ntor key: %v", err)
	}
	ntorB64 := base64.RawStdEncoding.EncodeToString(ntorKey[:])

	// Build the descriptor text up to and including "router-signature\n"
	var sb strings.Builder
	sb.WriteString("router TestRelay 192.168.1.1 9001 0 0\n")
	fmt.Fprintf(&sb, "fingerprint %s\n", fpSpaced)
	sb.WriteString("signing-key\n")
	sb.WriteString(string(pemBlock))
	fmt.Fprintf(&sb, "ntor-onion-key %s\n", ntorB64)
	sb.WriteString("router-signature\n")

	signedContent := sb.String()

	// Sign: SHA-1 of the signed content, then PKCS#1 v1.5 with crypto.Hash(0)
	digest := sha1.Sum([]byte(signedContent))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.Hash(0), digest[:])
	if err != nil {
		t.Fatalf("sign descriptor: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Append the signature PEM block
	sb.WriteString("-----BEGIN SIGNATURE-----\n")
	// Wrap at 64 chars per line (standard PEM)
	for i := 0; i < len(sigB64); i += 64 {
		end := i + 64
		if end > len(sigB64) {
			end = len(sigB64)
		}
		sb.WriteString(sigB64[i:end])
		sb.WriteString("\n")
	}
	sb.WriteString("-----END SIGNATURE-----\n")

	return sb.String(), privKey
}

func TestParseDescriptor(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	info, err := ParseDescriptor(desc)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}

	if info.Address != "192.168.1.1" {
		t.Fatalf("address: got %s, want 192.168.1.1", info.Address)
	}
	if info.ORPort != 9001 {
		t.Fatalf("port: got %d, want 9001", info.ORPort)
	}
	if info.Fingerprint == "" {
		t.Fatal("fingerprint is empty")
	}

	// Verify fingerprint is valid hex
	fpBytes, err := hex.DecodeString(info.Fingerprint)
	if err != nil {
		t.Fatalf("fingerprint not valid hex: %v", err)
	}
	if len(fpBytes) != 20 {
		t.Fatalf("fingerprint wrong length: %d", len(fpBytes))
	}

	// ntor key should be 32 non-zero bytes
	allZero := true
	for _, b := range info.NtorOnionKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("ntor onion key is all zeros")
	}
}

func TestParseDescriptorSigningKeyField(t *testing.T) {
	desc, privKey := buildSignedDescriptor(t)
	info, err := ParseDescriptor(desc)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}

	// SigningKey must be non-nil and match the key we generated
	if info.SigningKey == nil {
		t.Fatal("SigningKey is nil")
	}
	if info.SigningKey.N.Cmp(privKey.N) != 0 {
		t.Fatal("SigningKey.N does not match the generated key")
	}
	if info.SigningKey.E != privKey.E {
		t.Fatal("SigningKey.E does not match the generated key")
	}

	// Verify SigningKey was parsed via x509.ParsePKCS1PublicKey by re-encoding and comparing
	derExpected := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	derActual := x509.MarshalPKCS1PublicKey(info.SigningKey)
	if len(derExpected) != len(derActual) {
		t.Fatalf("DER lengths differ: got %d, want %d", len(derActual), len(derExpected))
	}
	for i := range derExpected {
		if derExpected[i] != derActual[i] {
			t.Fatalf("DER byte %d differs: got %02x, want %02x", i, derActual[i], derExpected[i])
		}
	}
}

func TestParseDescriptorSignatureBytesField(t *testing.T) {
	desc, privKey := buildSignedDescriptor(t)
	info, err := ParseDescriptor(desc)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}

	// SignatureBytes must be non-nil and non-empty
	if info.SignatureBytes == nil {
		t.Fatal("SignatureBytes is nil")
	}
	if len(info.SignatureBytes) == 0 {
		t.Fatal("SignatureBytes is empty")
	}

	// Independently verify the signature bytes match what we'd extract manually
	expectedSigBytes := extractSigBytes(t, desc)
	if len(info.SignatureBytes) != len(expectedSigBytes) {
		t.Fatalf("SignatureBytes length: got %d, want %d", len(info.SignatureBytes), len(expectedSigBytes))
	}
	for i := range expectedSigBytes {
		if info.SignatureBytes[i] != expectedSigBytes[i] {
			t.Fatalf("SignatureBytes[%d]: got %02x, want %02x", i, info.SignatureBytes[i], expectedSigBytes[i])
		}
	}

	// Verify the signature bytes can be used to verify the descriptor independently
	startIdx := strings.Index(desc, "router ")
	marker := "router-signature\n"
	endIdx := strings.Index(desc, marker)
	signedContent := desc[startIdx : endIdx+len(marker)]
	digest := sha1.Sum([]byte(signedContent))
	if err := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.Hash(0), digest[:], info.SignatureBytes); err != nil {
		t.Fatalf("signature verification with extracted bytes failed: %v", err)
	}
}

func TestParseDescriptorMissingSigningKeyError(t *testing.T) {
	// A descriptor without signing-key should return error containing "signing-key"
	desc := "router Test 1.2.3.4 9001 0 0\n" +
		"fingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\n" +
		"ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"router-signature\n" +
		"-----BEGIN SIGNATURE-----\n" +
		"AAAA\n" +
		"-----END SIGNATURE-----\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for missing signing-key")
	}
	if !strings.Contains(err.Error(), "signing-key") {
		t.Fatalf("error should contain 'signing-key', got: %v", err)
	}
}

func TestParseDescriptorMissingRouterSignatureError(t *testing.T) {
	// A descriptor without router-signature should return error containing "router-signature"
	desc := "router Test 1.2.3.4 9001 0 0\n" +
		"fingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\n" +
		"ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"signing-key\n" +
		"-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAL5a6IOSbS4KCJG6VJuXmXkFfN8vVGrBxIGECKpjlTiJVuGCGhk\n" +
		"-----END RSA PUBLIC KEY-----\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for missing router-signature")
	}
	if !strings.Contains(err.Error(), "router-signature") {
		t.Fatalf("error should contain 'router-signature', got: %v", err)
	}
}

func TestParseDescriptorMissingFields(t *testing.T) {
	_, err := ParseDescriptor("router Test 1.2.3.4 9001 0 0\n")
	if err == nil {
		t.Fatal("expected error for missing fingerprint")
	}
}

func TestParseDescriptorBadNtorKey(t *testing.T) {
	desc := "router Test 1.2.3.4 9001 0 0\nfingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\nntor-onion-key !!!invalid-base64!!!\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for bad ntor-onion-key")
	}
}

func TestParseDescriptorShortNtorKey(t *testing.T) {
	desc := "router Test 1.2.3.4 9001 0 0\nfingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\nntor-onion-key AQID\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for short ntor-onion-key")
	}
}

func TestParseDescriptorCorruptedSignature(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Prepend valid base64 ("AAAA..." = zero bytes) after the BEGIN marker,
	// which changes the decoded signature bytes and causes RSA verification failure.
	desc = strings.Replace(desc, "-----BEGIN SIGNATURE-----\n", "-----BEGIN SIGNATURE-----\nAAAAAAAAAAAA", 1)
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for corrupted signature")
	}
	if !strings.Contains(err.Error(), "signature verification") && !strings.Contains(err.Error(), "router-signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorMissingSigningKey(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Remove the signing-key section
	idx := strings.Index(desc, "signing-key\n")
	endIdx := strings.Index(desc[idx:], "-----END RSA PUBLIC KEY-----\n")
	desc = desc[:idx] + desc[idx+endIdx+len("-----END RSA PUBLIC KEY-----\n"):]
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for missing signing-key")
	}
	if !strings.Contains(err.Error(), "signing-key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorMissingRouterSignature(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Remove everything from "router-signature\n" onward
	idx := strings.Index(desc, "router-signature\n")
	desc = desc[:idx]
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for missing router-signature")
	}
	if !strings.Contains(err.Error(), "router-signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorFingerprintMismatch(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Replace the fingerprint with a different value
	lines := strings.Split(desc, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "fingerprint ") {
			lines[i] = "fingerprint DEAD BEEF 0000 1111 2222 3333 4444 5555 6666 7777"
			break
		}
	}
	desc = strings.Join(lines, "\n")
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for fingerprint mismatch")
	}
	if !strings.Contains(err.Error(), "fingerprint") || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorMalformedSigningKeyPEM(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Corrupt the PEM block content
	desc = strings.Replace(desc, "-----BEGIN RSA PUBLIC KEY-----\n", "-----BEGIN RSA PUBLIC KEY-----\n!!!CORRUPT!!!\n", 1)
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for malformed signing-key PEM")
	}
}

func TestParseDescriptorPEMAccumulation(t *testing.T) {
	// Verify that the line-based PEM accumulation correctly handles
	// signing-key and router-signature blocks with varying line counts.
	desc, privKey := buildSignedDescriptor(t)
	info, err := ParseDescriptor(desc)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}

	// The signing key from parsing should match the key we generated
	derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	fpHash := sha1.Sum(derBytes)
	expectedFP := strings.ToUpper(hex.EncodeToString(fpHash[:]))
	if info.Fingerprint != expectedFP {
		t.Fatalf("fingerprint: got %s, want %s", info.Fingerprint, expectedFP)
	}
}

func TestParseDescriptorSigningKeyTruncatedPEM(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Remove the END marker from the signing-key PEM block
	desc = strings.Replace(desc, "-----END RSA PUBLIC KEY-----\n", "", 1)
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for truncated signing-key PEM")
	}
}

func TestParseDescriptorSignatureTruncatedPEM(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Remove the END marker from the signature block
	desc = strings.Replace(desc, "-----END SIGNATURE-----\n", "", 1)
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for truncated signature PEM")
	}
}

func TestParseDescriptorSignatureInvalidBase64(t *testing.T) {
	desc, _ := buildSignedDescriptor(t)
	// Replace the signature content with invalid base64
	beginMarker := "-----BEGIN SIGNATURE-----\n"
	endMarker := "-----END SIGNATURE-----"
	beginIdx := strings.Index(desc, beginMarker)
	endIdx := strings.Index(desc, endMarker)
	desc = desc[:beginIdx+len(beginMarker)] + "!!!not-base64!!!\n" + desc[endIdx:]
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for invalid base64 in signature")
	}
	if !strings.Contains(err.Error(), "router-signature") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorMalformedRouterLine(t *testing.T) {
	// router line with too few fields should error
	desc := "router Test 1.2.3.4\nfingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\nntor-onion-key AQID\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for malformed router line")
	}
	if !strings.Contains(err.Error(), "malformed router line") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorBadORPort(t *testing.T) {
	desc := "router Test 1.2.3.4 notaport 0 0\nfingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\nntor-onion-key AQID\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for bad OR port")
	}
	if !strings.Contains(err.Error(), "OR port") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorWrongKeySignature(t *testing.T) {
	// Build a valid descriptor, then re-sign with a different key
	desc, _ := buildSignedDescriptor(t)

	// Generate a second key
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}

	// Extract signed content and re-sign with wrong key
	startIdx := strings.Index(desc, "router ")
	marker := "router-signature\n"
	endIdx := strings.Index(desc, marker)
	signedContent := desc[startIdx : endIdx+len(marker)]

	digest := sha1.Sum([]byte(signedContent))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, otherKey, crypto.Hash(0), digest[:])
	if err != nil {
		t.Fatalf("sign with wrong key: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Replace signature block
	beginMarker := "-----BEGIN SIGNATURE-----\n"
	beginIdx := strings.Index(desc, beginMarker)
	var sb strings.Builder
	sb.WriteString(desc[:beginIdx+len(beginMarker)])
	for i := 0; i < len(sigB64); i += 64 {
		end := i + 64
		if end > len(sigB64) {
			end = len(sigB64)
		}
		sb.WriteString(sigB64[i:end])
		sb.WriteString("\n")
	}
	sb.WriteString("-----END SIGNATURE-----\n")
	desc = sb.String()

	_, err = ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for wrong-key signature")
	}
	if !strings.Contains(err.Error(), "signature verification") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorBadFingerprintHex(t *testing.T) {
	desc := "router Test 1.2.3.4 9001 0 0\nfingerprint ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ\nntor-onion-key AQID\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for bad fingerprint hex")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseDescriptorShortFingerprint(t *testing.T) {
	desc := "router Test 1.2.3.4 9001 0 0\nfingerprint ABCD EF01\nntor-onion-key AQID\n"
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error for short fingerprint")
	}
	if !strings.Contains(err.Error(), "fingerprint wrong length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractSignedContentMissingRouter(t *testing.T) {
	_, err := extractSignedContent("no-router-line\nrouter-signature\n")
	if err == nil {
		t.Fatal("expected error for missing 'router '")
	}
	if !strings.Contains(err.Error(), "'router ' not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractSignedContentRouterNotAtLineStart(t *testing.T) {
	// "router " appears mid-line — should be rejected
	_, err := extractSignedContent("somethrouter foo\nrouter-signature\n")
	if err == nil {
		t.Fatal("expected error when 'router ' is not at start of line")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractSignedContentRouterSignatureNotAtLineStart(t *testing.T) {
	// "router-signature\n" appears mid-line — should be rejected
	_, err := extractSignedContent("router foo\nxrouter-signature\n")
	if err == nil {
		t.Fatal("expected error when 'router-signature' is not at start of line")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractSignedContentAnchored(t *testing.T) {
	// Both markers at start of line — should succeed
	content, err := extractSignedContent("router foo bar 9001 0 0\nstuff\nrouter-signature\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(content, "router ") {
		t.Fatal("content should start with 'router '")
	}
	if !strings.HasSuffix(content, "router-signature\n") {
		t.Fatal("content should end with 'router-signature\\n'")
	}
}

func TestExtractSignedContentMissingRouterSignature(t *testing.T) {
	_, err := extractSignedContent("router Test 1.2.3.4 9001 0 0\nno-sig-line\n")
	if err == nil {
		t.Fatal("expected error for missing 'router-signature'")
	}
	if !strings.Contains(err.Error(), "'router-signature' not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyDescriptorCryptoChainE2E(t *testing.T) {
	// End-to-end: build a descriptor, parse it, verify all crypto properties hold
	desc, privKey := buildSignedDescriptor(t)
	info, err := ParseDescriptor(desc)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}

	// Independently verify the fingerprint matches the signing key
	derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	fpHash := sha1.Sum(derBytes)
	expectedFP := strings.ToUpper(hex.EncodeToString(fpHash[:]))
	if info.Fingerprint != expectedFP {
		t.Fatalf("fingerprint mismatch: got %s, want %s", info.Fingerprint, expectedFP)
	}

	// Independently verify NodeID matches SHA-1 of DER
	if info.NodeID != fpHash {
		t.Fatal("NodeID does not match SHA-1 of signing key DER bytes")
	}

	// Independently verify the signed content and signature
	startIdx := strings.Index(desc, "router ")
	marker := "router-signature\n"
	endIdx := strings.Index(desc, marker)
	signedContent := desc[startIdx : endIdx+len(marker)]
	digest := sha1.Sum([]byte(signedContent))

	// Verify with the public key directly
	if err := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.Hash(0), digest[:], extractSigBytes(t, desc)); err != nil {
		t.Fatalf("independent signature verification failed: %v", err)
	}
}

func TestPEMAccumulationSizeLimit(t *testing.T) {
	// Build a descriptor with a signing-key PEM block that exceeds 8KB
	var sb strings.Builder
	sb.WriteString("router Test 1.2.3.4 9001 0 0\n")
	sb.WriteString("fingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\n")
	sb.WriteString("ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
	sb.WriteString("signing-key\n")
	sb.WriteString("-----BEGIN RSA PUBLIC KEY-----\n")
	// Write >8KB of fake PEM data
	for i := 0; i < 200; i++ {
		sb.WriteString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n") // 64 chars + newline
	}
	sb.WriteString("-----END RSA PUBLIC KEY-----\n")
	sb.WriteString("router-signature\n")
	sb.WriteString("-----BEGIN SIGNATURE-----\n")
	sb.WriteString("AAAA\n")
	sb.WriteString("-----END SIGNATURE-----\n")

	_, err := ParseDescriptor(sb.String())
	if err == nil {
		t.Fatal("expected error for oversized PEM block")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPEMEndMarkerWithCRLF(t *testing.T) {
	// Build a valid descriptor but use \r\n on the signature END marker.
	// The signing-key END marker is inside the signed content, so adding \r
	// there would change the hash. Only the signature block END marker
	// (which is outside signed content) can safely have \r\n.
	desc, _ := buildSignedDescriptor(t)
	desc = strings.Replace(desc, "-----END SIGNATURE-----\n", "-----END SIGNATURE-----\r\n", 1)
	info, err := ParseDescriptor(desc)
	if err != nil {
		t.Fatalf("ParseDescriptor with CRLF signature end marker: %v", err)
	}
	if info.Address != "192.168.1.1" {
		t.Fatalf("address: got %s, want 192.168.1.1", info.Address)
	}
}

func TestPEMEndMarkerWithCRLFSigningKey(t *testing.T) {
	// Verify that a signing-key PEM block with \r on the END marker
	// is correctly detected (the line "-----END RSA PUBLIC KEY-----\r"
	// should match after \r trim).
	// We can't test this with full signature verification because the
	// \r changes the signed content hash, so we test parsing only.
	desc := "router Test 1.2.3.4 9001 0 0\n" +
		"fingerprint ABCD EF01 2345 6789 ABCD EF01 2345 6789 ABCD EF01\n" +
		"ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"signing-key\n" +
		"-----BEGIN RSA PUBLIC KEY-----\n" +
		"MIGJAoGBAL5a6IOSbS4KCJG6VJuXmXkFfN8vVGrBxIGECKpjlTiJVuGCGhk\n" +
		"-----END RSA PUBLIC KEY-----\r\n" +
		"router-signature\n" +
		"-----BEGIN SIGNATURE-----\n" +
		"AAAA\n" +
		"-----END SIGNATURE-----\n"

	// This will fail on crypto validation, but it should get past PEM parsing.
	// If the \r trim didn't work, it would fail with "PEM block not found or incomplete".
	_, err := ParseDescriptor(desc)
	if err == nil {
		t.Fatal("expected error (crypto validation), but PEM parsing should have succeeded")
	}
	// The error should be about crypto, not about missing PEM block
	if strings.Contains(err.Error(), "PEM block not found or incomplete") {
		t.Fatalf("PEM end marker with \\r was not recognized: %v", err)
	}
}

func TestExtractSignedContentCRLF(t *testing.T) {
	// Verify that extractSignedContent works when the text uses CRLF line endings.
	// Without normalization, "router-signature\n" won't match "router-signature\r\n",
	// producing a confusing "router-signature not found" error.
	lfText := "router foo bar 9001 0 0\nstuff\nrouter-signature\n"
	crlfText := strings.ReplaceAll(lfText, "\n", "\r\n")

	content, err := extractSignedContent(crlfText)
	if err != nil {
		t.Fatalf("extractSignedContent with CRLF: %v", err)
	}
	if !strings.HasPrefix(content, "router ") {
		t.Fatal("content should start with 'router '")
	}
	if !strings.HasSuffix(content, "router-signature\n") {
		t.Fatal("content should end with 'router-signature\\n' after normalization")
	}
}

// extractSigBytes extracts the raw signature bytes from a descriptor for testing.
func extractSigBytes(t testing.TB, desc string) []byte {
	t.Helper()
	beginMarker := "-----BEGIN SIGNATURE-----\n"
	endMarker := "-----END SIGNATURE-----"
	beginIdx := strings.Index(desc, beginMarker)
	endIdx := strings.Index(desc, endMarker)
	if beginIdx < 0 || endIdx < 0 {
		t.Fatal("signature block not found")
	}
	b64 := desc[beginIdx+len(beginMarker) : endIdx]
	b64 = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(b64)
	sigBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode signature base64: %v", err)
	}
	return sigBytes
}
