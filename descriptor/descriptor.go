package descriptor

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
)

// RelayInfo contains the parsed relay descriptor fields needed for ntor handshake.
type RelayInfo struct {
	NodeID         [20]byte       // SHA-1 of relay's RSA identity key
	NtorOnionKey   [32]byte       // Curve25519 public key
	Address        string         // IP address
	ORPort         uint16         // OR port
	Fingerprint    string         // Hex fingerprint string (uppercase, no spaces)
	SigningKey     *rsa.PublicKey // RSA public key from the signing-key PEM block
	SignatureBytes []byte         // Raw bytes from the router-signature PEM block
}

// pemAccumulator tracks state for accumulating multi-line PEM blocks.
type pemAccumulator int

const (
	pemNone       pemAccumulator = iota
	pemSigningKey                // accumulating signing-key PEM block
	pemSignature                 // accumulating router-signature PEM block
)

// ParseDescriptor parses a relay server descriptor text, verifies the RSA
// signature and fingerprint cross-check, and extracts RelayInfo.
func ParseDescriptor(text string) (*RelayInfo, error) {
	info, signingKey, derBytes, sigBytes, err := parseDescriptorFields(text)
	if err != nil {
		return nil, err
	}

	// Verify fingerprint: SHA-1 of signing key DER must match the fingerprint field
	if err := verifyDescriptorFingerprint(derBytes, info.Fingerprint); err != nil {
		return nil, err
	}

	// Verify RSA signature: signed content is from "router " through "router-signature\n"
	if err := verifyDescriptorSignature(text, signingKey, sigBytes); err != nil {
		return nil, err
	}

	info.SigningKey = signingKey
	info.SignatureBytes = sigBytes

	return info, nil
}

// maxPEMBytes is the upper bound on accumulated PEM data (8 KB).
const maxPEMBytes = 8 * 1024

// descriptorParseState holds state accumulated during line-by-line descriptor parsing.
type descriptorParseState struct {
	info           *RelayInfo
	accumState     pemAccumulator
	signingKeyPEM  strings.Builder
	signaturePEM   strings.Builder
	hasRouter      bool
	hasFingerprint bool
	hasNtorKey     bool
	hasSigningKey  bool
	hasSignature   bool
}

// parseDescriptorFields parses all descriptor fields using line-by-line iteration,
// including multi-line PEM blocks for signing-key and router-signature.
// Returns the parsed RelayInfo, the RSA signing key, its DER bytes, and the signature bytes.
func parseDescriptorFields(text string) (*RelayInfo, *rsa.PublicKey, []byte, []byte, error) {
	s := &descriptorParseState{info: &RelayInfo{}}

	for _, line := range strings.Split(text, "\n") {
		if err := s.parseLine(line); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	if err := s.validateRequired(); err != nil {
		return nil, nil, nil, nil, err
	}

	signingKey, derBytes, err := parseSigningKeyPEM(s.signingKeyPEM.String())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sigBytes, err := parseSignaturePEM(s.signaturePEM.String())
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return s.info, signingKey, derBytes, sigBytes, nil
}

// parseLine handles a single line of descriptor text, including PEM accumulation.
func (s *descriptorParseState) parseLine(line string) error {
	if s.accumState != pemNone {
		return s.accumulatePEM(line)
	}
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "router "):
		if err := parseRouterLine(s.info, trimmed); err != nil {
			return err
		}
		s.hasRouter = true
	case strings.HasPrefix(trimmed, "fingerprint "):
		if err := parseFingerprintLine(s.info, trimmed); err != nil {
			return err
		}
		s.hasFingerprint = true
	case strings.HasPrefix(trimmed, "ntor-onion-key "):
		if err := parseNtorKeyLine(s.info, trimmed); err != nil {
			return err
		}
		s.hasNtorKey = true
	case trimmed == "signing-key":
		s.accumState = pemSigningKey
	case trimmed == "router-signature":
		s.accumState = pemSignature
	}
	return nil
}

// accumulatePEM appends a line to the active PEM block and checks for end markers.
func (s *descriptorParseState) accumulatePEM(line string) error {
	var buf *strings.Builder
	var endMarker string
	var done *bool
	switch s.accumState {
	case pemSigningKey:
		buf = &s.signingKeyPEM
		endMarker = "-----END RSA PUBLIC KEY-----"
		done = &s.hasSigningKey
	case pemSignature:
		buf = &s.signaturePEM
		endMarker = "-----END SIGNATURE-----"
		done = &s.hasSignature
	default:
		return nil
	}
	buf.WriteString(line)
	buf.WriteString("\n")
	if buf.Len() > maxPEMBytes {
		return fmt.Errorf("%s: PEM block exceeds %d bytes", pemLabel(s.accumState), maxPEMBytes)
	}
	if strings.TrimRight(line, "\r") == endMarker {
		s.accumState = pemNone
		*done = true
	}
	return nil
}

func pemLabel(state pemAccumulator) string {
	if state == pemSigningKey {
		return "signing-key"
	}
	return "router-signature"
}

// validateRequired checks that all required fields were found during parsing.
func (s *descriptorParseState) validateRequired() error {
	switch {
	case !s.hasRouter:
		return fmt.Errorf("missing router line")
	case !s.hasFingerprint:
		return fmt.Errorf("missing fingerprint line")
	case !s.hasNtorKey:
		return fmt.Errorf("missing ntor-onion-key line")
	case !s.hasSigningKey:
		return fmt.Errorf("signing-key: PEM block not found or incomplete")
	case !s.hasSignature:
		return fmt.Errorf("router-signature: PEM block not found or incomplete")
	}
	return nil
}

// parseSigningKeyPEM decodes a signing-key PEM block and returns the RSA public key and DER bytes.
func parseSigningKeyPEM(pemText string) (*rsa.PublicKey, []byte, error) {
	pemBlock, _ := pem.Decode([]byte(pemText))
	if pemBlock == nil {
		return nil, nil, fmt.Errorf("signing-key: failed to decode PEM block")
	}
	signingKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("signing-key: %w", err)
	}
	return signingKey, pemBlock.Bytes, nil
}

// parseSignaturePEM extracts and base64-decodes the signature bytes from a SIGNATURE PEM block.
func parseSignaturePEM(pemText string) ([]byte, error) {
	beginMarker := "-----BEGIN SIGNATURE-----"
	endMarker := "-----END SIGNATURE-----"
	beginIdx := strings.Index(pemText, beginMarker)
	endIdx := strings.Index(pemText, endMarker)
	if beginIdx < 0 || endIdx < 0 {
		return nil, fmt.Errorf("router-signature: malformed PEM block")
	}
	b64 := pemText[beginIdx+len(beginMarker) : endIdx]
	b64 = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(b64)
	sigBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("router-signature: %w", err)
	}
	return sigBytes, nil
}

func parseRouterLine(info *RelayInfo, line string) error {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return fmt.Errorf("malformed router line: %s", line)
	}
	info.Address = parts[2]
	port, err := strconv.ParseUint(parts[3], 10, 16)
	if err != nil {
		return fmt.Errorf("parse OR port: %w", err)
	}
	info.ORPort = uint16(port)
	return nil
}

func parseFingerprintLine(info *RelayInfo, line string) error {
	fpHex := strings.ReplaceAll(line[len("fingerprint "):], " ", "")
	fpBytes, err := hex.DecodeString(fpHex)
	if err != nil {
		return fmt.Errorf("decode fingerprint: %w", err)
	}
	if len(fpBytes) != 20 {
		return fmt.Errorf("fingerprint wrong length: %d", len(fpBytes))
	}
	copy(info.NodeID[:], fpBytes)
	info.Fingerprint = strings.ToUpper(fpHex)
	return nil
}

func parseNtorKeyLine(info *RelayInfo, line string) error {
	b64 := strings.TrimSpace(line[len("ntor-onion-key "):])
	keyBytes, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		keyBytes, err = base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("decode ntor-onion-key: %w", err)
		}
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("ntor-onion-key wrong length: %d", len(keyBytes))
	}
	copy(info.NtorOnionKey[:], keyBytes)
	return nil
}

func verifyDescriptorFingerprint(derBytes []byte, fingerprint string) error {
	fpHash := sha1.Sum(derBytes)
	computedFP := strings.ToUpper(hex.EncodeToString(fpHash[:]))
	if computedFP != fingerprint {
		return fmt.Errorf("fingerprint mismatch: computed %s from signing-key, descriptor says %s", computedFP, fingerprint)
	}
	return nil
}

func verifyDescriptorSignature(text string, signingKey *rsa.PublicKey, sigBytes []byte) error {
	signedContent, err := extractSignedContent(text)
	if err != nil {
		return err
	}
	digest := sha1.Sum([]byte(signedContent))
	// crypto.Hash(0) is required because Tor uses raw PKCS#1 v1.5 signatures:
	// the SHA-1 digest is padded directly without an ASN.1 DigestInfo prefix,
	// so we cannot pass crypto.SHA1 (which would prepend the prefix).
	if err := rsa.VerifyPKCS1v15(signingKey, crypto.Hash(0), digest[:], sigBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// extractSignedContent returns the signed portion of a relay descriptor:
// from "router " through "router-signature\n" (inclusive).
// Both markers must appear at the start of a line.
func extractSignedContent(text string) (string, error) {
	// Normalize CRLF to LF so marker searches work regardless of line-ending style.
	text = strings.ReplaceAll(text, "\r\n", "\n")

	startIdx := strings.Index(text, "router ")
	if startIdx < 0 {
		return "", fmt.Errorf("signed content: 'router ' not found")
	}
	// "router " must be at start of text or start of a line
	if startIdx != 0 && text[startIdx-1] != '\n' {
		return "", fmt.Errorf("signed content: 'router ' not found at start of line")
	}
	marker := "router-signature\n"
	endIdx := strings.Index(text, marker)
	if endIdx < 0 {
		return "", fmt.Errorf("signed content: 'router-signature' not found")
	}
	// "router-signature" must be at start of text or start of a line
	if endIdx != 0 && text[endIdx-1] != '\n' {
		return "", fmt.Errorf("signed content: 'router-signature' not found at start of line")
	}
	return text[startIdx : endIdx+len(marker)], nil
}
