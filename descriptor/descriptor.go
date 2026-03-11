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
	pemNone      pemAccumulator = iota
	pemSigningKey               // accumulating signing-key PEM block
	pemSignature                // accumulating router-signature PEM block
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

// parseDescriptorFields parses all descriptor fields using line-by-line iteration,
// including multi-line PEM blocks for signing-key and router-signature.
// Returns the parsed RelayInfo, the RSA signing key, its DER bytes, and the signature bytes.
func parseDescriptorFields(text string) (*RelayInfo, *rsa.PublicKey, []byte, []byte, error) {
	info := &RelayInfo{}
	var hasRouter, hasFingerprint, hasNtorKey bool

	// PEM accumulation state
	var accumState pemAccumulator
	var signingKeyPEM strings.Builder
	var signaturePEM strings.Builder

	var hasSigningKey, hasSignature bool

	for _, line := range strings.Split(text, "\n") {
		// When accumulating PEM lines, don't trim — PEM content is already clean
		switch accumState {
		case pemSigningKey:
			signingKeyPEM.WriteString(line)
			signingKeyPEM.WriteString("\n")
			if signingKeyPEM.Len() > maxPEMBytes {
				return nil, nil, nil, nil, fmt.Errorf("signing-key: PEM block exceeds %d bytes", maxPEMBytes)
			}
			if strings.TrimRight(line, "\r") == "-----END RSA PUBLIC KEY-----" {
				accumState = pemNone
				hasSigningKey = true
			}
			continue
		case pemSignature:
			signaturePEM.WriteString(line)
			signaturePEM.WriteString("\n")
			if signaturePEM.Len() > maxPEMBytes {
				return nil, nil, nil, nil, fmt.Errorf("router-signature: PEM block exceeds %d bytes", maxPEMBytes)
			}
			if strings.TrimRight(line, "\r") == "-----END SIGNATURE-----" {
				accumState = pemNone
				hasSignature = true
			}
			continue
		case pemNone:
			// fall through to normal line parsing
		}

		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "router "):
			if err := parseRouterLine(info, trimmed); err != nil {
				return nil, nil, nil, nil, err
			}
			hasRouter = true
		case strings.HasPrefix(trimmed, "fingerprint "):
			if err := parseFingerprintLine(info, trimmed); err != nil {
				return nil, nil, nil, nil, err
			}
			hasFingerprint = true
		case strings.HasPrefix(trimmed, "ntor-onion-key "):
			if err := parseNtorKeyLine(info, trimmed); err != nil {
				return nil, nil, nil, nil, err
			}
			hasNtorKey = true
		case trimmed == "signing-key":
			accumState = pemSigningKey
		case trimmed == "router-signature":
			accumState = pemSignature
		}
	}

	if !hasRouter {
		return nil, nil, nil, nil, fmt.Errorf("missing router line")
	}
	if !hasFingerprint {
		return nil, nil, nil, nil, fmt.Errorf("missing fingerprint line")
	}
	if !hasNtorKey {
		return nil, nil, nil, nil, fmt.Errorf("missing ntor-onion-key line")
	}
	if !hasSigningKey {
		return nil, nil, nil, nil, fmt.Errorf("signing-key: PEM block not found or incomplete")
	}
	if !hasSignature {
		return nil, nil, nil, nil, fmt.Errorf("router-signature: PEM block not found or incomplete")
	}

	// Parse signing-key PEM into *rsa.PublicKey
	pemBlock, _ := pem.Decode([]byte(signingKeyPEM.String()))
	if pemBlock == nil {
		return nil, nil, nil, nil, fmt.Errorf("signing-key: failed to decode PEM block")
	}
	signingKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("signing-key: %w", err)
	}

	// Base64-decode the router-signature bytes
	sigPEM := signaturePEM.String()
	beginMarker := "-----BEGIN SIGNATURE-----"
	endMarker := "-----END SIGNATURE-----"
	beginIdx := strings.Index(sigPEM, beginMarker)
	endIdx := strings.Index(sigPEM, endMarker)
	if beginIdx < 0 || endIdx < 0 {
		return nil, nil, nil, nil, fmt.Errorf("router-signature: malformed PEM block")
	}
	b64 := sigPEM[beginIdx+len(beginMarker) : endIdx]
	b64 = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(b64)
	sigBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("router-signature: %w", err)
	}

	return info, signingKey, pemBlock.Bytes, sigBytes, nil
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
