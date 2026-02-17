package onion

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// IntroPoint represents a parsed introduction point from a v3 HS descriptor.
type IntroPoint struct {
	// LinkSpecifiers is the raw link specifiers block for use in EXTEND2.
	LinkSpecifiers []byte
	// OnionKey is the ntor onion key of the introduction point relay (curve25519).
	OnionKey [32]byte
	// AuthKeyCert is the raw auth-key certificate.
	AuthKeyCert []byte
	// AuthKey is the 32-byte Ed25519 auth key extracted from the certificate.
	AuthKey [32]byte
	// EncKey is the curve25519 encryption key for the hs-ntor handshake (KP_hss_ntor).
	EncKey [32]byte
	// EncKeyCert is the raw enc-key-cert certificate.
	EncKeyCert []byte
}

// ParsedLinkSpecs holds the extracted fields from link specifiers.
type ParsedLinkSpecs struct {
	Address    string   // IPv4 or IPv6 address
	ORPort     uint16
	Identity   [20]byte // RSA identity (SHA-1 fingerprint)
	Ed25519ID  [32]byte
	HasEd25519 bool
}

// ParseLinkSpecifiers parses the NSPEC-prefixed link specifier block
// (as stored in IntroPoint.LinkSpecifiers) into structured fields.
func ParseLinkSpecifiers(data []byte) (*ParsedLinkSpecs, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("link specifiers too short")
	}
	nspec := int(data[0])
	result := &ParsedLinkSpecs{}
	off := 1
	for i := 0; i < nspec; i++ {
		if off+2 > len(data) {
			return nil, fmt.Errorf("truncated link specifier %d", i)
		}
		lstype := data[off]
		lslen := int(data[off+1])
		off += 2
		if off+lslen > len(data) {
			return nil, fmt.Errorf("link specifier %d data truncated", i)
		}
		lsdata := data[off : off+lslen]
		off += lslen

		switch lstype {
		case 0x00: // IPv4: 4 bytes IP + 2 bytes port
			if lslen != 6 {
				continue
			}
			result.Address = net.IP(lsdata[:4]).String()
			result.ORPort = binary.BigEndian.Uint16(lsdata[4:6])
		case 0x01: // IPv6: 16 bytes IP + 2 bytes port
			if lslen != 18 {
				continue
			}
			result.Address = net.IP(lsdata[:16]).String()
			result.ORPort = binary.BigEndian.Uint16(lsdata[16:18])
		case 0x02: // RSA identity: 20 bytes
			if lslen != 20 {
				continue
			}
			copy(result.Identity[:], lsdata)
		case 0x03: // Ed25519 identity: 32 bytes
			if lslen != 32 {
				continue
			}
			copy(result.Ed25519ID[:], lsdata)
			result.HasEd25519 = true
		}
	}
	if result.Address == "" {
		return nil, fmt.Errorf("no IPv4 or IPv6 link specifier found")
	}
	return result, nil
}

// DecryptAndParseDescriptor decrypts both layers of a v3 HS descriptor and
// returns the list of introduction points.
func DecryptAndParseDescriptor(outer *DescriptorOuter, blindedKey [32]byte, subcredential [32]byte) ([]IntroPoint, error) {
	// First layer: decrypt superencrypted blob.
	firstPlaintext, err := DecryptDescriptorLayer(
		outer.Superencrypted,
		blindedKey[:],
		subcredential[:],
		outer.RevisionCounter,
		"hsdir-superencrypted-data",
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt first layer: %w", err)
	}

	// Parse first layer to extract the "encrypted" blob.
	encryptedBlob, err := parseFirstLayerPlaintext(string(firstPlaintext))
	if err != nil {
		return nil, fmt.Errorf("parse first layer: %w", err)
	}

	// Second layer: decrypt encrypted blob (no descriptor_cookie for public services).
	secondPlaintext, err := DecryptDescriptorLayer(
		encryptedBlob,
		blindedKey[:],
		subcredential[:],
		outer.RevisionCounter,
		"hsdir-encrypted-data",
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt second layer: %w", err)
	}

	// Parse introduction points from the second layer plaintext.
	return parseIntroPoints(string(secondPlaintext))
}

// parseFirstLayerPlaintext extracts the encrypted blob from the first layer.
func parseFirstLayerPlaintext(text string) ([]byte, error) {
	var inEncrypted bool
	var encLines []string

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r \x00")
		if line == "-----BEGIN MESSAGE-----" {
			inEncrypted = true
			continue
		}
		if strings.Contains(line, "-----END MESSAGE-----") {
			// Handle case where END marker is on the same line as last base64 data
			before := strings.TrimSpace(strings.Split(line, "-----END MESSAGE-----")[0])
			if before != "" && inEncrypted {
				encLines = append(encLines, before)
			}
			inEncrypted = false
			continue
		}
		if inEncrypted {
			encLines = append(encLines, strings.TrimSpace(line))
		}
	}

	if len(encLines) == 0 {
		return nil, fmt.Errorf("no encrypted blob in first layer")
	}

	blob := strings.Join(encLines, "")
	decoded, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted blob: %w", err)
	}
	return decoded, nil
}

// parseIntroPoints parses the second layer plaintext into introduction points.
func parseIntroPoints(text string) ([]IntroPoint, error) {
	var points []IntroPoint
	var current *IntroPoint

	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		switch {
		case strings.HasPrefix(line, "introduction-point "):
			if current != nil {
				points = append(points, *current)
			}
			current = &IntroPoint{}
			b64 := strings.TrimPrefix(line, "introduction-point ")
			ls, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				// Try without padding.
				ls, err = base64.RawStdEncoding.DecodeString(b64)
				if err != nil {
					return nil, fmt.Errorf("decode link specifiers: %w", err)
				}
			}
			current.LinkSpecifiers = ls

		case strings.HasPrefix(line, "onion-key ntor ") && current != nil:
			keyB64 := strings.TrimPrefix(line, "onion-key ntor ")
			keyBytes, err := base64.RawStdEncoding.DecodeString(keyB64)
			if err != nil {
				keyBytes, err = base64.StdEncoding.DecodeString(keyB64)
				if err != nil {
					return nil, fmt.Errorf("decode onion-key: %w", err)
				}
			}
			if len(keyBytes) != 32 {
				return nil, fmt.Errorf("onion-key has invalid length: got %d, want 32", len(keyBytes))
			}
			copy(current.OnionKey[:], keyBytes)

		case strings.HasPrefix(line, "enc-key ntor ") && current != nil:
			keyB64 := strings.TrimPrefix(line, "enc-key ntor ")
			keyBytes, err := base64.RawStdEncoding.DecodeString(keyB64)
			if err != nil {
				keyBytes, err = base64.StdEncoding.DecodeString(keyB64)
				if err != nil {
					return nil, fmt.Errorf("decode enc-key: %w", err)
				}
			}
			if len(keyBytes) != 32 {
				return nil, fmt.Errorf("enc-key has invalid length: got %d, want 32", len(keyBytes))
			}
			copy(current.EncKey[:], keyBytes)

		case line == "auth-key" && current != nil:
			cert, end := extractCert(lines, i+1)
			if cert != nil {
				current.AuthKeyCert = cert
				// Extract the 32-byte Ed25519 key from the cert.
				// Cert format: version(1) | type(1) | expiration(4) | key_type(1) | certified_key(32) | ...
				if len(cert) >= 39 {
					copy(current.AuthKey[:], cert[7:39])
				}
				i = end
			}

		case line == "enc-key-cert" && current != nil:
			cert, end := extractCert(lines, i+1)
			if cert != nil {
				current.EncKeyCert = cert
				i = end
			}
		}
	}

	if current != nil {
		points = append(points, *current)
	}

	return points, nil
}

// extractCert extracts a PEM-like certificate block starting at the given line index.
func extractCert(lines []string, start int) ([]byte, int) {
	if start >= len(lines) {
		return nil, start
	}

	if lines[start] != "-----BEGIN ED25519 CERT-----" {
		return nil, start
	}

	var certLines []string
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "-----END ED25519 CERT-----" {
			blob := strings.Join(certLines, "")
			decoded, err := base64.StdEncoding.DecodeString(blob)
			if err != nil {
				return nil, i
			}
			return decoded, i
		}
		certLines = append(certLines, lines[i])
	}
	return nil, start
}
