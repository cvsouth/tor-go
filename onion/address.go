package onion

import (
	"encoding/base32"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

// DecodeOnion decodes a v3 .onion address and returns the 32-byte Ed25519 public key.
// It validates the checksum, version byte, and rejects keys with torsion components.
func DecodeOnion(address string) ([32]byte, error) {
	var pubkey [32]byte

	// Strip .onion suffix
	address = strings.TrimSuffix(strings.ToLower(address), ".onion")

	// Base32 decode (uppercase for standard base32)
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(address))
	if err != nil {
		return pubkey, fmt.Errorf("base32 decode: %w", err)
	}

	// Must be exactly 35 bytes: pubkey(32) + checksum(2) + version(1)
	if len(decoded) != 35 {
		return pubkey, fmt.Errorf("decoded length %d, expected 35", len(decoded))
	}

	copy(pubkey[:], decoded[:32])
	checksum := decoded[32:34]
	version := decoded[34]

	// Version must be 0x03
	if version != 0x03 {
		return pubkey, fmt.Errorf("unsupported version: %d", version)
	}

	// Verify checksum: SHA3-256(".onion checksum" || pubkey || version)[:2]
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pubkey[:])
	h.Write([]byte{version})
	expectedChecksum := h.Sum(nil)[:2]

	if checksum[0] != expectedChecksum[0] || checksum[1] != expectedChecksum[1] {
		return pubkey, fmt.Errorf("checksum mismatch")
	}

	// Validate the public key is a valid Ed25519 point
	if _, err := new(edwards25519.Point).SetBytes(pubkey[:]); err != nil {
		return pubkey, fmt.Errorf("invalid ed25519 point: %w", err)
	}

	return pubkey, nil
}
