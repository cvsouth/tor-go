package descriptor

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RelayInfo contains the parsed relay descriptor fields needed for ntor handshake.
type RelayInfo struct {
	NodeID      [20]byte // SHA-1 of relay's RSA identity key
	NtorOnionKey [32]byte // Curve25519 public key
	Address     string   // IP address
	ORPort      uint16   // OR port
	Fingerprint string   // Hex fingerprint string (uppercase, no spaces)
}

// FetchDescriptor fetches a relay's server descriptor from a Tor directory authority
// and parses the fields needed for ntor handshake.
//
// TODO SECURITY: Descriptors are fetched over plaintext HTTP and not signature-verified.
// The Tor spec requires verifying the router-signature (RSA) before trusting descriptor fields.
// Currently, a MITM on the HTTP connection could substitute ntor keys, but this would cause
// the ntor AUTH check to fail (the real relay won't produce valid AUTH for substituted keys).
// Full descriptor signature verification will be implemented in M5 (directory bootstrap).
func FetchDescriptor(dirAddr string, fingerprint string) (*RelayInfo, error) {
	url := fmt.Sprintf("http://%s/tor/server/fp/%s", dirAddr, fingerprint)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true, // Tor directory servers mishandle Accept-Encoding
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch descriptor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch descriptor: HTTP %d", resp.StatusCode)
	}

	// Limit body to 1MB to prevent abuse from malicious dir authorities
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read descriptor body: %w", err)
	}

	return ParseDescriptor(string(body))
}

// ParseDescriptor parses a relay server descriptor text and extracts RelayInfo.
func ParseDescriptor(text string) (*RelayInfo, error) {
	info := &RelayInfo{}
	var hasRouter, hasFingerprint, hasNtorKey bool

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "router ") {
			// router <nickname> <address> <ORPort> <SOCKSPort> <DirPort>
			parts := strings.Fields(line)
			if len(parts) < 4 {
				return nil, fmt.Errorf("malformed router line: %s", line)
			}
			info.Address = parts[2]
			port, err := strconv.ParseUint(parts[3], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse OR port: %w", err)
			}
			info.ORPort = uint16(port)
			hasRouter = true
		}

		if strings.HasPrefix(line, "fingerprint ") {
			// fingerprint XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX
			fpHex := strings.ReplaceAll(line[len("fingerprint "):], " ", "")
			fpBytes, err := hex.DecodeString(fpHex)
			if err != nil {
				return nil, fmt.Errorf("decode fingerprint: %w", err)
			}
			if len(fpBytes) != 20 {
				return nil, fmt.Errorf("fingerprint wrong length: %d", len(fpBytes))
			}
			copy(info.NodeID[:], fpBytes)
			info.Fingerprint = strings.ToUpper(fpHex)
			hasFingerprint = true
		}

		if strings.HasPrefix(line, "ntor-onion-key ") {
			// ntor-onion-key <base64>
			b64 := strings.TrimSpace(line[len("ntor-onion-key "):])
			// Tor uses base64 without padding
			keyBytes, err := base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				// Try with standard encoding (with padding)
				keyBytes, err = base64.StdEncoding.DecodeString(b64)
				if err != nil {
					return nil, fmt.Errorf("decode ntor-onion-key: %w", err)
				}
			}
			if len(keyBytes) != 32 {
				return nil, fmt.Errorf("ntor-onion-key wrong length: %d", len(keyBytes))
			}
			copy(info.NtorOnionKey[:], keyBytes)
			hasNtorKey = true
		}
	}

	if !hasRouter {
		return nil, fmt.Errorf("missing router line")
	}
	if !hasFingerprint {
		return nil, fmt.Errorf("missing fingerprint line")
	}
	if !hasNtorKey {
		return nil, fmt.Errorf("missing ntor-onion-key line")
	}

	return info, nil
}
