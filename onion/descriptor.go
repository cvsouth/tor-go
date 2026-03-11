package onion

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/directory"
)

// FetchDescriptorViaCircuit fetches a v3 hidden service descriptor using
// BEGIN_DIR over an existing circuit. The circuit's last hop must be the
// HSDir relay.
//
// The circuit's read loop must be started before calling this function.
func FetchDescriptorViaCircuit(circ *circuit.Circuit, blindedKey [32]byte) (string, error) {
	keyB64 := base64.RawStdEncoding.EncodeToString(blindedKey[:])
	body, err := directory.FetchViaBeginDir(circ, "/tor/hs/3/"+keyB64, 256*1024)
	if err != nil {
		return "", fmt.Errorf("fetch descriptor: %w", err)
	}
	return string(body), nil
}

// ParseDescriptorOuterLayer parses the outer layer of a v3 HS descriptor,
// returning the fields needed for decryption.
type DescriptorOuter struct {
	LifetimeSeconds int
	SigningKeyCert  []byte // The signing key certificate
	RevisionCounter uint64
	Superencrypted  []byte // The superencrypted blob
	Signature       []byte
}

// ParseDescriptorOuter parses the outer plaintext layer of an HS descriptor.
func ParseDescriptorOuter(text string) (*DescriptorOuter, error) {
	d := &DescriptorOuter{}
	lines := strings.Split(text, "\n")

	var inSuperencrypted bool
	var superencryptedLines []string

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "descriptor-lifetime "):
			n, err := fmt.Sscanf(line, "descriptor-lifetime %d", &d.LifetimeSeconds)
			if err != nil || n != 1 {
				return nil, fmt.Errorf("parse descriptor-lifetime: %w", err)
			}

		case strings.HasPrefix(line, "revision-counter "):
			n, err := fmt.Sscanf(line, "revision-counter %d", &d.RevisionCounter)
			if err != nil || n != 1 {
				return nil, fmt.Errorf("parse revision-counter: %w", err)
			}

		case line == "-----BEGIN MESSAGE-----":
			inSuperencrypted = true

		case strings.Contains(line, "-----END MESSAGE-----"):
			if inSuperencrypted {
				before := strings.TrimSpace(strings.TrimSuffix(line, "-----END MESSAGE-----"))
				if before != "" {
					superencryptedLines = append(superencryptedLines, before)
				}
			}
			inSuperencrypted = false
			blob := strings.Join(superencryptedLines, "")
			decoded, err := base64.StdEncoding.DecodeString(blob)
			if err != nil {
				return nil, fmt.Errorf("decode superencrypted blob: %w", err)
			}
			d.Superencrypted = decoded

		case inSuperencrypted:
			superencryptedLines = append(superencryptedLines, strings.TrimSpace(line))
		}
	}

	if d.Superencrypted == nil {
		return nil, fmt.Errorf("no superencrypted layer found")
	}

	return d, nil
}
