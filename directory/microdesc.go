package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cvsouth/tor-go/circuit"
)

// ParseMicrodescriptor extracts ntor-onion-key and Ed25519 identity from a microdescriptor.
func ParseMicrodescriptor(text string) (ntorKey [32]byte, ed25519Key [32]byte, hasNtor, hasEd bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")

		if strings.HasPrefix(line, "ntor-onion-key ") {
			keyB64 := strings.TrimSpace(line[len("ntor-onion-key "):])
			keyBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(keyB64, "="))
			if err != nil || len(keyBytes) != 32 {
				continue
			}
			copy(ntorKey[:], keyBytes)
			hasNtor = true
		}

		if strings.HasPrefix(line, "id ed25519 ") {
			keyB64 := strings.TrimSpace(line[len("id ed25519 "):])
			keyBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(keyB64, "="))
			if err != nil || len(keyBytes) != 32 {
				continue
			}
			copy(ed25519Key[:], keyBytes)
			hasEd = true
		}
	}
	return
}

// UpdateRelaysWithMicrodescriptors fetches microdescriptors for the given relays
// via a BEGIN_DIR stream on the provided circuit and updates their ntor keys
// and Ed25519 identities.
func UpdateRelaysWithMicrodescriptors(circ *circuit.Circuit, relays []Relay) error {
	// Build digest → relay index map
	digestToIdx := make(map[string]int)
	var digests []string
	for i, r := range relays {
		if r.MicrodescDigest == "" {
			continue
		}
		digest := r.MicrodescDigest
		digestToIdx[digest] = i
		digests = append(digests, digest)
	}

	if len(digests) == 0 {
		return nil
	}

	populated := 0
	for i := 0; i < len(digests); i += 92 {
		end := i + 92
		if end > len(digests) {
			end = len(digests)
		}
		batch := digests[i:end]

		body, err := FetchViaBeginDir(circ, "/tor/micro/d/"+strings.Join(batch, "-"), 50*1024*1024)
		if err != nil {
			continue
		}

		// Parse each microdescriptor and match by SHA-256 digest
		entries := splitMicrodescriptors(string(body))
		for _, entry := range entries {
			// Compute SHA-256 digest and base64-encode to match consensus format
			hash := sha256.Sum256([]byte(entry))
			digestB64 := base64.RawStdEncoding.EncodeToString(hash[:])

			idx, ok := digestToIdx[digestB64]
			if !ok {
				continue
			}

			ntorKey, ed25519Key, hasNtor, hasEd := ParseMicrodescriptor(entry)
			if !hasNtor {
				continue
			}

			relays[idx].NtorOnionKey = ntorKey
			relays[idx].HasNtorKey = true
			if hasEd {
				relays[idx].Ed25519ID = ed25519Key
				relays[idx].HasEd25519 = true
			}
			populated++
		}
	}

	if populated == 0 {
		return fmt.Errorf("all microdescriptor batches failed: no relays populated")
	}

	return nil
}

func splitMicrodescriptors(body string) []string {
	const marker = "onion-key\n"
	var entries []string
	for {
		idx := strings.Index(body, marker)
		if idx < 0 {
			break
		}
		// Find the next marker after this one
		rest := body[idx+len(marker):]
		nextIdx := strings.Index(rest, marker)
		var entry string
		if nextIdx < 0 {
			entry = body[idx:]
		} else {
			entry = body[idx : idx+len(marker)+nextIdx]
		}
		if strings.TrimSpace(entry) != "" {
			entries = append(entries, entry)
		}
		if nextIdx < 0 {
			break
		}
		body = body[idx+len(marker)+nextIdx:]
	}
	return entries
}
