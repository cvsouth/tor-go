package directory

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

// Known directory authority v3ident fingerprints (SHA-1 of identity key, hex uppercase).
var dirAuthorityFingerprints = map[string]bool{
	"F533C81CEF0BC0267857C99B2F471ADF249FA232": true, // moria1
	"2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C": true, // tor26
	"E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58": true, // dizum
	"70849B868D606BAECFB6128C5E3D782029AA394F": true, // Faravahar
	"23D15D965BC35114467363C165C4F724B64B4F66": true, // longclaw
	"27102BC123E7AF1D4741AE047E160C91ADC76B21": true, // bastet
	"0232AF901C31A04EE9848595AF9BB7620D4C5B2E": true, // dannenberg
	"49015F787433103580E3B66A1707A00E60F2D15B": true, // maatuska
	"ED03BB616EB2F60BEC80151114BB25CEF515B226": true, // gabelmoo
}

// ValidateFreshness checks that the consensus is currently valid.
func ValidateFreshness(c *Consensus) error {
	now := time.Now().UTC()
	skew := 5 * time.Minute

	if c.ValidAfter.IsZero() || c.ValidUntil.IsZero() {
		return fmt.Errorf("consensus missing validity timestamps")
	}
	if now.Before(c.ValidAfter.Add(-skew)) {
		return fmt.Errorf("consensus is from the future (valid-after %s, now %s)", c.ValidAfter, now)
	}
	if now.After(c.ValidUntil.Add(skew)) {
		return fmt.Errorf("consensus has expired (valid-until %s, now %s)", c.ValidUntil, now)
	}
	return nil
}

// ValidateSignatures cryptographically verifies RSA signatures on the consensus.
// It requires at least 5 valid signatures from known directory authorities.
// If certs is nil or empty, falls back to structural validation only.
func ValidateSignatures(text string, certs []KeyCert) error {
	if len(certs) == 0 {
		return ValidateSignaturesStructural(text)
	}

	// Build lookup: signing-key-digest -> KeyCert
	certByDigest := make(map[string]*KeyCert)
	for i := range certs {
		certByDigest[certs[i].SigningKeyDigest] = &certs[i]
	}

	// Find the signed content boundary: from start through space after "directory-signature "
	// Per dir-spec: hash through the space after "directory-signature", not the newline.
	signedContentEnd := strings.Index(text, "\ndirectory-signature ")
	if signedContentEnd < 0 {
		return fmt.Errorf("no directory-signature found in consensus")
	}
	signedContentEnd += len("\ndirectory-signature ")
	signedContent := text[:signedContentEnd]

	verified := make(map[string]bool)
	sigs := parseSignatureBlocks(text)
	for _, sig := range sigs {
		if !dirAuthorityFingerprints[sig.identity] {
			continue
		}
		cert, ok := certByDigest[sig.signingKeyDigest]
		if !ok {
			continue
		}
		if cert.IdentityFingerprint != sig.identity {
			continue
		}

		var h hash.Hash
		switch sig.algorithm {
		case "sha1", "":
			h = sha1.New()
		case "sha256":
			h = sha256.New()
		default:
			continue // ignore unrecognized algorithms per spec
		}

		h.Write([]byte(signedContent))
		digest := h.Sum(nil)

		// Tor directory signatures use PKCS#1 v1.5 padding without the ASN.1
		// DigestInfo prefix. Pass crypto.Hash(0) so Go verifies raw padding.
		if rsa.VerifyPKCS1v15(cert.SigningKey, crypto.Hash(0), digest, sig.signature) != nil {
			continue
		}
		verified[sig.identity] = true
	}

	if len(verified) < 5 {
		return fmt.Errorf("consensus has %d valid cryptographic signatures, need at least 5", len(verified))
	}
	return nil
}

// ValidateSignaturesStructural checks structural presence of signatures only.
// Used as fallback when key certificates are unavailable.
func ValidateSignaturesStructural(text string) error {
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "directory-signature ") {
			continue
		}
		parts := strings.Fields(line)
		var identity string
		switch len(parts) {
		case 3:
			identity = parts[1]
		case 4:
			identity = parts[2]
		default:
			continue
		}
		identity = strings.ToUpper(identity)
		if dirAuthorityFingerprints[identity] {
			seen[identity] = true
		}
	}
	if len(seen) < 5 {
		return fmt.Errorf("consensus has signatures from %d authorities, need at least 5", len(seen))
	}
	return nil
}

// signatureBlock holds a parsed directory-signature block.
type signatureBlock struct {
	algorithm        string
	identity         string
	signingKeyDigest string
	signature        []byte
}

// parseSignatureBlocks extracts all directory-signature blocks from consensus text.
func parseSignatureBlocks(text string) []signatureBlock {
	var blocks []signatureBlock
	remaining := text

	for {
		idx := strings.Index(remaining, "\ndirectory-signature ")
		if idx < 0 {
			break
		}
		remaining = remaining[idx+1:]

		lineEnd := strings.Index(remaining, "\n")
		if lineEnd < 0 {
			break
		}
		line := strings.TrimRight(remaining[:lineEnd], "\r")
		parts := strings.Fields(line)

		var sig signatureBlock
		switch len(parts) {
		case 3:
			sig.algorithm = "sha1"
			sig.identity = strings.ToUpper(parts[1])
			sig.signingKeyDigest = strings.ToUpper(parts[2])
		case 4:
			sig.algorithm = parts[1]
			sig.identity = strings.ToUpper(parts[2])
			sig.signingKeyDigest = strings.ToUpper(parts[3])
		default:
			continue
		}

		remaining = remaining[lineEnd+1:]
		sigStart := strings.Index(remaining, "-----BEGIN SIGNATURE-----")
		if sigStart < 0 {
			continue
		}
		sigEnd := strings.Index(remaining, "-----END SIGNATURE-----")
		if sigEnd < 0 {
			continue
		}

		b64 := remaining[sigStart+len("-----BEGIN SIGNATURE-----") : sigEnd]
		b64 = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(b64)

		sigBytes, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		sig.signature = sigBytes
		blocks = append(blocks, sig)

		remaining = remaining[sigEnd:]
	}

	return blocks
}

// ParseConsensus parses a microdescriptor consensus document.
func ParseConsensus(text string) (*Consensus, error) {
	c := &Consensus{
		BandwidthWeights: make(map[string]int64),
	}

	lines := strings.Split(text, "\n")
	var currentRelay *Relay

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		switch {
		case strings.HasPrefix(line, "valid-after "):
			t, err := time.Parse("2006-01-02 15:04:05", line[len("valid-after "):])
			if err != nil {
				return nil, fmt.Errorf("parse valid-after: %w", err)
			}
			c.ValidAfter = t

		case strings.HasPrefix(line, "fresh-until "):
			t, err := time.Parse("2006-01-02 15:04:05", line[len("fresh-until "):])
			if err != nil {
				return nil, fmt.Errorf("parse fresh-until: %w", err)
			}
			c.FreshUntil = t

		case strings.HasPrefix(line, "valid-until "):
			t, err := time.Parse("2006-01-02 15:04:05", line[len("valid-until "):])
			if err != nil {
				return nil, fmt.Errorf("parse valid-until: %w", err)
			}
			c.ValidUntil = t

		case strings.HasPrefix(line, "shared-rand-current-value "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				b, err := base64.StdEncoding.DecodeString(parts[2])
				if err == nil {
					c.SharedRandCurrentValue = b
				}
			}

		case strings.HasPrefix(line, "shared-rand-previous-value "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				b, err := base64.StdEncoding.DecodeString(parts[2])
				if err == nil {
					c.SharedRandPreviousValue = b
				}
			}

		case strings.HasPrefix(line, "r "):
			// New router entry. Save previous if exists.
			if currentRelay != nil {
				c.Relays = append(c.Relays, *currentRelay)
			}
			relay, err := parseRouterLine(line)
			if err != nil {
				// Skip unparseable router lines
				currentRelay = nil
				continue
			}
			currentRelay = relay

		case strings.HasPrefix(line, "m "):
			if currentRelay != nil {
				// m line: "m <digest>"
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					currentRelay.MicrodescDigest = strings.TrimPrefix(parts[1], "sha256=")
				}
			}

		case strings.HasPrefix(line, "s "):
			if currentRelay != nil {
				parseFlags(currentRelay, line)
			}

		case strings.HasPrefix(line, "w "):
			if currentRelay != nil {
				parseBandwidth(currentRelay, line)
			}

		case strings.HasPrefix(line, "bandwidth-weights "):
			parseBandwidthWeights(c, line)
		}
	}

	// Don't forget the last relay
	if currentRelay != nil {
		c.Relays = append(c.Relays, *currentRelay)
	}

	return c, nil
}

// parseRouterLine parses an "r" line from the consensus.
// Format: r <nickname> <identity-b64> <digest-b64> <date> <time> <ip> <orport> <dirport>
func parseRouterLine(line string) (*Relay, error) {
	parts := strings.Fields(line)
	// Microdesc consensus r line: r <nick> <identity> <date> <time> <ip> <orport> <dirport>
	if len(parts) < 8 {
		return nil, fmt.Errorf("r line too short: %q", line)
	}

	// Identity is base64-encoded SHA-1 (20 bytes), unpadded in consensus
	idBytes, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode identity: %w", err)
	}
	if len(idBytes) != 20 {
		return nil, fmt.Errorf("identity wrong length: %d", len(idBytes))
	}

	orPort, err := strconv.ParseUint(parts[6], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse ORPort: %w", err)
	}

	dirPort, err := strconv.ParseUint(parts[7], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse DirPort: %w", err)
	}

	relay := &Relay{
		Nickname: parts[1],
		Address:  parts[5],
		ORPort:   uint16(orPort),
		DirPort:  uint16(dirPort),
	}
	copy(relay.Identity[:], idBytes)

	return relay, nil
}

func parseFlags(relay *Relay, line string) {
	flags := strings.Fields(line)[1:] // skip "s"
	for _, f := range flags {
		switch f {
		case "Authority":
			relay.Flags.Authority = true
		case "BadExit":
			relay.Flags.BadExit = true
		case "Exit":
			relay.Flags.Exit = true
		case "Fast":
			relay.Flags.Fast = true
		case "Guard":
			relay.Flags.Guard = true
		case "HSDir":
			relay.Flags.HSDir = true
		case "Running":
			relay.Flags.Running = true
		case "Stable":
			relay.Flags.Stable = true
		case "Valid":
			relay.Flags.Valid = true
		}
	}
}

func parseBandwidth(relay *Relay, line string) {
	// Format: w Bandwidth=1234
	for _, field := range strings.Fields(line)[1:] {
		if strings.HasPrefix(field, "Bandwidth=") {
			bw, err := strconv.ParseInt(field[len("Bandwidth="):], 10, 64)
			if err == nil {
				relay.Bandwidth = bw
			}
		}
	}
}

func parseBandwidthWeights(c *Consensus, line string) {
	// Format: bandwidth-weights Wbd=0 Wbe=0 Wbg=4131 Wbm=10000 ...
	for _, field := range strings.Fields(line)[1:] {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) == 2 {
			val, err := strconv.ParseInt(parts[1], 10, 64)
			if err == nil {
				c.BandwidthWeights[parts[0]] = val
			}
		}
	}
}
