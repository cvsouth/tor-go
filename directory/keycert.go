package directory

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// KeyCert represents a parsed directory authority key certificate.
type KeyCert struct {
	IdentityFingerprint string         // SHA-1 of identity key DER, uppercase hex
	SigningKeyDigest    string         // SHA-1 of signing key DER, uppercase hex
	SigningKey          *rsa.PublicKey // The medium-term signing key
	Expires             time.Time      // dir-key-expires
}

// FetchKeyCerts fetches authority key certificates from directory authorities.
// Tries each authority until one succeeds.
func FetchKeyCerts() ([]KeyCert, error) {
	var lastErr error
	for _, addr := range DirAuthorities {
		text, err := fetchKeyCertsFrom(addr)
		if err != nil {
			lastErr = err
			continue
		}
		certs, err := ParseKeyCerts(text)
		if err != nil {
			lastErr = err
			continue
		}
		if len(certs) == 0 {
			lastErr = fmt.Errorf("no valid key certs from %s", addr)
			continue
		}
		return certs, nil
	}
	return nil, fmt.Errorf("all directory authorities failed for key certs: %w", lastErr)
}

func fetchKeyCertsFrom(addr string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}
	url := fmt.Sprintf("http://%s/tor/keys/all", addr)

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch key certs from %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch key certs from %s: HTTP %d", addr, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", fmt.Errorf("read key certs from %s: %w", addr, err)
	}
	return string(body), nil
}

// ParseKeyCerts parses concatenated authority key certificate text.
// Only returns certificates for known authorities that have not expired.
func ParseKeyCerts(text string) ([]KeyCert, error) {
	var certs []KeyCert
	now := time.Now()

	// Split into individual certificates by "dir-key-certificate-version"
	blocks := splitCertBlocks(text)

	for _, block := range blocks {
		kc, err := parseOneKeyCert(block, now)
		if err != nil {
			continue // Skip unparseable certs
		}
		certs = append(certs, *kc)
	}
	return certs, nil
}

// splitCertBlocks splits concatenated certificate text into individual cert blocks.
func splitCertBlocks(text string) []string {
	const marker = "dir-key-certificate-version"
	var blocks []string
	remaining := text
	for {
		idx := strings.Index(remaining, marker)
		if idx < 0 {
			break
		}
		remaining = remaining[idx:]
		// Find the next cert boundary
		next := strings.Index(remaining[1:], marker)
		if next < 0 {
			blocks = append(blocks, remaining)
			break
		}
		blocks = append(blocks, remaining[:next+1])
		remaining = remaining[next+1:]
	}
	return blocks
}

func parseOneKeyCert(block string, now time.Time) (*KeyCert, error) {
	fields := extractKeyCertFields(block)

	if fields.fingerprint == "" {
		return nil, fmt.Errorf("missing fingerprint")
	}
	if !dirAuthorityFingerprints[fields.fingerprint] {
		return nil, fmt.Errorf("unknown authority: %s", fields.fingerprint)
	}

	if err := verifyIdentityFingerprint(fields.identityKeyPEM, fields.fingerprint); err != nil {
		return nil, err
	}

	if !fields.expires.IsZero() && now.After(fields.expires) {
		return nil, fmt.Errorf("expired cert for %s", fields.fingerprint)
	}

	return parseSigningKey(fields)
}

type keyCertFields struct {
	fingerprint    string
	expires        time.Time
	signingKeyPEM  string
	identityKeyPEM string
}

func extractKeyCertFields(block string) keyCertFields {
	var f keyCertFields
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "fingerprint "):
			f.fingerprint = strings.ToUpper(strings.TrimSpace(line[len("fingerprint "):]))
		case strings.HasPrefix(line, "dir-key-expires "):
			t, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(line[len("dir-key-expires "):]))
			if err == nil {
				f.expires = t
			}
		case line == "dir-identity-key" && i+1 < len(lines):
			f.identityKeyPEM = extractPEMBlock(lines[i+1:])
		case line == "dir-signing-key" && i+1 < len(lines):
			f.signingKeyPEM = extractPEMBlock(lines[i+1:])
		}
	}
	return f
}

func verifyIdentityFingerprint(identityKeyPEM, fingerprint string) error {
	if identityKeyPEM == "" {
		return nil
	}
	idBlock, _ := pem.Decode([]byte(identityKeyPEM))
	if idBlock == nil {
		return nil
	}
	idDigest := sha1.Sum(idBlock.Bytes)
	computedFP := strings.ToUpper(hex.EncodeToString(idDigest[:]))
	if computedFP != fingerprint {
		return fmt.Errorf("identity key fingerprint mismatch for %s: computed %s", fingerprint, computedFP)
	}
	return nil
}

func parseSigningKey(f keyCertFields) (*KeyCert, error) {
	if f.signingKeyPEM == "" {
		return nil, fmt.Errorf("missing signing key for %s", f.fingerprint)
	}
	pemBlock, _ := pem.Decode([]byte(f.signingKeyPEM))
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM for %s", f.fingerprint)
	}
	pubKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key for %s: %w", f.fingerprint, err)
	}
	digest := sha1.Sum(pemBlock.Bytes)
	return &KeyCert{
		IdentityFingerprint: f.fingerprint,
		SigningKeyDigest:    strings.ToUpper(hex.EncodeToString(digest[:])),
		SigningKey:          pubKey,
		Expires:             f.expires,
	}, nil
}

// extractPEMBlock extracts a PEM block from lines starting at the given position.
func extractPEMBlock(lines []string) string {
	var sb strings.Builder
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		sb.WriteString(line)
		sb.WriteString("\n")
		if strings.HasPrefix(line, "-----END ") {
			break
		}
	}
	return sb.String()
}
