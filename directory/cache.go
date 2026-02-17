package directory

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultCacheDir returns the default cache directory (~/.daphne/tor-cache/).
func DefaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".daphne", "tor-cache")
}

// Cache handles caching of consensus and microdescriptor data to disk.
type Cache struct {
	Dir string
}

// cachedConsensus is the on-disk format for a cached consensus.
type cachedConsensus struct {
	Text       string    `json:"text"`
	ValidUntil time.Time `json:"valid_until"`
	FreshUntil time.Time `json:"fresh_until"`
}

// cachedMicrodescriptors is the on-disk format for cached microdescriptor data.
type cachedMicrodescriptors struct {
	// Relays stores the microdescriptor-derived fields keyed by MicrodescDigest.
	Relays map[string]cachedRelay `json:"relays"`
}

type cachedRelay struct {
	NtorOnionKey [32]byte `json:"ntor_onion_key"`
	Ed25519ID    [32]byte `json:"ed25519_id"`
	HasNtorKey   bool     `json:"has_ntor_key"`
	HasEd25519   bool     `json:"has_ed25519"`
}

// LoadConsensus attempts to load a cached consensus. Returns the consensus text
// and true if the cache is valid (valid-until has not passed), or empty string
// and false if no valid cache exists.
func (c *Cache) LoadConsensus() (string, bool) {
	if c.Dir == "" {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, "consensus.json"))
	if err != nil {
		return "", false
	}
	var cached cachedConsensus
	if err := json.Unmarshal(data, &cached); err != nil {
		return "", false
	}
	if time.Now().After(cached.ValidUntil) {
		return "", false
	}
	return cached.Text, true
}

// NeedsRefresh returns true if the cached consensus is past its fresh-until time.
func (c *Cache) NeedsRefresh() bool {
	if c.Dir == "" {
		return true
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, "consensus.json"))
	if err != nil {
		return true
	}
	var cached cachedConsensus
	if err := json.Unmarshal(data, &cached); err != nil {
		return true
	}
	return time.Now().After(cached.FreshUntil)
}

// SaveConsensus saves a consensus to the cache directory.
func (c *Cache) SaveConsensus(text string, freshUntil, validUntil time.Time) error {
	if c.Dir == "" {
		return fmt.Errorf("cache directory not set")
	}
	if err := os.MkdirAll(c.Dir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	cached := cachedConsensus{
		Text:       text,
		ValidUntil: validUntil,
		FreshUntil: freshUntil,
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshal consensus cache: %w", err)
	}
	return os.WriteFile(filepath.Join(c.Dir, "consensus.json"), data, 0600)
}

// LoadMicrodescriptors loads cached microdescriptor data and applies it to the
// given relay slice. Returns the number of relays updated.
func (c *Cache) LoadMicrodescriptors(relays []Relay) int {
	if c.Dir == "" {
		return 0
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, "microdescriptors.json"))
	if err != nil {
		return 0
	}
	var cached cachedMicrodescriptors
	if err := json.Unmarshal(data, &cached); err != nil {
		return 0
	}
	count := 0
	for i := range relays {
		cr, ok := cached.Relays[relays[i].MicrodescDigest]
		if !ok || !cr.HasNtorKey {
			continue
		}
		relays[i].NtorOnionKey = cr.NtorOnionKey
		relays[i].HasNtorKey = cr.HasNtorKey
		relays[i].Ed25519ID = cr.Ed25519ID
		relays[i].HasEd25519 = cr.HasEd25519
		count++
	}
	return count
}

// SaveMicrodescriptors saves microdescriptor data from the given relays to cache.
func (c *Cache) SaveMicrodescriptors(relays []Relay) error {
	if c.Dir == "" {
		return fmt.Errorf("cache directory not set")
	}
	if err := os.MkdirAll(c.Dir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	cached := cachedMicrodescriptors{
		Relays: make(map[string]cachedRelay),
	}
	for _, r := range relays {
		if !r.HasNtorKey || r.MicrodescDigest == "" {
			continue
		}
		cached.Relays[r.MicrodescDigest] = cachedRelay{
			NtorOnionKey: r.NtorOnionKey,
			Ed25519ID:    r.Ed25519ID,
			HasNtorKey:   r.HasNtorKey,
			HasEd25519:   r.HasEd25519,
		}
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshal microdescriptors cache: %w", err)
	}
	return os.WriteFile(filepath.Join(c.Dir, "microdescriptors.json"), data, 0600)
}

// cachedKeyCert is the on-disk format for a cached authority key certificate.
type cachedKeyCert struct {
	IdentityFingerprint string    `json:"identity_fingerprint"`
	SigningKeyDigest    string    `json:"signing_key_digest"`
	SigningKeyPEM       string    `json:"signing_key_pem"`
	Expires             time.Time `json:"expires"`
}

// LoadKeyCerts loads cached authority key certificates.
func (c *Cache) LoadKeyCerts() ([]KeyCert, error) {
	if c.Dir == "" {
		return nil, fmt.Errorf("cache directory not set")
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, "keycerts.json"))
	if err != nil {
		return nil, err
	}
	var cached []cachedKeyCert
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}

	now := time.Now()
	var certs []KeyCert
	for _, cc := range cached {
		if now.After(cc.Expires) {
			continue
		}
		block, _ := pem.Decode([]byte(cc.SigningKeyPEM))
		if block == nil {
			continue
		}
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, KeyCert{
			IdentityFingerprint: cc.IdentityFingerprint,
			SigningKeyDigest:    cc.SigningKeyDigest,
			SigningKey:          pubKey,
			Expires:             cc.Expires,
		})
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid cached key certs")
	}
	return certs, nil
}

// SaveKeyCerts saves authority key certificates to cache.
func (c *Cache) SaveKeyCerts(certs []KeyCert) error {
	if c.Dir == "" {
		return fmt.Errorf("cache directory not set")
	}
	if err := os.MkdirAll(c.Dir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	var cached []cachedKeyCert
	for _, kc := range certs {
		derBytes := x509.MarshalPKCS1PublicKey(kc.SigningKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: derBytes,
		})
		cached = append(cached, cachedKeyCert{
			IdentityFingerprint: kc.IdentityFingerprint,
			SigningKeyDigest:    kc.SigningKeyDigest,
			SigningKeyPEM:       string(pemBytes),
			Expires:             kc.Expires,
		})
	}

	data, err := json.Marshal(cached)
	if err != nil {
		return fmt.Errorf("marshal key certs: %w", err)
	}
	return os.WriteFile(filepath.Join(c.Dir, "keycerts.json"), data, 0600)
}
