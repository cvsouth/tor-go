package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheSaveAndLoadConsensus(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	text := "network-status-version 3 microdesc\nvalid-after 2025-01-01 00:00:00\n"
	freshUntil := time.Now().Add(1 * time.Hour)
	validUntil := time.Now().Add(3 * time.Hour)

	if err := cache.SaveConsensus(text, freshUntil, validUntil); err != nil {
		t.Fatalf("SaveConsensus: %v", err)
	}

	// File should exist
	if _, err := os.Stat(filepath.Join(dir, "consensus.json")); err != nil {
		t.Fatalf("cache file not found: %v", err)
	}

	loaded, ok := cache.LoadConsensus()
	if !ok {
		t.Fatal("LoadConsensus returned false for valid cache")
	}
	if loaded != text {
		t.Fatalf("loaded text mismatch: got %q", loaded)
	}
}

func TestCacheLoadConsensusExpired(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	text := "test consensus"
	freshUntil := time.Now().Add(-2 * time.Hour)
	validUntil := time.Now().Add(-1 * time.Hour)

	if err := cache.SaveConsensus(text, freshUntil, validUntil); err != nil {
		t.Fatalf("SaveConsensus: %v", err)
	}

	_, ok := cache.LoadConsensus()
	if ok {
		t.Fatal("LoadConsensus returned true for expired cache")
	}
}

func TestCacheLoadConsensusMissing(t *testing.T) {
	cache := &Cache{Dir: t.TempDir()}

	_, ok := cache.LoadConsensus()
	if ok {
		t.Fatal("LoadConsensus returned true for missing cache")
	}
}

func TestCacheNeedsRefresh(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	// Fresh consensus
	if err := cache.SaveConsensus("test", time.Now().Add(1*time.Hour), time.Now().Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if cache.NeedsRefresh() {
		t.Fatal("NeedsRefresh returned true for fresh consensus")
	}

	// Stale consensus (past fresh-until but before valid-until)
	if err := cache.SaveConsensus("test", time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !cache.NeedsRefresh() {
		t.Fatal("NeedsRefresh returned false for stale consensus")
	}
}

func TestCacheSaveAndLoadMicrodescriptors(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	relays := []Relay{
		{
			MicrodescDigest: "abc123",
			NtorOnionKey:    [32]byte{1, 2, 3},
			HasNtorKey:      true,
			Ed25519ID:       [32]byte{4, 5, 6},
			HasEd25519:      true,
		},
		{
			MicrodescDigest: "def456",
			NtorOnionKey:    [32]byte{7, 8, 9},
			HasNtorKey:      true,
		},
		{
			MicrodescDigest: "no-key",
			HasNtorKey:      false, // Should not be cached
		},
	}

	if err := cache.SaveMicrodescriptors(relays); err != nil {
		t.Fatalf("SaveMicrodescriptors: %v", err)
	}

	// Load into fresh relays with matching digests
	freshRelays := []Relay{
		{MicrodescDigest: "abc123"},
		{MicrodescDigest: "def456"},
		{MicrodescDigest: "unknown"},
	}

	count := cache.LoadMicrodescriptors(freshRelays)
	if count != 2 {
		t.Fatalf("expected 2 relays updated, got %d", count)
	}

	if freshRelays[0].NtorOnionKey != [32]byte{1, 2, 3} {
		t.Fatal("relay 0 ntor key mismatch")
	}
	if !freshRelays[0].HasEd25519 || freshRelays[0].Ed25519ID != [32]byte{4, 5, 6} {
		t.Fatal("relay 0 ed25519 mismatch")
	}
	if freshRelays[1].NtorOnionKey != [32]byte{7, 8, 9} {
		t.Fatal("relay 1 ntor key mismatch")
	}
	if freshRelays[2].HasNtorKey {
		t.Fatal("relay 2 should not have been updated")
	}
}

func TestCacheLoadMicrodescriptorsMissing(t *testing.T) {
	cache := &Cache{Dir: t.TempDir()}
	relays := []Relay{{MicrodescDigest: "abc"}}
	count := cache.LoadMicrodescriptors(relays)
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}
}

func TestCacheEmptyDir(t *testing.T) {
	cache := &Cache{Dir: ""}

	_, ok := cache.LoadConsensus()
	if ok {
		t.Fatal("should return false with empty dir")
	}
	if !cache.NeedsRefresh() {
		t.Fatal("should need refresh with empty dir")
	}
	if err := cache.SaveConsensus("test", time.Now(), time.Now()); err == nil {
		t.Fatal("should error with empty dir")
	}
	if cache.LoadMicrodescriptors(nil) != 0 {
		t.Fatal("should return 0 with empty dir")
	}
	if err := cache.SaveMicrodescriptors(nil); err == nil {
		t.Fatal("should error with empty dir")
	}
}

func TestCacheCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "cache")
	cache := &Cache{Dir: dir}

	if err := cache.SaveConsensus("test", time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatalf("SaveConsensus failed to create nested dir: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

func TestCacheCorruptedJSON(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	// Write corrupted data
	_ = os.WriteFile(filepath.Join(dir, "consensus.json"), []byte("{invalid json"), 0600)
	_ = os.WriteFile(filepath.Join(dir, "microdescriptors.json"), []byte("{invalid json"), 0600)

	if _, ok := cache.LoadConsensus(); ok {
		t.Fatal("should return false for corrupted consensus")
	}
	if !cache.NeedsRefresh() {
		t.Fatal("should need refresh for corrupted consensus")
	}
	relays := []Relay{{MicrodescDigest: "abc"}}
	if cache.LoadMicrodescriptors(relays) != 0 {
		t.Fatal("should return 0 for corrupted microdescriptors")
	}
}

func TestCacheSaveAndLoadKeyCerts(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	derBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	digest := sha1.Sum(derBytes)
	skDigest := strings.ToUpper(hex.EncodeToString(digest[:]))

	certs := []KeyCert{
		{
			IdentityFingerprint: "F533C81CEF0BC0267857C99B2F471ADF249FA232",
			SigningKeyDigest:    skDigest,
			SigningKey:          &key.PublicKey,
			Expires:             time.Now().Add(365 * 24 * time.Hour),
		},
	}

	if err := cache.SaveKeyCerts(certs); err != nil {
		t.Fatalf("SaveKeyCerts: %v", err)
	}

	loaded, err := cache.LoadKeyCerts()
	if err != nil {
		t.Fatalf("LoadKeyCerts: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(loaded))
	}
	if loaded[0].IdentityFingerprint != certs[0].IdentityFingerprint {
		t.Fatal("fingerprint mismatch")
	}
	if loaded[0].SigningKeyDigest != certs[0].SigningKeyDigest {
		t.Fatal("signing key digest mismatch")
	}
	if loaded[0].SigningKey.N.Cmp(key.N) != 0 {
		t.Fatal("signing key mismatch")
	}
}

func TestCacheLoadKeyCertsExpiredFiltered(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certs := []KeyCert{
		{
			IdentityFingerprint: "F533C81CEF0BC0267857C99B2F471ADF249FA232",
			SigningKeyDigest:    "ABCD",
			SigningKey:          &key.PublicKey,
			Expires:             time.Now().Add(-24 * time.Hour), // expired
		},
	}

	if err := cache.SaveKeyCerts(certs); err != nil {
		t.Fatal(err)
	}

	_, err := cache.LoadKeyCerts()
	if err == nil {
		t.Fatal("expected error for expired certs")
	}
}

func TestCacheFilePermissions(t *testing.T) {
	dir := t.TempDir()
	cache := &Cache{Dir: dir}

	if err := cache.SaveConsensus("test", time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "consensus.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}
}
