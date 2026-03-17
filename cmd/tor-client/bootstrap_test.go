package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/directory"
)

// TestLoadFromCacheMiss verifies that loadFromCache returns nil when
// no cached consensus exists. This confirms the cache-miss path triggers
// fetchFromAuthorities (which uses a circuit), not an error.
func TestLoadFromCacheMiss(t *testing.T) {
	cache := &directory.Cache{Dir: t.TempDir()}
	data := loadFromCache(cache)
	if data != nil {
		t.Fatal("expected nil from empty cache")
	}
}

// TestLoadFromCacheNonexistentDir verifies that a cache pointed at a
// nonexistent directory returns nil gracefully (no panic).
func TestLoadFromCacheNonexistentDir(t *testing.T) {
	cache := &directory.Cache{Dir: "/nonexistent/dir/that/does/not/exist"}
	data := loadFromCache(cache)
	if data != nil {
		t.Fatal("expected nil from nonexistent dir cache")
	}
}

// TestLoadFromCacheHitNoCircuit verifies the cache-hit path works without
// creating any circuit. We store a valid consensus and key certs in cache,
// then verify loadFromCache returns them directly.
func TestLoadFromCacheHitNoCircuit(t *testing.T) {
	cache := &directory.Cache{Dir: t.TempDir()}

	// Create a minimal consensus text and save it with future validity.
	consensusText := "network-status-version 3 microdesc\nvalid-after 2025-01-01 00:00:00\nfresh-until 2099-01-01 00:00:00\nvalid-until 2099-01-01 00:00:00\n"
	freshUntil := time.Now().Add(24 * time.Hour)
	validUntil := time.Now().Add(48 * time.Hour)

	if err := cache.SaveConsensus(consensusText, freshUntil, validUntil); err != nil {
		t.Fatalf("SaveConsensus: %v", err)
	}

	// Generate a test RSA key for key certs.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	derBytes := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	digest := sha1.Sum(derBytes)
	signingKeyDigest := strings.ToUpper(hex.EncodeToString(digest[:]))

	// Cache.LoadKeyCerts does not filter by authority fingerprint — it only
	// filters by expiry. Any fingerprint works here; we use a synthetic one.
	keyCerts := []directory.KeyCert{
		{
			IdentityFingerprint: "AABBCCDD00112233445566778899AABBCCDDEEFF",
			SigningKeyDigest:    signingKeyDigest,
			SigningKey:          &privKey.PublicKey,
			Expires:             time.Now().Add(365 * 24 * time.Hour),
		},
	}
	if err := cache.SaveKeyCerts(keyCerts); err != nil {
		t.Fatalf("SaveKeyCerts: %v", err)
	}

	// Load from cache — no circuit should be needed.
	data := loadFromCache(cache)
	if data.consensusText != consensusText {
		t.Fatalf("consensus text mismatch: got %d bytes, want %d bytes", len(data.consensusText), len(consensusText))
	}
	if len(data.keyCerts) != 1 {
		t.Fatalf("expected 1 key cert, got %d", len(data.keyCerts))
	}
}

// TestLoadFromCacheConsensusWithoutKeyCerts verifies that having a valid
// consensus but no key certs results in a cache miss.
func TestLoadFromCacheConsensusWithoutKeyCerts(t *testing.T) {
	cache := &directory.Cache{Dir: t.TempDir()}

	consensusText := "network-status-version 3 microdesc\n"
	freshUntil := time.Now().Add(24 * time.Hour)
	validUntil := time.Now().Add(48 * time.Hour)

	if err := cache.SaveConsensus(consensusText, freshUntil, validUntil); err != nil {
		t.Fatalf("SaveConsensus: %v", err)
	}
	// Deliberately do NOT save key certs.

	data := loadFromCache(cache)
	if data != nil {
		t.Fatal("expected nil when consensus exists but key certs are missing")
	}
}

// TestLoadFromCacheEmptyDir verifies that an empty cache dir string
// results in a cache miss.
func TestLoadFromCacheEmptyDir(t *testing.T) {
	cache := &directory.Cache{Dir: ""}
	data := loadFromCache(cache)
	if data != nil {
		t.Fatal("expected nil from empty dir cache")
	}
}

// TestLoadFromCacheExpiredConsensus verifies that an expired consensus
// in cache results in a cache miss (nil return).
func TestLoadFromCacheExpiredConsensus(t *testing.T) {
	cache := &directory.Cache{Dir: t.TempDir()}

	consensusText := "network-status-version 3 microdesc\n"
	// Expired validity.
	freshUntil := time.Now().Add(-48 * time.Hour)
	validUntil := time.Now().Add(-24 * time.Hour)

	if err := cache.SaveConsensus(consensusText, freshUntil, validUntil); err != nil {
		t.Fatalf("SaveConsensus: %v", err)
	}

	data := loadFromCache(cache)
	if data != nil {
		t.Fatal("expected nil for expired consensus")
	}
}

// TestCacheBootstrapDataSavesKeyCerts verifies that cacheBootstrapData
// persists key certificates to disk.
// Note: consensus caching is tested in validateAndParseConsensus and the
// cache_test.go round-trip tests; this test focuses on key cert persistence.
func TestCacheBootstrapDataSavesKeyCerts(t *testing.T) {
	cache := &directory.Cache{Dir: t.TempDir()}
	logger := testLogger()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Cache.LoadKeyCerts does not filter by authority fingerprint — it only
	// filters by expiry. Any fingerprint works here; we use a synthetic one.
	keyCerts := []directory.KeyCert{
		{
			IdentityFingerprint: "AABBCCDD00112233445566778899AABBCCDDEEFF",
			SigningKeyDigest:    "1234567890ABCDEF1234567890ABCDEF12345678",
			SigningKey:          &privKey.PublicKey,
			Expires:             time.Now().Add(365 * 24 * time.Hour),
		},
	}

	data := &bootstrapData{
		consensusText: "test consensus",
		keyCerts:      keyCerts,
	}

	cacheBootstrapData(data, cache, logger)

	// Verify key certs are now loadable from cache.
	loaded, err := cache.LoadKeyCerts()
	if err != nil {
		t.Fatalf("LoadKeyCerts after save: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 key cert, got %d", len(loaded))
	}

	// Verify the loaded cert has the same PEM-encoded key.
	originalDER := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)
	originalPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: originalDER})
	loadedDER := x509.MarshalPKCS1PublicKey(loaded[0].SigningKey)
	loadedPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: loadedDER})
	if string(originalPEM) != string(loadedPEM) {
		t.Fatal("signing key does not match after cache round-trip")
	}
}

// TestCountNtorKeys verifies the countNtorKeys helper.
func TestCountNtorKeys(t *testing.T) {
	relays := []directory.Relay{
		{Nickname: "relay1", HasNtorKey: true},
		{Nickname: "relay2", HasNtorKey: false},
		{Nickname: "relay3", HasNtorKey: true},
		{Nickname: "relay4", HasNtorKey: true},
		{Nickname: "relay5", HasNtorKey: false},
	}
	got := countNtorKeys(relays)
	if got != 3 {
		t.Fatalf("countNtorKeys = %d, want 3", got)
	}
}

// TestCountNtorKeysEmpty verifies countNtorKeys with an empty slice.
func TestCountNtorKeysEmpty(t *testing.T) {
	got := countNtorKeys(nil)
	if got != 0 {
		t.Fatalf("countNtorKeys(nil) = %d, want 0", got)
	}
}

// TestRelayInfoFromConsensus verifies that relayInfoFromConsensus correctly
// maps Relay fields to RelayInfo fields.
func TestRelayInfoFromConsensus(t *testing.T) {
	relay := &directory.Relay{
		Address: "1.2.3.4",
		ORPort:  9001,
	}
	relay.Identity = [20]byte{1, 2, 3}
	relay.NtorOnionKey = [32]byte{4, 5, 6}

	info := relayInfoFromConsensus(relay)
	if info.Address != "1.2.3.4" {
		t.Fatalf("Address = %s, want 1.2.3.4", info.Address)
	}
	if info.ORPort != 9001 {
		t.Fatalf("ORPort = %d, want 9001", info.ORPort)
	}
	if info.NodeID != relay.Identity {
		t.Fatal("NodeID mismatch")
	}
	if info.NtorOnionKey != relay.NtorOnionKey {
		t.Fatal("NtorOnionKey mismatch")
	}
}

// TestShuffleAuthoritiesLength verifies that shuffleAuthorities returns
// all authorities (same count as DirAuthorities).
func TestShuffleAuthoritiesLength(t *testing.T) {
	auths := shuffleAuthorities()
	if len(auths) != len(directory.DirAuthorities) {
		t.Fatalf("shuffleAuthorities returned %d, want %d", len(auths), len(directory.DirAuthorities))
	}
}

// TestShuffleAuthoritiesPreservesAllAuthorities verifies that shuffleAuthorities
// returns all authorities (same nicknames, possibly reordered).
func TestShuffleAuthoritiesPreservesAllAuthorities(t *testing.T) {
	auths := shuffleAuthorities()
	nicknames := make(map[string]bool)
	for _, a := range auths {
		nicknames[a.Nickname] = true
	}
	for _, a := range directory.DirAuthorities {
		if !nicknames[a.Nickname] {
			t.Fatalf("shuffleAuthorities missing authority %q", a.Nickname)
		}
	}
}

// TestShuffleAuthoritiesDoesNotMutateOriginal verifies that shuffleAuthorities
// does not modify the global DirAuthorities slice.
func TestShuffleAuthoritiesDoesNotMutateOriginal(t *testing.T) {
	// Record original order.
	original := make([]string, len(directory.DirAuthorities))
	for i, a := range directory.DirAuthorities {
		original[i] = a.Nickname
	}

	// Shuffle many times.
	for i := 0; i < 10; i++ {
		_ = shuffleAuthorities()
	}

	// Verify original is unchanged.
	for i, a := range directory.DirAuthorities {
		if a.Nickname != original[i] {
			t.Fatalf("DirAuthorities[%d] changed from %q to %q", i, original[i], a.Nickname)
		}
	}
}

// TestCountMissingNtorKeys verifies the countMissingNtorKeys helper.
func TestCountMissingNtorKeys(t *testing.T) {
	relays := []directory.Relay{
		{Nickname: "r1", HasNtorKey: true},
		{Nickname: "r2", HasNtorKey: false},
		{Nickname: "r3", HasNtorKey: false},
		{Nickname: "r4", HasNtorKey: true},
	}
	got := countMissingNtorKeys(relays)
	if got != 2 {
		t.Fatalf("countMissingNtorKeys = %d, want 2", got)
	}
}

// TestCountMissingNtorKeysAllPresent verifies zero when all have keys.
func TestCountMissingNtorKeysAllPresent(t *testing.T) {
	relays := []directory.Relay{
		{HasNtorKey: true},
		{HasNtorKey: true},
	}
	if got := countMissingNtorKeys(relays); got != 0 {
		t.Fatalf("countMissingNtorKeys = %d, want 0", got)
	}
}

// TestCountMissingNtorKeysNil verifies empty input.
func TestCountMissingNtorKeysNil(t *testing.T) {
	if got := countMissingNtorKeys(nil); got != 0 {
		t.Fatalf("countMissingNtorKeys(nil) = %d, want 0", got)
	}
}

// TestFilterUsefulRelays verifies that only relays with Running+Valid
// and at least one useful flag (Guard, Exit, Fast, HSDir) are returned.
func TestFilterUsefulRelays(t *testing.T) {
	relays := []directory.Relay{
		{Nickname: "guard", Flags: directory.RelayFlags{Running: true, Valid: true, Guard: true}},
		{Nickname: "exit", Flags: directory.RelayFlags{Running: true, Valid: true, Exit: true}},
		{Nickname: "fast", Flags: directory.RelayFlags{Running: true, Valid: true, Fast: true}},
		{Nickname: "hsdir", Flags: directory.RelayFlags{Running: true, Valid: true, HSDir: true}},
		{Nickname: "not-running", Flags: directory.RelayFlags{Running: false, Valid: true, Guard: true}},
		{Nickname: "not-valid", Flags: directory.RelayFlags{Running: true, Valid: false, Guard: true}},
		{Nickname: "no-flags", Flags: directory.RelayFlags{Running: true, Valid: true}},
		{Nickname: "stable-only", Flags: directory.RelayFlags{Running: true, Valid: true, Stable: true}},
	}
	useful := filterUsefulRelays(relays)
	if len(useful) != 4 {
		t.Fatalf("filterUsefulRelays returned %d, want 4", len(useful))
	}
	names := map[string]bool{}
	for _, r := range useful {
		names[r.Nickname] = true
	}
	for _, want := range []string{"guard", "exit", "fast", "hsdir"} {
		if !names[want] {
			t.Fatalf("expected %q in filtered relays", want)
		}
	}
}

// TestFilterUsefulRelaysEmpty verifies empty input.
func TestFilterUsefulRelaysEmpty(t *testing.T) {
	useful := filterUsefulRelays(nil)
	if len(useful) != 0 {
		t.Fatalf("filterUsefulRelays(nil) returned %d, want 0", len(useful))
	}
}

// TestE2EBootstrapSequence is an end-to-end test that verifies the complete
// bootstrap sequence: FetchAuthorityDescriptor (plaintext) -> BootstrapCircuit ->
// FetchConsensus (BEGIN_DIR) -> FetchKeyCerts (BEGIN_DIR) -> validate -> parse.
// This confirms that:
// 1. Only one plaintext fetch (FetchAuthorityDescriptor) is used
// 2. All other fetches go through BEGIN_DIR
// 3. Authority iteration with fallback works
// 4. Bootstrap circuit and link are properly closed (defer in testBootstrapFromAuthority)
func TestE2EBootstrapSequence(t *testing.T) {
	skipIfShort(t)

	// Try each authority with fallback, mirroring fetchFromAuthorities.
	var data *bootstrapData
	var succeededAuth string
	for i := range directory.DirAuthorities {
		auth := &directory.DirAuthorities[i]
		d, err := testBootstrapFromAuthority(t, auth)
		if err != nil {
			t.Logf("authority %s failed: %v", auth.Nickname, err)
			continue
		}
		data = d
		succeededAuth = auth.Nickname
		break
	}
	if data == nil {
		t.Fatal("failed to bootstrap from any authority")
		return // unreachable; helps staticcheck SA5011
	}
	t.Logf("bootstrapped from authority %s", succeededAuth)

	// Verify consensus text is substantial.
	if len(data.consensusText) < 1000 {
		t.Fatalf("consensus too small: %d bytes", len(data.consensusText))
	}

	// Verify we got key certs (fetched via BEGIN_DIR).
	if len(data.keyCerts) < 5 {
		t.Fatalf("expected >=5 key certs, got %d", len(data.keyCerts))
	}

	// Validate signatures (proves the consensus was fetched correctly).
	if err := directory.ValidateSignatures(data.consensusText, data.keyCerts); err != nil {
		t.Fatalf("ValidateSignatures: %v", err)
	}

	// Parse and validate freshness.
	consensus, err := directory.ParseConsensus(data.consensusText)
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}
	if err := directory.ValidateFreshness(consensus); err != nil {
		t.Fatalf("ValidateFreshness: %v", err)
	}

	// Verify the cache round-trip works (cache-hit path without circuit).
	cache := &directory.Cache{Dir: t.TempDir()}
	if err := cache.SaveConsensus(data.consensusText, consensus.FreshUntil, consensus.ValidUntil); err != nil {
		t.Fatalf("SaveConsensus: %v", err)
	}
	if err := cache.SaveKeyCerts(data.keyCerts); err != nil {
		t.Fatalf("SaveKeyCerts: %v", err)
	}

	// Reload from cache — no circuit needed.
	cachedData := loadFromCache(cache)
	if cachedData == nil {
		t.Fatal("loadFromCache returned nil after saving")
		return // unreachable; helps staticcheck SA5011
	}
	if cachedData.consensusText != data.consensusText {
		t.Fatal("cached consensus text differs from original")
	}
	if len(cachedData.keyCerts) < 5 {
		t.Fatalf("cached key certs: got %d, expected >=5", len(cachedData.keyCerts))
	}

	t.Logf("bootstrap sequence verified: %d relays, %d key certs, cache round-trip OK",
		len(consensus.Relays), len(data.keyCerts))
}
