package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseMicrodescriptor(t *testing.T) {
	// Create a test ntor key (32 bytes)
	ntorKeyBytes := make([]byte, 32)
	for i := range ntorKeyBytes {
		ntorKeyBytes[i] = byte(i)
	}
	ntorKeyB64 := base64.RawStdEncoding.EncodeToString(ntorKeyBytes)

	// Create a test ed25519 key
	edKeyBytes := make([]byte, 32)
	for i := range edKeyBytes {
		edKeyBytes[i] = byte(i + 100)
	}
	edKeyB64 := base64.RawStdEncoding.EncodeToString(edKeyBytes)

	text := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBALRFSomething\n-----END RSA PUBLIC KEY-----\nntor-onion-key " + ntorKeyB64 + "\nid ed25519 " + edKeyB64 + "\n"

	ntorKey, ed25519Key, hasNtor, hasEd := ParseMicrodescriptor(text)

	if !hasNtor {
		t.Fatal("expected ntor key")
	}
	if !hasEd {
		t.Fatal("expected ed25519 key")
	}

	for i := 0; i < 32; i++ {
		if ntorKey[i] != byte(i) {
			t.Fatalf("ntor key byte %d: got %d, want %d", i, ntorKey[i], i)
		}
	}

	for i := 0; i < 32; i++ {
		if ed25519Key[i] != byte(i+100) {
			t.Fatalf("ed25519 key byte %d: got %d, want %d", i, ed25519Key[i], i+100)
		}
	}
}

func TestParseMicrodescriptorNoKeys(t *testing.T) {
	text := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nstuff\n-----END RSA PUBLIC KEY-----\n"
	_, _, hasNtor, hasEd := ParseMicrodescriptor(text)
	if hasNtor {
		t.Fatal("should not have ntor key")
	}
	if hasEd {
		t.Fatal("should not have ed25519 key")
	}
}

func TestDigestMatchingPipeline(t *testing.T) {
	// Simulate: consensus has m line "sha256=<digest>", after parsing the prefix
	// is stripped, and the digest should match SHA-256 of the raw microdescriptor.
	microdesc := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBATest\n-----END RSA PUBLIC KEY-----\nntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"

	// Compute what the consensus would store (after stripping sha256= prefix)
	hash := sha256.Sum256([]byte(microdesc))
	digestB64 := base64.RawStdEncoding.EncodeToString(hash[:])

	// Simulate parsing consensus m line with sha256= prefix
	mLineDigest := "sha256=" + digestB64
	parsed := mLineDigest
	// This is what consensus.go now does: strip the prefix
	if len(parsed) > 7 && parsed[:7] == "sha256=" {
		parsed = parsed[7:]
	}

	// Now verify the split+hash matches
	entries := splitMicrodescriptors(microdesc)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	entryHash := sha256.Sum256([]byte(entries[0]))
	entryDigest := base64.RawStdEncoding.EncodeToString(entryHash[:])

	if entryDigest != parsed {
		t.Fatalf("digest mismatch: split entry %q != consensus %q", entryDigest, parsed)
	}
}

func TestSplitMicrodescriptors(t *testing.T) {
	body := "onion-key\nfirst entry\nntor-onion-key AAA\nonion-key\nsecond entry\nntor-onion-key BBB\n"
	entries := splitMicrodescriptors(body)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
}

func TestSplitMicrodescriptorsEmpty(t *testing.T) {
	entries := splitMicrodescriptors("")
	if len(entries) != 0 {
		t.Fatalf("got %d entries from empty body, want 0", len(entries))
	}
}

func TestSplitMicrodescriptorsSingle(t *testing.T) {
	body := "onion-key\nonly entry\nntor-onion-key AAA\n"
	entries := splitMicrodescriptors(body)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
}

func TestUpdateRelaysWithMicrodescriptorsNilCircuitTwoBatches(t *testing.T) {
	// Use 93 relays to exercise the batching boundary (batch size = 92),
	// ensuring two batches are attempted and both fail with nil circuit.
	relays := make([]Relay, 93)
	for i := range relays {
		relays[i] = Relay{MicrodescDigest: fmt.Sprintf("digest-%d", i)}
	}
	err := UpdateRelaysWithMicrodescriptors(nil, relays)
	if err == nil {
		t.Fatal("expected error for nil circuit with 93 relays (2 batches)")
	}
	if !strings.Contains(err.Error(), "all microdescriptor batches failed") {
		t.Fatalf("expected all-batches-failed error, got: %v", err)
	}
}

func TestUpdateRelaysWithMicrodescriptorsNoDigests(t *testing.T) {
	relays := []Relay{{Nickname: "abc"}, {Nickname: "def"}}
	err := UpdateRelaysWithMicrodescriptors(nil, relays)
	if err != nil {
		t.Fatalf("expected nil error for relays without digests, got: %v", err)
	}
}

func TestUpdateRelaysWithMicrodescriptorsEmptyRelays(t *testing.T) {
	err := UpdateRelaysWithMicrodescriptors(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error for empty relays, got: %v", err)
	}
}

func TestUpdateRelaysWithMicrodescriptorsErrorOnAllBatchesFailed(t *testing.T) {
	// Create relays with digests that won't match anything
	// The function should return an error since FetchViaBeginDir will fail with nil circuit
	relays := []Relay{
		{MicrodescDigest: "digest1"},
		{MicrodescDigest: "digest2"},
	}
	err := UpdateRelaysWithMicrodescriptors(nil, relays)
	if err == nil {
		t.Fatal("expected error when all batches fail")
	}
	if !strings.Contains(err.Error(), "all microdescriptor batches failed") {
		t.Fatalf("expected all-batches-failed error, got: %v", err)
	}
}

func TestParseMicrodescriptorInvalidBase64(t *testing.T) {
	text := "ntor-onion-key !!!invalid!!!\nid ed25519 !!!invalid!!!\n"
	_, _, hasNtor, hasEd := ParseMicrodescriptor(text)
	if hasNtor {
		t.Fatal("should not parse invalid ntor key")
	}
	if hasEd {
		t.Fatal("should not parse invalid ed25519 key")
	}
}

func TestParseMicrodescriptorWrongLength(t *testing.T) {
	// 16 bytes instead of 32
	shortKey := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	text := "ntor-onion-key " + shortKey + "\nid ed25519 " + shortKey + "\n"
	_, _, hasNtor, hasEd := ParseMicrodescriptor(text)
	if hasNtor {
		t.Fatal("should not accept 16-byte ntor key")
	}
	if hasEd {
		t.Fatal("should not accept 16-byte ed25519 key")
	}
}

func TestParseMicrodescriptorNtorOnly(t *testing.T) {
	ntorKeyBytes := make([]byte, 32)
	ntorKeyB64 := base64.RawStdEncoding.EncodeToString(ntorKeyBytes)
	text := "ntor-onion-key " + ntorKeyB64 + "\n"
	_, _, hasNtor, hasEd := ParseMicrodescriptor(text)
	if !hasNtor {
		t.Fatal("expected ntor key")
	}
	if hasEd {
		t.Fatal("should not have ed25519 key")
	}
}

func TestParseMicrodescriptorEd25519Only(t *testing.T) {
	edKeyBytes := make([]byte, 32)
	for i := range edKeyBytes {
		edKeyBytes[i] = byte(i + 50)
	}
	edKeyB64 := base64.RawStdEncoding.EncodeToString(edKeyBytes)
	text := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nstuff\n-----END RSA PUBLIC KEY-----\nid ed25519 " + edKeyB64 + "\n"

	_, ed25519Key, hasNtor, hasEd := ParseMicrodescriptor(text)
	if hasNtor {
		t.Fatal("should not have ntor key")
	}
	if !hasEd {
		t.Fatal("expected ed25519 key")
	}
	if !bytes.Equal(ed25519Key[:], edKeyBytes) {
		t.Fatalf("ed25519 key mismatch: got %v, want %v", ed25519Key[:], edKeyBytes)
	}
}

func TestParseMicrodescriptorBothKeys(t *testing.T) {
	ntorKeyBytes := make([]byte, 32)
	for i := range ntorKeyBytes {
		ntorKeyBytes[i] = byte(i * 3)
	}
	edKeyBytes := make([]byte, 32)
	for i := range edKeyBytes {
		edKeyBytes[i] = byte(i * 7)
	}
	ntorKeyB64 := base64.RawStdEncoding.EncodeToString(ntorKeyBytes)
	edKeyB64 := base64.RawStdEncoding.EncodeToString(edKeyBytes)

	text := "onion-key\n-----BEGIN RSA PUBLIC KEY-----\nstuff\n-----END RSA PUBLIC KEY-----\nntor-onion-key " + ntorKeyB64 + "\nid ed25519 " + edKeyB64 + "\n"

	ntorKey, ed25519Key, hasNtor, hasEd := ParseMicrodescriptor(text)
	if !hasNtor {
		t.Fatal("expected ntor key")
	}
	if !hasEd {
		t.Fatal("expected ed25519 key")
	}
	if !bytes.Equal(ntorKey[:], ntorKeyBytes) {
		t.Fatalf("ntor key bytes mismatch: got %v, want %v", ntorKey[:], ntorKeyBytes)
	}
	if !bytes.Equal(ed25519Key[:], edKeyBytes) {
		t.Fatalf("ed25519 key bytes mismatch: got %v, want %v", ed25519Key[:], edKeyBytes)
	}
}

func TestSplitMicrodescriptorsMarkerOnly(t *testing.T) {
	entries := splitMicrodescriptors("onion-key\n")
	// "onion-key\n" is the marker itself with no additional content;
	// splitMicrodescriptors produces "onion-key\n" which TrimSpace is "onion-key" (non-empty),
	// so it should yield one entry.
	if len(entries) != 1 {
		t.Fatalf("got %d entries for marker-only input, want 1", len(entries))
	}
	if entries[0] != "onion-key\n" {
		t.Fatalf("unexpected entry content: %q", entries[0])
	}
}
