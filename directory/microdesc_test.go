package directory

import (
	"crypto/sha256"
	"encoding/base64"
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
