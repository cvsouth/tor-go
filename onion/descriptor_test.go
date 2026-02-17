package onion

import (
	"encoding/base64"
	"testing"
)

func TestParseDescriptorOuter(t *testing.T) {
	// Create a minimal valid descriptor.
	blob := []byte("encrypted-data-here-for-testing-purposes!")
	blobB64 := base64.StdEncoding.EncodeToString(blob)

	text := "hs-descriptor 3\n" +
		"descriptor-lifetime 180\n" +
		"descriptor-signing-key-cert\n" +
		"-----BEGIN ED25519 CERT-----\nAAAA\n-----END ED25519 CERT-----\n" +
		"revision-counter 42\n" +
		"superencrypted\n" +
		"-----BEGIN MESSAGE-----\n" +
		blobB64 + "\n" +
		"-----END MESSAGE-----\n" +
		"signature BBBB\n"

	d, err := ParseDescriptorOuter(text)
	if err != nil {
		t.Fatalf("ParseDescriptorOuter: %v", err)
	}

	if d.LifetimeSeconds != 180 {
		t.Fatalf("lifetime: got %d, want 180", d.LifetimeSeconds)
	}
	if d.RevisionCounter != 42 {
		t.Fatalf("revision: got %d, want 42", d.RevisionCounter)
	}
	if string(d.Superencrypted) != string(blob) {
		t.Fatalf("superencrypted: got %q, want %q", d.Superencrypted, blob)
	}
}

func TestParseDescriptorOuterNoBlob(t *testing.T) {
	text := "hs-descriptor 3\ndescriptor-lifetime 180\nrevision-counter 1\n"
	_, err := ParseDescriptorOuter(text)
	if err == nil {
		t.Fatal("expected error for missing superencrypted blob")
	}
}
