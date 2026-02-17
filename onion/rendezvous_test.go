package onion

import (
	"testing"
)

func TestBuildINTRODUCE1(t *testing.T) {
	authKey := make([]byte, 32)
	authKey[0] = 0x42
	var encKey [32]byte
	encKey[0] = 0x09 // Must be valid curve25519 point
	var subcred [32]byte
	subcred[0] = 0xAA
	var rendCookie [20]byte
	rendCookie[0] = 0xBB
	var rendOnionKey [32]byte
	rendOnionKey[0] = 0xCC

	rendLinkSpecs, err := BuildRendLinkSpecs([20]byte{0x01}, "127.0.0.1", 9001, [32]byte{0x02})
	if err != nil {
		t.Fatalf("BuildRendLinkSpecs: %v", err)
	}

	payload, state, err := BuildINTRODUCE1(authKey, encKey, subcred, rendCookie, rendOnionKey, rendLinkSpecs)
	if err != nil {
		t.Fatalf("BuildINTRODUCE1: %v", err)
	}

	if state == nil {
		t.Fatal("expected non-nil state")
	}
	if len(payload) == 0 {
		t.Fatal("expected non-empty payload")
	}

	// Header should start with 20 zero bytes (LEGACY_KEY_ID).
	for i := 0; i < 20; i++ {
		if payload[i] != 0 {
			t.Fatalf("LEGACY_KEY_ID byte %d: got 0x%02x, want 0x00", i, payload[i])
		}
	}

	// AUTH_KEY_TYPE should be 0x02.
	if payload[20] != 0x02 {
		t.Fatalf("AUTH_KEY_TYPE: got 0x%02x, want 0x02", payload[20])
	}
}

func TestBuildRendLinkSpecs(t *testing.T) {
	specs, err := BuildRendLinkSpecs([20]byte{0x01}, "192.168.1.1", 443, [32]byte{0x02})
	if err != nil {
		t.Fatalf("BuildRendLinkSpecs: %v", err)
	}

	if specs[0] != 3 {
		t.Fatalf("NSPEC: got %d, want 3", specs[0])
	}

	// First spec: LSTYPE=0x00, LSLEN=0x06
	if specs[1] != 0x00 || specs[2] != 0x06 {
		t.Fatalf("first link spec type/len: got %x %x", specs[1], specs[2])
	}
	// IP: 192.168.1.1
	if specs[3] != 192 || specs[4] != 168 || specs[5] != 1 || specs[6] != 1 {
		t.Fatalf("IP bytes: %v", specs[3:7])
	}
	// Port: 443 = 0x01BB
	if specs[7] != 0x01 || specs[8] != 0xBB {
		t.Fatalf("port bytes: %x %x", specs[7], specs[8])
	}
}

func TestBuildRendLinkSpecsNoEd25519(t *testing.T) {
	specs, err := BuildRendLinkSpecs([20]byte{0x01}, "10.0.0.1", 9001, [32]byte{})
	if err != nil {
		t.Fatalf("BuildRendLinkSpecs: %v", err)
	}
	if specs[0] != 2 {
		t.Fatalf("NSPEC without ed25519: got %d, want 2", specs[0])
	}
}

func TestGenerateRendezvousCookie(t *testing.T) {
	c1, err := GenerateRendezvousCookie()
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := GenerateRendezvousCookie()
	if c1 == c2 {
		t.Fatal("cookies should be different")
	}
	if c1 == [20]byte{} {
		t.Fatal("cookie should not be zero")
	}
}

func TestCompleteRendezvousTooShort(t *testing.T) {
	_, err := CompleteRendezvous(&HsNtorClientState{}, make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for short RENDEZVOUS2 body")
	}
}

func TestHsNtorExpandKeys(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 0x42
	df, db, kf, kb := HsNtorExpandKeys(seed)

	// All should be non-zero and different.
	if df == [32]byte{} || db == [32]byte{} || kf == [32]byte{} || kb == [32]byte{} {
		t.Fatal("keys should not be zero")
	}
	if df == db || kf == kb || df == kf {
		t.Fatal("keys should be different")
	}

	// Deterministic.
	df2, db2, kf2, kb2 := HsNtorExpandKeys(seed)
	if df != df2 || db != db2 || kf != kf2 || kb != kb2 {
		t.Fatal("key expansion should be deterministic")
	}
}
