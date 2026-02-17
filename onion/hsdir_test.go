package onion

import (
	"bytes"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/directory"
)

func makeTestRelay(id byte, hsdir bool) directory.Relay {
	var ed [32]byte
	ed[0] = id
	return directory.Relay{
		Nickname:   string(rune('A' + id)),
		HasEd25519: true,
		Ed25519ID:  ed,
		Flags: directory.RelayFlags{
			HSDir:   hsdir,
			Running: true,
			Valid:   true,
		},
	}
}

func TestServiceIndex(t *testing.T) {
	var blindedKey [32]byte
	blindedKey[0] = 0x42

	idx1 := serviceIndex(blindedKey, 1, 1440, 16904)
	idx2 := serviceIndex(blindedKey, 2, 1440, 16904)

	// Different replicas should give different indices.
	if idx1 == idx2 {
		t.Fatal("different replicas should produce different service indices")
	}

	// Deterministic.
	idx1b := serviceIndex(blindedKey, 1, 1440, 16904)
	if idx1 != idx1b {
		t.Fatal("serviceIndex should be deterministic")
	}
}

func TestRelayIndex(t *testing.T) {
	nodeID := make([]byte, 32)
	nodeID[0] = 0x01
	srv := make([]byte, 32)
	srv[0] = 0xAA

	idx := relayIndex(nodeID, srv, 16904, 1440)
	if idx == [32]byte{} {
		t.Fatal("relay index should not be zero")
	}

	// Different SRV gives different index.
	srv2 := make([]byte, 32)
	srv2[0] = 0xBB
	idx2 := relayIndex(nodeID, srv2, 16904, 1440)
	if idx == idx2 {
		t.Fatal("different SRV should give different relay index")
	}
}

func TestSelectHSDirs(t *testing.T) {
	// Create a consensus with several HSDir relays.
	c := &directory.Consensus{
		ValidAfter:             time.Date(2020, 1, 1, 14, 0, 0, 0, time.UTC),
		SharedRandCurrentValue: make([]byte, 32),
	}
	for i := byte(0); i < 20; i++ {
		c.Relays = append(c.Relays, makeTestRelay(i, true))
	}

	var blindedKey [32]byte
	blindedKey[0] = 0x42

	result, err := SelectHSDirs(c, blindedKey, 16904, 1440, c.SharedRandCurrentValue)
	if err != nil {
		t.Fatalf("SelectHSDirs: %v", err)
	}

	// Should get up to hsdirNReplicas * hsdirSpreadFetch = 6 relays (minus dedup).
	if len(result) == 0 {
		t.Fatal("expected at least one HSDir")
	}
	if len(result) > hsdirNReplicas*hsdirSpreadFetch {
		t.Fatalf("too many HSDirs: %d", len(result))
	}

	// No duplicates.
	seen := make(map[byte]bool)
	for _, r := range result {
		if seen[r.Ed25519ID[0]] {
			t.Fatalf("duplicate HSDir: %d", r.Ed25519ID[0])
		}
		seen[r.Ed25519ID[0]] = true
	}
}

func TestSelectHSDirsNoHSDir(t *testing.T) {
	c := &directory.Consensus{
		SharedRandCurrentValue: make([]byte, 32),
	}
	// Add relays without HSDir flag.
	for i := byte(0); i < 5; i++ {
		c.Relays = append(c.Relays, makeTestRelay(i, false))
	}

	var blindedKey [32]byte
	_, err := SelectHSDirs(c, blindedKey, 16904, 1440, c.SharedRandCurrentValue)
	if err == nil {
		t.Fatal("expected error with no HSDir relays")
	}
}

func TestSelectHSDirsNoSRV(t *testing.T) {
	c := &directory.Consensus{}
	var blindedKey [32]byte
	_, err := SelectHSDirs(c, blindedKey, 16904, 1440, nil)
	if err == nil {
		t.Fatal("expected error with no SRV")
	}
}

func TestGetSRVForClient(t *testing.T) {
	current := bytes.Repeat([]byte{0xAA}, 32)
	previous := bytes.Repeat([]byte{0xBB}, 32)

	// Hour >= 12: use current SRV.
	c := &directory.Consensus{
		ValidAfter:              time.Date(2020, 1, 1, 14, 0, 0, 0, time.UTC),
		SharedRandCurrentValue:  current,
		SharedRandPreviousValue: previous,
	}
	srv, err := GetSRVForClient(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srv, current) {
		t.Fatal("hour>=12 should use current SRV")
	}

	// Hour < 12: use previous SRV.
	c.ValidAfter = time.Date(2020, 1, 1, 6, 0, 0, 0, time.UTC)
	srv, err = GetSRVForClient(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(srv, previous) {
		t.Fatal("hour<12 should use previous SRV")
	}
}

func TestPickRandomHSDir(t *testing.T) {
	relays := []*directory.Relay{
		{Nickname: "A"},
		{Nickname: "B"},
		{Nickname: "C"},
	}
	r, err := PickRandomHSDir(relays)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("expected non-nil relay")
	}
}

func TestPickRandomHSDirEmpty(t *testing.T) {
	_, err := PickRandomHSDir(nil)
	if err == nil {
		t.Fatal("expected error for empty list")
	}
}
