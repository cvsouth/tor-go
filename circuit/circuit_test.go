package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"testing"

	"github.com/cvsouth/tor-go/ntor"
)

func TestAllocateCircID(t *testing.T) {
	for i := 0; i < 100; i++ {
		id, err := allocateCircID()
		if err != nil {
			t.Fatalf("allocateCircID: %v", err)
		}
		if id&0x80000000 == 0 {
			t.Fatalf("MSB not set: 0x%08x", id)
		}
		if id == 0 {
			t.Fatal("circID is zero")
		}
	}
}

func TestInitHop(t *testing.T) {
	km := &ntor.KeyMaterial{}
	for i := range km.Kf {
		km.Kf[i] = byte(i)
	}
	for i := range km.Kb {
		km.Kb[i] = byte(i + 16)
	}
	for i := range km.Df {
		km.Df[i] = byte(i + 32)
	}
	for i := range km.Db {
		km.Db[i] = byte(i + 52)
	}

	hop, err := initHop(km)
	if err != nil {
		t.Fatalf("initHop: %v", err)
	}

	// Verify cipher streams work by encrypting some data
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ct := make([]byte, 32)
	hop.kf.XORKeyStream(ct, plaintext)

	// Verify it's different from plaintext
	same := true
	for i := range ct {
		if ct[i] != plaintext[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("encryption produced identical output")
	}

	// Verify stream state persists (second encrypt produces different output)
	ct2 := make([]byte, 32)
	hop.kf.XORKeyStream(ct2, plaintext)
	allSame := true
	for i := range ct {
		if ct[i] != ct2[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("AES-CTR stream state not persisting - second encrypt identical to first")
	}
}

func TestCipherStreamPersistence(t *testing.T) {
	// Verify that encrypting 32 bytes at once produces the same result
	// as encrypting 16 bytes twice (proving stream state persists)
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, aes.BlockSize)

	// Approach 1: encrypt 32 bytes at once
	block1, _ := aes.NewCipher(key)
	stream1 := cipher.NewCTR(block1, iv)
	plaintext := make([]byte, 32)
	ct1 := make([]byte, 32)
	stream1.XORKeyStream(ct1, plaintext)

	// Approach 2: encrypt 16 bytes, then 16 bytes
	block2, _ := aes.NewCipher(key)
	stream2 := cipher.NewCTR(block2, iv)
	ct2 := make([]byte, 32)
	stream2.XORKeyStream(ct2[:16], plaintext[:16])
	stream2.XORKeyStream(ct2[16:], plaintext[16:])

	for i := range ct1 {
		if ct1[i] != ct2[i] {
			t.Fatalf("byte %d: one-shot=%02x, split=%02x", i, ct1[i], ct2[i])
		}
	}
}

func TestRelayEarlyBudget(t *testing.T) {
	circ := &Circuit{
		ID:             0x80000001,
		RelayEarlySent: 0,
	}
	// Budget should be 8
	if MaxRelayEarly != 8 {
		t.Fatalf("MaxRelayEarly = %d, want 8", MaxRelayEarly)
	}
	// Simulate sending up to the limit (without a real link, just test the counter)
	for i := 0; i < MaxRelayEarly; i++ {
		circ.RelayEarlySent++
	}
	// Now SendRelayEarly should fail
	if circ.RelayEarlySent < MaxRelayEarly {
		t.Fatal("counter should be at max")
	}
	// Verify the guard works
	err := circ.SendRelayEarly(nil)
	if err == nil {
		t.Fatal("expected RELAY_EARLY budget exhausted error")
	}
}

func TestDigestSeedPersistence(t *testing.T) {
	// Verify that SHA-1 digest seeded with Df produces correct running digest
	seed := make([]byte, 20)
	for i := range seed {
		seed[i] = byte(i)
	}

	h := sha1.New()
	h.Write(seed)
	h.Write([]byte("hello"))
	d1 := h.Sum(nil)

	// Same thing step by step should produce same result
	h2 := sha1.New()
	h2.Write(seed)
	h2.Write([]byte("hello"))
	d2 := h2.Sum(nil)

	for i := range d1 {
		if d1[i] != d2[i] {
			t.Fatal("digest not deterministic")
		}
	}

	// Adding more data should change the digest
	h.Write([]byte("world"))
	d3 := h.Sum(nil)
	same := true
	for i := range d1 {
		if d1[i] != d3[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("running digest not accumulating")
	}
}

func TestBackwardDigest(t *testing.T) {
	hop := testHop(0x10, 0x20, 0xAA, 0xBB)
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	d1 := circ.BackwardDigest()
	if d1 == nil {
		t.Fatal("BackwardDigest returned nil")
	}
	if len(d1) != 20 { // SHA-1 output
		t.Fatalf("digest length = %d, want 20", len(d1))
	}

	// Calling again without updates should return same value (Sum doesn't mutate state)
	d2 := circ.BackwardDigest()
	for i := range d1 {
		if d1[i] != d2[i] {
			t.Fatal("BackwardDigest not stable across calls")
		}
	}
}

func TestBackwardDigestNoHops(t *testing.T) {
	circ := &Circuit{ID: 0x80000001}
	d := circ.BackwardDigest()
	if d != nil {
		t.Fatal("expected nil for no hops")
	}
}

func TestNewHopAndAddHop(t *testing.T) {
	// Create a hop with custom crypto (simulating SHA3-256/AES-256-CTR).
	key := make([]byte, 32) // AES-256
	key[0] = 0x42
	iv := make([]byte, aes.BlockSize)

	fwdBlock, _ := aes.NewCipher(key)
	bwdBlock, _ := aes.NewCipher(key) // Same key for test simplicity
	kf := cipher.NewCTR(fwdBlock, iv)
	kb := cipher.NewCTR(bwdBlock, iv)
	df := sha1.New() // Using SHA1 for test; real onion uses SHA3
	db := sha1.New()
	df.Write([]byte("forward-seed"))
	db.Write([]byte("backward-seed"))

	hop := NewHop(kf, kb, df, db)
	if hop == nil {
		t.Fatal("NewHop returned nil")
	}

	// Test AddHop on a circuit.
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{},
	}
	circ.AddHop(hop)
	if len(circ.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(circ.Hops))
	}
}
