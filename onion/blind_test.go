package onion

import (
	"testing"
	"time"

	"filippo.io/edwards25519"
)

func TestTimePeriodBasic(t *testing.T) {
	// From rend-spec-v3: 2016-04-13 11:15:01 UTC
	// minutes_since_epoch = 1460546101 / 60 = 24342435
	// tp = (24342435 - 720) / 1440 = 16904 (with integer division)
	ts := time.Date(2016, 4, 13, 11, 15, 1, 0, time.UTC)
	tp := TimePeriod(ts, 0)

	minutesSinceEpoch := ts.Unix() / 60 // 24342435
	expected := (minutesSinceEpoch - rotationTimeOffset) / defaultTimePeriodLength
	if tp != expected {
		t.Fatalf("TimePeriod: got %d, want %d", tp, expected)
	}
}

func TestTimePeriodEpoch(t *testing.T) {
	// At epoch + rotationTimeOffset minutes, tp should be 0
	ts := time.Unix(rotationTimeOffset*60, 0)
	tp := TimePeriod(ts, 0)
	if tp != 0 {
		t.Fatalf("TimePeriod at offset: got %d, want 0", tp)
	}
}

func TestTimePeriodCustomLength(t *testing.T) {
	ts := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	tp1 := TimePeriod(ts, 1440)
	tp2 := TimePeriod(ts, 0) // default is also 1440
	if tp1 != tp2 {
		t.Fatalf("custom length 1440 should match default: %d vs %d", tp1, tp2)
	}

	// Shorter period = larger period number
	tp3 := TimePeriod(ts, 720)
	if tp3 <= tp1 {
		t.Fatalf("shorter period should give larger number: %d vs %d", tp3, tp1)
	}
}

func TestBlindPublicKeyValid(t *testing.T) {
	// Use the Ed25519 basepoint as a known valid point
	B := edwards25519.NewGeneratorPoint()
	var pubkey [32]byte
	copy(pubkey[:], B.Bytes())

	blinded, err := BlindPublicKey(pubkey, 16904, 0)
	if err != nil {
		t.Fatalf("BlindPublicKey: %v", err)
	}

	// Blinded key should be a valid point
	if _, err := new(edwards25519.Point).SetBytes(blinded[:]); err != nil {
		t.Fatalf("blinded key is not a valid point: %v", err)
	}

	// Blinded key should differ from original
	if blinded == pubkey {
		t.Fatal("blinded key should differ from original")
	}
}

func TestBlindPublicKeyDeterministic(t *testing.T) {
	B := edwards25519.NewGeneratorPoint()
	var pubkey [32]byte
	copy(pubkey[:], B.Bytes())

	b1, _ := BlindPublicKey(pubkey, 100, 1440)
	b2, _ := BlindPublicKey(pubkey, 100, 1440)
	if b1 != b2 {
		t.Fatal("BlindPublicKey should be deterministic")
	}

	// Different period should give different result
	b3, _ := BlindPublicKey(pubkey, 101, 1440)
	if b1 == b3 {
		t.Fatal("different period should give different blinded key")
	}
}

func TestBlindPublicKeyInvalidPoint(t *testing.T) {
	var bad [32]byte
	bad[0] = 0x02 // y=2 has no valid x on the curve
	_, err := BlindPublicKey(bad, 100, 1440)
	if err == nil {
		t.Fatal("expected error for invalid point")
	}
}

func TestSubcredential(t *testing.T) {
	B := edwards25519.NewGeneratorPoint()
	var pubkey [32]byte
	copy(pubkey[:], B.Bytes())

	blinded, err := BlindPublicKey(pubkey, 16904, 0)
	if err != nil {
		t.Fatalf("BlindPublicKey: %v", err)
	}

	subcred := Subcredential(pubkey, blinded)

	// Should be non-zero
	if subcred == [32]byte{} {
		t.Fatal("subcredential should not be zero")
	}

	// Should be deterministic
	subcred2 := Subcredential(pubkey, blinded)
	if subcred != subcred2 {
		t.Fatal("subcredential should be deterministic")
	}

	// Different blinded key should give different subcredential
	blinded2, _ := BlindPublicKey(pubkey, 16905, 0)
	subcred3 := Subcredential(pubkey, blinded2)
	if subcred == subcred3 {
		t.Fatal("different blinded key should give different subcredential")
	}
}

func TestBuildBlindNonce(t *testing.T) {
	nonce := buildBlindNonce(100, 1440)
	// "key-blind" (9 bytes) + period (8 bytes) + length (8 bytes) = 25 bytes
	if len(nonce) != 25 {
		t.Fatalf("nonce length: got %d, want 25", len(nonce))
	}
	if string(nonce[:9]) != "key-blind" {
		t.Fatalf("nonce prefix: got %q", nonce[:9])
	}
}
