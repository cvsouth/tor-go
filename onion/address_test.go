package onion

import (
	"encoding/base32"
	"strings"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestDecodeOnionKnownAddresses(t *testing.T) {
	// Known valid v3 .onion addresses from rend-spec-v3
	addrs := []string{
		"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
		"sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion",
		"xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion",
	}

	for _, addr := range addrs {
		pubkey, err := DecodeOnion(addr)
		if err != nil {
			t.Fatalf("DecodeOnion(%q): %v", addr, err)
		}
		if pubkey == [32]byte{} {
			t.Fatalf("got zero pubkey for %q", addr)
		}
	}
}

func TestDecodeOnionRoundTrip(t *testing.T) {
	addr := "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
	pk, err := DecodeOnion(addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Re-encode and verify
	var buf [35]byte
	copy(buf[:32], pk[:])
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pk[:])
	h.Write([]byte{0x03})
	checksum := h.Sum(nil)[:2]
	buf[32] = checksum[0]
	buf[33] = checksum[1]
	buf[34] = 0x03
	reEncoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:])) + ".onion"
	if reEncoded != addr {
		t.Fatalf("round-trip failed: %q != %q", reEncoded, addr)
	}
}

func TestDecodeOnionBadChecksum(t *testing.T) {
	// Take a valid address and corrupt the checksum (change a character)
	addr := "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"
	_, err := DecodeOnion(addr)
	if err == nil {
		t.Fatal("expected error for bad checksum")
	}
}

func TestDecodeOnionBadVersion(t *testing.T) {
	// Decode a valid address, change version to 0x02, re-encode
	decoded, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(
		strings.ToUpper("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd"))
	decoded[34] = 0x02
	addr := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded)) + ".onion"

	_, err := DecodeOnion(addr)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestDecodeOnionTooShort(t *testing.T) {
	_, err := DecodeOnion("short.onion")
	if err == nil {
		t.Fatal("expected error for short address")
	}
}

func TestDecodeOnionWithoutSuffix(t *testing.T) {
	// Should work without .onion suffix
	addr := "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd"
	_, err := DecodeOnion(addr)
	if err != nil {
		t.Fatalf("DecodeOnion without .onion suffix: %v", err)
	}
}

func TestIsOnionAddress(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"example.onion:80", true},
		{"abc123.onion:443", true},
		{"ABC.ONION:80", true},
		{"example.com:80", false},
		{"example.onion", true},
		{"notanonion.com", false},
		{"", false},
	}
	for _, tt := range tests {
		got := IsOnionAddress(tt.input)
		if got != tt.want {
			t.Errorf("IsOnionAddress(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestCurrentTimePeriod(t *testing.T) {
	tp := CurrentTimePeriod()
	if tp <= 0 {
		t.Fatalf("CurrentTimePeriod() = %d, expected positive", tp)
	}
}
