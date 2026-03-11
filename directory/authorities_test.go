package directory

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestDirAuthoritiesCount(t *testing.T) {
	if len(DirAuthorities) != 9 {
		t.Fatalf("expected 9 directory authorities, got %d", len(DirAuthorities))
	}
}

func TestDirAuthoritiesUniqueNicknames(t *testing.T) {
	seen := make(map[string]bool)
	for _, auth := range DirAuthorities {
		if seen[auth.Nickname] {
			t.Fatalf("duplicate nickname: %s", auth.Nickname)
		}
		seen[auth.Nickname] = true
	}
}

func TestDirAuthoritiesUniqueV3Idents(t *testing.T) {
	seen := make(map[string]bool)
	for _, auth := range DirAuthorities {
		if seen[auth.V3Ident] {
			t.Fatalf("duplicate V3Ident: %s", auth.V3Ident)
		}
		seen[auth.V3Ident] = true
	}
}

func TestDirAuthoritiesV3IdentLength(t *testing.T) {
	for _, auth := range DirAuthorities {
		if len(auth.V3Ident) != 40 {
			t.Fatalf("%s: V3Ident length %d, expected 40", auth.Nickname, len(auth.V3Ident))
		}
	}
}

func TestDirAuthoritiesFingerprintMatchesV3Ident(t *testing.T) {
	for _, auth := range DirAuthorities {
		fpHex := hex.EncodeToString(auth.Fingerprint[:])
		expected := auth.V3Ident
		// Compare case-insensitively
		if len(fpHex) != 40 {
			t.Fatalf("%s: fingerprint hex length %d", auth.Nickname, len(fpHex))
		}
		decoded, err := hex.DecodeString(expected)
		if err != nil {
			t.Fatalf("%s: V3Ident not valid hex: %v", auth.Nickname, err)
		}
		for i, b := range decoded {
			if auth.Fingerprint[i] != b {
				t.Fatalf("%s: Fingerprint[%d] = %02x, expected %02x", auth.Nickname, i, auth.Fingerprint[i], b)
			}
		}
	}
}

func TestDirAuthoritiesPortsNonZero(t *testing.T) {
	for _, auth := range DirAuthorities {
		if auth.ORPort == 0 {
			t.Fatalf("%s: ORPort is 0", auth.Nickname)
		}
		if auth.DirPort == 0 {
			t.Fatalf("%s: DirPort is 0", auth.Nickname)
		}
	}
}

func TestDirAuthoritiesAddressNonEmpty(t *testing.T) {
	for _, auth := range DirAuthorities {
		if auth.Address == "" {
			t.Fatalf("%s: Address is empty", auth.Nickname)
		}
	}
}

func TestDirAuthorityDirAddr(t *testing.T) {
	tests := []struct {
		nickname string
		expected string
	}{
		{"moria1", "128.31.0.39:9131"},
		{"tor26", "86.59.21.38:80"},
		{"bastet", "66.111.2.131:9030"},
		{"maatuska", "171.25.193.9:443"},
	}
	for _, tt := range tests {
		for i := range DirAuthorities {
			if DirAuthorities[i].Nickname == tt.nickname {
				got := DirAuthorities[i].DirAddr()
				if got != tt.expected {
					t.Errorf("%s: DirAddr() = %q, want %q", tt.nickname, got, tt.expected)
				}
				break
			}
		}
	}
}

func TestDirAuthoritiesEd25519IDZero(t *testing.T) {
	var zero [32]byte
	for _, auth := range DirAuthorities {
		if auth.Ed25519ID != zero {
			t.Fatalf("%s: Ed25519ID should be zero (populated later from consensus/descriptor)", auth.Nickname)
		}
	}
}

func TestDirAuthorityFingerprintsDerivedFromDirAuthorities(t *testing.T) {
	// Verify that dirAuthorityFingerprints (populated by init()) matches DirAuthorities
	if len(dirAuthorityFingerprints) != len(DirAuthorities) {
		t.Fatalf("dirAuthorityFingerprints has %d entries, DirAuthorities has %d",
			len(dirAuthorityFingerprints), len(DirAuthorities))
	}
	for _, auth := range DirAuthorities {
		if !dirAuthorityFingerprints[auth.V3Ident] {
			t.Fatalf("dirAuthorityFingerprints missing %s (%s)", auth.Nickname, auth.V3Ident)
		}
	}
}

func TestFetchAuthorityDescriptorIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Shuffle authorities so we don't always hit the same one first
	auths := make([]DirAuthority, len(DirAuthorities))
	copy(auths, DirAuthorities)
	rand.Shuffle(len(auths), func(i, j int) { auths[i], auths[j] = auths[j], auths[i] })

	var lastErr error
	for _, auth := range auths {
		auth := auth
		info, err := FetchAuthorityDescriptor(&auth)
		if err != nil {
			t.Logf("authority %s failed: %v", auth.Nickname, err)
			lastErr = err
			continue
		}

		// Verify key is non-zero
		var zero [32]byte
		if info.NtorOnionKey == zero {
			t.Fatalf("authority %s returned zero ntor key", auth.Nickname)
		}

		t.Logf("authority %s returned ntor key: %x", auth.Nickname, info.NtorOnionKey)
		return // success
	}

	t.Fatalf("all authorities unreachable; last error: %v", lastErr)
}

func TestDirAuthoritiesKnownNicknames(t *testing.T) {
	expected := map[string]bool{
		"moria1": true, "tor26": true, "dizum": true,
		"Faravahar": true, "longclaw": true, "bastet": true,
		"dannenberg": true, "maatuska": true, "gabelmoo": true,
	}
	for _, auth := range DirAuthorities {
		if !expected[auth.Nickname] {
			t.Fatalf("unexpected authority nickname: %s", auth.Nickname)
		}
	}
}
