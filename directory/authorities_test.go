package directory

import (
	"encoding/hex"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
		{"moria1", "128.31.0.39:9231"},
		{"tor26", "217.196.147.77:80"},
		{"bastet", "204.13.164.118:80"},
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

func testAuthFromServer(ts *httptest.Server) *DirAuthority {
	// Parse the test server's host:port into a DirAuthority
	addr := ts.Listener.Addr().String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic("testAuthFromServer: failed to split host:port: " + err.Error())
	}
	port, err2 := strconv.ParseUint(portStr, 10, 16)
	if err2 != nil {
		panic("testAuthFromServer: failed to parse port: " + err2.Error())
	}
	return &DirAuthority{
		Nickname: "test-auth",
		Address:  host,
		DirPort:  uint16(port),
	}
}

func TestFetchAuthorityDescriptorHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	auth := testAuthFromServer(ts)
	_, err := FetchAuthorityDescriptor(auth)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected HTTP 500 in error, got: %v", err)
	}
}

func TestFetchAuthorityDescriptorMissingNtorKey(t *testing.T) {
	// Serve a descriptor that's missing the ntor-onion-key line.
	// Fingerprint must be 20 hex bytes (40 chars) with spaces every 4 chars.
	body := "router test 127.0.0.1 9001 0 0\nfingerprint AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111 2222 3333\n"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	auth := testAuthFromServer(ts)
	_, err := FetchAuthorityDescriptor(auth)
	if err == nil {
		t.Fatal("expected error for missing ntor key")
	}
	if !strings.Contains(err.Error(), "ntor-onion-key") {
		t.Fatalf("expected ntor-onion-key error, got: %v", err)
	}
}

func TestFetchAuthorityDescriptorEmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	auth := testAuthFromServer(ts)
	_, err := FetchAuthorityDescriptor(auth)
	if err == nil {
		t.Fatal("expected error for empty body")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, auth.Nickname) || !strings.Contains(errMsg, "parse") {
		t.Fatalf("expected error to contain both authority nickname %q and 'parse', got: %v", auth.Nickname, err)
	}
}

func TestFetchAuthorityDescriptorConnectionRefused(t *testing.T) {
	auth := &DirAuthority{
		Nickname: "test-refused",
		Address:  "127.0.0.1", // localhost port 1 — instant ECONNREFUSED
		DirPort:  1,
	}
	_, err := FetchAuthorityDescriptor(auth)
	if err == nil {
		t.Fatal("expected error for unreachable authority")
	}
	if !strings.Contains(err.Error(), "test-refused") {
		t.Fatalf("expected authority nickname %q in error, got: %v", "test-refused", err)
	}
}

func TestFetchAuthorityDescriptorRejectRedirect(t *testing.T) {
	// Verify that FetchAuthorityDescriptor does not follow HTTP redirects (anti-SSRF).
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should not reach here"))
	}))
	defer redirectTarget.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusMovedPermanently)
	}))
	defer ts.Close()

	auth := testAuthFromServer(ts)
	_, err := FetchAuthorityDescriptor(auth)
	if err == nil {
		t.Fatal("expected error for redirect response")
	}
	if !strings.Contains(err.Error(), "HTTP 301") {
		t.Fatalf("expected HTTP 301 in error, got: %v", err)
	}
}

func TestDirAuthoritiesKnownNicknames(t *testing.T) {
	expected := map[string]bool{
		"moria1": true, "tor26": true, "dizum": true,
		"gabelmoo": true, "dannenberg": true,
		"maatuska": true, "longclaw": true, "bastet": true,
		"faravahar": true,
	}
	if len(DirAuthorities) != len(expected) {
		t.Fatalf("expected %d authorities, got %d", len(expected), len(DirAuthorities))
	}
	for _, auth := range DirAuthorities {
		if !expected[auth.Nickname] {
			t.Fatalf("unexpected authority nickname: %s", auth.Nickname)
		}
	}
}
