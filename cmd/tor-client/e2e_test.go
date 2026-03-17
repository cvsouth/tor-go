package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/directory"
	"github.com/cvsouth/tor-go/link"
	"github.com/cvsouth/tor-go/pathselect"
	"github.com/cvsouth/tor-go/stream"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func skipIfShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
}

// testBootstrapFromAuthority fetches consensus, key certs, and microdescriptors
// from a single authority over one bootstrap circuit. Returns nil on failure.
func testBootstrapFromAuthority(t *testing.T, auth *directory.DirAuthority) (*bootstrapData, error) {
	t.Helper()
	logger := testLogger()

	relayInfo, err := directory.FetchAuthorityDescriptor(auth)
	if err != nil {
		return nil, fmt.Errorf("FetchAuthorityDescriptor(%s): %w", auth.Nickname, err)
	}
	circ, l, err := directory.BootstrapCircuit(auth, relayInfo, logger)
	if err != nil {
		return nil, fmt.Errorf("BootstrapCircuit(%s): %w", auth.Nickname, err)
	}
	defer func() { _ = circ.Destroy(); _ = l.Close() }()

	keyCerts, err := directory.FetchKeyCerts(circ)
	if err != nil {
		return nil, fmt.Errorf("FetchKeyCerts: %w", err)
	}
	t.Logf("  Got %d key certs", len(keyCerts))

	text, err := directory.FetchConsensus(circ)
	if err != nil {
		return nil, fmt.Errorf("FetchConsensus: %w", err)
	}
	t.Logf("  Got %d bytes consensus", len(text))

	return &bootstrapData{consensusText: text, keyCerts: keyCerts}, nil
}

// fetchConsensusAndCerts fetches a fresh consensus and key certs from the real
// Tor network using a single bootstrap circuit per authority attempt,
// validates signatures, and returns parsed results.
func fetchConsensusAndCerts(t *testing.T) (string, *directory.Consensus, []directory.KeyCert) {
	t.Helper()

	var data *bootstrapData
	for i := range directory.DirAuthorities {
		auth := &directory.DirAuthorities[i]
		d, err := testBootstrapFromAuthority(t, auth)
		if err != nil {
			t.Logf("  %v", err)
			continue
		}
		data = d
		break
	}
	if data == nil {
		t.Fatal("failed to bootstrap from any authority")
		return "", nil, nil // unreachable; helps staticcheck SA5011
	}

	if err := directory.ValidateSignatures(data.consensusText, data.keyCerts); err != nil {
		t.Fatalf("ValidateSignatures: %v", err)
	}
	t.Log("  Consensus cryptographically verified")

	consensus, err := directory.ParseConsensus(data.consensusText)
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}

	if err := directory.ValidateFreshness(consensus); err != nil {
		t.Fatalf("ValidateFreshness: %v", err)
	}

	return data.consensusText, consensus, data.keyCerts
}

// fetchMicrodescriptors fetches microdescriptors for useful relays and updates
// the consensus relay list in place, using a single bootstrap circuit.
func fetchMicrodescriptors(t *testing.T, consensus *directory.Consensus) {
	t.Helper()

	useful := filterUsefulRelaysForTest(consensus.Relays)
	t.Logf("  %d relays with useful flags", len(useful))

	fetchMicrodescViaAuthorities(t, useful)

	ntorCount := countNtorKeysInRelays(useful)
	t.Logf("  %d relays with ntor keys", ntorCount)

	if ntorCount < 100 {
		t.Fatalf("too few relays with ntor keys: %d", ntorCount)
	}

	consensus.Relays = useful
}

// filterUsefulRelaysForTest returns relays with Running+Valid and at least one
// useful flag (Guard, Exit, Fast, HSDir), matching production filterUsefulRelays.
func filterUsefulRelaysForTest(relays []directory.Relay) []directory.Relay {
	var useful []directory.Relay
	for _, r := range relays {
		if r.Flags.Running && r.Flags.Valid && (r.Flags.Guard || r.Flags.Exit || r.Flags.Fast || r.Flags.HSDir) {
			useful = append(useful, r)
		}
	}
	return useful
}

// fetchMicrodescViaAuthorities tries each authority in shuffled order, building a
// bootstrap circuit and fetching microdescriptors. Fatals if all fail.
func fetchMicrodescViaAuthorities(t *testing.T, relays []directory.Relay) {
	t.Helper()
	logger := testLogger()
	auths := make([]directory.DirAuthority, len(directory.DirAuthorities))
	copy(auths, directory.DirAuthorities)
	rand.Shuffle(len(auths), func(i, j int) { auths[i], auths[j] = auths[j], auths[i] })
	for i := range auths {
		auth := &auths[i]
		if err := fetchMicrodescFromOneAuthority(auth, relays, logger); err != nil {
			t.Logf("  microdesc fetch from %s: %v", auth.Nickname, err)
			continue
		}
		return
	}
	t.Fatal("failed to fetch microdescriptors from any authority")
}

// fetchMicrodescFromOneAuthority builds a bootstrap circuit to auth and fetches
// microdescriptors for the given relays.
func fetchMicrodescFromOneAuthority(auth *directory.DirAuthority, relays []directory.Relay, logger *slog.Logger) error {
	relayInfo, err := directory.FetchAuthorityDescriptor(auth)
	if err != nil {
		return fmt.Errorf("FetchAuthorityDescriptor: %w", err)
	}
	circ, l, err := directory.BootstrapCircuit(auth, relayInfo, logger)
	if err != nil {
		return fmt.Errorf("BootstrapCircuit: %w", err)
	}
	defer func() { _ = circ.Destroy(); _ = l.Close() }()
	return directory.UpdateRelaysWithMicrodescriptors(circ, relays)
}

// buildCircuit builds a 3-hop circuit and returns it along with its link.
// Retries up to maxAttempts times.
func buildCircuit(t *testing.T, consensus *directory.Consensus, logger *slog.Logger, maxAttempts int) (*circuit.Circuit, *link.Link) {
	t.Helper()

	for attempt := 0; attempt < maxAttempts; attempt++ {
		path, err := pathselect.SelectPath(consensus)
		if err != nil {
			t.Logf("  Attempt %d: path selection failed: %v", attempt, err)
			continue
		}
		t.Logf("  Attempt %d: %s → %s → %s", attempt, path.Guard.Nickname, path.Middle.Nickname, path.Exit.Nickname)

		l, err := link.Handshake(fmt.Sprintf("%s:%d", path.Guard.Address, path.Guard.ORPort), logger)
		if err != nil {
			t.Logf("  Attempt %d: handshake failed: %v", attempt, err)
			continue
		}

		l.StartReadLoop()

		guardInfo := relayInfoFromConsensus(&path.Guard)
		circ, err := circuit.Create(l, guardInfo, logger)
		if err != nil {
			_ = l.Close()
			t.Logf("  Attempt %d: create failed: %v", attempt, err)
			continue
		}

		if err := circ.Extend(relayInfoFromConsensus(&path.Middle), logger); err != nil {
			_ = l.Close()
			t.Logf("  Attempt %d: extend to middle failed: %v", attempt, err)
			continue
		}

		if err := circ.Extend(relayInfoFromConsensus(&path.Exit), logger); err != nil {
			_ = l.Close()
			t.Logf("  Attempt %d: extend to exit failed: %v", attempt, err)
			continue
		}

		circ.StartReadLoop()
		t.Logf("  Circuit built (ID: 0x%08x)", circ.ID)
		return circ, l
	}

	t.Fatalf("failed to build circuit after %d attempts", maxAttempts)
	return nil, nil
}

// TestE2EConsensusAndSignatures tests fetching and cryptographically verifying
// a real consensus from the Tor network using a single bootstrap circuit.
// This is the test that would have caught the PKCS#1 v1.5 DigestInfo bug.
func TestE2EConsensusAndSignatures(t *testing.T) {
	skipIfShort(t)

	var data *bootstrapData
	for i := range directory.DirAuthorities {
		auth := &directory.DirAuthorities[i]
		d, err := testBootstrapFromAuthority(t, auth)
		if err != nil {
			t.Logf("  %v", err)
			continue
		}
		data = d
		break
	}
	if data == nil {
		t.Fatal("failed to bootstrap from any authority")
		return // unreachable; helps staticcheck SA5011
	}

	if len(data.keyCerts) < 5 {
		t.Fatalf("expected ≥5 key certs, got %d", len(data.keyCerts))
	}
	t.Logf("Fetched %d key certs", len(data.keyCerts))

	if len(data.consensusText) < 1000 {
		t.Fatalf("consensus too small: %d bytes", len(data.consensusText))
	}

	// Cryptographic verification - the critical test
	if err := directory.ValidateSignatures(data.consensusText, data.keyCerts); err != nil {
		t.Fatalf("ValidateSignatures (crypto): %v", err)
	}

	consensus, err := directory.ParseConsensus(data.consensusText)
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}

	if len(consensus.Relays) < 1000 {
		t.Fatalf("expected >1000 relays, got %d", len(consensus.Relays))
	}
	if consensus.ValidAfter.IsZero() || consensus.ValidUntil.IsZero() || consensus.FreshUntil.IsZero() {
		t.Fatal("consensus missing timestamps")
	}
	if err := directory.ValidateFreshness(consensus); err != nil {
		t.Fatalf("ValidateFreshness: %v", err)
	}

	t.Logf("Consensus: %d relays, valid %s to %s",
		len(consensus.Relays),
		consensus.ValidAfter.Format(time.RFC3339),
		consensus.ValidUntil.Format(time.RFC3339))
}

// TestE2EMicrodescriptors tests fetching microdescriptors from the real network
// and verifying that ntor keys are populated.
func TestE2EMicrodescriptors(t *testing.T) {
	skipIfShort(t)

	_, consensus, _ := fetchConsensusAndCerts(t)

	useful := filterUsefulRelays(consensus.Relays)
	if len(useful) < 100 {
		t.Fatalf("too few useful relays: %d", len(useful))
	}
	t.Logf("%d useful relays", len(useful))

	fetchMicrodescriptorsFromAuthorities(t, useful)

	ntorCount := countNtorKeysInRelays(useful)
	t.Logf("%d/%d relays got ntor keys", ntorCount, len(useful))

	if ntorCount < len(useful)/2 {
		t.Fatalf("too few relays with ntor keys: %d/%d", ntorCount, len(useful))
	}

	verifyCacheRoundTrip(t, useful, ntorCount)
}

func fetchMicrodescriptorsFromAuthorities(t *testing.T, relays []directory.Relay) {
	t.Helper()
	logger := testLogger()
	for i := range directory.DirAuthorities {
		auth := &directory.DirAuthorities[i]
		relayInfo, err := directory.FetchAuthorityDescriptor(auth)
		if err != nil {
			t.Logf("  FetchAuthorityDescriptor(%s) failed: %v", auth.Nickname, err)
			continue
		}
		circ, l, err := directory.BootstrapCircuit(auth, relayInfo, logger)
		if err != nil {
			t.Logf("  BootstrapCircuit(%s) failed: %v", auth.Nickname, err)
			continue
		}
		err = directory.UpdateRelaysWithMicrodescriptors(circ, relays)
		_ = circ.Destroy()
		_ = l.Close()
		if err != nil {
			t.Logf("  UpdateRelaysWithMicrodescriptors via %s failed: %v", auth.Nickname, err)
			continue
		}
		return
	}
	t.Fatal("failed to fetch microdescriptors from any authority")
}

func countNtorKeysInRelays(relays []directory.Relay) int {
	count := 0
	for _, r := range relays {
		if r.HasNtorKey {
			count++
		}
	}
	return count
}

func verifyCacheRoundTrip(t *testing.T, useful []directory.Relay, ntorCount int) {
	t.Helper()
	cache := &directory.Cache{Dir: t.TempDir()}
	if err := cache.SaveMicrodescriptors(useful); err != nil {
		t.Fatalf("SaveMicrodescriptors: %v", err)
	}

	fresh := make([]directory.Relay, len(useful))
	for i, r := range useful {
		fresh[i] = directory.Relay{MicrodescDigest: r.MicrodescDigest}
	}

	loaded := cache.LoadMicrodescriptors(fresh)
	if loaded < ntorCount/2 {
		t.Fatalf("cache round-trip: loaded %d, expected ≥%d", loaded, ntorCount/2)
	}
	t.Logf("Cache round-trip: %d/%d relays restored", loaded, ntorCount)
}

// TestE2ECircuitBuild tests building a real 3-hop circuit through the Tor
// network and making an HTTP request through it. It retries with fresh circuits
// because exit relays may reject connections due to their exit policy.
func TestE2ECircuitBuild(t *testing.T) {
	skipIfShort(t)
	logger := testLogger()

	_, consensus, _ := fetchConsensusAndCerts(t)
	fetchMicrodescriptors(t, consensus)

	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		circ, l := buildCircuit(t, consensus, logger, 3)
		var s *stream.Stream
		cleanup := func() {
			if s != nil {
				_ = s.Close()
			}
			_ = circ.Destroy()
			_ = l.Close()
		}

		t.Logf("Attempt %d: opening stream to check.torproject.org:80...", attempt+1)
		var err error
		s, err = stream.Begin(circ, "check.torproject.org:80")
		if err != nil {
			t.Logf("Attempt %d: stream.Begin: %v", attempt+1, err)
			cleanup()
			lastErr = err
			continue
		}

		_, err = fmt.Fprintf(s, "GET / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n")
		if err != nil {
			t.Logf("Attempt %d: write: %v", attempt+1, err)
			cleanup()
			lastErr = err
			continue
		}

		reader := bufio.NewReader(s)
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			t.Logf("Attempt %d: read status: %v", attempt+1, err)
			cleanup()
			lastErr = err
			continue
		}

		// Any valid HTTP response proves the circuit carried traffic end-to-end.
		// check.torproject.org returns 301 (redirect to HTTPS) over plain HTTP,
		// which still demonstrates a working circuit.
		if !strings.HasPrefix(statusLine, "HTTP/") {
			t.Logf("Attempt %d: non-HTTP response: %q", attempt+1, strings.TrimSpace(statusLine))
			cleanup()
			lastErr = fmt.Errorf("non-HTTP response: %s", strings.TrimSpace(statusLine))
			continue
		}

		body, err := io.ReadAll(reader)
		if err != nil {
			t.Logf("Attempt %d: read body: %v", attempt+1, err)
			cleanup()
			lastErr = err
			continue
		}
		cleanup()

		t.Logf("HTTP request through Tor circuit succeeded (status: %s, %d bytes)",
			strings.TrimSpace(statusLine), len(body))
		return
	}

	t.Fatalf("all %d attempts failed; last error: %v", maxAttempts, lastErr)
}

// TestE2ECircuitRetry tests that circuit building is resilient to relay
// failures by attempting multiple builds.
func TestE2ECircuitRetry(t *testing.T) {
	skipIfShort(t)
	logger := testLogger()

	_, consensus, _ := fetchConsensusAndCerts(t)
	fetchMicrodescriptors(t, consensus)

	successes := 0
	attempts := 3
	for i := 0; i < attempts; i++ {
		t.Logf("Circuit build %d/%d", i+1, attempts)
		path, err := pathselect.SelectPath(consensus)
		if err != nil {
			t.Logf("  Path selection failed: %v", err)
			continue
		}

		l, err := link.Handshake(fmt.Sprintf("%s:%d", path.Guard.Address, path.Guard.ORPort), logger)
		if err != nil {
			t.Logf("  Handshake failed: %v", err)
			continue
		}

		l.StartReadLoop()

		circ, err := circuit.Create(l, relayInfoFromConsensus(&path.Guard), logger)
		if err != nil {
			_ = l.Close()
			t.Logf("  Create failed: %v", err)
			continue
		}

		if err := circ.Extend(relayInfoFromConsensus(&path.Middle), logger); err != nil {
			_ = l.Close()
			t.Logf("  Extend to middle failed: %v", err)
			continue
		}

		if err := circ.Extend(relayInfoFromConsensus(&path.Exit), logger); err != nil {
			_ = l.Close()
			t.Logf("  Extend to exit failed: %v", err)
			continue
		}
		t.Logf("  Success (ID: 0x%08x)", circ.ID)
		_ = circ.Destroy()
		_ = l.Close()
		successes++
	}

	// Require at least 1 success. The live Tor network has relay churn,
	// firewalled ORPorts, and rate limiting, so not every attempt will succeed.
	if successes < 1 {
		t.Fatalf("all %d circuit builds failed", attempts)
	}
	t.Logf("%d/%d circuit builds succeeded", successes, attempts)
}
