package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
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

// fetchConsensusAndCerts fetches a fresh consensus and key certs from the real
// Tor network, validates signatures, and returns parsed results.
func fetchConsensusAndCerts(t *testing.T) (string, *directory.Consensus, []directory.KeyCert) {
	t.Helper()

	t.Log("Fetching key certificates...")
	keyCerts, err := directory.FetchKeyCerts()
	if err != nil {
		t.Fatalf("FetchKeyCerts: %v", err)
	}
	t.Logf("  Got %d key certs", len(keyCerts))

	t.Log("Fetching consensus...")
	text, err := directory.FetchConsensus()
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	t.Logf("  Got %d bytes", len(text))

	if err := directory.ValidateSignatures(text, keyCerts); err != nil {
		t.Fatalf("ValidateSignatures: %v", err)
	}
	t.Log("  Consensus cryptographically verified")

	consensus, err := directory.ParseConsensus(text)
	if err != nil {
		t.Fatalf("ParseConsensus: %v", err)
	}

	if err := directory.ValidateFreshness(consensus); err != nil {
		t.Fatalf("ValidateFreshness: %v", err)
	}

	return text, consensus, keyCerts
}

// fetchMicrodescriptors fetches microdescriptors for useful relays and updates
// the consensus relay list in place.
func fetchMicrodescriptors(t *testing.T, consensus *directory.Consensus) {
	t.Helper()

	var useful []directory.Relay
	for _, r := range consensus.Relays {
		if r.Flags.Running && r.Flags.Valid && (r.Flags.Guard || r.Flags.Exit || r.Flags.Fast) {
			useful = append(useful, r)
		}
	}
	t.Logf("  %d relays with useful flags", len(useful))

	for _, addr := range directory.DirAuthorities {
		if err := directory.UpdateRelaysWithMicrodescriptors(addr, useful); err == nil {
			break
		}
	}

	ntorCount := 0
	for _, r := range useful {
		if r.HasNtorKey {
			ntorCount++
		}
	}
	t.Logf("  %d relays with ntor keys", ntorCount)

	if ntorCount < 100 {
		t.Fatalf("too few relays with ntor keys: %d", ntorCount)
	}

	consensus.Relays = useful
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

		guardInfo := relayInfoFromConsensus(&path.Guard)
		_ = l.SetDeadline(time.Now().Add(30 * time.Second))
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

		_ = l.SetDeadline(time.Time{})
		t.Logf("  Circuit built (ID: 0x%08x)", circ.ID)
		return circ, l
	}

	t.Fatalf("failed to build circuit after %d attempts", maxAttempts)
	return nil, nil
}

// TestE2EConsensusAndSignatures tests fetching and cryptographically verifying
// a real consensus from the Tor network. This is the test that would have
// caught the PKCS#1 v1.5 DigestInfo bug.
func TestE2EConsensusAndSignatures(t *testing.T) {
	skipIfShort(t)

	keyCerts, err := directory.FetchKeyCerts()
	if err != nil {
		t.Fatalf("FetchKeyCerts: %v", err)
	}
	if len(keyCerts) < 5 {
		t.Fatalf("expected ≥5 key certs, got %d", len(keyCerts))
	}
	t.Logf("Fetched %d key certs", len(keyCerts))

	text, err := directory.FetchConsensus()
	if err != nil {
		t.Fatalf("FetchConsensus: %v", err)
	}
	if len(text) < 1000 {
		t.Fatalf("consensus too small: %d bytes", len(text))
	}

	// Cryptographic verification — the critical test
	if err := directory.ValidateSignatures(text, keyCerts); err != nil {
		t.Fatalf("ValidateSignatures (crypto): %v", err)
	}

	// Structural verification should also pass
	if err := directory.ValidateSignaturesStructural(text); err != nil {
		t.Fatalf("ValidateSignaturesStructural: %v", err)
	}

	consensus, err := directory.ParseConsensus(text)
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

	fetchMicrodescriptorsFromAuthorities(useful)

	ntorCount := countNtorKeysInRelays(useful)
	t.Logf("%d/%d relays got ntor keys", ntorCount, len(useful))

	if ntorCount < len(useful)/2 {
		t.Fatalf("too few relays with ntor keys: %d/%d", ntorCount, len(useful))
	}

	verifyCacheRoundTrip(t, useful, ntorCount)
}

func filterUsefulRelays(relays []directory.Relay) []directory.Relay {
	var useful []directory.Relay
	for _, r := range relays {
		if r.Flags.Running && r.Flags.Valid && (r.Flags.Guard || r.Flags.Exit || r.Flags.Fast) {
			useful = append(useful, r)
		}
	}
	return useful
}

func fetchMicrodescriptorsFromAuthorities(relays []directory.Relay) {
	for _, addr := range directory.DirAuthorities {
		if directory.UpdateRelaysWithMicrodescriptors(addr, relays) == nil {
			break
		}
	}
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
// network and making an HTTP request through it.
func TestE2ECircuitBuild(t *testing.T) {
	skipIfShort(t)
	logger := testLogger()

	_, consensus, _ := fetchConsensusAndCerts(t)
	fetchMicrodescriptors(t, consensus)

	circ, l := buildCircuit(t, consensus, logger, 3)
	t.Cleanup(func() {
		_ = circ.Destroy()
		l.Close()
	})

	// Open a stream and make an HTTP request through the circuit
	t.Log("Opening stream to example.com:80...")
	s, err := stream.Begin(circ, "example.com:80")
	if err != nil {
		t.Fatalf("stream.Begin: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err = fmt.Fprintf(s, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	reader := bufio.NewReader(s)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.0 200") && !strings.HasPrefix(statusLine, "HTTP/1.1 200") {
		t.Fatalf("unexpected status: %q", strings.TrimSpace(statusLine))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "Example Domain") {
		t.Fatalf("response body doesn't contain expected content (got %d bytes)", len(body))
	}

	t.Logf("HTTP request through Tor circuit succeeded (%d bytes)", len(body))
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

		_ = l.SetDeadline(time.Now().Add(30 * time.Second))
		circ, err := circuit.Create(l, relayInfoFromConsensus(&path.Guard), logger)
		if err != nil {
			l.Close()
			t.Logf("  Create failed: %v", err)
			continue
		}

		if err := circ.Extend(relayInfoFromConsensus(&path.Middle), logger); err != nil {
			l.Close()
			t.Logf("  Extend to middle failed: %v", err)
			continue
		}

		if err := circ.Extend(relayInfoFromConsensus(&path.Exit), logger); err != nil {
			l.Close()
			t.Logf("  Extend to exit failed: %v", err)
			continue
		}

		_ = l.SetDeadline(time.Time{})
		t.Logf("  Success (ID: 0x%08x)", circ.ID)
		_ = circ.Destroy()
		l.Close()
		successes++
	}

	if successes < 2 {
		t.Fatalf("only %d/%d circuit builds succeeded, expected ≥2", successes, attempts)
	}
	t.Logf("%d/%d circuit builds succeeded", successes, attempts)
}
