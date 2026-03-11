package directory

import (
	"fmt"
	"log/slog"
	"math/rand"
	"testing"

	"github.com/cvsouth/tor-go/descriptor"
)

func TestBootstrapCircuitUnreachable(t *testing.T) {
	// Tests nil logger (no panic), unreachable address (graceful error),
	// zero Ed25519ID (pinning skipped), and non-zero Ed25519ID (pinning attempted).
	auth := &DirAuthority{
		Nickname: "unreachable",
		Address:  "192.0.2.1", // RFC 5737 TEST-NET, unreachable
		ORPort:   1,
	}
	relayInfo := &descriptor.RelayInfo{}

	// nil logger should not panic
	_, _, err := BootstrapCircuit(auth, relayInfo, nil)
	if err == nil {
		t.Fatal("expected error for unreachable authority, got nil")
	}
	t.Logf("nil logger, zero ed25519: got expected error: %v", err)

	// non-zero Ed25519ID should also fail gracefully (pinning attempted on handshake)
	auth.Ed25519ID[0] = 0x01
	_, _, err = BootstrapCircuit(auth, relayInfo, slog.Default())
	if err == nil {
		t.Fatal("expected error for unreachable authority with non-zero ed25519")
	}
	t.Logf("non-zero ed25519: got expected error: %v", err)
}

func TestBootstrapCircuitIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Shuffle authorities to spread load
	auths := make([]DirAuthority, len(DirAuthorities))
	copy(auths, DirAuthorities)
	rand.Shuffle(len(auths), func(i, j int) { auths[i], auths[j] = auths[j], auths[i] })

	var lastErr error
	for _, auth := range auths {
		auth := auth
		t.Logf("trying authority %s (%s:%d)", auth.Nickname, auth.Address, auth.ORPort)

		// Step 1: Fetch relay info (NodeID + ntor key) via plaintext HTTP
		relayInfo, err := FetchAuthorityDescriptor(&auth)
		if err != nil {
			t.Logf("  FetchAuthorityDescriptor failed: %v", err)
			lastErr = err
			continue
		}

		var zeroKey [32]byte
		if relayInfo.NtorOnionKey == zeroKey {
			t.Logf("  got zero ntor key, skipping")
			lastErr = fmt.Errorf("zero ntor key from %s", auth.Nickname)
			continue
		}
		t.Logf("  got ntor key: %x, nodeID: %x", relayInfo.NtorOnionKey[:8], relayInfo.NodeID[:8])

		// Step 2: Build 1-hop bootstrap circuit
		circ, l, err := BootstrapCircuit(&auth, relayInfo, slog.Default())
		if err != nil {
			t.Logf("  BootstrapCircuit failed: %v", err)
			lastErr = err
			continue
		}

		// Step 3: Verify circuit ID is non-zero
		if circ.ID == 0 {
			_ = circ.Destroy()
			_ = l.Close()
			t.Fatal("circuit ID is 0")
		}
		t.Logf("  circuit ID: 0x%08x", circ.ID)

		// Cleanup
		if err := circ.Destroy(); err != nil {
			t.Logf("  destroy circuit: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Logf("  close link: %v", err)
		}

		t.Logf("  success with authority %s", auth.Nickname)
		return
	}

	t.Fatalf("all authorities unreachable; last error: %v", lastErr)
}
