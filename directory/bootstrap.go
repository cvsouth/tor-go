package directory

import (
	"fmt"
	"log/slog"

	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/link"
)

// BootstrapCircuit builds a 1-hop circuit to a directory authority for
// bootstrapping (fetching consensus, key certificates, microdescriptors).
// The caller must close both the circuit and the link when done.
//
// relayInfo contains the authority's relay identity (NodeID) and ntor-onion-key,
// typically obtained via FetchAuthorityDescriptor over plaintext HTTP. Note:
// the relay's NodeID (from its server descriptor) differs from the authority's
// V3Ident (voting key) — the ntor handshake requires the relay NodeID.
//
// The circuit's read loop is started before returning because bootstrap
// circuits are used immediately for FetchViaBeginDir, which requires the
// read loop to dispatch relay cells to streams.
func BootstrapCircuit(auth *DirAuthority, relayInfo *descriptor.RelayInfo, logger *slog.Logger) (*circuit.Circuit, *link.Link, error) {
	if logger == nil {
		logger = slog.Default()
	}

	addr := fmt.Sprintf("%s:%d", auth.Address, auth.ORPort)

	// Ed25519ID is zero for all hardcoded authorities (populated later from
	// live consensus/descriptor). Pass nil to skip identity pinning for zero IDs.
	// This intentionally matches C Tor's bootstrap behavior: Ed25519 identity
	// pinning for authorities happens post-bootstrap, once the consensus has
	// been fetched and authority descriptors contain Ed25519 keys.
	var pin []byte
	var zeroEd [32]byte
	if auth.Ed25519ID != zeroEd {
		pin = auth.Ed25519ID[:]
	}

	l, err := link.HandshakeWithPinning(addr, pin, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake with %s (%s): %w", auth.Nickname, addr, err)
	}

	l.StartReadLoop()

	circ, err := circuit.Create(l, relayInfo, logger)
	if err != nil {
		_ = l.Close()
		return nil, nil, fmt.Errorf("create circuit to %s: %w", auth.Nickname, err)
	}

	circ.StartReadLoop()

	return circ, l, nil
}
