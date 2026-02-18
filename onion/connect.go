package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/directory"
	"github.com/cvsouth/tor-go/stream"
)

// ConnectResult holds the information needed to establish a stream to an
// onion service after the introduction/rendezvous protocol completes.
type ConnectResult struct {
	IntroPoints []IntroPoint
	BlindedKey  [32]byte
	Subcred     [32]byte
	Descriptor  *DescriptorOuter
}

// ResolveOnionService resolves a .onion address to a set of introduction points
// by fetching and decrypting the service descriptor. This is the first step
// before the introduction/rendezvous protocol.
//
// Parameters:
//   - address: the v3 .onion address (with or without .onion suffix)
//   - consensus: the current consensus
//   - httpClient: HTTP client for fetching the descriptor (can be nil if builder is provided)
//   - builder: optional circuit builder for BEGIN_DIR fetch (used when DirPort=0)
func ResolveOnionService(address string, consensus *directory.Consensus, httpClient *http.Client, builder ...CircuitBuilder) (*ConnectResult, error) {
	pubkey, err := DecodeOnion(address)
	if err != nil {
		return nil, fmt.Errorf("decode .onion address: %w", err)
	}

	periodLength := int64(defaultTimePeriodLength)
	periodNum := TimePeriod(consensus.ValidAfter, periodLength)

	blindedKey, err := BlindPublicKey(pubkey, periodNum, periodLength)
	if err != nil {
		return nil, fmt.Errorf("blind public key: %w", err)
	}

	subcred := Subcredential(pubkey, blindedKey)

	srv, err := GetSRVForClient(consensus)
	if err != nil {
		return nil, fmt.Errorf("get SRV: %w", err)
	}

	hsdirs, err := SelectHSDirs(consensus, blindedKey, periodNum, periodLength, srv)
	if err != nil {
		return nil, fmt.Errorf("select HSDirs: %w", err)
	}

	var cb CircuitBuilder
	if len(builder) > 0 {
		cb = builder[0]
	}

	descriptorText, err := fetchDescriptorFromHSDirs(hsdirs, blindedKey, httpClient, cb)
	if err != nil {
		return nil, err
	}

	outer, err := ParseDescriptorOuter(descriptorText)
	if err != nil {
		return nil, fmt.Errorf("parse descriptor: %w", err)
	}

	introPoints, err := DecryptAndParseDescriptor(outer, blindedKey, subcred)
	if err != nil {
		return nil, fmt.Errorf("decrypt descriptor: %w", err)
	}

	if len(introPoints) == 0 {
		return nil, fmt.Errorf("no introduction points in descriptor")
	}

	return &ConnectResult{
		IntroPoints: introPoints,
		BlindedKey:  blindedKey,
		Subcred:     subcred,
		Descriptor:  outer,
	}, nil
}

func fetchDescriptorFromHSDirs(hsdirs []*directory.Relay, blindedKey [32]byte, httpClient *http.Client, cb CircuitBuilder) (string, error) {
	var lastErr error
	for _, hsdir := range hsdirs {
		text, err := fetchFromHSDir(hsdir, blindedKey, httpClient, cb)
		if err != nil {
			lastErr = err
			continue
		}
		if text != "" {
			return text, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable HSDirs (all have DirPort=0 and no circuit builder)")
	}
	return "", fmt.Errorf("failed to fetch descriptor from all HSDirs: %w", lastErr)
}

func fetchFromHSDir(hsdir *directory.Relay, blindedKey [32]byte, httpClient *http.Client, cb CircuitBuilder) (string, error) {
	if hsdir.DirPort > 0 && httpClient != nil {
		addr := fmt.Sprintf("%s:%d", hsdir.Address, hsdir.DirPort)
		return FetchDescriptor(httpClient, addr, blindedKey)
	}
	if cb != nil {
		hsdirInfo := &descriptor.RelayInfo{
			NodeID:       hsdir.Identity,
			NtorOnionKey: hsdir.NtorOnionKey,
			Address:      hsdir.Address,
			ORPort:       hsdir.ORPort,
		}
		built, err := cb.BuildCircuit(hsdirInfo)
		if err != nil {
			return "", fmt.Errorf("build circuit to HSDir: %w", err)
		}
		defer func() { _ = built.LinkCloser.Close() }()
		return FetchDescriptorViaCircuit(built.Circuit, blindedKey)
	}
	return "", nil // No way to fetch from this HSDir
}

// IsOnionAddress returns true if the target address is a .onion address.
func IsOnionAddress(target string) bool {
	// Remove port if present.
	host := target
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		host = target[:idx]
	}
	return strings.HasSuffix(strings.ToLower(host), ".onion")
}

// TimePeriodFromConsensus computes the time period number using the
// consensus valid-after time (not the system clock), per rend-spec-v3.
func TimePeriodFromConsensus(consensus *directory.Consensus) int64 {
	return TimePeriod(consensus.ValidAfter, defaultTimePeriodLength)
}

// CurrentTimePeriod computes the time period from the current time.
// Prefer TimePeriodFromConsensus when a consensus is available.
func CurrentTimePeriod() int64 {
	return TimePeriod(time.Now(), defaultTimePeriodLength)
}

// BuiltCircuit holds a circuit and the metadata about the last hop,
// needed for the onion service protocol.
type BuiltCircuit struct {
	Circuit    *circuit.Circuit
	LinkCloser io.Closer             // Closes the underlying TLS link
	LastHop    *descriptor.RelayInfo // Info about the last relay in the circuit
}

// CircuitBuilder abstracts the ability to build a 3-hop Tor circuit.
type CircuitBuilder interface {
	// BuildCircuit builds a 3-hop circuit. If target is non-nil, it is used
	// as the last hop instead of a randomly selected exit.
	BuildCircuit(target *descriptor.RelayInfo) (*BuiltCircuit, error)
}

// ConnectOnionService performs the full v3 onion service connection protocol:
// resolve descriptor, establish rendezvous, introduce, and complete handshake.
// Returns an io.ReadWriteCloser for the connected stream.
func ConnectOnionService(
	address string,
	port uint16,
	consensus *directory.Consensus,
	httpClient *http.Client,
	builder CircuitBuilder,
	logger *slog.Logger,
) (io.ReadWriteCloser, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// 1. Resolve the onion service descriptor.
	logger.Info("resolving onion service", "address", address)
	result, err := ResolveOnionService(address, consensus, httpClient, builder)
	if err != nil {
		return nil, fmt.Errorf("resolve onion service: %w", err)
	}
	logger.Info("resolved onion service", "intro_points", len(result.IntroPoints))

	// 2. Build a rendezvous circuit (3-hop, random relay as rendezvous point).
	logger.Info("building rendezvous circuit")
	rendBuilt, err := builder.BuildCircuit(nil)
	if err != nil {
		return nil, fmt.Errorf("build rendezvous circuit: %w", err)
	}

	// 3. Generate rendezvous cookie and send ESTABLISH_RENDEZVOUS.
	cookie, err := GenerateRendezvousCookie()
	if err != nil {
		_ = rendBuilt.LinkCloser.Close()
		return nil, fmt.Errorf("generate cookie: %w", err)
	}

	logger.Info("sending ESTABLISH_RENDEZVOUS")
	if err := rendBuilt.Circuit.SendRelay(circuit.RelayEstablishRendezvous, 0, cookie[:]); err != nil {
		_ = rendBuilt.LinkCloser.Close()
		return nil, fmt.Errorf("send ESTABLISH_RENDEZVOUS: %w", err)
	}

	// 4. Wait for RENDEZVOUS_ESTABLISHED.
	_, relayCmd, _, _, err := rendBuilt.Circuit.ReceiveRelay()
	if err != nil {
		_ = rendBuilt.LinkCloser.Close()
		return nil, fmt.Errorf("receive RENDEZVOUS_ESTABLISHED: %w", err)
	}
	if relayCmd != circuit.RelayRendezvousEstablished {
		_ = rendBuilt.LinkCloser.Close()
		return nil, fmt.Errorf("expected RENDEZVOUS_ESTABLISHED (39), got %d", relayCmd)
	}
	logger.Info("rendezvous established")

	// 5. Build rendezvous point link specifiers for INTRODUCE1.
	rendLinkSpecs, err := BuildRendLinkSpecs(
		rendBuilt.LastHop.NodeID,
		rendBuilt.LastHop.Address,
		rendBuilt.LastHop.ORPort,
		[32]byte{}, // Ed25519 ID — not always available from consensus
	)
	if err != nil {
		_ = rendBuilt.LinkCloser.Close()
		return nil, fmt.Errorf("build rend link specs: %w", err)
	}

	// 6. Try each introduction point.
	var lastIntroErr error
	for ipIdx, ip := range result.IntroPoints {
		logger.Info("trying introduction point", "index", ipIdx)

		err := tryIntroPoint(ip, result, cookie, rendBuilt, rendLinkSpecs, builder, logger)
		if err != nil {
			logger.Warn("intro point failed", "index", ipIdx, "error", err)
			lastIntroErr = err
			continue
		}

		// Success — rendezvous circuit now has the onion service virtual hop.
		logger.Info("opening stream to onion service", "port", port)
		target := fmt.Sprintf("%s:%d", address, port)
		s, err := stream.Begin(rendBuilt.Circuit, target)
		if err != nil {
			_ = rendBuilt.LinkCloser.Close()
			return nil, fmt.Errorf("stream begin: %w", err)
		}

		return &onionStream{Stream: s, linkCloser: rendBuilt.LinkCloser}, nil
	}

	_ = rendBuilt.LinkCloser.Close()
	return nil, fmt.Errorf("all introduction points failed: %w", lastIntroErr)
}

func tryIntroPoint(
	ip IntroPoint,
	result *ConnectResult,
	cookie [20]byte,
	rendBuilt *BuiltCircuit,
	rendLinkSpecs []byte,
	builder CircuitBuilder,
	logger *slog.Logger,
) error {
	// Parse the intro point's link specifiers to get address info.
	specs, err := ParseLinkSpecifiers(ip.LinkSpecifiers)
	if err != nil {
		return fmt.Errorf("parse link specifiers: %w", err)
	}

	// Build intro point RelayInfo.
	introInfo := &descriptor.RelayInfo{
		NodeID:       specs.Identity,
		NtorOnionKey: ip.OnionKey,
		Address:      specs.Address,
		ORPort:       specs.ORPort,
	}

	// Build a 3-hop circuit to the introduction point.
	logger.Info("building intro circuit", "target", specs.Address)
	introBuilt, err := builder.BuildCircuit(introInfo)
	if err != nil {
		return fmt.Errorf("build intro circuit: %w", err)
	}
	defer func() { _ = introBuilt.LinkCloser.Close() }()

	// Build the INTRODUCE1 payload.
	// authKey: the intro point's auth key certificate (contains the ed25519 key)
	// encKey: the service's encryption key (from descriptor)
	// subcredential: computed from the service's identity
	// rendCookie: the cookie we sent in ESTABLISH_RENDEZVOUS
	// rendNodeOnionKey: the rend point's ntor key
	// rendLinkSpecs: the rend point's link specifiers
	logger.Info("sending INTRODUCE1")
	introduce1, hsState, err := BuildINTRODUCE1(
		ip.AuthKey[:],
		ip.EncKey,
		result.Subcred,
		cookie,
		rendBuilt.LastHop.NtorOnionKey,
		rendLinkSpecs,
	)
	if err != nil {
		return fmt.Errorf("build INTRODUCE1: %w", err)
	}

	// Send INTRODUCE1 on the intro circuit.
	if err := introBuilt.Circuit.SendRelay(circuit.RelayIntroduce1, 0, introduce1); err != nil {
		return fmt.Errorf("send INTRODUCE1: %w", err)
	}

	// Wait for INTRODUCE_ACK on the intro circuit.
	_, relayCmd, _, ackData, err := introBuilt.Circuit.ReceiveRelay()
	if err != nil {
		return fmt.Errorf("receive INTRODUCE_ACK: %w", err)
	}
	if relayCmd != circuit.RelayIntroduceAck {
		return fmt.Errorf("expected INTRODUCE_ACK (40), got %d", relayCmd)
	}
	// Check status: first 2 bytes = status, 0x0000 = success
	if len(ackData) >= 2 {
		status := uint16(ackData[0])<<8 | uint16(ackData[1])
		if status != 0 {
			return fmt.Errorf("INTRODUCE_ACK status=%d (non-zero)", status)
		}
	}
	logger.Info("INTRODUCE_ACK received (success)")

	// Wait for RENDEZVOUS2 on the rendezvous circuit.
	logger.Info("waiting for RENDEZVOUS2")
	_, relayCmd, _, rend2Data, err := rendBuilt.Circuit.ReceiveRelay()
	if err != nil {
		return fmt.Errorf("receive RENDEZVOUS2: %w", err)
	}
	if relayCmd != circuit.RelayRendezvous2 {
		return fmt.Errorf("expected RENDEZVOUS2 (37), got %d", relayCmd)
	}
	logger.Info("RENDEZVOUS2 received")

	// Complete the hs-ntor handshake.
	keys, err := CompleteRendezvous(hsState, rend2Data)
	if err != nil {
		return fmt.Errorf("complete rendezvous: %w", err)
	}

	// Add the virtual onion-service hop to the rendezvous circuit.
	// This hop uses SHA3-256 digests and AES-256-CTR encryption.
	hop, err := initOnionHop(keys)
	if err != nil {
		return fmt.Errorf("init onion hop: %w", err)
	}
	rendBuilt.Circuit.AddHop(hop)
	logger.Info("onion service virtual hop added")

	return nil
}

// initOnionHop creates a circuit hop with SHA3-256 digests and AES-256-CTR,
// as used for the virtual onion service hop after RENDEZVOUS2.
func initOnionHop(keys *RendezvousKeys) (*circuit.Hop, error) {
	zeroIV := make([]byte, aes.BlockSize)

	fwdBlock, err := aes.NewCipher(keys.Kf[:])
	if err != nil {
		return nil, fmt.Errorf("AES-256-CTR forward: %w", err)
	}
	bwdBlock, err := aes.NewCipher(keys.Kb[:])
	if err != nil {
		return nil, fmt.Errorf("AES-256-CTR backward: %w", err)
	}

	dfHash, dbHash := NewRendezvousDigests(keys.Df, keys.Db)

	return circuit.NewHop(
		cipher.NewCTR(fwdBlock, zeroIV),
		cipher.NewCTR(bwdBlock, zeroIV),
		dfHash,
		dbHash,
	), nil
}

// onionStream wraps a stream.Stream and closes the underlying link on Close.
type onionStream struct {
	*stream.Stream
	linkCloser io.Closer
}

func (s *onionStream) Close() error {
	err := s.Stream.Close()
	_ = s.linkCloser.Close()
	return err
}
