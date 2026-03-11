package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cvsouth/tor-go/circpool"
	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/directory"
	"github.com/cvsouth/tor-go/link"
	"github.com/cvsouth/tor-go/onion"
	"github.com/cvsouth/tor-go/pathselect"
	"github.com/cvsouth/tor-go/socks"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	logger, logFile := setupLogging()
	defer func() { _ = logFile.Close() }()

	fmt.Printf("=== Daphne Tor Client %s ===\n", Version)
	fmt.Println()

	cache := &directory.Cache{Dir: directory.DefaultCacheDir()}
	consensus := bootstrap(cache, logger)

	fmt.Println("\nStarting circuit pool...")
	cb := &circuitBuilder{consensus: consensus, logger: logger}
	pool := circpool.NewPool(&poolBuilder{cb: cb}, circpool.PoolConfig{Size: 3})
	assigner := circpool.NewAssigner(pool)

	runSOCKSProxy(consensus, pool, assigner, cb, logger)
}

func setupLogging() (*slog.Logger, *os.File) {
	logFile, err := os.OpenFile("tor-debug.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log file: %v\n", err)
		os.Exit(1)
	}
	fileHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})
	stdoutHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(&multiHandler{handlers: []slog.Handler{fileHandler, stdoutHandler}})
	return logger, logFile
}

// bootstrapData holds all data fetched during bootstrap.
type bootstrapData struct {
	consensusText string
	keyCerts      []directory.KeyCert
}

// bootstrap loads consensus and key certs from cache, or fetches them from
// a directory authority over a single bootstrap circuit. It validates, parses,
// and populates microdescriptors before returning the final consensus.
func bootstrap(cache *directory.Cache, logger *slog.Logger) *directory.Consensus {
	data := loadFromCache(cache)
	if data == nil {
		data = fetchFromAuthorities(logger)
		cacheBootstrapData(data, cache, logger)
	}
	consensus := validateAndParseConsensus(data.consensusText, data.keyCerts, cache, logger)
	populateMicrodescriptors(consensus, cache, logger)
	return consensus
}

// loadFromCache attempts to load consensus and key certs from the local cache.
// Returns nil if either is missing.
func loadFromCache(cache *directory.Cache) *bootstrapData {
	consensusText, hasCons := cache.LoadConsensus()
	keyCerts, err := cache.LoadKeyCerts()
	if !hasCons || err != nil || len(keyCerts) == 0 {
		return nil
	}
	fmt.Println("Loaded consensus and key certs from cache")
	return &bootstrapData{consensusText: consensusText, keyCerts: keyCerts}
}

// fetchFromAuthorities tries each directory authority in shuffled order,
// fetching consensus and key certs over a single bootstrap circuit per attempt.
// Shuffling avoids always hitting the same authority first, distributing load
// and reducing predictability for network observers.
func fetchFromAuthorities(logger *slog.Logger) *bootstrapData {
	fmt.Println("Fetching consensus from directory authorities...")
	auths := shuffleAuthorities()
	for i := range auths {
		data, err := bootstrapFromAuthority(&auths[i], logger)
		if err != nil {
			logger.Warn("bootstrap from authority failed", "authority", auths[i].Nickname, "error", err)
			continue
		}
		return data
	}
	fmt.Println("  Failed to fetch consensus from any authority")
	os.Exit(1)
	return nil
}

// shuffleAuthorities returns a shuffled copy of DirAuthorities to distribute
// load and reduce predictability for network observers.
func shuffleAuthorities() []directory.DirAuthority {
	auths := make([]directory.DirAuthority, len(directory.DirAuthorities))
	copy(auths, directory.DirAuthorities)
	rand.Shuffle(len(auths), func(i, j int) { auths[i], auths[j] = auths[j], auths[i] })
	return auths
}

// bootstrapFromAuthority fetches consensus and key certs from a single
// directory authority over one bootstrap circuit. The sequence is:
// (1) fetch ntor key via FetchAuthorityDescriptor (plaintext HTTP),
// (2) build 1-hop bootstrap circuit via BootstrapCircuit with identity pinning,
// (3) fetch consensus via FetchConsensus(circ),
// (4) fetch key certs via FetchKeyCerts(circ),
// (5) close bootstrap circuit and link.
func bootstrapFromAuthority(auth *directory.DirAuthority, logger *slog.Logger) (*bootstrapData, error) {
	relayInfo, err := directory.FetchAuthorityDescriptor(auth)
	if err != nil {
		return nil, fmt.Errorf("fetch descriptor: %w", err)
	}
	circ, l, err := directory.BootstrapCircuit(auth, relayInfo, logger)
	if err != nil {
		return nil, fmt.Errorf("bootstrap circuit: %w", err)
	}
	defer func() { _ = circ.Destroy(); _ = l.Close() }()

	text, err := directory.FetchConsensus(circ)
	if err != nil {
		return nil, fmt.Errorf("fetch consensus: %w", err)
	}
	fmt.Printf("  Fetched consensus (%d bytes)\n", len(text))

	keyCerts, err := directory.FetchKeyCerts(circ)
	if err != nil {
		return nil, fmt.Errorf("fetch key certs: %w", err)
	}
	fmt.Printf("  Fetched %d authority key certificates\n", len(keyCerts))

	return &bootstrapData{consensusText: text, keyCerts: keyCerts}, nil
}

// cacheBootstrapData saves fetched key certs to the local cache.
// Note: consensus caching happens separately in validateAndParseConsensus,
// after signature validation, so that only verified consensuses are cached.
func cacheBootstrapData(data *bootstrapData, cache *directory.Cache, logger *slog.Logger) {
	if err := cache.SaveKeyCerts(data.keyCerts); err != nil {
		logger.Warn("failed to cache key certs", "error", err)
	}
}

func validateAndParseConsensus(text string, keyCerts []directory.KeyCert, cache *directory.Cache, logger *slog.Logger) *directory.Consensus {
	if err := directory.ValidateSignatures(text, keyCerts); err != nil {
		fmt.Printf("  Signature validation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  Consensus cryptographically verified (≥5 RSA signatures)")

	consensus, err := directory.ParseConsensus(text)
	if err != nil {
		fmt.Printf("  Parse failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Parsed: %d relays, valid until %s\n", len(consensus.Relays), consensus.ValidUntil.Format(time.RFC3339))

	if err := directory.ValidateFreshness(consensus); err != nil {
		fmt.Printf("  Consensus validation failed: %v\n", err)
		os.Exit(1)
	}
	if err := cache.SaveConsensus(text, consensus.FreshUntil, consensus.ValidUntil); err != nil {
		logger.Warn("failed to cache consensus", "error", err)
	}
	return consensus
}

func populateMicrodescriptors(consensus *directory.Consensus, cache *directory.Cache, logger *slog.Logger) {
	fmt.Println("Fetching microdescriptors...")
	usefulRelays := filterUsefulRelays(consensus.Relays)
	fmt.Printf("  %d relays with useful flags\n", len(usefulRelays))

	cachedCount := cache.LoadMicrodescriptors(usefulRelays)
	if cachedCount > 0 {
		fmt.Printf("  Loaded %d relays from microdescriptor cache\n", cachedCount)
	}

	fetchMissingMicrodescriptors(usefulRelays, logger)

	ntorCount := countNtorKeys(usefulRelays)
	fmt.Printf("  %d relays with ntor keys\n", ntorCount)

	if err := cache.SaveMicrodescriptors(usefulRelays); err != nil {
		logger.Warn("failed to cache microdescriptors", "error", err)
	}
	consensus.Relays = usefulRelays
}

// filterUsefulRelays returns relays with Running+Valid and at least one useful flag.
func filterUsefulRelays(relays []directory.Relay) []directory.Relay {
	var useful []directory.Relay
	for _, r := range relays {
		if r.Flags.Running && r.Flags.Valid && (r.Flags.Guard || r.Flags.Exit || r.Flags.Fast || r.Flags.HSDir) {
			useful = append(useful, r)
		}
	}
	return useful
}

func fetchMissingMicrodescriptors(relays []directory.Relay, logger *slog.Logger) {
	needFetch := countMissingNtorKeys(relays)
	if needFetch == 0 {
		return
	}
	fmt.Printf("  Fetching microdescriptors for %d relays...\n", needFetch)
	auths := shuffleAuthorities()
	for i := range auths {
		if err := fetchMicrodescFromAuthority(&auths[i], relays, logger); err != nil {
			logger.Warn("microdesc fetch from authority failed", "authority", auths[i].Nickname, "error", err)
			continue
		}
		return
	}
	fmt.Println("  Failed to fetch microdescriptors from any authority")
}

// countMissingNtorKeys returns the number of relays without an ntor key.
func countMissingNtorKeys(relays []directory.Relay) int {
	count := 0
	for _, r := range relays {
		if !r.HasNtorKey {
			count++
		}
	}
	return count
}

// fetchMicrodescFromAuthority builds a bootstrap circuit to the given authority
// and fetches microdescriptors via UpdateRelaysWithMicrodescriptors.
func fetchMicrodescFromAuthority(auth *directory.DirAuthority, relays []directory.Relay, logger *slog.Logger) error {
	relayInfo, err := directory.FetchAuthorityDescriptor(auth)
	if err != nil {
		return fmt.Errorf("fetch descriptor: %w", err)
	}
	circ, l, err := directory.BootstrapCircuit(auth, relayInfo, logger)
	if err != nil {
		return fmt.Errorf("bootstrap circuit: %w", err)
	}
	defer func() { _ = circ.Destroy(); _ = l.Close() }()
	return directory.UpdateRelaysWithMicrodescriptors(circ, relays)
}

func countNtorKeys(relays []directory.Relay) int {
	count := 0
	for _, r := range relays {
		if r.HasNtorKey {
			count++
		}
	}
	return count
}

func runSOCKSProxy(consensus *directory.Consensus, pool *circpool.Pool, assigner *circpool.Assigner, cb *circuitBuilder, logger *slog.Logger) {
	socksAddr := "127.0.0.1:9050"
	fmt.Printf("\nStarting SOCKS5 proxy on %s...\n", socksAddr)

	srv := &socks.Server{
		Addr:   socksAddr,
		Logger: logger,
		GetCirc: func(target string) (*circuit.Circuit, error) {
			return assigner.AssignCircuit(target)
		},
		OnionHandler: func(onionAddr string, port uint16) (io.ReadWriteCloser, error) {
			return onion.ConnectOnionService(onionAddr, port, consensus, cb, logger)
		},
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		_ = srv.Close()
		pool.Close()
	}()

	fmt.Println("Ready. Use: curl --socks5-hostname 127.0.0.1:9050 http://example.com")
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("SOCKS5 server error: %v\n", err)
	}
}

func relayInfoFromConsensus(relay *directory.Relay) *descriptor.RelayInfo {
	return &descriptor.RelayInfo{
		NodeID:       relay.Identity,
		NtorOnionKey: relay.NtorOnionKey,
		Address:      relay.Address,
		ORPort:       relay.ORPort,
	}
}

// poolBuilder wraps circuitBuilder to implement circpool.CircuitBuilder.
// It builds circuits with a random exit (target=nil).
type poolBuilder struct {
	cb *circuitBuilder
}

func (pb *poolBuilder) Build() (*circuit.Circuit, io.Closer, error) {
	built, err := pb.cb.BuildCircuit(nil)
	if err != nil {
		return nil, nil, err
	}
	return built.Circuit, built.LinkCloser, nil
}

// circuitBuilder implements onion.CircuitBuilder.
type circuitBuilder struct {
	consensus *directory.Consensus
	logger    *slog.Logger
}

func (cb *circuitBuilder) BuildCircuit(target *descriptor.RelayInfo) (*onion.BuiltCircuit, error) {
	for attempt := 0; attempt < 3; attempt++ {
		built, err := cb.tryBuildCircuit(target)
		if err != nil {
			cb.logger.Warn("circuit build attempt failed", "attempt", attempt, "error", err)
			continue
		}
		return built, nil
	}
	return nil, fmt.Errorf("failed to build circuit after 3 attempts")
}

func (cb *circuitBuilder) tryBuildCircuit(target *descriptor.RelayInfo) (*onion.BuiltCircuit, error) {
	// Select path. If target is provided, use it as the last hop.
	var lastHopRelay *directory.Relay
	var guard, middle *directory.Relay

	if target != nil {
		// Find a relay in the consensus matching the target, or create a synthetic one.
		// For intro/rend points, we extend to them using their RelayInfo directly.
		// We still need guard and middle from path selection.
		// Use a dummy exit for path selection constraints, then replace it.
		exit, err := pathselect.SelectExit(cb.consensus)
		if err != nil {
			return nil, fmt.Errorf("select exit for path: %w", err)
		}
		g, err := pathselect.SelectGuard(cb.consensus, exit)
		if err != nil {
			return nil, fmt.Errorf("select guard: %w", err)
		}
		m, err := pathselect.SelectMiddle(cb.consensus, g, exit)
		if err != nil {
			return nil, fmt.Errorf("select middle: %w", err)
		}
		guard = g
		middle = m
	} else {
		path, err := pathselect.SelectPath(cb.consensus)
		if err != nil {
			return nil, fmt.Errorf("select path: %w", err)
		}
		guard = &path.Guard
		middle = &path.Middle
		lastHopRelay = &path.Exit
	}

	// Connect to guard.
	l, err := link.Handshake(fmt.Sprintf("%s:%d", guard.Address, guard.ORPort), cb.logger)
	if err != nil {
		return nil, fmt.Errorf("guard handshake: %w", err)
	}

	l.StartReadLoop()

	guardInfo := relayInfoFromConsensus(guard)
	c, err := circuit.Create(l, guardInfo, cb.logger)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("circuit create: %w", err)
	}

	// Extend to middle.
	middleInfo := relayInfoFromConsensus(middle)
	if err := c.Extend(middleInfo, cb.logger); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("extend to middle: %w", err)
	}

	// Extend to last hop.
	var lastHopInfo *descriptor.RelayInfo
	if target != nil {
		lastHopInfo = target
	} else {
		lastHopInfo = relayInfoFromConsensus(lastHopRelay)
	}
	if err := c.Extend(lastHopInfo, cb.logger); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("extend to last hop: %w", err)
	}

	c.StartReadLoop()
	cb.logger.Info("onion circuit built", "circID", fmt.Sprintf("0x%08x", c.ID))

	return &onion.BuiltCircuit{
		Circuit:    c,
		LinkCloser: l,
		LastHop:    lastHopInfo,
	}, nil
}

// multiHandler fans out slog records to multiple handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: hs}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: hs}
}
