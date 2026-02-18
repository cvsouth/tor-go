package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

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
	consensusText := loadOrFetchConsensus(cache)
	keyCerts := loadOrFetchKeyCerts(cache, logger)
	consensus := validateAndParseConsensus(consensusText, keyCerts, cache, logger)
	populateMicrodescriptors(consensus, cache, logger)

	fmt.Println("\nSelecting path and building circuit...")
	circ, circLink := buildInitialCircuit(consensus, logger)

	runSOCKSProxy(consensus, circ, circLink, logger)
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

func loadOrFetchConsensus(cache *directory.Cache) string {
	if text, ok := cache.LoadConsensus(); ok {
		fmt.Println("Loaded consensus from cache")
		return text
	}
	fmt.Println("Fetching consensus from directory authorities...")
	text, err := directory.FetchConsensus()
	if err != nil {
		fmt.Printf("  Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Fetched consensus (%d bytes)\n", len(text))
	return text
}

func loadOrFetchKeyCerts(cache *directory.Cache, logger *slog.Logger) []directory.KeyCert {
	keyCerts, err := cache.LoadKeyCerts()
	if err == nil && len(keyCerts) > 0 {
		fmt.Printf("Loaded %d authority key certificates from cache\n", len(keyCerts))
		return keyCerts
	}
	fmt.Println("Fetching authority key certificates...")
	keyCerts, err = directory.FetchKeyCerts()
	if err != nil {
		fmt.Printf("  Warning: failed to fetch key certificates: %v\n", err)
		fmt.Println("  Falling back to structural signature validation")
		return nil
	}
	fmt.Printf("  Fetched %d authority key certificates\n", len(keyCerts))
	if err := cache.SaveKeyCerts(keyCerts); err != nil {
		logger.Warn("failed to cache key certs", "error", err)
	}
	return keyCerts
}

func validateAndParseConsensus(text string, keyCerts []directory.KeyCert, cache *directory.Cache, logger *slog.Logger) *directory.Consensus {
	if err := directory.ValidateSignatures(text, keyCerts); err != nil {
		fmt.Printf("  Signature validation failed: %v\n", err)
		os.Exit(1)
	}
	if len(keyCerts) > 0 {
		fmt.Println("  Consensus cryptographically verified (≥5 RSA signatures)")
	} else {
		fmt.Println("  Consensus structurally validated (≥5 authority signatures)")
	}

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
	var usefulRelays []directory.Relay
	for _, r := range consensus.Relays {
		if r.Flags.Running && r.Flags.Valid && (r.Flags.Guard || r.Flags.Exit || r.Flags.Fast || r.Flags.HSDir) {
			usefulRelays = append(usefulRelays, r)
		}
	}
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

func fetchMissingMicrodescriptors(relays []directory.Relay, logger *slog.Logger) {
	needFetch := 0
	for _, r := range relays {
		if !r.HasNtorKey {
			needFetch++
		}
	}
	if needFetch == 0 {
		return
	}
	fmt.Printf("  Fetching microdescriptors for %d relays...\n", needFetch)
	for _, addr := range directory.DirAuthorities {
		if directory.UpdateRelaysWithMicrodescriptors(addr, relays) == nil {
			break
		}
		logger.Warn("microdesc fetch failed", "addr", addr)
	}
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

func buildInitialCircuit(consensus *directory.Consensus, logger *slog.Logger) (*circuit.Circuit, *link.Link) {
	for attempt := 0; attempt < 3; attempt++ {
		circ, l, err := tryBuildInitialCircuit(consensus, logger)
		if err != nil {
			fmt.Printf("  Attempt %d failed: %v\n", attempt, err)
			continue
		}
		fmt.Printf("  3-hop circuit built! (ID: 0x%08x)\n", circ.ID)
		return circ, l
	}
	fmt.Println("\nFailed to build circuit after 3 attempts.")
	os.Exit(1)
	return nil, nil
}

func tryBuildInitialCircuit(consensus *directory.Consensus, logger *slog.Logger) (*circuit.Circuit, *link.Link, error) {
	path, err := pathselect.SelectPath(consensus)
	if err != nil {
		return nil, nil, fmt.Errorf("path selection: %w", err)
	}
	fmt.Printf("  Path: %s → %s → %s\n", path.Guard.Nickname, path.Middle.Nickname, path.Exit.Nickname)

	l, err := link.Handshake(fmt.Sprintf("%s:%d", path.Guard.Address, path.Guard.ORPort), logger)
	if err != nil {
		return nil, nil, fmt.Errorf("guard connection: %w", err)
	}

	_ = l.SetDeadline(time.Now().Add(30 * time.Second))
	circ, err := circuit.Create(l, relayInfoFromConsensus(&path.Guard), logger)
	if err != nil {
		_ = l.Close()
		return nil, nil, fmt.Errorf("circuit create: %w", err)
	}

	if err := circ.Extend(relayInfoFromConsensus(&path.Middle), logger); err != nil {
		_ = l.Close()
		return nil, nil, fmt.Errorf("extend to middle: %w", err)
	}

	if err := circ.Extend(relayInfoFromConsensus(&path.Exit), logger); err != nil {
		_ = l.Close()
		return nil, nil, fmt.Errorf("extend to exit: %w", err)
	}

	_ = l.SetDeadline(time.Time{})
	return circ, l, nil
}

func runSOCKSProxy(consensus *directory.Consensus, circ *circuit.Circuit, circLink *link.Link, logger *slog.Logger) {
	var mu sync.Mutex
	socksAddr := "127.0.0.1:9050"
	fmt.Printf("\nStarting SOCKS5 proxy on %s...\n", socksAddr)

	cb := &circuitBuilder{consensus: consensus, logger: logger}
	hsHTTPClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		},
	}

	srv := &socks.Server{
		Addr:   socksAddr,
		Logger: logger,
		GetCirc: func() (*circuit.Circuit, error) {
			mu.Lock()
			defer mu.Unlock()
			if circ == nil {
				return nil, fmt.Errorf("circuit destroyed")
			}
			return circ, nil
		},
		OnionHandler: func(onionAddr string, port uint16) (io.ReadWriteCloser, error) {
			return onion.ConnectOnionService(onionAddr, port, consensus, hsHTTPClient, cb, logger)
		},
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		_ = srv.Close()
		mu.Lock()
		_ = circ.Destroy()
		circ = nil
		mu.Unlock()
		_ = circLink.Close()
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

	guardInfo := relayInfoFromConsensus(guard)
	_ = l.SetDeadline(time.Now().Add(30 * time.Second))
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

	_ = l.SetDeadline(time.Time{})
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
