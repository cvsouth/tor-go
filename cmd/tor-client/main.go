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

func main() {
	logFile, err := os.OpenFile("tor-debug.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	fileHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})
	stdoutHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(&multiHandler{handlers: []slog.Handler{fileHandler, stdoutHandler}})

	fmt.Println("=== Daphne Tor Client ===")
	fmt.Println()

	// Step 1: Load or fetch consensus
	cache := &directory.Cache{Dir: directory.DefaultCacheDir()}
	var consensusText string
	if text, ok := cache.LoadConsensus(); ok {
		fmt.Println("Loaded consensus from cache")
		consensusText = text
	} else {
		fmt.Println("Fetching consensus from directory authorities...")
		consensusText, err = directory.FetchConsensus()
		if err != nil {
			fmt.Printf("  Failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Fetched consensus (%d bytes)\n", len(consensusText))
	}

	// Step 2: Fetch authority key certificates and validate consensus signatures
	keyCerts, keyCertErr := cache.LoadKeyCerts()
	if keyCertErr != nil || len(keyCerts) == 0 {
		fmt.Println("Fetching authority key certificates...")
		keyCerts, keyCertErr = directory.FetchKeyCerts()
		if keyCertErr != nil {
			fmt.Printf("  Warning: failed to fetch key certificates: %v\n", keyCertErr)
			fmt.Println("  Falling back to structural signature validation")
			keyCerts = nil
		} else {
			fmt.Printf("  Fetched %d authority key certificates\n", len(keyCerts))
			if err := cache.SaveKeyCerts(keyCerts); err != nil {
				logger.Warn("failed to cache key certs", "error", err)
			}
		}
	} else {
		fmt.Printf("Loaded %d authority key certificates from cache\n", len(keyCerts))
	}

	if err := directory.ValidateSignatures(consensusText, keyCerts); err != nil {
		fmt.Printf("  Signature validation failed: %v\n", err)
		os.Exit(1)
	}
	if len(keyCerts) > 0 {
		fmt.Println("  Consensus cryptographically verified (≥5 RSA signatures)")
	} else {
		fmt.Println("  Consensus structurally validated (≥5 authority signatures)")
	}

	consensus, err := directory.ParseConsensus(consensusText)
	if err != nil {
		fmt.Printf("  Parse failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Parsed: %d relays, valid until %s\n", len(consensus.Relays), consensus.ValidUntil.Format(time.RFC3339))

	if err := directory.ValidateFreshness(consensus); err != nil {
		fmt.Printf("  Consensus validation failed: %v\n", err)
		os.Exit(1)
	}

	// Cache the consensus for next startup
	if err := cache.SaveConsensus(consensusText, consensus.FreshUntil, consensus.ValidUntil); err != nil {
		logger.Warn("failed to cache consensus", "error", err)
	}

	// Step 3: Fetch microdescriptors for relays with useful flags
	fmt.Println("Fetching microdescriptors...")
	var usefulRelays []directory.Relay
	for _, r := range consensus.Relays {
		if r.Flags.Running && r.Flags.Valid && (r.Flags.Guard || r.Flags.Exit || r.Flags.Fast || r.Flags.HSDir) {
			usefulRelays = append(usefulRelays, r)
		}
	}
	fmt.Printf("  %d relays with useful flags\n", len(usefulRelays))

	// Try loading microdescriptors from cache first
	cachedCount := cache.LoadMicrodescriptors(usefulRelays)
	if cachedCount > 0 {
		fmt.Printf("  Loaded %d relays from microdescriptor cache\n", cachedCount)
	}

	// Count how many still need ntor keys
	needFetch := 0
	for _, r := range usefulRelays {
		if !r.HasNtorKey {
			needFetch++
		}
	}

	if needFetch > 0 {
		fmt.Printf("  Fetching microdescriptors for %d relays...\n", needFetch)
		for _, addr := range directory.DirAuthorities {
			err = directory.UpdateRelaysWithMicrodescriptors(addr, usefulRelays)
			if err == nil {
				break
			}
			logger.Warn("microdesc fetch failed", "addr", addr, "error", err)
		}
	}

	// Count how many have ntor keys
	ntorCount := 0
	for _, r := range usefulRelays {
		if r.HasNtorKey {
			ntorCount++
		}
	}
	fmt.Printf("  %d relays with ntor keys\n", ntorCount)

	// Cache microdescriptors for next startup
	if err := cache.SaveMicrodescriptors(usefulRelays); err != nil {
		logger.Warn("failed to cache microdescriptors", "error", err)
	}

	// Update the consensus relays with the fetched data
	consensus.Relays = usefulRelays

	// Step 4: Build circuit using path selection
	fmt.Println("\nSelecting path and building circuit...")

	var circ *circuit.Circuit
	var circLink *link.Link
	var mu sync.Mutex

	for attempt := 0; attempt < 3; attempt++ {
		path, err := pathselect.SelectPath(consensus)
		if err != nil {
			fmt.Printf("  Path selection failed: %v\n", err)
			continue
		}
		fmt.Printf("  Path: %s → %s → %s\n", path.Guard.Nickname, path.Middle.Nickname, path.Exit.Nickname)
		fmt.Printf("  Guard: %s:%d\n", path.Guard.Address, path.Guard.ORPort)

		// Connect to guard
		l, err := link.Handshake(fmt.Sprintf("%s:%d", path.Guard.Address, path.Guard.ORPort), logger)
		if err != nil {
			fmt.Printf("  Guard connection failed: %v\n", err)
			continue
		}

		// Build relay info from consensus data for guard
		guardInfo := relayInfoFromConsensus(&path.Guard)

		// Create circuit to guard
		l.SetDeadline(time.Now().Add(30 * time.Second))
		circ, err = circuit.Create(l, guardInfo, logger)
		if err != nil {
			l.Close()
			fmt.Printf("  Circuit create failed: %v\n", err)
			continue
		}

		// Extend to middle
		middleInfo := relayInfoFromConsensus(&path.Middle)
		if err := circ.Extend(middleInfo, logger); err != nil {
			l.Close()
			fmt.Printf("  Extend to middle failed: %v\n", err)
			circ = nil
			continue
		}

		// Extend to exit
		exitInfo := relayInfoFromConsensus(&path.Exit)
		if err := circ.Extend(exitInfo, logger); err != nil {
			l.Close()
			fmt.Printf("  Extend to exit failed: %v\n", err)
			circ = nil
			continue
		}

		l.SetDeadline(time.Time{})
		circLink = l
		fmt.Printf("  3-hop circuit built! (ID: 0x%08x)\n", circ.ID)
		break
	}

	if circ == nil {
		fmt.Println("\nFailed to build circuit after 3 attempts.")
		os.Exit(1)
	}

	// Step 5: Start SOCKS5 proxy
	socksAddr := "127.0.0.1:9050"
	fmt.Printf("\nStarting SOCKS5 proxy on %s...\n", socksAddr)

	// Create circuit builder for onion service connections.
	cb := &circuitBuilder{
		consensus: consensus,
		logger:    logger,
	}

	// Create HTTP client for descriptor fetches.
	// HSDirs serve descriptors on their DirPort via HTTP.
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

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		srv.Close()
		mu.Lock()
		circ.Destroy()
		circ = nil
		mu.Unlock()
		circLink.Close()
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
	l.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := circuit.Create(l, guardInfo, cb.logger)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("circuit create: %w", err)
	}

	// Extend to middle.
	middleInfo := relayInfoFromConsensus(middle)
	if err := c.Extend(middleInfo, cb.logger); err != nil {
		l.Close()
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
		l.Close()
		return nil, fmt.Errorf("extend to last hop: %w", err)
	}

	l.SetDeadline(time.Time{})
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
