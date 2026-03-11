package link

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cvsouth/tor-go/cell"
)

// CircuitReceiver receives raw cells routed to a circuit by the link read loop.
type CircuitReceiver struct {
	Cells     chan cell.Cell
	Done      <-chan struct{}
	done      chan struct{} // writable; Done is read-only alias
	doneOnce  sync.Once
	cellsOnce sync.Once
}

// closeDone closes the done channel (idempotent).
func (cr *CircuitReceiver) closeDone() {
	cr.doneOnce.Do(func() {
		close(cr.done)
	})
}

// closeCells closes the Cells channel (idempotent).
func (cr *CircuitReceiver) closeCells() {
	cr.cellsOnce.Do(func() {
		close(cr.Cells)
	})
}

// ReadCell reads a cell from the circuit's channel.
// This satisfies the circuit.CellReader interface.
func (cr *CircuitReceiver) ReadCell() (cell.Cell, error) {
	select {
	case c, ok := <-cr.Cells:
		if !ok {
			return nil, fmt.Errorf("circuit receiver channel closed")
		}
		return c, nil
	case <-cr.Done:
		return nil, fmt.Errorf("circuit receiver done")
	}
}

// Link represents an established Tor link connection.
type Link struct {
	conn    *tls.Conn
	Version uint16
	Reader  *cell.Reader
	Writer  *cell.Writer
	// RelayIdentityEd25519 is the relay's Ed25519 identity key from CERTS validation.
	RelayIdentityEd25519 []byte
	// RelayAddr is the relay's IP:port we connected to.
	RelayAddr string
	// CircIDs tracks allocated circuit IDs on this link to prevent collisions.
	CircIDs map[uint32]bool

	// Circuit dispatch table for the link read loop.
	circuits        map[uint32]*CircuitReceiver
	circuitsMu      sync.RWMutex
	done            chan struct{} // signals link death
	readLoopOnce    sync.Once
	readLoopStarted bool // true after StartReadLoop; guarded by circuitsMu
	destroyOnce     sync.Once
}

// ClaimCircID registers a circuit ID on this link. Returns false if already in use.
func (l *Link) ClaimCircID(id uint32) bool {
	if l.CircIDs == nil {
		l.CircIDs = make(map[uint32]bool)
	}
	if l.CircIDs[id] {
		return false
	}
	l.CircIDs[id] = true
	return true
}

// ReleaseCircID removes a circuit ID from this link's tracking.
func (l *Link) ReleaseCircID(id uint32) {
	delete(l.CircIDs, id)
}

// SetDeadline sets a deadline on the underlying connection.
func (l *Link) SetDeadline(t time.Time) error {
	return l.conn.SetDeadline(t)
}

// Close closes the underlying TLS connection.
func (l *Link) Close() error {
	return l.conn.Close()
}

// RegisterCircuit creates and stores a CircuitReceiver for the given circuit ID.
// Returns an error if the ID is already registered or the link is dead.
func (l *Link) RegisterCircuit(circID uint32) (*CircuitReceiver, error) {
	doneCh := make(chan struct{})
	cr := &CircuitReceiver{
		Cells: make(chan cell.Cell, 32),
		Done:  doneCh,
		done:  doneCh,
	}

	l.circuitsMu.Lock()
	defer l.circuitsMu.Unlock()

	// Check link death under the lock.
	if l.done != nil {
		select {
		case <-l.done:
			return nil, fmt.Errorf("link is dead")
		default:
		}
	}

	if l.circuits == nil {
		l.circuits = make(map[uint32]*CircuitReceiver)
	}
	if _, exists := l.circuits[circID]; exists {
		return nil, fmt.Errorf("circuit ID 0x%08x already registered", circID)
	}
	l.circuits[circID] = cr
	return cr, nil
}

// UnregisterCircuit removes a circuit from the dispatch table and signals Done.
// It does NOT close cr.Cells - the cells channel is only closed in cleanupAllCircuits
// (on link death) to avoid a race with runReadLoop sending to the channel.
func (l *Link) UnregisterCircuit(circID uint32) {
	l.circuitsMu.Lock()
	var cr *CircuitReceiver
	if l.circuits != nil {
		cr = l.circuits[circID]
		delete(l.circuits, circID)
	}
	l.circuitsMu.Unlock()

	if cr != nil {
		cr.closeDone()
	}
}

// StartReadLoop starts the background read loop goroutine (idempotent via sync.Once).
func (l *Link) StartReadLoop() {
	l.readLoopOnce.Do(func() {
		l.circuitsMu.Lock()
		l.readLoopStarted = true
		l.circuitsMu.Unlock()
		go l.runReadLoop()
	})
}

// runReadLoop reads cells from the TLS connection and routes them by circuit ID.
func (l *Link) runReadLoop() {
	defer l.cleanupAllCircuits()
	defer l.destroy()

	for {
		c, err := l.Reader.ReadCell()
		if err != nil {
			slog.Debug("link read loop exiting", "addr", l.RelayAddr, "err", err)
			return
		}

		cmd := c.Command()

		// Discard PADDING/VPADDING at the link level.
		if cmd == cell.CmdPadding || cmd == cell.CmdVPadding {
			continue
		}

		circID := c.CircID()

		l.circuitsMu.RLock()
		cr, exists := l.circuits[circID]
		l.circuitsMu.RUnlock()

		if !exists {
			slog.Debug("discarding cell for unknown circuit", "circID", fmt.Sprintf("0x%08x", circID), "cmd", cmd)
			continue
		}

		select {
		case cr.Cells <- c:
		case <-cr.Done:
			slog.Debug("discarding cell for closed circuit", "circID", fmt.Sprintf("0x%08x", circID), "cmd", cmd)
		case <-l.done:
			return
		}
	}
}

// cleanupAllCircuits closes all circuit done and cells channels so consumers unblock.
func (l *Link) cleanupAllCircuits() {
	l.circuitsMu.Lock()
	defer l.circuitsMu.Unlock()

	for _, cr := range l.circuits {
		cr.closeDone()
		cr.closeCells()
	}
}

// destroy signals link death by closing the done channel (idempotent via sync.Once).
func (l *Link) destroy() {
	l.destroyOnce.Do(func() {
		if l.done != nil {
			close(l.done)
		}
	})
}

// LinkDone returns the link's done channel for detecting link death.
// Returns nil if the link has no done channel (e.g., test links).
func (l *Link) LinkDone() <-chan struct{} {
	return l.done
}

// NewTestLink creates a Link suitable for testing with the given cell reader
// and writer. It initializes the circuits map and done channel so that
// RegisterCircuit, StartReadLoop, etc. work correctly.
func NewTestLink(reader *cell.Reader, writer *cell.Writer) *Link {
	return &Link{
		Reader:   reader,
		Writer:   writer,
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}
}

// Handshake connects to a Tor relay and performs the full link handshake.
// Returns a ready Link or an error.
func Handshake(addr string, logger *slog.Logger) (*Link, error) {
	return HandshakeWithPinning(addr, nil, logger)
}

// HandshakeWithPinning connects to a Tor relay and performs the full link handshake.
// If expectedEd25519 is non-nil, the relay's Ed25519 identity key from the CERTS
// cell is compared using constant-time comparison; a mismatch returns an error.
func HandshakeWithPinning(addr string, expectedEd25519 []byte, logger *slog.Logger) (*Link, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Step 1: TLS connection
	tlsConn, peerCertHash, err := dialTLS(addr, logger)
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(tlsConn)
	cr := cell.NewReader(br)
	cw := cell.NewWriter(tlsConn)

	// Step 2: VERSIONS exchange
	versionsCell := cell.NewVersionsCell([]uint16{4, 5})
	logger.Debug("sending VERSIONS", "versions", []uint16{4, 5})
	if err := cw.WriteCell(versionsCell); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("send VERSIONS: %w", err)
	}

	serverVersions, err := cr.ReadVersionsCell()
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("read VERSIONS: %w", err)
	}
	versions := cell.ParseVersions(serverVersions)
	logger.Debug("received VERSIONS", "versions", versions)

	negotiated := negotiateVersion(versions)
	if negotiated == 0 {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("no common link protocol version >= 4 (server offered %v)", versions)
	}
	logger.Info("version negotiated", "version", negotiated)

	// Step 3: Read CERTS cell
	certsCell, err := readExpectedCell(cr, cell.CmdCerts, logger)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("read CERTS: %w", err)
	}

	identityKey, err := validateCerts(certsCell.Payload(), peerCertHash[:], logger)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("validate CERTS: %w", err)
	}
	logger.Debug("certs validated", "identity", fmt.Sprintf("%x", identityKey[:8]))

	if err := checkPinning(identityKey, expectedEd25519); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if expectedEd25519 != nil {
		logger.Debug("identity pinning verified")
	}

	// Step 4: Read AUTH_CHALLENGE (discard)
	_, err = readExpectedCell(cr, cell.CmdAuthChallenge, logger)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("read AUTH_CHALLENGE: %w", err)
	}
	logger.Debug("auth_challenge received and discarded")

	// Step 5: Read relay's NETINFO
	netinfoCell, err := readExpectedCell(cr, cell.CmdNetInfo, logger)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("read NETINFO: %w", err)
	}
	logger.Debug("received relay NETINFO", "payload_hex", fmt.Sprintf("%x", netinfoCell.Payload()[:20]))

	// Step 6: Send our NETINFO
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("parse relay addr: %w", err)
	}
	relayIP := net.ParseIP(host).To4()
	if relayIP == nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("relay IP not IPv4: %s", host)
	}

	ourNetinfo := buildNetInfo(relayIP)
	logger.Debug("sending NETINFO")
	if err := cw.WriteCell(ourNetinfo); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("send NETINFO: %w", err)
	}

	// Clear handshake deadline
	_ = tlsConn.SetDeadline(time.Time{})
	logger.Info("handshake complete")

	return &Link{
		conn:                 tlsConn,
		Version:              negotiated,
		Reader:               cr,
		Writer:               cw,
		RelayIdentityEd25519: identityKey,
		RelayAddr:            addr,
		circuits:             make(map[uint32]*CircuitReceiver),
		done:                 make(chan struct{}),
	}, nil
}

// dialTLS establishes a TLS connection to the given address and returns the
// connection along with the SHA-256 hash of the peer's TLS certificate.
func dialTLS(addr string, logger *slog.Logger) (*tls.Conn, [32]byte, error) {
	logger.Info("connecting", "addr", addr)
	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("tcp dial: %w", err)
	}

	tlsConfig := &tls.Config{
		// Tor relays use self-signed certs; identity is verified via CERTS cell Ed25519 chain, not TLS PKI.
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
		MinVersion:             tls.VersionTLS12,
		// Use Go's default cipher suites and curve preferences to avoid a distinctive TLS fingerprint.
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	// Set deadline for entire handshake phase
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = tcpConn.Close()
		return nil, [32]byte{}, fmt.Errorf("tls handshake: %w", err)
	}
	logger.Info("tls established", "version", tlsConn.ConnectionState().Version)

	// Get peer TLS cert for CERTS validation
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = tlsConn.Close()
		return nil, [32]byte{}, fmt.Errorf("no peer TLS certificate")
	}
	peerCertDER := state.PeerCertificates[0].Raw
	peerCertHash := sha256.Sum256(peerCertDER)
	logger.Debug("peer TLS cert hash", "sha256", fmt.Sprintf("%x", peerCertHash))

	return tlsConn, peerCertHash, nil
}

// checkPinning verifies that actualKey matches expectedKey using constant-time
// comparison. If expectedKey is nil, the check is skipped (no pinning requested).
func checkPinning(actualKey, expectedKey []byte) error {
	if expectedKey == nil {
		return nil
	}
	if subtle.ConstantTimeCompare(actualKey, expectedKey) != 1 {
		return fmt.Errorf("identity pinning failed: expected %x, got %x", expectedKey, actualKey)
	}
	return nil
}

func negotiateVersion(serverVersions []uint16) uint16 {
	clientVersions := map[uint16]bool{4: true, 5: true}
	var best uint16
	for _, v := range serverVersions {
		if clientVersions[v] && v > best {
			best = v
		}
	}
	return best
}

// readExpectedCell reads cells, skipping PADDING/VPADDING, until it gets the expected command.
func readExpectedCell(cr *cell.Reader, expected uint8, logger *slog.Logger) (cell.Cell, error) {
	for i := 0; i < 100; i++ {
		c, err := cr.ReadCell()
		if err != nil {
			return nil, err
		}
		cmd := c.Command()
		if cmd == cell.CmdPadding || cmd == cell.CmdVPadding {
			logger.Debug("skipping padding cell", "cmd", cmd)
			continue
		}
		if cmd != expected {
			return nil, fmt.Errorf("expected command %d, got %d", expected, cmd)
		}
		return c, nil
	}
	return nil, fmt.Errorf("too many padding cells before command %d", expected)
}

// buildNetInfo creates a client NETINFO cell.
func buildNetInfo(relayIP net.IP) cell.Cell {
	c := cell.NewFixedCell(0, cell.CmdNetInfo)
	p := c.Payload()
	// Timestamp = 0 (avoid fingerprinting)
	p[0] = 0
	p[1] = 0
	p[2] = 0
	p[3] = 0
	// OTHERADDR = relay's IPv4
	p[4] = 0x04 // ATYPE IPv4
	p[5] = 0x04 // ALEN = 4
	copy(p[6:10], relayIP)
	// NMYADDR = 0
	p[10] = 0x00
	return c
}
