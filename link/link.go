package link

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/cvsouth/tor-go/cell"
)

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

// Handshake connects to a Tor relay and performs the full link handshake.
// Returns a ready Link or an error.
func Handshake(addr string, logger *slog.Logger) (*Link, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Step 1: TLS connection
	logger.Info("connecting", "addr", addr)
	tcpConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
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
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	logger.Info("tls established", "version", tlsConn.ConnectionState().Version)

	// Get peer TLS cert for CERTS validation
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("no peer TLS certificate")
	}
	peerCertDER := state.PeerCertificates[0].Raw
	peerCertHash := sha256.Sum256(peerCertDER)
	logger.Debug("peer TLS cert hash", "sha256", fmt.Sprintf("%x", peerCertHash))

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
	}, nil
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
