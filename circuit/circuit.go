package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"log/slog"
	"sync"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/link"
	"github.com/cvsouth/tor-go/ntor"
)

// Hop holds the encryption state for one circuit hop.
type Hop struct {
	kf cipher.Stream // Forward AES-128-CTR (client→relay)
	kb cipher.Stream // Backward AES-128-CTR (relay→client)
	df hash.Hash     // Forward running SHA-1 digest
	db hash.Hash     // Backward running SHA-1 digest
}

// MaxRelayEarly is the maximum number of RELAY_EARLY cells per circuit (tor-spec §5.6).
const MaxRelayEarly = 8

// Circuit represents an established Tor circuit over a link.
type Circuit struct {
	rmu            sync.Mutex // protects reads: Reader, kb, db
	wmu            sync.Mutex // protects writes: Writer, kf, df, RelayEarlySent
	ID             uint32
	Link           *link.Link
	Hops           []*Hop
	RelayEarlySent int // tracks RELAY_EARLY cells sent (max 8)
}

// Create performs a CREATE2/CREATED2 handshake to build a single-hop circuit.
func Create(l *link.Link, relayInfo *descriptor.RelayInfo, logger *slog.Logger) (*Circuit, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Allocate circuit ID with MSB=1, ensuring uniqueness on this link
	var circID uint32
	for attempts := 0; attempts < 16; attempts++ {
		id, err := allocateCircID()
		if err != nil {
			return nil, fmt.Errorf("allocate circuit ID: %w", err)
		}
		if l.ClaimCircID(id) {
			circID = id
			break
		}
	}
	if circID == 0 {
		return nil, fmt.Errorf("failed to allocate unique circuit ID after 16 attempts")
	}
	logger.Info("circuit ID allocated", "circID", fmt.Sprintf("0x%08x", circID))

	// Create ntor handshake
	hs, err := ntor.NewHandshake(relayInfo.NodeID, relayInfo.NtorOnionKey)
	if err != nil {
		return nil, fmt.Errorf("ntor handshake init: %w", err)
	}
	defer hs.Close() // Zero ephemeral private key on all exit paths

	// Build CREATE2 cell
	clientData := hs.ClientData()
	create2 := cell.NewFixedCell(circID, cell.CmdCreate2)
	p := create2.Payload()
	binary.BigEndian.PutUint16(p[0:2], 0x0002) // HTYPE = ntor
	binary.BigEndian.PutUint16(p[2:4], 84)     // HLEN = 84
	copy(p[4:88], clientData[:])

	// Set deadline for circuit creation
	l.SetDeadline(time.Now().Add(30 * time.Second))
	defer l.SetDeadline(time.Time{}) // Clear deadline after

	logger.Debug("sending CREATE2", "circID", fmt.Sprintf("0x%08x", circID))
	if err := l.Writer.WriteCell(create2); err != nil {
		return nil, fmt.Errorf("send CREATE2: %w", err)
	}

	// Read response
	resp, err := l.Reader.ReadCell()
	if err != nil {
		return nil, fmt.Errorf("read CREATED2: %w", err)
	}

	cmd := resp.Command()
	if cmd == cell.CmdDestroy {
		reason := resp.Payload()[0]
		return nil, fmt.Errorf("relay sent DESTROY (reason=%d) instead of CREATED2", reason)
	}
	if cmd != cell.CmdCreated2 {
		return nil, fmt.Errorf("expected CREATED2 (11), got command %d", cmd)
	}

	// Parse CREATED2: HLEN(2) + HDATA(HLEN)
	rp := resp.Payload()
	hlen := binary.BigEndian.Uint16(rp[0:2])
	if hlen != 64 {
		return nil, fmt.Errorf("CREATED2 HLEN=%d, expected 64", hlen)
	}

	var serverData [64]byte
	copy(serverData[:], rp[2:66])

	logger.Debug("received CREATED2")

	// Complete ntor handshake
	km, err := hs.Complete(serverData)
	if err != nil {
		return nil, fmt.Errorf("ntor complete: %w", err)
	}

	logger.Info("ntor handshake complete")

	// Initialize AES-128-CTR ciphers with zero IV
	hop, err := initHop(km)
	clear(km.Kf[:])
	clear(km.Kb[:])
	clear(km.Df[:])
	clear(km.Db[:])
	if err != nil {
		return nil, fmt.Errorf("init hop: %w", err)
	}

	return &Circuit{
		ID:   circID,
		Link: l,
		Hops: []*Hop{hop},
	}, nil
}

// SendRelay encrypts and sends a relay cell through the circuit.
// The encrypt and write are atomic to prevent interleaving of cipher stream state.
func (c *Circuit) SendRelay(relayCmd uint8, streamID uint16, data []byte) error {
	c.wmu.Lock()
	relayCell, err := c.encryptRelayLocked(relayCmd, streamID, data)
	if err != nil {
		c.wmu.Unlock()
		return fmt.Errorf("encrypt relay: %w", err)
	}
	err = c.Link.Writer.WriteCell(relayCell)
	c.wmu.Unlock()
	return err
}

// ReceiveRelay reads and decrypts a relay cell from the circuit.
// It skips PADDING cells and returns an error on DESTROY.
// The read and decrypt are atomic to prevent interleaving of cipher stream state.
func (c *Circuit) ReceiveRelay() (hopIdx int, relayCmd uint8, streamID uint16, data []byte, err error) {
	for {
		c.rmu.Lock()
		incoming, err := c.Link.Reader.ReadCell()
		if err != nil {
			c.rmu.Unlock()
			return 0, 0, 0, nil, fmt.Errorf("read cell: %w", err)
		}

		cmd := incoming.Command()
		switch cmd {
		case cell.CmdPadding:
			c.rmu.Unlock()
			continue
		case cell.CmdDestroy:
			c.rmu.Unlock()
			reason := incoming.Payload()[0]
			return 0, 0, 0, nil, fmt.Errorf("circuit destroyed by relay (reason=%d)", reason)
		case cell.CmdRelay, cell.CmdRelayEarly:
			h, rc, sid, d, derr := c.decryptRelayLocked(incoming)
			c.rmu.Unlock()
			return h, rc, sid, d, derr
		default:
			c.rmu.Unlock()
			return 0, 0, 0, nil, fmt.Errorf("unexpected cell command %d on circuit", cmd)
		}
	}
}

// BackwardDigest returns the current backward digest state (for SENDME v1).
// NOTE: This must be called while the circuit mutex is NOT held (it acquires it).
// For use in flow control after ReceiveRelay returns.
func (c *Circuit) BackwardDigest() []byte {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.Hops) == 0 {
		return nil
	}
	return c.Hops[len(c.Hops)-1].db.Sum(nil)
}

// SendRelayEarly sends a RELAY_EARLY cell, enforcing the per-circuit budget of 8.
// Caller must NOT hold c.wmu.
func (c *Circuit) SendRelayEarly(payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.RelayEarlySent >= MaxRelayEarly {
		return fmt.Errorf("RELAY_EARLY budget exhausted (%d/%d)", c.RelayEarlySent, MaxRelayEarly)
	}
	c.RelayEarlySent++

	earlyCell := cell.NewFixedCell(c.ID, cell.CmdRelayEarly)
	copy(earlyCell.Payload(), payload)
	return c.Link.Writer.WriteCell(earlyCell)
}

// Destroy sends a DESTROY cell to tear down the circuit.
func (c *Circuit) Destroy() error {
	destroy := cell.NewFixedCell(c.ID, cell.CmdDestroy)
	destroy.Payload()[0] = 0 // reason = NONE
	return c.Link.Writer.WriteCell(destroy)
}

// NewHop creates a Hop with caller-provided cipher streams and digest hashes.
// This allows onion service circuits to use SHA3-256/AES-256-CTR instead of SHA1/AES-128-CTR.
func NewHop(kf, kb cipher.Stream, df, db hash.Hash) *Hop {
	return &Hop{kf: kf, kb: kb, df: df, db: db}
}

// AddHop appends a hop to the circuit (e.g., the virtual onion-service hop after RENDEZVOUS2).
func (c *Circuit) AddHop(hop *Hop) {
	c.wmu.Lock()
	c.rmu.Lock()
	c.Hops = append(c.Hops, hop)
	c.rmu.Unlock()
	c.wmu.Unlock()
}

func allocateCircID() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	circID := binary.BigEndian.Uint32(buf[:])
	circID |= 0x80000000 // Set MSB (client-initiated)
	return circID, nil
}

func initHop(km *ntor.KeyMaterial) (*Hop, error) {
	// AES-128-CTR with zero IV (stream state persists across cells)
	zeroIV := make([]byte, aes.BlockSize)

	fwdBlock, err := aes.NewCipher(km.Kf[:])
	if err != nil {
		return nil, fmt.Errorf("AES-CTR forward: %w", err)
	}
	bwdBlock, err := aes.NewCipher(km.Kb[:])
	if err != nil {
		return nil, fmt.Errorf("AES-CTR backward: %w", err)
	}

	// SHA-1 running digests seeded with Df/Db
	df := sha1.New()
	df.Write(km.Df[:])
	db := sha1.New()
	db.Write(km.Db[:])

	return &Hop{
		kf: cipher.NewCTR(fwdBlock, zeroIV),
		kb: cipher.NewCTR(bwdBlock, zeroIV),
		df: df,
		db: db,
	}, nil
}
