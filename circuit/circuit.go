package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/link"
	"github.com/cvsouth/tor-go/ntor"
)

// nextStreamID is the global atomic counter for stream ID allocation.
// Both the stream package and onion package use NextStreamID() to avoid
// circular imports - the allocator lives here because circuit is imported by both.
var nextStreamID atomic.Uint32

func init() {
	nextStreamID.Store(1)
}

// NextStreamID allocates a unique non-zero stream ID (uint16).
// It is safe for concurrent use from multiple goroutines.
func NextStreamID() uint16 {
	for {
		raw := nextStreamID.Add(1) - 1
		id := uint16(raw)
		if id != 0 {
			return id
		}
		// Wrapped to 0 - skip it. The uint32 counter will naturally
		// wrap at 2^32, which covers ~65535 full uint16 cycles.
	}
}

// ResetNextStreamID sets the stream ID counter to the given value.
// This is exported for use in tests only.
func ResetNextStreamID(v uint32) {
	nextStreamID.Store(v)
}

// Hop holds the encryption state for one circuit hop.
type Hop struct {
	kf cipher.Stream // Forward AES-128-CTR (client→relay)
	kb cipher.Stream // Backward AES-128-CTR (relay→client)
	df hash.Hash     // Forward running SHA-1 digest
	db hash.Hash     // Backward running SHA-1 digest
}

// MaxRelayEarly is the maximum number of RELAY_EARLY cells per circuit (tor-spec §5.6).
const MaxRelayEarly = 8

// Circuit-level flow control constants.
const (
	circSendMeWindow = 100  // Send circuit SENDME every 100 DATA cells received
	initCircWindow   = 1000 // Initial circuit-level receive window
	sendMeVersion    = 1    // SENDME v1 version byte
)

// CellReader abstracts cell reading so the circuit can be tested without real TLS.
type CellReader interface {
	ReadCell() (cell.Cell, error)
}

// RelayCell holds a decrypted relay cell routed to a stream.
type RelayCell struct {
	HopIdx   int
	Cmd      uint8
	StreamID uint16
	Data     []byte
	Digest   []byte // backward digest snapshot after decryption (for SENDME v1)
}

// StreamReceiver receives relay cells for a single stream.
type StreamReceiver struct {
	Cells     chan RelayCell
	Done      <-chan struct{}
	done      chan struct{} // writable; Done is read-only alias
	doneOnce  sync.Once
	cellsOnce sync.Once
}

// closeDone closes the done channel (idempotent).
func (sr *StreamReceiver) closeDone() {
	sr.doneOnce.Do(func() {
		close(sr.done)
	})
}

// closeCells closes the Cells channel (idempotent).
func (sr *StreamReceiver) closeCells() {
	sr.cellsOnce.Do(func() {
		close(sr.Cells)
	})
}

// Circuit represents an established Tor circuit over a link.
type Circuit struct {
	rmu            sync.Mutex // protects reads: Reader, kb, db
	wmu            sync.Mutex // protects writes: Writer, kf, df, RelayEarlySent
	ID             uint32
	Link           *link.Link
	Hops           []*Hop
	RelayEarlySent int // tracks RELAY_EARLY cells sent (max 8)

	// Stream dispatch table
	streams         map[uint16]*StreamReceiver
	streamsMu       sync.RWMutex
	done            chan struct{}  // signals circuit death
	readLoopOnce    sync.Once      // ensures read loop starts only once
	readLoopStarted bool           // true after StartReadLoop; guarded by streamsMu
	destroyOnce     sync.Once      // ensures done channel closes only once
	destroyCallOnce sync.Once      // ensures Destroy() runs only once
	cellReader      CellReader     // injectable for testing; defaults to Link.Reader
	setupMu         sync.Mutex     // serializes ReceiveRelaySetup with StartReadLoop
	setupWg         sync.WaitGroup // tracks in-flight ReceiveRelaySetup calls

	// Circuit-level flow control (protected by streamsMu)
	circDataReceived int // DATA cells received since last circuit SENDME
	circWindow       int // Circuit-level receive window (init 1000)

	// Circuit-level send window signaling
	circWindowSignal chan struct{} // buffered(1), signaled when circuit SENDME received
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

	// Register with the link's circuit dispatch table so the link read loop
	// routes cells for this circuit to our channel.
	linkRecv, err := l.RegisterCircuit(circID)
	if err != nil {
		l.ReleaseCircID(circID)
		return nil, fmt.Errorf("register circuit: %w", err)
	}

	// cleanup releases circuit resources on error paths.
	cleanup := func() {
		l.UnregisterCircuit(circID)
		l.ReleaseCircID(circID)
	}

	logger.Debug("sending CREATE2", "circID", fmt.Sprintf("0x%08x", circID))
	if err := l.Writer.WriteCell(create2); err != nil {
		cleanup()
		return nil, fmt.Errorf("send CREATE2: %w", err)
	}

	// Read response from link's circuit channel with a timeout.
	// We use select directly instead of SetDeadline, because SetDeadline on
	// the TLS connection would interrupt the link read loop's in-progress reads.
	serverData, err := receiveCreated2(linkRecv)
	if err != nil {
		cleanup()
		return nil, err
	}

	logger.Debug("received CREATED2")

	// Complete ntor handshake
	km, err := hs.Complete(serverData)
	if err != nil {
		cleanup()
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
		cleanup()
		return nil, fmt.Errorf("init hop: %w", err)
	}

	return &Circuit{
		ID:               circID,
		Link:             l,
		Hops:             []*Hop{hop},
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
		cellReader:       linkRecv,
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

// ReceiveRelaySetup reads and decrypts a relay cell from the circuit.
// It is intended ONLY for use during circuit setup, before StartReadLoop is called.
// Once the read loop is running, use RegisterStream + channel reads instead.
// Returns an error if the read loop has already been started.
//
// setupMu serializes this with StartReadLoop: if ReceiveRelaySetup is in-flight,
// StartReadLoop blocks until it completes, preventing a TOCTOU race on cell reads.
func (c *Circuit) ReceiveRelaySetup() (hopIdx int, relayCmd uint8, streamID uint16, data []byte, err error) {
	c.setupMu.Lock()
	c.streamsMu.RLock()
	started := c.readLoopStarted
	c.streamsMu.RUnlock()
	if started {
		c.setupMu.Unlock()
		return 0, 0, 0, nil, fmt.Errorf("ReceiveRelaySetup called after StartReadLoop; use RegisterStream + channel reads instead")
	}
	c.setupWg.Add(1)
	c.setupMu.Unlock()
	defer c.setupWg.Done()
	hopIdx, relayCmd, streamID, data, _, err = c.receiveRelay()
	return
}

// receiveRelay reads and decrypts a relay cell from the circuit.
// It skips PADDING cells and returns an error on DESTROY.
// ReadCell is called without holding rmu (it may block on a channel);
// rmu is only acquired for the decrypt + digest capture on RELAY/RELAY_EARLY cells.
// The returned digest is the backward digest snapshot captured under rmu after decryption,
// for use in SENDME v1 flow control.
func (c *Circuit) receiveRelay() (hopIdx int, relayCmd uint8, streamID uint16, data []byte, digest []byte, err error) {
	reader := c.getCellReader()
	for {
		incoming, err := reader.ReadCell()
		if err != nil {
			return 0, 0, 0, nil, nil, fmt.Errorf("read cell: %w", err)
		}

		cmd := incoming.Command()
		switch cmd {
		case cell.CmdPadding:
			continue
		case cell.CmdDestroy:
			reason := incoming.Payload()[0]
			return 0, 0, 0, nil, nil, fmt.Errorf("circuit destroyed by relay (reason=%d)", reason)
		case cell.CmdRelay, cell.CmdRelayEarly:
			c.rmu.Lock()
			h, rc, sid, d, derr := c.decryptRelayLocked(incoming)
			if derr != nil {
				c.rmu.Unlock()
				return 0, 0, 0, nil, nil, derr
			}
			// Capture backward digest under rmu to avoid race with concurrent cells.
			var bwDigest []byte
			if len(c.Hops) > 0 {
				bwDigest = c.Hops[len(c.Hops)-1].db.Sum(nil)
			}
			c.rmu.Unlock()
			return h, rc, sid, d, bwDigest, nil
		default:
			return 0, 0, 0, nil, nil, fmt.Errorf("unexpected cell command %d on circuit", cmd)
		}
	}
}

// getCellReader returns the cell reader to use. If cellReader is set (for testing),
// it is used; otherwise falls back to Link.Reader.
func (c *Circuit) getCellReader() CellReader {
	if c.cellReader != nil {
		return c.cellReader
	}
	return c.Link.Reader
}

// RegisterStream creates and stores a StreamReceiver for the given stream ID.
// Returns an error if the ID is already registered or the circuit is destroyed.
func (c *Circuit) RegisterStream(id uint16) (*StreamReceiver, error) {
	doneCh := make(chan struct{})
	sr := &StreamReceiver{
		Cells: make(chan RelayCell, 64),
		Done:  doneCh,
		done:  doneCh,
	}

	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	// Check circuit death under the lock to prevent TOCTOU race with destroy().
	select {
	case <-c.done:
		return nil, fmt.Errorf("circuit is destroyed")
	default:
	}

	if _, exists := c.streams[id]; exists {
		return nil, fmt.Errorf("stream ID %d already registered", id)
	}
	c.streams[id] = sr
	return sr, nil
}

// UnregisterStream removes a stream from the dispatch table and signals Done.
// It does NOT close sr.Cells - the cells channel is only closed in cleanupAllStreams
// (on circuit death) to avoid a race with runReadLoop sending to the channel.
// Consumers should select on sr.Done to detect unregistration/circuit death.
func (c *Circuit) UnregisterStream(id uint16) {
	c.streamsMu.Lock()
	sr := c.streams[id]
	delete(c.streams, id)
	c.streamsMu.Unlock()

	if sr != nil {
		sr.closeDone()
	}
}

// StartReadLoop starts the background read loop goroutine (idempotent via sync.Once).
// It acquires setupMu to serialize with ReceiveRelaySetup, then waits for any
// in-flight setup reads to complete before starting the goroutine.
func (c *Circuit) StartReadLoop() {
	c.readLoopOnce.Do(func() {
		c.setupMu.Lock()
		c.streamsMu.Lock()
		c.readLoopStarted = true
		c.streamsMu.Unlock()
		c.setupMu.Unlock()
		// Wait for any in-flight ReceiveRelaySetup calls to drain.
		c.setupWg.Wait()
		go c.runReadLoop()
	})
}

// runReadLoop is the background goroutine that reads cells and routes them to streams.
func (c *Circuit) runReadLoop() {
	defer c.cleanupAllStreams() // runs second (LIFO)
	defer c.destroy()           // runs first: closes c.done so RegisterStream rejects new streams

	for {
		hopIdx, relayCmd, streamID, data, digest, err := c.receiveRelay()
		if err != nil {
			// Circuit died (DESTROY, read error, etc.)
			slog.Debug("read loop exiting", "circID", fmt.Sprintf("0x%08x", c.ID), "err", err)
			return
		}

		rc := RelayCell{
			HopIdx:   hopIdx,
			Cmd:      relayCmd,
			StreamID: streamID,
			Data:     data,
			Digest:   digest,
		}

		if streamID == 0 {
			c.handleCircuitCell(rc)
			continue
		}

		// Count DATA cells for circuit-level flow control
		if relayCmd == RelayData {
			if err := c.handleCircuitDataReceived(digest); err != nil {
				slog.Error("circuit SENDME failed", "circID", fmt.Sprintf("0x%08x", c.ID), "err", err)
				return
			}
		}

		c.streamsMu.RLock()
		sr, exists := c.streams[streamID]
		c.streamsMu.RUnlock()

		if !exists {
			slog.Debug("discarding cell for unknown stream", "streamID", streamID, "cmd", relayCmd)
			continue
		}

		select {
		case sr.Cells <- rc:
		case <-sr.Done:
			// Stream closed; discard the cell.
			slog.Debug("discarding cell for closed stream", "streamID", streamID, "cmd", relayCmd)
		case <-c.done:
			return
		}
	}
}

// handleCircuitCell handles circuit-level relay cells (streamID=0) such as SENDME.
func (c *Circuit) handleCircuitCell(rc RelayCell) {
	switch rc.Cmd {
	case RelaySendMe:
		c.streamsMu.Lock()
		c.circWindow += circSendMeWindow
		newWindow := c.circWindow
		c.streamsMu.Unlock()
		// Signal any writers waiting on circuit window (non-blocking)
		select {
		case c.circWindowSignal <- struct{}{}:
		default:
		}
		slog.Debug("circuit-level SENDME received", "circID", fmt.Sprintf("0x%08x", c.ID), "newWindow", newWindow)
	default:
		slog.Debug("circuit-level cell", "circID", fmt.Sprintf("0x%08x", c.ID), "cmd", rc.Cmd)
	}
}

// CircuitWindow returns the current circuit-level send window.
func (c *Circuit) CircuitWindow() int {
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	return c.circWindow
}

// circuitWindowTimeout is how long WaitCircuitWindow blocks before giving up.
const circuitWindowTimeout = 30 * time.Second

// WaitCircuitWindow blocks until circWindow > 0 or the circuit/stream dies or times out.
func (c *Circuit) WaitCircuitWindow(done <-chan struct{}) error {
	timer := time.NewTimer(circuitWindowTimeout)
	defer timer.Stop()

	for {
		c.streamsMu.RLock()
		w := c.circWindow
		c.streamsMu.RUnlock()
		if w > 0 {
			// Re-signal in case other writers are also waiting
			select {
			case c.circWindowSignal <- struct{}{}:
			default:
			}
			return nil
		}
		select {
		case <-c.circWindowSignal:
			// Circuit window may have been replenished - re-check
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(circuitWindowTimeout)
			continue
		case <-c.done:
			return fmt.Errorf("circuit died while waiting for circuit window")
		case <-done:
			return fmt.Errorf("stream closed while waiting for circuit window")
		case <-timer.C:
			return fmt.Errorf("timeout waiting for circuit window")
		}
	}
}

// DecrementCircuitWindow decrements the circuit-level send window by 1.
func (c *Circuit) DecrementCircuitWindow() {
	c.streamsMu.Lock()
	c.circWindow--
	c.streamsMu.Unlock()
}

// TryDecrementCircuitWindow atomically checks and decrements the circuit-level
// send window. Returns true if the decrement succeeded (window was > 0),
// false if the window was already 0 (caller should retry the wait).
func (c *Circuit) TryDecrementCircuitWindow() bool {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()
	if c.circWindow <= 0 {
		return false
	}
	c.circWindow--
	return true
}

// RestoreCircuitWindow increments the circuit-level send window by 1.
// Used to restore credit when a send fails after the window was already decremented.
func (c *Circuit) RestoreCircuitWindow() {
	c.streamsMu.Lock()
	c.circWindow++
	c.streamsMu.Unlock()
}

// Done returns the circuit's done channel for external consumers to detect circuit death.
func (c *Circuit) Done() <-chan struct{} {
	return c.done
}

// SetCircuitWindowForTest sets the circuit window to a specific value (for testing only).
func (c *Circuit) SetCircuitWindowForTest(w int) {
	c.streamsMu.Lock()
	c.circWindow = w
	c.streamsMu.Unlock()
}

// destroy signals circuit death by closing the done channel (idempotent via sync.Once).
func (c *Circuit) destroy() {
	c.destroyOnce.Do(func() {
		close(c.done)
	})
}

// cleanupAllStreams closes all stream done and cells channels so consumers unblock.
// Holds streamsMu for the entire operation to prevent concurrent registrations
// (safe because destroy() has already closed c.done, so RegisterStream will reject
// under the lock, and the channel closes are fast).
func (c *Circuit) cleanupAllStreams() {
	c.streamsMu.Lock()
	defer c.streamsMu.Unlock()

	for _, sr := range c.streams {
		sr.closeDone()
		sr.closeCells()
	}
}

// SendMeV1 builds a SENDME v1 payload with the given digest.
// Returns an error if the digest is nil or shorter than 20 bytes.
func SendMeV1(digest []byte) ([]byte, error) {
	if len(digest) < 20 {
		return nil, fmt.Errorf("SendMeV1: digest too short (%d bytes, need 20)", len(digest))
	}
	// Version(1) + DataLen(2) + Data(20)
	payload := make([]byte, 23)
	payload[0] = sendMeVersion
	binary.BigEndian.PutUint16(payload[1:3], 20)
	copy(payload[3:23], digest[:20])
	return payload, nil
}

// handleCircuitDataReceived tracks circuit-level DATA cell counting and sends
// circuit-level SENDME when the threshold is reached.
// The digest parameter is the backward digest snapshot captured after decryption.
//
// If SendRelay fails after the counter has been reset to 0, the lost SENDME is
// acceptable because the error causes the read loop to return, which tears down
// the circuit (via destroy + cleanupAllStreams). The relay will eventually
// time out and clean up its side.
func (c *Circuit) handleCircuitDataReceived(digest []byte) error {
	c.streamsMu.Lock()
	c.circDataReceived++
	count := c.circDataReceived
	if count >= circSendMeWindow {
		c.circDataReceived = 0
	}
	c.streamsMu.Unlock()

	if count >= circSendMeWindow {
		payload, err := SendMeV1(digest)
		if err != nil {
			return fmt.Errorf("circuit SENDME digest: %w", err)
		}
		if err := c.SendRelay(RelaySendMe, 0, payload); err != nil {
			return fmt.Errorf("send circuit SENDME: %w", err)
		}
	}
	return nil
}

// SetCellReader sets an injectable cell reader (for testing).
func (c *Circuit) SetCellReader(cr CellReader) {
	c.cellReader = cr
}

// NewTestCircuit creates a Circuit suitable for testing with the given cell reader.
// It includes a Link with a discard writer so SendRelay works without a real TLS connection.
// The circuit has no crypto hops - callers that need decryption should add hops via AddHop.
func NewTestCircuit(id uint32, cr CellReader) *Circuit {
	return &Circuit{
		ID:               id,
		cellReader:       cr,
		Link:             &link.Link{Writer: cell.NewWriter(io.Discard)},
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}
}

// StreamCount returns the number of currently registered streams.
func (c *Circuit) StreamCount() int {
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	return len(c.streams)
}

// StreamIDs returns the IDs of all currently registered streams.
func (c *Circuit) StreamIDs() []uint16 {
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	ids := make([]uint16, 0, len(c.streams))
	for id := range c.streams {
		ids = append(ids, id)
	}
	return ids
}

// BackwardDigest returns the current backward digest state (for SENDME v1).
// NOTE: This must be called while the circuit mutex is NOT held (it acquires it).
// For use in flow control after receiving a relay cell.
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

// Destroy tears down the circuit: sends a DESTROY cell, closes all streams,
// releases the circuit ID, and signals circuit death. Idempotent - second call returns nil.
func (c *Circuit) Destroy() error {
	var err error
	c.destroyCallOnce.Do(func() {
		// Send DESTROY cell if Link is available.
		if c.Link != nil {
			destroy := cell.NewFixedCell(c.ID, cell.CmdDestroy)
			destroy.Payload()[0] = 0 // reason = NONE
			err = c.Link.Writer.WriteCell(destroy)
		}

		// Signal circuit death (idempotent via destroyOnce).
		c.destroy()

		// Close all stream channels so consumers unblock.
		c.cleanupAllStreams()

		// Unregister from the link's circuit dispatch table.
		if c.Link != nil {
			c.Link.UnregisterCircuit(c.ID)
		}

		// Release the circuit ID from the link's tracking.
		if c.Link != nil {
			c.Link.ReleaseCircID(c.ID)
		}
	})
	return err
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

// receiveCreated2 reads a CREATED2 response from the link circuit receiver and
// returns the 64-byte server handshake data. It returns an error if the link
// dies, times out, or sends an unexpected response.
func receiveCreated2(linkRecv *link.CircuitReceiver) ([64]byte, error) {
	var serverData [64]byte

	var resp cell.Cell
	select {
	case c, ok := <-linkRecv.Cells:
		if !ok {
			return serverData, fmt.Errorf("read CREATED2: circuit receiver channel closed")
		}
		resp = c
	case <-linkRecv.Done:
		return serverData, fmt.Errorf("read CREATED2: circuit receiver done")
	case <-time.After(30 * time.Second):
		return serverData, fmt.Errorf("read CREATED2: timeout waiting for CREATED2")
	}

	cmd := resp.Command()
	if cmd == cell.CmdDestroy {
		reason := resp.Payload()[0]
		return serverData, fmt.Errorf("relay sent DESTROY (reason=%d) instead of CREATED2", reason)
	}
	if cmd != cell.CmdCreated2 {
		return serverData, fmt.Errorf("expected CREATED2 (11), got command %d", cmd)
	}

	rp := resp.Payload()
	hlen := binary.BigEndian.Uint16(rp[0:2])
	if hlen != 64 {
		return serverData, fmt.Errorf("CREATED2 HLEN=%d, expected 64", hlen)
	}

	copy(serverData[:], rp[2:66])
	return serverData, nil
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
