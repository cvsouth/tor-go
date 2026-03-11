package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/link"
)

// fakeCellReader feeds pre-built cells to the circuit read loop.
type fakeCellReader struct {
	mu    sync.Mutex
	cells []cell.Cell
	pos   int
	err   error // returned when cells exhausted
}

func newFakeCellReader(cells ...cell.Cell) *fakeCellReader {
	return &fakeCellReader{
		cells: cells,
		err:   errors.New("no more cells"),
	}
}

func (f *fakeCellReader) ReadCell() (cell.Cell, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pos >= len(f.cells) {
		return nil, f.err
	}
	c := f.cells[f.pos]
	f.pos++
	return c, nil
}

// buildRelayCellFromRelay builds a properly encrypted relay cell that a 1-hop circuit can decrypt.
// It uses the backward cipher (kb) and backward digest (db) matching the hop.
//
// The digest computation here mirrors the production decrypt path in decryptRelayLocked:
// 1. The full 509-byte payload (with the digest field zeroed) is fed into the running Db hash.
// 2. The first 4 bytes of the resulting SHA-1 sum are placed into the digest field.
// 3. The payload is then encrypted with Kb (AES-128-CTR).
// On the client side, decryptRelayLocked reverses this: decrypt with Kb, zero the digest
// field, feed into its own Db copy, and compare the first 4 bytes. Because both sides
// start from the same Db seed and process cells in order, the running digests stay in sync.
func buildRelayCellFromRelay(circID uint32, relayCmd uint8, streamID uint16, data []byte, _ []byte, _ byte, kbEncrypt cipher.Stream, dbRelay hash.Hash) cell.Cell {
	var payload [RelayPayloadLen]byte
	payload[relayCommandOff] = relayCmd
	binary.BigEndian.PutUint16(payload[relayStreamIDOff:], streamID)
	binary.BigEndian.PutUint16(payload[relayLengthOff:], uint16(len(data)))
	copy(payload[relayDataOff:], data)

	// Compute digest
	dbRelay.Write(payload[:])
	digest := dbRelay.Sum(nil)
	copy(payload[relayDigestOff:relayDigestOff+4], digest[:4])

	// Encrypt with Kb
	kbEncrypt.XORKeyStream(payload[:], payload[:])

	relayCell := cell.NewFixedCell(circID, cell.CmdRelay)
	copy(relayCell.Payload(), payload[:])
	return relayCell
}

// testDispatchCircuit creates a Circuit with a fake cell reader and matching crypto
// for building relay cells. Returns the circuit, the kb encrypt stream, and the db relay hash.
func testDispatchCircuit(circID uint32) (*Circuit, cipher.Stream, hash.Hash) {
	kbKey := make([]byte, 16)
	for i := range kbKey {
		kbKey[i] = byte(0x20 + i)
	}
	iv := make([]byte, aes.BlockSize)

	// Relay-side encryption (kb encrypt)
	bwdEnc, _ := aes.NewCipher(kbKey)
	kbEncrypt := cipher.NewCTR(bwdEnc, iv)

	// Client-side decryption (kb decrypt)
	bwdDec, _ := aes.NewCipher(kbKey)
	kbDecrypt := cipher.NewCTR(bwdDec, iv)

	dbSeed := []byte{0xBB}
	dbRelay := sha1.New()
	dbRelay.Write(dbSeed)
	dbClient := sha1.New()
	dbClient.Write(dbSeed)

	kfKey := make([]byte, 16)
	fwdBlock, _ := aes.NewCipher(kfKey)

	hop := &Hop{
		kf: cipher.NewCTR(fwdBlock, iv),
		kb: kbDecrypt,
		df: sha1.New(),
		db: dbClient,
	}

	circ := &Circuit{
		ID:               circID,
		Link:             &link.Link{Writer: cell.NewWriter(io.Discard)},
		Hops:             []*Hop{hop},
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	return circ, kbEncrypt, dbRelay
}

func TestRegisterStream(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	sr, err := circ.RegisterStream(42)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	if sr == nil {
		t.Fatal("RegisterStream returned nil")
	}
	if cap(sr.Cells) != 64 {
		t.Fatalf("channel capacity = %d, want 64", cap(sr.Cells))
	}

	circ.streamsMu.RLock()
	stored := circ.streams[42]
	circ.streamsMu.RUnlock()
	if stored != sr {
		t.Fatal("stream not stored in dispatch table")
	}
}

func TestRegisterStreamDuplicate(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	_, err := circ.RegisterStream(42)
	if err != nil {
		t.Fatalf("first RegisterStream: %v", err)
	}

	_, err = circ.RegisterStream(42)
	if err == nil {
		t.Fatal("expected error for duplicate stream ID")
	}
}

func TestUnregisterStream(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	_, err := circ.RegisterStream(42)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.UnregisterStream(42)

	circ.streamsMu.RLock()
	_, exists := circ.streams[42]
	circ.streamsMu.RUnlock()
	if exists {
		t.Fatal("stream still in dispatch table after unregister")
	}
}

func TestUnregisterStreamSignalsDoneButNotCells(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	sr, err := circ.RegisterStream(42)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.UnregisterStream(42)

	// UnregisterStream closes sr.Done so consumers selecting on it are notified.
	select {
	case <-sr.Done:
		// expected: Done is closed
	default:
		t.Fatal("expected Done to be closed after UnregisterStream")
	}

	// UnregisterStream does NOT close sr.Cells (to avoid a race with the read loop).
	// The channel should still be open - a non-blocking receive should hit default.
	select {
	case <-sr.Cells:
		t.Fatal("unexpected receive from cells channel after unregister")
	default:
		// expected: channel is open but empty
	}
}

func TestReadLoopRoutesToCorrectStream(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Build two relay cells for different streams
	cell1 := buildRelayCellFromRelay(circID, RelayData, 10, []byte("stream-10"), nil, 0, kbEncrypt, dbRelay)
	cell2 := buildRelayCellFromRelay(circID, RelayData, 20, []byte("stream-20"), nil, 0, kbEncrypt, dbRelay)

	// After the two relay cells, send a DESTROY to terminate the read loop
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(cell1, cell2, destroyCell)
	circ.cellReader = reader

	sr10, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream(10): %v", err)
	}
	sr20, err := circ.RegisterStream(20)
	if err != nil {
		t.Fatalf("RegisterStream(20): %v", err)
	}

	circ.StartReadLoop()

	// Wait for cells to arrive
	select {
	case rc := <-sr10.Cells:
		if string(rc.Data) != "stream-10" {
			t.Fatalf("stream 10 got data %q, want %q", rc.Data, "stream-10")
		}
		if rc.Cmd != RelayData {
			t.Fatalf("stream 10 cmd = %d, want %d", rc.Cmd, RelayData)
		}
		if rc.StreamID != 10 {
			t.Fatalf("stream 10 streamID = %d, want 10", rc.StreamID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 10 cell")
	}

	select {
	case rc := <-sr20.Cells:
		if string(rc.Data) != "stream-20" {
			t.Fatalf("stream 20 got data %q, want %q", rc.Data, "stream-20")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 20 cell")
	}
}

func TestReadLoopDiscardsUnknownStreamCells(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Cell for unregistered stream 99, then a cell for registered stream 10
	cellUnknown := buildRelayCellFromRelay(circID, RelayData, 99, []byte("unknown"), nil, 0, kbEncrypt, dbRelay)
	cellKnown := buildRelayCellFromRelay(circID, RelayData, 10, []byte("known"), nil, 0, kbEncrypt, dbRelay)
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(cellUnknown, cellKnown, destroyCell)
	circ.cellReader = reader

	sr10, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream(10): %v", err)
	}

	circ.StartReadLoop()

	select {
	case rc := <-sr10.Cells:
		if string(rc.Data) != "known" {
			t.Fatalf("got data %q, want %q", rc.Data, "known")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 10 cell")
	}
}

func TestReadLoopHandlesCircuitLevelCells(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Circuit-level cell (streamID=0, SENDME)
	circuitCell := buildRelayCellFromRelay(circID, RelaySendMe, 0, nil, nil, 0, kbEncrypt, dbRelay)
	// Then a cell for stream 10
	stream10Cell := buildRelayCellFromRelay(circID, RelayData, 10, []byte("after-sendme"), nil, 0, kbEncrypt, dbRelay)
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(circuitCell, stream10Cell, destroyCell)
	circ.cellReader = reader

	sr10, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream(10): %v", err)
	}

	circ.StartReadLoop()

	// Stream 10 should still get its cell (circuit-level cell was handled, not routed)
	select {
	case rc := <-sr10.Cells:
		if string(rc.Data) != "after-sendme" {
			t.Fatalf("got data %q, want %q", rc.Data, "after-sendme")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 10 cell after circuit-level cell")
	}
}

func TestCircuitDeathClosesAllStreams(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)

	// Only a DESTROY cell
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(destroyCell)
	circ.cellReader = reader

	sr10, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream(10): %v", err)
	}
	sr20, err := circ.RegisterStream(20)
	if err != nil {
		t.Fatalf("RegisterStream(20): %v", err)
	}

	circ.StartReadLoop()

	// Both streams' done channels should close
	select {
	case <-sr10.Done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 10 done")
	}
	select {
	case <-sr20.Done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 20 done")
	}

	// Circuit done should also close
	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit done")
	}
}

func TestStartReadLoopIdempotent(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)

	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(destroyCell)
	circ.cellReader = reader

	// Call StartReadLoop multiple times - should not panic or start multiple goroutines
	circ.StartReadLoop()
	circ.StartReadLoop()
	circ.StartReadLoop()

	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit done")
	}
}

func TestRegisterStreamAfterDestroy(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	// Close done to simulate circuit death
	close(circ.done)

	_, err := circ.RegisterStream(42)
	if err == nil {
		t.Fatal("expected error registering stream on destroyed circuit")
	}
}

func TestReadLoopExitsOnDestroyCell(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)

	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(destroyCell)
	circ.cellReader = reader

	circ.StartReadLoop()

	// done channel should close when DESTROY is received
	select {
	case <-circ.done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("read loop did not exit on DESTROY cell")
	}
}

func TestCleanupAllStreamsClosesCellsChannel(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	sr, err := circ.RegisterStream(42)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.cleanupAllStreams()

	// sr.Cells should be closed by cleanupAllStreams
	select {
	case _, ok := <-sr.Cells:
		if ok {
			t.Fatal("expected cells channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("cells channel not closed after cleanupAllStreams")
	}

	// sr.Done should also be closed
	select {
	case <-sr.Done:
	case <-time.After(time.Second):
		t.Fatal("done channel not closed after cleanupAllStreams")
	}
}

func TestConcurrentRegisterUnregisterStream(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines register unique stream IDs, half unregister them.
	for i := 0; i < goroutines; i++ {
		id := uint16(i + 1)
		go func() {
			defer wg.Done()
			_, _ = circ.RegisterStream(id)
		}()
		go func() {
			defer wg.Done()
			circ.UnregisterStream(id)
		}()
	}

	wg.Wait()

	// No panic or race detected = success.
	// Also verify: registering after all goroutines finish should work for any freed ID.
	_, err := circ.RegisterStream(9999)
	if err != nil {
		t.Fatalf("RegisterStream after concurrent ops: %v", err)
	}
}

func TestExtendAfterStartReadLoopFails(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)

	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0
	reader := newFakeCellReader(destroyCell)
	circ.cellReader = reader

	circ.StartReadLoop()

	// Extend should return an error because the read loop is running.
	info := &descriptor.RelayInfo{Address: "1.2.3.4", ORPort: 9001}
	err := circ.Extend(info, nil)
	if err == nil {
		t.Fatal("expected error calling Extend after StartReadLoop")
	}
	if !strings.Contains(err.Error(), "StartReadLoop") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCircuitLevelSendMeFromReadLoop(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Build 100 DATA cells to trigger circuit-level SENDME, then DESTROY
	var cells []cell.Cell
	for i := 0; i < 100; i++ {
		c := buildRelayCellFromRelay(circID, RelayData, 10, []byte("x"), nil, 0, kbEncrypt, dbRelay)
		cells = append(cells, c)
	}
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0
	cells = append(cells, destroyCell)

	reader := newFakeCellReader(cells...)
	circ.cellReader = reader

	sr10, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream(10): %v", err)
	}

	circ.StartReadLoop()

	// Drain all 100 cells from the stream
	for i := 0; i < 100; i++ {
		select {
		case <-sr10.Cells:
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for cell %d", i)
		}
	}

	// Wait for circuit to finish
	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit done")
	}

	// Verify circuit-level data counter was reset (SENDME was sent)
	circ.streamsMu.RLock()
	count := circ.circDataReceived
	circ.streamsMu.RUnlock()
	if count != 0 {
		t.Fatalf("circDataReceived = %d, want 0 (circuit SENDME should have been sent)", count)
	}
}

func TestCircuitLevelSendMeWindowIncrement(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Send a circuit-level SENDME (streamID=0) to the circuit
	sendmeCell := buildRelayCellFromRelay(circID, RelaySendMe, 0, nil, nil, 0, kbEncrypt, dbRelay)
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(sendmeCell, destroyCell)
	circ.cellReader = reader

	circ.StartReadLoop()

	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit done")
	}

	// handleCircuitCell should have incremented circWindow by 100
	circ.streamsMu.RLock()
	w := circ.circWindow
	circ.streamsMu.RUnlock()
	if w != initCircWindow+circSendMeWindow {
		t.Fatalf("circWindow = %d, want %d", w, initCircWindow+circSendMeWindow)
	}
}

func TestDigestCapturedUnderLock(t *testing.T) {
	// Verify that RelayCell.Digest is populated by receiveRelay under the read lock,
	// not by a separate BackwardDigest() call after releasing the lock.
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	dataCell := buildRelayCellFromRelay(circID, RelayData, 10, []byte("test"), nil, 0, kbEncrypt, dbRelay)
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0

	reader := newFakeCellReader(dataCell, destroyCell)
	circ.cellReader = reader

	sr10, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream(10): %v", err)
	}

	circ.StartReadLoop()

	select {
	case rc := <-sr10.Cells:
		if rc.Digest == nil {
			t.Fatal("RelayCell.Digest is nil - digest not captured from receiveRelay")
		}
		if len(rc.Digest) != 20 {
			t.Fatalf("digest length = %d, want 20 (SHA-1)", len(rc.Digest))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for cell")
	}
}

func TestHandleCircuitDataReceivedTOCTOU(t *testing.T) {
	// Verify that the counter is reset atomically with the threshold check.
	// After exactly circSendMeWindow DATA cells, circDataReceived should be 0.
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Build exactly circSendMeWindow DATA cells
	var cells []cell.Cell
	for i := 0; i < circSendMeWindow; i++ {
		c := buildRelayCellFromRelay(circID, RelayData, 10, []byte("x"), nil, 0, kbEncrypt, dbRelay)
		cells = append(cells, c)
	}
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0
	cells = append(cells, destroyCell)

	reader := newFakeCellReader(cells...)
	circ.cellReader = reader

	sr, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.StartReadLoop()

	// Drain all cells
	for i := 0; i < circSendMeWindow; i++ {
		select {
		case <-sr.Cells:
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for cell %d", i)
		}
	}

	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit done")
	}

	circ.streamsMu.RLock()
	count := circ.circDataReceived
	circ.streamsMu.RUnlock()
	if count != 0 {
		t.Fatalf("circDataReceived = %d, want 0 after SENDME threshold", count)
	}
}

func TestTryDecrementCircuitWindowSuccess(t *testing.T) {
	circ := &Circuit{
		ID:               0x80000001,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       5,
		circWindowSignal: make(chan struct{}, 1),
	}

	for i := 0; i < 5; i++ {
		if !circ.TryDecrementCircuitWindow() {
			t.Fatalf("TryDecrementCircuitWindow returned false at iteration %d", i)
		}
	}

	// Window is now 0 - should return false
	if circ.TryDecrementCircuitWindow() {
		t.Fatal("TryDecrementCircuitWindow should return false when window is 0")
	}

	// Verify window is exactly 0, not negative
	w := circ.CircuitWindow()
	if w != 0 {
		t.Fatalf("circWindow = %d, want 0", w)
	}
}

func TestTryDecrementCircuitWindowConcurrent(t *testing.T) {
	const initialWindow = 100
	circ := &Circuit{
		ID:               0x80000001,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initialWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	// Run 200 goroutines trying to decrement - only 100 should succeed
	const goroutines = 200
	results := make(chan bool, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			results <- circ.TryDecrementCircuitWindow()
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != initialWindow {
		t.Fatalf("expected %d successful decrements, got %d", initialWindow, successes)
	}
	if w := circ.CircuitWindow(); w != 0 {
		t.Fatalf("circWindow = %d, want 0", w)
	}
}

func TestReadLoopDropsCellForFullStream(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Build enough relay cells to fill the 64-capacity channel, plus one more
	var cells []cell.Cell
	for i := 0; i < 66; i++ {
		c := buildRelayCellFromRelay(circID, RelayData, 10, []byte("x"), nil, 0, kbEncrypt, dbRelay)
		cells = append(cells, c)
	}
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0
	cells = append(cells, destroyCell)

	reader := newFakeCellReader(cells...)
	circ.cellReader = reader

	sr, err := circ.RegisterStream(10)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	// Close the stream's done channel to simulate a stream that stopped reading.
	sr.closeDone()

	circ.StartReadLoop()

	// The read loop should not block forever - it should finish after DESTROY.
	select {
	case <-circ.done:
		// success: read loop exited without blocking on the full channel
	case <-time.After(5 * time.Second):
		t.Fatal("read loop blocked on full stream channel")
	}
}
