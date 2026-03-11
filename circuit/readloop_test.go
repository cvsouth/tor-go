package circuit

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
)

// channelCellReader reads cells from a channel, allowing dynamic test scenarios.
type channelCellReader struct {
	ch chan cell.Cell
}

func newChannelReader() *channelCellReader {
	return &channelCellReader{ch: make(chan cell.Cell, 256)}
}

func (c *channelCellReader) ReadCell() (cell.Cell, error) {
	cl, ok := <-c.ch
	if !ok {
		return nil, io.EOF
	}
	return cl, nil
}

func TestConcurrent10Streams100Cells(t *testing.T) {
	const circID = uint32(0x80000001)
	const numStreams = 10
	const cellsPerStream = 100

	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)
	reader := newChannelReader()
	circ.cellReader = reader

	// Register all streams before starting read loop
	receivers := make(map[uint16]*StreamReceiver)
	for i := uint16(1); i <= numStreams; i++ {
		sr, err := circ.RegisterStream(i)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", i, err)
		}
		receivers[i] = sr
	}

	circ.StartReadLoop()

	// Feed cells interleaved from a background goroutine
	go func() {
		for cellIdx := 0; cellIdx < cellsPerStream; cellIdx++ {
			for streamID := uint16(1); streamID <= numStreams; streamID++ {
				data := []byte(fmt.Sprintf("s%d-c%d", streamID, cellIdx))
				c := buildRelayCellFromRelay(circID, RelayData, streamID, data, nil, 0, kbEncrypt, dbRelay)
				reader.ch <- c
			}
		}
		// Terminate the read loop
		destroy := cell.NewFixedCell(circID, cell.CmdDestroy)
		destroy.Payload()[0] = 0
		reader.ch <- destroy
	}()

	// Concurrently read from all streams
	var wg sync.WaitGroup
	wg.Add(numStreams)
	for streamID := uint16(1); streamID <= numStreams; streamID++ {
		go func(sid uint16) {
			defer wg.Done()
			sr := receivers[sid]
			for cellIdx := 0; cellIdx < cellsPerStream; cellIdx++ {
				expected := fmt.Sprintf("s%d-c%d", sid, cellIdx)
				select {
				case rc, ok := <-sr.Cells:
					if !ok {
						t.Errorf("stream %d: channel closed after %d cells", sid, cellIdx)
						return
					}
					if string(rc.Data) != expected {
						t.Errorf("stream %d cell %d: got %q, want %q", sid, cellIdx, rc.Data, expected)
						return
					}
				case <-time.After(5 * time.Second):
					t.Errorf("stream %d: timeout at cell %d", sid, cellIdx)
					return
				}
			}
		}(streamID)
	}
	wg.Wait()
}

func TestStreamOpenCloseChurn(t *testing.T) {
	const circID = uint32(0x80000001)
	const longLivedStreams = 5
	const churnStreams = 50
	const cellsPerLongLived = 20

	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)
	reader := newChannelReader()
	circ.cellReader = reader

	// Register long-lived streams
	longReceivers := make([]*StreamReceiver, longLivedStreams)
	for i := 0; i < longLivedStreams; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		longReceivers[i] = sr
	}

	circ.StartReadLoop()

	// Background: rapidly open and close churn streams
	var churnWg sync.WaitGroup
	churnWg.Add(churnStreams)
	for i := 0; i < churnStreams; i++ {
		go func(idx int) {
			defer churnWg.Done()
			sid := uint16(100 + idx)
			sr, err := circ.RegisterStream(sid)
			if err != nil {
				return // circuit might be dead
			}
			_ = sr
			circ.UnregisterStream(sid)
		}(i)
	}

	// Feed cells for long-lived streams
	go func() {
		for cellIdx := 0; cellIdx < cellsPerLongLived; cellIdx++ {
			for sid := uint16(1); sid <= longLivedStreams; sid++ {
				data := []byte(fmt.Sprintf("ll-%d-%d", sid, cellIdx))
				c := buildRelayCellFromRelay(circID, RelayData, sid, data, nil, 0, kbEncrypt, dbRelay)
				reader.ch <- c
			}
		}
		// Wait for churn to finish, then terminate
		churnWg.Wait()
		destroy := cell.NewFixedCell(circID, cell.CmdDestroy)
		destroy.Payload()[0] = 0
		reader.ch <- destroy
	}()

	// Verify long-lived streams receive all their cells
	var llWg sync.WaitGroup
	llWg.Add(longLivedStreams)
	for i := 0; i < longLivedStreams; i++ {
		go func(idx int) {
			defer llWg.Done()
			sr := longReceivers[idx]
			sid := uint16(idx + 1)
			for cellIdx := 0; cellIdx < cellsPerLongLived; cellIdx++ {
				expected := fmt.Sprintf("ll-%d-%d", sid, cellIdx)
				select {
				case rc, ok := <-sr.Cells:
					if !ok {
						t.Errorf("long-lived stream %d: channel closed at cell %d", sid, cellIdx)
						return
					}
					if string(rc.Data) != expected {
						t.Errorf("long-lived stream %d cell %d: got %q, want %q", sid, cellIdx, rc.Data, expected)
						return
					}
				case <-time.After(5 * time.Second):
					t.Errorf("long-lived stream %d: timeout at cell %d", sid, cellIdx)
					return
				}
			}
		}(i)
	}
	llWg.Wait()
	churnWg.Wait()
}

func TestCircuitDeathDuringConcurrentIO(t *testing.T) {
	const circID = uint32(0x80000001)
	const numStreams = 5

	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)
	reader := newChannelReader()
	circ.cellReader = reader

	receivers := make([]*StreamReceiver, numStreams)
	for i := 0; i < numStreams; i++ {
		sr, err := circ.RegisterStream(uint16(i + 1))
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", i+1, err)
		}
		receivers[i] = sr
	}

	circ.StartReadLoop()

	// Start goroutines reading from all streams
	var wg sync.WaitGroup
	wg.Add(numStreams)
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			sr := receivers[idx]
			for {
				select {
				case _, ok := <-sr.Cells:
					if !ok {
						return
					}
				case <-sr.Done:
					return
				}
			}
		}(i)
	}

	// Feed some cells, then kill the circuit
	for j := 0; j < 10; j++ {
		for sid := uint16(1); sid <= numStreams; sid++ {
			c := buildRelayCellFromRelay(circID, RelayData, sid, []byte("data"), nil, 0, kbEncrypt, dbRelay)
			reader.ch <- c
		}
	}
	close(reader.ch) // kill the circuit

	// All goroutines must exit within 5s
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("goroutines did not exit within 5s after circuit death")
	}
}

func TestReadLoopBackpressure(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)
	reader := newChannelReader()
	circ.cellReader = reader

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.StartReadLoop()

	// Register a second stream before filling to use as sync marker
	sr2, err := circ.RegisterStream(2)
	if err != nil {
		t.Fatalf("RegisterStream(2): %v", err)
	}

	// Fill the 64-capacity channel by sending 64 cells
	for i := 0; i < 64; i++ {
		c := buildRelayCellFromRelay(circID, RelayData, 1, []byte(fmt.Sprintf("cell-%d", i)), nil, 0, kbEncrypt, dbRelay)
		reader.ch <- c
	}

	// Send a cell for stream 2 - it will only be dispatched after all 64
	// stream-1 cells have been processed by the read loop (sequential dispatch).
	// The read loop may block trying to send to stream 1's full channel,
	// so we drain stream 1 first from a goroutine.
	c2 := buildRelayCellFromRelay(circID, RelayData, 2, []byte("stream2"), nil, 0, kbEncrypt, dbRelay)
	reader.ch <- c2

	// Drain stream 1 to unblock the read loop (it may be blocked on full channel)
	for i := 0; i < 64; i++ {
		select {
		case <-sr.Cells:
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout draining stream 1 at cell %d", i)
		}
	}

	// Now stream 2 should get its cell - proves read loop wasn't permanently blocked
	select {
	case rc := <-sr2.Cells:
		if string(rc.Data) != "stream2" {
			t.Fatalf("stream 2 got %q, want %q", rc.Data, "stream2")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for stream 2 cell")
	}

	// Clean up
	close(reader.ch)
}

func TestNoGoroutineLeaks(t *testing.T) {
	// Allow background goroutines to settle
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)
	reader := newChannelReader()
	circ.cellReader = reader

	// Open 20 streams
	for i := uint16(1); i <= 20; i++ {
		_, err := circ.RegisterStream(i)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", i, err)
		}
	}

	circ.StartReadLoop()

	// Close all 20 streams
	for i := uint16(1); i <= 20; i++ {
		circ.UnregisterStream(i)
	}

	// Destroy the circuit
	close(reader.ch)

	// Wait for circuit done
	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("circuit did not die")
	}

	// Wait for goroutine count to stabilize
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		current := runtime.NumGoroutine()
		// Allow some slack (test framework goroutines, etc.)
		if current <= baseline+2 {
			return // success
		}
	}
	t.Fatalf("goroutine leak: baseline=%d, current=%d", baseline, runtime.NumGoroutine())
}

func TestConcurrentRegisterUnregister(t *testing.T) {
	circ := &Circuit{
		ID:      0x80000001,
		streams: make(map[uint16]*StreamReceiver),
		done:    make(chan struct{}),
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			// Each goroutine registers and unregisters multiple IDs
			for j := 0; j < 10; j++ {
				sid := uint16((idx*10 + j) % 200)
				if sid == 0 {
					sid = 1
				}
				_, _ = circ.RegisterStream(sid)
				circ.UnregisterStream(sid)
			}
		}(i)
	}

	wg.Wait()
	// No panic or race = success
}

func TestReadLoopHandlesPaddingCells(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)
	reader := newChannelReader()
	circ.cellReader = reader

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.StartReadLoop()

	// Interleave PADDING cells with RELAY cells
	padding1 := cell.NewFixedCell(circID, cell.CmdPadding)
	relay1 := buildRelayCellFromRelay(circID, RelayData, 1, []byte("first"), nil, 0, kbEncrypt, dbRelay)
	padding2 := cell.NewFixedCell(circID, cell.CmdPadding)
	padding3 := cell.NewFixedCell(circID, cell.CmdPadding)
	relay2 := buildRelayCellFromRelay(circID, RelayData, 1, []byte("second"), nil, 0, kbEncrypt, dbRelay)

	reader.ch <- padding1
	reader.ch <- relay1
	reader.ch <- padding2
	reader.ch <- padding3
	reader.ch <- relay2

	destroy := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroy.Payload()[0] = 0
	reader.ch <- destroy

	// Verify only RELAY cells are delivered
	select {
	case rc := <-sr.Cells:
		if string(rc.Data) != "first" {
			t.Fatalf("got %q, want %q", rc.Data, "first")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first relay cell")
	}

	select {
	case rc := <-sr.Cells:
		if string(rc.Data) != "second" {
			t.Fatalf("got %q, want %q", rc.Data, "second")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for second relay cell")
	}
}

func TestStreamReadWriteAfterCircuitDeath(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)

	// Use a blocking reader that we can kill
	blockReader := &blockingCellReaderWithUnblock{
		unblock: make(chan struct{}),
	}
	circ.cellReader = blockReader

	_, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.StartReadLoop()

	// Kill the circuit
	close(blockReader.unblock)

	// Wait for circuit death
	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("circuit did not die")
	}

	// RegisterStream should fail after death
	_, err = circ.RegisterStream(99)
	if err == nil {
		t.Fatal("expected error registering stream after circuit death")
	}

	// SendRelay may succeed (writes to io.Discard) or fail - either is fine.
	// The key assertion is that it completes without hanging.
	_ = circ.SendRelay(RelayData, 1, []byte("test"))
}

type blockingCellReaderWithUnblock struct {
	unblock chan struct{}
}

func (b *blockingCellReaderWithUnblock) ReadCell() (cell.Cell, error) {
	<-b.unblock
	return nil, errors.New("connection closed")
}

// signalingCellReader wraps a channel reader and signals when ReadCell is called.
type signalingCellReader struct {
	ch         chan cell.Cell
	readCalled chan struct{} // signaled (once) on first ReadCell call
	once       sync.Once
}

func (s *signalingCellReader) ReadCell() (cell.Cell, error) {
	s.once.Do(func() {
		s.readCalled <- struct{}{}
	})
	c, ok := <-s.ch
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

// --- Fix 1: receiveRelay does not hold rmu while blocking on ReadCell ---

// slowCellReader blocks for a configurable duration before returning a cell,
// and tracks whether rmu is held by trying to lock it (non-blocking).
type slowCellReader struct {
	ch        chan cell.Cell
	rmu       *sync.Mutex // pointer to circuit's rmu
	wasLocked bool        // set to true if rmu was held during ReadCell
	mu        sync.Mutex  // protects wasLocked
}

func (s *slowCellReader) ReadCell() (cell.Cell, error) {
	// Try to lock rmu - if we succeed, it was NOT held by the caller.
	// If we can't lock, the caller is holding it (the bug we're testing for).
	locked := s.rmu.TryLock()
	if locked {
		s.rmu.Unlock()
	} else {
		s.mu.Lock()
		s.wasLocked = true
		s.mu.Unlock()
	}

	c, ok := <-s.ch
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}

func TestReceiveRelayDoesNotHoldRmuDuringReadCell(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	reader := &slowCellReader{
		ch:  make(chan cell.Cell, 16),
		rmu: &circ.rmu,
	}
	circ.cellReader = reader

	// Feed a relay cell followed by a DESTROY
	dataCell := buildRelayCellFromRelay(circID, RelayData, 1, []byte("test"), nil, 0, kbEncrypt, dbRelay)
	reader.ch <- dataCell
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0
	reader.ch <- destroyCell

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	circ.StartReadLoop()

	select {
	case <-sr.Cells:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for cell")
	}

	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit done")
	}

	reader.mu.Lock()
	wasLocked := reader.wasLocked
	reader.mu.Unlock()
	if wasLocked {
		t.Fatal("rmu was held during ReadCell - receiveRelay should not hold rmu while blocking")
	}
}

// --- Fix 3: ReceiveRelaySetup / StartReadLoop TOCTOU race ---

func TestReceiveRelaySetupBlocksStartReadLoop(t *testing.T) {
	// Verify that StartReadLoop waits for in-flight ReceiveRelaySetup calls to complete.
	const circID = uint32(0x80000001)
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Use a signaling reader that notifies us when ReadCell is called
	sigReader := &signalingCellReader{
		ch:         make(chan cell.Cell, 16),
		readCalled: make(chan struct{}, 1),
	}
	circ.cellReader = sigReader

	// Start ReceiveRelaySetup in a goroutine - it will block waiting for a cell
	setupDone := make(chan struct{})
	go func() {
		defer close(setupDone)
		_, _, _, _, _ = circ.ReceiveRelaySetup()
	}()

	// Wait for ReceiveRelaySetup to actually call ReadCell (proves it's in-flight)
	select {
	case <-sigReader.readCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("ReceiveRelaySetup did not call ReadCell")
	}

	// Now call StartReadLoop - it should wait for ReceiveRelaySetup to finish
	readLoopStarted := make(chan struct{})
	go func() {
		circ.StartReadLoop()
		close(readLoopStarted)
	}()

	// Feed a cell to unblock ReceiveRelaySetup
	dataCell := buildRelayCellFromRelay(circID, RelayData, 0, []byte("setup"), nil, 0, kbEncrypt, dbRelay)
	sigReader.ch <- dataCell

	// ReceiveRelaySetup should complete
	select {
	case <-setupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ReceiveRelaySetup did not complete")
	}

	// StartReadLoop should proceed after setup completes
	select {
	case <-readLoopStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("StartReadLoop did not start after ReceiveRelaySetup completed")
	}

	// Clean up: send DESTROY to stop the read loop
	destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
	destroyCell.Payload()[0] = 0
	sigReader.ch <- destroyCell

	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("circuit did not die")
	}
}

func TestReceiveRelaySetupAfterStartReadLoopFails(t *testing.T) {
	const circID = uint32(0x80000001)
	circ, _, _ := testDispatchCircuit(circID)

	blockReader := &blockingCellReaderWithUnblock{
		unblock: make(chan struct{}),
	}
	circ.cellReader = blockReader

	circ.StartReadLoop()

	_, _, _, _, err := circ.ReceiveRelaySetup()
	if err == nil {
		t.Fatal("expected error calling ReceiveRelaySetup after StartReadLoop")
	}

	close(blockReader.unblock)
	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("circuit did not die")
	}
}

func TestConcurrentReceiveRelaySetupAndStartReadLoop(t *testing.T) {
	// Race test: call ReceiveRelaySetup and StartReadLoop concurrently.
	// Neither should panic, and the circuit should eventually die cleanly.
	const circID = uint32(0x80000001)

	for i := 0; i < 20; i++ {
		circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)
		reader := newChannelReader()
		circ.cellReader = reader

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, _, _, _, _ = circ.ReceiveRelaySetup()
		}()

		go func() {
			defer wg.Done()
			// Small jitter to increase race likelihood
			runtime.Gosched()
			circ.StartReadLoop()
		}()

		// Feed cells to unblock any readers
		dataCell := buildRelayCellFromRelay(circID, RelayData, 0, []byte("x"), nil, 0, kbEncrypt, dbRelay)
		reader.ch <- dataCell

		destroyCell := cell.NewFixedCell(circID, cell.CmdDestroy)
		destroyCell.Payload()[0] = 0
		reader.ch <- destroyCell

		wg.Wait()

		select {
		case <-circ.done:
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: circuit did not die", i)
		}
	}
}
