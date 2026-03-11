package link

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
)

// TestMultiCircuitMultiStream verifies that 3 circuits on one link, each with 5
// conceptual "streams" (represented by unique payload tags), all receive exactly
// their cells when interleaved. This tests the link-level routing by circID.
//
// The link read loop routes raw cells by circID to CircuitReceiver channels.
// Each circuit's goroutine reads from its channel and verifies correct delivery.
func TestMultiCircuitMultiStream(t *testing.T) {
	l, pw := pipeLink(t)

	const numCircuits = 3
	const streamsPerCircuit = 5
	const cellsPerStream = 20

	// Register circuits.
	type circEntry struct {
		circID uint32
		cr     *CircuitReceiver
	}
	circuits := make([]circEntry, numCircuits)
	for i := 0; i < numCircuits; i++ {
		circID := uint32(0x80000001 + i)
		cr, err := l.RegisterCircuit(circID)
		if err != nil {
			t.Fatalf("RegisterCircuit(0x%08x): %v", circID, err)
		}
		circuits[i] = circEntry{circID: circID, cr: cr}
	}

	l.StartReadLoop()

	// Background feeder: write interleaved cells for all circuits and streams.
	// Each cell encodes its circuit index, stream index, and cell index in the payload.
	go func() {
		for cellIdx := 0; cellIdx < cellsPerStream; cellIdx++ {
			for ci := 0; ci < numCircuits; ci++ {
				for si := 0; si < streamsPerCircuit; si++ {
					circID := uint32(0x80000001 + ci)
					c := cell.NewFixedCell(circID, cell.CmdRelay)
					p := c.Payload()
					p[0] = byte(ci)      // circuit index
					p[1] = byte(si)      // stream index
					p[2] = byte(cellIdx) // cell index
					writeCells(pw, c)
				}
			}
		}
		_ = pw.Close()
	}()

	// Each circuit goroutine reads all its cells and verifies correctness.
	var wg sync.WaitGroup
	wg.Add(numCircuits)
	for ci := 0; ci < numCircuits; ci++ {
		go func(circIdx int) {
			defer wg.Done()
			verifyCircuitCells(t, circuits[circIdx].cr, circIdx, streamsPerCircuit, cellsPerStream)
		}(ci)
	}

	wg.Wait()

	// Link should die after pipe close.
	select {
	case <-l.done:
	case <-time.After(5 * time.Second):
		t.Fatal("link did not die after pipe close")
	}
}

// TestOneCircuitDiesOthersContinue verifies that when one circuit receives a
// DESTROY cell, it is delivered to that circuit's channel, while the other
// circuits continue to receive their cells unaffected.
func TestOneCircuitDiesOthersContinue(t *testing.T) {
	l, pw := pipeLink(t)

	cr1, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit(1): %v", err)
	}
	cr2, err := l.RegisterCircuit(0x80000002)
	if err != nil {
		t.Fatalf("RegisterCircuit(2): %v", err)
	}
	cr3, err := l.RegisterCircuit(0x80000003)
	if err != nil {
		t.Fatalf("RegisterCircuit(3): %v", err)
	}

	l.StartReadLoop()

	// Use a channel to synchronize: the feeder writes the first batch, waits for
	// the test to consume the DESTROY from circuit 2, then continues.
	destroyConsumed := make(chan struct{})

	go func() {
		// First round: all circuits get a relay cell.
		c1 := cell.NewFixedCell(0x80000001, cell.CmdRelay)
		c1.Payload()[0] = 0x11
		c2 := cell.NewFixedCell(0x80000002, cell.CmdRelay)
		c2.Payload()[0] = 0x22
		c3 := cell.NewFixedCell(0x80000003, cell.CmdRelay)
		c3.Payload()[0] = 0x33
		writeCells(pw, c1, c2, c3)

		// DESTROY for circuit 2.
		destroy := cell.NewFixedCell(0x80000002, cell.CmdDestroy)
		destroy.Payload()[0] = 5 // reason
		writeCells(pw, destroy)

		// Wait for the test to consume the DESTROY before unregistering,
		// otherwise UnregisterCircuit closes Done and the read loop discards
		// the DESTROY via the cr.Done select case.
		<-destroyConsumed
		l.UnregisterCircuit(0x80000002)

		// More cells for circuits 1 and 3.
		c1b := cell.NewFixedCell(0x80000001, cell.CmdRelay)
		c1b.Payload()[0] = 0x12
		c3b := cell.NewFixedCell(0x80000003, cell.CmdRelay)
		c3b.Payload()[0] = 0x34
		writeCells(pw, c1b, c3b)

		_ = pw.Close()
	}()

	// Circuit 2 should receive its relay cell and then the DESTROY.
	select {
	case c := <-cr2.Cells:
		if c.Payload()[0] != 0x22 {
			t.Fatalf("circuit 2 first cell: payload[0] = %02x, want 22", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 2 first cell")
	}

	select {
	case c := <-cr2.Cells:
		if c.Command() != cell.CmdDestroy {
			t.Fatalf("circuit 2 expected DESTROY, got command %d", c.Command())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 2 DESTROY")
	}

	// Signal the feeder that we've consumed the DESTROY.
	close(destroyConsumed)

	// Circuit 2's Done should be closed after unregister.
	select {
	case <-cr2.Done:
	case <-time.After(2 * time.Second):
		t.Fatal("circuit 2 Done not closed after DESTROY + unregister")
	}

	// Circuit 1 should get both its cells.
	assertCellSequence(t, "circuit 1", cr1.Cells, 0x11, 0x12)

	// Circuit 3 should get both its cells.
	assertCellSequence(t, "circuit 3", cr3.Cells, 0x33, 0x34)
}

// verifyCircuitCells reads all cells for a circuit and verifies correct routing and ordering.
// Payload layout: [circuitIdx, streamIdx, cellIdx].
func verifyCircuitCells(t *testing.T, cr *CircuitReceiver, circIdx, streamsPerCircuit, cellsPerStream int) {
	t.Helper()
	expected := streamsPerCircuit * cellsPerStream
	received := 0
	streamCounts := make(map[byte]int)

	for received < expected {
		select {
		case c := <-cr.Cells:
			if c.Payload()[0] != byte(circIdx) {
				t.Errorf("circuit %d got cell with circuit index %d", circIdx, c.Payload()[0])
				return
			}
			si := c.Payload()[1]
			cellIdx := int(c.Payload()[2])
			if cellIdx != streamCounts[si] {
				t.Errorf("circuit %d stream %d: got cell %d, want %d", circIdx, si, cellIdx, streamCounts[si])
				return
			}
			streamCounts[si]++
			received++
		case <-time.After(5 * time.Second):
			t.Errorf("circuit %d: timeout at cell %d/%d", circIdx, received, expected)
			return
		}
	}

	for si := 0; si < streamsPerCircuit; si++ {
		if streamCounts[byte(si)] != cellsPerStream {
			t.Errorf("circuit %d stream %d: got %d cells, want %d", circIdx, si, streamCounts[byte(si)], cellsPerStream)
		}
	}
}

// assertCellSequence reads cells from ch and asserts each has the given payload[0] values in order.
func assertCellSequence(t *testing.T, name string, ch <-chan cell.Cell, expected ...byte) {
	t.Helper()
	for _, exp := range expected {
		select {
		case c := <-ch:
			if c.Payload()[0] != exp {
				t.Fatalf("%s: payload[0] = %02x, want %02x", name, c.Payload()[0], exp)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for %s cell %02x", name, exp)
		}
	}
}

// drainCircuitCells reads cells from cr.Cells in order until linkDone fires or
// the channel is closed, verifying payload[0] matches the sequential index.
// Returns the total number of cells received.
func drainCircuitCells(t *testing.T, cr *CircuitReceiver, linkDone <-chan struct{}, expectedCells int) int {
	t.Helper()
	received := 0
	for {
		select {
		case c, ok := <-cr.Cells:
			if !ok {
				return received
			}
			if c.Payload()[0] != byte(received) {
				t.Fatalf("cell %d: payload[0] = %d, want %d", received, c.Payload()[0], received)
			}
			received++
			if received == expectedCells {
				return received
			}
		case <-linkDone:
			// Drain remaining buffered cells.
			for {
				select {
				case c, ok := <-cr.Cells:
					if !ok {
						return received
					}
					if c.Payload()[0] != byte(received) {
						t.Fatalf("cell %d: payload[0] = %d, want %d", received, c.Payload()[0], received)
					}
					received++
				default:
					return received
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout after receiving %d cells", received)
			return received
		}
	}
}

// TestLinkDeathClosesAllCircuitsAndStreams verifies that when the link
// dies (pipe closes), ALL registered circuits have both their Done and Cells
// channels closed, so any consumers blocking on either are unblocked.
func TestLinkDeathClosesAllCircuitsAndStreams(t *testing.T) {
	l, pw := pipeLink(t)

	const numCircuits = 5
	receivers := make([]*CircuitReceiver, numCircuits)
	for i := 0; i < numCircuits; i++ {
		circID := uint32(0x80000001 + i)
		cr, err := l.RegisterCircuit(circID)
		if err != nil {
			t.Fatalf("RegisterCircuit(0x%08x): %v", circID, err)
		}
		receivers[i] = cr
	}

	l.StartReadLoop()

	// Kill the link.
	_ = pw.Close()

	// All circuits' Done channels should close.
	for i, cr := range receivers {
		select {
		case <-cr.Done:
		case <-time.After(2 * time.Second):
			t.Fatalf("circuit %d Done not closed after link death", i)
		}
	}

	// All circuits' Cells channels should also be closed.
	for i, cr := range receivers {
		select {
		case _, ok := <-cr.Cells:
			if ok {
				// Might have received a cell before close - drain and check again.
				select {
				case _, ok2 := <-cr.Cells:
					if ok2 {
						t.Fatalf("circuit %d Cells channel still open after link death", i)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("circuit %d Cells channel not closed after link death (second read)", i)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("circuit %d Cells channel not closed after link death", i)
		}
	}

	// Link done should be closed.
	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
		t.Fatal("link done not closed")
	}
}

// TestNoGoroutineLeaksLinkLevel creates and destroys multiple circuits on a link,
// verifying that goroutine count returns to a stable baseline.
func TestNoGoroutineLeaksLinkLevel(t *testing.T) {
	// Warm up: run one full cycle to stabilize runtime goroutines.
	func() {
		warmL, warmPW := pipeLink(t)
		_, _ = warmL.RegisterCircuit(0x80000001)
		warmL.StartReadLoop()
		_ = warmPW.Close()
		<-warmL.done
	}()

	// Wait for goroutine count to stabilize (two consecutive reads return the
	// same value) rather than relying on a fixed sleep.
	runtime.GC()
	prev := runtime.NumGoroutine()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		cur := runtime.NumGoroutine()
		if cur == prev {
			break
		}
		prev = cur
	}
	baseline := prev

	const iterations = 5
	for iter := 0; iter < iterations; iter++ {
		l, pw := pipeLink(t)

		for i := 0; i < 5; i++ {
			circID := uint32(0x80000001 + i)
			_, err := l.RegisterCircuit(circID)
			if err != nil {
				t.Fatalf("iter %d: RegisterCircuit(0x%08x): %v", iter, circID, err)
			}
		}

		l.StartReadLoop()

		// Send a few cells then close.
		go func() {
			for i := 0; i < 5; i++ {
				circID := uint32(0x80000001 + i)
				c := cell.NewFixedCell(circID, cell.CmdRelay)
				writeCells(pw, c)
			}
			_ = pw.Close()
		}()

		// Wait for link death.
		select {
		case <-l.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iter %d: link did not die", iter)
		}
	}

	// Poll for goroutines to wind down, retrying for up to ~2 seconds.
	for range 20 {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	final := runtime.NumGoroutine()
	t.Fatalf("goroutine leak: baseline=%d, final=%d (delta=%d)", baseline, final, final-baseline)
}

// TestBackpressureLinkToCircuitToStream verifies that when a circuit's channel is full,
// the link read loop blocks on the send (backpressure) rather than dropping cells.
// Once the channel is drained, delivery resumes normally.
func TestBackpressureLinkToCircuitToStream(t *testing.T) {
	l, pw := pipeLink(t)

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	l.StartReadLoop()

	// The CircuitReceiver channel has capacity 32.
	// Fill it with 32 cells, then send one more that should block.
	const chanCap = 32
	const expectedCells = chanCap + 5

	// Write all cells from a goroutine.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for i := 0; i < expectedCells; i++ {
			c := cell.NewFixedCell(0x80000001, cell.CmdRelay)
			c.Payload()[0] = byte(i)
			writeCells(pw, c)
		}
		_ = pw.Close()
	}()

	// Drain all cells. The read loop applies backpressure when the channel is
	// full and resumes delivery once space is available.
	received := drainCircuitCells(t, cr, l.done, expectedCells)
	if received != expectedCells {
		t.Fatalf("received %d cells, want %d (backpressure dropped cells)", received, expectedCells)
	}

	// Wait for writer to finish.
	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not finish")
	}
}

// TestConcurrentCircuitRegistrationDuringReadLoop verifies that circuits can be
// registered and unregistered while the read loop is actively running, without
// races or missed cells.
func TestConcurrentCircuitRegistrationDuringReadLoop(t *testing.T) {
	l, pw := pipeLink(t)

	// Pre-register one circuit.
	cr1, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit(1): %v", err)
	}

	l.StartReadLoop()

	// Register a second circuit while the read loop is running.
	cr2, err := l.RegisterCircuit(0x80000002)
	if err != nil {
		t.Fatalf("RegisterCircuit(2) during read loop: %v", err)
	}

	// Send cells for both circuits.
	go func() {
		c1 := cell.NewFixedCell(0x80000001, cell.CmdRelay)
		c1.Payload()[0] = 0xAA
		c2 := cell.NewFixedCell(0x80000002, cell.CmdRelay)
		c2.Payload()[0] = 0xBB
		writeCells(pw, c1, c2)

		// Unregister circuit 1, then send another cell for circuit 2.
		l.UnregisterCircuit(0x80000001)

		c2b := cell.NewFixedCell(0x80000002, cell.CmdRelay)
		c2b.Payload()[0] = 0xCC
		writeCells(pw, c2b)

		_ = pw.Close()
	}()

	// Circuit 1 should get its cell.
	select {
	case c := <-cr1.Cells:
		if c.Payload()[0] != 0xAA {
			t.Fatalf("circuit 1: payload[0] = %02x, want AA", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 1 cell")
	}

	// Circuit 2 should get both its cells.
	assertCellSequence(t, "circuit 2", cr2.Cells, 0xBB, 0xCC)

	// Wait for link death.
	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
		t.Fatal("link did not die")
	}
}

// TestMassiveInterleavedCellRouting is a stress test with many circuits receiving
// many cells concurrently, verifying no data corruption or misrouting under load.
func TestMassiveInterleavedCellRouting(t *testing.T) {
	l, pw := pipeLink(t)

	const numCircuits = 20
	const cellsPerCircuit = 100

	receivers := make(map[uint32]*CircuitReceiver)
	for i := 0; i < numCircuits; i++ {
		circID := uint32(0x80000001 + i)
		cr, err := l.RegisterCircuit(circID)
		if err != nil {
			t.Fatalf("RegisterCircuit(0x%08x): %v", circID, err)
		}
		receivers[circID] = cr
	}

	l.StartReadLoop()

	// Write interleaved cells.
	go func() {
		for cellIdx := 0; cellIdx < cellsPerCircuit; cellIdx++ {
			for i := 0; i < numCircuits; i++ {
				circID := uint32(0x80000001 + i)
				c := cell.NewFixedCell(circID, cell.CmdRelay)
				c.Payload()[0] = byte(i)
				c.Payload()[1] = byte(cellIdx)
				writeCells(pw, c)
			}
		}
		_ = pw.Close()
	}()

	// Verify each circuit gets exactly its cells in order.
	var wg sync.WaitGroup
	wg.Add(numCircuits)
	for i := 0; i < numCircuits; i++ {
		go func(idx int) {
			defer wg.Done()
			circID := uint32(0x80000001 + idx)
			cr := receivers[circID]
			for cellIdx := 0; cellIdx < cellsPerCircuit; cellIdx++ {
				select {
				case c := <-cr.Cells:
					if c.Payload()[0] != byte(idx) {
						t.Errorf("circuit 0x%08x cell %d: payload[0]=%d, want %d", circID, cellIdx, c.Payload()[0], idx)
						return
					}
					if c.Payload()[1] != byte(cellIdx) {
						t.Errorf("circuit 0x%08x cell %d: payload[1]=%d, want %d", circID, cellIdx, c.Payload()[1], cellIdx)
						return
					}
				case <-time.After(10 * time.Second):
					t.Errorf("circuit 0x%08x: timeout at cell %d", circID, cellIdx)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestReadCellErrorOnCircuitReceiverChannelClosed verifies that ReadCell returns
// an error when the Cells channel is closed (as happens on link death).
func TestReadCellErrorOnCircuitReceiverChannelClosed(t *testing.T) {
	doneCh := make(chan struct{})
	cr := &CircuitReceiver{
		Cells: make(chan cell.Cell),
		Done:  doneCh,
		done:  doneCh,
	}

	// Close the cells channel.
	close(cr.Cells)

	_, err := cr.ReadCell()
	if err == nil {
		t.Fatal("expected error from ReadCell on closed Cells channel")
	}
}

// TestLinkReadLoopDoesNotDeliverAfterUnregister verifies that once a circuit is
// unregistered, subsequent cells for that circuit ID are discarded.
func TestLinkReadLoopDoesNotDeliverAfterUnregister(t *testing.T) {
	l, pw := pipeLink(t)

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}
	// Also register a second circuit as a sentinel.
	cr2, err := l.RegisterCircuit(0x80000002)
	if err != nil {
		t.Fatalf("RegisterCircuit(2): %v", err)
	}

	l.StartReadLoop()

	// Use a channel to synchronize: the feeder sends the first cell, then
	// waits for the main goroutine to consume it before unregistering.
	cellConsumed := make(chan struct{})

	go func() {
		// Cell for circuit 1.
		c1 := cell.NewFixedCell(0x80000001, cell.CmdRelay)
		c1.Payload()[0] = 0x01
		writeCells(pw, c1)

		// Wait for the main goroutine to read the cell, guaranteeing delivery
		// before we unregister.
		<-cellConsumed

		// Unregister circuit 1.
		l.UnregisterCircuit(0x80000001)

		// Another cell for circuit 1 (should be discarded).
		c1b := cell.NewFixedCell(0x80000001, cell.CmdRelay)
		c1b.Payload()[0] = 0x02
		writeCells(pw, c1b)

		// Sentinel cell for circuit 2 to prove the read loop is still alive.
		c2 := cell.NewFixedCell(0x80000002, cell.CmdRelay)
		c2.Payload()[0] = 0xFF
		writeCells(pw, c2)

		_ = pw.Close()
	}()

	// Circuit 1 should get exactly one cell.
	select {
	case c := <-cr.Cells:
		if c.Payload()[0] != 0x01 {
			t.Fatalf("circuit 1: got payload %02x, want 01", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 1 cell")
	}

	// Signal the feeder that we've consumed the cell.
	close(cellConsumed)

	// Circuit 1 Done should be closed after unregister.
	select {
	case <-cr.Done:
	case <-time.After(2 * time.Second):
		t.Fatal("circuit 1 Done not closed after unregister")
	}

	// Sentinel: circuit 2 should get its cell (proving read loop continued).
	select {
	case c := <-cr2.Cells:
		if c.Payload()[0] != 0xFF {
			t.Fatalf("circuit 2: got payload %02x, want FF", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 2 sentinel cell")
	}

}
