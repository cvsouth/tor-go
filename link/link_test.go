package link

import (
	"bufio"
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
)

// pipeLink creates a Link backed by a net.Pipe-like pair: cells written to the
// returned writer will be readable by the link's Reader. The link's Writer
// writes to io.Discard.
func pipeLink(t *testing.T) (*Link, *io.PipeWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	br := bufio.NewReader(pr)
	cr := cell.NewReader(br)
	cw := cell.NewWriter(io.Discard)

	l := &Link{
		Reader:   cr,
		Writer:   cw,
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}
	return l, pw
}

// writeCells writes pre-built cells to a pipe writer.
func writeCells(pw *io.PipeWriter, cells ...cell.Cell) {
	for _, c := range cells {
		_, _ = pw.Write(c)
	}
}

func TestLinkRegisterCircuit(t *testing.T) {
	l := &Link{
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}
	if cr == nil {
		t.Fatal("RegisterCircuit returned nil")
	}
	if cap(cr.Cells) != 32 {
		t.Fatalf("channel capacity = %d, want 32", cap(cr.Cells))
	}

	l.circuitsMu.RLock()
	stored := l.circuits[0x80000001]
	l.circuitsMu.RUnlock()
	if stored != cr {
		t.Fatal("circuit not stored in dispatch table")
	}
}

func TestLinkRegisterCircuitDuplicate(t *testing.T) {
	l := &Link{
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}

	_, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("first RegisterCircuit: %v", err)
	}

	_, err = l.RegisterCircuit(0x80000001)
	if err == nil {
		t.Fatal("expected error for duplicate circuit ID")
	}
}

func TestLinkRegisterCircuitOnDeadLink(t *testing.T) {
	l := &Link{
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}
	close(l.done)

	_, err := l.RegisterCircuit(0x80000001)
	if err == nil {
		t.Fatal("expected error registering circuit on dead link")
	}
}

func TestLinkUnregisterCircuit(t *testing.T) {
	l := &Link{
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	l.UnregisterCircuit(0x80000001)

	l.circuitsMu.RLock()
	_, exists := l.circuits[0x80000001]
	l.circuitsMu.RUnlock()
	if exists {
		t.Fatal("circuit still in dispatch table after unregister")
	}

	// Done channel should be closed.
	select {
	case <-cr.Done:
	default:
		t.Fatal("expected Done to be closed after UnregisterCircuit")
	}
}

func TestLinkUnregisterCircuitNilMap(t *testing.T) {
	l := &Link{}
	// Should not panic.
	l.UnregisterCircuit(0x80000001)
}

func TestLinkReadLoopRoutesCorrectly(t *testing.T) {
	l, pw := pipeLink(t)

	cr1, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit(1): %v", err)
	}
	cr2, err := l.RegisterCircuit(0x80000002)
	if err != nil {
		t.Fatalf("RegisterCircuit(2): %v", err)
	}

	l.StartReadLoop()

	// Write cells for both circuits.
	cell1 := cell.NewFixedCell(0x80000001, cell.CmdRelay)
	cell1.Payload()[0] = 0xAA
	cell2 := cell.NewFixedCell(0x80000002, cell.CmdRelay)
	cell2.Payload()[0] = 0xBB

	go func() {
		writeCells(pw, cell1, cell2)
		_ = pw.Close()
	}()

	// Circuit 1 should receive its cell.
	select {
	case c := <-cr1.Cells:
		if c.CircID() != 0x80000001 {
			t.Fatalf("circuit 1 got circID 0x%08x", c.CircID())
		}
		if c.Payload()[0] != 0xAA {
			t.Fatalf("circuit 1 payload[0] = %02x, want AA", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 1 cell")
	}

	// Circuit 2 should receive its cell.
	select {
	case c := <-cr2.Cells:
		if c.CircID() != 0x80000002 {
			t.Fatalf("circuit 2 got circID 0x%08x", c.CircID())
		}
		if c.Payload()[0] != 0xBB {
			t.Fatalf("circuit 2 payload[0] = %02x, want BB", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for circuit 2 cell")
	}

	// After pipe close, link should die.
	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
		t.Fatal("link did not die after pipe close")
	}
}

func TestLinkReadLoopDiscardsPadding(t *testing.T) {
	l, pw := pipeLink(t)

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	l.StartReadLoop()

	padding := cell.NewFixedCell(0, cell.CmdPadding)
	relay := cell.NewFixedCell(0x80000001, cell.CmdRelay)
	relay.Payload()[0] = 0xCC

	go func() {
		writeCells(pw, padding, relay)
		_ = pw.Close()
	}()

	// Should only get the relay cell, padding discarded.
	select {
	case c := <-cr.Cells:
		if c.Command() != cell.CmdRelay {
			t.Fatalf("got command %d, want RELAY", c.Command())
		}
		if c.Payload()[0] != 0xCC {
			t.Fatalf("payload[0] = %02x, want CC", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for relay cell")
	}
}

func TestLinkReadLoopDiscardsUnknownCircuit(t *testing.T) {
	l, pw := pipeLink(t)

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	l.StartReadLoop()

	// Cell for unknown circuit 0x99999999, then one for registered circuit.
	unknown := cell.NewFixedCell(0x99999999, cell.CmdRelay)
	known := cell.NewFixedCell(0x80000001, cell.CmdRelay)
	known.Payload()[0] = 0xDD

	go func() {
		writeCells(pw, unknown, known)
		_ = pw.Close()
	}()

	select {
	case c := <-cr.Cells:
		if c.Payload()[0] != 0xDD {
			t.Fatalf("payload[0] = %02x, want DD", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for known circuit cell")
	}
}

func TestLinkDeathClosesAllCircuits(t *testing.T) {
	l, pw := pipeLink(t)

	cr1, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit(1): %v", err)
	}
	cr2, err := l.RegisterCircuit(0x80000002)
	if err != nil {
		t.Fatalf("RegisterCircuit(2): %v", err)
	}

	l.StartReadLoop()

	// Close pipe to kill the link.
	_ = pw.Close()

	// Both circuits' done channels should close.
	for i, cr := range []*CircuitReceiver{cr1, cr2} {
		select {
		case <-cr.Done:
		case <-time.After(2 * time.Second):
			t.Fatalf("circuit %d Done not closed after link death", i+1)
		}
	}

	// Link done should close.
	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
		t.Fatal("link done not closed")
	}
}

func TestLinkStartReadLoopIdempotent(t *testing.T) {
	l, pw := pipeLink(t)

	l.StartReadLoop()
	l.StartReadLoop()
	l.StartReadLoop()

	_ = pw.Close()

	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
		t.Fatal("link did not die")
	}
}

func TestLinkReadLoopDeliversDestroyCellToCircuit(t *testing.T) {
	l, pw := pipeLink(t)

	cr, err := l.RegisterCircuit(0x80000001)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	l.StartReadLoop()

	// DESTROY cell is a regular fixed cell routed by circID.
	destroy := cell.NewFixedCell(0x80000001, cell.CmdDestroy)
	destroy.Payload()[0] = 5 // reason code

	go func() {
		writeCells(pw, destroy)
		_ = pw.Close()
	}()

	// The DESTROY should be delivered to the circuit's channel.
	select {
	case c := <-cr.Cells:
		if c.Command() != cell.CmdDestroy {
			t.Fatalf("got command %d, want DESTROY", c.Command())
		}
		if c.Payload()[0] != 5 {
			t.Fatalf("destroy reason = %d, want 5", c.Payload()[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for DESTROY cell")
	}
}

func TestCircuitReceiverReadCell(t *testing.T) {
	doneCh := make(chan struct{})
	cr := &CircuitReceiver{
		Cells: make(chan cell.Cell, 1),
		Done:  doneCh,
		done:  doneCh,
	}

	expected := cell.NewFixedCell(0x80000001, cell.CmdRelay)
	cr.Cells <- expected

	got, err := cr.ReadCell()
	if err != nil {
		t.Fatalf("ReadCell: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("ReadCell returned wrong cell")
	}
}

func TestCircuitReceiverReadCellOnClosedChannel(t *testing.T) {
	doneCh := make(chan struct{})
	cr := &CircuitReceiver{
		Cells: make(chan cell.Cell),
		Done:  doneCh,
		done:  doneCh,
	}
	close(doneCh)

	_, err := cr.ReadCell()
	if err == nil {
		t.Fatal("expected error from ReadCell on closed receiver")
	}
}

func TestConcurrentRegisterUnregisterCircuits(t *testing.T) {
	l := &Link{
		circuits: make(map[uint32]*CircuitReceiver),
		done:     make(chan struct{}),
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		id := uint32(0x80000000 + i)
		go func() {
			defer wg.Done()
			_, _ = l.RegisterCircuit(id)
		}()
		go func() {
			defer wg.Done()
			l.UnregisterCircuit(id)
		}()
	}

	wg.Wait()
	// No panic or race = success.
}

func TestLinkReadLoopMultipleCircuitsInterleavedCells(t *testing.T) {
	l, pw := pipeLink(t)

	const numCircuits = 5
	const cellsPerCircuit = 10

	receivers := make(map[uint32]*CircuitReceiver)
	for i := 0; i < numCircuits; i++ {
		circID := uint32(0x80000001 + i)
		cr, err := l.RegisterCircuit(circID)
		if err != nil {
			t.Fatalf("RegisterCircuit(%08x): %v", circID, err)
		}
		receivers[circID] = cr
	}

	l.StartReadLoop()

	// Write interleaved cells from a goroutine.
	go func() {
		for cellIdx := 0; cellIdx < cellsPerCircuit; cellIdx++ {
			for i := 0; i < numCircuits; i++ {
				circID := uint32(0x80000001 + i)
				c := cell.NewFixedCell(circID, cell.CmdRelay)
				c.Payload()[0] = byte(cellIdx)
				c.Payload()[1] = byte(i)
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
					if c.Payload()[0] != byte(cellIdx) {
						t.Errorf("circuit %08x cell %d: payload[0]=%d, want %d", circID, cellIdx, c.Payload()[0], cellIdx)
						return
					}
					if c.Payload()[1] != byte(idx) {
						t.Errorf("circuit %08x cell %d: payload[1]=%d, want %d", circID, cellIdx, c.Payload()[1], idx)
						return
					}
				case <-time.After(5 * time.Second):
					t.Errorf("circuit %08x: timeout at cell %d", circID, cellIdx)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestCircuitIDAllocationUniqueOnSameLink verifies that ClaimCircID
// prevents two circuits from getting the same ID on the same link.
func TestCircuitIDAllocationUniqueOnSameLink(t *testing.T) {
	l := &Link{}

	// Claim a bunch of IDs.
	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		id := uint32(0x80000000 + i)
		if !l.ClaimCircID(id) {
			t.Fatalf("ClaimCircID(%08x) failed on first claim", id)
		}
		ids[id] = true
	}

	// Re-claiming any of them should fail.
	for id := range ids {
		if l.ClaimCircID(id) {
			t.Fatalf("ClaimCircID(%08x) succeeded on duplicate claim", id)
		}
	}

	// Releasing and re-claiming should work.
	for id := range ids {
		l.ReleaseCircID(id)
		if !l.ClaimCircID(id) {
			t.Fatalf("ClaimCircID(%08x) failed after release", id)
		}
	}
}
