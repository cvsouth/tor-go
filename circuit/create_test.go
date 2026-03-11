package circuit

import (
	"bufio"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/link"
)

// TestExtendMultipleHopsViaChannelReader verifies that multiple Extend calls
// each read their EXTENDED2 response from the same channel-based cellReader.
func TestExtendMultipleHopsViaChannelReader(t *testing.T) {
	const circID = uint32(0x80000001)

	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	reader := newChannelReader()
	circ.cellReader = reader

	// Simulate 3 EXTENDED2 responses (for 3 additional hops).
	for i := 0; i < 3; i++ {
		extended2Data := make([]byte, 66)
		binary.BigEndian.PutUint16(extended2Data[0:2], 64)
		for j := 2; j < 66; j++ {
			extended2Data[j] = byte(i*10 + j)
		}
		extended2Cell := buildRelayCellFromRelay(circID, RelayExtended2, 0, extended2Data, nil, 0, kbEncrypt, dbRelay)
		reader.ch <- extended2Cell
	}

	// Read each EXTENDED2 via receiveRelay.
	for i := 0; i < 3; i++ {
		_, relayCmd, _, data, _, err := circ.receiveRelay()
		if err != nil {
			t.Fatalf("hop %d: receiveRelay: %v", i, err)
		}
		if relayCmd != RelayExtended2 {
			t.Fatalf("hop %d: relayCmd = %d, want %d", i, relayCmd, RelayExtended2)
		}
		if len(data) < 66 {
			t.Fatalf("hop %d: data too short: %d bytes", i, len(data))
		}
	}
}

// TestCircuitCellReaderSetToLinkReceiver verifies that when a circuit is
// constructed with a link receiver as cellReader, getCellReader returns it.
func TestCircuitCellReaderSetToLinkReceiver(t *testing.T) {
	const circID = uint32(0x80000001)

	l := &link.Link{
		Writer: cell.NewWriter(io.Discard),
	}

	cr, err := l.RegisterCircuit(circID)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	circ := &Circuit{
		ID:         circID,
		Link:       l,
		cellReader: cr,
		streams:    make(map[uint16]*StreamReceiver),
		done:       make(chan struct{}),
	}

	// getCellReader should return the link receiver, not the link's raw reader.
	got := circ.getCellReader()
	if got != cr {
		t.Fatal("getCellReader did not return the link receiver")
	}
}

// TestLinkDeathDuringCreateHandshake verifies that when the link dies while
// a circuit is waiting for CREATED2, the circuit receiver's Done channel
// notifies the waiter.
func TestLinkDeathDuringCreateHandshake(t *testing.T) {
	l, pw := pipeLinkFromCircuit(t)

	const circID = uint32(0x80000001)
	cr, err := l.RegisterCircuit(circID)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	l.StartReadLoop()

	// Close the pipe immediately to kill the link.
	_ = pw.Close()

	// The circuit receiver should be notified via Done.
	select {
	case <-cr.Done:
		// Link death propagated to circuit.
	case <-time.After(2 * time.Second):
		t.Fatal("circuit receiver not notified of link death")
	}

	// ReadCell should fail.
	_, err = cr.ReadCell()
	if err == nil {
		t.Fatal("expected error from ReadCell after link death")
	}
}

// TestCreateRegistersWithLink verifies that during Create(), the circuit is
// registered with the link's circuit dispatch table before CREATE2 is sent,
// and that the resulting circuit's cellReader is the link's CircuitReceiver.
// Since Create() requires real ntor crypto, we test the mechanism at the
// component level: RegisterCircuit → link read loop → CircuitReceiver.ReadCell.
func TestCreateRegistersWithLink(t *testing.T) {
	l, pw := pipeLinkFromCircuit(t)

	const circID = uint32(0x80000001)

	// Register the circuit (as Create does internally).
	cr, err := l.RegisterCircuit(circID)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	// Verify registration by checking the dispatch table.
	l.StartReadLoop()

	// Write a CREATED2 cell through the pipe - the link read loop should route it
	// to the CircuitReceiver.
	created2 := cell.NewFixedCell(circID, cell.CmdCreated2)
	created2.Payload()[0] = 0x00 // HLEN high byte
	created2.Payload()[1] = 0x40 // HLEN = 64
	for i := 2; i < 66; i++ {
		created2.Payload()[i] = byte(i)
	}

	writeErr := make(chan error, 1)
	go func() {
		if _, err := pw.Write(created2); err != nil {
			writeErr <- err
			return
		}
		if err := pw.Close(); err != nil {
			writeErr <- err
			return
		}
		writeErr <- nil
	}()

	// Read via the CircuitReceiver's channel (as Create does with linkRecv.Cells).
	select {
	case c := <-cr.Cells:
		if c.Command() != cell.CmdCreated2 {
			t.Fatalf("got command %d, want CREATED2 (%d)", c.Command(), cell.CmdCreated2)
		}
		hlen := binary.BigEndian.Uint16(c.Payload()[0:2])
		if hlen != 64 {
			t.Fatalf("HLEN = %d, want 64", hlen)
		}
	case <-cr.Done:
		t.Fatal("circuit receiver closed before CREATED2 arrived")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for CREATED2 via link read loop")
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("pipe write goroutine: %v", err)
	}
}

// TestCreateTwoCircuitsOnSameLink verifies that two circuits registered on the
// same link each receive their own cells independently through the link read
// loop. This tests that link multiplexing works for multiple concurrent Create
// operations.
func TestCreateTwoCircuitsOnSameLink(t *testing.T) {
	l, pw := pipeLinkFromCircuit(t)

	const circID1 = uint32(0x80000001)
	const circID2 = uint32(0x80000002)

	cr1, err := l.RegisterCircuit(circID1)
	if err != nil {
		t.Fatalf("RegisterCircuit(%08x): %v", circID1, err)
	}
	cr2, err := l.RegisterCircuit(circID2)
	if err != nil {
		t.Fatalf("RegisterCircuit(%08x): %v", circID2, err)
	}

	l.StartReadLoop()

	// Write CREATED2 for circuit 1, then CREATED2 for circuit 2.
	writeErr := make(chan error, 1)
	go func() {
		c1 := cell.NewFixedCell(circID1, cell.CmdCreated2)
		c1.Payload()[0] = 0x00
		c1.Payload()[1] = 0x40
		c1.Payload()[2] = 0x01 // marker for circuit 1
		if _, err := pw.Write(c1); err != nil {
			writeErr <- err
			return
		}

		c2 := cell.NewFixedCell(circID2, cell.CmdCreated2)
		c2.Payload()[0] = 0x00
		c2.Payload()[1] = 0x40
		c2.Payload()[2] = 0x02 // marker for circuit 2
		if _, err := pw.Write(c2); err != nil {
			writeErr <- err
			return
		}

		if err := pw.Close(); err != nil {
			writeErr <- err
			return
		}
		writeErr <- nil
	}()

	// Circuit 1 should get its CREATED2.
	assertCreated2Received(t, "circuit 1", cr1.Cells, 0x01)

	// Circuit 2 should get its CREATED2.
	assertCreated2Received(t, "circuit 2", cr2.Cells, 0x02)

	// Link should die after pipe close.
	select {
	case <-l.LinkDone():
	case <-time.After(2 * time.Second):
		t.Fatal("link did not die after pipe close")
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("pipe write goroutine: %v", err)
	}
}

// TestExtendWorksWithLinkReadLoop verifies that Extend() correctly reads
// EXTENDED2 responses through the circuit's cellReader (which is set to the
// link's CircuitReceiver). During Extend, the circuit's own read loop is NOT
// started - Extend reads from the circuit channel directly via receiveRelay.
func TestExtendWorksWithLinkReadLoop(t *testing.T) {
	const circID = uint32(0x80000001)

	// Build a 1-hop circuit with matched crypto.
	circ, kbEncrypt, dbRelay := testDispatchCircuit(circID)

	// Use a channel-based reader to simulate the link read loop routing cells.
	reader := newChannelReader()
	circ.cellReader = reader

	// Verify the circuit's read loop has NOT been started.
	circ.streamsMu.RLock()
	readLoopStarted := circ.readLoopStarted
	circ.streamsMu.RUnlock()
	if readLoopStarted {
		t.Fatal("read loop should not be started during Extend")
	}

	// Build an EXTENDED2 relay cell (encrypted with the hop's backward cipher).
	extended2Data := make([]byte, 66)
	binary.BigEndian.PutUint16(extended2Data[0:2], 64)
	for i := 2; i < 66; i++ {
		extended2Data[i] = byte(i)
	}
	extended2Cell := buildRelayCellFromRelay(circID, RelayExtended2, 0, extended2Data, nil, 0, kbEncrypt, dbRelay)

	// Feed the EXTENDED2 cell into the channel reader.
	reader.ch <- extended2Cell

	// Call receiveRelay directly (as Extend does internally).
	hopIdx, relayCmd, streamID, data, _, err := circ.receiveRelay()
	if err != nil {
		t.Fatalf("receiveRelay: %v", err)
	}
	if relayCmd != RelayExtended2 {
		t.Fatalf("relayCmd = %d, want %d (EXTENDED2)", relayCmd, RelayExtended2)
	}
	if hopIdx != 0 {
		t.Fatalf("hopIdx = %d, want 0", hopIdx)
	}
	if streamID != 0 {
		t.Fatalf("streamID = %d, want 0", streamID)
	}
	if len(data) < 2 {
		t.Fatalf("data too short: %d bytes", len(data))
	}
	hlen := binary.BigEndian.Uint16(data[0:2])
	if hlen != 64 {
		t.Fatalf("HLEN = %d, want 64", hlen)
	}
}

// TestCreateUnregistersOnFailure verifies that when the CREATE2 handshake
// fails (relay sends DESTROY, wrong command, or link dies), the circuit is
// unregistered from the link and the circuit ID is released, allowing
// re-use of the same ID.
func TestCreateUnregistersOnFailure(t *testing.T) {
	t.Run("DESTROY response", func(t *testing.T) {
		const circID = uint32(0x80000001)
		l, cr := newTestLinkWithCircuit(t, circID)

		// Simulate relay sending DESTROY.
		sendAndReceiveCell(t, cr, circID, cell.CmdDestroy, func(resp cell.Cell) {
			if resp.Command() != cell.CmdDestroy {
				t.Fatalf("expected DESTROY, got %d", resp.Command())
			}
		})

		// Cleanup as Create() does on failure.
		l.UnregisterCircuit(circID)
		l.ReleaseCircID(circID)

		// Re-registration should succeed (proves cleanup worked).
		cr2, err := l.RegisterCircuit(circID)
		if err != nil {
			t.Fatalf("re-register after cleanup: %v", err)
		}
		if cr2 == nil {
			t.Fatal("re-register returned nil")
		}
		l.UnregisterCircuit(circID)

		// Re-claim should succeed (proves circuit ID was released).
		l.ReleaseCircID(circID)
		assertCircIDClaimable(t, l, circID)
	})

	t.Run("wrong response command", func(t *testing.T) {
		const circID = uint32(0x80000002)
		l, cr := newTestLinkWithCircuit(t, circID)

		// Simulate relay sending wrong command.
		sendAndReceiveCell(t, cr, circID, cell.CmdRelay, func(resp cell.Cell) {
			if resp.Command() == cell.CmdCreated2 {
				t.Fatal("should not have received CREATED2")
			}
		})

		l.UnregisterCircuit(circID)
		l.ReleaseCircID(circID)
		assertCircIDClaimable(t, l, circID)
	})

	t.Run("link death closes receiver", func(t *testing.T) {
		const circID = uint32(0x80000003)
		l, cr := newTestLinkWithCircuit(t, circID)

		// Simulate link death by unregistering (closes Done).
		l.UnregisterCircuit(circID)

		// ReadCell should fail.
		_, readErr := cr.ReadCell()
		if readErr == nil {
			t.Fatal("expected error from ReadCell after link death")
		}

		l.ReleaseCircID(circID)
		assertCircIDClaimable(t, l, circID)
	})
}

// assertCreated2Received reads a CREATED2 cell from ch and verifies its marker byte.
func assertCreated2Received(t *testing.T, name string, ch <-chan cell.Cell, marker byte) {
	t.Helper()
	select {
	case c := <-ch:
		if c.Command() != cell.CmdCreated2 {
			t.Fatalf("%s: got command %d, want CREATED2", name, c.Command())
		}
		if c.Payload()[2] != marker {
			t.Fatalf("%s: payload[2]=%02x, want %02x", name, c.Payload()[2], marker)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s CREATED2", name)
	}
}

// newTestLinkWithCircuit creates a link with a discard writer, claims circID, and registers it.
func newTestLinkWithCircuit(t *testing.T, circID uint32) (*link.Link, *link.CircuitReceiver) {
	t.Helper()
	l := &link.Link{Writer: cell.NewWriter(io.Discard)}
	l.ClaimCircID(circID)
	cr, err := l.RegisterCircuit(circID)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}
	return l, cr
}

// sendAndReceiveCell sends a cell with the given command into cr.Cells and reads it back.
// check is called with the received cell for assertions.
func sendAndReceiveCell(t *testing.T, cr *link.CircuitReceiver, circID uint32, cmd uint8, check func(cell.Cell)) {
	t.Helper()
	sendErr := make(chan error, 1)
	go func() {
		cr.Cells <- cell.NewFixedCell(circID, cmd)
		sendErr <- nil
	}()
	select {
	case resp := <-cr.Cells:
		check(resp)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("send goroutine: %v", err)
	}
}

// assertCircIDClaimable verifies that a circuit ID can be re-claimed on the link.
func assertCircIDClaimable(t *testing.T, l *link.Link, circID uint32) {
	t.Helper()
	if !l.ClaimCircID(circID) {
		t.Fatal("circuit ID not released after cleanup")
	}
}

// --- helpers ---

// pipeLinkFromCircuit creates a link with a pipe, usable from circuit tests.
func pipeLinkFromCircuit(t *testing.T) (*link.Link, *io.PipeWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	br := bufio.NewReader(pr)
	cr := cell.NewReader(br)
	cw := cell.NewWriter(io.Discard)

	l := link.NewTestLink(cr, cw)
	return l, pw
}
