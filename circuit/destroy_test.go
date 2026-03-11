package circuit

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/link"
)

func TestDestroyReleasesCircuitID(t *testing.T) {
	const circID = uint32(0x80000001)
	l := &link.Link{
		Writer: cell.NewWriter(io.Discard),
	}
	l.ClaimCircID(circID)

	circ := &Circuit{
		ID:               circID,
		Link:             l,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	if err := circ.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	// CircID should have been released - re-claiming should succeed.
	if !l.ClaimCircID(circID) {
		t.Fatal("circuit ID was not released after Destroy")
	}
}

func TestDestroyIdempotent(t *testing.T) {
	const circID = uint32(0x80000001)
	l := &link.Link{
		Writer: cell.NewWriter(io.Discard),
	}
	l.ClaimCircID(circID)

	circ := &Circuit{
		ID:               circID,
		Link:             l,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	err1 := circ.Destroy()
	if err1 != nil {
		t.Fatalf("first Destroy: %v", err1)
	}

	err2 := circ.Destroy()
	if err2 != nil {
		t.Fatalf("second Destroy should return nil, got: %v", err2)
	}
}

func TestDestroySignalsAllStreams(t *testing.T) {
	const circID = uint32(0x80000001)
	circ := &Circuit{
		ID:               circID,
		Link:             &link.Link{Writer: cell.NewWriter(io.Discard)},
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	sr1, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream(1): %v", err)
	}
	sr2, err := circ.RegisterStream(2)
	if err != nil {
		t.Fatalf("RegisterStream(2): %v", err)
	}
	sr3, err := circ.RegisterStream(3)
	if err != nil {
		t.Fatalf("RegisterStream(3): %v", err)
	}

	if err := circ.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	for i, sr := range []*StreamReceiver{sr1, sr2, sr3} {
		select {
		case <-sr.Done:
		case <-time.After(time.Second):
			t.Fatalf("stream %d Done channel not closed after Destroy", i+1)
		}
	}
}

func TestDestroyThenRegisterFails(t *testing.T) {
	const circID = uint32(0x80000001)
	circ := &Circuit{
		ID:               circID,
		Link:             &link.Link{Writer: cell.NewWriter(io.Discard)},
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	if err := circ.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	_, err := circ.RegisterStream(42)
	if err == nil {
		t.Fatal("expected error registering stream after Destroy")
	}
}

func TestDestroyStopsReadLoop(t *testing.T) {
	const circID = uint32(0x80000001)

	// Use a blocking cell reader that blocks until the circuit is destroyed.
	blockReader := &blockingCellReader{
		unblock: make(chan struct{}),
	}

	circ := &Circuit{
		ID:               circID,
		Link:             &link.Link{Writer: cell.NewWriter(io.Discard)},
		cellReader:       blockReader,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}
	// Need at least one hop for the read loop's decrypt to work,
	// but the reader will return an error before decrypt is reached.

	circ.StartReadLoop()

	// Give the read loop time to start blocking on ReadCell.
	time.Sleep(10 * time.Millisecond)

	// Destroy unblocks the reader (simulating the relay closing the connection).
	close(blockReader.unblock)

	if err := circ.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	select {
	case <-circ.done:
	case <-time.After(2 * time.Second):
		t.Fatal("read loop did not exit after Destroy")
	}
}

func TestDestroyWithNilLink(t *testing.T) {
	circ := &Circuit{
		ID:               0x80000001,
		Link:             nil,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	// Should not panic.
	err := circ.Destroy()
	if err != nil {
		t.Fatalf("Destroy with nil link should return nil, got: %v", err)
	}

	// done channel should be closed.
	select {
	case <-circ.done:
	default:
		t.Fatal("done channel not closed after Destroy with nil link")
	}
}

func TestDestroyConcurrent(t *testing.T) {
	const circID = uint32(0x80000001)
	l := &link.Link{
		Writer: cell.NewWriter(io.Discard),
	}
	l.ClaimCircID(circID)

	circ := &Circuit{
		ID:               circID,
		Link:             l,
		streams:          make(map[uint16]*StreamReceiver),
		done:             make(chan struct{}),
		circWindow:       initCircWindow,
		circWindowSignal: make(chan struct{}, 1),
	}

	// Register some streams.
	for i := uint16(1); i <= 5; i++ {
		if _, err := circ.RegisterStream(i); err != nil {
			t.Fatalf("RegisterStream(%d): %v", i, err)
		}
	}

	// Call Destroy concurrently from 10 goroutines - should not panic or race.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = circ.Destroy()
		}()
	}
	wg.Wait()

	select {
	case <-circ.done:
	default:
		t.Fatal("done channel not closed after concurrent Destroy calls")
	}
}

// blockingCellReader blocks on ReadCell until unblock is closed, then returns an error.
type blockingCellReader struct {
	unblock chan struct{}
}

func (b *blockingCellReader) ReadCell() (cell.Cell, error) {
	<-b.unblock
	return nil, errors.New("connection closed")
}
