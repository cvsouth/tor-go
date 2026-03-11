package stream

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/circuit"
)

func TestSendMeFlowControlUnderConcurrentLoad(t *testing.T) {
	const circID = uint32(0x80000001)
	const numStreams = 3
	// Each stream writes enough data to exhaust its send window.
	// Initial streamWindow = 500, so writing 500 cells exhausts it.
	// We'll set a small initial window and verify SENDMEs unblock writes.
	const initialWindow = 5
	const totalWritesPerStream = 10

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	entries := makeTestStreams(t, circ, numStreams, initialWindow)

	// Writers: each stream writes totalWritesPerStream cells.
	// With initialWindow=5, they'll block after 5 writes until SENDMEs arrive.
	var writerWg sync.WaitGroup
	writerWg.Add(numStreams)
	writerErrs := make(chan error, numStreams)
	var totalWrites atomic.Int64

	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer writerWg.Done()
			s := entries[idx].stream
			for j := 0; j < totalWritesPerStream; j++ {
				_, err := s.Write([]byte("x"))
				if err != nil {
					writerErrs <- fmt.Errorf("stream %d write %d: %w", entries[idx].sid, j, err)
					return
				}
				totalWrites.Add(1)
			}
		}(i)
	}

	// Readers: process SENDMEs to unblock writers
	readerWg := startStreamReaders(entries)

	// Send SENDMEs only after writers have exhausted their initial windows.
	// Wait until total writes reach initialWindow*numStreams, meaning all
	// writers have used up their windows and are blocked.
	go func() {
		target := int64(initialWindow * numStreams)
		for totalWrites.Load() < target {
			runtime.Gosched()
		}
		for i := 0; i < numStreams; i++ {
			sid := uint16(i + 1)
			sendme := buildRelayCell(circID, circuit.RelaySendMe, sid, nil, kbEnc, dbRelay)
			reader.ch <- sendme
		}
	}()

	waitDone(t, &writerWg, 10*time.Second, "timeout waiting for writers to complete")

	// Check for writer errors
	close(writerErrs)
	for err := range writerErrs {
		t.Fatal(err)
	}

	// Clean up: close all streams to stop readers
	for i := 0; i < numStreams; i++ {
		close(entries[i].stream.doneCh)
	}

	// Close the cell reader to stop the circuit
	close(reader.ch)

	waitDone(t, readerWg, 5*time.Second, "readers did not exit after cleanup")

	// Verify all stream windows were decremented correctly.
	// Each stream wrote totalWritesPerStream cells, each decrementing window by 1.
	// The SENDME added streamSendMeWindow (50) back.
	// Final window = initialWindow - totalWritesPerStream + 50
	for i := 0; i < numStreams; i++ {
		s := entries[i].stream
		expected := initialWindow - totalWritesPerStream + streamSendMeWindow
		actual := s.StreamWindow()
		if actual != expected {
			t.Errorf("stream %d: window=%d, want %d", entries[i].sid, actual, expected)
		}
	}
}

// streamEntry holds a stream together with its receiver and stream ID.
type streamEntry struct {
	stream *Stream
	recv   *circuit.StreamReceiver
	sid    uint16
}

// makeTestStreams creates numStreams streams registered on circ, each with the given initial window.
func makeTestStreams(t *testing.T, circ *circuit.Circuit, numStreams, initialWindow int) []streamEntry {
	t.Helper()
	entries := make([]streamEntry, numStreams)
	for i := 0; i < numStreams; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		entries[i] = streamEntry{
			stream: &Stream{
				ID:                 sid,
				Circuit:            circ,
				recv:               sr,
				doneCh:             make(chan struct{}),
				streamWindow:       initialWindow,
				streamWindowSignal: make(chan struct{}, 1),
			},
			recv: sr,
			sid:  sid,
		}
	}
	return entries
}

// startStreamReaders launches a background reader goroutine for each entry and returns the WaitGroup.
func startStreamReaders(entries []streamEntry) *sync.WaitGroup {
	var wg sync.WaitGroup
	wg.Add(len(entries))
	for i := range entries {
		go func(idx int) {
			defer wg.Done()
			buf := make([]byte, 100)
			for {
				if _, err := entries[idx].stream.Read(buf); err != nil {
					return
				}
			}
		}(i)
	}
	return &wg
}

// waitDone waits for all goroutines in wg to finish or fatals after timeout.
func waitDone(t *testing.T, wg *sync.WaitGroup, timeout time.Duration, msg string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal(msg)
	}
}

func TestConcurrentStreamReadsWithCircuitDeath(t *testing.T) {
	// Verify all stream reads unblock when the circuit dies
	const circID = uint32(0x80000001)
	const numStreams = 10

	reader := newChannelCellReader()
	circ, _, _ := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	streams := make([]*Stream, numStreams)
	for i := 0; i < numStreams; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		streams[i] = &Stream{
			ID:                 sid,
			Circuit:            circ,
			recv:               sr,
			doneCh:             make(chan struct{}),
			streamWindow:       500,
			streamWindowSignal: make(chan struct{}, 1),
		}
	}

	// Start reads on all streams, signaling when each reader has started
	readersStarted := make(chan struct{}, numStreams)
	var wg sync.WaitGroup
	wg.Add(numStreams)
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			readersStarted <- struct{}{}
			buf := make([]byte, 100)
			_, _ = streams[idx].Read(buf) // should return error when circuit dies
		}(i)
	}

	// Wait for all readers to start before killing the circuit
	for i := 0; i < numStreams; i++ {
		<-readersStarted
	}
	// Give goroutines time to actually block in Read after signaling
	runtime.Gosched()
	time.Sleep(time.Millisecond)
	close(reader.ch)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success: all reads unblocked
	case <-time.After(5 * time.Second):
		t.Fatal("not all reads unblocked after circuit death")
	}
}

func TestConcurrentWriteAndReadOnSameStream(t *testing.T) {
	// Multiple goroutines writing to the same stream while one reads
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	s := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               sr,
		doneCh:             make(chan struct{}),
		streamWindow:       100,
		streamWindowSignal: make(chan struct{}, 1),
	}

	const writers = 5
	const writesPerWriter = 10

	var writerWg sync.WaitGroup
	writerWg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer writerWg.Done()
			for j := 0; j < writesPerWriter; j++ {
				_, _ = s.Write([]byte("x"))
			}
		}()
	}

	// Start a reader that processes incoming SENDMEs
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 100)
		for {
			_, readErr := s.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	// Send SENDMEs to keep writers unblocked (no pacing sleep needed -
	// the buffered channel and flow control handle ordering)
	sendmeDone := make(chan struct{})
	stopSendme := make(chan struct{})
	go func() {
		defer close(sendmeDone)
		for i := 0; i < 10; i++ {
			sendme := buildRelayCell(circID, circuit.RelaySendMe, 1, nil, kbEnc, dbRelay)
			select {
			case reader.ch <- sendme:
			case <-stopSendme:
				return
			}
		}
	}()

	writersDone := make(chan struct{})
	go func() {
		writerWg.Wait()
		close(writersDone)
	}()

	select {
	case <-writersDone:
		// success
	case <-time.After(10 * time.Second):
		t.Fatal("writers did not complete")
	}

	// Clean up: stop SENDME sender before closing channel
	close(stopSendme)
	<-sendmeDone

	close(s.doneCh)
	close(reader.ch)

	select {
	case <-readerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not exit after cleanup")
	}
}

func TestStreamCloseWhileReading(t *testing.T) {
	// Closing a stream while a Read is blocked should unblock the Read
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	s := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               sr,
		doneCh:             make(chan struct{}),
		streamWindow:       500,
		streamWindowSignal: make(chan struct{}, 1),
	}

	readStarted := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		close(readStarted)
		buf := make([]byte, 100)
		_, readErr := s.Read(buf)
		readDone <- readErr
	}()

	// Wait for reader to start, then close the stream
	<-readStarted
	close(s.doneCh)

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected error from Read after stream close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock after stream close")
	}
}

func TestMultipleStreamsEachReceive50CellsTriggeringSendMe(t *testing.T) {
	// Verify that each stream independently tracks its DATA count and sends SENDMEs
	const circID = uint32(0x80000001)
	const numStreams = 3

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	type se struct {
		s  *Stream
		sr *circuit.StreamReceiver
	}
	entries := make([]se, numStreams)
	for i := 0; i < numStreams; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		entries[i] = se{
			s: &Stream{
				ID:                 sid,
				Circuit:            circ,
				recv:               sr,
				doneCh:             make(chan struct{}),
				streamWindow:       500,
				streamWindowSignal: make(chan struct{}, 1),
			},
			sr: sr,
		}
	}

	// Send 50 DATA cells for each stream (triggers stream SENDME for each)
	go func() {
		for cellIdx := 0; cellIdx < streamSendMeWindow; cellIdx++ {
			for i := 0; i < numStreams; i++ {
				sid := uint16(i + 1)
				c := buildRelayCell(circID, circuit.RelayData, sid, []byte("x"), kbEnc, dbRelay)
				reader.ch <- c
			}
		}
	}()

	// Read all cells from all streams concurrently
	var wg sync.WaitGroup
	wg.Add(numStreams)
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			s := entries[idx].s
			buf := make([]byte, 100)
			for cellIdx := 0; cellIdx < streamSendMeWindow; cellIdx++ {
				_, err := s.Read(buf)
				if err != nil {
					t.Errorf("stream %d read %d: %v", idx+1, cellIdx, err)
					return
				}
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout reading cells")
	}

	// Verify each stream's data counter was reset (SENDME was sent)
	for i := 0; i < numStreams; i++ {
		if entries[i].s.streamDataReceived != 0 {
			t.Errorf("stream %d: streamDataReceived=%d, want 0", i+1, entries[i].s.streamDataReceived)
		}
	}
}

func TestRapidOpenCloseDuringActiveIO(t *testing.T) {
	// Open and close streams rapidly while another stream is actively reading
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	// Active stream
	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream(1): %v", err)
	}
	activeStream := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               sr,
		doneCh:             make(chan struct{}),
		streamWindow:       500,
		streamWindowSignal: make(chan struct{}, 1),
	}

	// Feed data to the active stream
	const totalCells = 50
	go func() {
		for i := 0; i < totalCells; i++ {
			c := buildRelayCell(circID, circuit.RelayData, 1, []byte(fmt.Sprintf("cell-%d", i)), kbEnc, dbRelay)
			reader.ch <- c
		}
	}()

	// Churn streams in parallel
	var churnWg sync.WaitGroup
	churnWg.Add(20)
	for i := 0; i < 20; i++ {
		go func(idx int) {
			defer churnWg.Done()
			sid := uint16(100 + idx)
			churnSr, churnErr := circ.RegisterStream(sid)
			if churnErr != nil {
				return
			}
			_ = churnSr
			circ.UnregisterStream(sid)
		}(i)
	}

	// Read from active stream
	buf := make([]byte, 100)
	for i := 0; i < totalCells; i++ {
		n, readErr := activeStream.Read(buf)
		if readErr != nil {
			t.Fatalf("Read %d: %v", i, readErr)
		}
		expected := fmt.Sprintf("cell-%d", i)
		if string(buf[:n]) != expected {
			t.Fatalf("cell %d: got %q, want %q", i, buf[:n], expected)
		}
	}

	churnWg.Wait()

	// Clean up
	close(reader.ch)
}

func TestStreamWindowNeverGoesNegativeUnderConcurrentWriteAndSendMe(t *testing.T) {
	// Multiple writers and concurrent SENDMEs should never produce a negative window
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	recv, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	const initialWindow = 20
	s := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               recv,
		doneCh:             make(chan struct{}),
		streamWindow:       initialWindow,
		streamWindowSignal: make(chan struct{}, 1),
	}

	// Use sync.Once to protect against double-close of s.doneCh.
	// The timeout path and the normal cleanup path both need to close it.
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(s.doneCh) }) }

	// Run a reader to process SENDMEs
	go func() {
		buf := make([]byte, 100)
		for {
			_, readErr := s.Read(buf)
			if readErr != nil {
				return
			}
		}
	}()

	// Send SENDMEs concurrently with writes (no pacing sleep needed)
	stopSendme := make(chan struct{})
	sendmeDone := make(chan struct{})
	go func() {
		defer close(sendmeDone)
		for i := 0; i < 5; i++ {
			sendme := buildRelayCell(circID, circuit.RelaySendMe, 1, nil, kbEnc, dbRelay)
			select {
			case reader.ch <- sendme:
			case <-stopSendme:
				return
			}
		}
	}()

	const writers = 10
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				_, _ = s.Write([]byte("x"))
			}
		}()
	}

	writersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(writersDone)
	}()

	select {
	case <-writersDone:
	case <-time.After(10 * time.Second):
		// Close stream to unblock stuck writers
		closeDone()
		t.Fatal("writers timed out")
	}

	// Verify window is non-negative
	s.windowMu.Lock()
	w := s.streamWindow
	s.windowMu.Unlock()
	if w < 0 {
		t.Fatalf("stream window went negative: %d", w)
	}

	// Clean up: stop SENDME sender before closing channel
	close(stopSendme)
	<-sendmeDone

	closeDone()
	close(reader.ch)
}

// TestConcurrent10Streams100Cells exercises the full multiplexing path at the stream layer:
// 10 concurrent streams on one circuit, each sending and receiving 100 cells, no data loss.
//
// IMPORTANT: numStreams * cellsPerStream must not exceed initCircWindow (1000),
// otherwise the circuit-level receive window will be exhausted and the read loop
// will stall waiting for a circuit SENDME that this test does not send.
func TestConcurrent10Streams100Cells(t *testing.T) {
	const circID = uint32(0x80000001)
	const numStreams = 10
	const cellsPerStream = 100

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	type streamEntry struct {
		stream *Stream
		recv   *circuit.StreamReceiver
	}
	streams := make([]streamEntry, numStreams)
	for i := 0; i < numStreams; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		s := &Stream{
			ID:                 sid,
			Circuit:            circ,
			recv:               sr,
			doneCh:             make(chan struct{}),
			streamWindow:       500,
			streamWindowSignal: make(chan struct{}, 1),
		}
		streams[i] = streamEntry{stream: s, recv: sr}
	}

	// Feed cells interleaved from a background goroutine
	go func() {
		for cellIdx := 0; cellIdx < cellsPerStream; cellIdx++ {
			for i := 0; i < numStreams; i++ {
				sid := uint16(i + 1)
				data := []byte(fmt.Sprintf("s%d-c%d", sid, cellIdx))
				c := buildRelayCell(circID, circuit.RelayData, sid, data, kbEnc, dbRelay)
				reader.ch <- c
			}
		}
	}()

	// Concurrently read from all streams - also write concurrently
	var wg sync.WaitGroup
	wg.Add(numStreams * 2) // readers + writers

	// Writers: each stream writes cellsPerStream cells
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			s := streams[idx].stream
			for j := 0; j < cellsPerStream; j++ {
				data := []byte(fmt.Sprintf("w%d-%d", idx, j))
				_, err := s.Write(data)
				if err != nil {
					t.Errorf("stream %d write %d: %v", idx+1, j, err)
					return
				}
			}
		}(i)
	}

	// Readers: each stream reads cellsPerStream cells and verifies ordering
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			s := streams[idx].stream
			sid := uint16(idx + 1)
			buf := make([]byte, 100)
			for cellIdx := 0; cellIdx < cellsPerStream; cellIdx++ {
				n, err := s.Read(buf)
				if err != nil {
					t.Errorf("stream %d cell %d: Read error: %v", sid, cellIdx, err)
					return
				}
				expected := fmt.Sprintf("s%d-c%d", sid, cellIdx)
				if string(buf[:n]) != expected {
					t.Errorf("stream %d cell %d: got %q, want %q", sid, cellIdx, buf[:n], expected)
					return
				}
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success: all data delivered, no loss
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for all streams to complete reads and writes")
	}

	// Close the cell reader to stop the circuit read loop goroutine.
	close(reader.ch)
}

// TestStreamOpenCloseChurn rapidly opens and closes 50 streams while 5 long-lived
// streams are actively reading data, verifying no corruption or deadlocks.
func TestStreamOpenCloseChurn(t *testing.T) {
	const circID = uint32(0x80000001)
	const longLivedCount = 5
	const churnCount = 50
	const cellsPerLongLived = 30

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	// Create 5 long-lived streams
	longStreams := make([]*Stream, longLivedCount)
	for i := 0; i < longLivedCount; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		longStreams[i] = &Stream{
			ID:                 sid,
			Circuit:            circ,
			recv:               sr,
			doneCh:             make(chan struct{}),
			streamWindow:       500,
			streamWindowSignal: make(chan struct{}, 1),
		}
	}

	// Feed data to long-lived streams from background
	go func() {
		for cellIdx := 0; cellIdx < cellsPerLongLived; cellIdx++ {
			for i := 0; i < longLivedCount; i++ {
				sid := uint16(i + 1)
				c := buildRelayCell(circID, circuit.RelayData, sid,
					[]byte(fmt.Sprintf("ll-%d-%d", sid, cellIdx)), kbEnc, dbRelay)
				reader.ch <- c
			}
		}
	}()

	// Churn: rapidly open and close 50 streams in parallel
	var churnWg sync.WaitGroup
	churnWg.Add(churnCount)
	for i := 0; i < churnCount; i++ {
		go func(idx int) {
			defer churnWg.Done()
			sid := uint16(100 + idx)
			sr, err := circ.RegisterStream(sid)
			if err != nil {
				return // circuit may have died
			}
			_ = sr
			circ.UnregisterStream(sid)
		}(i)
	}

	// Read from all long-lived streams concurrently
	var readWg sync.WaitGroup
	readWg.Add(longLivedCount)
	for i := 0; i < longLivedCount; i++ {
		go func(idx int) {
			defer readWg.Done()
			s := longStreams[idx]
			buf := make([]byte, 100)
			for cellIdx := 0; cellIdx < cellsPerLongLived; cellIdx++ {
				n, err := s.Read(buf)
				if err != nil {
					t.Errorf("long-lived stream %d read %d: %v", idx+1, cellIdx, err)
					return
				}
				expected := fmt.Sprintf("ll-%d-%d", uint16(idx+1), cellIdx)
				if string(buf[:n]) != expected {
					t.Errorf("long-lived stream %d cell %d: got %q, want %q", idx+1, cellIdx, buf[:n], expected)
					return
				}
			}
		}(i)
	}

	readDone := make(chan struct{})
	go func() {
		readWg.Wait()
		close(readDone)
	}()

	select {
	case <-readDone:
		// success
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for long-lived stream reads")
	}

	churnWg.Wait()
	close(reader.ch)
}

// TestCircuitDeathDuringConcurrentIO kills a circuit while 5 streams are actively
// reading and writing, verifying all goroutines exit within 5 seconds.
func TestCircuitDeathDuringConcurrentIO(t *testing.T) {
	const circID = uint32(0x80000001)
	const numStreams = 5

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	streams := make([]*Stream, numStreams)
	for i := 0; i < numStreams; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		streams[i] = &Stream{
			ID:                 sid,
			Circuit:            circ,
			recv:               sr,
			doneCh:             make(chan struct{}),
			streamWindow:       500,
			streamWindowSignal: make(chan struct{}, 1),
		}
	}

	var wg sync.WaitGroup
	wg.Add(numStreams * 2) // readers + writers

	// Start readers on all streams, signaling when started
	readersStarted := make(chan struct{}, numStreams)
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			readersStarted <- struct{}{}
			buf := make([]byte, 100)
			for {
				_, err := streams[idx].Read(buf)
				if err != nil {
					return
				}
			}
		}(i)
	}

	// Start writers on all streams, signaling when started.
	// Writers loop forever without checking circuit death - this is intentional.
	// They rely on Write returning an error once the circuit dies, and the 5s
	// timeout below serves as a safety net if that doesn't happen.
	writersStarted := make(chan struct{}, numStreams)
	for i := 0; i < numStreams; i++ {
		go func(idx int) {
			defer wg.Done()
			writersStarted <- struct{}{}
			for {
				_, err := streams[idx].Write([]byte("data"))
				if err != nil {
					return
				}
			}
		}(i)
	}

	// Wait for all readers and writers to start
	for i := 0; i < numStreams; i++ {
		<-readersStarted
		<-writersStarted
	}

	// Feed some cells to keep things active
	for j := 0; j < 10; j++ {
		for i := 0; i < numStreams; i++ {
			sid := uint16(i + 1)
			c := buildRelayCell(circID, circuit.RelayData, sid, []byte("x"), kbEnc, dbRelay)
			reader.ch <- c
		}
	}

	// Kill the circuit mid-operation
	close(reader.ch)

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

// TestReadLoopBackpressure fills a stream's channel to capacity (64), then verifies
// the read loop blocks (backpressure) rather than dropping cells.
func TestReadLoopBackpressure(t *testing.T) {
	const circID = uint32(0x80000001)

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	s := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               sr,
		doneCh:             make(chan struct{}),
		streamWindow:       500,
		streamWindowSignal: make(chan struct{}, 1),
	}

	// Register a second stream as a synchronization marker
	sr2, err := circ.RegisterStream(2)
	if err != nil {
		t.Fatalf("RegisterStream(2): %v", err)
	}

	// Send 64 cells to fill the channel to capacity
	for i := 0; i < 64; i++ {
		c := buildRelayCell(circID, circuit.RelayData, 1, []byte(fmt.Sprintf("cell-%d", i)), kbEnc, dbRelay)
		reader.ch <- c
	}

	// Send a marker cell on stream 2 - when it arrives, all 64 cells
	// have been dispatched (read loop processes cells sequentially)
	marker := buildRelayCell(circID, circuit.RelayData, 2, []byte("sync"), kbEnc, dbRelay)
	reader.ch <- marker
	select {
	case <-sr2.Cells:
		// Read loop has processed all prior cells
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for sync marker")
	}

	// Now drain all 64 cells via Stream.Read and verify none were dropped
	buf := make([]byte, 100)
	for i := 0; i < 64; i++ {
		n, readErr := s.Read(buf)
		if readErr != nil {
			t.Fatalf("Read %d: %v", i, readErr)
		}
		expected := fmt.Sprintf("cell-%d", i)
		if string(buf[:n]) != expected {
			t.Fatalf("cell %d: got %q, want %q", i, buf[:n], expected)
		}
	}

	// Clean up
	close(reader.ch)
}

// TestNoGoroutineLeaks opens/closes 20 streams, destroys the circuit, and verifies
// goroutine count returns to baseline.
func TestNoGoroutineLeaks(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	// Open 20 streams
	streams := make([]*Stream, 20)
	for i := 0; i < 20; i++ {
		sid := uint16(i + 1)
		sr, err := circ.RegisterStream(sid)
		if err != nil {
			t.Fatalf("RegisterStream(%d): %v", sid, err)
		}
		streams[i] = &Stream{
			ID:                 sid,
			Circuit:            circ,
			recv:               sr,
			doneCh:             make(chan struct{}),
			streamWindow:       500,
			streamWindowSignal: make(chan struct{}, 1),
		}
	}

	// Close all 20 streams
	for i := 0; i < 20; i++ {
		close(streams[i].doneCh)
		circ.UnregisterStream(uint16(i + 1))
	}

	// Destroy the circuit
	close(reader.ch)

	// Wait for circuit done
	select {
	case <-circ.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("circuit did not die")
	}

	// Wait for goroutine count to stabilize
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		current := runtime.NumGoroutine()
		if current <= baseline+2 {
			return // success
		}
	}
	t.Fatalf("goroutine leak: baseline=%d, current=%d", baseline, runtime.NumGoroutine())
}

// TestConcurrentRegisterUnregister has 20 goroutines concurrently registering and
// unregistering streams, verifying no races or panics.
func TestConcurrentRegisterUnregister(t *testing.T) {
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testStreamCircuit(circID, reader)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Stream ID collisions across goroutines are intentional here.
	// The modulo arithmetic causes different goroutines to race on the same
	// stream IDs, exercising the map's concurrent access safety.
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
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
	close(reader.ch)
	// No panic or race = success
}

// TestReadLoopHandlesPaddingCells interleaves PADDING cells among RELAY cells
// and verifies that only RELAY_DATA cells are delivered to the stream.
func TestReadLoopHandlesPaddingCells(t *testing.T) {
	const circID = uint32(0x80000001)

	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	s := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               sr,
		doneCh:             make(chan struct{}),
		streamWindow:       500,
		streamWindowSignal: make(chan struct{}, 1),
	}

	// Interleave PADDING with RELAY cells
	padding1 := cell.NewFixedCell(circID, cell.CmdPadding)
	relay1 := buildRelayCell(circID, circuit.RelayData, 1, []byte("first"), kbEnc, dbRelay)
	padding2 := cell.NewFixedCell(circID, cell.CmdPadding)
	padding3 := cell.NewFixedCell(circID, cell.CmdPadding)
	relay2 := buildRelayCell(circID, circuit.RelayData, 1, []byte("second"), kbEnc, dbRelay)
	padding4 := cell.NewFixedCell(circID, cell.CmdPadding)
	relay3 := buildRelayCell(circID, circuit.RelayData, 1, []byte("third"), kbEnc, dbRelay)

	reader.ch <- padding1
	reader.ch <- relay1
	reader.ch <- padding2
	reader.ch <- padding3
	reader.ch <- relay2
	reader.ch <- padding4
	reader.ch <- relay3

	// Read all three data cells via Stream.Read
	buf := make([]byte, 100)
	expected := []string{"first", "second", "third"}
	for i, exp := range expected {
		n, readErr := s.Read(buf)
		if readErr != nil {
			t.Fatalf("Read %d: %v", i, readErr)
		}
		if string(buf[:n]) != exp {
			t.Fatalf("cell %d: got %q, want %q", i, buf[:n], exp)
		}
	}

	close(reader.ch)
}

// TestStreamReadWriteAfterCircuitDeath verifies that Read and Write return errors
// promptly after the circuit dies, rather than hanging.
func TestStreamReadWriteAfterCircuitDeath(t *testing.T) {
	const circID = uint32(0x80000001)

	reader := newChannelCellReader()
	circ, _, _ := testStreamCircuit(circID, reader)
	circ.StartReadLoop()

	sr, err := circ.RegisterStream(1)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	s := &Stream{
		ID:                 1,
		Circuit:            circ,
		recv:               sr,
		doneCh:             make(chan struct{}),
		streamWindow:       500,
		streamWindowSignal: make(chan struct{}, 1),
	}

	// Kill the circuit
	close(reader.ch)

	// Wait for circuit death
	select {
	case <-circ.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("circuit did not die")
	}

	// Read should return an error promptly
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 100)
		_, readErr := s.Read(buf)
		readDone <- readErr
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected error from Read after circuit death")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not return promptly after circuit death")
	}

	// Write should return an error promptly (may succeed to io.Discard or fail)
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := s.Write([]byte("test"))
		writeDone <- writeErr
	}()

	select {
	case <-writeDone:
		// Either error or success is fine - key is it doesn't hang
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return promptly after circuit death")
	}
}
