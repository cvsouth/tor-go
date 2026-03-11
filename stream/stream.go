package stream

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cvsouth/tor-go/circuit"
)

var _ io.ReadWriteCloser = (*Stream)(nil)

const (
	relayEndReasonDone = 6
)

// streamWindowTimeout is how long Write blocks waiting for a SENDME before giving up.
const streamWindowTimeout = 30 * time.Second

// beginTimeout is how long Begin waits for RELAY_CONNECTED before giving up.
const beginTimeout = 30 * time.Second

// Stream represents a Tor stream over a circuit.
type Stream struct {
	ID      uint16
	Circuit *circuit.Circuit
	buf     []byte
	closed  atomic.Bool
	eof     bool
	recv    *circuit.StreamReceiver // per-stream cell channel from circuit dispatch
	doneCh  chan struct{}           // stream-level done signaling

	closeOnce sync.Once // ensures doneCh is closed exactly once

	// Flow control (protected by windowMu)
	windowMu           sync.Mutex
	streamWindow       int           // Stream-level send package window (init 500)
	streamWindowSignal chan struct{} // buffered(1), signaled when stream SENDME received

	streamDataReceived int // only accessed from Read goroutine, no mutex needed
}

// Begin opens a new stream to the given target (host:port) through the circuit.
// It sends RELAY_BEGIN and waits for RELAY_CONNECTED.
func Begin(circ *circuit.Circuit, target string) (*Stream, error) {
	id := circuit.NextStreamID()

	// Register with circuit dispatch BEFORE sending RELAY_BEGIN
	recv, err := circ.RegisterStream(id)
	if err != nil {
		return nil, fmt.Errorf("register stream: %w", err)
	}

	// RELAY_BEGIN payload: "host:port\0" + flags(4 bytes, all zero)
	payload := make([]byte, len(target)+1+4)
	copy(payload, target)
	// null terminator and flags are already zero

	if err := circ.SendRelay(circuit.RelayBegin, id, payload); err != nil {
		circ.UnregisterStream(id)
		return nil, fmt.Errorf("send RELAY_BEGIN: %w", err)
	}

	// Wait for RELAY_CONNECTED (or RELAY_END on failure)
	select {
	case rc, ok := <-recv.Cells:
		if !ok {
			circ.UnregisterStream(id)
			return nil, fmt.Errorf("stream channel closed while waiting for CONNECTED")
		}
		switch rc.Cmd {
		case circuit.RelayConnected:
			return &Stream{
				ID:                 id,
				Circuit:            circ,
				streamWindow:       initStreamWindow,
				streamWindowSignal: make(chan struct{}, 1),
				recv:               recv,
				doneCh:             make(chan struct{}),
			}, nil
		case circuit.RelayEnd:
			circ.UnregisterStream(id)
			reason := uint8(0)
			if len(rc.Data) > 0 {
				reason = rc.Data[0]
			}
			return nil, fmt.Errorf("stream rejected: RELAY_END reason=%d", reason)
		default:
			circ.UnregisterStream(id)
			return nil, fmt.Errorf("unexpected relay command %d while waiting for CONNECTED", rc.Cmd)
		}
	case <-recv.Done:
		circ.UnregisterStream(id)
		return nil, fmt.Errorf("circuit died while waiting for CONNECTED")
	case <-time.After(beginTimeout):
		circ.UnregisterStream(id)
		return nil, fmt.Errorf("timeout waiting for RELAY_CONNECTED")
	}
}

// Write sends data through the stream as RELAY_DATA cells.
// Data is split into chunks of up to 498 bytes (MaxRelayDataLen).
// Respects send-side flow control windows. Blocks when either the stream-level
// or circuit-level window is exhausted, waiting for SENDMEs to arrive via Read.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	total := 0
	for len(p) > 0 {
		// Wait for stream-level window, then atomically check-and-decrement
		// to avoid TOCTOU: another writer could consume the window between
		// waitStreamWindow returning and the decrement.
		for {
			if err := s.waitStreamWindow(); err != nil {
				return total, err
			}
			s.windowMu.Lock()
			if s.streamWindow <= 0 {
				s.windowMu.Unlock()
				continue // retry the wait
			}
			s.streamWindow--
			s.windowMu.Unlock()
			break
		}

		// Wait for circuit-level window, then atomically check-and-decrement
		for {
			if err := s.Circuit.WaitCircuitWindow(s.doneCh); err != nil {
				// Restore stream window credit since we already decremented it
				s.windowMu.Lock()
				s.streamWindow++
				s.windowMu.Unlock()
				return total, err
			}
			if s.Circuit.TryDecrementCircuitWindow() {
				break
			}
			// Window was consumed by another writer - retry
		}

		chunk := p
		if len(chunk) > circuit.MaxRelayDataLen {
			chunk = p[:circuit.MaxRelayDataLen]
		}
		if err := s.Circuit.SendRelay(circuit.RelayData, s.ID, chunk); err != nil {
			// Restore both window credits since send failed after both were decremented
			s.windowMu.Lock()
			s.streamWindow++
			s.windowMu.Unlock()
			s.Circuit.RestoreCircuitWindow()
			return total, fmt.Errorf("send RELAY_DATA: %w", err)
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// waitStreamWindow blocks until streamWindow > 0 or the stream/circuit dies or times out.
func (s *Stream) waitStreamWindow() error {
	timer := time.NewTimer(streamWindowTimeout)
	defer timer.Stop()

	for {
		s.windowMu.Lock()
		w := s.streamWindow
		s.windowMu.Unlock()
		if w > 0 {
			// Re-signal in case other writers are also waiting
			select {
			case s.streamWindowSignal <- struct{}{}:
			default:
			}
			return nil
		}
		select {
		case <-s.streamWindowSignal:
			// Stream window may have been replenished - re-check
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(streamWindowTimeout)
			continue
		case <-s.recv.Done:
			return fmt.Errorf("circuit died while waiting for stream window")
		case <-s.doneCh:
			return fmt.Errorf("stream closed while waiting for stream window")
		case <-timer.C:
			return fmt.Errorf("timeout waiting for stream window")
		}
	}
}

// Read receives data from the stream.
// It reads RELAY_DATA cells from the per-stream channel and buffers their contents.
//
// Read is NOT safe for concurrent use from multiple goroutines. The internal
// buffer (s.buf) and other read state are not synchronized. Callers must
// serialize access externally if needed. This is standard for io.Reader.
func (s *Stream) Read(p []byte) (int, error) {
	if s.eof {
		return 0, io.EOF
	}
	if s.closed.Load() {
		return 0, io.EOF
	}

	// Return buffered data first
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}

	// Read from per-stream channel, looping on SENDME cells.
	// Uses a two-phase approach to avoid losing buffered cells when
	// a done channel fires concurrently with pending cell data.
	for {
		// Phase 1: drain buffered cells first (non-blocking)
		select {
		case rc, ok := <-s.recv.Cells:
			if n, err, done := s.receiveCell(p, rc, ok); done {
				return n, err
			}
			continue // SENDME - loop again
		default:
		}

		// Phase 2: blocking wait (includes done channels)
		select {
		case rc, ok := <-s.recv.Cells:
			if n, err, done := s.receiveCell(p, rc, ok); done {
				return n, err
			}
			continue // SENDME - loop again
		case <-s.recv.Done:
			// Circuit died - drain any remaining buffered cells before giving up
			select {
			case rc, ok := <-s.recv.Cells:
				if n, err, done := s.receiveCell(p, rc, ok); done {
					return n, err
				}
			default:
			}
			return 0, fmt.Errorf("stream or circuit closed during read")
		case <-s.doneCh:
			return 0, fmt.Errorf("stream closed during read")
		}
	}
}

// receiveCell processes a single cell read from the recv.Cells channel.
// Returns (n, err, done=true) when the caller should return (n, err),
// or (0, nil, false) when the caller should continue looping (e.g., SENDME).
func (s *Stream) receiveCell(p []byte, rc circuit.RelayCell, ok bool) (int, error, bool) {
	if !ok {
		return 0, io.EOF, true
	}
	n, err := s.handleRelayCell(p, rc)
	if err != nil {
		return n, err, true
	}
	return n, nil, n > 0
}

// handleRelayCell processes a single relay cell received during Read.
// Returns (n, nil) with n > 0 for data cells, (0, nil) for SENDME cells
// (caller should continue looping), or (0, err) for errors.
func (s *Stream) handleRelayCell(p []byte, rc circuit.RelayCell) (int, error) {
	switch rc.Cmd {
	case circuit.RelayData:
		if err := s.handleDataReceived(rc.Digest); err != nil {
			return 0, err
		}
		n := copy(p, rc.Data)
		if n < len(rc.Data) {
			s.buf = append(s.buf, rc.Data[n:]...)
		}
		return n, nil
	case circuit.RelayEnd:
		s.eof = true
		return 0, io.EOF
	case circuit.RelaySendMe:
		s.windowMu.Lock()
		s.streamWindow += streamSendMeWindow
		s.windowMu.Unlock()
		// Signal any writer waiting on stream window (non-blocking)
		select {
		case s.streamWindowSignal <- struct{}{}:
		default:
		}
		return 0, nil // signal caller to continue
	default:
		return 0, fmt.Errorf("unexpected relay command %d on stream", rc.Cmd)
	}
}

// StreamWindow returns the current stream-level send window (for testing/diagnostics).
func (s *Stream) StreamWindow() int {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	return s.streamWindow
}

// Close sends RELAY_END to close the stream.
func (s *Stream) Close() error {
	if s.closed.Swap(true) {
		return nil // already closed
	}

	// Signal stream-level done (idempotent via sync.Once)
	s.closeOnce.Do(func() {
		close(s.doneCh)
	})

	err := s.Circuit.SendRelay(circuit.RelayEnd, s.ID, []byte{relayEndReasonDone})
	s.Circuit.UnregisterStream(s.ID)
	return err
}
