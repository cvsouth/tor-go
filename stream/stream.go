package stream

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/cvsouth/tor-go/circuit"
)

var _ io.ReadWriteCloser = (*Stream)(nil)

// nextStreamID is a global atomic counter for stream ID allocation.
var nextStreamID atomic.Uint32

func init() {
	nextStreamID.Store(1)
}

const (
	relayEndReasonDone = 6
)

// Stream represents a Tor stream over a circuit.
type Stream struct {
	ID                 uint16
	Circuit            *circuit.Circuit
	CircWindow         int // Circuit-level send package window (init 1000)
	StreamWindow       int // Stream-level send package window (init 500)
	buf                []byte
	closed             bool
	eof                bool
	circDataReceived   int // DATA cells received since last circuit SENDME
	streamDataReceived int // DATA cells received since last stream SENDME
}

// Begin opens a new stream to the given target (host:port) through the circuit.
// It sends RELAY_BEGIN and waits for RELAY_CONNECTED.
func Begin(circ *circuit.Circuit, target string) (*Stream, error) {
	var id uint16
	for {
		raw := nextStreamID.Add(1) - 1
		id = uint16(raw)
		if id != 0 {
			break
		}
		// Prevent infinite loop on overflow — 65535 streams is the uint16 limit
		if raw > 0xFFFF {
			return nil, fmt.Errorf("stream ID space exhausted")
		}
	}

	// RELAY_BEGIN payload: "host:port\0" + flags(4 bytes, all zero)
	payload := make([]byte, len(target)+1+4)
	copy(payload, target)
	// null terminator and flags are already zero

	if err := circ.SendRelay(circuit.RelayBegin, id, payload); err != nil {
		return nil, fmt.Errorf("send RELAY_BEGIN: %w", err)
	}

	// Wait for RELAY_CONNECTED (or RELAY_END on failure)
	for {
		_, relayCmd, respStreamID, data, err := circ.ReceiveRelay()
		if err != nil {
			return nil, fmt.Errorf("receive relay response: %w", err)
		}

		// Ignore cells for other streams
		if respStreamID != id {
			continue
		}

		switch relayCmd {
		case circuit.RelayConnected:
			return &Stream{
				ID:           id,
				Circuit:      circ,
				CircWindow:   1000,
				StreamWindow: 500,
			}, nil
		case circuit.RelayEnd:
			reason := uint8(0)
			if len(data) > 0 {
				reason = data[0]
			}
			return nil, fmt.Errorf("stream rejected: RELAY_END reason=%d", reason)
		default:
			return nil, fmt.Errorf("unexpected relay command %d while waiting for CONNECTED", relayCmd)
		}
	}
}

// Write sends data through the stream as RELAY_DATA cells.
// Data is split into chunks of up to 498 bytes (MaxRelayDataLen).
// Respects send-side flow control windows.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("stream closed")
	}

	total := 0
	for len(p) > 0 {
		// Check send windows — if exhausted, we'd need to wait for SENDME.
		// For now, error if windows are exhausted (proper blocking requires
		// a concurrent read loop which will be added with stream multiplexing).
		if s.CircWindow <= 0 || s.StreamWindow <= 0 {
			return total, fmt.Errorf("send window exhausted (circ=%d, stream=%d)", s.CircWindow, s.StreamWindow)
		}

		chunk := p
		if len(chunk) > circuit.MaxRelayDataLen {
			chunk = p[:circuit.MaxRelayDataLen]
		}
		if err := s.Circuit.SendRelay(circuit.RelayData, s.ID, chunk); err != nil {
			return total, fmt.Errorf("send RELAY_DATA: %w", err)
		}
		s.CircWindow--
		s.StreamWindow--
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read receives data from the stream.
// It reads RELAY_DATA cells and buffers their contents.
func (s *Stream) Read(p []byte) (int, error) {
	if s.eof {
		return 0, io.EOF
	}
	if s.closed {
		return 0, fmt.Errorf("stream closed")
	}

	// Return buffered data first
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}

	// Read cells until we get data for this stream
	for {
		_, relayCmd, streamID, data, err := s.Circuit.ReceiveRelay()
		if err != nil {
			return 0, fmt.Errorf("receive relay: %w", err)
		}

		// Handle circuit-level SENDME (streamID=0)
		if relayCmd == circuit.RelaySendMe && streamID == 0 {
			s.CircWindow += 100
			continue
		}

		if streamID != s.ID {
			// Cell for a different stream — for now, discard
			// TODO: multiplex streams properly
			continue
		}

		switch relayCmd {
		case circuit.RelayData:
			if err := s.handleDataReceived(); err != nil {
				return 0, err
			}
			n := copy(p, data)
			if n < len(data) {
				s.buf = append(s.buf, data[n:]...)
			}
			return n, nil
		case circuit.RelayEnd:
			s.eof = true
			return 0, io.EOF
		case circuit.RelaySendMe:
			// Stream-level SENDME — relay is ready for more data
			s.StreamWindow += 50
			continue
		default:
			return 0, fmt.Errorf("unexpected relay command %d on stream", relayCmd)
		}
	}
}

// Close sends RELAY_END to close the stream.
func (s *Stream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.Circuit.SendRelay(circuit.RelayEnd, s.ID, []byte{relayEndReasonDone})
}
