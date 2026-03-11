package stream

import (
	"fmt"

	"github.com/cvsouth/tor-go/circuit"
)

const (
	// Stream-level SENDME every 50 DATA cells received
	streamSendMeWindow = 50
	// Initial stream window
	initStreamWindow = 500
)

// handleDataReceived tracks flow control for received DATA cells.
// Call this after receiving each RELAY_DATA cell.
// Only handles stream-level SENDME - circuit-level SENDME is handled by the circuit read loop.
// The digest parameter is the backward digest snapshot from the RelayCell.
func (s *Stream) handleDataReceived(digest []byte) error {
	s.streamDataReceived++

	// Stream-level SENDME every 50 DATA cells
	if s.streamDataReceived >= streamSendMeWindow {
		payload, err := circuit.SendMeV1(digest)
		if err != nil {
			return fmt.Errorf("stream SENDME digest: %w", err)
		}
		if err := s.Circuit.SendRelay(circuit.RelaySendMe, s.ID, payload); err != nil {
			return fmt.Errorf("send stream SENDME: %w", err)
		}
		s.streamDataReceived = 0
	}

	return nil
}
