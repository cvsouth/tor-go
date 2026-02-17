package stream

import (
	"encoding/binary"
	"fmt"

	"github.com/cvsouth/tor-go/circuit"
)

const (
	// Circuit-level SENDME every 100 DATA cells received
	circSendMeWindow = 100
	// Stream-level SENDME every 50 DATA cells received
	streamSendMeWindow = 50
	// Initial circuit window
	initCircWindow = 1000
	// Initial stream window
	initStreamWindow = 500
	// SENDME v1 version byte
	sendMeVersion = 1
)

// sendMeV1 builds a SENDME v1 payload with the given digest.
func sendMeV1(digest []byte) []byte {
	// Version(1) + DataLen(2) + Data(20)
	payload := make([]byte, 23)
	payload[0] = sendMeVersion
	binary.BigEndian.PutUint16(payload[1:3], 20) // digest length
	copy(payload[3:23], digest[:20])
	return payload
}

// handleDataReceived tracks flow control for received DATA cells.
// Call this after receiving each RELAY_DATA cell.
func (s *Stream) handleDataReceived() error {
	s.circDataReceived++
	s.streamDataReceived++

	// Circuit-level SENDME (streamID=0) every 100 DATA cells
	if s.circDataReceived >= circSendMeWindow {
		// Get the current backward digest for SENDME v1
		digest := s.Circuit.BackwardDigest()
		payload := sendMeV1(digest)
		if err := s.Circuit.SendRelay(circuit.RelaySendMe, 0, payload); err != nil {
			return fmt.Errorf("send circuit SENDME: %w", err)
		}
		s.CircWindow += circSendMeWindow
		s.circDataReceived = 0
	}

	// Stream-level SENDME every 50 DATA cells
	if s.streamDataReceived >= streamSendMeWindow {
		digest := s.Circuit.BackwardDigest()
		payload := sendMeV1(digest)
		if err := s.Circuit.SendRelay(circuit.RelaySendMe, s.ID, payload); err != nil {
			return fmt.Errorf("send stream SENDME: %w", err)
		}
		s.StreamWindow += streamSendMeWindow
		s.streamDataReceived = 0
	}

	return nil
}
