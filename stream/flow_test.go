package stream

import (
	"encoding/binary"
	"testing"
)

func TestSendMeV1Payload(t *testing.T) {
	digest := make([]byte, 20)
	for i := range digest {
		digest[i] = byte(i + 0xA0)
	}

	payload := sendMeV1(digest)

	// Version byte
	if payload[0] != 1 {
		t.Fatalf("version = %d, want 1", payload[0])
	}

	// Data length
	dataLen := binary.BigEndian.Uint16(payload[1:3])
	if dataLen != 20 {
		t.Fatalf("data length = %d, want 20", dataLen)
	}

	// Digest data
	for i := 0; i < 20; i++ {
		if payload[3+i] != byte(i+0xA0) {
			t.Fatalf("digest[%d] = %d, want %d", i, payload[3+i], i+0xA0)
		}
	}

	// Total length
	if len(payload) != 23 {
		t.Fatalf("payload length = %d, want 23", len(payload))
	}
}

func TestFlowControlConstants(t *testing.T) {
	if circSendMeWindow != 100 {
		t.Fatalf("circSendMeWindow = %d, want 100", circSendMeWindow)
	}
	if streamSendMeWindow != 50 {
		t.Fatalf("streamSendMeWindow = %d, want 50", streamSendMeWindow)
	}
	if initCircWindow != 1000 {
		t.Fatalf("initCircWindow = %d, want 1000", initCircWindow)
	}
	if initStreamWindow != 500 {
		t.Fatalf("initStreamWindow = %d, want 500", initStreamWindow)
	}
}
