package stream

import (
	"encoding/binary"
	"testing"

	"github.com/cvsouth/tor-go/circuit"
)

func TestSendMeV1Payload(t *testing.T) {
	digest := make([]byte, 20)
	for i := range digest {
		digest[i] = byte(i + 0xA0)
	}

	payload, err := circuit.SendMeV1(digest)
	if err != nil {
		t.Fatalf("SendMeV1: %v", err)
	}

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

func TestSendMeV1NilDigest(t *testing.T) {
	// SendMeV1 must return an error with nil digest.
	_, err := circuit.SendMeV1(nil)
	if err == nil {
		t.Fatal("expected error for nil digest")
	}
}

func TestSendMeV1ShortDigest(t *testing.T) {
	// SendMeV1 must return an error with a digest shorter than 20 bytes.
	short := []byte{0xAA, 0xBB, 0xCC}
	_, err := circuit.SendMeV1(short)
	if err == nil {
		t.Fatal("expected error for short digest")
	}
}

func TestFlowControlConstants(t *testing.T) {
	if streamSendMeWindow != 50 {
		t.Fatalf("streamSendMeWindow = %d, want 50", streamSendMeWindow)
	}
	if initStreamWindow != 500 {
		t.Fatalf("initStreamWindow = %d, want 500", initStreamWindow)
	}
}
