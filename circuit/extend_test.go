package circuit

import (
	"encoding/binary"
	"testing"

	"github.com/cvsouth/tor-go/descriptor"
)

func TestBuildExtend2Payload(t *testing.T) {
	info := &descriptor.RelayInfo{
		Address: "1.2.3.4",
		ORPort:  9001,
	}
	copy(info.NodeID[:], make([]byte, 20)) // zero nodeID for test
	for i := range info.NodeID {
		info.NodeID[i] = byte(i)
	}

	var clientData [84]byte
	for i := range clientData {
		clientData[i] = byte(i + 100)
	}

	payload := buildExtend2Payload(info, clientData)

	// Parse NSPEC
	if payload[0] != 2 { // IPv4 + RSA identity
		t.Fatalf("NSPEC = %d, want 2", payload[0])
	}

	off := 1

	// IPv4 spec: type=0x00, len=6, ip=1.2.3.4, port=9001
	if payload[off] != LinkSpecIPv4 {
		t.Fatalf("spec[0] type = %d, want %d", payload[off], LinkSpecIPv4)
	}
	off++
	if payload[off] != 6 {
		t.Fatalf("spec[0] len = %d, want 6", payload[off])
	}
	off++
	if payload[off] != 1 || payload[off+1] != 2 || payload[off+2] != 3 || payload[off+3] != 4 {
		t.Fatalf("spec[0] IP = %v, want 1.2.3.4", payload[off:off+4])
	}
	off += 4
	port := binary.BigEndian.Uint16(payload[off:])
	if port != 9001 {
		t.Fatalf("spec[0] port = %d, want 9001", port)
	}
	off += 2

	// RSA identity spec: type=0x02, len=20
	if payload[off] != LinkSpecRSAID {
		t.Fatalf("spec[1] type = %d, want %d", payload[off], LinkSpecRSAID)
	}
	off++
	if payload[off] != 20 {
		t.Fatalf("spec[1] len = %d, want 20", payload[off])
	}
	off++
	for i := 0; i < 20; i++ {
		if payload[off+i] != byte(i) {
			t.Fatalf("spec[1] nodeID[%d] = %d, want %d", i, payload[off+i], i)
		}
	}
	off += 20

	// HTYPE
	htype := binary.BigEndian.Uint16(payload[off:])
	if htype != 0x0002 {
		t.Fatalf("HTYPE = 0x%04x, want 0x0002", htype)
	}
	off += 2

	// HLEN
	hlen := binary.BigEndian.Uint16(payload[off:])
	if hlen != 84 {
		t.Fatalf("HLEN = %d, want 84", hlen)
	}
	off += 2

	// HDATA
	for i := 0; i < 84; i++ {
		if payload[off+i] != byte(i+100) {
			t.Fatalf("HDATA[%d] = %d, want %d", i, payload[off+i], i+100)
		}
	}
}
