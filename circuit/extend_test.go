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
	for i := range info.NodeID {
		info.NodeID[i] = byte(i)
	}

	var clientData [84]byte
	for i := range clientData {
		clientData[i] = byte(i + 100)
	}

	payload := buildExtend2Payload(info, clientData)

	if payload[0] != 2 {
		t.Fatalf("NSPEC = %d, want 2", payload[0])
	}

	off := 1
	off = checkIPv4Spec(t, payload, off)
	off = checkRSAIDSpec(t, payload, off)
	checkHandshakeData(t, payload, off, clientData)
}

func checkIPv4Spec(t *testing.T, payload []byte, off int) int {
	t.Helper()
	if payload[off] != LinkSpecIPv4 {
		t.Fatalf("spec[0] type = %d, want %d", payload[off], LinkSpecIPv4)
	}
	if payload[off+1] != 6 {
		t.Fatalf("spec[0] len = %d, want 6", payload[off+1])
	}
	off += 2
	if payload[off] != 1 || payload[off+1] != 2 || payload[off+2] != 3 || payload[off+3] != 4 {
		t.Fatalf("spec[0] IP = %v, want 1.2.3.4", payload[off:off+4])
	}
	port := binary.BigEndian.Uint16(payload[off+4:])
	if port != 9001 {
		t.Fatalf("spec[0] port = %d, want 9001", port)
	}
	return off + 6
}

func checkRSAIDSpec(t *testing.T, payload []byte, off int) int {
	t.Helper()
	if payload[off] != LinkSpecRSAID {
		t.Fatalf("spec[1] type = %d, want %d", payload[off], LinkSpecRSAID)
	}
	if payload[off+1] != 20 {
		t.Fatalf("spec[1] len = %d, want 20", payload[off+1])
	}
	off += 2
	for i := 0; i < 20; i++ {
		if payload[off+i] != byte(i) {
			t.Fatalf("spec[1] nodeID[%d] = %d, want %d", i, payload[off+i], i)
		}
	}
	return off + 20
}

func checkHandshakeData(t *testing.T, payload []byte, off int, clientData [84]byte) {
	t.Helper()
	htype := binary.BigEndian.Uint16(payload[off:])
	if htype != 0x0002 {
		t.Fatalf("HTYPE = 0x%04x, want 0x0002", htype)
	}
	hlen := binary.BigEndian.Uint16(payload[off+2:])
	if hlen != 84 {
		t.Fatalf("HLEN = %d, want 84", hlen)
	}
	off += 4
	for i := 0; i < 84; i++ {
		if payload[off+i] != clientData[i] {
			t.Fatalf("HDATA[%d] = %d, want %d", i, payload[off+i], clientData[i])
		}
	}
}
