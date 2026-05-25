package circuit

import (
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/link"
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

// TestReceiveExtended2Timeout verifies that receiveExtended2 returns a timeout
// error when no cell arrives, rather than blocking forever. This guards against
// regressing the hang that made TestE2ECircuitRetry consume the full test
// budget when a relay went silent mid-handshake.
func TestReceiveExtended2Timeout(t *testing.T) {
	const circID = uint32(0x80000001)
	l := &link.Link{Writer: cell.NewWriter(io.Discard)}
	cr, err := l.RegisterCircuit(circID)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	circ := &Circuit{
		ID:         circID,
		Link:       l,
		cellReader: cr,
		streams:    make(map[uint16]*StreamReceiver),
		done:       make(chan struct{}),
	}

	// Use a small deadline directly via receiveRelayBefore: receiveExtended2
	// hard-codes extendTimeout (30s), which is too long for a unit test.
	start := time.Now()
	_, _, _, _, _, err = circ.receiveRelayBefore(time.Now().Add(50 * time.Millisecond))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("receiveRelayBefore took %v, expected ~50ms", elapsed)
	}
}

// TestReceiveExtended2DeadlineUnblocksOnLinkDone verifies the deadline path
// still respects Done (link death) before the timeout fires.
func TestReceiveExtended2DeadlineUnblocksOnLinkDone(t *testing.T) {
	const circID = uint32(0x80000001)
	l := &link.Link{Writer: cell.NewWriter(io.Discard)}
	cr, err := l.RegisterCircuit(circID)
	if err != nil {
		t.Fatalf("RegisterCircuit: %v", err)
	}

	circ := &Circuit{
		ID:         circID,
		Link:       l,
		cellReader: cr,
		streams:    make(map[uint16]*StreamReceiver),
		done:       make(chan struct{}),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		l.UnregisterCircuit(circID) // closes cr.Done
	}()

	start := time.Now()
	_, _, _, _, _, err = circ.receiveRelayBefore(time.Now().Add(2 * time.Second))
	elapsed := time.Since(start)
	wg.Wait()

	if err == nil {
		t.Fatal("expected error from closed receiver, got nil")
	}
	if strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected receiver-done error, got timeout: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("receiveRelayBefore took %v, expected ~20ms", elapsed)
	}
}
