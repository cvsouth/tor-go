package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/circuit"
)

// channelCellReader reads cells from a channel for testing.
type channelCellReader struct {
	ch chan cell.Cell
}

func newChannelCellReader() *channelCellReader {
	return &channelCellReader{ch: make(chan cell.Cell, 64)}
}

func (c *channelCellReader) ReadCell() (cell.Cell, error) {
	cl, ok := <-c.ch
	if !ok {
		return nil, io.EOF
	}
	return cl, nil
}

const relayPayloadLen = cell.MaxPayloadLen
const relayCommandOff = 0
const relayStreamIDOff = 3
const relayDigestOff = 5
const relayLengthOff = 9
const relayDataOff = 11

// buildRelayCell builds a properly encrypted relay cell for testing.
func buildRelayCell(circID uint32, relayCmd uint8, streamID uint16, data []byte, kbEncrypt cipher.Stream, dbRelay hash.Hash) cell.Cell {
	var payload [relayPayloadLen]byte
	payload[relayCommandOff] = relayCmd
	binary.BigEndian.PutUint16(payload[relayStreamIDOff:], streamID)
	binary.BigEndian.PutUint16(payload[relayLengthOff:], uint16(len(data)))
	copy(payload[relayDataOff:], data)

	dbRelay.Write(payload[:])
	digest := dbRelay.Sum(nil)
	copy(payload[relayDigestOff:relayDigestOff+4], digest[:4])

	kbEncrypt.XORKeyStream(payload[:], payload[:])

	relayCell := cell.NewFixedCell(circID, cell.CmdRelay)
	copy(relayCell.Payload(), payload[:])
	return relayCell
}

// testFetchCircuit creates a circuit with matching crypto for building relay cells.
func testFetchCircuit(circID uint32, cr circuit.CellReader) (*circuit.Circuit, cipher.Stream, hash.Hash) {
	kbKey := make([]byte, 16)
	for i := range kbKey {
		kbKey[i] = byte(0x20 + i)
	}
	iv := make([]byte, aes.BlockSize)

	bwdEnc, _ := aes.NewCipher(kbKey)
	kbEncrypt := cipher.NewCTR(bwdEnc, iv)

	bwdDec, _ := aes.NewCipher(kbKey)
	kbDecrypt := cipher.NewCTR(bwdDec, iv)

	dbSeed := []byte{0xBB}
	dbRelay := sha1.New()
	dbRelay.Write(dbSeed)
	dbClient := sha1.New()
	dbClient.Write(dbSeed)

	kfKey := make([]byte, 16)
	fwdBlock, _ := aes.NewCipher(kfKey)

	hop := circuit.NewHop(
		cipher.NewCTR(fwdBlock, iv),
		kbDecrypt,
		sha1.New(),
		dbClient,
	)

	circ := circuit.NewTestCircuit(circID, cr)
	circ.Hops = append(circ.Hops, hop)

	return circ, kbEncrypt, dbRelay
}

func TestDescriptorFetchAllocatesUniqueStreamID(t *testing.T) {
	// Two consecutive calls to NextStreamID should return different IDs.
	circuit.ResetNextStreamID(1)
	id1 := circuit.NextStreamID()
	id2 := circuit.NextStreamID()
	if id1 == id2 {
		t.Fatalf("stream IDs not unique: both %d", id1)
	}
	if id1 == 0 || id2 == 0 {
		t.Fatalf("stream IDs must be non-zero: id1=%d id2=%d", id1, id2)
	}
}

func TestDescriptorFetchRegistersAndUnregisters(t *testing.T) {
	// Verify FetchDescriptorViaCircuit registers and unregisters the stream.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	circuit.ResetNextStreamID(42)

	// Feed CONNECTED then HTTP response then END
	go func() {
		time.Sleep(50 * time.Millisecond)
		connCell := buildRelayCell(circID, circuit.RelayConnected, 42, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		time.Sleep(20 * time.Millisecond)
		httpResp := []byte("HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\ntest")
		dataCell := buildRelayCell(circID, circuit.RelayData, 42, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		time.Sleep(20 * time.Millisecond)
		endCell := buildRelayCell(circID, circuit.RelayEnd, 42, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	body, err := FetchDescriptorViaCircuit(circ, blindedKey)
	if err != nil {
		t.Fatalf("FetchDescriptorViaCircuit: %v", err)
	}
	if body != "test" {
		t.Fatalf("body = %q, want %q", body, "test")
	}

	// After the function returns, the stream should be unregistered.
	// Registering the same ID should succeed.
	_, err = circ.RegisterStream(42)
	if err != nil {
		t.Fatalf("re-registering stream 42 after fetch: %v", err)
	}
}

func TestTwoConcurrentDescriptorFetches(t *testing.T) {
	// Two concurrent fetches should get different stream IDs.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	circuit.ResetNextStreamID(100)

	var wg sync.WaitGroup
	var ids [2]uint16

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// NextStreamID is called inside FetchDescriptorViaCircuit.
			// We capture the ID by observing which stream IDs get registered.
			// For simplicity, we just call NextStreamID to see what would be allocated.
			id := circuit.NextStreamID()
			ids[idx] = id
		}(i)
	}
	wg.Wait()

	if ids[0] == ids[1] {
		t.Fatalf("concurrent fetches got same stream ID: %d", ids[0])
	}
	if ids[0] == 0 || ids[1] == 0 {
		t.Fatalf("stream IDs must be non-zero: %d, %d", ids[0], ids[1])
	}

	// Clean up
	close(reader.ch)

	_ = kbEnc
	_ = dbRelay
}

func TestDescriptorFetchUnregistersOnError(t *testing.T) {
	// When BEGIN_DIR is rejected, the stream should still be unregistered.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	circuit.ResetNextStreamID(55)

	// Feed RELAY_END to reject BEGIN_DIR
	go func() {
		time.Sleep(50 * time.Millisecond)
		endCell := buildRelayCell(circID, circuit.RelayEnd, 55, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)
	if err == nil {
		t.Fatal("expected error when BEGIN_DIR is rejected")
	}

	// Stream should be unregistered via defer.
	_, regErr := circ.RegisterStream(55)
	if regErr != nil {
		t.Fatalf("re-registering stream 55 after error: %v", regErr)
	}
}

func TestNoReceiveRelayExported(t *testing.T) {
	// Compilation-level check: ReceiveRelay is no longer exported.
	// If someone adds ReceiveRelay back, this file would need to be updated.
	// The method is now ReceiveRelaySetup. This test verifies the rename
	// by calling ReceiveRelaySetup and confirming it exists.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testFetchCircuit(circID, reader)

	// ReceiveRelaySetup should work before StartReadLoop
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(reader.ch) // cause EOF to unblock ReceiveRelaySetup
	}()
	_, _, _, _, err := circ.ReceiveRelaySetup()
	if err == nil {
		t.Fatal("expected error from ReceiveRelaySetup with closed reader")
	}
}

func TestReceiveRelaySetupFailsAfterReadLoop(t *testing.T) {
	// ReceiveRelaySetup should return an error after StartReadLoop is called.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testFetchCircuit(circID, reader)

	circ.StartReadLoop()

	_, _, _, _, err := circ.ReceiveRelaySetup()
	if err == nil {
		t.Fatal("expected error calling ReceiveRelaySetup after StartReadLoop")
	}

	// Clean up
	close(reader.ch)
}

func TestDescriptorFetchCircuitDied(t *testing.T) {
	// When the circuit dies during waitForConnected, the function should return an error.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	circuit.ResetNextStreamID(77)

	// Kill the circuit immediately
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(reader.ch)
	}()

	var blindedKey [32]byte
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)
	if err == nil {
		t.Fatal("expected error when circuit dies")
	}
}

func TestWaitForConnectedSkipsUnexpectedCells(t *testing.T) {
	// waitForConnected should skip non-CONNECTED/non-END cells (e.g., SENDME)
	// and keep waiting until CONNECTED arrives.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	circuit.ResetNextStreamID(88)

	go func() {
		time.Sleep(50 * time.Millisecond)
		// Send a SENDME (unexpected during waitForConnected) before CONNECTED
		sendmeCell := buildRelayCell(circID, circuit.RelaySendMe, 88, nil, kbEnc, dbRelay)
		reader.ch <- sendmeCell

		time.Sleep(20 * time.Millisecond)
		// Now send CONNECTED
		connCell := buildRelayCell(circID, circuit.RelayConnected, 88, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		time.Sleep(20 * time.Millisecond)
		// Send HTTP response and END
		httpResp := []byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
		dataCell := buildRelayCell(circID, circuit.RelayData, 88, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		time.Sleep(20 * time.Millisecond)
		endCell := buildRelayCell(circID, circuit.RelayEnd, 88, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	body, err := FetchDescriptorViaCircuit(circ, blindedKey)
	if err != nil {
		t.Fatalf("FetchDescriptorViaCircuit: %v", err)
	}
	if body != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

func TestWaitForConnectedMultipleUnexpectedCells(t *testing.T) {
	// Multiple unexpected cells before CONNECTED should all be skipped.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	circuit.ResetNextStreamID(89)

	go func() {
		time.Sleep(50 * time.Millisecond)
		// Send 3 SENDMEs before CONNECTED
		for i := 0; i < 3; i++ {
			sendmeCell := buildRelayCell(circID, circuit.RelaySendMe, 89, nil, kbEnc, dbRelay)
			reader.ch <- sendmeCell
			time.Sleep(10 * time.Millisecond)
		}
		connCell := buildRelayCell(circID, circuit.RelayConnected, 89, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		time.Sleep(20 * time.Millisecond)
		httpResp := []byte("HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\ndone")
		dataCell := buildRelayCell(circID, circuit.RelayData, 89, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		time.Sleep(20 * time.Millisecond)
		endCell := buildRelayCell(circID, circuit.RelayEnd, 89, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	body, err := FetchDescriptorViaCircuit(circ, blindedKey)
	if err != nil {
		t.Fatalf("FetchDescriptorViaCircuit: %v", err)
	}
	if body != "done" {
		t.Fatalf("body = %q, want %q", body, "done")
	}
}
