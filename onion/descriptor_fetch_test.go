package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"
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

// waitForStream polls the circuit until exactly one stream is registered and returns
// its ID. Safe for use from goroutines (does not call t.Fatal).
func waitForStream(circ *circuit.Circuit, timeout time.Duration) (uint16, error) {
	deadline := time.After(timeout)
	for {
		ids := circ.StreamIDs()
		if len(ids) == 1 {
			if ids[0] == 0 {
				return 0, fmt.Errorf("registered stream ID is zero")
			}
			return ids[0], nil
		}
		select {
		case <-deadline:
			return 0, fmt.Errorf("timed out waiting for stream registration (found %d streams)", len(ids))
		default:
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func TestDescriptorFetchAllocatesUniqueStreamID(t *testing.T) {
	// Two consecutive calls to NextStreamID should return different non-zero IDs.
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

	// Use channels to communicate stream ID and errors from the goroutine.
	streamIDCh := make(chan uint16, 1)
	errCh := make(chan error, 1)

	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		streamIDCh <- sid

		connCell := buildRelayCell(circID, circuit.RelayConnected, sid, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		httpResp := []byte("HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\ntest")
		dataCell := buildRelayCell(circID, circuit.RelayData, sid, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	body, err := FetchDescriptorViaCircuit(circ, blindedKey)

	// Check for goroutine errors first.
	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err != nil {
		t.Fatalf("FetchDescriptorViaCircuit: %v", err)
	}
	if body != "test" {
		t.Fatalf("body = %q, want %q", body, "test")
	}

	// After the function returns, the stream should be unregistered.
	// Registering the same ID should succeed.
	sid := <-streamIDCh
	_, err = circ.RegisterStream(sid)
	if err != nil {
		t.Fatalf("re-registering stream %d after fetch: %v", sid, err)
	}
}

func TestDescriptorFetchUnregistersOnError(t *testing.T) {
	// When BEGIN_DIR is rejected, the stream should still be unregistered.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	streamIDCh := make(chan uint16, 1)
	errCh := make(chan error, 1)

	// Feed RELAY_END to reject BEGIN_DIR
	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		streamIDCh <- sid

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err == nil {
		t.Fatal("expected error when BEGIN_DIR is rejected")
	}

	// Stream should be unregistered after error.
	sid := <-streamIDCh
	_, regErr := circ.RegisterStream(sid)
	if regErr != nil {
		t.Fatalf("re-registering stream %d after error: %v", sid, regErr)
	}
}

func TestNoReceiveRelayExported(t *testing.T) {
	// Compilation-level check: ReceiveRelay is no longer exported.
	// The method is now ReceiveRelaySetup. This test verifies the rename
	// by calling ReceiveRelaySetup and confirming it exists.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testFetchCircuit(circID, reader)

	// ReceiveRelaySetup should work before StartReadLoop
	go func() {
		// time.Sleep is needed here because ReceiveRelaySetup blocks on
		// cellReader.ReadCell(), and we need to close the channel after
		// the call has started to unblock it. There is no registration
		// event to synchronize on since this tests pre-read-loop behavior.
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
	// When the circuit dies, the function should return an error.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, _, _ := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	errCh := make(chan error, 1)

	// Kill the circuit after the stream is registered.
	go func() {
		if _, err := waitForStream(circ, 2*time.Second); err != nil {
			errCh <- err
			return
		}
		close(reader.ch)
	}()

	var blindedKey [32]byte
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err == nil {
		t.Fatal("expected error when circuit dies")
	}
}

func TestDescriptorFetchNon200Status(t *testing.T) {
	// FetchDescriptorViaCircuit should return an error for non-200 HTTP responses.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	errCh := make(chan error, 1)
	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}

		connCell := buildRelayCell(circID, circuit.RelayConnected, sid, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		httpResp := []byte("HTTP/1.0 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found")
		dataCell := buildRelayCell(circID, circuit.RelayData, sid, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err == nil {
		t.Fatal("expected error for HTTP 404 response")
	}
}

func TestDescriptorFetchHTTP204Accepted(t *testing.T) {
	// HTTP 204 (No Content) is in the 200-299 range and should succeed.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	errCh := make(chan error, 1)
	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}

		connCell := buildRelayCell(circID, circuit.RelayConnected, sid, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		httpResp := []byte("HTTP/1.0 204 No Content\r\nContent-Length: 0\r\n\r\n")
		dataCell := buildRelayCell(circID, circuit.RelayData, sid, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	body, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err != nil {
		t.Fatalf("expected success for HTTP 204, got: %v", err)
	}
	if body != "" {
		t.Fatalf("expected empty body for 204, got %q", body)
	}
}

func TestDescriptorFetchHTTP500Rejected(t *testing.T) {
	// HTTP 500 is outside 200-299 and should fail.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	errCh := make(chan error, 1)
	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}

		connCell := buildRelayCell(circID, circuit.RelayConnected, sid, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		httpResp := []byte("HTTP/1.0 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror")
		dataCell := buildRelayCell(circID, circuit.RelayData, sid, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err == nil {
		t.Fatal("expected error for HTTP 500 response")
	}
}

func TestDescriptorFetchPreservesBodyData(t *testing.T) {
	// Verify that the body is returned exactly as received, without TrimRight
	// or any other data corruption.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	// Body with trailing whitespace, newlines, and null bytes that must be preserved.
	bodyContent := "data with trailing spaces  \n\r\n\x00"

	errCh := make(chan error, 1)
	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}

		connCell := buildRelayCell(circID, circuit.RelayConnected, sid, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		httpResp := []byte("HTTP/1.0 200 OK\r\nContent-Length: 31\r\n\r\n" + bodyContent)
		dataCell := buildRelayCell(circID, circuit.RelayData, sid, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	body, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != bodyContent {
		t.Fatalf("body corrupted: got %q, want %q", body, bodyContent)
	}
}

func TestDescriptorFetchURLPathContainsBlindedKey(t *testing.T) {
	// Verify FetchDescriptorViaCircuit constructs the correct URL path with
	// the base64-encoded blinded key. We test this indirectly: the HTTP 404
	// error message should contain the expected path and the encoded key.
	const circID = uint32(0x80000001)
	reader := newChannelCellReader()
	circ, kbEnc, dbRelay := testFetchCircuit(circID, reader)
	circ.StartReadLoop()

	errCh := make(chan error, 1)
	go func() {
		sid, err := waitForStream(circ, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}

		connCell := buildRelayCell(circID, circuit.RelayConnected, sid, nil, kbEnc, dbRelay)
		reader.ch <- connCell

		httpResp := []byte("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
		dataCell := buildRelayCell(circID, circuit.RelayData, sid, httpResp, kbEnc, dbRelay)
		reader.ch <- dataCell

		endCell := buildRelayCell(circID, circuit.RelayEnd, sid, nil, kbEnc, dbRelay)
		reader.ch <- endCell
	}()

	var blindedKey [32]byte
	for i := range blindedKey {
		blindedKey[i] = byte(i)
	}
	_, err := FetchDescriptorViaCircuit(circ, blindedKey)

	select {
	case gErr := <-errCh:
		t.Fatalf("goroutine error: %v", gErr)
	default:
	}

	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}

	errMsg := err.Error()
	// The error message should contain "/tor/hs/3/"
	if !strings.Contains(errMsg, "/tor/hs/3/") {
		t.Fatalf("expected error to contain /tor/hs/3/, got: %v", errMsg)
	}
	// The error message should contain the base64-encoded blinded key.
	expectedB64 := base64.RawStdEncoding.EncodeToString(blindedKey[:])
	if !strings.Contains(errMsg, expectedB64) {
		t.Fatalf("expected error to contain base64-encoded blinded key %q, got: %v", expectedB64, errMsg)
	}
}
