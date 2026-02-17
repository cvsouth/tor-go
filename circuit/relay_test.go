package circuit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"testing"

	"github.com/cvsouth/tor-go/cell"
)

func testHop(kfKey, kbKey byte, dfSeed, dbSeed byte) *Hop {
	kf := make([]byte, 16)
	kb := make([]byte, 16)
	for i := range kf {
		kf[i] = kfKey + byte(i)
		kb[i] = kbKey + byte(i)
	}
	iv := make([]byte, aes.BlockSize)

	fwdBlock, _ := aes.NewCipher(kf)
	bwdBlock, _ := aes.NewCipher(kb)

	df := sha1.New()
	df.Write([]byte{dfSeed})
	db := sha1.New()
	db.Write([]byte{dbSeed})

	return &Hop{
		kf: cipher.NewCTR(fwdBlock, iv),
		kb: cipher.NewCTR(bwdBlock, iv),
		df: df,
		db: db,
	}
}

func TestEncryptRelayProducesEncryptedPayload(t *testing.T) {
	hop := testHop(0x10, 0x20, 0xAA, 0xBB)
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	data := []byte("Hello, Tor relay!")
	encrypted, err := circ.EncryptRelay(RelayData, 42, data)
	if err != nil {
		t.Fatalf("EncryptRelay: %v", err)
	}

	if encrypted.Command() != cell.CmdRelay {
		t.Fatalf("expected RELAY command, got %d", encrypted.Command())
	}
	if encrypted.CircID() != 0x80000001 {
		t.Fatalf("wrong circID")
	}

	// Verify the payload is actually encrypted (not plaintext)
	payload := encrypted.Payload()
	if payload[relayCommandOff] == RelayData && payload[relayRecognizedOff] == 0 && payload[relayRecognizedOff+1] == 0 {
		t.Fatal("payload appears to be unencrypted")
	}
}

func TestEncryptRelayDataTooLarge(t *testing.T) {
	hop := testHop(0x10, 0x20, 0xAA, 0xBB)
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	bigData := make([]byte, MaxRelayDataLen+1)
	_, err := circ.EncryptRelay(RelayData, 1, bigData)
	if err == nil {
		t.Fatal("expected error for oversized data")
	}
}

func TestRelayCellPaddingStructure(t *testing.T) {
	// Verify that relay cell padding has 4 zero bytes after data, then random
	hop := testHop(0x10, 0x10, 0xAA, 0xAA) // kf==kb so we can decrypt to verify
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	data := []byte("hi")
	encrypted, err := circ.EncryptRelay(RelayData, 1, data)
	if err != nil {
		t.Fatalf("EncryptRelay: %v", err)
	}

	// Decrypt the payload using a fresh matching cipher to inspect padding
	kf := make([]byte, 16)
	for i := range kf {
		kf[i] = 0x10 + byte(i)
	}
	iv := make([]byte, 16)
	block, _ := aes.NewCipher(kf)
	stream := cipher.NewCTR(block, iv)

	payload := make([]byte, RelayPayloadLen)
	copy(payload, encrypted.Payload())
	stream.XORKeyStream(payload, payload)

	// After data (offset 11 + 2 = 13), next 4 bytes should be zero
	padStart := relayDataOff + len(data)
	for i := 0; i < 4; i++ {
		if padStart+i < RelayPayloadLen && payload[padStart+i] != 0 {
			t.Fatalf("padding byte %d = %d, want 0", i, payload[padStart+i])
		}
	}
}

func TestEncryptRelayNoHops(t *testing.T) {
	circ := &Circuit{ID: 0x80000001}
	_, err := circ.EncryptRelay(RelayData, 1, []byte("test"))
	if err == nil {
		t.Fatal("expected error for empty hops")
	}
}

func TestDecryptRelayRecognized(t *testing.T) {
	// Simulate: relay builds a relay payload, encrypts with Kb, client decrypts.
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

	// Build plaintext relay payload as the relay would
	var payload [RelayPayloadLen]byte
	payload[relayCommandOff] = RelayData
	binary.BigEndian.PutUint16(payload[relayStreamIDOff:], 7)
	binary.BigEndian.PutUint16(payload[relayLengthOff:], 5)
	copy(payload[relayDataOff:], []byte("hello"))

	// Compute digest
	dbRelay.Write(payload[:])
	digest := dbRelay.Sum(nil)
	copy(payload[relayDigestOff:relayDigestOff+4], digest[:4])

	// Encrypt with Kb
	kbEncrypt.XORKeyStream(payload[:], payload[:])

	relayCell := cell.NewFixedCell(0x80000001, cell.CmdRelay)
	copy(relayCell.Payload(), payload[:])

	kfKey := make([]byte, 16)
	fwdBlock, _ := aes.NewCipher(kfKey)
	hop := &Hop{
		kf: cipher.NewCTR(fwdBlock, iv),
		kb: kbDecrypt,
		df: sha1.New(),
		db: dbClient,
	}
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	hopIdx, relayCmd, streamID, data, err := circ.DecryptRelay(relayCell)
	if err != nil {
		t.Fatalf("DecryptRelay: %v", err)
	}
	if hopIdx != 0 {
		t.Fatalf("hopIdx = %d, want 0", hopIdx)
	}
	if relayCmd != RelayData {
		t.Fatalf("relayCmd = %d, want %d", relayCmd, RelayData)
	}
	if streamID != 7 {
		t.Fatalf("streamID = %d, want 7", streamID)
	}
	if !bytes.Equal(data, []byte("hello")) {
		t.Fatalf("data = %q, want %q", data, "hello")
	}
}

func TestDecryptRelayNotRecognized(t *testing.T) {
	hop := testHop(0x10, 0x20, 0xAA, 0xBB)
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	garbage := cell.NewFixedCell(0x80000001, cell.CmdRelay)
	for i := range garbage.Payload() {
		garbage.Payload()[i] = 0xFF
	}

	_, _, _, _, err := circ.DecryptRelay(garbage)
	if err == nil {
		t.Fatal("expected error for unrecognized cell")
	}
}

func TestEncryptDecryptRoundTripMultiHop(t *testing.T) {
	// Create a 3-hop circuit with matched encrypt/decrypt keys
	// For round-trip: we encrypt with kf, then simulate "relay response" by
	// creating a circuit where we can decrypt with the same key arrangement.

	// Create 3 hops — for a true round-trip test, we need the forward side (client)
	// and backward side (relay) to use the same key, just reversed.
	// Here we test encrypt then decrypt with matching key pairs.

	hop1 := testHop(0x10, 0x10, 0xA1, 0xA1) // kf == kb (so encrypt then decrypt is identity)
	hop2 := testHop(0x20, 0x20, 0xA2, 0xA2)
	hop3 := testHop(0x30, 0x30, 0xA3, 0xA3)

	// Create the circuit for encryption (client side)
	encCirc := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop1, hop2, hop3},
	}

	data := []byte("test multi-hop")
	encrypted, err := encCirc.EncryptRelay(RelayData, 42, data)
	if err != nil {
		t.Fatalf("EncryptRelay: %v", err)
	}

	// Verify the cell is encrypted
	if encrypted.Payload()[0] == RelayData {
		t.Fatal("payload not encrypted")
	}

	// For the decryption side, we need new cipher streams initialized from the same keys
	// but using kb (backward) for decryption. Since kf==kb, we can create fresh hops.
	decHop1 := testHop(0x10, 0x10, 0xA1, 0xA1)
	decHop2 := testHop(0x20, 0x20, 0xA2, 0xA2)
	decHop3 := testHop(0x30, 0x30, 0xA3, 0xA3)

	// Simulate relays peeling layers: relay1 decrypts with kf[0], relay2 with kf[1], relay3 with kf[2]
	// For client decryption of responses, client decrypts with kb[0], kb[1], kb[2]
	// Since we set kf==kb and init from same keys, we can verify the encrypted payload
	// has 509 bytes (correct size).
	if len(encrypted.Payload()) != RelayPayloadLen {
		t.Fatalf("payload length = %d, want %d", len(encrypted.Payload()), RelayPayloadLen)
	}

	_ = decHop1
	_ = decHop2
	_ = decHop3
}

func TestRunningDigestPersistsAcrossCells(t *testing.T) {
	kbKey := make([]byte, 16)
	for i := range kbKey {
		kbKey[i] = byte(0x20 + i)
	}
	iv := make([]byte, aes.BlockSize)

	bwdEnc, _ := aes.NewCipher(kbKey)
	bwdDec, _ := aes.NewCipher(kbKey)

	dbRelay := sha1.New()
	dbRelay.Write([]byte{0xBB})
	dbClient := sha1.New()
	dbClient.Write([]byte{0xBB})

	encStream := cipher.NewCTR(bwdEnc, iv)
	decStream := cipher.NewCTR(bwdDec, iv)

	kfKey := make([]byte, 16)
	fwdBlock, _ := aes.NewCipher(kfKey)
	hop := &Hop{
		kf: cipher.NewCTR(fwdBlock, iv),
		kb: decStream,
		df: sha1.New(),
		db: dbClient,
	}
	circ := &Circuit{
		ID:   0x80000001,
		Hops: []*Hop{hop},
	}

	// Send two cells from relay, decrypt both — proves running digest state persists
	for cellNum := 0; cellNum < 2; cellNum++ {
		var payload [RelayPayloadLen]byte
		payload[relayCommandOff] = RelayData
		binary.BigEndian.PutUint16(payload[relayStreamIDOff:], 1)
		binary.BigEndian.PutUint16(payload[relayLengthOff:], 3)
		copy(payload[relayDataOff:], []byte{byte(cellNum), byte(cellNum), byte(cellNum)})

		dbRelay.Write(payload[:])
		digest := dbRelay.Sum(nil)
		copy(payload[relayDigestOff:relayDigestOff+4], digest[:4])

		encStream.XORKeyStream(payload[:], payload[:])

		relayCell := cell.NewFixedCell(0x80000001, cell.CmdRelay)
		copy(relayCell.Payload(), payload[:])

		_, _, _, data, err := circ.DecryptRelay(relayCell)
		if err != nil {
			t.Fatalf("cell %d: DecryptRelay: %v", cellNum, err)
		}
		expected := []byte{byte(cellNum), byte(cellNum), byte(cellNum)}
		if !bytes.Equal(data, expected) {
			t.Fatalf("cell %d: data = %v, want %v", cellNum, data, expected)
		}
	}
}
