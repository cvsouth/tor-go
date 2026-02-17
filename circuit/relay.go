package circuit

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"fmt"

	"github.com/cvsouth/tor-go/cell"
)

// Relay cell command constants (tor-spec §6.1).
const (
	RelayBegin                 uint8 = 1
	RelayData                  uint8 = 2
	RelayEnd                   uint8 = 3
	RelayConnected             uint8 = 4
	RelaySendMe                uint8 = 5
	RelayBeginDir              uint8 = 13
	RelayExtend2               uint8 = 14
	RelayExtended2             uint8 = 15
	RelayEstablishRendezvous   uint8 = 33
	RelayIntroduce1            uint8 = 34
	RelayRendezvous2           uint8 = 37
	RelayRendezvousEstablished uint8 = 39
	RelayIntroduceAck          uint8 = 40
)

// RelayPayloadLen is the length of a relay cell payload (inside a fixed cell).
const RelayPayloadLen = cell.MaxPayloadLen // 509

// Relay header offsets within the 509-byte payload.
const (
	relayCommandOff    = 0  // 1 byte
	relayRecognizedOff = 1  // 2 bytes
	relayStreamIDOff   = 3  // 2 bytes
	relayDigestOff     = 5  // 4 bytes
	relayLengthOff     = 9  // 2 bytes
	relayDataOff       = 11 // up to 498 bytes
)

// MaxRelayDataLen is the maximum data in a single relay cell.
const MaxRelayDataLen = RelayPayloadLen - relayDataOff // 498

// EncryptRelay builds and encrypts a relay cell payload for sending through the circuit.
// It acquires the circuit mutex. For use when the caller does NOT already hold it.
func (c *Circuit) EncryptRelay(relayCmd uint8, streamID uint16, data []byte) (cell.Cell, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.encryptRelayLocked(relayCmd, streamID, data)
}

// encryptRelayLocked is the lock-free internal implementation. Caller must hold c.wmu.
func (c *Circuit) encryptRelayLocked(relayCmd uint8, streamID uint16, data []byte) (cell.Cell, error) {

	if len(c.Hops) == 0 {
		return nil, fmt.Errorf("circuit has no hops")
	}
	if len(data) > MaxRelayDataLen {
		return nil, fmt.Errorf("relay data too large: %d > %d", len(data), MaxRelayDataLen)
	}

	// Build relay payload (509 bytes)
	var payload [RelayPayloadLen]byte
	payload[relayCommandOff] = relayCmd
	// recognized = 0 (already zero)
	binary.BigEndian.PutUint16(payload[relayStreamIDOff:], streamID)
	// digest = 0 for now (computed below)
	binary.BigEndian.PutUint16(payload[relayLengthOff:], uint16(len(data)))
	copy(payload[relayDataOff:], data)

	// Per tor-spec §6.1: padding = 4 zero bytes + random bytes
	padStart := relayDataOff + len(data)
	if padStart+4 < RelayPayloadLen {
		_, _ = rand.Read(payload[padStart+4:])
	}

	// Compute digest: hash the payload with digest field zeroed, take first 4 bytes
	hop := c.Hops[len(c.Hops)-1]
	hop.df.Write(payload[:])
	digest := hop.df.Sum(nil) // SHA-1 sum (doesn't reset state)
	copy(payload[relayDigestOff:relayDigestOff+4], digest[:4])

	// Encrypt: from last hop to first (onion layering)
	encrypted := payload[:]
	for i := len(c.Hops) - 1; i >= 0; i-- {
		c.Hops[i].kf.XORKeyStream(encrypted, encrypted)
	}

	// Build the RELAY cell
	relayCell := cell.NewFixedCell(c.ID, cell.CmdRelay)
	copy(relayCell.Payload(), encrypted)
	return relayCell, nil
}

// DecryptRelay decrypts an incoming relay cell payload.
// It acquires the circuit mutex. For use when the caller does NOT already hold it.
func (c *Circuit) DecryptRelay(incoming cell.Cell) (hopIdx int, relayCmd uint8, streamID uint16, data []byte, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.decryptRelayLocked(incoming)
}

// decryptRelayLocked is the lock-free internal implementation. Caller must hold c.rmu.
func (c *Circuit) decryptRelayLocked(incoming cell.Cell) (hopIdx int, relayCmd uint8, streamID uint16, data []byte, err error) {

	if len(c.Hops) == 0 {
		return 0, 0, 0, nil, fmt.Errorf("circuit has no hops")
	}

	payload := make([]byte, RelayPayloadLen)
	copy(payload, incoming.Payload()[:RelayPayloadLen])

	for i, hop := range c.Hops {
		// Decrypt this layer
		hop.kb.XORKeyStream(payload, payload)

		// Check recognized field
		recognized := binary.BigEndian.Uint16(payload[relayRecognizedOff:])
		if recognized != 0 {
			continue // Not recognized at this hop, try next layer
		}

		// Extract and verify digest
		var savedDigest [4]byte
		copy(savedDigest[:], payload[relayDigestOff:relayDigestOff+4])

		// Zero the digest field for hash computation
		payload[relayDigestOff] = 0
		payload[relayDigestOff+1] = 0
		payload[relayDigestOff+2] = 0
		payload[relayDigestOff+3] = 0

		// Snapshot Db state before writing, in case recognized==0 is coincidental
		dbState, err := hop.db.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			return 0, 0, 0, nil, fmt.Errorf("snapshot digest state: %w", err)
		}

		// Compute expected digest using running Db hash
		hop.db.Write(payload)
		computedDigest := hop.db.Sum(nil)

		if subtle.ConstantTimeCompare(savedDigest[:], computedDigest[:4]) == 1 {
			// Match — extract data
			relayCmd = payload[relayCommandOff]
			streamID = binary.BigEndian.Uint16(payload[relayStreamIDOff:])
			dataLen := binary.BigEndian.Uint16(payload[relayLengthOff:])
			if int(dataLen) > MaxRelayDataLen {
				return 0, 0, 0, nil, fmt.Errorf("relay data length %d exceeds maximum %d", dataLen, MaxRelayDataLen)
			}
			data = make([]byte, dataLen)
			copy(data, payload[relayDataOff:relayDataOff+int(dataLen)])
			return i, relayCmd, streamID, data, nil
		}

		// False recognized==0 — restore Db state and continue
		if err := hop.db.(encoding.BinaryUnmarshaler).UnmarshalBinary(dbState); err != nil {
			return 0, 0, 0, nil, fmt.Errorf("restore digest state: %w", err)
		}
	}

	return 0, 0, 0, nil, fmt.Errorf("relay cell not recognized at any hop")
}
