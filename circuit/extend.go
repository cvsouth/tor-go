package circuit

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/ntor"
)

// LinkSpecType constants for EXTEND2 link specifiers.
const (
	LinkSpecIPv4    = 0x00 // 6 bytes: 4 IP + 2 port
	LinkSpecIPv6    = 0x01 // 18 bytes: 16 IP + 2 port
	LinkSpecRSAID   = 0x02 // 20 bytes: RSA identity fingerprint
	LinkSpecEd25519 = 0x03 // 32 bytes: Ed25519 identity
)

// Extend extends the circuit through an additional relay using EXTEND2/EXTENDED2.
// The EXTEND2 is sent as a RELAY_EARLY cell (encrypted to the last hop).
func (c *Circuit) Extend(relayInfo *descriptor.RelayInfo, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	// Validate address before building payload
	ip := net.ParseIP(relayInfo.Address)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address for relay: %s", relayInfo.Address)
	}

	// Build ntor handshake for the new hop
	hs, err := ntor.NewHandshake(relayInfo.NodeID, relayInfo.NtorOnionKey)
	if err != nil {
		return fmt.Errorf("ntor handshake init: %w", err)
	}
	defer hs.Close()

	clientData := hs.ClientData()

	// Build EXTEND2 payload
	extend2Payload := buildExtend2Payload(relayInfo, clientData)

	// Encrypt and send as RELAY_EARLY atomically under the mutex
	// to prevent another goroutine from interleaving between encrypt and write.
	c.wmu.Lock()
	relayCell, err := c.encryptRelayLocked(RelayExtend2, 0, extend2Payload)
	if err != nil {
		c.wmu.Unlock()
		return fmt.Errorf("encrypt EXTEND2: %w", err)
	}
	if c.RelayEarlySent >= MaxRelayEarly {
		c.wmu.Unlock()
		return fmt.Errorf("RELAY_EARLY budget exhausted (%d/%d)", c.RelayEarlySent, MaxRelayEarly)
	}
	c.RelayEarlySent++
	earlyCell := cell.NewFixedCell(c.ID, cell.CmdRelayEarly)
	copy(earlyCell.Payload(), relayCell.Payload())
	err = c.Link.Writer.WriteCell(earlyCell)
	c.wmu.Unlock()
	if err != nil {
		return fmt.Errorf("send EXTEND2: %w", err)
	}

	logger.Debug("sent EXTEND2", "to", relayInfo.Address)

	// Wait for EXTENDED2
	_, relayCmd, _, data, err := c.ReceiveRelay()
	if err != nil {
		return fmt.Errorf("receive EXTENDED2: %w", err)
	}
	if relayCmd != RelayExtended2 {
		return fmt.Errorf("expected EXTENDED2 (15), got relay command %d", relayCmd)
	}

	// Parse EXTENDED2: HLEN(2) + HDATA(HLEN)
	if len(data) < 2 {
		return fmt.Errorf("EXTENDED2 too short: %d bytes", len(data))
	}
	hlen := binary.BigEndian.Uint16(data[0:2])
	if hlen != 64 {
		return fmt.Errorf("EXTENDED2 HLEN=%d, expected 64", hlen)
	}
	if len(data) < 2+int(hlen) {
		return fmt.Errorf("EXTENDED2 truncated: %d bytes, need %d", len(data), 2+hlen)
	}

	var serverData [64]byte
	copy(serverData[:], data[2:66])

	// Complete ntor handshake for the new hop
	km, err := hs.Complete(serverData)
	if err != nil {
		return fmt.Errorf("ntor complete for new hop: %w", err)
	}

	// Initialize the new hop
	hop, err := initHop(km)
	clear(km.Kf[:])
	clear(km.Kb[:])
	clear(km.Df[:])
	clear(km.Db[:])
	if err != nil {
		return fmt.Errorf("init new hop: %w", err)
	}

	c.wmu.Lock()
	c.rmu.Lock()
	c.Hops = append(c.Hops, hop)
	c.rmu.Unlock()
	c.wmu.Unlock()

	logger.Info("circuit extended", "hops", len(c.Hops))
	return nil
}

func buildExtend2Payload(relayInfo *descriptor.RelayInfo, clientData [84]byte) []byte {
	var specs [][]byte

	// IPv4 link specifier (type 0x00, 6 bytes)
	ip := net.ParseIP(relayInfo.Address)
	if ip4 := ip.To4(); ip4 != nil {
		spec := make([]byte, 8) // type(1) + len(1) + ip(4) + port(2)
		spec[0] = LinkSpecIPv4
		spec[1] = 6
		copy(spec[2:6], ip4)
		binary.BigEndian.PutUint16(spec[6:8], relayInfo.ORPort)
		specs = append(specs, spec)
	}

	// RSA identity (type 0x02, 20 bytes)
	rsaSpec := make([]byte, 22) // type(1) + len(1) + id(20)
	rsaSpec[0] = LinkSpecRSAID
	rsaSpec[1] = 20
	copy(rsaSpec[2:22], relayInfo.NodeID[:])
	specs = append(specs, rsaSpec)

	// Build payload: NSPEC(1) + link_specifiers + HTYPE(2) + HLEN(2) + HDATA(84)
	totalSpecLen := 0
	for _, s := range specs {
		totalSpecLen += len(s)
	}
	payload := make([]byte, 1+totalSpecLen+2+2+84)

	off := 0
	payload[off] = byte(len(specs))
	off++
	for _, s := range specs {
		copy(payload[off:], s)
		off += len(s)
	}
	binary.BigEndian.PutUint16(payload[off:], 0x0002) // HTYPE = ntor
	off += 2
	binary.BigEndian.PutUint16(payload[off:], 84) // HLEN
	off += 2
	copy(payload[off:], clientData[:])

	return payload
}
