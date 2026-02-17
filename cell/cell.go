package cell

import "encoding/binary"

// Command constants
const (
	CmdPadding          uint8 = 0
	CmdCreate           uint8 = 1
	CmdCreated          uint8 = 2
	CmdRelay            uint8 = 3
	CmdDestroy          uint8 = 4
	CmdCreateFast       uint8 = 5
	CmdCreatedFast      uint8 = 6
	CmdVersions         uint8 = 7
	CmdNetInfo          uint8 = 8
	CmdRelayEarly       uint8 = 9
	CmdCreate2          uint8 = 10
	CmdCreated2         uint8 = 11
	CmdPaddingNegotiate uint8 = 12
	CmdVPadding         uint8 = 128
	CmdCerts            uint8 = 129
	CmdAuthChallenge    uint8 = 130
	CmdAuthenticate     uint8 = 131
)

const (
	MaxPayloadLen    = 509
	FixedCellLen     = 514   // 4 (circID) + 1 (cmd) + 509 (payload)
	MaxVarPayloadLen = 10000 // Safety cap for variable-length cell payloads
)

// IsVariableLength returns true for VERSIONS (7) and commands >= 128.
func IsVariableLength(cmd uint8) bool {
	return cmd == CmdVersions || cmd >= 128
}

// Cell is a Tor cell backed by a byte slice.
type Cell []byte

// NewFixedCell creates a 514-byte fixed-length cell.
func NewFixedCell(circID uint32, cmd uint8) Cell {
	c := make(Cell, FixedCellLen)
	binary.BigEndian.PutUint32(c[0:4], circID)
	c[4] = cmd
	return c
}

// NewVarCell creates a variable-length cell with the given payload.
func NewVarCell(circID uint32, cmd uint8, payload []byte) Cell {
	c := make(Cell, 7+len(payload))
	binary.BigEndian.PutUint32(c[0:4], circID)
	c[4] = cmd
	binary.BigEndian.PutUint16(c[5:7], uint16(len(payload)))
	copy(c[7:], payload)
	return c
}

// NewVersionsCell creates a VERSIONS cell with 2-byte CircID (always 0).
func NewVersionsCell(versions []uint16) Cell {
	payload := make([]byte, 2*len(versions))
	for i, v := range versions {
		binary.BigEndian.PutUint16(payload[2*i:], v)
	}
	// VERSIONS uses 2-byte CircID
	c := make(Cell, 5+len(payload))
	c[0] = 0 // CircID high byte
	c[1] = 0 // CircID low byte
	c[2] = CmdVersions
	binary.BigEndian.PutUint16(c[3:5], uint16(len(payload)))
	copy(c[5:], payload)
	return c
}

func (c Cell) CircID() uint32 {
	return binary.BigEndian.Uint32(c[0:4])
}

func (c Cell) Command() uint8 {
	return c[4]
}

func (c Cell) Payload() []byte {
	if IsVariableLength(c.Command()) {
		return c[7:]
	}
	return c[5:]
}

func (c Cell) PayloadLen() int {
	if IsVariableLength(c.Command()) {
		return int(binary.BigEndian.Uint16(c[5:7]))
	}
	return MaxPayloadLen
}
