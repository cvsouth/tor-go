package cell

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Reader reads Tor cells from a buffered reader.
type Reader struct {
	r *bufio.Reader
}

func NewReader(r *bufio.Reader) *Reader {
	return &Reader{r: r}
}

// ReadCell reads a cell with 4-byte CircID (link protocol v4+).
func (cr *Reader) ReadCell() (Cell, error) {
	// Read 5-byte header: 4-byte CircID + 1-byte command
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(cr.r, hdr); err != nil {
		return nil, fmt.Errorf("read cell header: %w", err)
	}
	cmd := hdr[4]

	if IsVariableLength(cmd) {
		// Read 2-byte length
		var lenBuf [2]byte
		if _, err := io.ReadFull(cr.r, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("read varlen length: %w", err)
		}
		pLen := binary.BigEndian.Uint16(lenBuf[:])
		if int(pLen) > MaxVarPayloadLen {
			return nil, fmt.Errorf("variable-length cell payload too large: %d bytes (max %d)", pLen, MaxVarPayloadLen)
		}
		c := make(Cell, 7+int(pLen))
		copy(c[0:5], hdr)
		copy(c[5:7], lenBuf[:])
		if pLen > 0 {
			if _, err := io.ReadFull(cr.r, c[7:]); err != nil {
				return nil, fmt.Errorf("read varlen payload: %w", err)
			}
		}
		return c, nil
	}

	// Fixed-length: read remaining 509 bytes
	c := make(Cell, FixedCellLen)
	copy(c[0:5], hdr)
	if _, err := io.ReadFull(cr.r, c[5:]); err != nil {
		return nil, fmt.Errorf("read fixed payload: %w", err)
	}
	return c, nil
}

// ReadVersionsCell reads a VERSIONS cell which uses 2-byte CircID.
func (cr *Reader) ReadVersionsCell() (Cell, error) {
	// 2-byte CircID + 1-byte command + 2-byte length
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(cr.r, hdr); err != nil {
		return nil, fmt.Errorf("read versions header: %w", err)
	}
	if hdr[2] != CmdVersions {
		return nil, fmt.Errorf("expected VERSIONS (7), got command %d", hdr[2])
	}
	pLen := binary.BigEndian.Uint16(hdr[3:5])
	c := make(Cell, 5+int(pLen))
	copy(c[0:5], hdr)
	if pLen > 0 {
		if _, err := io.ReadFull(cr.r, c[5:]); err != nil {
			return nil, fmt.Errorf("read versions payload: %w", err)
		}
	}
	return c, nil
}

// ParseVersions extracts version numbers from a VERSIONS cell read with ReadVersionsCell.
// The cell format is: 2-byte CircID + 1-byte cmd + 2-byte length + payload.
// Note: VERSIONS cells have a 2-byte CircID layout, so Cell accessor methods
// (CircID, Command, Payload, PayloadLen) must NOT be used on them.
func ParseVersions(c Cell) []uint16 {
	payload := c[5:] // after 2-byte circID + cmd + 2-byte length
	n := len(payload) / 2
	versions := make([]uint16, n)
	for i := range versions {
		versions[i] = binary.BigEndian.Uint16(payload[2*i:])
	}
	return versions
}

// Writer writes Tor cells.
type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (cw *Writer) WriteCell(c Cell) error {
	_, err := cw.w.Write(c)
	return err
}
