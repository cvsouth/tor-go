package cell

import (
	"bufio"
	"bytes"
	"testing"
)

func TestIsVariableLength(t *testing.T) {
	if IsVariableLength(CmdRelay) {
		t.Fatal("RELAY should be fixed")
	}
	if !IsVariableLength(CmdVersions) {
		t.Fatal("VERSIONS should be variable")
	}
	if !IsVariableLength(CmdCerts) {
		t.Fatal("CERTS should be variable")
	}
	if IsVariableLength(CmdNetInfo) {
		t.Fatal("NETINFO should be fixed")
	}
}

func TestFixedCellRoundTrip(t *testing.T) {
	c := NewFixedCell(0x80000001, CmdNetInfo)
	c.Payload()[0] = 0xAB
	if len(c) != FixedCellLen {
		t.Fatalf("expected %d bytes, got %d", FixedCellLen, len(c))
	}
	if c.CircID() != 0x80000001 {
		t.Fatalf("circID mismatch")
	}
	if c.Command() != CmdNetInfo {
		t.Fatal("command mismatch")
	}

	// Write then read
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteCell(c); err != nil {
		t.Fatal(err)
	}
	r := NewReader(bufio.NewReader(&buf))
	got, err := r.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c, got) {
		t.Fatal("round-trip mismatch")
	}
}

func TestVarCellRoundTrip(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	c := NewVarCell(0, CmdCerts, payload)
	if c.Command() != CmdCerts {
		t.Fatal("command mismatch")
	}
	if c.PayloadLen() != 3 {
		t.Fatalf("payload len: got %d", c.PayloadLen())
	}

	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteCell(c); err != nil {
		t.Fatal(err)
	}
	r := NewReader(bufio.NewReader(&buf))
	got, err := r.ReadCell()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c, got) {
		t.Fatal("round-trip mismatch")
	}
}

func TestVersionsCellSpecialFormat(t *testing.T) {
	c := NewVersionsCell([]uint16{4, 5})
	// Should be 5 bytes header + 4 bytes payload = 9
	if len(c) != 9 {
		t.Fatalf("expected 9 bytes, got %d", len(c))
	}
	// 2-byte CircID=0, cmd=7, length=4, versions
	if c[0] != 0 || c[1] != 0 {
		t.Fatal("CircID should be 0")
	}
	if c[2] != CmdVersions {
		t.Fatal("command should be VERSIONS")
	}

	// Write and read back
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if err := w.WriteCell(c); err != nil {
		t.Fatal(err)
	}
	r := NewReader(bufio.NewReader(&buf))
	got, err := r.ReadVersionsCell()
	if err != nil {
		t.Fatal(err)
	}
	versions := ParseVersions(got)
	if len(versions) != 2 || versions[0] != 4 || versions[1] != 5 {
		t.Fatalf("versions mismatch: %v", versions)
	}
}
