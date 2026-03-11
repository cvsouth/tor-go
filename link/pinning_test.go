package link

import (
	"strings"
	"testing"
)

// TestCheckPinningNilSkips verifies that nil expectedKey skips the check.
func TestCheckPinningNilSkips(t *testing.T) {
	actual := []byte{1, 2, 3}
	if err := checkPinning(actual, nil); err != nil {
		t.Fatalf("checkPinning with nil expected should return nil, got: %v", err)
	}
}

// TestCheckPinningMatch verifies that matching keys produce no error.
func TestCheckPinningMatch(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	expected := make([]byte, 32)
	copy(expected, key)

	if err := checkPinning(key, expected); err != nil {
		t.Fatalf("checkPinning with matching keys should return nil, got: %v", err)
	}
}

// TestCheckPinningMismatch verifies that mismatched keys return an error
// containing "identity pinning failed".
func TestCheckPinningMismatch(t *testing.T) {
	actual := make([]byte, 32)
	expected := make([]byte, 32)
	expected[0] = 0xFF // differ

	err := checkPinning(actual, expected)
	if err == nil {
		t.Fatal("checkPinning with mismatched keys should return an error")
	}
	if !strings.Contains(err.Error(), "identity pinning failed") {
		t.Fatalf("error should contain 'identity pinning failed', got: %v", err)
	}
}

// TestCheckPinningDifferentLengths verifies that keys of different lengths
// are treated as a mismatch.
func TestCheckPinningDifferentLengths(t *testing.T) {
	actual := make([]byte, 32)
	expected := make([]byte, 16)

	err := checkPinning(actual, expected)
	if err == nil {
		t.Fatal("checkPinning with different-length keys should return an error")
	}
	if !strings.Contains(err.Error(), "identity pinning failed") {
		t.Fatalf("error should contain 'identity pinning failed', got: %v", err)
	}
}

// TestHandshakeDelegatesToHandshakeWithPinning verifies that Handshake
// delegates to HandshakeWithPinning with nil expectedEd25519.
func TestHandshakeDelegatesToHandshakeWithPinning(t *testing.T) {
	addr := "127.0.0.1:1" // unreachable port
	_, err1 := Handshake(addr, nil)
	_, err2 := HandshakeWithPinning(addr, nil, nil)

	if err1 == nil || err2 == nil {
		t.Fatal("expected errors from unreachable address")
	}
	// Both should fail at the TCP dial stage with the same kind of error.
	if err1.Error() != err2.Error() {
		t.Errorf("Handshake and HandshakeWithPinning errors differ:\n  Handshake:            %v\n  HandshakeWithPinning: %v", err1, err2)
	}
}

// TestCheckPinningBothNil verifies that checkPinning(nil, nil) returns nil,
// treating nil expectedKey as "no pinning requested".
func TestCheckPinningBothNil(t *testing.T) {
	if err := checkPinning(nil, nil); err != nil {
		t.Fatalf("checkPinning(nil, nil) should return nil, got: %v", err)
	}
}

// TestHandshakeWithPinningUnreachable tests that providing an expectedEd25519
// key to HandshakeWithPinning works at the API level (the connection fails
// before reaching the pinning check, but the function accepts the parameter).
func TestHandshakeWithPinningUnreachable(t *testing.T) {
	fakeKey := make([]byte, 32)
	for i := range fakeKey {
		fakeKey[i] = byte(i)
	}

	_, err := HandshakeWithPinning("127.0.0.1:1", fakeKey, nil)
	if err == nil {
		t.Fatal("expected error from unreachable address")
	}
}
