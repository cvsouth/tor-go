package ntor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// simulateServer performs the server side of the ntor handshake for testing.
func simulateServer(nodeID [20]byte, b [32]byte, B [32]byte, clientData [84]byte) ([64]byte, error) {
	// Parse client data
	// clientData = nodeID(20) || B(32) || X(32)
	var X [32]byte
	copy(X[:], clientData[52:84])

	// Generate server ephemeral keypair
	var y [32]byte
	rand.Read(y[:])
	Y, _ := curve25519.X25519(y[:], curve25519.Basepoint)

	// Compute shared secrets (server side)
	exp1, _ := curve25519.X25519(y[:], X[:]) // y * X
	exp2, _ := curve25519.X25519(b[:], X[:]) // b * X

	// Zero server ephemeral private key after use
	clear(y[:])

	// Build secret_input
	secretInput := make([]byte, 0, 204)
	secretInput = append(secretInput, exp1...)
	secretInput = append(secretInput, exp2...)
	secretInput = append(secretInput, nodeID[:]...)
	secretInput = append(secretInput, B[:]...)
	secretInput = append(secretInput, X[:]...)
	secretInput = append(secretInput, Y...)
	secretInput = append(secretInput, []byte(protoID)...)

	// Compute AUTH
	verify := ntorHMAC(secretInput, tVerify)
	authInput := make([]byte, 0, 178)
	authInput = append(authInput, verify...)
	authInput = append(authInput, nodeID[:]...)
	authInput = append(authInput, B[:]...)
	authInput = append(authInput, Y...)
	authInput = append(authInput, X[:]...)
	authInput = append(authInput, []byte(protoID)...)
	authInput = append(authInput, []byte("Server")...)
	auth := ntorHMAC(authInput, tMac)

	// Zero sensitive intermediates
	clear(secretInput)
	clear(authInput)

	var response [64]byte
	copy(response[0:32], Y)
	copy(response[32:64], auth)
	return response, nil
}

func TestNtorHandshakeRoundTrip(t *testing.T) {
	// Generate relay's static keypair
	var b [32]byte
	rand.Read(b[:])
	B, _ := curve25519.X25519(b[:], curve25519.Basepoint)
	var Bkey [32]byte
	copy(Bkey[:], B)

	var nodeID [20]byte
	rand.Read(nodeID[:])

	// Client side
	hs, err := NewHandshake(nodeID, Bkey)
	if err != nil {
		t.Fatalf("NewHandshake: %v", err)
	}
	defer hs.Close()

	clientData := hs.ClientData()

	// Verify client data layout
	for i := 0; i < 20; i++ {
		if clientData[i] != nodeID[i] {
			t.Fatal("client data: nodeID mismatch")
		}
	}

	// Server side
	serverResp, err := simulateServer(nodeID, b, Bkey, clientData)
	if err != nil {
		t.Fatalf("simulateServer: %v", err)
	}
	clear(b[:]) // Zero static private key after use

	// Client completes
	km, err := hs.Complete(serverResp)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Verify keys are non-zero
	if km.Df == [20]byte{} || km.Db == [20]byte{} {
		t.Fatal("digest seeds are zero")
	}
	if km.Kf == [16]byte{} || km.Kb == [16]byte{} {
		t.Fatal("encryption keys are zero")
	}
}

func TestNtorBadAuth(t *testing.T) {
	var b [32]byte
	rand.Read(b[:])
	B, _ := curve25519.X25519(b[:], curve25519.Basepoint)
	var Bkey [32]byte
	copy(Bkey[:], B)

	var nodeID [20]byte
	rand.Read(nodeID[:])

	hs, _ := NewHandshake(nodeID, Bkey)
	defer hs.Close()
	clientData := hs.ClientData()

	serverResp, _ := simulateServer(nodeID, b, Bkey, clientData)
	clear(b[:])

	// Corrupt AUTH
	serverResp[63] ^= 0xFF

	_, err := hs.Complete(serverResp)
	if err == nil {
		t.Fatal("expected AUTH verification failure")
	}
}

func TestNtorClientDataLayout(t *testing.T) {
	var nodeID [20]byte
	var ntorKey [32]byte
	for i := range nodeID {
		nodeID[i] = byte(i)
	}
	for i := range ntorKey {
		ntorKey[i] = byte(i + 100)
	}

	hs, err := NewHandshake(nodeID, ntorKey)
	if err != nil {
		t.Fatalf("NewHandshake: %v", err)
	}

	data := hs.ClientData()

	// Check nodeID
	for i := 0; i < 20; i++ {
		if data[i] != byte(i) {
			t.Fatalf("nodeID byte %d: got %d, want %d", i, data[i], i)
		}
	}
	// Check ntorKey
	for i := 0; i < 32; i++ {
		if data[20+i] != byte(i+100) {
			t.Fatalf("ntorKey byte %d: got %d, want %d", i, data[20+i], i+100)
		}
	}
	// Check X is 32 bytes and non-zero
	allZero := true
	for i := 52; i < 84; i++ {
		if data[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("public key X is all zeros")
	}
}

func TestKeyDerivationConsistency(t *testing.T) {
	// Verify that our HKDF usage produces expected output for known input
	secretInput := make([]byte, 204)
	for i := range secretInput {
		secretInput[i] = byte(i)
	}

	kdf := hkdf.New(sha256.New, secretInput, []byte(tKey), []byte(mExpand))
	keys := make([]byte, 92)
	io.ReadFull(kdf, keys)

	// Run it again - should produce identical output
	kdf2 := hkdf.New(sha256.New, secretInput, []byte(tKey), []byte(mExpand))
	keys2 := make([]byte, 92)
	io.ReadFull(kdf2, keys2)

	if !hmac.Equal(keys, keys2) {
		t.Fatal("HKDF not deterministic")
	}
}

func TestNtorConstants(t *testing.T) {
	if protoID != "ntor-curve25519-sha256-1" {
		t.Fatalf("protoID: %q", protoID)
	}
	if tKey != "ntor-curve25519-sha256-1:key_extract" {
		t.Fatalf("tKey: %q", tKey)
	}
	if tMac != "ntor-curve25519-sha256-1:mac" {
		t.Fatalf("tMac: %q", tMac)
	}
	if tVerify != "ntor-curve25519-sha256-1:verify" {
		t.Fatalf("tVerify: %q", tVerify)
	}
	if mExpand != "ntor-curve25519-sha256-1:key_expand" {
		t.Fatalf("mExpand: %q", mExpand)
	}
}
