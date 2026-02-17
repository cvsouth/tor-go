package ntor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	protoID = "ntor-curve25519-sha256-1"
	tKey    = protoID + ":key_extract"
	tMac    = protoID + ":mac"
	tVerify = protoID + ":verify"
	mExpand = protoID + ":key_expand"
)

// KeyMaterial holds the derived circuit keys from a successful ntor handshake.
type KeyMaterial struct {
	Df [20]byte // Forward digest seed (client→relay)
	Db [20]byte // Backward digest seed (relay→client)
	Kf [16]byte // Forward AES-128-CTR key
	Kb [16]byte // Backward AES-128-CTR key
}

// HandshakeState holds the client's ephemeral state for an ntor handshake.
type HandshakeState struct {
	nodeID  [20]byte // SHA-1 of relay's RSA identity
	ntorKey [32]byte // Relay's Curve25519 onion key (B)
	x       [32]byte // Client ephemeral private key
	X       [32]byte // Client ephemeral public key
}

// NewHandshake creates a new ntor handshake state with a fresh ephemeral keypair.
func NewHandshake(nodeID [20]byte, ntorKey [32]byte) (*HandshakeState, error) {
	var x [32]byte
	if _, err := rand.Read(x[:]); err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	X, err := curve25519.X25519(x[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute public key: %w", err)
	}

	hs := &HandshakeState{
		nodeID:  nodeID,
		ntorKey: ntorKey,
		x:       x,
	}
	copy(hs.X[:], X)
	return hs, nil
}

// Close zeroes the ephemeral private key. Call on error paths when Complete() won't be called.
func (hs *HandshakeState) Close() {
	clear(hs.x[:])
}

// ClientData returns the 84-byte CREATE2 HDATA: node_id(20) || B(32) || X(32).
func (hs *HandshakeState) ClientData() [84]byte {
	var data [84]byte
	copy(data[0:20], hs.nodeID[:])
	copy(data[20:52], hs.ntorKey[:])
	copy(data[52:84], hs.X[:])
	return data
}

// Complete processes the server's 64-byte response (Y || AUTH), verifies AUTH,
// and derives circuit keys. Returns KeyMaterial or an error.
func (hs *HandshakeState) Complete(serverData [64]byte) (*KeyMaterial, error) {
	var Y, authReceived [32]byte
	copy(Y[:], serverData[0:32])
	copy(authReceived[:], serverData[32:64])

	// Compute shared secrets
	exp1, err := curve25519.X25519(hs.x[:], Y[:]) // ephemeral-ephemeral
	if err != nil {
		return nil, fmt.Errorf("curve25519 x*Y: %w", err)
	}
	if isZero(exp1) {
		return nil, fmt.Errorf("x*Y produced all-zeros point")
	}

	exp2, err := curve25519.X25519(hs.x[:], hs.ntorKey[:]) // ephemeral-static
	if err != nil {
		return nil, fmt.Errorf("curve25519 x*B: %w", err)
	}
	if isZero(exp2) {
		return nil, fmt.Errorf("x*B produced all-zeros point")
	}

	// Build secret_input: exp1 || exp2 || ID || B || X || Y || PROTOID (204 bytes)
	secretInput := make([]byte, 0, 204)
	secretInput = append(secretInput, exp1...)
	secretInput = append(secretInput, exp2...)
	secretInput = append(secretInput, hs.nodeID[:]...)
	secretInput = append(secretInput, hs.ntorKey[:]...)
	secretInput = append(secretInput, hs.X[:]...)
	secretInput = append(secretInput, Y[:]...)
	secretInput = append(secretInput, []byte(protoID)...)

	// Verify AUTH
	verify := ntorHMAC(secretInput, tVerify)

	// auth_input: verify || ID || B || Y || X || PROTOID || "Server" (178 bytes)
	authInput := make([]byte, 0, 178)
	authInput = append(authInput, verify...)
	authInput = append(authInput, hs.nodeID[:]...)
	authInput = append(authInput, hs.ntorKey[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, hs.X[:]...)
	authInput = append(authInput, []byte(protoID)...)
	authInput = append(authInput, []byte("Server")...)

	expectedAuth := ntorHMAC(authInput, tMac)
	if !hmac.Equal(expectedAuth, authReceived[:]) {
		return nil, fmt.Errorf("AUTH verification failed")
	}

	// Derive keys via HKDF-SHA256
	kdf := hkdf.New(sha256.New, secretInput, []byte(tKey), []byte(mExpand))
	keys := make([]byte, 92)
	if _, err := io.ReadFull(kdf, keys); err != nil {
		return nil, fmt.Errorf("HKDF key derivation: %w", err)
	}

	km := &KeyMaterial{}
	copy(km.Df[:], keys[0:20])
	copy(km.Db[:], keys[20:40])
	copy(km.Kf[:], keys[40:56])
	copy(km.Kb[:], keys[56:72])

	// Zero sensitive intermediates
	clear(keys)
	clear(secretInput)
	clear(authInput)
	clear(hs.x[:])

	return km, nil
}

func ntorHMAC(msg []byte, key string) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(msg)
	return h.Sum(nil)
}

func isZero(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}
