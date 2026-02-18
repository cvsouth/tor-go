package onion

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHsNtorSpecTestVectors(t *testing.T) {
	// Test vectors from rend-spec-v3 Appendix G.1

	// Service keys
	authKeyBytes := mustDecodeHex("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F")
	B_bytes := mustDecodeHex("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979")
	b_bytes := mustDecodeHex("A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A")
	subcred_bytes := mustDecodeHex("0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57")

	// Client ephemeral keypair
	x_bytes := mustDecodeHex("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341")
	X_bytes := mustDecodeHex("BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D")

	// Expected ENC_KEY and MAC_KEY
	expectedEncKey := mustDecodeHex("9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706")
	expectedMacKey := mustDecodeHex("FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5")

	// Server ephemeral keypair
	y_bytes := mustDecodeHex("68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55")
	Y_bytes := mustDecodeHex("8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700")

	// Expected results
	expectedAuthMAC := mustDecodeHex("4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208")
	expectedKeySeed := mustDecodeHex("4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB")

	_ = b_bytes // Used by server side
	_ = y_bytes // Used by server side

	// --- Client-side INTRODUCE1 key derivation ---

	var B [32]byte
	copy(B[:], B_bytes)
	var subcred [32]byte
	copy(subcred[:], subcred_bytes)

	// Manually derive keys with known ephemeral key (not random).
	expBx, err := curve25519.X25519(x_bytes, B_bytes)
	if err != nil {
		t.Fatalf("EXP(B,x): %v", err)
	}

	introSecret := buildIntroSecretInput(expBx, authKeyBytes, X_bytes, B_bytes)
	info := append(append([]byte{}, mHsexpand...), subcred_bytes...)

	kdfInput := make([]byte, 0, len(introSecret)+len(tHsenc)+len(info))
	kdfInput = append(kdfInput, introSecret...)
	kdfInput = append(kdfInput, tHsenc...)
	kdfInput = append(kdfInput, info...)

	keys := make([]byte, sKeyLen+macKeyLen)
	shake := sha3.NewShake256()
	shake.Write(kdfInput)
	_, _ = shake.Read(keys)

	encKey := keys[:sKeyLen]
	macKey := keys[sKeyLen:]

	if !bytes.Equal(encKey, expectedEncKey) {
		t.Fatalf("ENC_KEY mismatch:\n  got  %x\n  want %x", encKey, expectedEncKey)
	}
	if !bytes.Equal(macKey, expectedMacKey) {
		t.Fatalf("MAC_KEY mismatch:\n  got  %x\n  want %x", macKey, expectedMacKey)
	}

	// --- Client-side RENDEZVOUS2 verification ---

	// Simulate: server sends Y | AUTH
	var serverPK [32]byte
	copy(serverPK[:], Y_bytes)

	// Compute rend_secret_hs_input client side.
	expYx, err := curve25519.X25519(x_bytes, Y_bytes)
	if err != nil {
		t.Fatalf("EXP(Y,x): %v", err)
	}

	rendSecret := buildRendSecretInput(expYx, expBx, authKeyBytes, B_bytes, X_bytes, Y_bytes)

	ntorKeySeed := hsMAC(rendSecret, tHsenc)
	verify := hsMAC(rendSecret, tHsverify)

	authInput := make([]byte, 0, 256)
	authInput = append(authInput, verify...)
	authInput = append(authInput, authKeyBytes...)
	authInput = append(authInput, B_bytes...)
	authInput = append(authInput, Y_bytes...)
	authInput = append(authInput, X_bytes...)
	authInput = append(authInput, []byte(hsNtorProtoid)...)
	authInput = append(authInput, []byte("Server")...)

	authInputMAC := hsMAC(authInput, tHsmac)

	if !bytes.Equal(authInputMAC, expectedAuthMAC) {
		t.Fatalf("AUTH_INPUT_MAC mismatch:\n  got  %x\n  want %x", authInputMAC, expectedAuthMAC)
	}
	if !bytes.Equal(ntorKeySeed, expectedKeySeed) {
		t.Fatalf("NTOR_KEY_SEED mismatch:\n  got  %x\n  want %x", ntorKeySeed, expectedKeySeed)
	}
}

func TestHsNtorHandshakeRoundTrip(t *testing.T) {
	// Generate a static service keypair.
	var b, B [32]byte
	b[0] = 0x42
	B_bytes, _ := curve25519.X25519(b[:], curve25519.Basepoint)
	copy(B[:], B_bytes)

	authKey := make([]byte, 32)
	authKey[0] = 0x99
	var subcred [32]byte
	subcred[0] = 0xAA

	// Client side.
	state, _, _, err := HsNtorClientHandshake(B, authKey, subcred)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Simulate server side: generate y,Y and compute rend output.
	var y [32]byte
	y[0] = 0x77
	var Y [32]byte
	Y_bytes, _ := curve25519.X25519(y[:], curve25519.Basepoint)
	copy(Y[:], Y_bytes)

	// Server computes rend_secret_hs_input.
	expXy, _ := curve25519.X25519(y[:], state.X[:])
	expXb, _ := curve25519.X25519(b[:], state.X[:])
	rendSecret := buildRendSecretInput(expXy, expXb, authKey, B[:], state.X[:], Y[:])

	ntorKeySeed := hsMAC(rendSecret, tHsenc)
	verify := hsMAC(rendSecret, tHsverify)
	authInput := make([]byte, 0, 256)
	authInput = append(authInput, verify...)
	authInput = append(authInput, authKey...)
	authInput = append(authInput, B[:]...)
	authInput = append(authInput, Y[:]...)
	authInput = append(authInput, state.X[:]...)
	authInput = append(authInput, []byte(hsNtorProtoid)...)
	authInput = append(authInput, []byte("Server")...)
	serverAuth := hsMAC(authInput, tHsmac)

	var auth [32]byte
	copy(auth[:], serverAuth)

	// Client completes handshake.
	clientKeySeed, err := HsNtorClientCompleteHandshake(state, Y, auth)
	if err != nil {
		t.Fatalf("client complete: %v", err)
	}

	if !bytes.Equal(clientKeySeed, ntorKeySeed) {
		t.Fatal("key seeds don't match")
	}
}

func TestHsNtorBadAuth(t *testing.T) {
	var b, B [32]byte
	b[0] = 0x42
	B_bytes, _ := curve25519.X25519(b[:], curve25519.Basepoint)
	copy(B[:], B_bytes)

	state, _, _, _ := HsNtorClientHandshake(B, make([]byte, 32), [32]byte{})

	var badAuth [32]byte
	badAuth[0] = 0xFF
	var Y [32]byte
	Y[0] = 0x01

	_, err := HsNtorClientCompleteHandshake(state, Y, badAuth)
	if err == nil {
		t.Fatal("expected AUTH verification failure")
	}
}
