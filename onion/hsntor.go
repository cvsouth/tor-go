package onion

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const (
	hsNtorProtoid = "tor-hs-ntor-curve25519-sha3-256-1"
	pkPubkeyLen   = 32
	macOutputLen  = 32 // SHA3-256 output
)

var (
	tHsenc    = []byte(hsNtorProtoid + ":hs_key_extract")
	tHsverify = []byte(hsNtorProtoid + ":hs_verify")
	tHsmac    = []byte(hsNtorProtoid + ":hs_mac")
	mHsexpand = []byte(hsNtorProtoid + ":hs_key_expand")
)

// HsNtorClientState holds the client's ephemeral state during an hs-ntor handshake.
type HsNtorClientState struct {
	X       [32]byte // Client ephemeral public key
	x       [32]byte // Client ephemeral private key
	B       [32]byte // Service encryption key (KP_hss_ntor / enc-key ntor)
	AuthKey []byte   // Introduction point auth key
	Subcred [32]byte // Subcredential
}

// HsNtorClientHandshake initiates the client side of an hs-ntor handshake.
// It generates the ephemeral keypair, derives the encryption and MAC keys for
// the INTRODUCE1 encrypted section, and returns the client state.
//
// B is the service's enc-key (curve25519 public key from the descriptor).
// authKey is the introduction point's auth key.
// subcredential is the service's subcredential for the current period.
func HsNtorClientHandshake(B [32]byte, authKey []byte, subcredential [32]byte) (*HsNtorClientState, [32]byte, [32]byte, error) {
	// Generate ephemeral keypair x, X.
	var x, X [32]byte
	if _, err := rand.Read(x[:]); err != nil {
		return nil, [32]byte{}, [32]byte{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	X_bytes, err := curve25519.X25519(x[:], curve25519.Basepoint)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, fmt.Errorf("curve25519 basepoint mult: %w", err)
	}
	copy(X[:], X_bytes)

	// intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
	expBx, err := curve25519.X25519(x[:], B[:])
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, fmt.Errorf("curve25519 DH: %w", err)
	}
	if isAllZeros(expBx) {
		return nil, [32]byte{}, [32]byte{}, fmt.Errorf("EXP(B,x) produced all-zeros point")
	}

	introSecret := buildIntroSecretInput(expBx, authKey, X[:], B[:])

	// info = m_hsexpand | N_hs_subcred
	info := append(append([]byte{}, mHsexpand...), subcredential[:]...)

	// hs_keys = SHAKE256_KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN + MAC_KEY_LEN)
	kdfInput := make([]byte, 0, len(introSecret)+len(tHsenc)+len(info))
	kdfInput = append(kdfInput, introSecret...)
	kdfInput = append(kdfInput, tHsenc...)
	kdfInput = append(kdfInput, info...)

	keys := make([]byte, sKeyLen+macKeyLen)
	shake := sha3.NewShake256()
	shake.Write(kdfInput)
	shake.Read(keys)

	var encKey, macKey [32]byte
	copy(encKey[:], keys[:sKeyLen])
	copy(macKey[:], keys[sKeyLen:])

	state := &HsNtorClientState{
		X:       X,
		x:       x,
		B:       B,
		AuthKey: authKey,
		Subcred: subcredential,
	}

	return state, encKey, macKey, nil
}

// HsNtorClientCompleteHandshake completes the client side of the hs-ntor
// handshake upon receiving the RENDEZVOUS2 message containing SERVER_PK (Y)
// and AUTH. Returns the key seed for key expansion.
func HsNtorClientCompleteHandshake(state *HsNtorClientState, serverPK [32]byte, auth [32]byte) ([]byte, error) {
	// rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
	expYx, err := curve25519.X25519(state.x[:], serverPK[:])
	if err != nil {
		return nil, fmt.Errorf("EXP(Y,x): %w", err)
	}
	if isAllZeros(expYx) {
		return nil, fmt.Errorf("EXP(Y,x) produced all-zeros point")
	}
	expBx, err := curve25519.X25519(state.x[:], state.B[:])
	if err != nil {
		return nil, fmt.Errorf("EXP(B,x): %w", err)
	}
	if isAllZeros(expBx) {
		return nil, fmt.Errorf("EXP(B,x) produced all-zeros point")
	}

	rendSecret := buildRendSecretInput(expYx, expBx, state.AuthKey, state.B[:], state.X[:], serverPK[:])

	// NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)
	ntorKeySeed := hsMAC(rendSecret, tHsenc)

	// verify = MAC(rend_secret_hs_input, t_hsverify)
	verify := hsMAC(rendSecret, tHsverify)

	// auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
	authInput := make([]byte, 0, len(verify)+len(state.AuthKey)+32+32+32+len(hsNtorProtoid)+6)
	authInput = append(authInput, verify...)
	authInput = append(authInput, state.AuthKey...)
	authInput = append(authInput, state.B[:]...)
	authInput = append(authInput, serverPK[:]...)
	authInput = append(authInput, state.X[:]...)
	authInput = append(authInput, []byte(hsNtorProtoid)...)
	authInput = append(authInput, []byte("Server")...)

	// AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
	expectedAuth := hsMAC(authInput, tHsmac)

	if !hmac.Equal(expectedAuth, auth[:]) {
		return nil, fmt.Errorf("hs-ntor AUTH verification failed")
	}

	// Zero ephemeral private key — no longer needed after handshake completes.
	for i := range state.x {
		state.x[i] = 0
	}

	return ntorKeySeed, nil
}

// HsNtorExpandKeys derives the relay encryption keys from the NTOR_KEY_SEED.
// K = KDF(NTOR_KEY_SEED | m_hsexpand, SHA3_256_LEN*2 + S_KEY_LEN*2)
// Returns Df(32), Db(32), Kf(32), Kb(32).
func HsNtorExpandKeys(ntorKeySeed []byte) (df, db [32]byte, kf, kb [32]byte) {
	kdfInput := append(append([]byte{}, ntorKeySeed...), mHsexpand...)

	totalLen := 32 + 32 + sKeyLen + sKeyLen // SHA3_256_LEN*2 + S_KEY_LEN*2
	keys := make([]byte, totalLen)
	shake := sha3.NewShake256()
	shake.Write(kdfInput)
	shake.Read(keys)

	copy(df[:], keys[0:32])
	copy(db[:], keys[32:64])
	copy(kf[:], keys[64:96])
	copy(kb[:], keys[96:128])
	return
}

// buildIntroSecretInput constructs intro_secret_hs_input =
// EXP(B,x) | AUTH_KEY | X | B | PROTOID
func buildIntroSecretInput(expBx []byte, authKey, X, B []byte) []byte {
	result := make([]byte, 0, len(expBx)+len(authKey)+len(X)+len(B)+len(hsNtorProtoid))
	result = append(result, expBx...)
	result = append(result, authKey...)
	result = append(result, X...)
	result = append(result, B...)
	result = append(result, []byte(hsNtorProtoid)...)
	return result
}

// buildRendSecretInput constructs rend_secret_hs_input =
// EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
func buildRendSecretInput(expYx, expBx, authKey, B, X, Y []byte) []byte {
	result := make([]byte, 0, len(expYx)+len(expBx)+len(authKey)+len(B)+len(X)+len(Y)+len(hsNtorProtoid))
	result = append(result, expYx...)
	result = append(result, expBx...)
	result = append(result, authKey...)
	result = append(result, B...)
	result = append(result, X...)
	result = append(result, Y...)
	result = append(result, []byte(hsNtorProtoid)...)
	return result
}

// isAllZeros checks if a byte slice is all zeros using constant-time comparison.
func isAllZeros(b []byte) bool {
	var acc byte
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

// hsMAC computes MAC(key, message) = SHA3-256(key_len | key | message)
// per the hs-ntor spec's MAC construction.
// In the spec, MAC(key=k, message=m) where k is the variable secret
// and m is the fixed tweak constant.
func hsMAC(key, message []byte) []byte {
	h := sha3.New256()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(key)))
	h.Write(lenBuf[:])
	h.Write(key)
	h.Write(message)
	return h.Sum(nil)
}
