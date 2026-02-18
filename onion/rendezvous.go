package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding"
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/crypto/sha3"
)

// RendezvousKeys holds the derived keys for an onion service circuit.
type RendezvousKeys struct {
	Df [32]byte // Forward digest seed (SHA3-256)
	Db [32]byte // Backward digest seed (SHA3-256)
	Kf [32]byte // Forward AES-256-CTR key
	Kb [32]byte // Backward AES-256-CTR key
}

// BuildINTRODUCE1 builds the INTRODUCE1 relay cell payload.
// Parameters:
//   - authKey: the introduction point's auth key (from descriptor)
//   - encKey: the service's enc-key ntor (curve25519, from descriptor)
//   - subcredential: the service's subcredential
//   - rendCookie: 20-byte rendezvous cookie
//   - rendNodeOnionKey: the rendezvous point's ntor onion key
//   - rendLinkSpecs: the rendezvous point's link specifiers (encoded for EXTEND2)
//
// Returns the full INTRODUCE1 payload and the hs-ntor client state for
// completing the handshake when RENDEZVOUS2 arrives.
func BuildINTRODUCE1(authKey []byte, encKey [32]byte, subcredential [32]byte,
	rendCookie [20]byte, rendNodeOnionKey [32]byte, rendLinkSpecs []byte) ([]byte, *HsNtorClientState, error) {

	// hs-ntor client handshake: derive ENC_KEY and MAC_KEY.
	state, encKeyDerived, macKeyDerived, err := HsNtorClientHandshake(encKey, authKey, subcredential)
	if err != nil {
		return nil, nil, fmt.Errorf("hs-ntor handshake: %w", err)
	}

	// Build the plaintext body per [PROCESS_INTRO2]:
	// RENDEZVOUS_COOKIE(20) | N_EXTENSIONS(1) | ONION_KEY_TYPE(1) |
	// ONION_KEY_LEN(2) | ONION_KEY(32) | NSPEC(1) | link_specifiers...
	plaintext := make([]byte, 0, 256)
	plaintext = append(plaintext, rendCookie[:]...)
	plaintext = append(plaintext, 0x00) // N_EXTENSIONS = 0

	// ONION_KEY_TYPE = 0x01 (ntor)
	plaintext = append(plaintext, 0x01)
	// ONION_KEY_LEN = 32
	var keyLenBuf [2]byte
	binary.BigEndian.PutUint16(keyLenBuf[:], 32)
	plaintext = append(plaintext, keyLenBuf[:]...)
	plaintext = append(plaintext, rendNodeOnionKey[:]...)

	// Link specifiers (already encoded in EXTEND2 format).
	plaintext = append(plaintext, rendLinkSpecs...)

	// Pad to 246 bytes (current C-tor behavior, per spec note).
	if len(plaintext) < 246 {
		pad := make([]byte, 246-len(plaintext))
		plaintext = append(plaintext, pad...)
	}

	// Encrypt plaintext with ENC_KEY using AES-256-CTR with zero IV.
	block, err := aes.NewCipher(encKeyDerived[:])
	if err != nil {
		return nil, nil, fmt.Errorf("AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	encrypted := make([]byte, len(plaintext))
	stream.XORKeyStream(encrypted, plaintext)

	// Build header H per [FMT_INTRO1]:
	// LEGACY_KEY_ID(20 zeros) | AUTH_KEY_TYPE(1=0x02) | AUTH_KEY_LEN(2) | AUTH_KEY | N_EXTENSIONS(1=0)
	header := make([]byte, 0, 20+1+2+len(authKey)+1)
	header = append(header, make([]byte, 20)...) // LEGACY_KEY_ID = 20 zero bytes
	header = append(header, 0x02)                // AUTH_KEY_TYPE = 0x02 (Ed25519)
	var authKeyLenBuf [2]byte
	binary.BigEndian.PutUint16(authKeyLenBuf[:], uint16(len(authKey)))
	header = append(header, authKeyLenBuf[:]...)
	header = append(header, authKey...)
	header = append(header, 0x00) // N_EXTENSIONS = 0

	// Compute MAC: MAC(MAC_KEY, H | X | encrypted)
	macInput := make([]byte, 0, len(header)+32+len(encrypted))
	macInput = append(macInput, header...)
	macInput = append(macInput, state.X[:]...)
	macInput = append(macInput, encrypted...)
	mac := hsMAC(macKeyDerived[:], macInput)

	// Final INTRODUCE1 payload: H | X | encrypted | MAC
	payload := make([]byte, 0, len(header)+32+len(encrypted)+32)
	payload = append(payload, header...)
	payload = append(payload, state.X[:]...)
	payload = append(payload, encrypted...)
	payload = append(payload, mac...)

	return payload, state, nil
}

// CompleteRendezvous processes the RENDEZVOUS2 message from the rendezvous
// point, completing the hs-ntor handshake and deriving circuit keys.
// The rendezvous2Body contains: SERVER_PK(32) | AUTH(32).
func CompleteRendezvous(state *HsNtorClientState, rendezvous2Body []byte) (*RendezvousKeys, error) {
	if len(rendezvous2Body) < 64 {
		return nil, fmt.Errorf("RENDEZVOUS2 body too short: %d bytes", len(rendezvous2Body))
	}

	var serverPK, auth [32]byte
	copy(serverPK[:], rendezvous2Body[:32])
	copy(auth[:], rendezvous2Body[32:64])

	// Complete the hs-ntor handshake.
	ntorKeySeed, err := HsNtorClientCompleteHandshake(state, serverPK, auth)
	if err != nil {
		return nil, fmt.Errorf("hs-ntor complete: %w", err)
	}

	// Key expansion: K = KDF(NTOR_KEY_SEED | m_hsexpand, SHA3_256_LEN*2 + S_KEY_LEN*2)
	df, db, kf, kb := HsNtorExpandKeys(ntorKeySeed)

	return &RendezvousKeys{
		Df: df,
		Db: db,
		Kf: kf,
		Kb: kb,
	}, nil
}

// GenerateRendezvousCookie generates a random 20-byte rendezvous cookie.
func GenerateRendezvousCookie() ([20]byte, error) {
	var cookie [20]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return cookie, fmt.Errorf("generate rendezvous cookie: %w", err)
	}
	return cookie, nil
}

// BuildRendLinkSpecs encodes link specifiers for a rendezvous point in the
// format expected by INTRODUCE1 plaintext: NSPEC | (LSTYPE | LSLEN | LSPEC)...
func BuildRendLinkSpecs(identity [20]byte, address string, orPort uint16, ed25519ID [32]byte) ([]byte, error) {
	// Parse IPv4 address.
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", address)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", address)
	}
	var ipBytes [4]byte
	copy(ipBytes[:], ipv4)

	specs := make([]byte, 0, 128)

	// NSPEC count: 3 specifiers (TLS-over-TCP IPv4, Legacy identity, Ed25519 identity)
	nspec := byte(3)
	if ed25519ID == [32]byte{} {
		nspec = 2
	}
	specs = append(specs, nspec)

	// LSTYPE 0x00: TLS-over-TCP, IPv4 (6 bytes: 4 IP + 2 port)
	specs = append(specs, 0x00, 0x06)
	specs = append(specs, ipBytes[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], orPort)
	specs = append(specs, portBuf[:]...)

	// LSTYPE 0x02: Legacy RSA identity (20 bytes)
	specs = append(specs, 0x02, 0x14)
	specs = append(specs, identity[:]...)

	// LSTYPE 0x03: Ed25519 identity (32 bytes)
	if ed25519ID != [32]byte{} {
		specs = append(specs, 0x03, 0x20)
		specs = append(specs, ed25519ID[:]...)
	}

	return specs, nil
}

// NewRendezvousDigests creates SHA3-256 running digests initialized with
// the given seeds. These are used for relay cell authentication on the
// onion service circuit (as opposed to SHA-1 for regular circuit hops).
func NewRendezvousDigests(df, db [32]byte) (hashDf, hashDb sha3Hash) {
	hDf := sha3.New256()
	hDf.Write(df[:])
	hDb := sha3.New256()
	hDb.Write(db[:])
	return sha3Hash{hDf}, sha3Hash{hDb}
}

// sha3Hash wraps a sha3 hash to implement hash.Hash and encoding.BinaryMarshaler/BinaryUnmarshaler,
// which are required by DecryptRelay for digest state snapshotting.
type sha3Hash struct {
	h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
		Reset()
		Size() int
		BlockSize() int
	}
}

func (s sha3Hash) Write(p []byte) (int, error) { return s.h.Write(p) }
func (s sha3Hash) Sum(b []byte) []byte         { return s.h.Sum(b) }
func (s sha3Hash) Reset()                      { s.h.Reset() }
func (s sha3Hash) Size() int                   { return s.h.Size() }
func (s sha3Hash) BlockSize() int              { return s.h.BlockSize() }

func (s sha3Hash) MarshalBinary() ([]byte, error) {
	if m, ok := s.h.(encoding.BinaryMarshaler); ok {
		return m.MarshalBinary()
	}
	return nil, fmt.Errorf("sha3Hash: underlying hash does not support MarshalBinary")
}

func (s sha3Hash) UnmarshalBinary(data []byte) error {
	if u, ok := s.h.(encoding.BinaryUnmarshaler); ok {
		return u.UnmarshalBinary(data)
	}
	return fmt.Errorf("sha3Hash: underlying hash does not support UnmarshalBinary")
}
