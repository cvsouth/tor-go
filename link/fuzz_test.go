package link

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

func FuzzParseTorCert(f *testing.F) {
	// Seed: valid cert built the same way as unit tests
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	var certifiedKey [32]byte
	copy(certifiedKey[:], "test-certified-key-32-bytes!!!!!")

	buf := make([]byte, 0, 140)
	buf = append(buf, 0x01)     // version
	buf = append(buf, 0x04)     // cert type
	expHours := uint32(time.Now().Add(365*24*time.Hour).Unix() / 3600)
	var expBuf [4]byte
	binary.BigEndian.PutUint32(expBuf[:], expHours)
	buf = append(buf, expBuf[:]...)
	buf = append(buf, 0x01) // key type
	buf = append(buf, certifiedKey[:]...)
	buf = append(buf, 0x01) // n_extensions = 1
	var extLenBuf [2]byte
	binary.BigEndian.PutUint16(extLenBuf[:], 32)
	buf = append(buf, extLenBuf[:]...)
	buf = append(buf, 0x04) // ExtType
	buf = append(buf, 0x00) // ExtFlags
	signingPubKey := privKey.Public().(ed25519.PublicKey)
	buf = append(buf, signingPubKey...)
	sig := ed25519.Sign(privKey, buf)
	buf = append(buf, sig...)
	f.Add(buf)

	// Seed: minimal cert (no extensions)
	minBuf := make([]byte, 0, 104)
	minBuf = append(minBuf, 0x01)
	minBuf = append(minBuf, 0x05)
	minBuf = append(minBuf, expBuf[:]...)
	minBuf = append(minBuf, 0x03)
	minBuf = append(minBuf, certifiedKey[:]...)
	minBuf = append(minBuf, 0x00) // n_extensions = 0
	sig2 := ed25519.Sign(privKey, minBuf)
	minBuf = append(minBuf, sig2...)
	f.Add(minBuf)

	// Seed: too short
	f.Add([]byte{0x01, 0x02, 0x03})

	// Seed: empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input.
		parseTorCert(data)
	})
}
