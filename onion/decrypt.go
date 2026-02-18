package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	sKeyLen   = 32 // AES-256
	sIVLen    = 16 // AES-CTR IV
	macKeyLen = 32
	saltLen   = 16
	macLen    = 32 // SHA3-256 output
	totalKeys = sKeyLen + sIVLen + macKeyLen
)

// DecryptDescriptorLayer decrypts one layer of a v3 HS descriptor.
// The encrypted blob format is: SALT(16) | ENCRYPTED(variable) | MAC(32)
//
// Parameters:
//   - encrypted: the raw encrypted blob
//   - secretData: SECRET_DATA (blinded_public_key for outer, blinded_public_key|descriptor_cookie for inner)
//   - subcredential: the 32-byte subcredential
//   - revisionCounter: the descriptor's revision counter
//   - stringConstant: "hsdir-superencrypted-data" for outer, "hsdir-encrypted-data" for inner
func DecryptDescriptorLayer(encrypted []byte, secretData, subcredential []byte, revisionCounter uint64, stringConstant string) ([]byte, error) {
	// Minimum size: SALT(16) + at least 1 byte ciphertext + MAC(32)
	if len(encrypted) < saltLen+1+macLen {
		return nil, fmt.Errorf("encrypted blob too short: %d bytes", len(encrypted))
	}

	salt := encrypted[:saltLen]
	ciphertext := encrypted[saltLen : len(encrypted)-macLen]
	mac := encrypted[len(encrypted)-macLen:]

	// Derive keys: secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)
	var revBuf [8]byte
	binary.BigEndian.PutUint64(revBuf[:], revisionCounter)

	secretInput := make([]byte, 0, len(secretData)+len(subcredential)+8)
	secretInput = append(secretInput, secretData...)
	secretInput = append(secretInput, subcredential...)
	secretInput = append(secretInput, revBuf[:]...)

	// keys = SHAKE256(secret_input | salt | STRING_CONSTANT, totalKeys)
	kdfInput := make([]byte, 0, len(secretInput)+saltLen+len(stringConstant))
	kdfInput = append(kdfInput, secretInput...)
	kdfInput = append(kdfInput, salt...)
	kdfInput = append(kdfInput, []byte(stringConstant)...)

	keys := make([]byte, totalKeys)
	shake := sha3.NewShake256()
	shake.Write(kdfInput)
	_, _ = shake.Read(keys)

	secretKey := keys[:sKeyLen]
	secretIV := keys[sKeyLen : sKeyLen+sIVLen]
	macKey := keys[sKeyLen+sIVLen:]

	// Verify MAC before decrypting (MAC-then-decrypt).
	// D_MAC = SHA3-256(mac_key_len | MAC_KEY | salt_len | SALT | ENCRYPTED)
	expectedMAC := computeMAC(macKey, salt, ciphertext)
	if subtle.ConstantTimeCompare(expectedMAC, mac) != 1 {
		return nil, fmt.Errorf("descriptor MAC verification failed")
	}

	// Decrypt: AES-256-CTR XOR
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	stream := cipher.NewCTR(block, secretIV)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// computeMAC computes D_MAC = SHA3-256(mac_key_len | MAC_KEY | salt_len | SALT | ENCRYPTED)
func computeMAC(macKey, salt, encrypted []byte) []byte {
	h := sha3.New256()
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(macKey)))
	h.Write(lenBuf[:])
	h.Write(macKey)
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(salt)))
	h.Write(lenBuf[:])
	h.Write(salt)
	h.Write(encrypted)
	return h.Sum(nil)
}
