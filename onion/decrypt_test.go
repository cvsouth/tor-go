package onion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/sha3"
)

// encryptDescriptorLayer encrypts plaintext using the same scheme as DecryptDescriptorLayer,
// for testing round-trip correctness.
func encryptDescriptorLayer(plaintext, secretData, subcredential []byte, revisionCounter uint64, stringConstant string) ([]byte, error) {
	// Generate random salt.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive keys.
	var revBuf [8]byte
	binary.BigEndian.PutUint64(revBuf[:], revisionCounter)

	secretInput := make([]byte, 0, len(secretData)+len(subcredential)+8)
	secretInput = append(secretInput, secretData...)
	secretInput = append(secretInput, subcredential...)
	secretInput = append(secretInput, revBuf[:]...)

	kdfInput := make([]byte, 0, len(secretInput)+saltLen+len(stringConstant))
	kdfInput = append(kdfInput, secretInput...)
	kdfInput = append(kdfInput, salt...)
	kdfInput = append(kdfInput, []byte(stringConstant)...)

	keys := make([]byte, totalKeys)
	shake := sha3.NewShake256()
	shake.Write(kdfInput)
	shake.Read(keys)

	secretKey := keys[:sKeyLen]
	secretIV := keys[sKeyLen : sKeyLen+sIVLen]
	macKey := keys[sKeyLen+sIVLen:]

	// Encrypt.
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, secretIV)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// Compute MAC.
	mac := computeMAC(macKey, salt, ciphertext)

	// Format: SALT | ENCRYPTED | MAC
	result := make([]byte, 0, saltLen+len(ciphertext)+macLen)
	result = append(result, salt...)
	result = append(result, ciphertext...)
	result = append(result, mac...)
	return result, nil
}

func TestDecryptDescriptorLayerRoundTrip(t *testing.T) {
	plaintext := []byte("introduction-point aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	secretData := make([]byte, 32)
	secretData[0] = 0x42
	subcred := make([]byte, 32)
	subcred[0] = 0x99
	revisionCounter := uint64(12345)
	stringConstant := "hsdir-superencrypted-data"

	encrypted, err := encryptDescriptorLayer(plaintext, secretData, subcred, revisionCounter, stringConstant)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := DecryptDescriptorLayer(encrypted, secretData, subcred, revisionCounter, stringConstant)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptDescriptorLayerBadMAC(t *testing.T) {
	plaintext := []byte("test data")
	secretData := make([]byte, 32)
	subcred := make([]byte, 32)

	encrypted, err := encryptDescriptorLayer(plaintext, secretData, subcred, 1, "hsdir-superencrypted-data")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Corrupt the MAC (last 32 bytes).
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err = DecryptDescriptorLayer(encrypted, secretData, subcred, 1, "hsdir-superencrypted-data")
	if err == nil {
		t.Fatal("expected MAC verification failure")
	}
}

func TestDecryptDescriptorLayerWrongKey(t *testing.T) {
	plaintext := []byte("test data")
	secretData := make([]byte, 32)
	subcred := make([]byte, 32)

	encrypted, err := encryptDescriptorLayer(plaintext, secretData, subcred, 1, "hsdir-superencrypted-data")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Use wrong secret data.
	wrongSecret := make([]byte, 32)
	wrongSecret[0] = 0xFF
	_, err = DecryptDescriptorLayer(encrypted, wrongSecret, subcred, 1, "hsdir-superencrypted-data")
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestDecryptDescriptorLayerTooShort(t *testing.T) {
	_, err := DecryptDescriptorLayer(make([]byte, 48), nil, nil, 0, "test")
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := []byte{1, 2, 3, 4}
	c := []byte{1, 2, 3, 5}
	d := []byte{1, 2, 3}

	if subtle.ConstantTimeCompare(a, b) != 1 {
		t.Fatal("equal slices should match")
	}
	if subtle.ConstantTimeCompare(a, c) == 1 {
		t.Fatal("different slices should not match")
	}
	if subtle.ConstantTimeCompare(a, d) == 1 {
		t.Fatal("different lengths should not match")
	}
}
