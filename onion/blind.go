package onion

import (
	"encoding/binary"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

const (
	// Default time period length in minutes (1 day)
	defaultTimePeriodLength = 1440
	// Rotation time offset: 12 voting periods of 60 minutes each = 720 minutes
	rotationTimeOffset = 12 * 60
)

// blindString is the constant prefix for blinding factor derivation.
var blindString = []byte("Derive temporary signing key\x00")

// ed25519Basepoint is the string representation of the Ed25519 basepoint B,
// as specified in rend-spec-v3.
var ed25519Basepoint = []byte("(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)")

// TimePeriod computes the current time period number.
// tp = (minutes_since_epoch - rotation_time_offset) / time_period_length
func TimePeriod(t time.Time, periodLength int64) int64 {
	if periodLength <= 0 {
		periodLength = defaultTimePeriodLength
	}
	minutesSinceEpoch := t.Unix() / 60
	return (minutesSinceEpoch - rotationTimeOffset) / periodLength
}

// BlindPublicKey derives the blinded public key A' = h * A for the given
// time period. The nonce N = "key-blind" | INT_8(period_number) | INT_8(period_length).
func BlindPublicKey(pubkey [32]byte, periodNumber int64, periodLength int64) ([32]byte, error) {
	var blinded [32]byte

	if periodLength <= 0 {
		periodLength = defaultTimePeriodLength
	}

	// Compute nonce N
	nonce := buildBlindNonce(periodNumber, periodLength)

	// Compute blinding factor h = SHA3-256(BLIND_STRING | A | s | B | N)
	// For client-side, s (secret) is empty
	h := sha3.New256()
	h.Write(blindString)
	h.Write(pubkey[:])
	h.Write(ed25519Basepoint)
	h.Write(nonce)
	hBytes := h.Sum(nil)

	// h as scalar (SetBytesWithClamping handles clamping)
	hScalar, err := new(edwards25519.Scalar).SetBytesWithClamping(hBytes)
	if err != nil {
		return blinded, err
	}

	// A as point
	A, err := new(edwards25519.Point).SetBytes(pubkey[:])
	if err != nil {
		return blinded, err
	}

	// A' = h * A
	Aprime := new(edwards25519.Point).ScalarMult(hScalar, A)
	copy(blinded[:], Aprime.Bytes())
	return blinded, nil
}

// Subcredential computes the subcredential for a given time period.
// N_hs_subcred = SHA3-256("subcredential" | N_hs_cred | blinded_public_key)
// N_hs_cred = SHA3-256("credential" | public_identity_key)
func Subcredential(pubkey [32]byte, blindedKey [32]byte) [32]byte {
	// Credential
	credHash := sha3.New256()
	credHash.Write([]byte("credential"))
	credHash.Write(pubkey[:])
	credential := credHash.Sum(nil)

	// Subcredential
	subHash := sha3.New256()
	subHash.Write([]byte("subcredential"))
	subHash.Write(credential)
	subHash.Write(blindedKey[:])
	var subcred [32]byte
	copy(subcred[:], subHash.Sum(nil))
	return subcred
}

func buildBlindNonce(periodNumber, periodLength int64) []byte {
	// N = "key-blind" | INT_8(period_number) | INT_8(period_length)
	nonce := make([]byte, 0, 9+8+8)
	nonce = append(nonce, []byte("key-blind")...)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(periodNumber))
	nonce = append(nonce, buf[:]...)
	binary.BigEndian.PutUint64(buf[:], uint64(periodLength))
	nonce = append(nonce, buf[:]...)
	return nonce
}
