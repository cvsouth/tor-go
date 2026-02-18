package link

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"
)

// Ed25519 Tor certificate types
const (
	certTypeIdentitySigning = 4
	certTypeSigningTLS      = 5
)

// torCert represents a parsed Ed25519 Tor certificate.
type torCert struct {
	Version       uint8
	CertType      uint8
	ExpirationHrs uint32
	KeyType       uint8
	CertifiedKey  [32]byte
	SigningKey    [32]byte // from extension type 0x04
	Signature     [64]byte
	Raw           []byte // full cert bytes for signature verification
}

func parseTorCert(data []byte) (*torCert, error) {
	if len(data) < 39+64 { // minimum: 39 header + 64 signature
		return nil, fmt.Errorf("tor cert too short: %d bytes", len(data))
	}

	tc := &torCert{
		Raw:           data,
		Version:       data[0],
		CertType:      data[1],
		ExpirationHrs: binary.BigEndian.Uint32(data[2:6]),
		KeyType:       data[6],
	}
	copy(tc.CertifiedKey[:], data[7:39])

	// Parse extensions
	nExt := data[39]
	pos := 40
	for i := uint8(0); i < nExt; i++ {
		if pos+4 > len(data)-64 { // must leave room for signature
			return nil, fmt.Errorf("extension overflows cert at pos %d", pos)
		}
		extLen := int(binary.BigEndian.Uint16(data[pos:])) // length of ExtData only
		extType := data[pos+2]
		extFlags := data[pos+3]
		pos += 4 // skip ExtLen(2) + ExtType(1) + ExtFlags(1)
		if pos+extLen > len(data)-64 {
			return nil, fmt.Errorf("extension data overflows")
		}
		extData := data[pos : pos+extLen]
		if extType == 0x04 && len(extData) == 32 {
			copy(tc.SigningKey[:], extData)
		} else if extFlags&0x01 != 0 {
			// AFFECTS_VALIDATION is set on an unrecognized extension — must reject per cert-spec
			return nil, fmt.Errorf("unrecognized critical extension type 0x%02x", extType)
		}
		pos += extLen
	}

	// Signature is the last 64 bytes
	copy(tc.Signature[:], data[len(data)-64:])

	return tc, nil
}

// verify checks expiration and Ed25519 signature.
// If signingKey is non-nil, it's used instead of the embedded extension key.
func (tc *torCert) verify(signingKey []byte) error {
	expTime := time.Unix(int64(tc.ExpirationHrs)*3600, 0)
	if time.Now().After(expTime) {
		return fmt.Errorf("cert expired at %v", expTime)
	}

	// Determine which key to verify with
	var pubKey ed25519.PublicKey
	if signingKey != nil {
		pubKey = ed25519.PublicKey(signingKey)
	} else {
		zeroKey := [32]byte{}
		if tc.SigningKey == zeroKey {
			return fmt.Errorf("no signing key extension (type 0x04) found and none provided")
		}
		pubKey = ed25519.PublicKey(tc.SigningKey[:])
	}

	signed := tc.Raw[:len(tc.Raw)-64]
	if !ed25519.Verify(pubKey, signed, tc.Signature[:]) {
		return fmt.Errorf("ed25519 signature verification failed")
	}

	return nil
}

// validateCerts parses a CERTS cell payload and validates the Ed25519 certificate chain.
// Returns the relay's Ed25519 identity key.
func validateCerts(payload []byte, peerCertHash []byte, logger *slog.Logger) ([]byte, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("empty CERTS payload")
	}
	nCerts := payload[0]
	logger.Debug("certs cell", "n_certs", nCerts)

	pos := 1
	var cert4, cert5 *torCert

	for i := uint8(0); i < nCerts; i++ {
		if pos+3 > len(payload) {
			return nil, fmt.Errorf("certs cell truncated at cert %d", i)
		}
		certType := payload[pos]
		certLen := int(binary.BigEndian.Uint16(payload[pos+1:]))
		pos += 3
		if pos+certLen > len(payload) {
			return nil, fmt.Errorf("cert %d data overflows (type=%d, len=%d)", i, certType, certLen)
		}
		certData := payload[pos : pos+certLen]
		pos += certLen

		logger.Debug("cert entry", "index", i, "type", certType, "len", certLen)

		switch certType {
		case certTypeIdentitySigning:
			tc, err := parseTorCert(certData)
			if err != nil {
				return nil, fmt.Errorf("parse cert type 4: %w", err)
			}
			cert4 = tc
		case certTypeSigningTLS:
			tc, err := parseTorCert(certData)
			if err != nil {
				return nil, fmt.Errorf("parse cert type 5: %w", err)
			}
			cert5 = tc
		default:
			// Skip RSA certs and others
			logger.Debug("skipping cert", "type", certType)
		}
	}

	if cert4 == nil {
		return nil, fmt.Errorf("missing CertType 4 (IDENTITY_V_SIGNING)")
	}
	if cert5 == nil {
		return nil, fmt.Errorf("missing CertType 5 (SIGNING_V_TLS_CERT)")
	}

	// Validate CertType 4: identity key signs signing key
	// The extension 0x04 contains the identity key; certified key is the signing key
	if err := cert4.verify(nil); err != nil {
		return nil, fmt.Errorf("cert type 4 verification: %w", err)
	}
	identityKey := cert4.SigningKey // The key that signed cert4 IS the identity key
	signingKey := cert4.CertifiedKey

	logger.Debug("cert4 valid", "identity_key", fmt.Sprintf("%x", identityKey[:8]),
		"signing_key", fmt.Sprintf("%x", signingKey[:8]))

	// Validate CertType 5: signing key certifies TLS cert hash
	// cert5 may not have extension 0x04, so provide signing key explicitly
	if err := cert5.verify(signingKey[:]); err != nil {
		return nil, fmt.Errorf("cert type 5 verification: %w", err)
	}

	// cert5's certified key should be SHA-256 of TLS cert
	if cert5.KeyType != 0x03 {
		return nil, fmt.Errorf("cert type 5 key type should be 0x03 (SHA256-of-X509), got 0x%02x", cert5.KeyType)
	}
	if !hmac.Equal(cert5.CertifiedKey[:], peerCertHash[:32]) {
		return nil, fmt.Errorf("cert type 5 certified key does not match TLS certificate hash")
	}

	logger.Debug("cert5 valid: TLS cert hash matches")

	return identityKey[:], nil
}
