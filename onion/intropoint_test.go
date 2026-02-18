package onion

import (
	"encoding/base64"
	"testing"
)

func TestParseIntroPoints(t *testing.T) {
	// Create test keys.
	linkSpec := make([]byte, 8)
	linkSpec[0] = 0x01
	onionKey := make([]byte, 32)
	onionKey[0] = 0xAA
	encKey := make([]byte, 32)
	encKey[0] = 0xBB
	authCert := make([]byte, 16)
	authCert[0] = 0xCC

	text := "introduction-point " + base64.StdEncoding.EncodeToString(linkSpec) + "\n" +
		"onion-key ntor " + base64.RawStdEncoding.EncodeToString(onionKey) + "\n" +
		"auth-key\n" +
		"-----BEGIN ED25519 CERT-----\n" +
		base64.StdEncoding.EncodeToString(authCert) + "\n" +
		"-----END ED25519 CERT-----\n" +
		"enc-key ntor " + base64.RawStdEncoding.EncodeToString(encKey) + "\n" +
		"enc-key-cert\n" +
		"-----BEGIN ED25519 CERT-----\n" +
		base64.StdEncoding.EncodeToString(authCert) + "\n" +
		"-----END ED25519 CERT-----\n"

	points, err := parseIntroPoints(text)
	if err != nil {
		t.Fatalf("parseIntroPoints: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("expected 1 intro point, got %d", len(points))
	}

	p := points[0]
	if p.OnionKey[0] != 0xAA {
		t.Fatalf("onion key: got 0x%02x, want 0xAA", p.OnionKey[0])
	}
	if p.EncKey[0] != 0xBB {
		t.Fatalf("enc key: got 0x%02x, want 0xBB", p.EncKey[0])
	}
	if len(p.AuthKeyCert) == 0 {
		t.Fatal("expected auth-key cert")
	}
	if len(p.LinkSpecifiers) == 0 {
		t.Fatal("expected link specifiers")
	}
}

func TestParseIntroPointsMultiple(t *testing.T) {
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ls := base64.StdEncoding.EncodeToString(make([]byte, 8))

	text := "introduction-point " + ls + "\n" +
		"onion-key ntor " + key + "\n" +
		"enc-key ntor " + key + "\n" +
		"introduction-point " + ls + "\n" +
		"onion-key ntor " + key + "\n" +
		"enc-key ntor " + key + "\n" +
		"introduction-point " + ls + "\n" +
		"onion-key ntor " + key + "\n" +
		"enc-key ntor " + key + "\n"

	points, err := parseIntroPoints(text)
	if err != nil {
		t.Fatalf("parseIntroPoints: %v", err)
	}
	if len(points) != 3 {
		t.Fatalf("expected 3 intro points, got %d", len(points))
	}
}

func TestParseIntroPointsEmpty(t *testing.T) {
	points, err := parseIntroPoints("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(points) != 0 {
		t.Fatalf("expected 0 intro points, got %d", len(points))
	}
}

func TestParseLinkSpecifiers(t *testing.T) {
	// Build a link specifier block: NSPEC=2, IPv4 + RSA identity
	data := []byte{
		0x02,       // NSPEC = 2
		0x00, 0x06, // LSTYPE=IPv4, LSLEN=6
		192, 168, 1, 1, // IP
		0x01, 0xBB, // port 443
		0x02, 0x14, // LSTYPE=RSA, LSLEN=20
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20, // identity
	}

	specs, err := ParseLinkSpecifiers(data)
	if err != nil {
		t.Fatalf("ParseLinkSpecifiers: %v", err)
	}
	if specs.Address != "192.168.1.1" {
		t.Errorf("address: got %q, want 192.168.1.1", specs.Address)
	}
	if specs.ORPort != 443 {
		t.Errorf("port: got %d, want 443", specs.ORPort)
	}
	if specs.Identity[0] != 1 || specs.Identity[19] != 20 {
		t.Errorf("identity mismatch")
	}
}

func TestParseLinkSpecifiersNoAddress(t *testing.T) {
	// Only RSA identity, no IPv4/IPv6
	data := []byte{0x01, 0x02, 0x14}
	data = append(data, make([]byte, 20)...)
	_, err := ParseLinkSpecifiers(data)
	if err == nil {
		t.Fatal("expected error for missing address")
	}
}

func TestParseFirstLayerPlaintext(t *testing.T) {
	innerBlob := []byte("encrypted-inner-data")
	b64 := base64.StdEncoding.EncodeToString(innerBlob)

	text := "desc-auth-type x25519\n" +
		"desc-auth-ephemeral-key AAAA\n" +
		"auth-client AAAA BBBB CCCC\n" +
		"encrypted\n" +
		"-----BEGIN MESSAGE-----\n" +
		b64 + "\n" +
		"-----END MESSAGE-----\n"

	result, err := parseFirstLayerPlaintext(text)
	if err != nil {
		t.Fatalf("parseFirstLayerPlaintext: %v", err)
	}
	if string(result) != string(innerBlob) {
		t.Fatalf("got %q, want %q", result, innerBlob)
	}
}
