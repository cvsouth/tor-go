package onion

import (
	"encoding/base64"
	"testing"
)

func FuzzParseLinkSpecifiers(f *testing.F) {
	// Seed: valid IPv4 + RSA identity link specifier block
	f.Add([]byte{
		0x02,       // NSPEC = 2
		0x00, 0x06, // LSTYPE=IPv4, LSLEN=6
		192, 168, 1, 1, // IP
		0x01, 0xBB, // port 443
		0x02, 0x14, // LSTYPE=RSA, LSLEN=20
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	})

	// Seed: single IPv6 specifier
	f.Add([]byte{
		0x01,       // NSPEC = 1
		0x01, 0x12, // LSTYPE=IPv6, LSLEN=18
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // IPv6
		0x00, 0x50, // port 80
	})

	// Seed: empty
	f.Add([]byte{})

	// Seed: zero specifiers
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input.
		ParseLinkSpecifiers(data)
	})
}

func FuzzDecodeOnion(f *testing.F) {
	// Known valid v3 .onion addresses
	f.Add("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion")
	f.Add("sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion")
	f.Add("xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion")
	// Without suffix
	f.Add("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd")
	// Short / invalid
	f.Add("short.onion")
	f.Add("")

	f.Fuzz(func(t *testing.T, address string) {
		DecodeOnion(address)
	})
}

func FuzzDecodeChunked(f *testing.F) {
	// Valid chunked encoding
	f.Add("5\r\nhello\r\n6\r\n world\r\n0\r\n")
	// Single chunk
	f.Add("a\r\n0123456789\r\n0\r\n")
	// Empty
	f.Add("")
	// Just terminator
	f.Add("0\r\n")
	// Malformed
	f.Add("gg\r\nbad hex\r\n")

	f.Fuzz(func(t *testing.T, data string) {
		decodeChunked(data)
	})
}

func FuzzParseDescriptorOuter(f *testing.F) {
	// Minimal valid-ish descriptor
	blob := base64.StdEncoding.EncodeToString([]byte("test-superencrypted-data"))
	f.Add("hs-descriptor 3\n" +
		"descriptor-lifetime 180\n" +
		"descriptor-signing-key-cert\n" +
		"-----BEGIN ED25519 CERT-----\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n" +
		"-----END ED25519 CERT-----\n" +
		"revision-counter 1\n" +
		"superencrypted\n" +
		"-----BEGIN MESSAGE-----\n" +
		blob + "\n" +
		"-----END MESSAGE-----\n" +
		"signature AAAA\n")

	// Empty
	f.Add("")

	// Just headers, no message block
	f.Add("descriptor-lifetime 999\nrevision-counter 42\n")

	f.Fuzz(func(t *testing.T, text string) {
		ParseDescriptorOuter(text)
	})
}
