package descriptor

import (
	"testing"
)

func FuzzParseDescriptor(f *testing.F) {
	// Seed: minimal valid relay descriptor
	f.Add("router TestRelay 1.2.3.4 9001 0 0\n" +
		"fingerprint ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234 ABCD 1234\n" +
		"ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")

	// Seed: empty
	f.Add("")

	// Seed: missing required fields
	f.Add("router OnlyRouter 5.6.7.8 443 0 0\n")

	// Seed: malformed lines
	f.Add("router\nfingerprint ZZZZ\nntor-onion-key !!!\n")

	f.Fuzz(func(t *testing.T, text string) {
		// Must not panic on any input.
		ParseDescriptor(text)
	})
}
