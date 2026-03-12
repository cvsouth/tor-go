package descriptor

import (
	"testing"
)

func FuzzParseDescriptor(f *testing.F) {
	// Seed: dynamically generated valid descriptor with correct signature
	validDesc, _ := buildSignedDescriptor(f)
	f.Add(validDesc)

	// Seed: empty
	f.Add("")

	// Seed: missing required fields
	f.Add("router OnlyRouter 5.6.7.8 443 0 0\n")

	// Seed: malformed lines
	f.Add("router\nfingerprint ZZZZ\nntor-onion-key !!!\n")

	f.Fuzz(func(t *testing.T, text string) {
		// Must not panic on any input.
		_, _ = ParseDescriptor(text)
	})
}
