package directory

import (
	"testing"
)

func FuzzParseConsensus(f *testing.F) {
	// Seed: valid minimal consensus from existing tests
	f.Add(`network-status-version 3 microdesc
vote-status consensus
consensus-method 32
valid-after 2025-01-15 12:00:00
fresh-until 2025-01-15 13:00:00
valid-until 2025-01-15 15:00:00
shared-rand-current-value 12 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
r TestRelay1 AAAAAAAAAAAAAAAAAAAAAAAAAAA 2025-01-15 11:30:00 1.2.3.4 9001 0
m sha256=abcdefghijklmnopqrstuvwxyz012345678901234567
s Exit Fast Guard Running Stable Valid
w Bandwidth=5000
bandwidth-weights Wbd=0 Wbe=0 Wbg=4131 Wbm=10000
`)

	// Seed: empty document
	f.Add("")

	// Seed: just headers, no relays
	f.Add("valid-after 2025-01-15 12:00:00\nfresh-until 2025-01-15 13:00:00\n")

	// Seed: relay with incomplete fields
	f.Add("r Broken\ns Exit\nw Bandwidth=abc\n")

	f.Fuzz(func(t *testing.T, text string) {
		// Must not panic on any input.
		ParseConsensus(text)
	})
}

func FuzzParseMicrodescriptor(f *testing.F) {
	// Seed: valid microdescriptor
	f.Add("onion-key\nntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nid ed25519 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n")

	// Seed: no keys
	f.Add("onion-key\n")

	// Seed: empty
	f.Add("")

	// Seed: bad base64
	f.Add("ntor-onion-key !!!invalid!!!\nid ed25519 ???also-bad???\n")

	f.Fuzz(func(t *testing.T, text string) {
		ParseMicrodescriptor(text)
	})
}
