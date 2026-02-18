package directory

import "time"

// Consensus represents a parsed Tor microdescriptor consensus.
type Consensus struct {
	ValidAfter              time.Time
	FreshUntil              time.Time
	ValidUntil              time.Time
	SharedRandCurrentValue  []byte
	SharedRandPreviousValue []byte
	Relays                  []Relay
	BandwidthWeights        map[string]int64 // Wgg, Wgm, Wmg, Wmm, etc.
}

// Relay represents a router entry in the consensus.
type Relay struct {
	Nickname        string
	Identity        [20]byte // SHA-1 of RSA identity key (base64-decoded from "r" line)
	Address         string   // IPv4 address
	ORPort          uint16
	DirPort         uint16
	Flags           RelayFlags
	Bandwidth       int64  // From "w Bandwidth=" line
	MicrodescDigest string // Base64 microdesc digest from "m" line

	// Populated after microdescriptor fetch
	NtorOnionKey [32]byte
	Ed25519ID    [32]byte
	HasNtorKey   bool
	HasEd25519   bool
}

// RelayFlags represents the flags assigned to a relay in the consensus.
type RelayFlags struct {
	Authority bool
	BadExit   bool
	Exit      bool
	Fast      bool
	Guard     bool
	HSDir     bool
	Running   bool
	Stable    bool
	Valid     bool
}
