package onion

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"golang.org/x/crypto/sha3"

	"github.com/cvsouth/tor-go/directory"
)

const (
	hsdirNReplicas   = 2
	hsdirSpreadFetch = 3
)

// hsdirEntry pairs a relay with its computed hash ring index.
type hsdirEntry struct {
	Relay *directory.Relay
	Index [32]byte
}

// SelectHSDirs selects the HSDirs to fetch a descriptor from for the given
// blinded public key and time period, per rend-spec-v3 §2.2.3.
func SelectHSDirs(consensus *directory.Consensus, blindedKey [32]byte, periodNum, periodLength int64, srv []byte) ([]*directory.Relay, error) {
	if len(srv) == 0 {
		return nil, fmt.Errorf("no shared random value available")
	}

	// Build the hash ring of HSDir relays.
	var ring []hsdirEntry
	for i := range consensus.Relays {
		r := &consensus.Relays[i]
		if !r.Flags.HSDir || !r.Flags.Running || !r.Flags.Valid || !r.HasEd25519 {
			continue
		}
		idx := relayIndex(r.Ed25519ID[:], srv, periodNum, periodLength)
		ring = append(ring, hsdirEntry{Relay: r, Index: idx})
	}
	if len(ring) == 0 {
		return nil, fmt.Errorf("no HSDir relays in consensus")
	}

	sort.Slice(ring, func(i, j int) bool {
		return bytes.Compare(ring[i].Index[:], ring[j].Index[:]) < 0
	})

	// For each replica, compute the service index and pick hsdir_spread_fetch
	// relays starting from that position in the ring.
	selected := make(map[*directory.Relay]bool)
	var result []*directory.Relay

	for replica := int64(1); replica <= hsdirNReplicas; replica++ {
		svcIdx := serviceIndex(blindedKey, replica, periodLength, periodNum)

		// Find the first relay in the ring whose index >= svcIdx.
		start := sort.Search(len(ring), func(i int) bool {
			return bytes.Compare(ring[i].Index[:], svcIdx[:]) >= 0
		})

		count := 0
		offset := 0
		for count < hsdirSpreadFetch {
			pos := (start + offset) % len(ring)
			offset++
			r := ring[pos].Relay
			if selected[r] {
				continue
			}
			selected[r] = true
			result = append(result, r)
			count++
			if len(selected) >= len(ring) {
				break // exhausted all HSDirs
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no HSDirs selected")
	}

	// Pick one randomly from the result set.
	return result, nil
}

// PickRandomHSDir picks a random HSDir from the candidate list.
func PickRandomHSDir(candidates []*directory.Relay) (*directory.Relay, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no HSDir candidates")
	}
	idx, err := uniformRandom(len(candidates))
	if err != nil {
		return nil, err
	}
	return candidates[idx], nil
}

// serviceIndex computes hs_service_index per rend-spec-v3 §2.2.3.
// SHA3-256("store-at-idx" | blinded_public_key | INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))
func serviceIndex(blindedKey [32]byte, replicanum, periodLength, periodNum int64) [32]byte {
	h := sha3.New256()
	h.Write([]byte("store-at-idx"))
	h.Write(blindedKey[:])
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(replicanum))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(periodLength))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(periodNum))
	h.Write(buf[:])
	var idx [32]byte
	copy(idx[:], h.Sum(nil))
	return idx
}

// relayIndex computes hs_relay_index per rend-spec-v3 §2.2.3.
// SHA3-256("node-idx" | node_identity | shared_random_value | INT_8(period_num) | INT_8(period_length))
func relayIndex(nodeIdentity, srv []byte, periodNum, periodLength int64) [32]byte {
	h := sha3.New256()
	h.Write([]byte("node-idx"))
	h.Write(nodeIdentity)
	h.Write(srv)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(periodNum))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(periodLength))
	h.Write(buf[:])
	var idx [32]byte
	copy(idx[:], h.Sum(nil))
	return idx
}

// GetSRVForClient returns the appropriate SRV for a client to use, per
// rend-spec-v3 §2.2.4.1. Between a new TP and a new SRV, use current SRV.
// Between a new SRV and a new TP, use previous SRV.
func GetSRVForClient(consensus *directory.Consensus) ([]byte, error) {
	// SRV changes at 00:00 UTC, TP changes at 12:00 UTC.
	// If valid-after hour < 12: we're between SRV and TP → use previous SRV
	// If valid-after hour >= 12: we're between TP and SRV → use current SRV
	hour := consensus.ValidAfter.Hour()
	if hour >= 12 {
		if len(consensus.SharedRandCurrentValue) > 0 {
			return consensus.SharedRandCurrentValue, nil
		}
		return nil, fmt.Errorf("no current SRV in consensus")
	}
	if len(consensus.SharedRandPreviousValue) > 0 {
		return consensus.SharedRandPreviousValue, nil
	}
	// Fallback to current if previous not available
	if len(consensus.SharedRandCurrentValue) > 0 {
		return consensus.SharedRandCurrentValue, nil
	}
	return nil, fmt.Errorf("no SRV available in consensus")
}

// modulo bias is negligible for 1-byte random over small lists but let's
// be precise: use big.Int for uniform selection if needed.
func uniformRandom(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("n must be positive")
	}
	max := new(big.Int).SetInt64(int64(n))
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return int(r.Int64()), nil
}
