package pathselect

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"github.com/cvsouth/tor-go/directory"
)

// Path represents a selected guard → middle → exit path.
type Path struct {
	Guard  directory.Relay
	Middle directory.Relay
	Exit   directory.Relay
}

// SelectPath selects a 3-hop path from the consensus.
func SelectPath(consensus *directory.Consensus) (*Path, error) {
	exit, err := SelectExit(consensus)
	if err != nil {
		return nil, fmt.Errorf("select exit: %w", err)
	}

	guard, err := SelectGuard(consensus, exit)
	if err != nil {
		return nil, fmt.Errorf("select guard: %w", err)
	}

	middle, err := SelectMiddle(consensus, guard, exit)
	if err != nil {
		return nil, fmt.Errorf("select middle: %w", err)
	}

	return &Path{Guard: *guard, Middle: *middle, Exit: *exit}, nil
}

// SelectExit selects an exit relay with the Exit flag and no BadExit.
func SelectExit(consensus *directory.Consensus) (*directory.Relay, error) {
	var candidates []directory.Relay
	var weights []int64

	wee := getWeight(consensus, "Wee", 10000)

	for _, r := range consensus.Relays {
		if !r.Flags.Exit || r.Flags.BadExit || !r.Flags.Running || !r.Flags.Valid || !r.HasNtorKey {
			continue
		}
		candidates = append(candidates, r)
		weights = append(weights, r.Bandwidth*wee/10000)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable exit relays found")
	}

	idx, err := weightedRandom(weights)
	if err != nil {
		return nil, err
	}
	return &candidates[idx], nil
}

// SelectGuard selects a guard relay with Guard+Fast+Running flags, not in the same /16 as the exit.
func SelectGuard(consensus *directory.Consensus, exit *directory.Relay) (*directory.Relay, error) {
	var candidates []directory.Relay
	var weights []int64

	wgg := getWeight(consensus, "Wgg", 10000)
	wgd := getWeight(consensus, "Wgd", 10000)
	exitSubnet := subnet16(exit.Address)

	for _, r := range consensus.Relays {
		if !r.Flags.Guard || !r.Flags.Fast || !r.Flags.Running || !r.Flags.Valid || !r.HasNtorKey {
			continue
		}
		// Same /16 subnet check
		if subnet16(r.Address) == exitSubnet {
			continue
		}
		// Don't pick the same relay as exit
		if r.Identity == exit.Identity {
			continue
		}
		candidates = append(candidates, r)
		w := wgg
		if r.Flags.Exit {
			w = wgd
		}
		weights = append(weights, r.Bandwidth*w/10000)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable guard relays found")
	}

	idx, err := weightedRandom(weights)
	if err != nil {
		return nil, err
	}
	return &candidates[idx], nil
}

// SelectMiddle selects a middle relay with Fast+Running flags, not in same /16 as guard or exit.
func SelectMiddle(consensus *directory.Consensus, guard, exit *directory.Relay) (*directory.Relay, error) {
	var candidates []directory.Relay
	var weights []int64

	wmm := getWeight(consensus, "Wmm", 10000)
	wmg := getWeight(consensus, "Wmg", 10000)
	wme := getWeight(consensus, "Wme", 10000)
	wmd := getWeight(consensus, "Wmd", 10000)
	guardSubnet := subnet16(guard.Address)
	exitSubnet := subnet16(exit.Address)

	for _, r := range consensus.Relays {
		if !r.Flags.Fast || !r.Flags.Running || !r.Flags.Valid || !r.HasNtorKey {
			continue
		}
		// Same /16 subnet check
		s := subnet16(r.Address)
		if s == guardSubnet || s == exitSubnet {
			continue
		}
		// Don't pick same relay
		if r.Identity == guard.Identity || r.Identity == exit.Identity {
			continue
		}
		candidates = append(candidates, r)
		w := wmm
		switch {
		case r.Flags.Guard && r.Flags.Exit:
			w = wmd
		case r.Flags.Guard:
			w = wmg
		case r.Flags.Exit:
			w = wme
		}
		weights = append(weights, r.Bandwidth*w/10000)
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no suitable middle relays found")
	}

	idx, err := weightedRandom(weights)
	if err != nil {
		return nil, err
	}
	return &candidates[idx], nil
}

func getWeight(c *directory.Consensus, key string, defaultVal int64) int64 {
	if v, ok := c.BandwidthWeights[key]; ok {
		return v
	}
	return defaultVal
}

// subnet16 returns the /16 prefix of an IPv4 address as a string.
func subnet16(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d", ip4[0], ip4[1])
}

// weightedRandom selects an index proportional to the given weights using crypto/rand.
func weightedRandom(weights []int64) (int, error) {
	if len(weights) == 0 {
		return 0, fmt.Errorf("empty weights")
	}

	var total int64
	for _, w := range weights {
		if w < 0 {
			w = 0
		}
		total += w
	}

	if total <= 0 {
		// All zero weights — uniform random (unbiased)
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(weights))))
		if err != nil {
			return 0, fmt.Errorf("crypto/rand: %w", err)
		}
		return int(n.Int64()), nil
	}

	// Generate random value in [0, total) without modulo bias
	n, err := rand.Int(rand.Reader, big.NewInt(total))
	if err != nil {
		return 0, fmt.Errorf("crypto/rand: %w", err)
	}
	r := n.Int64()

	var cumulative int64
	for i, w := range weights {
		if w < 0 {
			w = 0
		}
		cumulative += w
		if r < cumulative {
			return i, nil
		}
	}

	return len(weights) - 1, nil
}
