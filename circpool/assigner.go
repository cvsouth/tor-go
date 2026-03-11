package circpool

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cvsouth/tor-go/circuit"
)

// Assigner assigns streams to circuits based on origin isolation policy.
// Same origin reuses the same circuit (if still healthy). Different origins
// get different circuits when the pool has capacity. .onion addresses always
// get their own dedicated circuit, never shared with clearnet origins.
type Assigner struct {
	pool    *Pool
	mu      sync.Mutex
	mapping map[string]*circuit.Circuit // origin -> circuit
}

// NewAssigner creates an Assigner backed by the given pool.
func NewAssigner(pool *Pool) *Assigner {
	return &Assigner{
		pool:    pool,
		mapping: make(map[string]*circuit.Circuit),
	}
}

// AssignCircuit returns a circuit for the given origin.
// Same origin reuses the same circuit (if still healthy).
// Different origins get different circuits (when pool has capacity).
// .onion addresses always get their own circuit (never shared with clearnet).
func (a *Assigner) AssignCircuit(origin string) (*circuit.Circuit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check existing mapping.
	if circ, ok := a.mapping[origin]; ok {
		if isCircuitHealthy(circ) {
			return circ, nil
		}
		// Dead circuit - clean up and get a new one.
		delete(a.mapping, origin)
		a.pool.Return(circ)
	}

	// Check if all pool circuits are already checked out by this assigner.
	// If so, skip the blocking Get() and fall back immediately.
	if a.hasAllCircuits() {
		circ := a.leastUsedCircuit(origin)
		if circ == nil {
			return nil, fmt.Errorf("no circuits available and no fallback candidates")
		}
		a.mapping[origin] = circ
		return circ, nil
	}

	// Try to get a fresh circuit from the pool.
	circ, err := a.pool.Get()
	if err != nil {
		// Pool exhausted - fall back to least-loaded (reuse existing).
		circ = a.leastUsedCircuit(origin)
		if circ == nil {
			return nil, fmt.Errorf("no circuits available: %w", err)
		}
		a.mapping[origin] = circ
		return circ, nil
	}

	a.mapping[origin] = circ

	// Start a goroutine to clean up the mapping when the circuit dies.
	go a.watchCircuit(origin, circ)

	return circ, nil
}

// Release notifies the assigner that a circuit is no longer needed for an origin.
func (a *Assigner) Release(origin string) {
	a.mu.Lock()
	circ, ok := a.mapping[origin]
	if ok {
		delete(a.mapping, origin)
	}
	a.mu.Unlock()

	if ok && circ != nil {
		a.pool.Return(circ)
	}
}

// hasAllCircuits returns true if the assigner already holds at least as many
// unique circuits as the pool's configured size, meaning pool.Get() would block.
// Caller must hold a.mu.
func (a *Assigner) hasAllCircuits() bool {
	unique := make(map[*circuit.Circuit]struct{})
	for _, c := range a.mapping {
		if isCircuitHealthy(c) {
			unique[c] = struct{}{}
		}
	}
	return len(unique) >= a.pool.Size() && a.pool.ReadyCount() == 0
}

// leastUsedCircuit returns a circuit that is used by the fewest origins.
// It respects onion isolation: onion origins never reuse clearnet circuits
// and vice versa.
func (a *Assigner) leastUsedCircuit(origin string) *circuit.Circuit {
	isOnion := strings.HasSuffix(strings.ToLower(origin), ".onion")

	// Count how many origins share each circuit.
	usage := make(map[*circuit.Circuit]int)
	for o, c := range a.mapping {
		if !isCircuitHealthy(c) {
			continue
		}
		oIsOnion := strings.HasSuffix(strings.ToLower(o), ".onion")
		// Enforce onion/clearnet isolation.
		if isOnion != oIsOnion {
			continue
		}
		usage[c]++
	}

	var best *circuit.Circuit
	bestCount := int(^uint(0) >> 1) // max int
	for c, count := range usage {
		if count < bestCount {
			bestCount = count
			best = c
		}
	}
	return best
}

// watchCircuit monitors a circuit's Done channel and cleans up the mapping
// when the circuit dies.
func (a *Assigner) watchCircuit(origin string, circ *circuit.Circuit) {
	<-circ.Done()

	a.mu.Lock()
	// Only delete if the mapping still points to the same circuit.
	if a.mapping[origin] == circ {
		delete(a.mapping, origin)
	}
	a.mu.Unlock()
}

// isCircuitHealthy checks if a circuit is still alive.
func isCircuitHealthy(circ *circuit.Circuit) bool {
	select {
	case <-circ.Done():
		return false
	default:
		return true
	}
}
