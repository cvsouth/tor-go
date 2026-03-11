// Package circpool maintains a pool of pre-built Tor circuits ready for use.
package circpool

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cvsouth/tor-go/circuit"
)

// CircuitBuilder creates a new circuit and returns the circuit plus an
// io.Closer for the underlying link (or other resources).
type CircuitBuilder interface {
	// Build creates a new circuit. Close blocks until any in-progress Build
	// completes; future context support could make this interruptible.
	Build() (*circuit.Circuit, io.Closer, error)
}

// PoolConfig configures the circuit pool.
type PoolConfig struct {
	Size       int           // Number of ready circuits to maintain (default 3)
	MaxAge     time.Duration // Max circuit lifetime (default 10 minutes)
	GetTimeout time.Duration // Max time to wait for a circuit (default 30s)
}

func (c *PoolConfig) defaults() {
	if c.Size <= 0 {
		c.Size = 3
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 10 * time.Minute
	}
	if c.GetTimeout <= 0 {
		c.GetTimeout = 30 * time.Second
	}
}

// poolEntry holds a circuit with its metadata and link closer.
type poolEntry struct {
	circ      *circuit.Circuit
	closer    io.Closer
	createdAt time.Time
}

// isHealthy returns true if the circuit is alive and not expired.
func (e *poolEntry) isHealthy(maxAge time.Duration) bool {
	select {
	case <-e.circ.Done():
		return false
	default:
	}
	if maxAge > 0 && time.Since(e.createdAt) >= maxAge {
		return false
	}
	return true
}

// destroy tears down the circuit and closes the link.
func (e *poolEntry) destroy() {
	_ = e.circ.Destroy()
	if e.closer != nil {
		_ = e.closer.Close()
	}
}

// Pool maintains a set of pre-built circuits ready for immediate use.
//
// Close forcibly destroys all circuits, including those currently checked out
// via Get. Callers holding such circuits will see errors on subsequent
// operations. Close blocks until any in-progress Build completes.
type Pool struct {
	builder      CircuitBuilder
	config       PoolConfig
	mu           sync.Mutex
	cond         *sync.Cond
	ready        []*poolEntry
	inUse        map[*circuit.Circuit]*poolEntry
	closed       bool
	fillerSignal chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	wg           sync.WaitGroup
}

// NewPool creates and starts a circuit pool. A background goroutine fills
// the pool to config.Size and replaces dead or expired circuits.
func NewPool(builder CircuitBuilder, config PoolConfig) *Pool {
	config.defaults()
	p := &Pool{
		builder:      builder,
		config:       config,
		ready:        make([]*poolEntry, 0, config.Size),
		inUse:        make(map[*circuit.Circuit]*poolEntry),
		fillerSignal: make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	p.cond = sync.NewCond(&p.mu)

	// Signal filler to start initial fill.
	p.signalFiller()

	p.wg.Add(1)
	go p.filler()
	return p
}

// Get returns an available circuit, blocking up to GetTimeout if none are
// ready. Returns an error if the pool is closed or the timeout expires.
func (p *Pool) Get() (*circuit.Circuit, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	deadline := time.Now().Add(p.config.GetTimeout)

	for {
		// Try to pop a healthy circuit from the ready slice.
		for len(p.ready) > 0 {
			last := len(p.ready) - 1
			entry := p.ready[last]
			p.ready = p.ready[:last]

			if entry.isHealthy(p.config.MaxAge) {
				p.inUse[entry.circ] = entry
				return entry.circ, nil
			}

			// Unhealthy - destroy outside the lock.
			p.mu.Unlock()
			entry.destroy()
			p.signalFiller()
			p.mu.Lock()
		}

		if p.closed {
			return nil, fmt.Errorf("pool is closed")
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("timeout waiting for circuit")
		}

		// Wait with timeout using a timer that broadcasts on expiry.
		timer := time.AfterFunc(remaining, func() {
			p.cond.Broadcast()
		})
		p.cond.Wait()
		timer.Stop()
	}
}

// Return gives a circuit back to the pool. If the circuit is still healthy
// it goes back into the ready pool; otherwise it is destroyed and the filler
// goroutine is signaled to build a replacement.
func (p *Pool) Return(circ *circuit.Circuit) {
	p.mu.Lock()
	entry, ok := p.inUse[circ]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(p.inUse, circ)

	if entry.isHealthy(p.config.MaxAge) && !p.closed {
		p.ready = append(p.ready, entry)
		p.cond.Signal()
		p.mu.Unlock()
	} else {
		p.mu.Unlock()
		entry.destroy()
		p.signalFiller()
	}
}

// Close tears down all circuits (ready and in-use) and stops the filler.
// Close forcibly destroys all circuits, including those currently checked out
// via Get. Callers holding such circuits will see errors on subsequent
// operations. Close blocks until any in-progress Build completes.
func (p *Pool) Close() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.wg.Wait()

		p.mu.Lock()
		p.closed = true

		// Destroy all ready circuits.
		for _, entry := range p.ready {
			entry.destroy()
		}
		p.ready = nil

		// Destroy in-use circuits. We keep the map allocated to avoid
		// races with concurrent Return calls after Close.
		for circ, entry := range p.inUse {
			entry.destroy()
			delete(p.inUse, circ)
		}

		p.cond.Broadcast()
		p.mu.Unlock()
	})
}

// Size returns the configured pool size.
func (p *Pool) Size() int {
	return p.config.Size
}

// ReadyCount returns the number of circuits currently in the ready queue.
func (p *Pool) ReadyCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ready)
}

// signalFiller sends a non-blocking signal to the filler goroutine.
func (p *Pool) signalFiller() {
	select {
	case p.fillerSignal <- struct{}{}:
	default:
	}
}

// filler is the background goroutine that keeps the pool filled to config.Size.
// It blocks on fillerSignal rather than polling.
func (p *Pool) filler() {
	defer p.wg.Done()

	const retryInterval = 500 * time.Millisecond

	for {
		select {
		case <-p.done:
			return
		case <-p.fillerSignal:
		}

		p.fillOnce(retryInterval)
	}
}

// fillOnce runs one fill cycle: evict expired, then build circuits until full.
func (p *Pool) fillOnce(retryInterval time.Duration) {
	for {
		select {
		case <-p.done:
			return
		default:
		}

		// Evict expired circuits.
		p.evictExpired()

		// Calculate need under the mutex.
		p.mu.Lock()
		need := p.config.Size - len(p.ready) - len(p.inUse)
		p.mu.Unlock()

		if need <= 0 {
			return
		}

		// Build one circuit at a time (keeps the loop responsive to shutdown).
		circ, closer, err := p.builder.Build()
		if err != nil {
			slog.Debug("pool: build failed", "err", err)
			select {
			case <-p.done:
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		entry := &poolEntry{
			circ:      circ,
			closer:    closer,
			createdAt: time.Now(),
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			entry.destroy()
			return
		}
		p.ready = append(p.ready, entry)
		p.cond.Signal()
		p.mu.Unlock()
	}
}

// evictExpired removes and destroys expired circuits from the ready slice.
func (p *Pool) evictExpired() {
	p.mu.Lock()
	var evicted []*poolEntry
	kept := p.ready[:0]
	for _, entry := range p.ready {
		if entry.isHealthy(p.config.MaxAge) {
			kept = append(kept, entry)
		} else {
			evicted = append(evicted, entry)
		}
	}
	p.ready = kept
	p.mu.Unlock()

	for _, entry := range evicted {
		entry.destroy()
	}

	if len(evicted) > 0 {
		p.signalFiller()
	}
}
