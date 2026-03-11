package circpool

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/circuit"
)

// mockBuilder implements CircuitBuilder for tests.
type mockBuilder struct {
	mu        sync.Mutex
	built     int
	failAfter int // if > 0, fail after this many builds
	failErr   error
	delay     time.Duration // artificial build delay
}

func (m *mockBuilder) Build() (*circuit.Circuit, io.Closer, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAfter > 0 && m.built >= m.failAfter {
		if m.failErr != nil {
			return nil, nil, m.failErr
		}
		return nil, nil, errors.New("mock build failure")
	}
	m.built++
	circ := newTestPoolCircuit()
	return circ, io.NopCloser(nil), nil
}

func (m *mockBuilder) builtCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.built
}

// newTestPoolCircuit creates a minimal circuit for pool tests.
func newTestPoolCircuit() *circuit.Circuit {
	return circuit.NewTestCircuit(0x80000001, &nopCellReader{})
}

// nopCellReader blocks forever (circuit won't read cells in pool tests).
type nopCellReader struct{}

func (n *nopCellReader) ReadCell() (cell.Cell, error) {
	select {} //nolint:gosimple // intentional block forever
}

func TestPoolStartsWithNCircuits(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 3})
	defer p.Close()

	// Wait for pool to fill.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("pool did not fill: built=%d, want 3", builder.builtCount())
		default:
		}
		if builder.builtCount() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if builder.builtCount() != 3 {
		t.Fatalf("expected 3 circuits built, got %d", builder.builtCount())
	}
}

func TestPoolGetAndReturn(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 2})
	defer p.Close()

	// Wait for pool to fill.
	waitForBuilt(t, builder, 2)

	circ, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if circ == nil {
		t.Fatal("Get returned nil circuit")
	}

	// Return it.
	p.Return(circ)

	// Should be able to get it again.
	circ2, err := p.Get()
	if err != nil {
		t.Fatalf("Get after Return: %v", err)
	}
	if circ2 == nil {
		t.Fatal("Get after Return returned nil")
	}
}

func TestPoolGetBlocksWhenEmpty(t *testing.T) {
	// Builder with delay so pool starts empty.
	builder := &mockBuilder{delay: 200 * time.Millisecond}
	p := NewPool(builder, PoolConfig{Size: 1, GetTimeout: 2 * time.Second})
	defer p.Close()

	start := time.Now()
	circ, err := p.Get()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if circ == nil {
		t.Fatal("Get returned nil")
	}
	if elapsed < 100*time.Millisecond {
		t.Fatalf("Get returned too quickly (%v), expected to block", elapsed)
	}
}

func TestPoolGetTimesOut(t *testing.T) {
	// Builder that always fails - pool never fills.
	builder := &mockBuilder{failAfter: 0, failErr: errors.New("always fail")}
	builder.failAfter = 1
	builder.built = 1 // already at limit

	p := NewPool(builder, PoolConfig{Size: 1, GetTimeout: 100 * time.Millisecond})
	defer p.Close()

	start := time.Now()
	_, err := p.Get()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed < 80*time.Millisecond {
		t.Fatalf("Get returned too quickly (%v), expected timeout", elapsed)
	}
}

func TestPoolRebuildsOnCircuitDeath(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 2})
	defer p.Close()

	waitForBuilt(t, builder, 2)

	// Get a circuit and destroy it, then return it.
	circ, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = circ.Destroy()
	p.Return(circ)

	// Pool should rebuild. Wait for builder to have built more than 2.
	waitForBuilt(t, builder, 3)
}

func TestPoolRotatesAfterMaxAge(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{
		Size:   1,
		MaxAge: 100 * time.Millisecond,
	})
	defer p.Close()

	waitForBuilt(t, builder, 1)

	// Wait for the circuit to expire.
	time.Sleep(200 * time.Millisecond)

	// Get should return a new circuit (the expired one should be replaced).
	circ, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if circ == nil {
		t.Fatal("Get returned nil")
	}

	// Builder should have built more than 1 circuit (the expired one was replaced).
	if builder.builtCount() < 2 {
		t.Fatalf("expected at least 2 builds (rotation), got %d", builder.builtCount())
	}
}

func TestPoolCloseClean(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 3})

	waitForBuilt(t, builder, 3)

	p.Close()

	// Get after close should fail.
	_, err := p.Get()
	if err == nil {
		t.Fatal("expected error on Get after Close")
	}

	// Second close should not panic.
	p.Close()
}

func TestPoolConcurrentGetReturn(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 5, GetTimeout: 5 * time.Second})
	defer p.Close()

	waitForBuilt(t, builder, 5)

	var wg sync.WaitGroup
	var gets atomic.Int32

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			circ, err := p.Get()
			if err != nil {
				return // pool may be under pressure, that's fine
			}
			gets.Add(1)
			time.Sleep(5 * time.Millisecond) // simulate usage
			p.Return(circ)
		}()
	}

	wg.Wait()
	if gets.Load() == 0 {
		t.Fatal("no successful Gets in concurrent test")
	}
}

func TestPoolBuildFailureDoesNotCrash(t *testing.T) {
	// Builder that fails on every attempt.
	builder := &mockBuilder{
		failAfter: 1,
		built:     1, // already at limit, will fail on every Build call
		failErr:   errors.New("build broken"),
	}

	p := NewPool(builder, PoolConfig{Size: 2, GetTimeout: 100 * time.Millisecond})
	defer p.Close()

	// Should not crash. Get should timeout.
	_, err := p.Get()
	if err == nil {
		t.Fatal("expected timeout error when builder always fails")
	}
}

// waitForBuilt polls until builder.builtCount() >= n.
func waitForBuilt(t *testing.T, builder *mockBuilder, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for %d circuits to be built (got %d)", n, builder.builtCount())
		default:
		}
		if builder.builtCount() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Verify that the mock creates circuits with working Done channels.
func TestMockCircuitDone(t *testing.T) {
	circ := newTestPoolCircuit()
	select {
	case <-circ.Done():
		t.Fatal("circuit should not be done yet")
	default:
	}

	_ = circ.Destroy()

	select {
	case <-circ.Done():
	case <-time.After(time.Second):
		t.Fatal("circuit Done not closed after Destroy")
	}
}

// mockCloser tracks whether Close was called.
type mockCloser struct {
	closed atomic.Bool
}

func (m *mockCloser) Close() error {
	m.closed.Store(true)
	return nil
}

// closerBuilder returns mockClosers to verify they get closed.
type closerBuilder struct {
	mu      sync.Mutex
	closers []*mockCloser
}

func (cb *closerBuilder) Build() (*circuit.Circuit, io.Closer, error) {
	circ := newTestPoolCircuit()
	mc := &mockCloser{}
	cb.mu.Lock()
	cb.closers = append(cb.closers, mc)
	cb.mu.Unlock()
	return circ, mc, nil
}

func TestPoolReturnAfterClose(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 2})

	waitForBuilt(t, builder, 2)

	circ, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	p.Close()

	// Return after Close should not panic (tests that inUse map is not nil).
	p.Return(circ)
}

func TestPoolReturnUnknownCircuit(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 1})
	defer p.Close()

	waitForBuilt(t, builder, 1)

	// Return a circuit that was never checked out.
	unknown := newTestPoolCircuit()
	p.Return(unknown) // should not panic
}

func TestPoolFillerCountsInUse(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 2, GetTimeout: 2 * time.Second})
	defer p.Close()

	waitForBuilt(t, builder, 2)

	// Get both circuits (both now in-use).
	c1, err := p.Get()
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	c2, err := p.Get()
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}

	// The filler should NOT build more circuits because in-use count
	// is included in the deficit calculation: need = Size - ready - inUse.
	time.Sleep(100 * time.Millisecond)
	if builder.builtCount() != 2 {
		t.Fatalf("expected exactly 2 builds (in-use circuits count), got %d", builder.builtCount())
	}

	p.Return(c1)
	p.Return(c2)
}

func TestPoolSignalFillerOnEviction(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{
		Size:       2,
		MaxAge:     50 * time.Millisecond,
		GetTimeout: 5 * time.Second,
	})
	defer p.Close()

	waitForBuilt(t, builder, 2)

	// Wait for circuits to expire, then Get should trigger eviction + rebuild.
	time.Sleep(100 * time.Millisecond)

	circ, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if circ == nil {
		t.Fatal("Get returned nil")
	}

	// Builder should have built replacements.
	if builder.builtCount() < 3 {
		t.Fatalf("expected at least 3 builds after eviction, got %d", builder.builtCount())
	}
}

func TestPoolCloseDestroysAllCircuits(t *testing.T) {
	cb := &closerBuilder{}
	p := NewPool(cb, PoolConfig{Size: 3})

	// Wait for pool to fill.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for pool to fill")
		default:
		}
		cb.mu.Lock()
		n := len(cb.closers)
		cb.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Get one circuit (so it's in-use, not ready).
	circ, err := p.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = circ // just holding it

	p.Close()

	// All closers should have been called.
	cb.mu.Lock()
	defer cb.mu.Unlock()
	for i, mc := range cb.closers {
		if !mc.closed.Load() {
			t.Errorf("closer %d was not closed", i)
		}
	}
}
