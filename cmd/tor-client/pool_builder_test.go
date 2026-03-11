package main

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvsouth/tor-go/cell"
	"github.com/cvsouth/tor-go/circpool"
	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/onion"
)

// nopCellReader blocks forever (circuit won't read cells in these tests).
type nopCellReader struct{}

// ReadCell blocks forever. Test circuits using nopCellReader must never have
// StartReadLoop called, since select{} will block the goroutine permanently.
func (n *nopCellReader) ReadCell() (cell.Cell, error) {
	select {} //nolint:gosimple // intentional block forever
}

// fakeCircuitBuilder is a test double for circuitBuilder that doesn't need
// a real Tor network. It implements the same BuildCircuit interface.
type fakeCircuitBuilder struct {
	nextID      atomic.Uint32
	callCount   int
	lastTarget  *descriptor.RelayInfo
	shouldFail  bool
	failMessage string
}

func (f *fakeCircuitBuilder) BuildCircuit(target *descriptor.RelayInfo) (*onion.BuiltCircuit, error) {
	f.callCount++
	f.lastTarget = target
	if f.shouldFail {
		msg := "build failed"
		if f.failMessage != "" {
			msg = f.failMessage
		}
		return nil, errors.New(msg)
	}
	id := f.nextID.Add(1) | 0x80000000 // MSB set per Tor spec for initiated circuits
	circ := circuit.NewTestCircuit(id, &nopCellReader{})
	return &onion.BuiltCircuit{
		Circuit:    circ,
		LinkCloser: io.NopCloser(nil),
	}, nil
}

// testablePoolBuilder wraps a fakeCircuitBuilder to implement circpool.CircuitBuilder,
// mirroring what poolBuilder does with the real circuitBuilder.
type testablePoolBuilder struct {
	cb *fakeCircuitBuilder
}

func (pb *testablePoolBuilder) Build() (*circuit.Circuit, io.Closer, error) {
	built, err := pb.cb.BuildCircuit(nil)
	if err != nil {
		return nil, nil, err
	}
	return built.Circuit, built.LinkCloser, nil
}

func TestPoolBuilderCallsBuildCircuitWithNilTarget(t *testing.T) {
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	circ, closer, err := pb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if circ == nil {
		t.Fatal("Build returned nil circuit")
	}
	if closer == nil {
		t.Fatal("Build returned nil closer")
	}
	if fake.callCount != 1 {
		t.Fatalf("expected 1 call to BuildCircuit, got %d", fake.callCount)
	}
	if fake.lastTarget != nil {
		t.Fatal("expected nil target (random exit), got non-nil")
	}
}

func TestPoolBuilderPropagatesError(t *testing.T) {
	fake := &fakeCircuitBuilder{shouldFail: true, failMessage: "test error"}
	pb := &testablePoolBuilder{cb: fake}

	circ, closer, err := pb.Build()
	if err == nil {
		t.Fatal("expected error from Build")
	}
	if circ != nil {
		t.Fatal("expected nil circuit on error")
	}
	if closer != nil {
		t.Fatal("expected nil closer on error")
	}
	if err.Error() != "test error" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPoolBuilderImplementsCircuitBuilder(t *testing.T) {
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	// Verify it satisfies the interface at compile time.
	var _ circpool.CircuitBuilder = pb
}

func TestPoolBuilderReturnsCircuitAndCloser(t *testing.T) {
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	circ, closer, err := pb.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Circuit should have a valid Done channel.
	select {
	case <-circ.Done():
		t.Fatal("circuit should not be done yet")
	default:
	}

	// Closer should be closeable without error.
	if err := closer.Close(); err != nil {
		t.Fatalf("closer.Close: %v", err)
	}
}

func TestPoolBuilderMultipleBuilds(t *testing.T) {
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	for i := 0; i < 5; i++ {
		circ, closer, err := pb.Build()
		if err != nil {
			t.Fatalf("Build %d: %v", i, err)
		}
		if circ == nil || closer == nil {
			t.Fatalf("Build %d returned nil", i)
		}
	}
	if fake.callCount != 5 {
		t.Fatalf("expected 5 calls, got %d", fake.callCount)
	}
}

func TestPoolBuilderIntegrationWithPool(t *testing.T) {
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	pool := circpool.NewPool(pb, circpool.PoolConfig{Size: 2, GetTimeout: 5 * time.Second})
	defer pool.Close()

	// Wait for pool to fill.
	assigner := circpool.NewAssigner(pool)

	circ, err := assigner.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("AssignCircuit: %v", err)
	}
	if circ == nil {
		t.Fatal("AssignCircuit returned nil")
	}

	// Same origin should return same circuit.
	circ2, err := assigner.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("AssignCircuit same origin: %v", err)
	}
	if circ != circ2 {
		t.Fatal("same origin should return same circuit")
	}

	// Different origin should get a different circuit (pool has capacity).
	circ3, err := assigner.AssignCircuit("other.com")
	if err != nil {
		t.Fatalf("AssignCircuit different origin: %v", err)
	}
	if circ3 == circ {
		t.Fatal("different origin should get different circuit when pool has capacity")
	}
}

func TestPoolBuilderShutdown(t *testing.T) {
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	pool := circpool.NewPool(pb, circpool.PoolConfig{Size: 1, GetTimeout: 5 * time.Second})

	assigner := circpool.NewAssigner(pool)
	_, err := assigner.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("AssignCircuit: %v", err)
	}

	// Close pool (like shutdown handler does).
	pool.Close()

	// Further assigns should fail.
	_, err = assigner.AssignCircuit("new.com")
	if err == nil {
		t.Fatal("expected error after pool close")
	}
}

// trackingCloser records Close calls for verifying graceful shutdown.
type trackingCloser struct {
	closed atomic.Bool
}

func (tc *trackingCloser) Close() error {
	tc.closed.Store(true)
	return nil
}

// trackingCircuitBuilder builds circuits with tracking closers to verify
// that pool.Close() destroys all circuits and their link closers.
type trackingCircuitBuilder struct {
	nextID  atomic.Uint32
	mu      sync.Mutex
	closers []*trackingCloser
}

func (b *trackingCircuitBuilder) Build() (*circuit.Circuit, io.Closer, error) {
	id := b.nextID.Add(1) | 0x80000000 // MSB set per Tor spec
	circ := circuit.NewTestCircuit(id, &nopCellReader{})
	tc := &trackingCloser{}
	b.mu.Lock()
	b.closers = append(b.closers, tc)
	b.mu.Unlock()
	return circ, tc, nil
}

func (b *trackingCircuitBuilder) builtCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.closers)
}

// allClosed returns true if every link closer created by this builder has been closed.
func (b *trackingCircuitBuilder) allClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, tc := range b.closers {
		if !tc.closed.Load() {
			return false
		}
	}
	return true
}

// waitForPoolBuilt polls until the builder has created at least n circuits.
func waitForPoolBuilt(t *testing.T, b *trackingCircuitBuilder, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for %d circuits (got %d)", n, b.builtCount())
		default:
		}
		if b.builtCount() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMainCircuitPoolIntegration verifies the full wiring path:
// circuitBuilder -> poolBuilder -> Pool -> Assigner -> SOCKS GetCirc callback.
// This mirrors exactly how main() wires things together.
func TestMainCircuitPoolIntegration(t *testing.T) {
	// 1. Create the same wiring pattern as main():
	//    circuitBuilder -> poolBuilder -> Pool -> Assigner -> GetCirc
	// We use testablePoolBuilder (mirrors poolBuilder's logic) with fakeCircuitBuilder
	// to avoid needing a real Tor network.
	fake := &fakeCircuitBuilder{}
	pb := &testablePoolBuilder{cb: fake}

	// Verify poolBuilder satisfies CircuitBuilder (compile-time check on real type).
	var _ circpool.CircuitBuilder = &poolBuilder{}

	pool := circpool.NewPool(pb, circpool.PoolConfig{Size: 3, GetTimeout: 5 * time.Second})
	defer pool.Close()
	assigner := circpool.NewAssigner(pool)

	// 2. Wire the GetCirc function exactly as runSOCKSProxy does.
	getCirc := func(target string) (*circuit.Circuit, error) {
		return assigner.AssignCircuit(target)
	}

	// 3. Verify circuit assignment works through the full chain.
	circ1 := assertGetCirc(t, getCirc, "example.com")

	// 4. Same origin should reuse the same circuit (origin isolation).
	circ1b := assertGetCirc(t, getCirc, "example.com")
	if circ1b != circ1 {
		t.Fatal("same origin should return same circuit")
	}

	// 5. Different origins get different circuits when pool has capacity.
	circ2 := assertGetCirc(t, getCirc, "other.com")
	if circ2 == circ1 {
		t.Fatal("different origins should get different circuits")
	}

	circ3 := assertGetCirc(t, getCirc, "third.com")
	if circ3 == circ1 || circ3 == circ2 {
		t.Fatal("third origin should get a unique circuit")
	}

	// 6. Pool exhausted: fourth origin should fall back to sharing.
	circ4 := assertGetCirc(t, getCirc, "fourth.com")
	if circ4 == nil {
		t.Fatal("fallback should still return a circuit")
	}

	// 7. Verify the builder was called with nil target (random exit).
	if fake.callCount < 3 {
		t.Fatalf("expected at least 3 BuildCircuit calls, got %d", fake.callCount)
	}
	if fake.lastTarget != nil {
		t.Fatal("pool builder should always call BuildCircuit with nil target")
	}

	// 8. Concurrent access should be safe.
	runConcurrentGetCirc(t, getCirc, 20)
}

// assertGetCirc calls getCirc and fatals if it returns an error or nil circuit.
func assertGetCirc(t *testing.T, getCirc func(string) (*circuit.Circuit, error), target string) *circuit.Circuit {
	t.Helper()
	circ, err := getCirc(target)
	if err != nil {
		t.Fatalf("getCirc(%s): %v", target, err)
	}
	if circ == nil {
		t.Fatalf("getCirc(%s) returned nil circuit", target)
	}
	return circ
}

// runConcurrentGetCirc spawns n goroutines calling getCirc with rotating origins and checks for errors.
func runConcurrentGetCirc(t *testing.T, getCirc func(string) (*circuit.Circuit, error), n int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	origins := []string{"a.com", "b.com", "c.com"}
	for i := 0; i < n; i++ {
		wg.Add(1)
		origin := origins[i%len(origins)]
		go func(o string) {
			defer wg.Done()
			_, err := getCirc(o)
			if err != nil {
				errs <- err
			}
		}(origin)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent getCirc error: %v", err)
	}
}

// TestGracefulShutdownDestroysPool verifies that pool.Close() destroys all
// pooled circuits (both ready and in-use) and closes their link closers,
// exactly as the signal handler in runSOCKSProxy does.
func TestGracefulShutdownDestroysPool(t *testing.T) {
	builder := &trackingCircuitBuilder{}
	pool := circpool.NewPool(builder, circpool.PoolConfig{Size: 3, GetTimeout: 5 * time.Second})
	assigner := circpool.NewAssigner(pool)

	// Wait for pool to fill.
	waitForPoolBuilt(t, builder, 3)

	// Check out one circuit (simulates an active SOCKS connection).
	inUseCirc, err := assigner.AssignCircuit("active.com")
	if err != nil {
		t.Fatalf("AssignCircuit: %v", err)
	}

	// Verify the circuit is alive before shutdown.
	select {
	case <-inUseCirc.Done():
		t.Fatal("circuit should be alive before shutdown")
	default:
	}

	// Simulate graceful shutdown (same as the signal handler).
	pool.Close()

	// 1. All link closers should have been called.
	if !builder.allClosed() {
		t.Error("not all link closers were closed during shutdown")
	}

	// 2. The in-use circuit should be destroyed (Done channel closed).
	select {
	case <-inUseCirc.Done():
		// Good: circuit was destroyed.
	case <-time.After(time.Second):
		t.Fatal("in-use circuit was not destroyed during shutdown")
	}

	// 3. Pool.Get should fail after Close.
	_, err = pool.Get()
	if err == nil {
		t.Fatal("expected error from pool.Get after Close")
	}

	// 4. Assigner should fail after pool is closed.
	_, err = assigner.AssignCircuit("new.com")
	if err == nil {
		t.Fatal("expected error from AssignCircuit after pool close")
	}

	// 5. Double close should not panic.
	pool.Close()
}
