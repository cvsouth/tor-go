package circpool

import (
	"sync"
	"testing"
	"time"
)

func TestSameOriginGetsSameCircuit(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 3, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 3)

	a := NewAssigner(p)

	c1, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("first assign: %v", err)
	}
	c2, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("second assign: %v", err)
	}
	if c1 != c2 {
		t.Fatal("same origin should return the same circuit")
	}
}

func TestDifferentOriginsGetDifferentCircuits(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 3, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 3)

	a := NewAssigner(p)

	c1, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("assign example.com: %v", err)
	}
	c2, err := a.AssignCircuit("other.com")
	if err != nil {
		t.Fatalf("assign other.com: %v", err)
	}
	if c1 == c2 {
		t.Fatal("different origins should get different circuits when pool has capacity")
	}
}

func TestFallbackWhenPoolExhausted(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 2, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 2)

	a := NewAssigner(p)

	// Assign all pool circuits to different origins.
	_, err := a.AssignCircuit("a.com")
	if err != nil {
		t.Fatalf("assign a.com: %v", err)
	}
	_, err = a.AssignCircuit("b.com")
	if err != nil {
		t.Fatalf("assign b.com: %v", err)
	}

	// Pool is exhausted; third origin should fall back to reusing a circuit.
	c3, err := a.AssignCircuit("c.com")
	if err != nil {
		t.Fatalf("assign c.com: %v", err)
	}
	if c3 == nil {
		t.Fatal("expected fallback circuit, got nil")
	}
}

func TestAssignerCleansUpExpiredMappings(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 3, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 3)

	a := NewAssigner(p)

	c1, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	// Kill the circuit.
	_ = c1.Destroy()

	// Wait for Done channel to close.
	select {
	case <-c1.Done():
	case <-time.After(time.Second):
		t.Fatal("circuit Done not closed after Destroy")
	}

	// Next assign for same origin should get a new circuit.
	c2, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("re-assign after destroy: %v", err)
	}
	if c2 == c1 {
		t.Fatal("should have gotten a new circuit after old one died")
	}
}

func TestAssignerConcurrentSafe(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 5, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 5)

	a := NewAssigner(p)

	origins := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}
	var wg sync.WaitGroup
	errs := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		origin := origins[i%len(origins)]
		go func(o string) {
			defer wg.Done()
			_, err := a.AssignCircuit(o)
			if err != nil {
				errs <- err
			}
		}(origin)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent assign error: %v", err)
	}
}

func TestAssignerOnionIsolation(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 5, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 5)

	a := NewAssigner(p)

	// Get a clearnet circuit.
	clearCirc, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("assign clearnet: %v", err)
	}

	// Get an onion circuit.
	onionCirc, err := a.AssignCircuit("abc123.onion")
	if err != nil {
		t.Fatalf("assign onion: %v", err)
	}

	// Onion circuit must be different from clearnet.
	if onionCirc == clearCirc {
		t.Fatal("onion circuit must not be shared with clearnet")
	}

	// Two different onion addresses must get different circuits.
	onionCirc2, err := a.AssignCircuit("def456.onion")
	if err != nil {
		t.Fatalf("assign second onion: %v", err)
	}
	if onionCirc2 == onionCirc {
		t.Fatal("different onion addresses must get different circuits")
	}

	// Same onion address should reuse the same circuit.
	onionCirc3, err := a.AssignCircuit("abc123.onion")
	if err != nil {
		t.Fatalf("re-assign same onion: %v", err)
	}
	if onionCirc3 != onionCirc {
		t.Fatal("same onion address should reuse its circuit")
	}
}

func TestAssignerRelease(t *testing.T) {
	builder := &mockBuilder{}
	p := NewPool(builder, PoolConfig{Size: 3, GetTimeout: 5 * time.Second})
	defer p.Close()
	waitForBuilt(t, builder, 3)

	a := NewAssigner(p)

	c1, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("assign: %v", err)
	}

	a.Release("example.com")

	// After release, same origin may get a different circuit.
	c2, err := a.AssignCircuit("example.com")
	if err != nil {
		t.Fatalf("re-assign after release: %v", err)
	}
	// The circuit was returned to pool, so it might be the same or different.
	// The key thing is that the mapping was removed.
	_ = c1
	_ = c2
}
