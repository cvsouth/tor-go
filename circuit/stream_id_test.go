package circuit

import (
	"sync"
	"testing"
)

func TestNextStreamIDNonZero(t *testing.T) {
	ResetNextStreamID(1)
	for i := 0; i < 200; i++ {
		id := NextStreamID()
		if id == 0 {
			t.Fatalf("NextStreamID returned 0 on iteration %d", i)
		}
	}
}

func TestNextStreamIDUnique(t *testing.T) {
	ResetNextStreamID(1)
	ids := make(map[uint16]bool)
	for i := 0; i < 1000; i++ {
		id := NextStreamID()
		if ids[id] {
			t.Fatalf("duplicate stream ID %d on iteration %d", id, i)
		}
		ids[id] = true
	}
}

func TestNextStreamIDSkipsZeroOnWrap(t *testing.T) {
	// Set counter so the next allocation wraps uint16 to 0.
	ResetNextStreamID(0xFFFF)
	id1 := NextStreamID()
	if id1 != 0xFFFF {
		t.Fatalf("expected 0xFFFF, got %d", id1)
	}
	// Next one wraps uint16 to 0, should be skipped.
	id2 := NextStreamID()
	if id2 == 0 {
		t.Fatal("NextStreamID returned 0 after wrap")
	}
}

func TestNextStreamIDConcurrent(t *testing.T) {
	ResetNextStreamID(1)
	const goroutines = 100
	const idsPerGoroutine = 100

	var mu sync.Mutex
	allIDs := make(map[uint16]bool)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			localIDs := make([]uint16, idsPerGoroutine)
			for i := 0; i < idsPerGoroutine; i++ {
				localIDs[i] = NextStreamID()
			}
			mu.Lock()
			for _, id := range localIDs {
				if id == 0 {
					t.Errorf("got stream ID 0")
				}
				allIDs[id] = true
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	// With 10000 allocations starting from 1, all IDs should be unique
	// (assuming no uint16 wrap collisions within 10000 allocations).
	if len(allIDs) != goroutines*idsPerGoroutine {
		t.Fatalf("expected %d unique IDs, got %d", goroutines*idsPerGoroutine, len(allIDs))
	}
}
