package pathselect

import (
	"testing"

	"github.com/cvsouth/tor-go/directory"
)

func testConsensus() *directory.Consensus {
	c := &directory.Consensus{
		BandwidthWeights: map[string]int64{
			"Wgg": 5869, "Wgd": 5869, "Wgm": 5869,
			"Wmg": 4131, "Wmm": 10000, "Wme": 10000, "Wmd": 4131,
			"Wee": 10000, "Web": 10000, "Wed": 10000, "Wem": 10000,
		},
	}

	// Guard+Exit relay
	r1 := directory.Relay{
		Nickname:   "GuardExit1",
		Address:    "1.2.3.4",
		ORPort:     9001,
		Bandwidth:  5000,
		HasNtorKey: true,
	}
	r1.Identity = [20]byte{1}
	r1.Flags.Guard = true
	r1.Flags.Exit = true
	r1.Flags.Fast = true
	r1.Flags.Running = true
	r1.Flags.Valid = true

	// Guard-only relay
	r2 := directory.Relay{
		Nickname:   "Guard2",
		Address:    "5.6.7.8",
		ORPort:     443,
		Bandwidth:  3000,
		HasNtorKey: true,
	}
	r2.Identity = [20]byte{2}
	r2.Flags.Guard = true
	r2.Flags.Fast = true
	r2.Flags.Running = true
	r2.Flags.Valid = true

	// Middle relay
	r3 := directory.Relay{
		Nickname:   "Middle3",
		Address:    "10.20.30.40",
		ORPort:     9001,
		Bandwidth:  2000,
		HasNtorKey: true,
	}
	r3.Identity = [20]byte{3}
	r3.Flags.Fast = true
	r3.Flags.Running = true
	r3.Flags.Valid = true

	// Exit-only relay
	r4 := directory.Relay{
		Nickname:   "Exit4",
		Address:    "20.30.40.50",
		ORPort:     443,
		Bandwidth:  4000,
		HasNtorKey: true,
	}
	r4.Identity = [20]byte{4}
	r4.Flags.Exit = true
	r4.Flags.Fast = true
	r4.Flags.Running = true
	r4.Flags.Valid = true

	// BadExit relay (should never be selected as exit)
	r5 := directory.Relay{
		Nickname:   "BadExit5",
		Address:    "30.40.50.60",
		ORPort:     9001,
		Bandwidth:  10000,
		HasNtorKey: true,
	}
	r5.Identity = [20]byte{5}
	r5.Flags.Exit = true
	r5.Flags.BadExit = true
	r5.Flags.Fast = true
	r5.Flags.Running = true
	r5.Flags.Valid = true

	c.Relays = []directory.Relay{r1, r2, r3, r4, r5}
	return c
}

func TestSelectExit(t *testing.T) {
	c := testConsensus()

	// Run many selections — should never pick BadExit
	for i := 0; i < 100; i++ {
		exit, err := SelectExit(c)
		if err != nil {
			t.Fatalf("SelectExit: %v", err)
		}
		if exit.Flags.BadExit {
			t.Fatal("selected BadExit relay")
		}
		if !exit.Flags.Exit {
			t.Fatal("selected non-Exit relay")
		}
	}
}

func TestSelectGuard(t *testing.T) {
	c := testConsensus()
	exit := &c.Relays[3] // Exit4

	for i := 0; i < 100; i++ {
		guard, err := SelectGuard(c, exit)
		if err != nil {
			t.Fatalf("SelectGuard: %v", err)
		}
		if !guard.Flags.Guard {
			t.Fatal("selected non-Guard relay")
		}
		if guard.Identity == exit.Identity {
			t.Fatal("guard is same as exit")
		}
	}
}

func TestSelectMiddle(t *testing.T) {
	c := testConsensus()
	guard := &c.Relays[1] // Guard2
	exit := &c.Relays[3]  // Exit4

	for i := 0; i < 100; i++ {
		middle, err := SelectMiddle(c, guard, exit)
		if err != nil {
			t.Fatalf("SelectMiddle: %v", err)
		}
		if middle.Identity == guard.Identity {
			t.Fatal("middle is same as guard")
		}
		if middle.Identity == exit.Identity {
			t.Fatal("middle is same as exit")
		}
	}
}

func TestSelectPath(t *testing.T) {
	c := testConsensus()

	for i := 0; i < 50; i++ {
		path, err := SelectPath(c)
		if err != nil {
			t.Fatalf("SelectPath: %v", err)
		}
		if path.Guard.Identity == path.Middle.Identity {
			t.Fatal("guard == middle")
		}
		if path.Guard.Identity == path.Exit.Identity {
			t.Fatal("guard == exit")
		}
		if path.Middle.Identity == path.Exit.Identity {
			t.Fatal("middle == exit")
		}
		if !path.Exit.Flags.Exit {
			t.Fatal("exit not Exit")
		}
		if !path.Guard.Flags.Guard {
			t.Fatal("guard not Guard")
		}
	}
}

func TestSubnet16(t *testing.T) {
	if subnet16("1.2.3.4") != "1.2" {
		t.Fatalf("subnet16(1.2.3.4) = %q", subnet16("1.2.3.4"))
	}
	if subnet16("1.2.99.100") != "1.2" {
		t.Fatal("same /16 not detected")
	}
}

func TestWeightedRandom(t *testing.T) {
	// With very skewed weights, the heavy one should be selected most of the time
	weights := []int64{1, 1000000}
	counts := [2]int{}
	for i := 0; i < 1000; i++ {
		idx, err := weightedRandom(weights)
		if err != nil {
			t.Fatal(err)
		}
		counts[idx]++
	}
	// Heavy weight should be selected >95% of the time
	if counts[1] < 950 {
		t.Fatalf("heavy weight selected %d/1000 times, expected >950", counts[1])
	}
}
