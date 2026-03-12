package onion

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/cvsouth/tor-go/descriptor"
	"github.com/cvsouth/tor-go/directory"
)

func TestTimePeriodFromConsensusDeterministic(t *testing.T) {
	c := &directory.Consensus{}
	// ValidAfter is zero time, should still return a value without panic.
	tp := TimePeriodFromConsensus(c)
	// The result depends on the zero time but should be deterministic.
	tp2 := TimePeriodFromConsensus(c)
	if tp != tp2 {
		t.Fatalf("TimePeriodFromConsensus not deterministic: %d vs %d", tp, tp2)
	}
}

// errCircuitBuilder is a CircuitBuilder that always returns an error.
type errCircuitBuilder struct {
	err error
}

func (e *errCircuitBuilder) BuildCircuit(_ *descriptor.RelayInfo) (*BuiltCircuit, error) {
	return nil, e.err
}

func TestFetchFromHSDirNilBuilder(t *testing.T) {
	relay := &directory.Relay{Address: "127.0.0.1", ORPort: 9001}
	var blindedKey [32]byte
	_, err := fetchFromHSDir(relay, blindedKey, nil)
	if err == nil {
		t.Fatal("expected error with nil builder")
	}
}

func TestFetchFromHSDirBuildError(t *testing.T) {
	relay := &directory.Relay{Address: "127.0.0.1", ORPort: 9001}
	var blindedKey [32]byte
	cb := &errCircuitBuilder{err: fmt.Errorf("build failed")}
	_, err := fetchFromHSDir(relay, blindedKey, cb)
	if err == nil {
		t.Fatal("expected error when build fails")
	}
}

func TestFetchDescriptorFromHSDirsAllFail(t *testing.T) {
	relays := []*directory.Relay{
		{Address: "1.2.3.4", ORPort: 9001},
		{Address: "5.6.7.8", ORPort: 9002},
	}
	var blindedKey [32]byte
	cb := &errCircuitBuilder{err: fmt.Errorf("cannot connect")}
	_, err := fetchDescriptorFromHSDirs(relays, blindedKey, cb)
	if err == nil {
		t.Fatal("expected error when all HSDirs fail")
	}
}

func TestFetchDescriptorFromHSDirsNilBuilder(t *testing.T) {
	relays := []*directory.Relay{
		{Address: "1.2.3.4", ORPort: 9001},
	}
	var blindedKey [32]byte
	_, err := fetchDescriptorFromHSDirs(relays, blindedKey, nil)
	if err == nil {
		t.Fatal("expected error with nil builder")
	}
}

func TestFetchDescriptorFromHSDirsEmptyList(t *testing.T) {
	var relays []*directory.Relay
	var blindedKey [32]byte
	cb := &errCircuitBuilder{err: fmt.Errorf("should not be called")}
	_, err := fetchDescriptorFromHSDirs(relays, blindedKey, cb)
	if err == nil {
		t.Fatal("expected error with empty relay list")
	}
}

func TestResolveOnionServiceBadAddress(t *testing.T) {
	consensus := &directory.Consensus{}
	cb := &errCircuitBuilder{err: fmt.Errorf("unused")}
	_, err := ResolveOnionService("not-a-valid-onion", consensus, cb)
	if err == nil {
		t.Fatal("expected error for invalid onion address")
	}
}

func TestConnectOnionServiceBadAddress(t *testing.T) {
	consensus := &directory.Consensus{}
	cb := &errCircuitBuilder{err: fmt.Errorf("unused")}
	_, err := ConnectOnionService("not-a-valid-onion", 80, consensus, cb, nil)
	if err == nil {
		t.Fatal("expected error for invalid onion address")
	}
}

// TestFetchFromHSDirAlwaysUsesCircuitBuilder verifies that fetchFromHSDir
// always goes through the CircuitBuilder path (no DirPort/HTTP fallback).
func TestFetchFromHSDirAlwaysUsesCircuitBuilder(t *testing.T) {
	// Even a relay with a DirPort set should still require a CircuitBuilder.
	relay := &directory.Relay{
		Address: "192.0.2.1",
		ORPort:  9001,
		DirPort: 9030, // DirPort present but should be ignored
	}
	var blindedKey [32]byte

	// With nil builder, must error (no HTTP fallback to DirPort).
	_, err := fetchFromHSDir(relay, blindedKey, nil)
	if err == nil {
		t.Fatal("expected error with nil builder even when DirPort is set")
	}
	if got := err.Error(); got != fmt.Sprintf("no circuit builder available to fetch from HSDir %s", relay.Address) {
		t.Fatalf("unexpected error message: %s", got)
	}
}

// TestFetchFromHSDirErrorMessageContainsAddress verifies the error includes
// the HSDir address for debugging.
func TestFetchFromHSDirErrorMessageContainsAddress(t *testing.T) {
	relay := &directory.Relay{Address: "198.51.100.42", ORPort: 443}
	var blindedKey [32]byte
	_, err := fetchFromHSDir(relay, blindedKey, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !strings.Contains(got, "198.51.100.42") {
		t.Fatalf("error should contain HSDir address, got: %s", got)
	}
}

// TestFetchDescriptorFromHSDirsTriesAllRelays verifies that all HSDirs
// are tried when earlier ones fail.
func TestFetchDescriptorFromHSDirsTriesAllRelays(t *testing.T) {
	relays := []*directory.Relay{
		{Address: "10.0.0.1", ORPort: 9001},
		{Address: "10.0.0.2", ORPort: 9002},
		{Address: "10.0.0.3", ORPort: 9003},
	}
	var blindedKey [32]byte
	callCount := 0
	cb := &countingCircuitBuilder{
		err:       fmt.Errorf("always fail"),
		callCount: &callCount,
	}
	_, err := fetchDescriptorFromHSDirs(relays, blindedKey, cb)
	if err == nil {
		t.Fatal("expected error")
	}
	if callCount != 3 {
		t.Fatalf("expected 3 attempts (one per HSDir), got %d", callCount)
	}
}

// TestResolveOnionServiceNoHTTPClientParam verifies that ResolveOnionService
// does not accept an httpClient parameter — the variadic builder param is
// the only optional argument.
func TestResolveOnionServiceNoHTTPClientParam(t *testing.T) {
	// This is a compile-time verification: ResolveOnionService accepts
	// (string, *directory.Consensus, ...CircuitBuilder) and nothing else.
	// If someone adds an httpClient parameter, this test will fail to compile.
	var fn func(string, *directory.Consensus, ...CircuitBuilder) (*ConnectResult, error) = ResolveOnionService //nolint:staticcheck // explicit type is intentional — compile-time signature check
	_ = fn
}

// TestConnectOnionServiceNoHTTPClientParam verifies that ConnectOnionService
// does not accept an httpClient parameter — it takes *slog.Logger as the last
// parameter, not an HTTP client.
func TestConnectOnionServiceNoHTTPClientParam(t *testing.T) {
	// Compile-time check: ConnectOnionService has the signature
	// (string, uint16, *directory.Consensus, CircuitBuilder, *slog.Logger) (io.ReadWriteCloser, error).
	// If someone adds an httpClient parameter, this assignment will fail to compile.
	var fn func(string, uint16, *directory.Consensus, CircuitBuilder, *slog.Logger) (io.ReadWriteCloser, error) = ConnectOnionService //nolint:staticcheck // explicit type is intentional — compile-time signature check
	_ = fn
}

// TestIsOnionAddressVariants tests IsOnionAddress with various inputs.
func TestIsOnionAddressVariants(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"facebookcorewwwi.onion", true},
		{"facebookcorewwwi.onion:80", true},
		{"FACEBOOKCOREWWWI.ONION", true},
		{"example.com", false},
		{"example.com:443", false},
		{"", false},
		{".onion", true},
		{"test.onion:8080", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsOnionAddress(tt.input)
			if got != tt.want {
				t.Fatalf("IsOnionAddress(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestCurrentTimePeriodPositive verifies CurrentTimePeriod returns a positive value.
func TestCurrentTimePeriodPositive(t *testing.T) {
	tp := CurrentTimePeriod()
	if tp <= 0 {
		t.Fatalf("CurrentTimePeriod() = %d, expected positive", tp)
	}
}

// countingCircuitBuilder tracks how many times BuildCircuit is called.
type countingCircuitBuilder struct {
	err       error
	callCount *int
}

func (c *countingCircuitBuilder) BuildCircuit(_ *descriptor.RelayInfo) (*BuiltCircuit, error) {
	*c.callCount++
	return nil, c.err
}
