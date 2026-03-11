package directory

import (
	"strings"
	"testing"
)

func TestFetchConsensusNilCircuit(t *testing.T) {
	_, err := FetchConsensus(nil)
	if err == nil {
		t.Fatal("expected error for nil circuit")
	}
	if !strings.Contains(err.Error(), "fetch consensus") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}
