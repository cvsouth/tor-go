package directory

import (
	"strings"
	"testing"
)

func TestFetchViaBeginDirNilCircuit(t *testing.T) {
	_, err := FetchViaBeginDir(nil, "/test", 1024)
	if err == nil {
		t.Fatal("expected error for nil circuit")
	}
}

func TestFetchViaBeginDirEmptyPath(t *testing.T) {
	// Even with an empty path, a nil circuit should still fail at BeginDir.
	_, err := FetchViaBeginDir(nil, "", 1024)
	if err == nil {
		t.Fatal("expected error for nil circuit with empty path")
	}
}

func TestFetchViaBeginDirCRLFInjection(t *testing.T) {
	tests := []struct {
		name    string
		urlPath string
	}{
		{"carriage return", "/test\r"},
		{"newline", "/test\n"},
		{"CRLF in middle", "/test\r\nHost: evil\r\n\r\n"},
		{"newline only", "/test\nInjected-Header: value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FetchViaBeginDir(nil, tt.urlPath, 1024)
			if err == nil {
				t.Fatal("expected error for CRLF in URL path")
			}
			if !strings.Contains(err.Error(), "CRLF") {
				t.Fatalf("expected CRLF error, got: %v", err)
			}
		})
	}
}

func TestFetchViaBeginDirCleanPath(t *testing.T) {
	// A clean path should not trigger the CRLF check; it should fail
	// at the nil circuit check instead.
	_, err := FetchViaBeginDir(nil, "/tor/status-vote/current/consensus-microdesc", 1024)
	if err == nil {
		t.Fatal("expected error for nil circuit")
	}
	if strings.Contains(err.Error(), "CRLF") {
		t.Fatal("clean path should not trigger CRLF error")
	}
}
