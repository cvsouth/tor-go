package directory

import (
	"bufio"
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

func TestFetchViaBeginDirCRLFBeforeNilCircuit(t *testing.T) {
	// CRLF validation must happen before the nil circuit check.
	_, err := FetchViaBeginDir(nil, "/test\r\n", 1024)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CRLF") {
		t.Fatalf("expected CRLF error before nil circuit error, got: %v", err)
	}
}

func TestFetchViaBeginDirArbitraryPaths(t *testing.T) {
	// Verify various valid URL paths are accepted (they fail at nil circuit,
	// not at validation).
	paths := []string{
		"/tor/hs/3/base64key",
		"/tor/micro/d/digest1-digest2",
		"/tor/status-vote/current/consensus-microdesc",
		"/tor/server/authority",
		"/custom/path",
		"/",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			_, err := FetchViaBeginDir(nil, p, 1024)
			if err == nil {
				t.Fatal("expected error for nil circuit")
			}
			if strings.Contains(err.Error(), "CRLF") {
				t.Fatalf("valid path %q should not trigger CRLF error", p)
			}
			if !strings.Contains(err.Error(), "circuit is nil") {
				t.Fatalf("expected nil circuit error, got: %v", err)
			}
		})
	}
}

func TestFetchViaBeginDirConfigurableSizeNilCircuit(t *testing.T) {
	// Verify different maxResponseBytes values are accepted with a nil circuit.
	// The function should fail at the nil circuit check, not at size validation.
	sizes := []int{1, 100, 1024, 10 * 1024 * 1024}
	for _, sz := range sizes {
		_, err := FetchViaBeginDir(nil, "/test", sz)
		if err == nil {
			t.Fatalf("expected error for nil circuit with maxResponseBytes=%d", sz)
		}
		if !strings.Contains(err.Error(), "circuit is nil") {
			t.Fatalf("expected nil circuit error, got: %v", err)
		}
	}
}

func TestFetchViaBeginDirInvalidMaxResponseBytes(t *testing.T) {
	// maxResponseBytes <= 0 should be rejected before attempting to open a stream.
	// We pass a nil circuit — if the error mentions "circuit is nil" instead of
	// "maxResponseBytes must be positive", the early validation is missing.
	tests := []struct {
		name string
		max  int
	}{
		{"zero", 0},
		{"negative", -1},
		{"very negative", -1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FetchViaBeginDir(nil, "/test", tt.max)
			if err == nil {
				t.Fatal("expected error for invalid maxResponseBytes")
			}
			if !strings.Contains(err.Error(), "maxResponseBytes must be positive") {
				t.Fatalf("expected maxResponseBytes validation error, got: %v", err)
			}
		})
	}
}

// --- HTTP response parsing unit tests ---
// These test readHTTPResponse directly with synthetic HTTP responses,
// exercising the stdlib http.ReadResponse parsing, status code validation,
// chunked transfer decoding, and body size limiting without needing a circuit.

func httpReader(raw string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(raw))
}

func TestReadHTTPResponse200(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	body, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}
}

func TestReadHTTPResponse204NoContent(t *testing.T) {
	raw := "HTTP/1.0 204 No Content\r\nContent-Length: 0\r\n\r\n"
	body, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("expected empty body, got %q", body)
	}
}

func TestReadHTTPResponseStatusCodes(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		wantErr   bool
		errSubstr string
	}{
		{"200 OK", "200 OK", false, ""},
		{"201 Created", "201 Created", false, ""},
		{"204 No Content", "204 No Content", false, ""},
		{"299 edge", "299 Custom", false, ""},
		{"301 Redirect", "301 Moved Permanently", true, "HTTP 301"},
		{"400 Bad Request", "400 Bad Request", true, "HTTP 400"},
		{"404 Not Found", "404 Not Found", true, "HTTP 404"},
		{"500 Server Error", "500 Internal Server Error", true, "HTTP 500"},
		{"199 below range", "199 Custom", true, "HTTP 199"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "HTTP/1.0 " + tt.status + "\r\nContent-Length: 0\r\n\r\n"
			_, err := readHTTPResponse(httpReader(raw), "/test", 1024)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q should contain %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestReadHTTPResponseChunkedEncoding(t *testing.T) {
	// Verify stdlib handles chunked transfer encoding transparently.
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	body, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "hello world" {
		t.Fatalf("body = %q, want %q", body, "hello world")
	}
}

func TestReadHTTPResponseBodySizeLimit(t *testing.T) {
	// Body exactly at the limit should be accepted (inclusive maximum).
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"
	body, err := readHTTPResponse(httpReader(raw), "/test", 10)
	if err != nil {
		t.Fatalf("unexpected error for body exactly at limit: %v", err)
	}
	if string(body) != "0123456789" {
		t.Fatalf("body = %q, want %q", body, "0123456789")
	}

	// Body one byte over the limit should be rejected.
	raw = "HTTP/1.0 200 OK\r\nContent-Length: 11\r\n\r\n01234567890"
	_, err = readHTTPResponse(httpReader(raw), "/test", 10)
	if err == nil {
		t.Fatal("expected error when body exceeds limit by one byte")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected exceeded error, got: %v", err)
	}
}

func TestReadHTTPResponseBodyUnderLimit(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\n012345678"
	body, err := readHTTPResponse(httpReader(raw), "/test", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "012345678" {
		t.Fatalf("body = %q, want %q", body, "012345678")
	}
}

func TestReadHTTPResponsePreservesTrailingData(t *testing.T) {
	// Trailing whitespace, newlines, and null bytes must NOT be trimmed.
	content := "data\n\r\n \x00"
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\n" + content
	body, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != content {
		t.Fatalf("body corrupted: got %q, want %q", body, content)
	}
}

func TestReadHTTPResponseMalformedResponse(t *testing.T) {
	raw := "NOT HTTP AT ALL\r\n\r\n"
	_, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err == nil {
		t.Fatal("expected error for malformed HTTP response")
	}
}

func TestReadHTTPResponseErrorIncludesPath(t *testing.T) {
	raw := "HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
	_, err := readHTTPResponse(httpReader(raw), "/tor/hs/3/key", 1024)
	if err == nil {
		t.Fatal("expected error for 503")
	}
	if !strings.Contains(err.Error(), "/tor/hs/3/key") {
		t.Fatalf("error should contain URL path, got: %v", err)
	}
}

func TestReadHTTPResponseEmptyBody200(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"
	body, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("expected empty body, got %d bytes", len(body))
	}
}

func TestReadHTTPResponseHTTP11(t *testing.T) {
	// HTTP/1.1 responses should also be handled correctly.
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nfoo"
	body, err := readHTTPResponse(httpReader(raw), "/test", 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "foo" {
		t.Fatalf("body = %q, want %q", body, "foo")
	}
}

func TestReadHTTPResponseBodyExceedsLimit(t *testing.T) {
	// A 100-byte body with a 10-byte limit must be rejected.
	// LimitReader prevents reading more than 10 bytes into memory,
	// and the size check returns an error.
	body100 := strings.Repeat("A", 100)
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\n" + body100
	_, err := readHTTPResponse(httpReader(raw), "/test", 10)
	if err == nil {
		t.Fatal("expected error when body exceeds limit")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected exceeded error, got: %v", err)
	}
}

func TestFetchViaBeginDirCRLFBeforeMaxResponseBytes(t *testing.T) {
	// CRLF validation must come before maxResponseBytes validation.
	// Pass maxResponseBytes=0 (invalid) with a CRLF path — the CRLF error
	// must be returned, not "maxResponseBytes must be positive".
	_, err := FetchViaBeginDir(nil, "/test\r\n", 0)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "CRLF") {
		t.Fatalf("expected CRLF error before maxResponseBytes error, got: %v", err)
	}
}

func TestReadHTTPResponseZeroMaxBytes(t *testing.T) {
	raw := "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	_, err := readHTTPResponse(httpReader(raw), "/test", 0)
	if err == nil {
		t.Fatal("expected error for zero maxResponseBytes")
	}
	if !strings.Contains(err.Error(), "maxResponseBytes must be positive") {
		t.Fatalf("expected clear validation error, got: %v", err)
	}

	// Negative value should also be rejected.
	_, err = readHTTPResponse(httpReader(raw), "/test", -1)
	if err == nil {
		t.Fatal("expected error for negative maxResponseBytes")
	}
	if !strings.Contains(err.Error(), "maxResponseBytes must be positive") {
		t.Fatalf("expected clear validation error, got: %v", err)
	}
}
