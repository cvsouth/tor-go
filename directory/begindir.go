package directory

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/stream"
)

// FetchViaBeginDir fetches a resource from a Tor relay's directory port using
// a BEGIN_DIR stream over the given circuit. The circuit's last hop must support
// directory requests (e.g., an HSDir relay or a directory authority).
//
// urlPath is the HTTP path to request (e.g., "/tor/status-vote/current/consensus-microdesc").
// maxResponseBytes limits the response body size.
func FetchViaBeginDir(circ *circuit.Circuit, urlPath string, maxResponseBytes int) ([]byte, error) {
	if strings.ContainsAny(urlPath, "\r\n") {
		return nil, fmt.Errorf("invalid URL path: contains CRLF")
	}
	if maxResponseBytes <= 0 {
		return nil, fmt.Errorf("maxResponseBytes must be positive")
	}
	if circ == nil {
		return nil, fmt.Errorf("circuit is nil")
	}
	s, err := stream.BeginDir(circ)
	if err != nil {
		return nil, fmt.Errorf("begin dir: %w", err)
	}
	defer func() { _ = s.Close() }()

	// urlPath is used verbatim — callers are trusted to provide valid URL paths (no encoding is applied).
	httpReq := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: tor\r\nAccept-Encoding: identity\r\n\r\n", urlPath)
	if _, err := s.Write([]byte(httpReq)); err != nil {
		return nil, fmt.Errorf("write HTTP request: %w", err)
	}

	return readHTTPResponse(bufio.NewReader(s), urlPath, maxResponseBytes)
}

// readHTTPResponse reads and validates an HTTP response from r.
// It uses the stdlib http.ReadResponse for proper HTTP parsing (status codes,
// chunked transfer encoding, etc.) and limits the body to maxResponseBytes.
func readHTTPResponse(r *bufio.Reader, urlPath string, maxResponseBytes int) ([]byte, error) {
	// Defense-in-depth: validate maxResponseBytes here even though FetchViaBeginDir
	// also checks, because readHTTPResponse may be called by other internal callers
	// that bypass FetchViaBeginDir.
	if maxResponseBytes <= 0 {
		return nil, fmt.Errorf("maxResponseBytes must be positive")
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, urlPath)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponseBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeded %d byte limit for %s", maxResponseBytes, urlPath)
	}
	return body, nil
}
