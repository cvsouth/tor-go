package onion

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cvsouth/tor-go/circuit"
)

// FetchDescriptor fetches a v3 hidden service descriptor from the given HSDir
// relay. The request is made to the relay's DirPort using the blinded public
// key to construct the URL: /tor/hs/3/<base64_blinded_key>
//
// Per rend-spec-v3, this request should be made anonymously over a Tor circuit.
// The client parameter allows routing through Tor.
func FetchDescriptor(client *http.Client, hsdirAddr string, blindedKey [32]byte) (string, error) {
	// Base64 encode the blinded key (raw standard encoding, no padding per spec).
	keyB64 := base64.RawStdEncoding.EncodeToString(blindedKey[:])

	url := fmt.Sprintf("http://%s/tor/hs/3/%s", hsdirAddr, keyB64)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	// Per rend-spec-v3: clients SHOULD NOT advertise compression methods.
	// Don't set Accept-Encoding to avoid fingerprinting.

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch descriptor from %s: %w", hsdirAddr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch descriptor from %s: HTTP %d", hsdirAddr, resp.StatusCode)
	}

	// Descriptors are typically small (< 50KB), cap at 256KB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", fmt.Errorf("read descriptor from %s: %w", hsdirAddr, err)
	}

	return string(body), nil
}

// FetchDescriptorViaCircuit fetches a v3 hidden service descriptor using
// BEGIN_DIR over an existing circuit (for HSDirs without a public DirPort).
// The circuit's last hop must be the HSDir relay.
func FetchDescriptorViaCircuit(circ *circuit.Circuit, blindedKey [32]byte) (string, error) {
	keyB64 := base64.RawStdEncoding.EncodeToString(blindedKey[:])

	// Send RELAY_BEGIN_DIR (opens a directory stream on the circuit's last hop).
	// Stream ID allocation via stream.Begin is for RELAY_BEGIN — for BEGIN_DIR
	// we manually allocate a stream ID and send the cell.
	streamID := uint16(1) // Simple allocation for single-use circuit

	if err := circ.SendRelay(circuit.RelayBeginDir, streamID, nil); err != nil {
		return "", fmt.Errorf("send BEGIN_DIR: %w", err)
	}

	// Wait for RELAY_CONNECTED.
	for {
		_, cmd, sid, _, err := circ.ReceiveRelay()
		if err != nil {
			return "", fmt.Errorf("wait for CONNECTED: %w", err)
		}
		if sid != streamID {
			continue
		}
		if cmd == circuit.RelayConnected {
			break
		}
		if cmd == circuit.RelayEnd {
			return "", fmt.Errorf("BEGIN_DIR rejected")
		}
	}

	// Send the HTTP request over the directory stream.
	// Use HTTP/1.0 to avoid chunked encoding, and disable compression.
	httpReq := fmt.Sprintf("GET /tor/hs/3/%s HTTP/1.0\r\nHost: tor\r\nAccept-Encoding: identity\r\n\r\n", keyB64)
	if err := circ.SendRelay(circuit.RelayData, streamID, []byte(httpReq)); err != nil {
		return "", fmt.Errorf("send HTTP request: %w", err)
	}

	// Read the HTTP response.
	var respBuf []byte
	for {
		_, cmd, sid, data, err := circ.ReceiveRelay()
		if err != nil {
			return "", fmt.Errorf("read HTTP response: %w", err)
		}
		if sid != streamID {
			continue
		}
		if cmd == circuit.RelayData {
			respBuf = append(respBuf, data...)
			if len(respBuf) > 256*1024 {
				return "", fmt.Errorf("descriptor too large")
			}
		} else if cmd == circuit.RelayEnd {
			break
		} else if cmd == circuit.RelaySendMe {
			// Flow control — ignore for now, we're reading small data
			continue
		}
	}

	// Parse the HTTP response to extract the body.
	resp := string(respBuf)
	idx := strings.Index(resp, "\r\n\r\n")
	if idx < 0 {
		return "", fmt.Errorf("invalid HTTP response from HSDir")
	}
	headerSection := resp[:idx]
	statusLine := headerSection[:strings.Index(headerSection, "\r\n")]
	if !strings.Contains(statusLine, "200") {
		return "", fmt.Errorf("HSDir HTTP response: %s", statusLine)
	}

	body := resp[idx+4:]

	// Handle chunked transfer encoding.
	if strings.Contains(strings.ToLower(headerSection), "transfer-encoding: chunked") {
		body = decodeChunked(body)
	}

	body = strings.TrimRight(body, "\x00\r\n ")

	// Send RELAY_END to clean up the stream.
	_ = circ.SendRelay(circuit.RelayEnd, streamID, []byte{6}) // reason=DONE

	return body, nil
}

// decodeChunked decodes an HTTP chunked transfer-encoded body.
func decodeChunked(data string) string {
	var result strings.Builder
	remaining := data
	for {
		// Each chunk: hex_size\r\n data\r\n
		crlfIdx := strings.Index(remaining, "\r\n")
		if crlfIdx < 0 {
			break
		}
		sizeHex := strings.TrimSpace(remaining[:crlfIdx])
		if sizeHex == "" {
			break
		}
		var size int
		_, err := fmt.Sscanf(sizeHex, "%x", &size)
		if err != nil || size == 0 {
			break // size=0 means end of chunked data
		}
		remaining = remaining[crlfIdx+2:]
		if len(remaining) < size {
			result.WriteString(remaining)
			break
		}
		result.WriteString(remaining[:size])
		remaining = remaining[size:]
		// Skip trailing \r\n after chunk data
		if strings.HasPrefix(remaining, "\r\n") {
			remaining = remaining[2:]
		}
	}
	return result.String()
}

// ParseDescriptorOuterLayer parses the outer layer of a v3 HS descriptor,
// returning the fields needed for decryption.
type DescriptorOuter struct {
	LifetimeSeconds int
	SigningKeyCert  []byte // The signing key certificate
	RevisionCounter uint64
	Superencrypted  []byte // The superencrypted blob
	Signature       []byte
}

// ParseDescriptorOuter parses the outer plaintext layer of an HS descriptor.
func ParseDescriptorOuter(text string) (*DescriptorOuter, error) {
	d := &DescriptorOuter{}
	lines := strings.Split(text, "\n")

	var inSuperencrypted bool
	var superencryptedLines []string

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "descriptor-lifetime "):
			n, err := fmt.Sscanf(line, "descriptor-lifetime %d", &d.LifetimeSeconds)
			if err != nil || n != 1 {
				return nil, fmt.Errorf("parse descriptor-lifetime: %w", err)
			}

		case strings.HasPrefix(line, "revision-counter "):
			n, err := fmt.Sscanf(line, "revision-counter %d", &d.RevisionCounter)
			if err != nil || n != 1 {
				return nil, fmt.Errorf("parse revision-counter: %w", err)
			}

		case line == "-----BEGIN MESSAGE-----":
			inSuperencrypted = true

		case strings.Contains(line, "-----END MESSAGE-----"):
			if inSuperencrypted {
				before := strings.TrimSpace(strings.Split(line, "-----END MESSAGE-----")[0])
				if before != "" {
					superencryptedLines = append(superencryptedLines, before)
				}
			}
			inSuperencrypted = false
			blob := strings.Join(superencryptedLines, "")
			decoded, err := base64.StdEncoding.DecodeString(blob)
			if err != nil {
				return nil, fmt.Errorf("decode superencrypted blob: %w", err)
			}
			d.Superencrypted = decoded

		case inSuperencrypted:
			superencryptedLines = append(superencryptedLines, strings.TrimSpace(line))
		}
	}

	if d.Superencrypted == nil {
		return nil, fmt.Errorf("no superencrypted layer found")
	}

	return d, nil
}
