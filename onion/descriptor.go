package onion

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/cvsouth/tor-go/circuit"
)

// FetchDescriptorViaCircuit fetches a v3 hidden service descriptor using
// BEGIN_DIR over an existing circuit. The circuit's last hop must be the
// HSDir relay.
//
// The circuit's read loop must be started before calling this function.
// The function allocates a unique stream ID, registers it with the circuit's
// dispatch table, and reads responses from the per-stream channel.
func FetchDescriptorViaCircuit(circ *circuit.Circuit, blindedKey [32]byte) (string, error) {
	keyB64 := base64.RawStdEncoding.EncodeToString(blindedKey[:])
	streamID := circuit.NextStreamID()

	recv, err := circ.RegisterStream(streamID)
	if err != nil {
		return "", fmt.Errorf("register stream: %w", err)
	}
	defer circ.UnregisterStream(streamID)

	if err := circ.SendRelay(circuit.RelayBeginDir, streamID, nil); err != nil {
		return "", fmt.Errorf("send BEGIN_DIR: %w", err)
	}

	if err := waitForConnected(recv); err != nil {
		return "", err
	}

	httpReq := fmt.Sprintf("GET /tor/hs/3/%s HTTP/1.0\r\nHost: tor\r\nAccept-Encoding: identity\r\n\r\n", keyB64)
	if err := circ.SendRelay(circuit.RelayData, streamID, []byte(httpReq)); err != nil {
		return "", fmt.Errorf("send HTTP request: %w", err)
	}

	respBuf, err := readDirResponse(recv)
	if err != nil {
		return "", err
	}

	body, err := parseHTTPResponse(string(respBuf))
	if err != nil {
		return "", err
	}

	_ = circ.SendRelay(circuit.RelayEnd, streamID, []byte{6})
	return body, nil
}

func waitForConnected(recv *circuit.StreamReceiver) error {
	for {
		select {
		case rc, ok := <-recv.Cells:
			if !ok {
				return fmt.Errorf("wait for CONNECTED: stream channel closed")
			}
			if rc.Cmd == circuit.RelayConnected {
				return nil
			}
			if rc.Cmd == circuit.RelayEnd {
				return fmt.Errorf("BEGIN_DIR rejected")
			}
			// Skip unexpected cells (e.g., SENDME) and keep waiting.
			continue
		case <-recv.Done:
			return fmt.Errorf("wait for CONNECTED: circuit died")
		}
	}
}

func readDirResponse(recv *circuit.StreamReceiver) ([]byte, error) {
	var buf []byte
	for {
		select {
		case rc, ok := <-recv.Cells:
			if !ok {
				return nil, fmt.Errorf("read HTTP response: stream channel closed")
			}
			switch rc.Cmd {
			case circuit.RelayData:
				buf = append(buf, rc.Data...)
				if len(buf) > 256*1024 {
					return nil, fmt.Errorf("descriptor too large")
				}
			case circuit.RelayEnd:
				return buf, nil
			}
		case <-recv.Done:
			return nil, fmt.Errorf("read HTTP response: circuit died")
		}
	}
}

func parseHTTPResponse(resp string) (string, error) {
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
	if strings.Contains(strings.ToLower(headerSection), "transfer-encoding: chunked") {
		body = decodeChunked(body)
	}
	return strings.TrimRight(body, "\x00\r\n "), nil
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
		if err != nil || size <= 0 {
			break // size<=0 means end of chunked data
		}
		remaining = remaining[crlfIdx+2:]
		if len(remaining) < size {
			result.WriteString(remaining)
			break
		}
		result.WriteString(remaining[:size])
		remaining = remaining[size:]
		// Skip trailing \r\n after chunk data
		remaining = strings.TrimPrefix(remaining, "\r\n")
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
				before := strings.TrimSpace(strings.TrimSuffix(line, "-----END MESSAGE-----"))
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
