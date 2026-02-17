package socks

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/cvsouth/tor-go/circuit"
)

func TestDoHandshakeValid(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.doHandshake(server)
	}()

	// Send valid SOCKS5 handshake: version 5, 1 method, no-auth
	client.Write([]byte{0x05, 0x01, 0x00})

	// Read server response
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		t.Fatalf("unexpected response: %x", buf)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
}

func TestDoHandshakeNoAuthNotOffered(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.doHandshake(server)
	}()

	// Send SOCKS5 handshake with only username/password auth (0x02)
	client.Write([]byte{0x05, 0x01, 0x02})

	// Server should send 0xFF rejection
	buf := make([]byte, 2)
	io.ReadFull(client, buf)
	if buf[1] != 0xFF {
		t.Fatalf("expected 0xFF rejection, got %x", buf[1])
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for missing no-auth method")
	}
}

func TestDoHandshakeWrongVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.doHandshake(server)
	}()

	// Write in goroutine since server may close before reading all bytes
	go func() {
		client.Write([]byte{0x04, 0x01, 0x00}) // SOCKS4
	}()

	if err := <-errCh; err == nil {
		t.Fatal("expected error for SOCKS4")
	}
}

func TestReadConnectDomain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		target, err := s.readConnect(server)
		ch <- result{target, err}
	}()

	domain := []byte("example.com")
	msg := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	msg = append(msg, domain...)
	msg = append(msg, 0x00, 0x50) // port 80
	client.Write(msg)

	r := <-ch
	if r.err != nil {
		t.Fatalf("readConnect failed: %v", r.err)
	}
	if r.target != "example.com:80" {
		t.Fatalf("got target %q, want example.com:80", r.target)
	}
}

func TestReadConnectIPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		target, err := s.readConnect(server)
		ch <- result{target, err}
	}()

	msg := []byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB}
	client.Write(msg)

	r := <-ch
	if r.err != nil {
		t.Fatalf("readConnect failed: %v", r.err)
	}
	if r.target != "1.2.3.4:443" {
		t.Fatalf("got target %q, want 1.2.3.4:443", r.target)
	}
}

func TestReadConnectIPv6Rejected(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		target, err := s.readConnect(server)
		ch <- result{target, err}
	}()

	go func() {
		msg := []byte{0x05, 0x01, 0x00, 0x04}
		msg = append(msg, make([]byte, 18)...) // 16 addr + 2 port
		client.Write(msg)
	}()

	// Read reply (server sends it before returning error)
	buf := make([]byte, 10)
	io.ReadFull(client, buf)
	if buf[1] != 0x08 {
		t.Fatalf("expected reply 0x08, got %x", buf[1])
	}

	r := <-ch
	if r.err == nil {
		t.Fatal("expected error for IPv6")
	}
}

func TestReadConnectUnsupportedCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		target, err := s.readConnect(server)
		ch <- result{target, err}
	}()

	go func() {
		// BIND command (0x02)
		msg := []byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50}
		client.Write(msg)
	}()

	buf := make([]byte, 10)
	io.ReadFull(client, buf)
	if buf[1] != 0x07 {
		t.Fatalf("expected reply 0x07, got %x", buf[1])
	}

	r := <-ch
	if r.err == nil {
		t.Fatal("expected error for BIND command")
	}
}

func TestSendReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go sendReply(server, 0x00)

	buf := make([]byte, 10)
	n, _ := io.ReadFull(client, buf)
	if n != 10 {
		t.Fatalf("expected 10 bytes, got %d", n)
	}
	expected := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf, expected) {
		t.Fatalf("got %x, want %x", buf, expected)
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort uint16
	}{
		{"example.com:80", "example.com", 80},
		{"example.com:443", "example.com", 443},
		{"example.com", "example.com", 0},
		{"1.2.3.4:9001", "1.2.3.4", 9001},
		{"abc.onion:80", "abc.onion", 80},
		{"noport", "noport", 0},
	}
	for _, tt := range tests {
		host, port := splitHostPort(tt.input)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %d), want (%q, %d)",
				tt.input, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestListenNonLoopbackRejected(t *testing.T) {
	s := &Server{
		Addr: "0.0.0.0:9050",
	}
	err := s.ListenAndServe()
	if err == nil {
		s.Close()
		t.Fatal("expected error for non-loopback address")
	}
}

func TestHandleConnFullFlow(t *testing.T) {
	// Test a full SOCKS5 handshake + CONNECT that fails at GetCirc
	client, server := net.Pipe()
	defer client.Close()

	s := &Server{
		GetCirc: func() (*circuit.Circuit, error) {
			return nil, fmt.Errorf("no circuit available")
		},
		Logger: slog.Default(),
	}

	done := make(chan struct{})
	go func() {
		s.handleConn(server)
		close(done)
	}()

	// Send handshake
	client.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(client, buf)

	// Send CONNECT to example.com:80
	domain := []byte("example.com")
	msg := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	msg = append(msg, domain...)
	msg = append(msg, 0x00, 0x50)
	client.Write(msg)

	// Read error reply (0x01 = general failure)
	reply := make([]byte, 10)
	io.ReadFull(client, reply)
	if reply[1] != 0x01 {
		t.Fatalf("expected reply 0x01 (general failure), got 0x%02x", reply[1])
	}

	<-done
}

func TestServerClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &Server{ln: ln}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second close should not panic
	s.Close()
}

func TestHandleOnionRouting(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// Create a mock onion handler that returns a simple pipe
	onionClient, onionServer := net.Pipe()
	defer onionClient.Close()

	s := &Server{
		OnionHandler: func(addr string, port uint16) (io.ReadWriteCloser, error) {
			if addr != "test.onion" {
				t.Errorf("unexpected addr: %s", addr)
			}
			if port != 80 {
				t.Errorf("unexpected port: %d", port)
			}
			return onionServer, nil
		},
		Logger: slog.Default(),
	}

	done := make(chan struct{})
	go func() {
		s.handleConn(server)
		close(done)
	}()

	// Handshake
	client.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	io.ReadFull(client, buf)

	// CONNECT to test.onion:80
	domain := []byte("test.onion")
	msg := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	msg = append(msg, domain...)
	msg = append(msg, 0x00, 0x50)
	client.Write(msg)

	// Read success reply
	reply := make([]byte, 10)
	io.ReadFull(client, reply)
	if reply[1] != 0x00 {
		t.Fatalf("expected success reply, got 0x%02x", reply[1])
	}

	// Send data through onion connection
	go func() {
		onionClient.Write([]byte("hello from onion"))
		onionClient.Close()
	}()

	data := make([]byte, 100)
	n, _ := client.Read(data)
	if string(data[:n]) != "hello from onion" {
		t.Fatalf("got %q, want %q", data[:n], "hello from onion")
	}

	client.Close()
	<-done
}

func TestReadConnectEmptyDomain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	s := &Server{}
	type result struct {
		target string
		err    error
	}
	ch := make(chan result, 1)

	go func() {
		target, err := s.readConnect(server)
		ch <- result{target, err}
	}()

	go func() {
		// Domain with length 0
		msg := []byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50}
		client.Write(msg)
	}()

	r := <-ch
	if r.err == nil {
		t.Fatal("expected error for empty domain")
	}
}
