package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cvsouth/tor-go/circuit"
	"github.com/cvsouth/tor-go/stream"
)

const maxConns = 256

// OnionHandler is called when a .onion address is requested. It should
// establish the full onion service connection and return a ReadWriteCloser
// for bidirectional data relay.
type OnionHandler func(onionAddr string, port uint16) (io.ReadWriteCloser, error)

// Server is a SOCKS5 proxy server that routes traffic through Tor circuits.
type Server struct {
	Addr         string
	GetCirc      func() (*circuit.Circuit, error) // Called to get a circuit for each connection
	OnionHandler OnionHandler                     // Optional handler for .onion addresses
	Logger       *slog.Logger
	ln           net.Listener
	sem          chan struct{}
}

// ListenAndServe starts the SOCKS5 server.
func (s *Server) ListenAndServe() error {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}

	// Validate the address is a loopback address to prevent accidental exposure.
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsLoopback() {
		return fmt.Errorf("SOCKS5 server must bind to loopback address, got %s", host)
	}
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("SOCKS5 server must bind to loopback address, got %s", host)
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.ln = ln
	s.sem = make(chan struct{}, maxConns)
	s.Logger.Info("SOCKS5 server listening", "addr", s.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		s.sem <- struct{}{}
		go func() {
			defer func() { <-s.sem }()
			s.handleConn(conn)
		}()
	}
}

// Serve accepts connections on the given listener. Unlike ListenAndServe,
// this allows the caller to create the listener first and know the exact
// address before serving begins.
func (s *Server) Serve(ln net.Listener) error {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok && !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("SOCKS5 server must bind to loopback address, got %s", tcpAddr.IP)
	}
	s.ln = ln
	s.sem = make(chan struct{}, maxConns)
	s.Logger.Info("SOCKS5 server listening", "addr", ln.Addr().String())

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		s.sem <- struct{}{}
		go func() {
			defer func() { <-s.sem }()
			s.handleConn(conn)
		}()
	}
}

// Close stops the SOCKS5 server.
func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Set initial deadline for handshake + connect (2 minutes)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))

	// SOCKS5 version handshake
	if err := s.doHandshake(conn); err != nil {
		s.Logger.Debug("handshake failed", "error", err)
		return
	}

	// SOCKS5 CONNECT request
	target, err := s.readConnect(conn)
	if err != nil {
		s.Logger.Debug("connect request failed", "error", err)
		return
	}

	s.Logger.Info("SOCKS5 CONNECT")

	// Check if this is a .onion address.
	host, port := splitHostPort(target)
	if strings.HasSuffix(strings.ToLower(host), ".onion") && s.OnionHandler != nil {
		s.handleOnion(conn, host, port)
		return
	}

	// Get a Tor circuit
	circ, err := s.GetCirc()
	if err != nil {
		s.Logger.Error("get circuit failed", "error", err)
		sendReply(conn, 0x01) // General failure
		return
	}

	// Open Tor stream
	torStream, err := stream.Begin(circ, target)
	if err != nil {
		s.Logger.Error("stream begin failed", "error", err)
		sendReply(conn, 0x04) // Host unreachable
		return
	}
	defer func() { _ = torStream.Close() }()

	// Send success reply
	sendReply(conn, 0x00)

	// Clear deadline for data relay phase (streams have their own timeouts)
	_ = conn.SetDeadline(time.Time{})

	// Relay data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(torStream, conn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, torStream)
	}()

	wg.Wait()
}

func (s *Server) doHandshake(conn net.Conn) error {
	// Read: VER(1) NMETHODS(1) METHODS(NMETHODS)
	var buf [258]byte
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}
	nMethods := int(buf[1])
	if nMethods == 0 {
		return fmt.Errorf("no methods offered")
	}
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Check that no-auth (0x00) is offered
	found := false
	for i := 0; i < nMethods; i++ {
		if buf[i] == 0x00 {
			found = true
			break
		}
	}
	if !found {
		_, _ = conn.Write([]byte{0x05, 0xFF}) // No acceptable method
		return fmt.Errorf("client does not offer no-auth method")
	}

	// Send: VER(1) METHOD(1) — no auth (0x00)
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func (s *Server) readConnect(conn net.Conn) (string, error) {
	// Read: VER(1) CMD(1) RSV(1) ATYP(1)
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("bad version: %d", hdr[0])
	}
	if hdr[1] != 0x01 { // CONNECT
		sendReply(conn, 0x07) // Command not supported
		return "", fmt.Errorf("unsupported command: %d", hdr[1])
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		var addr [4]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case 0x03: // Domain name
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
		if host == "" {
			return "", fmt.Errorf("empty domain name")
		}
	case 0x04: // IPv6
		sendReply(conn, 0x08) // Address type not supported
		return "", fmt.Errorf("IPv6 not supported")
	default:
		return "", fmt.Errorf("unknown address type: %d", hdr[3])
	}

	// Read port (2 bytes, big endian)
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	return fmt.Sprintf("%s:%d", host, port), nil
}

func (s *Server) handleOnion(conn net.Conn, onionAddr string, port uint16) {
	s.Logger.Info("SOCKS5 .onion CONNECT")

	rwc, err := s.OnionHandler(onionAddr, port)
	if err != nil {
		s.Logger.Error("onion connect failed", "error", err)
		sendReply(conn, 0x04) // Host unreachable
		return
	}
	defer func() { _ = rwc.Close() }()

	sendReply(conn, 0x00)

	// Clear deadline for data relay phase
	_ = conn.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(rwc, conn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, rwc)
	}()
	wg.Wait()
}

func splitHostPort(target string) (string, uint16) {
	idx := strings.LastIndex(target, ":")
	if idx < 0 {
		return target, 0
	}
	host := target[:idx]
	var port uint16
	_, _ = fmt.Sscanf(target[idx+1:], "%d", &port)
	return host, port
}

func sendReply(conn net.Conn, rep byte) {
	// VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(4) BND.PORT(2)
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, _ = conn.Write(reply)
}
