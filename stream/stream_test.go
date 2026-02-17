package stream

import (
	"testing"
)

func TestStreamIDAllocation(t *testing.T) {
	// Reset counter for test isolation
	nextStreamID.Store(1)

	ids := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		id := uint16(nextStreamID.Add(1) - 1)
		if id == 0 {
			t.Fatal("stream ID should never be 0")
		}
		if ids[id] {
			t.Fatalf("duplicate stream ID: %d", id)
		}
		ids[id] = true
	}
}

func TestStreamWriteWhenClosed(t *testing.T) {
	s := &Stream{
		ID:           1,
		CircWindow:   1000,
		StreamWindow: 500,
		closed:       true,
	}
	_, err := s.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error writing to closed stream")
	}
}

func TestStreamWriteWindowExhausted(t *testing.T) {
	s := &Stream{
		ID:           1,
		CircWindow:   0,
		StreamWindow: 500,
	}
	_, err := s.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error when circuit window exhausted")
	}

	s.CircWindow = 1000
	s.StreamWindow = 0
	_, err = s.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error when stream window exhausted")
	}
}

func TestStreamReadWhenClosed(t *testing.T) {
	s := &Stream{
		ID:     1,
		closed: true,
	}
	_, err := s.Read(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error reading from closed stream")
	}
}

func TestStreamReadWhenEOF(t *testing.T) {
	s := &Stream{
		ID:  1,
		eof: true,
	}
	_, err := s.Read(make([]byte, 10))
	if err == nil {
		t.Fatal("expected EOF error")
	}
}

func TestStreamReadFromBuffer(t *testing.T) {
	s := &Stream{
		ID:  1,
		buf: []byte("hello world"),
	}
	buf := make([]byte, 5)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("read %d bytes, want 5", n)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q, want %q", buf[:n], "hello")
	}
	// Second read should return remaining
	n, err = s.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("read %d bytes, want 5", n)
	}
	if string(buf[:n]) != " worl" {
		t.Fatalf("got %q, want %q", buf[:n], " worl")
	}
}

func TestStreamCloseIdempotent(t *testing.T) {
	// Close on an already-closed stream should not error
	s := &Stream{
		ID:     1,
		closed: true,
	}
	err := s.Close()
	if err != nil {
		t.Fatalf("second close should not error: %v", err)
	}
}

func TestStreamInitialWindows(t *testing.T) {
	s := &Stream{
		ID:           1,
		CircWindow:   1000,
		StreamWindow: 500,
	}
	if s.CircWindow != 1000 {
		t.Fatalf("CircWindow = %d, want 1000", s.CircWindow)
	}
	if s.StreamWindow != 500 {
		t.Fatalf("StreamWindow = %d, want 500", s.StreamWindow)
	}
}
