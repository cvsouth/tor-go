package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestMultiHandlerEnabled verifies that Enabled returns true if any handler
// is enabled at the given level.
func TestMultiHandlerEnabled(t *testing.T) {
	debugHandler := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug})
	errorHandler := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})

	mh := &multiHandler{handlers: []slog.Handler{debugHandler, errorHandler}}

	// Debug level: debugHandler is enabled, so multiHandler should be enabled.
	if !mh.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("expected Enabled=true for Debug (debugHandler is enabled)")
	}

	// Info level: debugHandler is enabled at Info.
	if !mh.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("expected Enabled=true for Info")
	}

	// Error level: both are enabled.
	if !mh.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("expected Enabled=true for Error")
	}
}

// TestMultiHandlerEnabledNoneMatch verifies that Enabled returns false when
// no handler is enabled at the given level.
func TestMultiHandlerEnabledNoneMatch(t *testing.T) {
	errorHandler := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})
	mh := &multiHandler{handlers: []slog.Handler{errorHandler}}

	if mh.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("expected Enabled=false for Debug when only error handler exists")
	}
}

// TestMultiHandlerEnabledEmpty verifies that an empty multiHandler returns false.
func TestMultiHandlerEnabledEmpty(t *testing.T) {
	mh := &multiHandler{handlers: nil}
	if mh.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("expected Enabled=false for empty handler list")
	}
}

// TestMultiHandlerHandle verifies that Handle fans out to all enabled handlers.
func TestMultiHandlerHandle(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	h1 := slog.NewTextHandler(&buf1, &slog.HandlerOptions{Level: slog.LevelInfo})
	h2 := slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelInfo})

	mh := &multiHandler{handlers: []slog.Handler{h1, h2}}
	logger := slog.New(mh)
	logger.Info("test message", "key", "value")

	if !strings.Contains(buf1.String(), "test message") {
		t.Fatalf("handler 1 did not receive message: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "test message") {
		t.Fatalf("handler 2 did not receive message: %s", buf2.String())
	}
}

// TestMultiHandlerHandleSkipsDisabled verifies that Handle skips handlers
// that are not enabled at the record's level.
func TestMultiHandlerHandleSkipsDisabled(t *testing.T) {
	var debugBuf, errorBuf bytes.Buffer
	debugHandler := slog.NewTextHandler(&debugBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	errorHandler := slog.NewTextHandler(&errorBuf, &slog.HandlerOptions{Level: slog.LevelError})

	mh := &multiHandler{handlers: []slog.Handler{debugHandler, errorHandler}}
	logger := slog.New(mh)
	logger.Info("info message")

	if !strings.Contains(debugBuf.String(), "info message") {
		t.Fatalf("debug handler should receive info message: %s", debugBuf.String())
	}
	if strings.Contains(errorBuf.String(), "info message") {
		t.Fatalf("error handler should not receive info message: %s", errorBuf.String())
	}
}

// TestMultiHandlerWithAttrs verifies that WithAttrs returns a new multiHandler
// with the attrs applied to all child handlers.
func TestMultiHandlerWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	mh := &multiHandler{handlers: []slog.Handler{h}}

	mhWithAttrs := mh.WithAttrs([]slog.Attr{slog.String("component", "bootstrap")})
	logger := slog.New(mhWithAttrs)
	logger.Info("test")

	if !strings.Contains(buf.String(), "component=bootstrap") {
		t.Fatalf("expected attrs in output: %s", buf.String())
	}
}

// TestMultiHandlerWithGroup verifies that WithGroup returns a new multiHandler
// with the group applied to all child handlers.
func TestMultiHandlerWithGroup(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	mh := &multiHandler{handlers: []slog.Handler{h}}

	mhWithGroup := mh.WithGroup("bootstrap")
	logger := slog.New(mhWithGroup)
	logger.Info("test", "key", "val")

	if !strings.Contains(buf.String(), "bootstrap.key=val") {
		t.Fatalf("expected group prefix in output: %s", buf.String())
	}
}
