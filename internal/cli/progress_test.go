package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// failWriter rejects every write after the first n bytes.
type failWriter struct {
	buf     bytes.Buffer
	allowed int
	err     error
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.allowed {
		return 0, w.err
	}
	return w.buf.Write(p)
}

func noopTicker() {}

func TestStartDiscoveryProgressDisabledIsNoop(t *testing.T) {
	ctx := context.Background()
	gotCtx, closeFn := startDiscoveryProgress(ctx, &bytes.Buffer{}, true)
	if gotCtx != ctx {
		t.Fatal("non-terminal writer must return the original context")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, closeFn := startDiscoveryProgress(ctx, &bytes.Buffer{}, false); closeFn() != nil {
		t.Fatal("disabled progress must close without error")
	}
}

func TestProgressDrawsCountsAndClearsOnClose(t *testing.T) {
	var out bytes.Buffer
	tick := make(chan time.Time)
	_, progress, closeFn := startProgress(context.Background(), &out, 0, tick, noopTicker)
	progress.Folders.Add(3)
	progress.Environments.Add(1)
	tick <- time.Time{}
	// An unchanged sample must not redraw.
	tick <- time.Time{}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	want := progressClear + "Folders scanned: 3 | Environments found: 1" + progressClear
	if got := out.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestProgressTruncatesToWidth(t *testing.T) {
	var out bytes.Buffer
	tick := make(chan time.Time)
	_, _, closeFn := startProgress(context.Background(), &out, 10, tick, noopTicker)
	tick <- time.Time{}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !strings.Contains(out.String(), "Folders sc") || strings.Contains(out.String(), "Folders scanned:") {
		t.Fatalf("line not truncated to width 10: %q", out.String())
	}
}

func TestProgressCloseIsIdempotent(t *testing.T) {
	var out bytes.Buffer
	_, _, closeFn := startProgress(context.Background(), &out, 0, make(chan time.Time), noopTicker)
	if err := closeFn(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	before := out.Len()
	if err := closeFn(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if out.Len() != before {
		t.Fatal("second close must not write again")
	}
}

func TestProgressContextCancelStopsRenderer(t *testing.T) {
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	_, _, closeFn := startProgress(ctx, &out, 0, make(chan time.Time), noopTicker)
	cancel()
	if err := closeFn(); err != nil {
		t.Fatalf("close after cancel: %v", err)
	}
}

func TestProgressClosedTickChannelStopsRenderer(t *testing.T) {
	var out bytes.Buffer
	tick := make(chan time.Time)
	_, _, closeFn := startProgress(context.Background(), &out, 0, tick, noopTicker)
	close(tick)
	if err := closeFn(); err != nil || out.String() != progressClear {
		t.Fatalf("closed ticks must only clear the line: %q, %v", out.String(), err)
	}
}

func TestProgressPrecancelledWritesNothing(t *testing.T) {
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gotCtx, _, closeFn := startProgress(ctx, &out, 0, make(chan time.Time), noopTicker)
	if gotCtx != ctx {
		t.Fatal("precancelled context must be returned unchanged")
	}
	if err := closeFn(); err != nil || out.Len() != 0 {
		t.Fatalf("err=%v output=%q, want no output", err, out.String())
	}
}

func TestProgressReturnsFirstWriteError(t *testing.T) {
	writeErr := errors.New("tty gone")
	w := &failWriter{allowed: 0, err: writeErr}
	tick := make(chan time.Time)
	_, _, closeFn := startProgress(context.Background(), w, 0, tick, noopTicker)
	tick <- time.Time{}
	if err := closeFn(); !errors.Is(err, writeErr) {
		t.Fatalf("close error = %v, want %v", err, writeErr)
	}
}
