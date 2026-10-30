package cli

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/discovery"
)

// discoveryAttach runs one progress entry point and exposes only its discovery counters.
type discoveryAttach struct {
	name   string
	attach func(out io.Writer, tick chan time.Time, stop func()) (*discovery.Progress, func() error)
}

var discoveryAttachers = []discoveryAttach{
	{"startProgress", func(out io.Writer, tick chan time.Time, stop func()) (*discovery.Progress, func() error) {
		_, counts, closeFn := startProgress(context.Background(), out, 0, tick, stop)
		return counts, closeFn
	}},
	{"startScanProgressCore", func(out io.Writer, tick chan time.Time, stop func()) (*discovery.Progress, func() error) {
		_, counts, _, closeFn := startScanProgressCore(context.Background(), out, scanCoreConfig{enabled: true, tick: tick, stopTicker: stop, now: time.Now})
		return counts, closeFn
	}},
	{"startLintProgressCore", func(out io.Writer, tick chan time.Time, stop func()) (*discovery.Progress, func() error) {
		_, counts, _, closeFn := startLintProgressCore(context.Background(), out, scanCoreConfig{enabled: true, tick: tick, stopTicker: stop, now: time.Now})
		return counts, closeFn
	}},
}

// Discovery bytes stay identical across all commands, including unchanged ticks and cleanup.
func TestProgressDiscoveryPhaseTranscriptIsIdenticalAcrossAttachFns(t *testing.T) {
	const clear = "\r\x1b[2K"
	const zeroLine = "Folders scanned: 0 | Environments found: 0"
	const changedLine = "Folders scanned: 2 | Environments found: 1"
	want := clear + zeroLine + clear + changedLine + clear
	for _, tc := range discoveryAttachers {
		t.Run(tc.name, func(t *testing.T) {
			w := newAckWriter()
			tick := make(chan time.Time)
			counts, closeFn := tc.attach(w, tick, noopTicker)
			t.Cleanup(func() { _ = closeFn() })
			sendTick := func() {
				t.Helper()
				select {
				case tick <- time.Time{}:
				case <-time.After(5 * time.Second):
					t.Fatal("renderer stopped accepting ticks")
				}
			}
			sendTick()
			w.awaitFrame(t) // initial frame reports zero counts
			counts.Folders.Add(2)
			counts.Environments.Add(1)
			sendTick()
			w.awaitFrame(t) // changed counts redraw once
			// Unchanged counts: the renderer receives this tick but must not write.
			// Close waits for the renderer to finish, so the transcript is complete after it returns.
			sendTick()
			if err := closeFn(); err != nil {
				t.Fatalf("close: %v", err)
			}
			if got := w.String(); got != want {
				t.Fatalf("discovery transcript = %q, want %q", got, want)
			}
		})
	}
}

// TestProgressSetupStopsTickerOnceWithoutCounters pins the no-op setup paths: the tick
// source is released exactly once, no counters are attached, nothing is written, and
// close can be called repeatedly.
func TestProgressSetupStopsTickerOnceWithoutCounters(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	type setup func(ctx context.Context, out io.Writer, stop func()) (context.Context, bool, func() error)
	cases := []struct {
		name  string
		ctx   context.Context
		start setup
	}{
		{"scan disabled", context.Background(), func(ctx context.Context, out io.Writer, stop func()) (context.Context, bool, func() error) {
			got, d, s, closeFn := startScanProgressCore(ctx, out, scanCoreConfig{stopTicker: stop})
			return got, d == nil && s == nil, closeFn
		}},
		{"lint disabled", context.Background(), func(ctx context.Context, out io.Writer, stop func()) (context.Context, bool, func() error) {
			got, d, p, closeFn := startLintProgressCore(ctx, out, scanCoreConfig{stopTicker: stop})
			return got, d == nil && p == nil, closeFn
		}},
		{"scan canceled", canceled, func(ctx context.Context, out io.Writer, stop func()) (context.Context, bool, func() error) {
			got, d, s, closeFn := startScanProgressCore(ctx, out, scanCoreConfig{enabled: true, stopTicker: stop})
			return got, d == nil && s == nil, closeFn
		}},
		{"lint canceled", canceled, func(ctx context.Context, out io.Writer, stop func()) (context.Context, bool, func() error) {
			got, d, p, closeFn := startLintProgressCore(ctx, out, scanCoreConfig{enabled: true, stopTicker: stop})
			return got, d == nil && p == nil, closeFn
		}},
		{"progress canceled", canceled, func(ctx context.Context, out io.Writer, stop func()) (context.Context, bool, func() error) {
			got, d, closeFn := startProgress(ctx, out, 0, make(chan time.Time), stop)
			return got, d == nil, closeFn
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			stops := 0
			got, noCounters, closeFn := tc.start(tc.ctx, &out, func() { stops++ })
			if got != tc.ctx || !noCounters {
				t.Fatal("no-op setup must return the original context with nil counters")
			}
			for range 2 {
				if err := closeFn(); err != nil {
					t.Fatalf("close: %v", err)
				}
			}
			if stops != 1 {
				t.Fatalf("ticker stopped %d times, want 1", stops)
			}
			if out.Len() != 0 {
				t.Fatalf("no-op setup wrote %q", out.String())
			}
		})
	}
}

// TestProgressCloseStopsActiveTickerOnce pins that an active renderer releases its
// ticker on the first close and that a repeated close does not release it again.
func TestProgressCloseStopsActiveTickerOnce(t *testing.T) {
	for _, tc := range discoveryAttachers {
		t.Run(tc.name, func(t *testing.T) {
			stops := 0
			_, closeFn := tc.attach(newAckWriter(), make(chan time.Time), func() { stops++ })
			for range 2 {
				if err := closeFn(); err != nil {
					t.Fatalf("close: %v", err)
				}
			}
			if stops != 1 {
				t.Fatalf("active ticker stopped %d times, want 1", stops)
			}
		})
	}
}
