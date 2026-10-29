package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
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

// fakeClock is read by the renderer goroutine and written by the test, so it is atomic.
type fakeClock struct{ nanos atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.nanos.Store(time.Unix(1000, 0).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.nanos.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.nanos.Add(int64(d)) }

// ackWriter signals on acks after each write, so a test knows a frame was drawn.
type ackWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	acks chan struct{}
}

func newAckWriter() *ackWriter { return &ackWriter{acks: make(chan struct{}, 64)} }

func (w *ackWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	w.acks <- struct{}{}
	return n, err
}

func (w *ackWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// awaitFrame blocks until the writer has received one more write.
func (w *ackWriter) awaitFrame(t *testing.T) {
	t.Helper()
	select {
	case <-w.acks:
	case <-time.After(5 * time.Second):
		t.Fatal("renderer did not draw a frame")
	}
}

// tickAndAwait sends one tick and waits until the resulting frame is drawn.
func tickAndAwait(t *testing.T, tick chan time.Time, w *ackWriter) {
	t.Helper()
	tick <- time.Time{}
	w.awaitFrame(t)
}

func scanCfg(tick chan time.Time, clock *fakeClock) scanCoreConfig {
	return scanCoreConfig{width: 0, enabled: true, tick: tick, stopTicker: noopTicker, now: clock.Now}
}

func TestStartScanProgressDisabledIsNoop(t *testing.T) {
	ctx := context.Background()
	gotCtx, closeFn := startScanProgress(ctx, &bytes.Buffer{}, true)
	if gotCtx != ctx {
		t.Fatal("non-terminal writer must return the original context")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, closeFn := startScanProgress(ctx, &bytes.Buffer{}, false); closeFn() != nil {
		t.Fatal("disabled scan progress must close without error")
	}
}

func TestLintProgressSwitchesPhaseAndStaysAlive(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	_, discoveryP, inspection, closeFn := startLintProgressCore(context.Background(), w, scanCfg(tick, newFakeClock()))
	discoveryP.Folders.Store(30)
	discoveryP.Environments.Store(4)
	tickAndAwait(t, tick, w)
	inspection.Total.Store(4)
	inspection.Started.Store(true)
	inspection.Finished.Store(2)
	inspection.Failed.Store(1)
	inspection.Active.Store(1)
	tickAndAwait(t, tick, w)
	tickAndAwait(t, tick, w)
	// Independent atomic samples can briefly observe a failed attempt first.
	inspection.Finished.Store(0)
	inspection.Failed.Store(1)
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	text := w.String()
	if !strings.Contains(text, "Folders scanned: 30 | Environments found: 4") || !strings.Contains(text, "/ Linting environments: 2/4 finished") || !strings.Contains(text, "1 inspected | 1 failed | 1 active") || !strings.Contains(text, "- Linting environments: 2/4 finished") || !strings.Contains(text, "0 inspected | 1 failed") || strings.Contains(text, "184467") || !strings.HasSuffix(text, progressClear) {
		t.Fatalf("lint must display both phases, advance the spinner, and clear: %q", text)
	}
}

func TestLintProgressDisabledAndCanceled(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	if got, closeFn := startLintProgress(ctx, &out, true); got != ctx || closeFn() != nil || out.Len() != 0 {
		t.Fatal("noninteractive lint must not attach counters or emit progress")
	}
	got, d, p, closeFn := startLintProgressCore(ctx, &out, scanCoreConfig{stopTicker: noopTicker})
	if got != ctx || d != nil || p != nil || closeFn() != nil {
		t.Fatal("disabled lint progress must be a no-op")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	got, d, p, closeFn = startLintProgressCore(ctx, &out, scanCoreConfig{enabled: true, stopTicker: noopTicker})
	if got != ctx || d != nil || p != nil || closeFn() != nil || out.Len() != 0 {
		t.Fatal("pre-canceled lint progress must not start a renderer")
	}
}

func TestLintProgressReturnsWriteFailure(t *testing.T) {
	writeErr := errors.New("terminal gone")
	w := &failWriter{allowed: 0, err: writeErr}
	tick := make(chan time.Time)
	_, _, _, closeFn := startLintProgressCore(context.Background(), w, scanCfg(tick, newFakeClock()))
	tick <- time.Time{}
	if err := closeFn(); !errors.Is(err, writeErr) {
		t.Fatalf("lint progress must preserve write failure: %v", err)
	}
}

func TestLintProgressEstimatesTimeAndThroughputAfterDiscovery(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	clock := newFakeClock()
	_, discoveryP, counts, closeFn := startLintProgressCore(context.Background(), w, scanCfg(tick, clock))
	discoveryP.Folders.Store(30)
	tickAndAwait(t, tick, w)
	clock.Advance(time.Hour) // Discovery and prior validation must not affect evidence-pass estimates.
	counts.Total.Store(4)
	counts.Started.Store(true)
	counts.Finished.Store(2)
	counts.Failed.Store(1)
	counts.Inspected.Store(1)
	counts.InspectionDuration.Store(int64(10 * time.Second))
	counts.Active.Store(1)
	counts.ActiveStarted.Store(clock.Now().UnixNano())
	tickAndAwait(t, tick, w)
	clock.Advance(3 * time.Second)
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2/4 finished", "remaining ~00:20", "remaining ~00:17", "0.10 it/s", "1 failed"} {
		if !strings.Contains(w.String(), want) {
			t.Fatalf("lint progress missing %q: %q", want, w.String())
		}
	}
}

func TestLintProgressWithoutSamplesOverrunAndCompletion(t *testing.T) {
	counts := &evidence.Progress{}
	counts.Total.Store(3)
	counts.Finished.Store(2)
	counts.Failed.Store(2)
	now := time.Unix(1000, 0)
	if line := lintLine(counts, now, "|"); !strings.Contains(line, "remaining estimating") || strings.Contains(line, "Inf") || strings.Contains(line, "NaN") {
		t.Fatalf("fast rejection is not an inspection timing sample: %s", line)
	}
	counts.Inspected.Store(1)
	if line := lintLine(counts, now, "|"); !strings.Contains(line, "remaining estimating | -- it/s") || strings.Contains(line, "Inf") || strings.Contains(line, "NaN") {
		t.Fatalf("a successful inspection below clock resolution must not invent an estimate or rate: %s", line)
	}
	counts.InspectionDuration.Store(int64(time.Second))
	counts.Active.Store(1)
	counts.ActiveStarted.Store(now.Add(-2 * time.Second).UnixNano())
	if line := lintLine(counts, now, "|"); !strings.Contains(line, "remaining estimating") {
		t.Fatalf("an inspection beyond the estimated duration must not claim zero remaining: %s", line)
	}
	counts.Finished.Store(3)
	if line := lintLine(counts, now, "|"); !strings.Contains(line, "remaining 00:00") {
		t.Fatalf("completed lint should report zero remaining: %s", line)
	}
}

func TestLintTimeAndThroughputVisibleOnStandardTerminal(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	cfg := scanCfg(tick, newFakeClock())
	cfg.width = 80
	_, _, counts, closeFn := startLintProgressCore(context.Background(), w, cfg)
	counts.Started.Store(true)
	counts.Total.Store(100)
	counts.Finished.Store(99)
	counts.Inspected.Store(99)
	counts.InspectionDuration.Store(int64(990 * time.Second))
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "remaining ~00:10") || !strings.Contains(w.String(), "0.10 it/s") {
		t.Fatalf("ETA and rate must not be truncated behind secondary counts: %q", w.String())
	}
}

func TestScanProgressDisabledAttachesNothing(t *testing.T) {
	ctx := context.Background()
	gotCtx, d, s, closeFn := startScanProgressCore(ctx, &bytes.Buffer{}, scanCoreConfig{stopTicker: noopTicker})
	if gotCtx != ctx || d != nil || s != nil {
		t.Fatal("disabled core must return ctx unchanged with no counters")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestScanProgressDiscoveryLineUnchangedBeforeSBOMPhase(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	_, discoveryP, _, closeFn := startScanProgressCore(context.Background(), w, scanCfg(tick, newFakeClock()))
	discoveryP.Folders.Add(3)
	discoveryP.Environments.Add(1)
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	want := progressClear + "Folders scanned: 3 | Environments found: 1" + progressClear
	if got := w.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestScanProgressSwitchesToSBOMPhaseAndEstimatesRemaining(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	clock := newFakeClock()
	_, _, sbom, closeFn := startScanProgressCore(context.Background(), w, scanCfg(tick, clock))
	sbom.Started.Store(true)
	sbom.Total.Store(4)
	sbom.Finished.Store(3)
	sbom.Active.Store(1)
	sbom.PreExisting.Store(1)
	sbom.Failed.Store(1)
	sbom.Cataloged.Store(1)
	sbom.CatalogDuration.Store(int64(90 * time.Second))
	sbom.ActiveStarted.Store(clock.Now().UnixNano())

	tickAndAwait(t, tick, w)
	clock.Advance(65 * time.Second)
	tickAndAwait(t, tick, w) // Subtract time spent on the active scan from the estimate.
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	got := w.String()
	for _, want := range []string{
		"| Creating SBOMs: 3/4 finished | remaining ~01:30 | 0.01 it/s | 1 pre-existing | 1 failed | 1 active",
		"/ Creating SBOMs: 3/4 finished | remaining ~00:25 | 0.01 it/s | 1 pre-existing | 1 failed | 1 active",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "%") || strings.Contains(got, "elapsed") {
		t.Fatalf("SBOM phase must show approximate remaining time instead of elapsed: %q", got)
	}
}

func TestScanProgressSpinnerRotatesEveryTickWithoutCountChange(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	_, _, sbom, closeFn := startScanProgressCore(context.Background(), w, scanCfg(tick, newFakeClock()))
	sbom.Started.Store(true)
	sbom.Total.Store(2)
	for range 4 {
		tickAndAwait(t, tick, w)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, frame := range spinnerFrames {
		if !strings.Contains(w.String(), frame+" Creating SBOMs") {
			t.Fatalf("spinner frame %q missing from %q", frame, w.String())
		}
	}
}

func TestScanProgressRemainingBeyondOneHour(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	clock := newFakeClock()
	_, _, sbom, closeFn := startScanProgressCore(context.Background(), w, scanCfg(tick, clock))
	sbom.Started.Store(true)
	sbom.Total.Store(2)
	sbom.Finished.Store(1)
	sbom.Cataloged.Store(1)
	sbom.CatalogDuration.Store(int64(3725 * time.Second))
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !strings.Contains(w.String(), "remaining ~62:05") {
		t.Fatalf("remaining time must count minutes past one hour: %q", w.String())
	}
}

func TestSBOMRemainingWithoutSamplesAndOverrun(t *testing.T) {
	counts := &inventory.Progress{}
	counts.Total.Store(5)
	counts.Finished.Store(4)
	counts.PreExisting.Store(4)
	if line := sbomLine(counts, time.Unix(1000, 0), "|"); !strings.Contains(line, "remaining estimating") {
		t.Fatalf("pre-existing skips cannot supply a cataloging rate: %s", line)
	}
	counts.Cataloged.Store(1)
	counts.CatalogDuration.Store(int64(time.Second))
	if line := sbomLine(counts, time.Unix(1000, 0), "|"); !strings.Contains(line, "1.00 it/s") {
		t.Fatalf("scan must display real cataloging throughput: %s", line)
	}
	counts.Active.Store(1)
	counts.ActiveStarted.Store(time.Unix(998, 0).UnixNano())
	if line := sbomLine(counts, time.Unix(1000, 0), "|"); !strings.Contains(line, "remaining estimating") {
		t.Fatalf("an active scan exceeding its estimate must not claim zero remaining: %s", line)
	}
	counts.Finished.Store(5)
	if line := sbomLine(counts, time.Unix(1000, 0), "|"); !strings.Contains(line, "remaining 00:00") {
		t.Fatalf("finished scans should report zero remaining: %s", line)
	}
}

func TestScanRemainingVisibleOnStandardTerminal(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	cfg := scanCfg(tick, newFakeClock())
	cfg.width = 80
	_, _, counts, closeFn := startScanProgressCore(context.Background(), w, cfg)
	counts.Started.Store(true)
	counts.Total.Store(100)
	counts.Finished.Store(99)
	counts.PreExisting.Store(98)
	counts.Cataloged.Store(1)
	counts.CatalogDuration.Store(int64(12 * time.Second))
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "remaining ~00:12") || !strings.Contains(w.String(), "0.08 it/s") {
		t.Fatalf("remaining time and rate must not be truncated behind secondary counters: %q", w.String())
	}
}

func TestScanProgressCloseIsIdempotentAndClears(t *testing.T) {
	w := newAckWriter()
	_, _, sbom, closeFn := startScanProgressCore(context.Background(), w, scanCfg(make(chan time.Time), newFakeClock()))
	sbom.Started.Store(true)
	if err := closeFn(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	before := w.String()
	if err := closeFn(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if w.String() != before {
		t.Fatal("second close must not write again")
	}
	if !strings.HasSuffix(w.String(), progressClear) {
		t.Fatalf("close must end by clearing the line: %q", w.String())
	}
}

func TestScanProgressCancelStopsRenderer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, _, _, closeFn := startScanProgressCore(ctx, newAckWriter(), scanCfg(make(chan time.Time), newFakeClock()))
	cancel()
	if err := closeFn(); err != nil {
		t.Fatalf("close after cancel: %v", err)
	}
}

func TestScanProgressReturnsWriteError(t *testing.T) {
	writeErr := errors.New("tty gone")
	w := &failWriter{allowed: 0, err: writeErr}
	tick := make(chan time.Time)
	_, discoveryP, _, closeFn := startScanProgressCore(context.Background(), w, scanCfg(tick, newFakeClock()))
	discoveryP.Folders.Add(1)
	tick <- time.Time{}
	if err := closeFn(); !errors.Is(err, writeErr) {
		t.Fatalf("close error = %v, want %v", err, writeErr)
	}
}

func TestScanProgressNarrowTerminalStaysOnOneLine(t *testing.T) {
	w := newAckWriter()
	tick := make(chan time.Time)
	cfg := scanCfg(tick, newFakeClock())
	cfg.width = 12
	_, _, sbom, closeFn := startScanProgressCore(context.Background(), w, cfg)
	sbom.Started.Store(true)
	sbom.Total.Store(9)
	tickAndAwait(t, tick, w)
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if strings.ContainsAny(w.String(), "\n\r\x1b") && strings.Count(w.String(), "\r") != 2 {
		t.Fatalf("narrow line must not wrap or add control text: %q", w.String())
	}
}

func TestStartScanProgressTermDumbDisablesRendering(t *testing.T) {
	t.Setenv("TERM", "dumb")
	ctx := context.Background()
	gotCtx, closeFn := startScanProgress(ctx, &bytes.Buffer{}, true)
	if gotCtx != ctx {
		t.Fatal("TERM=dumb must return the original context")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
