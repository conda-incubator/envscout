package cli

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
	"golang.org/x/term"
)

// progressInterval caps redraws at 5Hz.
const progressInterval = 200 * time.Millisecond

// progressClear erases the current terminal line and returns the cursor to column 0.
const progressClear = "\r\x1b[2K"

// spinnerFrames rotate once per tick so a long SBOM phase visibly stays alive.
var spinnerFrames = []string{"|", "/", "-", "\\"}

// startDiscoveryProgress renders live discovery counters on out when progress is
// enabled and out is an interactive terminal. Otherwise it returns ctx unchanged
// and a no-op close, so callers never branch on the result.
func startDiscoveryProgress(ctx context.Context, out io.Writer, enabled bool) (context.Context, func() error) {
	if !progressEnabled(ctx, out, enabled) {
		return ctx, func() error { return nil }
	}
	ticker := time.NewTicker(progressInterval)
	ctx, _, closeFn := startProgress(ctx, out, terminalWidth(out), ticker.C, ticker.Stop)
	return ctx, closeFn
}

// startProgress is the testable core. tick drives redraws; stopTicker releases
// the source. It attaches a *discovery.Progress to ctx so the discovery worker
// increments counters, and a single goroutine renders until close is called or
// ctx is canceled.
func startProgress(ctx context.Context, out io.Writer, width int, tick <-chan time.Time, stopTicker func()) (context.Context, *discovery.Progress, func() error) {
	if ctx.Err() != nil {
		stopTicker()
		return ctx, nil, func() error { return nil }
	}
	counts := &discovery.Progress{}
	ctx = discovery.WithProgress(ctx, counts)
	line := func(int) string {
		return fmt.Sprintf("Folders scanned: %d | Environments found: %d", counts.Folders.Load(), counts.Environments.Load())
	}
	return ctx, counts, runProgressLoop(ctx, out, width, tick, stopTicker, line)
}

// startScanProgress is the scan-command entry point. It uses the same gate as
// startDiscoveryProgress and switches to SBOM counters once the domain starts.
func startScanProgress(ctx context.Context, out io.Writer, enabled bool) (context.Context, func() error) {
	if !progressEnabled(ctx, out, enabled) {
		return ctx, func() error { return nil }
	}
	ticker := time.NewTicker(progressInterval)
	ctx, _, _, closeFn := startScanProgressCore(ctx, out, scanCoreConfig{
		width:      terminalWidth(out),
		enabled:    true,
		tick:       ticker.C,
		stopTicker: ticker.Stop,
		now:        time.Now,
	})
	return ctx, closeFn
}

func startLintProgress(ctx context.Context, out io.Writer, enabled bool) (context.Context, func() error) {
	if !progressEnabled(ctx, out, enabled) {
		return ctx, func() error { return nil }
	}
	ticker := time.NewTicker(progressInterval)
	ctx, _, _, closeFn := startLintProgressCore(ctx, out, scanCoreConfig{width: terminalWidth(out), enabled: true, tick: ticker.C, stopTicker: ticker.Stop, now: time.Now})
	return ctx, closeFn
}

func startLintProgressCore(ctx context.Context, out io.Writer, cfg scanCoreConfig) (context.Context, *discovery.Progress, *evidence.Progress, func() error) {
	if !cfg.enabled || ctx.Err() != nil {
		if cfg.stopTicker != nil {
			cfg.stopTicker()
		}
		return ctx, nil, nil, func() error { return nil }
	}
	discoveryCounts := &discovery.Progress{}
	inspectionCounts := &evidence.Progress{}
	ctx = discovery.WithProgress(ctx, discoveryCounts)
	ctx = evidence.WithProgress(ctx, inspectionCounts)
	line := func(ticks int) string {
		if !inspectionCounts.Started.Load() {
			return fmt.Sprintf("Folders scanned: %d | Environments found: %d", discoveryCounts.Folders.Load(), discoveryCounts.Environments.Load())
		}
		return lintLine(inspectionCounts, cfg.now(), spinnerFrames[(ticks-1)%len(spinnerFrames)])
	}
	return ctx, discoveryCounts, inspectionCounts, runProgressLoop(ctx, out, cfg.width, cfg.tick, cfg.stopTicker, line)
}

// progressEnabled is the shared gate: enabled by the caller, not canceled, an
// interactive terminal, and TERM not dumb.
func progressEnabled(ctx context.Context, out io.Writer, enabled bool) bool {
	return enabled && ctx.Err() == nil && isTerminal(out) && os.Getenv("TERM") != "dumb"
}

// scanCoreConfig injects the clock, tick source, and width so tests run without sleeps.
type scanCoreConfig struct {
	width      int
	enabled    bool
	tick       <-chan time.Time
	stopTicker func()
	now        func() time.Time
}

// startScanProgressCore attaches discovery and inventory counters to ctx and renders
// discovery counts until the domain marks the SBOM phase started, then SBOM counts.
// Disabled configs return ctx unchanged, with no counters and no timers.
func startScanProgressCore(ctx context.Context, out io.Writer, cfg scanCoreConfig) (context.Context, *discovery.Progress, *inventory.Progress, func() error) {
	if !cfg.enabled || ctx.Err() != nil {
		if cfg.stopTicker != nil {
			cfg.stopTicker()
		}
		return ctx, nil, nil, func() error { return nil }
	}
	discoveryCounts := &discovery.Progress{}
	sbomCounts := &inventory.Progress{}
	ctx = discovery.WithProgress(ctx, discoveryCounts)
	ctx = inventory.WithProgress(ctx, sbomCounts)

	line := func(ticks int) string {
		if !sbomCounts.Started.Load() {
			return fmt.Sprintf("Folders scanned: %d | Environments found: %d", discoveryCounts.Folders.Load(), discoveryCounts.Environments.Load())
		}
		return sbomLine(sbomCounts, cfg.now(), spinnerFrames[(ticks-1)%len(spinnerFrames)])
	}
	return ctx, discoveryCounts, sbomCounts, runProgressLoop(ctx, out, cfg.width, cfg.tick, cfg.stopTicker, line)
}

// runProgressLoop owns the single renderer goroutine and the idempotent close. line
// receives the 1-based tick count. Identical text is not redrawn, so the phased line
// must change text on every tick through its spinner.
func runProgressLoop(ctx context.Context, out io.Writer, width int, tick <-chan time.Time, stopTicker func(), line func(ticks int) string) func() error {
	stop := make(chan struct{})
	done := make(chan struct{})
	printer := newPrinter(out)
	go func() {
		defer close(done)
		var last string
		ticks := 0
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case _, ok := <-tick:
				if !ok {
					return
				}
				ticks++
				text := line(ticks)
				if text == last {
					continue
				}
				last = text
				if width > 0 {
					text = ansi.Truncate(text, width, "")
				}
				printer.write(progressClear + text)
			}
		}
	}()

	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			stopTicker()
			close(stop)
			<-done
			// The goroutine has stopped, so clearing cannot race a redraw.
			printer.write(progressClear)
			closeErr = printer.Err()
		})
		return closeErr
	}
}

// sbomLine estimates remaining time from actual new scans, never fast skips.
func sbomLine(counts *inventory.Progress, now time.Time, spin string) string {
	finished, total := counts.Finished.Load(), counts.Total.Load()
	remaining, rate := progressEstimate(finished, total, counts.Cataloged.Load(), counts.CatalogDuration.Load(), counts.ActiveStarted.Load(), now)
	return fmt.Sprintf("%s Creating SBOMs: %d/%d finished | remaining %s | %s it/s | %d pre-existing | %d failed | %d active",
		spin, finished, total, remaining, rate, counts.PreExisting.Load(), counts.Failed.Load(), counts.Active.Load())
}

func lintLine(counts *evidence.Progress, now time.Time, spin string) string {
	finished, total, failed := counts.Finished.Load(), counts.Total.Load(), counts.Failed.Load()
	remaining, rate := progressEstimate(finished, total, counts.Inspected.Load(), counts.InspectionDuration.Load(), counts.ActiveStarted.Load(), now)
	return fmt.Sprintf("%s Linting environments: %d/%d finished | remaining %s | %s it/s | %d inspected | %d failed | %d active",
		spin, finished, total, remaining, rate, finished-min(finished, failed), failed, counts.Active.Load())
}

// Fast skips and rejected inputs are not timing samples for unfinished work.
func progressEstimate(finished, total, samples uint64, duration, activeStarted int64, now time.Time) (string, string) {
	remaining, rate := "estimating", "--"
	if samples > 0 && duration > 0 {
		rate = fmt.Sprintf("%.2f", float64(samples)/float64(duration)*float64(time.Second))
	}
	if finished >= total {
		remaining = "00:00"
	} else if samples > 0 && duration > 0 {
		nanos := float64(duration) / float64(samples) * float64(total-finished)
		if activeStarted > 0 {
			nanos -= float64(max(now.Sub(time.Unix(0, activeStarted)), 0))
		}
		if nanos > 0 && nanos < float64(time.Duration(1<<63-1)) {
			seconds := int64(math.Ceil(nanos / float64(time.Second)))
			remaining = fmt.Sprintf("~%02d:%02d", seconds/60, seconds%60)
		}
	}
	return remaining, rate
}

// terminalWidth reads the terminal width once. Zero means unknown.
func terminalWidth(out io.Writer) int {
	file, ok := out.(*os.File)
	if !ok {
		return 0
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return 0
	}
	return width
}
