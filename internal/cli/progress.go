package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/conda-incubator/envscout/internal/discovery"
	"golang.org/x/term"
)

// progressInterval caps redraws at 5Hz.
const progressInterval = 200 * time.Millisecond

// progressClear erases the current terminal line and returns the cursor to column 0.
const progressClear = "\r\x1b[2K"

// startDiscoveryProgress renders live discovery counters on out when progress is
// enabled and out is an interactive terminal. Otherwise it returns ctx unchanged
// and a no-op close, so callers never branch on the result.
func startDiscoveryProgress(ctx context.Context, out io.Writer, enabled bool) (context.Context, func() error) {
	if !enabled || ctx.Err() != nil || !isTerminal(out) || os.Getenv("TERM") == "dumb" {
		return ctx, func() error { return nil }
	}
	width := terminalWidth(out)
	ticker := time.NewTicker(progressInterval)
	ctx, _, closeFn := startProgress(ctx, out, width, ticker.C, func() { ticker.Stop() })
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

	stop := make(chan struct{})
	done := make(chan struct{})
	printer := newPrinter(out)
	go func() {
		defer close(done)
		var last string
		draw := func() {
			line := fmt.Sprintf("Folders scanned: %d | Environments found: %d", counts.Folders.Load(), counts.Environments.Load())
			if line == last {
				return
			}
			last = line
			if width > 0 {
				line = ansi.Truncate(line, width, "")
			}
			printer.write(progressClear + line)
		}
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
				draw()
			}
		}
	}()

	var once sync.Once
	var closeErr error
	closeFn := func() error {
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
	return ctx, counts, closeFn
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
