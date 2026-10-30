//go:build darwin || linux

package cli

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func TestTerminalProgressEntryPointsHonorRealTerminalGate(t *testing.T) {
	for _, start := range []struct {
		name string
		call func(context.Context, io.Writer, bool) (context.Context, func() error)
	}{
		{"find", startDiscoveryProgress},
		{"scan", startScanProgress},
		{"lint", startLintProgress},
	} {
		t.Run(start.name, func(t *testing.T) {
			for _, test := range []struct {
				name, term string
				enabled    bool
				canceled   bool
				active     bool
			}{
				{"active", "xterm", true, false, true},
				{"disabled", "xterm", false, false, false},
				{"dumb", "dumb", true, false, false},
				{"canceled", "xterm", true, true, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					t.Setenv("TERM", test.term)
					master, slave := progressPTY(t)
					if _, err := term.MakeRaw(int(slave.Fd())); err != nil {
						t.Fatal(err)
					}
					if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
						t.Fatal(err)
					}
					if !isTerminal(slave) || terminalWidth(slave) != 80 {
						t.Fatal("fixture must be an operating-system terminal with a known width")
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if test.canceled {
						cancel()
					}
					got, closeFn := start.call(ctx, slave, test.enabled)
					t.Cleanup(func() { _ = closeFn() })
					if (got != ctx) != test.active {
						t.Fatal("progress must attach counters only for an enabled, non-canceled, non-dumb terminal")
					}
					for range 2 {
						if err := closeFn(); err != nil {
							t.Fatal(err)
						}
					}
					// A sentinel bounds the transcript without assuming a real tick's timing.
					const sentinel = "END-PROGRESS"
					if _, err := io.WriteString(slave, sentinel); err != nil {
						t.Fatal(err)
					}
					var output strings.Builder
					deadline := time.Now().Add(5 * time.Second)
					for !strings.HasSuffix(output.String(), sentinel) {
						remaining := time.Until(deadline)
						if remaining <= 0 {
							t.Fatal("terminal output exceeded the read deadline")
						}
						ready, err := unix.Poll([]unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}, max(int(remaining/time.Millisecond), 1))
						if err != nil || ready == 0 {
							t.Fatalf("terminal output not completed: %v", err)
						}
						var buffer [4096]byte
						n, err := unix.Read(int(master.Fd()), buffer[:])
						if err != nil || n == 0 {
							t.Fatalf("terminal output ended before the sentinel: %v", err)
						}
						output.Write(buffer[:n])
					}
					transcript := strings.TrimSuffix(output.String(), sentinel)
					if test.active {
						const clear = "\r\x1b[2K"
						if transcript != clear && transcript != clear+"Folders scanned: 0 | Environments found: 0"+clear {
							t.Fatalf("active terminal must render only discovery and one closing clear: %q", transcript)
						}
					} else if transcript != "" {
						t.Fatalf("inactive terminal must remain untouched: %q", transcript)
					}
				})
			}
		})
	}
}
