//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func oscPTYTranscript(t *testing.T, master, slave *os.File) string {
	t.Helper()
	const sentinel = "END-OSC-TEST"
	if _, err := io.WriteString(slave, sentinel); err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	for !strings.HasSuffix(text.String(), sentinel) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("PTY transcript timed out")
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}, max(1, int(remaining/time.Millisecond)))
		if err != nil || ready == 0 {
			t.Fatalf("PTY transcript unavailable: %v", err)
		}
		var buffer [4096]byte
		n, err := unix.Read(int(master.Fd()), buffer[:])
		if err != nil || n == 0 {
			t.Fatalf("PTY transcript incomplete: %v", err)
		}
		text.Write(buffer[:n])
	}
	return strings.TrimSuffix(text.String(), sentinel)
}

func TestOSCRealLintCommandFinalizesActualOutcome(t *testing.T) {
	t.Setenv("TERM", "xterm")
	root := lintFixture(t, 12)
	for _, test := range []struct {
		mode, failOn, state string
		code                int
	}{
		{"7501", "none", "done", 0}, {"7501", "info", "error", 1},
		{"94", "info", "", 1}, {"auto", "none", "", 0}, {"none", "none", "", 0},
	} {
		master, slave := progressPTY(t)
		input, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, "untouched-input"); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		cmd := New()
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(slave)
		cmd.SetIn(input)
		cmd.SetArgs([]string{"lint", root, "--osc-progress", test.mode, "--fail-on", test.failOn, "--rule", "ENV001", "--debug"})
		err = cmd.ExecuteContext(context.Background())
		if ExitCode(err) != test.code || !strings.Contains(stdout.String(), "ENV001") {
			t.Fatalf("lint result changed: %v %q", err, stdout.String())
		}
		transcript := oscPTYTranscript(t, master, slave)
		switch test.mode {
		case "7501":
			if !strings.Contains(transcript, "state=working:id=envscout/lint:progress=100") ||
				!strings.Contains(transcript, "state="+test.state+":id=envscout/lint") || strings.Contains(transcript, "\x1b]9;4;") {
				t.Fatalf("lint outcome must follow evaluation, not successful collection: %q", transcript)
			}
		case "94", "auto":
			if !strings.HasSuffix(transcript, "\x1b]9;4;0;0\x07") || strings.Contains(transcript, "\x1b]7501;") {
				t.Fatalf("9;4 must clear even for a policy failure: %q", transcript)
			}
			if test.mode == "auto" && !strings.Contains(transcript, "probe=unavailable-input") {
				t.Fatalf("auto with piped input must fall back without consuming input: %q", transcript)
			}
		case "none":
			if strings.Contains(transcript, "\x1b]") || !strings.Contains(transcript, "selected=none reason=disabled") || !strings.Contains(transcript, progressClear) {
				t.Fatalf("none must retain text progress without OSC: %q", transcript)
			}
		}
		payload, err := io.ReadAll(input)
		_ = input.Close()
		if err != nil || string(payload) != "untouched-input" || strings.Contains(transcript, oscQuery) {
			t.Fatal("explicit protocols must not query or read piped stdin")
		}
	}
}

func TestOSCRealScanPreExistingFastPath(t *testing.T) {
	t.Setenv("TERM", "xterm")
	root, output := condaRoot(t), t.TempDir()
	if _, _, err := runCLI(t, context.Background(), "scan", root, "--output-dir", output); err != nil {
		t.Fatal(err)
	}
	master, slave := progressPTY(t)
	cmd := New()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(slave)
	cmd.SetArgs([]string{"scan", root, "--output-dir", output, "--osc-progress", "7501"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	transcript := oscPTYTranscript(t, master, slave)
	if !strings.Contains(transcript, "state=working:id=envscout/scan:progress=100") || !strings.Contains(transcript, "state=done:id=envscout/scan") {
		t.Fatalf("fast pre-existing work must notify even before the first tick: %q", transcript)
	}
}
