package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/buildkite/osc7501"
)

func oscFixture(mode string, out io.Writer) (*oscProgress, *printer) {
	o := &oscProgress{ctx: context.Background(), out: out, operation: "scan", requested: mode,
		lastPercent: -1, probe: func(context.Context, *os.File, *os.File) (bool, string, error) {
			panic("explicit protocol must not probe")
		}}
	return o, newPrinter(out)
}

func oscReport(t *testing.T, text string) osc7501.Report {
	t.Helper()
	const prefix, suffix = "\x1b]7501;", "\x1b\\"
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, suffix) {
		t.Fatalf("invalid OSC framing: %q", text)
	}
	report, err := osc7501.Parse([]byte(text[len(prefix) : len(text)-len(suffix)]))
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestOSC94PercentageAndLifecycle(t *testing.T) {
	var out bytes.Buffer
	o, p := oscFixture("94", &out)
	o.update(p, false, 1, 4)
	o.update(p, true, 0, 0)
	if out.Len() != 0 || o.resolved {
		t.Fatal("discovery/zero-total must not select or emit a protocol")
	}
	o.update(p, true, 1, 4)
	o.update(p, true, 1, 4)
	o.update(p, true, 0, 4)
	o.update(p, true, 9, 4)
	if got, want := out.String(), "\x1b]9;4;1;25\x07\x1b]9;4;1;100\x07"; got != want {
		t.Fatalf("progress=%q, want %q", got, want)
	}
	if err := o.finish(nil); err != nil || !strings.HasSuffix(out.String(), "\x1b]9;4;0;0\x07") {
		t.Fatalf("final clear: %q %v", out.String(), err)
	}
	before := out.Len()
	if o.finish(errors.New("late")) != nil || out.Len() != before {
		t.Fatal("finalization must be idempotent")
	}
}

func TestOSCPercentageCannotOverflow(t *testing.T) {
	for _, test := range []struct {
		completed, total uint64
		want             string
	}{{math.MaxUint64, math.MaxUint64, "100"}, {math.MaxUint64 / 2, math.MaxUint64, "49"}, {0, math.MaxUint64, "0"}} {
		var out bytes.Buffer
		o, p := oscFixture("94", &out)
		o.update(p, true, test.completed, test.total)
		if out.String() != "\x1b]9;4;1;"+test.want+"\x07" {
			t.Fatalf("large counter percentage: %q", out.String())
		}
	}
}

func TestOSC7501FinalCommandStates(t *testing.T) {
	for _, test := range []struct {
		name, state string
		err         error
	}{
		{"success", "done", nil}, {"policy-failure", "error", &commandExit{code: 1, silent: true}},
		{"error", "error", errors.New("failed")}, {"canceled", "idle", errors.Join(errors.New("failed"), context.Canceled)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			o, p := oscFixture("7501", &out)
			o.update(p, true, 1, 2)
			working := oscReport(t, out.String())
			if working.State != "working" || working.Progress != 50 || working.App != "envscout" || working.ID != "envscout/scan" {
				t.Fatalf("working report: %+v", working)
			}
			out.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			o.ctx = ctx
			cancel() // deferred timeout cleanup must not override the actual command result.
			if err := o.finish(test.err); err != nil {
				t.Fatal(err)
			}
			if report := oscReport(t, out.String()); report.State != test.state || report.Progress != -1 {
				t.Fatalf("final report: %+v", report)
			}
		})
	}
}

func TestOSCWriteFailuresAndQuietFinish(t *testing.T) {
	writeErr := errors.New("terminal closed")
	for _, test := range []struct {
		out  io.Writer
		want error
	}{{&failWriter{allowed: 0, err: writeErr}, writeErr}, {zeroWriter{}, io.ErrShortWrite}} {
		o, p := oscFixture("94", test.out)
		o.update(p, true, 1, 2)
		if !errors.Is(o.finish(nil), test.want) {
			t.Fatal("OSC writes must retain the first error, including silent short writes")
		}
	}
	o, p := oscFixture("94", &failWriter{allowed: 0, err: writeErr})
	o.update(p, true, 1, 2)
	if err := o.finish(errors.Join(errors.New("command failed"), writeErr)); err != nil {
		t.Fatalf("finalization must not duplicate a previously propagated write error: %v", err)
	}
	var out bytes.Buffer
	o, _ = oscFixture("7501", &out)
	if o.finish(nil) != nil || out.Len() != 0 || (*oscProgress)(nil).finish(nil) != nil {
		t.Fatal("inactive/nil finalization must be silent")
	}
}

func TestOSCReplyFraming(t *testing.T) {
	const reply = "\x1b]7501;?:states=idle,working,done,error\x1b\\"
	const da = "\x1b[?62;1c"
	for _, test := range []struct {
		text                string
		supported, finished bool
	}{
		{reply, true, false}, {reply + da, true, true}, {da + reply, false, true},
		{"\x1b]7501;?:future=ignored\x07" + da, true, true},
		{"\x1b]7501;?:states=working,done\x07" + da, false, true},
		{osc7501.Query + da, false, true}, {"\x1b]7501;state=working\x07" + da, false, true},
		{"\x1b]7501;?:states=idle,working,", false, false},
		{"\x1b]7501;?:bad;x=1\x07" + da, false, true},
		{"\x1b[?25lc" + reply + da, true, true},
		{reply + "noise", true, false},
		{reply + "\x1b]7501;?:states=working\x07" + da, true, true},
	} {
		if supported, finished := interpretOSCReply([]byte(test.text)); supported != test.supported || finished != test.finished {
			t.Fatalf("reply %q = %t/%t, want %t/%t", test.text, supported, finished, test.supported, test.finished)
		}
	}
}

func TestOSCFlagsAndDisabledDiagnostics(t *testing.T) {
	if flag := New().PersistentFlags().Lookup("osc-progress"); flag == nil || flag.DefValue != "auto" {
		t.Fatal("OSC selection must default to auto")
	}
	if _, _, err := runCLI(t, context.Background(), "find", "--osc-progress=invalid"); ExitCode(err) != 2 {
		t.Fatalf("invalid OSC mode must be a usage error: %v", err)
	}
	root := condaRoot(t)
	for _, test := range []struct{ mode, format, reason string }{
		{"7501", "json", "json"}, {"94", "text", "non-terminal"}, {"none", "json", "disabled"},
	} {
		stdout, stderr, err := runCLI(t, context.Background(), "scan", root, "--osc-progress", test.mode,
			"--format", test.format, "--debug", "--output-dir", t.TempDir())
		if err != nil || !strings.Contains(stderr, "selected=none reason="+test.reason) || strings.Contains(stderr, "\x1b") ||
			test.format == "json" && !json.Valid([]byte(stdout)) {
			t.Fatalf("disabled diagnostics must leave reports unchanged: %v %q %q", err, stdout, stderr)
		}
	}
	_, stderr, err := runCLI(t, context.Background(), "lint", "--list-rules", "--debug")
	if err != nil || !strings.Contains(stderr, "reason=list-rules") || strings.Contains(stderr, "\x1b") {
		t.Fatalf("rule listing must not probe: %v %q", err, stderr)
	}
	_, stderr, err = runCLI(t, context.Background(), "find", root, "--debug", "--osc-progress", "auto")
	if err != nil || !strings.Contains(stderr, "reason=unsupported-command") || strings.Contains(stderr, "\x1b") {
		t.Fatalf("discovery must not select or probe a terminal status protocol: %v %q", err, stderr)
	}
}
