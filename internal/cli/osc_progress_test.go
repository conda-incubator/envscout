package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/buildkite/osc7501"
)

func awaitOSCText(t *testing.T, w *ackWriter, text string) {
	t.Helper()
	for !strings.Contains(w.String(), text) {
		w.awaitFrame(t)
	}
}

func TestOSCProgressDiscoveryAndCompletion(t *testing.T) {
	w := newAckWriter()
	o, _ := oscFixture("7501", w)
	tick := make(chan time.Time)
	cfg := scanCfg(tick, newFakeClock())
	cfg.osc = o
	_, discovery, counts, stop := startScanProgressCore(context.Background(), w, cfg)
	t.Cleanup(func() { _ = stop() })
	discovery.Folders.Store(17)
	tick <- time.Time{}
	awaitOSCText(t, w, "Folders scanned: 17")
	if strings.Contains(w.String(), "]7501;") || strings.Contains(w.String(), "]9;4;") {
		t.Fatal("discovery must remain text-only")
	}
	counts.Total.Store(4)
	counts.Finished.Store(2)
	counts.Failed.Store(1)
	counts.PreExisting.Store(1)
	counts.Started.Store(true)
	tick <- time.Time{}
	awaitOSCText(t, w, "2/4 finished")
	working := string(osc7501.Report{State: "working", ID: "envscout/scan", Progress: 50, App: "envscout", Msg: "scan environments"}.Encode())
	if !strings.Contains(w.String(), working) {
		t.Fatal("failed and pre-existing attempts must count toward completed percentage")
	}
	if err := stop(); err != nil || strings.Contains(w.String(), "state=done") {
		t.Fatalf("renderer stop must not finalize the command: %v %q", err, w.String())
	}
	if err := o.finish(nil); err != nil || !strings.Contains(w.String(), "state=done") {
		t.Fatalf("command finalization must report done: %v %q", err, w.String())
	}
}

func TestOSCFastLintFinalOutcome(t *testing.T) {
	for _, test := range []struct {
		err   error
		state string
	}{{nil, "done"}, {&commandExit{code: 1, silent: true}, "error"}, {context.Canceled, "idle"}} {
		var out bytes.Buffer
		o, _ := oscFixture("7501", &out)
		o.operation = "lint"
		cfg := scanCfg(make(chan time.Time), newFakeClock())
		cfg.osc = o
		_, _, counts, stop := startLintProgressCore(context.Background(), &out, cfg)
		counts.Total.Store(1)
		counts.Finished.Store(1)
		counts.Started.Store(true)
		if err := stop(); err != nil || !strings.Contains(out.String(), "progress=100") || strings.Contains(out.String(), "state=done") {
			t.Fatalf("fast operation must be sampled only as work until final result: %v %q", err, out.String())
		}
		if err := o.finish(test.err); err != nil || !strings.Contains(out.String(), "state="+test.state) {
			t.Fatalf("final command state: %v %q", err, out.String())
		}
	}
}

func TestOSCNoneKeepsTextAndNoWorkExplained(t *testing.T) {
	for _, total := range []uint64{0, 4} {
		w := newAckWriter()
		o, _ := oscFixture("none", w)
		o.debug = true
		cfg := scanCfg(make(chan time.Time), newFakeClock())
		cfg.osc = o
		_, _, counts, stop := startScanProgressCore(context.Background(), w, cfg)
		counts.Total.Store(total)
		counts.Started.Store(true)
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if err := o.finish(nil); err != nil || strings.Contains(w.String(), "\x1b]") || !strings.Contains(w.String(), "selected=none") {
			t.Fatalf("none/zero work must remain silent except debug: %v %q", err, w.String())
		}
	}
}

func TestOSCProgressWriteErrorRemainsSticky(t *testing.T) {
	writeErr := errors.New("terminal closed")
	w := &failWriter{allowed: 0, err: writeErr}
	o, _ := oscFixture("7501", w)
	tick := make(chan time.Time)
	cfg := scanCfg(tick, newFakeClock())
	cfg.osc = o
	_, _, counts, stop := startScanProgressCore(context.Background(), w, cfg)
	counts.Total.Store(4)
	counts.Started.Store(true)
	tick <- time.Time{}
	if !errors.Is(stop(), writeErr) || !errors.Is(o.finish(nil), writeErr) {
		t.Fatal("renderer and OSC finalization must preserve the first write error")
	}
}
