//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func answerOSCQuery(master, slave *os.File, reply string, cancel context.CancelFunc) error {
	deadline := time.Now().Add(5 * time.Second)
	var query []byte
	for len(query) < len(oscQuery) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("OSC query was not written")
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}, max(1, int(remaining/time.Millisecond)))
		if err != nil || ready == 0 {
			return fmt.Errorf("OSC query read: %v", err)
		}
		var char [1]byte
		n, err := unix.Read(int(master.Fd()), char[:])
		if err != nil || n == 0 {
			return fmt.Errorf("OSC query read: %v", err)
		}
		query = append(query, char[0])
	}
	if string(query) != oscQuery {
		return fmt.Errorf("query=%q, want %q", query, oscQuery)
	}
	raw, err := slave.SyscallConn()
	if err != nil {
		return err
	}
	var mode *unix.Termios
	if controlErr := raw.Control(func(fd uintptr) { mode, err = unix.IoctlGetTermios(int(fd), oscTermiosGet) }); controlErr != nil {
		return controlErr
	}
	if err != nil {
		return err
	}
	if mode.Lflag&(unix.ICANON|unix.ECHO) != 0 || mode.Lflag&unix.ISIG == 0 || mode.Oflag&unix.OPOST == 0 {
		return fmt.Errorf("probe must disable line/echo input but preserve signals and output: %+v", mode)
	}
	if cancel != nil {
		cancel()
	}
	_, err = io.WriteString(master, reply)
	return err
}

func TestOSCProbeReplyAndTerminalRestoration(t *testing.T) {
	const reply = "\x1b]7501;?:states=idle,working,done,error\x1b\\"
	const da = "\x1b[?62;1c"
	for _, test := range []struct {
		name, reply, reason string
		supported, canceled bool
	}{
		{"supported", reply + da, "supported", true, false},
		{"unsupported", da, "unsupported", false, false},
		{"no reply", "", "timeout", false, false},
		{"supported without DA", reply, "supported", true, false},
		{"malformed", "\x1b]7501;?:malformed\x07" + da, "unsupported", false, false},
		{"echoed query", oscQuery + da, "unsupported", false, false},
		{"canceled after query", "", "canceled", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			master, slave := progressPTY(t)
			before, err := unix.IoctlGetTermios(int(slave.Fd()), oscTermiosGet)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var onQuery context.CancelFunc
			if test.canceled {
				onQuery = cancel
			}
			answered := make(chan error, 1)
			go func() { answered <- answerOSCQuery(master, slave, test.reply, onQuery) }()
			started := time.Now()
			supported, reason, err := probeOSC7501(ctx, slave, slave)
			if answerErr := <-answered; answerErr != nil {
				t.Fatal(answerErr)
			}
			if supported != test.supported || reason != test.reason || test.canceled != errors.Is(err, context.Canceled) ||
				!test.canceled && err != nil || time.Since(started) > 2*time.Second {
				t.Fatalf("bounded probe=%t/%q/%v, want %t/%q", supported, reason, err, test.supported, test.reason)
			}
			after, err := unix.IoctlGetTermios(int(slave.Fd()), oscTermiosGet)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("terminal state was not restored: %v", err)
			}
		})
	}
}

func TestOSCProbeNeverConsumesPipedOrQueuedInput(t *testing.T) {
	master, slave := progressPTY(t)
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	if _, err := io.WriteString(writer, "payload"); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if supported, reason, err := probeOSC7501(context.Background(), input, slave); supported || reason != "unavailable-input" || err != nil {
		t.Fatalf("piped input probe=%t/%q/%v", supported, reason, err)
	}
	if payload, err := io.ReadAll(input); err != nil || string(payload) != "payload" {
		t.Fatal("probe consumed piped input")
	}
	if _, err := io.WriteString(master, "typed\n"); err != nil {
		t.Fatal(err)
	}
	ready, err := unix.Poll([]unix.PollFd{{Fd: int32(slave.Fd()), Events: unix.POLLIN}}, 5000)
	if err != nil || ready == 0 {
		t.Fatalf("queued input fixture unavailable: %v", err)
	}
	if supported, reason, err := probeOSC7501(context.Background(), slave, slave); supported || reason != "unavailable-input" || err != nil {
		t.Fatalf("queued input probe=%t/%q/%v", supported, reason, err)
	}
	var buffer [32]byte
	n, err := unix.Read(int(slave.Fd()), buffer[:])
	if err != nil || string(buffer[:n]) != "typed\n" {
		t.Fatal("probe consumed queued terminal input")
	}
}

func TestOSCAutoSelectsExactlyOneProtocol(t *testing.T) {
	t.Setenv("TERM", "xterm")
	for _, supported := range []bool{false, true} {
		master, slave := progressPTY(t)
		o, p := oscFixture("auto", slave)
		o.input, o.debug, o.probe = slave, true, probeOSC7501
		reply := "\x1b[?62;1c"
		if supported {
			reply = "\x1b]7501;?:states=idle,working,done,error\x07" + reply
		}
		answered := make(chan error, 1)
		go func() { answered <- answerOSCQuery(master, slave, reply, nil) }()
		o.update(p, true, 1, 4)
		if err := <-answered; err != nil {
			t.Fatal(err)
		}
		o.update(p, true, 2, 4) // Query must not repeat after selection.
		if err := o.finish(nil); err != nil {
			t.Fatal(err)
		}
		transcript := oscPTYTranscript(t, master, slave)
		if supported {
			if o.selected != "7501" || !strings.Contains(transcript, "probe=supported") || !strings.Contains(transcript, "state=done") || strings.Contains(transcript, "]9;4;") {
				t.Fatalf("7501 selection=%q transcript=%q", o.selected, transcript)
			}
		} else if o.selected != "94" || !strings.Contains(transcript, "probe=unsupported") || strings.Contains(transcript, "]7501;") || !strings.HasSuffix(transcript, "\x1b]9;4;0;0\x07") {
			t.Fatalf("fallback selection=%q transcript=%q", o.selected, transcript)
		}
	}
}

func TestOSCProbeEarlyCancelAndDifferentTerminalAreQuiet(t *testing.T) {
	master, slave := progressPTY(t)
	_, other := progressPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), oscTermiosGet)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if supported, reason, err := probeOSC7501(ctx, slave, slave); supported || reason != "canceled" || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled probe=%t/%q/%v", supported, reason, err)
	}
	if supported, reason, err := probeOSC7501(context.Background(), other, slave); supported || reason != "unavailable-input" || err != nil {
		t.Fatalf("different terminal probe=%t/%q/%v", supported, reason, err)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), oscTermiosGet)
	if err != nil || !reflect.DeepEqual(before, after) || oscPTYTranscript(t, master, slave) != "" {
		t.Fatal("ineligible probes must not touch output or terminal mode")
	}
}

func TestOSCProbeCancellationDoesNotPoisonOutput(t *testing.T) {
	master, slave := progressPTY(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o, p := oscFixture("auto", slave)
	o.input, o.ctx, o.probe = slave, ctx, probeOSC7501
	answered := make(chan error, 1)
	go func() { answered <- answerOSCQuery(master, slave, "", cancel) }()
	o.update(p, true, 1, 4)
	if err := <-answered; err != nil {
		t.Fatal(err)
	}
	if p.Err() != nil || o.active || o.selected != "none" || o.finish(context.Canceled) != nil {
		t.Fatalf("probe cancellation must stay a command cancellation, not a failed output writer: %+v", o)
	}
	if transcript := oscPTYTranscript(t, master, slave); transcript != "" {
		t.Fatalf("canceled probe emitted status: %q", transcript)
	}
}

func TestOSCProbePreservesPartialCanonicalLine(t *testing.T) {
	master, slave := progressPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), oscTermiosGet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(master, "typed"); err != nil {
		t.Fatal(err)
	}
	_, _, err = probeOSC7501(context.Background(), slave, slave)
	if err != nil {
		t.Fatal(err)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), oscTermiosGet)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("terminal state was not restored: %v", err)
	}
	if _, err := io.WriteString(master, "\n"); err != nil {
		t.Fatal(err)
	}
	// Linux can expose the old partial line and the later newline in separate
	// reads after ICANON is restored. Check preserved bytes, not read boundaries.
	const want = "typed\n"
	var buffer [len(want)]byte
	deadline := time.Now().Add(time.Second)
	for n := 0; n < len(buffer); {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("partial canonical line timed out after probe: %q", buffer[:n])
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(slave.Fd()), Events: unix.POLLIN}}, max(1, int(remaining/time.Millisecond)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || ready == 0 {
			t.Fatalf("partial canonical line unavailable after probe: %q, %v", buffer[:n], err)
		}
		read, err := unix.Read(int(slave.Fd()), buffer[n:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil || read == 0 {
			t.Fatalf("partial canonical line read after probe: %q, %v", buffer[:n], err)
		}
		n += read
	}
	if string(buffer[:]) != want {
		t.Fatalf("probe changed partial canonical input: %q", buffer[:])
	}
}

func TestOSCProbePreservesDescriptorFlags(t *testing.T) {
	master, slave := progressPTY(t)
	raw, err := slave.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var before, after int
	if controlErr := raw.Control(func(fd uintptr) {
		err = unix.SetNonblock(int(fd), true)
		if err == nil {
			before, err = unix.FcntlInt(fd, unix.F_GETFL, 0)
		}
	}); controlErr != nil || err != nil {
		t.Fatalf("nonblocking descriptor fixture failed: %v %v", controlErr, err)
	}
	if !isTerminal(slave) {
		t.Fatal("descriptor-safe terminal detection rejected the PTY")
	}
	_ = terminalWidth(slave)
	answered := make(chan error, 1)
	go func() { answered <- answerOSCQuery(master, slave, "\x1b[?62;1c", nil) }()
	_, _, err = probeOSC7501(context.Background(), slave, slave)
	if answerErr := <-answered; answerErr != nil || err != nil {
		t.Fatalf("descriptor preservation probe failed: %v %v", err, answerErr)
	}
	if controlErr := raw.Control(func(fd uintptr) { after, err = unix.FcntlInt(fd, unix.F_GETFL, 0) }); controlErr != nil || err != nil {
		t.Fatalf("reading restored descriptor flags failed: %v %v", controlErr, err)
	}
	// Darwin adds a kernel "was written" bit after the query. Compare the
	// user-settable flags, including nonblocking mode, rather than that bit.
	const flags = unix.O_NONBLOCK | unix.O_APPEND | unix.O_ASYNC | unix.O_SYNC
	if before&unix.O_NONBLOCK == 0 || before&flags != after&flags {
		t.Fatalf("probe changed descriptor flags: before=%#x after=%#x", before, after)
	}
}
