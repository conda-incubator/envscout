package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/bits"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/buildkite/osc7501"
	"github.com/spf13/cobra"
)

const oscProbeTimeout = 100 * time.Millisecond
const oscQuery = osc7501.Query + "\x1b[c"

type oscKey struct{}

// Only the renderer owns this state until it stops; command finalization follows it.
type oscProgress struct {
	ctx                 context.Context
	input               *os.File
	out                 io.Writer
	operation           string
	requested, selected string
	debug, resolved     bool
	active, finished    bool
	lastPercent         int
	printer             *printer
	probe               func(context.Context, *os.File, *os.File) (bool, string, error)
}

func newOSCProgress(cmd *cobra.Command, opts *commandOptions) (*oscProgress, error) {
	o := &oscProgress{ctx: cmd.Context(), out: cmd.ErrOrStderr(), operation: cmd.Name(),
		requested: opts.oscProgress, debug: opts.debug, lastPercent: -1, probe: probeOSC7501}
	o.input, _ = cmd.InOrStdin().(*os.File)
	reason := ""
	switch {
	case o.requested == "none":
		reason = "disabled"
	case cmd.Name() != "scan" && cmd.Name() != "lint":
		reason = "unsupported-command"
	case cmd.Name() == "lint" && cmd.Flags().Lookup("list-rules").Value.String() == "true":
		reason = "list-rules"
	case opts.source != "dir":
		reason = "unsupported-source"
	case opts.format != "text":
		reason = "json"
	case !isTerminal(o.out):
		reason = "non-terminal"
	case os.Getenv("TERM") == "dumb":
		reason = "dumb-terminal"
	case o.ctx.Err() != nil:
		reason = "canceled"
	}
	if reason != "" {
		o.selected, o.resolved = "none", true
		p := newPrinter(o.out)
		o.diagnostic(p, "reason", reason)
		return o, p.Err()
	}
	return o, nil
}

func oscFrom(ctx context.Context) *oscProgress {
	o, _ := ctx.Value(oscKey{}).(*oscProgress)
	return o
}

func (o *oscProgress) diagnostic(p *printer, key, reason string) {
	if o.debug {
		p.Printf("debug: osc-progress requested=%s selected=%s %s=%s\n", o.requested, o.selected, key, reason)
	}
}

func (o *oscProgress) update(p *printer, started bool, completed, total uint64) {
	if o == nil {
		return
	}
	o.printer = p
	if !started || total == 0 || o.finished || p.Err() != nil {
		return
	}
	if !o.resolved {
		o.selected, o.resolved = o.requested, true
		reason := "skipped-explicit"
		if o.requested == "auto" {
			o.selected, reason = "94", "unavailable-input"
			out, ok := o.out.(*os.File)
			if o.ctx.Err() != nil {
				o.selected, reason = "none", "canceled"
			} else if ok && o.input != nil && isTerminal(o.input) {
				supported, result, err := o.probe(o.ctx, o.input, out)
				reason = result
				if err != nil {
					o.selected = "none"
					if o.debug {
						p.write(progressClear)
					}
					o.diagnostic(p, "probe", reason)
					if err == o.ctx.Err() {
						return // The command owns cancellation, not the sticky output error.
					}
					p.err = err
					return
				}
				if supported {
					o.selected = "7501"
				}
			}
		}
		if o.debug {
			p.write(progressClear)
			o.diagnostic(p, "probe", reason)
		}
	}
	if o.selected == "none" {
		return
	}
	// The total is fixed after discovery. Count attempts, not timing samples or bytes.
	hi, lo := bits.Mul64(min(completed, total), 100)
	value, _ := bits.Div64(hi, lo, total)
	percent := max(o.lastPercent, int(value))
	if percent == o.lastPercent {
		return
	}
	o.active, o.lastPercent = true, percent
	if o.selected == "7501" {
		p.write(string(osc7501.Report{State: osc7501.StateWorking, ID: "envscout/" + o.operation,
			App: "envscout", Progress: percent, Msg: o.operation + " environments"}.Encode()))
	} else {
		p.Printf("\x1b]9;4;1;%d\x07", percent)
	}
}

func (o *oscProgress) finish(commandErr error) error {
	if o == nil || o.finished {
		return nil
	}
	o.finished = true
	p := o.printer
	if p == nil {
		p = newPrinter(o.out)
	}
	if !o.resolved {
		o.selected, o.resolved = "none", true
		o.diagnostic(p, "reason", "no-known-work")
	}
	if o.active {
		if o.selected == "94" {
			p.write("\x1b]9;4;0;0\x07")
		} else {
			state, message := osc7501.StateDone, o.operation+" complete"
			if errors.Is(commandErr, context.Canceled) {
				state, message = osc7501.StateIdle, ""
			} else if commandErr != nil {
				state, message = osc7501.StateError, o.operation+" failed"
			}
			p.write(string(osc7501.Report{State: state, ID: "envscout/" + o.operation,
				App: "envscout", Progress: -1, Msg: message}.Encode()))
		}
	}
	if p.Err() != nil && errors.Is(commandErr, p.Err()) {
		return nil // Renderer shutdown already propagated this same sticky error.
	}
	return p.Err()
}

// Recognize framed replies, not reports or echoed queries. A DA reply ends probing.
func interpretOSCReply(data []byte) (supported, finished bool) {
	for len(data) > 0 {
		start := bytes.IndexByte(data, '\x1b')
		if start < 0 {
			return supported, false
		}
		data = data[start:]
		if bytes.HasPrefix(data, []byte("\x1b[?")) {
			end := -1
			for i := 3; i < len(data); i++ {
				if data[i] >= 0x40 && data[i] <= 0x7e {
					if data[i] == 'c' {
						return supported, true
					}
					end = i + 1
					break
				}
			}
			if end < 0 {
				return supported, false
			}
			data = data[end:]
			continue
		}
		if !bytes.HasPrefix(data, []byte("\x1b]7501;")) {
			data = data[1:]
			continue
		}
		body := data[len("\x1b]7501;"):]
		end, size := bytes.Index(body, []byte("\x1b\\")), 2
		if bell := bytes.IndexByte(body, '\x07'); bell >= 0 && (end < 0 || bell < end) {
			end, size = bell, 1
		}
		if end < 0 {
			return supported, false
		}
		text := string(body[:end])
		data = body[end+size:]
		if !strings.HasPrefix(text, "?:") {
			continue
		}
		states := []string{"idle", "working", "done", "blocked", "error"}
		valid := true
		for _, pair := range strings.Split(text[2:], ":") {
			key, value, ok := strings.Cut(pair, "=")
			if !ok || key == "" {
				valid = false
				break
			}
			for _, char := range key {
				valid = valid && char >= 'a' && char <= 'z'
			}
			for _, char := range value {
				valid = valid && (char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
					char >= '0' && char <= '9' || strings.ContainsRune("_.,+/=-", char))
			}
			if key == "states" {
				states = strings.Split(value, ",")
			}
		}
		if !valid {
			continue
		}
		supported = supported || slices.Contains(states, "working") && slices.Contains(states, "done") &&
			slices.Contains(states, "error") && slices.Contains(states, "idle")
	}
	return supported, false
}
