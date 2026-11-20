package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// streamReader yields pattern cyclically until total bytes have been produced. It lets the
// bound tests reach the exact 16 MiB limit without materialising the history in memory.
type streamReader struct {
	pattern []byte
	total   int
	pos     int
}

func (s *streamReader) Read(p []byte) (int, error) {
	if s.pos >= s.total {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && s.pos < s.total {
		p[n] = s.pattern[s.pos%len(s.pattern)]
		n++
		s.pos++
	}
	return n, nil
}

// errAfterReader returns its data and then err instead of io.EOF.
func errAfterReader(data string, err error) io.Reader {
	return io.MultiReader(strings.NewReader(data), iotest.ErrReader(err))
}

// cancelOnReadReader cancels the context during the read that returns its data, so the
// caller decides whether the scanner ever observes the cancellation.
type cancelOnReadReader struct {
	data    string
	cancel  context.CancelFunc
	withEOF bool
	done    bool
}

func (c *cancelOnReadReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	c.done = true
	c.cancel()
	n := copy(p, c.data)
	if c.withEOF {
		return n, io.EOF
	}
	return n, nil
}

func TestHistoryContractRevisionGrammar(t *testing.T) {
	tests := []struct {
		name string
		data string
		want *int
	}{
		// nil: no counted header
		{"empty input", "", nil},
		{"headerless comment", "# cmd: conda create\n", nil},
		{"empty marker pair", "==> <==\n", nil},
		{"spaces-only body", "==>   <==\n", nil},
		{"first terminator at position zero", "==> <== a <==\n", nil},
		{"missing terminator", "==> 2026-01-01 00:00:00\n", nil},
		{"terminator without arrow prefix", "== a <==\n", nil},
		{"wrong opening marker", "=> a <==\n", nil},
		{"reversed markers", "<== a ==>\n", nil},
		{"wrong closing marker", "==> a <=>\n", nil},
		{"unicode whitespace only body", "==>\u2003<==\n", nil},
		{"header without trailing newline but empty body", "==> <==", nil},
		{"non-breaking space only body", "==>\u00a0<==\n", nil},

		// zero: one counted header
		{"minimal header", "==> a <==\n", intPtr(0)},
		{"header without trailing newline", "==> a <==", intPtr(0)},
		{"crlf line ending", "==> a <==\r\n", intPtr(0)},
		{"no spaces inside markers", "==>a<==\n", intPtr(0)},
		{"leading ascii whitespace trimmed", " \t==> a <==\n", intPtr(0)},
		{"leading unicode whitespace trimmed", "\u00a0==>\u00a0x\u00a0<==\u00a0\n", intPtr(0)},
		{"trailing text after terminator", "==> a <== trailing\n", intPtr(0)},
		{"second terminator ignored", "==> a <== b <==\n", intPtr(0)},
		{"date body", "==> 2026-01-01 00:00:00 <==\n", intPtr(0)},
		{"uppercase body", "==> ALPHA <==\n", intPtr(0)},

		// counts: latest index is count-1
		{"two headers", "==> a <==\n==> b <==\n", intPtr(1)},
		{"three headers with headerless noise", "# x\n==> a <==\nnoise\n==> b <==\n==> c <==\n", intPtr(2)},
		{"empty-body header still counted", "==> a <==\n==> <==\n==> c <==\n", intPtr(1)},
		{"empty-body headers alone", "==> <==\n==> <==\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mode := range []struct {
				name string
				r    io.Reader
			}{
				{"direct", strings.NewReader(tt.data)},
				{"one byte per read", iotest.OneByteReader(strings.NewReader(tt.data))},
			} {
				got, err := parseHistoryRevision(mode.r)
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", mode.name, err)
				}
				if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
					t.Fatalf("%s: revision = %v; want %v", mode.name, fmtRevision(got), fmtRevision(tt.want))
				}
			}
		})
	}
}

func fmtRevision(p *int) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprint(*p)
}

func TestHistoryContractReaderErrorsDiscardCounts(t *testing.T) {
	boom := io.ErrUnexpectedEOF
	got, err := parseHistoryRevision(errAfterReader("==> a <==\n==> b <==\n", boom))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v; want %v", err, boom)
	}
	if got != nil {
		t.Fatalf("revision after reader error = %d; want nil", *got)
	}
}

func TestHistoryContractTokenLimit(t *testing.T) {
	t.Run("oversized line discards earlier counts", func(t *testing.T) {
		data := "==> a <==\n==> b <==\n" + strings.Repeat("x", maxMetadataBytes+1)
		got, err := parseHistoryRevision(strings.NewReader(data))
		if !errors.Is(err, bufio.ErrTooLong) {
			t.Fatalf("err = %v; want %v", err, bufio.ErrTooLong)
		}
		if err.Error() != "bufio.Scanner: token too long" {
			t.Fatalf("error text = %q", err.Error())
		}
		if got != nil {
			t.Fatalf("revision = %d; want nil", *got)
		}
	})
	t.Run("line below limit is accepted", func(t *testing.T) {
		line := "==> a <==" + strings.Repeat(" ", maxMetadataBytes-len("==> a <==")-1)
		got, err := parseHistoryRevision(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || *got != 0 {
			t.Fatalf("revision = %s; want 0", fmtRevision(got))
		}
	})
}

func TestHistoryContractCancellation(t *testing.T) {
	t.Run("pre-cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := parseHistoryRevision(contextReader{ctx: ctx, r: strings.NewReader("==> a <==\n")})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v; want context.Canceled", err)
		}
		if got != nil {
			t.Fatalf("revision = %d; want nil", *got)
		}
	})
	t.Run("cancelled during data read before EOF", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := &cancelOnReadReader{data: "==> a <==\n", cancel: cancel}
		got, err := parseHistoryRevision(contextReader{ctx: ctx, r: r})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v; want context.Canceled", err)
		}
		if got != nil {
			t.Fatalf("revision = %d; want nil", *got)
		}
	})
	t.Run("cancelled with final data and EOF keeps the count", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r := &cancelOnReadReader{data: "==> a <==\n", cancel: cancel, withEOF: true}
		got, err := parseHistoryRevision(contextReader{ctx: ctx, r: r})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || *got != 0 {
			t.Fatalf("revision = %s; want 0", fmtRevision(got))
		}
	})
}

func TestHistoryContractByteBound(t *testing.T) {
	header := []byte("==> a <==\n")
	t.Run("exactly maxHistoryBytes is accepted", func(t *testing.T) {
		r := &streamReader{pattern: header, total: maxHistoryBytes}
		got, err := boundedHistoryRevision(context.Background(), r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 16 MiB holds floor(maxHistoryBytes/len(header)) complete headers; the trailing
		// partial line has no terminator and is not counted.
		want := maxHistoryBytes/len(header) - 1
		if got == nil || *got != want {
			t.Fatalf("revision = %s; want %d", fmtRevision(got), want)
		}
	})
	t.Run("one byte over maxHistoryBytes is rejected", func(t *testing.T) {
		r := &streamReader{pattern: header, total: maxHistoryBytes + 1}
		got, err := boundedHistoryRevision(context.Background(), r)
		want := fmt.Sprintf("history exceeds %d bytes", maxHistoryBytes)
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v; want %q", err, want)
		}
		if got != nil {
			t.Fatalf("revision = %d; want nil", *got)
		}
	})
}
