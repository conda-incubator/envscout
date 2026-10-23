package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/spf13/pflag"
)

// failAfterWriter accepts limit bytes then returns err on every later write.
type failAfterWriter struct {
	limit  int
	err    error
	writes int
	buf    bytes.Buffer
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.buf.Len() >= w.limit {
		return 0, w.err
	}
	n, err := w.buf.Write(p)
	if err != nil {
		return n, err
	}
	return n, nil
}

// zeroWriter reports zero bytes written with no error, forcing a short write.
type zeroWriter struct{}

func (zeroWriter) Write(p []byte) (int, error) { return 0, nil }

func TestPrinterSuccessWritesFormattedOutput(t *testing.T) {
	var buf bytes.Buffer
	p := newPrinter(&buf)
	p.Printf("name=%s n=%d\n", "env", 3)
	p.Println("a", 1, true)
	if err := p.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	if got, want := buf.String(), "name=env n=3\na 1 true\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestPrinterStickyErrorPreservesIdentityAndStopsWriting(t *testing.T) {
	sentinel := errors.New("disk full")
	w := &failAfterWriter{limit: 0, err: sentinel}
	p := newPrinter(w)
	p.Printf("first\n")
	if !errors.Is(p.Err(), sentinel) {
		t.Fatalf("Err() = %v, want errors.Is sentinel", p.Err())
	}
	writesAfterFailure := w.writes
	p.Printf("second\n")
	p.Println("third")
	if w.writes != writesAfterFailure {
		t.Fatalf("writer called %d more time(s) after sticky error", w.writes-writesAfterFailure)
	}
	if !errors.Is(p.Err(), sentinel) {
		t.Fatalf("Err() changed after sticky error: %v", p.Err())
	}
}

func TestPrinterShortWriteReportsErrShortWrite(t *testing.T) {
	p := newPrinter(zeroWriter{})
	p.Printf("data")
	if !errors.Is(p.Err(), io.ErrShortWrite) {
		t.Fatalf("Err() = %v, want io.ErrShortWrite", p.Err())
	}
}

func TestPrinterNoPanicOnWriterError(t *testing.T) {
	sentinel := errors.New("closed")
	p := newPrinter(&failAfterWriter{limit: 0, err: sentinel})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("printer panicked: %v", r)
		}
	}()
	p.Println("x")
	p.Printf("%d", 1)
}

func TestEncodeJSONIndentsWithTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	value := map[string]any{"name": "env", "items": []int{1, 2}}
	if err := encodeJSON(&buf, value); err != nil {
		t.Fatalf("encodeJSON error = %v", err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "}\n") {
		t.Fatalf("output %q lacks trailing newline", out)
	}
	if !strings.Contains(out, "\n  \"items\": [") {
		t.Fatalf("output %q is not indented with two spaces", out)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
	if decoded["name"] != "env" {
		t.Fatalf("decoded name = %v, want env", decoded["name"])
	}
}

func TestEncodeJSONPropagatesWriterError(t *testing.T) {
	sentinel := errors.New("write failed")
	err := encodeJSON(&failAfterWriter{limit: 0, err: sentinel}, map[string]int{"a": 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("encodeJSON error = %v, want sentinel", err)
	}
}

func TestEnumValueAcceptsChoicesAndKeepsDefault(t *testing.T) {
	target := "text"
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Var(newEnumValue(&target, "text", "json"), "format", "output format")
	if target != "text" {
		t.Fatalf("default changed before parsing: %q", target)
	}
	if err := fs.Parse([]string{"--format", "json"}); err != nil {
		t.Fatalf("Parse(json) error = %v", err)
	}
	if target != "json" {
		t.Fatalf("target = %q, want json", target)
	}
}

func TestEnumValueDefaultUsedWhenFlagAbsent(t *testing.T) {
	target := "text"
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Var(newEnumValue(&target, "text", "json"), "format", "output format")
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if target != "text" {
		t.Fatalf("target = %q, want default text", target)
	}
}

func TestEnumValueRejectsInvalidAndLeavesTarget(t *testing.T) {
	target := "text"
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(newEnumValue(&target, "text", "json"), "format", "output format")
	err := fs.Parse([]string{"--format", "yaml"})
	if err == nil {
		t.Fatal("Parse(yaml) error = nil, want error")
	}
	if !strings.Contains(err.Error(), "text, json") {
		t.Fatalf("error %q does not list allowed values", err)
	}
	if target != "text" {
		t.Fatalf("target mutated on invalid input: %q", target)
	}
}

func TestEnumValueStringAndType(t *testing.T) {
	target := "json"
	v := newEnumValue(&target, "text", "json")
	if got := v.String(); got != "json" {
		t.Fatalf("String() = %q, want json", got)
	}
	if got := v.Type(); got != "string" {
		t.Fatalf("Type() = %q, want string", got)
	}
}

func TestColourDisabledOnBufferWriter(t *testing.T) {
	var buf bytes.Buffer
	got := colour(&buf, false, "red", color.FgRed)
	if got != "red" {
		t.Fatalf("colour on buffer = %q, want plain text", got)
	}
}

func TestColourDisabledByExplicitNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if got := colour(&bytes.Buffer{}, true, "red", color.FgRed); got != "red" {
		t.Fatalf("colour with noColor = %q, want plain text", got)
	}
}

func TestColourDisabledByNoColorEnvEvenForTerminalWriter(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if got := colour(&bytes.Buffer{}, false, "red", color.FgRed); strings.Contains(got, "\x1b[") {
		t.Fatalf("colour with NO_COLOR = %q, want no ANSI", got)
	}
}

func TestColourTextWithFormatDirectivesIsNotInterpreted(t *testing.T) {
	var buf bytes.Buffer
	got := colour(&buf, true, "100%s %d", color.FgGreen)
	if got != "100%s %d" {
		t.Fatalf("colour = %q, want literal text", got)
	}
}

func TestColourDoesNotMutateGlobalNoColor(t *testing.T) {
	before := color.NoColor
	colour(&bytes.Buffer{}, true, "x", color.FgRed)
	colour(&bytes.Buffer{}, false, "x", color.FgRed)
	if color.NoColor != before {
		t.Fatalf("color.NoColor mutated from %v to %v", before, color.NoColor)
	}
}
