package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/fatih/color"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// operationTimeout bounds one image or lint operation. Directory find and scan
// are unbounded and use the caller's context directly.
const operationTimeout = 5 * time.Minute

// commandExit carries an explicit exit code. Silent errors were already rendered
// on stdout, so the caller must not print them again.
type commandExit struct {
	code   int
	err    error
	silent bool
}

func (e *commandExit) Error() string {
	if e.err != nil {
		return safeText(e.err.Error())
	}
	return "lint policy threshold exceeded"
}

func (e *commandExit) Unwrap() error { return e.err }

// inputError marks a usage, configuration or flag failure, which exits 2.
func inputError(err error) error { return &commandExit{code: 2, err: err} }

// ExitCode maps a command error to a process status. Cancellation wins even when
// wrapped in a commandExit, so 130 holds regardless of how the error was joined.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	var exit *commandExit
	if errors.As(err, &exit) {
		return exit.code
	}
	return 1
}

// ShouldPrintError reports whether the error text still needs to be written to stderr.
func ShouldPrintError(err error) bool {
	var exit *commandExit
	return err != nil && (!errors.As(err, &exit) || !exit.silent)
}

// operationContext applies the per-operation timeout beneath the caller's context.
func operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, operationTimeout)
}

// printer writes formatted output and remembers the first write error. Every
// write goes through write, so once an error is recorded nothing more is sent.
type printer struct {
	out io.Writer
	err error
}

func newPrinter(out io.Writer) *printer {
	return &printer{out: out}
}

// write is the single sticky write path. A silent short write becomes io.ErrShortWrite.
func (p *printer) write(data string) {
	if p.err != nil {
		return
	}
	n, err := io.WriteString(p.out, data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	p.err = err
}

// Printf formats according to format and writes the result.
func (p *printer) Printf(format string, args ...any) {
	p.write(fmt.Sprintf(format, args...))
}

// Println writes args separated by spaces followed by a newline.
func (p *printer) Println(args ...any) {
	p.write(fmt.Sprintln(args...))
}

// Err returns the first write error encountered, or nil.
func (p *printer) Err() error {
	return p.err
}

// renderIssues writes one warning line per discovery issue.
func renderIssues(p *printer, prefix string, issues []discovery.Issue) {
	for _, issue := range issues {
		p.Printf("warning: %s%s: %s\n", prefix, safeText(issue.Path), safeText(issue.Error))
	}
}

// encodeJSON writes value as indented JSON with a trailing newline.
func encodeJSON(out io.Writer, value any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

// enumValue implements pflag.Value for a fixed set of string choices.
type enumValue struct {
	target  *string
	choices []string
}

func newEnumValue(target *string, choices ...string) *enumValue {
	return &enumValue{target: target, choices: choices}
}

func (e *enumValue) String() string { return *e.target }

// Set assigns value only when it is one of the allowed choices.
func (e *enumValue) Set(value string) error {
	for _, choice := range e.choices {
		if value == choice {
			*e.target = value
			return nil
		}
	}
	return fmt.Errorf("must be one of %s, got %q", strings.Join(e.choices, ", "), value)
}

func (e *enumValue) Type() string { return "string" }

var _ pflag.Value = (*enumValue)(nil)

// colour renders text with attrs for out. Colour is disabled when noColor is set,
// NO_COLOR is non-empty, or out is not a terminal. Global color state is never mutated.
func colour(out io.Writer, noColor bool, text string, attrs ...color.Attribute) string {
	c := color.New(attrs...)
	if noColor || os.Getenv("NO_COLOR") != "" || !isTerminal(out) {
		c.DisableColor()
	} else {
		c.EnableColor()
	}
	return c.Sprint(text)
}

// isTerminal reports whether writer is an operating-system terminal file.
func isTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

// safeText quotes control characters so untrusted paths and messages cannot alter a terminal.
func safeText(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return strconv.QuoteToASCII(s)
	}
	return s
}
