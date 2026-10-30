package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestErrorContractExitCodeAndPrintPolicy pins the exit status and stderr policy
// for each error shape. The first commandExit found by errors.As decides both
// the code and the silence, while cancellation always wins the code.
func TestErrorContractExitCodeAndPrintPolicy(t *testing.T) {
	cause := errors.New("cause")
	cases := []struct {
		name  string
		err   error
		code  int
		print bool
	}{
		{"nil", nil, 0, false},
		{"plain", cause, 1, true},
		{"canceled", context.Canceled, 130, true},
		{"deadline", context.DeadlineExceeded, 1, true},
		{"input", inputError(cause), 2, true},
		{"outerInputOverSilent", inputError(&commandExit{code: 1, err: cause, silent: true}), 2, true},
		{"explicitZeroPrintable", &commandExit{code: 0, err: cause}, 0, true},
		{"silentOne", &commandExit{code: 1, silent: true}, 1, false},
		{"silentTwo", &commandExit{code: 2, silent: true}, 2, false},
		{"wrappedSilent", fmt.Errorf("wrapped: %w", &commandExit{code: 1, silent: true}), 1, false},
		{"silentFirstJoin", errors.Join(&commandExit{code: 1, silent: true}, inputError(cause)), 1, false},
		{"printableFirstJoin", errors.Join(inputError(cause), &commandExit{code: 1, silent: true}), 2, true},
		{"cancelAcrossPrintableJoin", errors.Join(inputError(cause), context.Canceled), 130, true},
		{"cancelAcrossSilentJoin", errors.Join(context.Canceled, &commandExit{code: 1, silent: true}), 130, false},
		{"silentCancel", &commandExit{code: 130, err: context.Canceled, silent: true}, 130, false},
		{"wrappedSilentCancel", fmt.Errorf("stop: %w", &commandExit{code: 130, err: context.Canceled, silent: true}), 130, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.err); got != tc.code {
				t.Fatalf("ExitCode = %d, want %d", got, tc.code)
			}
			if got := ShouldPrintError(tc.err); got != tc.print {
				t.Fatalf("ShouldPrintError = %t, want %t", got, tc.print)
			}
		})
	}
}

// TestErrorContractKeepsSentinelIdentity checks that wrapping keeps the original
// sentinel reachable through errors.Is, for both printable and silent exits.
func TestErrorContractKeepsSentinelIdentity(t *testing.T) {
	sentinel := errors.New("sentinel")
	printable := inputError(fmt.Errorf("write: %w", sentinel))
	if !errors.Is(printable, sentinel) || ExitCode(printable) != 2 || !ShouldPrintError(printable) {
		t.Fatalf("printable exit lost sentinel or print state: %v", printable)
	}
	silent := &commandExit{code: 1, err: sentinel, silent: true}
	if !errors.Is(silent, sentinel) || ExitCode(silent) != 1 || ShouldPrintError(silent) {
		t.Fatalf("silent exit lost sentinel or print state: %v", silent)
	}
}

// TestErrorContractPreCanceledDirectoryCommands runs find, scan and lint on an
// empty directory with a cancelled context. Each exits 130; only lint is silent,
// and scan/lint JSON remains valid while an empty find has no report.
func TestErrorContractPreCanceledDirectoryCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, command := range []string{"find", "scan", "lint"} {
		for _, format := range []string{"text", "json"} {
			t.Run(command+"/"+format, func(t *testing.T) {
				root := t.TempDir()
				sboms := filepath.Join(t.TempDir(), "sboms")
				args := []string{command, "--format", format, root}
				if command == "scan" {
					args = []string{command, "--format", format, "--output-dir", sboms, root}
				}
				stdout, stderr, err := runCLI(t, ctx, args...)
				if ExitCode(err) != 130 || !errors.Is(err, context.Canceled) {
					t.Fatalf("ExitCode = %d, want 130: %v", ExitCode(err), err)
				}
				if ShouldPrintError(err) != (command != "lint") {
					t.Fatalf("ShouldPrintError = %t for %s: %v", ShouldPrintError(err), command, err)
				}
				if stderr != "" {
					t.Fatalf("command must return its error, not print it twice: %q", stderr)
				}
				// An empty find walk has no partial evidence, so it returns the error alone.
				if command == "find" && stdout != "" {
					t.Fatalf("cancelled find with no evidence wrote stdout: %q", stdout)
				}
				if format == "json" && command != "find" && !json.Valid([]byte(stdout)) {
					t.Fatalf("cancelled %s JSON is not valid: %q", command, stdout)
				}
				if entries, _ := os.ReadDir(sboms); command == "scan" && len(entries) != 0 {
					t.Fatalf("cancelled scan wrote %d SBOM entries", len(entries))
				}
			})
		}
	}
}

// TestErrorContractStdoutWriteFailureIsReported fails the first stdout write on
// an empty directory. Find and scan exit 1; lint reports the output failure as
// exit 2. Each keeps the sentinel and marks it printable by the entry point.
func TestErrorContractStdoutWriteFailureIsReported(t *testing.T) {
	sentinel := errors.New("stdout closed")
	cases := []struct {
		command, format string
		code            int
	}{
		{"find", "text", 1}, {"find", "json", 1},
		{"scan", "text", 1}, {"scan", "json", 1},
		{"lint", "text", 2}, {"lint", "json", 2},
	}
	for _, tc := range cases {
		t.Run(tc.command+"/"+tc.format, func(t *testing.T) {
			root := t.TempDir()
			cmd := New()
			cmd.SetOut(&failAfterWriter{limit: 0, err: sentinel})
			var stderr bytes.Buffer
			cmd.SetErr(&stderr)
			args := []string{tc.command, "--format", tc.format, root}
			if tc.command == "scan" {
				args = append(args, "--output-dir", filepath.Join(t.TempDir(), "sboms"))
			}
			cmd.SetArgs(args)
			err := cmd.ExecuteContext(context.Background())
			if ExitCode(err) != tc.code || !ShouldPrintError(err) || !errors.Is(err, sentinel) {
				t.Fatalf("ExitCode=%d print=%t sentinel=%t: %v", ExitCode(err), ShouldPrintError(err), errors.Is(err, sentinel), err)
			}
			if tc.command == "lint" && !strings.HasPrefix(err.Error(), "write lint output: ") {
				t.Fatalf("lint output failure prefix changed: %q", err.Error())
			}
			if stderr.Len() != 0 {
				t.Fatalf("write failure should not add stderr output: %q", stderr.String())
			}
		})
	}
}
