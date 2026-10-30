package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/inventory"
	"github.com/conda-incubator/envscout/internal/testimage"
)

// TestImageCommandPreCanceledOutput pins what a pre-canceled image run emits. Text
// output is suppressed entirely; JSON carries a structured failure report. Both exit
// 130, keep the error printable, and leave no SBOM artifacts behind.
func TestImageCommandPreCanceledOutput(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1", "0")},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		args []string
		json bool
	}{
		{"find text", []string{"find"}, false},
		{"scan text", []string{"scan"}, false},
		{"find json", []string{"find", "--format", "json"}, true},
		{"scan json", []string{"scan", "--format", "json"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workdir := t.TempDir()
			t.Chdir(workdir)
			args := append(tc.args, "--source", "oci-archive", "--platform", "linux/amd64", archive)
			stdout, stderr, err := runCLI(t, ctx, args...)
			if ExitCode(err) != 130 || !errors.Is(err, context.Canceled) || !ShouldPrintError(err) {
				t.Fatalf("exit %d, ShouldPrintError %v, err %v; want 130 printable canceled error", ExitCode(err), ShouldPrintError(err), err)
			}
			if stderr != "" {
				t.Fatalf("image cancellation must return its printable error without a second diagnostic: %q", stderr)
			}
			if !tc.json {
				if stdout != "" {
					t.Fatalf("text output must be suppressed on cancellation, got %q", stdout)
				}
			} else {
				var report inventory.ImageReport
				if err := json.Unmarshal([]byte(stdout), &report); err != nil {
					t.Fatalf("JSON failure report missing: %v: %q", err, stdout)
				}
				if report.Status != inventory.StatusIncomplete || !strings.Contains(report.Error, context.Canceled.Error()) {
					t.Fatalf("JSON must record incomplete status and cancellation: %s", stdout)
				}
			}
			if _, statErr := os.Stat(filepath.Join(workdir, "sboms")); !os.IsNotExist(statErr) {
				t.Fatal("pre-canceled image run produced SBOM artifacts")
			}
		})
	}
}

// TestImageCommandPartialHistoryKeepsIdentityAndIssues uses a conda-meta/history entry
// that is a symlink. Links are never followed for history, so the link is reported as
// an issue. The loaded image identity and the discovered prefix must survive, and the
// run must exit 1 with an incomplete summary.
func TestImageCommandPartialHistoryKeepsIdentityAndIssues(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1", "0")},
		{Name: "env/conda-meta/history", Type: tar.TypeSymlink, Link: "demo.json"},
	})
	for _, tc := range []struct {
		name    string
		args    []string
		json    bool
		verbose bool
		scan    bool
	}{
		{"find json quiet", []string{"find", "--format", "json"}, true, false, false},
		{"find text quiet", []string{"find"}, false, false, false},
		{"find text verbose", []string{"find", "--verbose"}, false, true, false},
		{"scan json", []string{"scan", "--format", "json"}, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workdir := t.TempDir()
			t.Chdir(workdir)
			args := append(tc.args, "--source", "oci-archive", "--platform", "linux/amd64", archive)
			stdout, stderr, err := runCLI(t, context.Background(), args...)
			if ExitCode(err) != 1 || !ShouldPrintError(err) {
				t.Fatalf("exit %d, ShouldPrintError %v, err %v; want exit 1 printable", ExitCode(err), ShouldPrintError(err), err)
			}
			if tc.json {
				var report inventory.ImageReport
				if err := json.Unmarshal([]byte(stdout), &report); err != nil {
					t.Fatalf("partial JSON missing: %v: %s", err, stdout)
				}
				if report.Image.ManifestDigest == "" || report.Image.Input != archive {
					t.Fatalf("loaded identity dropped: %+v", report.Image)
				}
				if report.Status != inventory.StatusIncomplete || len(report.Issues) != 1 || len(report.Environments) != 1 || report.Environments[0].Path != "/env" {
					t.Fatalf("want incomplete with 1 issue and 1 environment: %s", stdout)
				}
				if !strings.HasSuffix(report.Issues[0].Path, "conda-meta/history") {
					t.Fatalf("issue path %q does not name history", report.Issues[0].Path)
				}
				if (report.Result != nil) != tc.scan {
					t.Fatalf("find must not inventory; scan must retain its whole-image result: %s", stdout)
				}
			} else {
				if !strings.Contains(stdout, "Summary: incomplete") || !strings.Contains(stdout, "Image evidence") {
					t.Fatalf("partial text must show incomplete summary: %s", stdout)
				}
			}
			// Scan always lists per-path warnings; find lists them only with --verbose.
			if wantDetail := tc.verbose || tc.scan; wantDetail != strings.Contains(stderr, "warning: image path") {
				t.Fatalf("warning detail mismatch (want %v): %q", wantDetail, stderr)
			}
			if !tc.verbose && !tc.scan && !strings.Contains(stderr, "use --verbose to see details") {
				t.Fatalf("quiet find must point to --verbose: %q", stderr)
			}
			if tc.scan {
				files, dirErr := os.ReadDir("sboms")
				if dirErr != nil || len(files) != 1 {
					t.Fatalf("whole-image SBOM must be kept beside the failure: %v %v", files, dirErr)
				}
			}
		})
	}
}

// TestImageCommandWriterErrorJoinsBeforeCancellation pins error composition when the
// stdout writer fails and the context is also cancelled. The writer error is joined
// first, both causes stay reachable, and cancellation still wins the exit code.
func TestImageCommandWriterErrorJoinsBeforeCancellation(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1", "0")},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sentinel := errors.New("stdout closed")
	for _, command := range []string{"find", "scan"} {
		for _, format := range []string{"text", "json"} {
			t.Run(command+"/"+format, func(t *testing.T) {
				cmd := New()
				writer := &failAfterWriter{limit: 0, err: sentinel}
				cmd.SetOut(writer)
				var stderr bytes.Buffer
				cmd.SetErr(&stderr)
				cmd.SetArgs([]string{command, "--format", format, "--source", "oci-archive", "--platform", "linux/amd64", archive})
				err := cmd.ExecuteContext(ctx)
				if !errors.Is(err, context.Canceled) || ExitCode(err) != 130 || !ShouldPrintError(err) {
					t.Fatalf("cancellation must retain its identity, printable state and exit 130: %v", err)
				}
				if format == "text" {
					if writer.writes != 0 || errors.Is(err, sentinel) {
						t.Fatalf("unloaded text report must not attempt rendering: writes=%d err=%v", writer.writes, err)
					}
				} else if writer.writes != 1 || !errors.Is(err, sentinel) || err.Error() != sentinel.Error()+"\n"+context.Canceled.Error() {
					t.Fatalf("JSON must attempt rendering and join its error first: writes=%d err=%v", writer.writes, err)
				}
			})
		}
	}
}
