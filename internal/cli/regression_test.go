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
	"sync/atomic"
	"testing"
	"time"

	"github.com/anaconda/envscout/internal/testimage"
)

// runCLI executes args on a fresh root with captured stdout and stderr.
func runCLI(t *testing.T, ctx context.Context, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := New()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(ctx)
	return out.String(), errOut.String(), err
}

func condaRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	meta := filepath.Join(root, "demo", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(`{"name":"pkg","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestFormatFlagAcceptedBeforeAndAfterSubcommand(t *testing.T) {
	root := condaRoot(t)
	for _, args := range [][]string{
		{"--format", "json", "find", root},
		{"find", "--format", "json", root},
		{"find", root, "--format=json"},
	} {
		stdout, _, err := runCLI(t, context.Background(), args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !json.Valid([]byte(stdout)) {
			t.Fatalf("%v did not emit JSON: %q", args, stdout)
		}
	}
}

func TestExplicitDirSourceNeedsNoPlatform(t *testing.T) {
	root := condaRoot(t)
	for _, args := range [][]string{
		{"find", "--source", "dir", root},
		{"scan", "--source", "dir", "--output-dir", t.TempDir(), root},
	} {
		t.Chdir(t.TempDir())
		if _, _, err := runCLI(t, context.Background(), args...); err != nil {
			t.Fatalf("explicit dir %v rejected: %v", args, err)
		}
	}
}

func TestInvalidEnumRejectedWithoutArtifacts(t *testing.T) {
	workdir := t.TempDir()
	t.Chdir(workdir)
	for _, args := range [][]string{
		{"scan", "--format", "xml", condaRoot(t)},
		{"scan", "--source", "docker", condaRoot(t)},
		{"lint", "--format", "sarif", condaRoot(t)},
	} {
		if _, _, err := runCLI(t, context.Background(), args...); err == nil {
			t.Fatalf("invalid enum accepted: %v", args)
		}
	}
	if _, err := os.Stat(filepath.Join(workdir, "sboms")); !os.IsNotExist(err) {
		t.Fatal("rejected invocation produced SBOM artifacts")
	}
}

func TestRemovedJSONFlagIsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"find", "--json", condaRoot(t)},
		{"scan", "--json", condaRoot(t)},
		{"lint", "--json", condaRoot(t)},
	} {
		_, _, err := runCLI(t, context.Background(), args...)
		if err == nil || !strings.Contains(err.Error(), "unknown flag: --json") {
			t.Fatalf("%v should reject removed --json: %v", args, err)
		}
	}
}

func TestListRulesRejectsExplicitFlagsWithoutOutput(t *testing.T) {
	for _, flag := range [][]string{
		{"--source", "dir"}, {"--platform", "linux/amd64"}, {"--output-dir", "x"},
		{"--profile", "local"}, {"--fail-on", "warning"}, {"--config", "missing.json"},
		{"--runtime-prefix", "/app"}, {"--project", "."}, {"--rule", "EC001"}, {"--disable-rule", "EC001"},
	} {
		stdout, _, err := runCLI(t, context.Background(), append([]string{"lint", "--list-rules"}, flag...)...)
		if ExitCode(err) != 2 || stdout != "" {
			t.Fatalf("--list-rules %v: exit %d output %q err %v", flag, ExitCode(err), stdout, err)
		}
	}
	stdout, _, err := runCLI(t, context.Background(), "lint", "--list-rules", "--format", "json", "--no-color")
	if err != nil || !json.Valid([]byte(stdout)) {
		t.Fatalf("list-rules with --format/--no-color must be accepted: %v", err)
	}
	if _, _, err := runCLI(t, context.Background(), "lint", "--list-rules", condaRoot(t)); ExitCode(err) != 2 {
		t.Fatalf("--list-rules with a target must exit 2, got %v", err)
	}
}

func TestScanJSONLocalWritesSingleObjectAndKeepsExistingSBOMs(t *testing.T) {
	root := condaRoot(t)
	outDir := filepath.Join(t.TempDir(), "custom")
	stdout, stderr, err := runCLI(t, context.Background(), "scan", "--format", "json", "--output-dir", outDir, root)
	if err != nil {
		t.Fatalf("scan json: %v: %s", err, stderr)
	}
	var report struct {
		Source       string `json:"source"`
		Status       string `json:"status"`
		Observations []struct {
			Environment struct {
				Name string `json:"name"`
			} `json:"environment"`
			Error string `json:"error"`
		} `json:"observations"`
		Discovery struct {
			Roots []string `json:"roots"`
		} `json:"discovery"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("stdout must be one JSON object: %v: %s", err, stdout)
	}
	if report.Source != "dir" || report.Status != "complete" || len(report.Observations) != 1 || report.Observations[0].Environment.Name != "demo" {
		t.Fatalf("unexpected scan report: %s", stdout)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one SBOM in custom output dir: %v %v", entries, err)
	}
	before, err := os.ReadFile(filepath.Join(outDir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = runCLI(t, context.Background(), "scan", "--format", "json", "--output-dir", outDir, root)
	if ExitCode(err) != 1 {
		t.Fatalf("repeated scan should be incomplete, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(outDir, entries[0].Name()))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeated scan overwrote an existing SBOM")
	}
}

func TestScanJSONPartialFailureRendersBeforeError(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good", "conda-meta")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "pkg.json"), []byte(`{"name":"pkg","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Discovery confirms a prefix by its directory alone; this record is parsed and
	// dropped during scanning, so the failure is a failed target, not a discovery issue.
	bad := filepath.Join(root, "broken", "conda-meta")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "broken.json"), []byte(`{"name":"broken"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "sboms")
	stdout, _, err := runCLI(t, context.Background(), "scan", "--format", "json", "--output-dir", outDir, root)
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("partial scan should exit 1: %v", err)
	}
	var report struct {
		Status       string `json:"status"`
		Observations []struct {
			Environment struct {
				Name string `json:"name"`
			} `json:"environment"`
			Error  string `json:"error"`
			Result struct {
				Path string `json:"path"`
			} `json:"result"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("partial JSON report missing: %v: %s", err, stdout)
	}
	if report.Status != "incomplete" || len(report.Observations) != 2 {
		t.Fatalf("unexpected partial report: %s", stdout)
	}
	var failed, kept int
	for _, observation := range report.Observations {
		switch {
		case observation.Error != "":
			failed++
		case observation.Result.Path != "":
			kept++
		}
	}
	if failed != 1 || kept != 1 {
		t.Fatalf("want one failed target and one kept SBOM, got failed=%d kept=%d: %s", failed, kept, stdout)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("both candidate SBOMs should be retained on disk: %v %v", entries, err)
	}
}

func TestScanJSONImageIncludesIdentityAndWritesWholeImageSBOM(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "opt/conda/conda-meta/python.json", Data: `{"name":"python","version":"3.12","build":"0","subdir":"linux-64"}`},
	})
	t.Chdir(t.TempDir())
	stdout, _, err := runCLI(t, context.Background(), "scan", "--source", "oci-archive", "--platform", "linux/amd64", "--format", "json", archive)
	if err != nil {
		t.Fatalf("image scan json: %v", err)
	}
	var report struct {
		Image struct {
			ManifestDigest string `json:"manifest_digest"`
		} `json:"image"`
		Result struct {
			Path string `json:"path"`
		} `json:"result"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("image JSON not a single object: %v: %s", err, stdout)
	}
	if report.Image.ManifestDigest == "" || report.Result.Path == "" || report.Status == "" {
		t.Fatalf("image JSON missing identity or result: %s", stdout)
	}
}

func TestFindJSONNeverEmitsNonJSONOnStdout(t *testing.T) {
	stdout, _, err := runCLI(t, context.Background(), "find", "--format", "json", condaRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("stdout is not one JSON object: %v", err)
	}
}

// TestCancellationExitsOneThirtyForEveryCommand verifies that a cancelled parent
// context maps to exit 130 whether it appears directly or wrapped.
func TestCancellationExitsOneThirtyForEveryCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := condaRoot(t)
	t.Chdir(t.TempDir())
	for _, args := range [][]string{
		{"find", root},
		{"find"},
		{"scan", root},
		{"lint", root},
	} {
		if _, _, err := runCLI(t, ctx, args...); ExitCode(err) != 130 {
			t.Errorf("%v: exit %d, want 130: %v", args, ExitCode(err), err)
		}
	}
}

func TestWrappedCancellationIsOneThirty(t *testing.T) {
	err := fmt.Errorf("scan: %w", fmt.Errorf("inner: %w", context.Canceled))
	if ExitCode(err) != 130 {
		t.Fatalf("wrapped cancellation exit = %d", ExitCode(err))
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("wrapping lost context.Canceled")
	}
}

func TestDeadlineInLintIsStructuredInspectionFailure(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	stdout, _, err := runCLI(t, ctx, "lint", "--format", "json", condaRoot(t))
	if ExitCode(err) != 2 || !json.Valid([]byte(stdout)) {
		t.Fatalf("deadline lint: exit %d, output %s", ExitCode(err), stdout)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestStickyOutputFailureReturnsError(t *testing.T) {
	cmd := New()
	cmd.SetOut(failingWriter{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"find", condaRoot(t)})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("text write failure not reported: %v", err)
	}
	cmd = New()
	cmd.SetOut(failingWriter{})
	cmd.SetArgs([]string{"lint", "--list-rules"})
	if ExitCode(cmd.Execute()) != 2 {
		t.Fatal("list-rules write failure must exit 2")
	}
}

// countdownContext reports nil from Err for the first limit calls, then Canceled.
// It drives cancellation at a deterministic point in a walk without sleeping.
type countdownContext struct {
	context.Context
	limit int
	calls atomic.Int64
}

func (c *countdownContext) Err() error {
	if c.calls.Add(1) > int64(c.limit) {
		return context.Canceled
	}
	return nil
}

// TestFindCancelledMidWalkKeepsPartialReport finds the call budget at which the
// walk has recorded its one environment and then stops, and requires the JSON
// report to keep that environment with exit 130.
// The exact number of Err calls a walk makes is an implementation detail, so the
// budget is searched rather than pinned. The invariant: some budget cancels after
// the environment is recorded, and that run keeps the environment in valid JSON
// with exit 130.
func TestFindCancelledMidWalkKeepsPartialReport(t *testing.T) {
	root := condaRoot(t)
	for limit := 1; limit < 500; limit++ {
		ctx := &countdownContext{Context: context.Background(), limit: limit}
		stdout, _, err := runCLI(t, ctx, "find", "--format", "json", root)
		if ExitCode(err) != 130 || !strings.Contains(stdout, `"name": "demo"`) {
			continue
		}
		if !json.Valid([]byte(stdout)) {
			t.Fatalf("partial report is not JSON: %s", stdout)
		}
		return
	}
	t.Fatal("no call budget produced a cancelled walk holding the discovered environment")
}

func TestFindLocalCancelledBeforeWalkReturnsNoReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stdout, _, err := runCLI(t, ctx, "find", "--format", "json", condaRoot(t))
	if ExitCode(err) != 130 || stdout != "" {
		t.Fatalf("pre-cancelled find: exit %d output %q", ExitCode(err), stdout)
	}
}

func TestOutputDirEmptyRejectedBeforeArtifacts(t *testing.T) {
	workdir := t.TempDir()
	t.Chdir(workdir)
	archive := testimage.Archive(t, []testimage.Entry{{Name: "opt/conda/conda-meta/python.json", Data: `{"name":"python","version":"3.12","build":"0"}`}})
	for _, args := range [][]string{
		{"scan", "--output-dir", "", condaRoot(t)},
		{"scan", "--source", "oci-archive", "--platform", "linux/amd64", "--output-dir", "", archive},
	} {
		if ExitCode(runErr(t, args...)) != 2 {
			t.Fatalf("%v: empty output dir must be an input error", args)
		}
	}
	if _, err := os.Stat(filepath.Join(workdir, "sboms")); !os.IsNotExist(err) {
		t.Fatal("empty output dir produced artifacts")
	}
}

func runErr(t *testing.T, args ...string) error {
	t.Helper()
	_, _, err := runCLI(t, context.Background(), args...)
	return err
}

func TestWrappedCommandExitCancellationIsOneThirty(t *testing.T) {
	err := fmt.Errorf("outer: %w", &commandExit{code: 2, err: context.Canceled})
	if ExitCode(err) != 130 {
		t.Fatalf("cancellation inside commandExit = %d, want 130", ExitCode(err))
	}
	if ExitCode(&commandExit{code: 2, err: errors.New("bad")}) != 2 {
		t.Fatal("non-cancellation commandExit must keep its code")
	}
}

func TestFlagParseErrorsExitTwoOnEveryCommand(t *testing.T) {
	for _, args := range [][]string{
		{"find", "--format", "xml", "x"},
		{"scan", "--format", "xml", "x"},
		{"lint", "--format", "xml", "x"},
	} {
		if ExitCode(runErr(t, args...)) != 2 {
			t.Fatalf("%v: flag error must exit 2", args)
		}
	}
}

func TestOutputDirRejectedOutsideScan(t *testing.T) {
	workdir := t.TempDir()
	t.Chdir(workdir)
	for _, args := range [][]string{
		{"find", "--output-dir", "x", condaRoot(t)},
		{"--output-dir", "x", "find", condaRoot(t)},
		{"lint", "--output-dir", "x", condaRoot(t)},
	} {
		stdout, _, err := runCLI(t, context.Background(), args...)
		if ExitCode(err) != 2 || stdout != "" {
			t.Fatalf("%v: exit %d stdout %q err %v", args, ExitCode(err), stdout, err)
		}
	}
	if _, err := os.Stat(filepath.Join(workdir, "x")); !os.IsNotExist(err) {
		t.Fatal("rejected --output-dir produced artifacts")
	}
	t.Chdir(t.TempDir())
	if _, _, err := runCLI(t, context.Background(), "--output-dir", "out", "scan", condaRoot(t)); err != nil {
		t.Fatalf("scan with output-dir before subcommand: %v", err)
	}
}

func TestBadRootTextIsSilentJSONIsStructured(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-root")
	t.Chdir(t.TempDir())
	stdout, _, err := runCLI(t, context.Background(), "scan", missing)
	if ExitCode(err) != 1 || stdout != "" {
		t.Fatalf("text bad-root scan: exit %d stdout %q", ExitCode(err), stdout)
	}
	stdout, _, err = runCLI(t, context.Background(), "scan", "--format", "json", missing)
	assertIncompleteJSON(t, stdout, err, "dir", missing)
	if _, _, err := runCLI(t, context.Background(), "find", "--format", "json", missing); ExitCode(err) != 1 {
		t.Fatalf("find bad root must exit 1: %v", err)
	}
}

func TestBadImageTextIsSilentJSONIsStructured(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.tar")
	t.Chdir(t.TempDir())
	for _, command := range []string{"find", "scan"} {
		stdout, _, err := runCLI(t, context.Background(), command, "--source", "oci-archive", "--platform", "linux/amd64", missing)
		if ExitCode(err) != 1 || stdout != "" {
			t.Fatalf("text bad image %s: exit %d stdout %q", command, ExitCode(err), stdout)
		}
		stdout, _, err = runCLI(t, context.Background(), command, "--source", "oci-archive", "--platform", "linux/amd64", "--format", "json", missing)
		assertIncompleteJSON(t, stdout, err, "oci-archive", missing)
	}
}

// assertIncompleteJSON requires one structured object carrying the error, an
// incomplete status, the source, non-nil arrays and exit 1.
func assertIncompleteJSON(t *testing.T, stdout string, err error, source, path string) {
	t.Helper()
	if ExitCode(err) != 1 {
		t.Fatalf("exit %d, want 1: %v", ExitCode(err), err)
	}
	var report map[string]any
	if decodeErr := json.Unmarshal([]byte(stdout), &report); decodeErr != nil {
		t.Fatalf("stdout is not one JSON object: %v: %s", decodeErr, stdout)
	}
	message, _ := report["error"].(string)
	if !strings.Contains(message, path) {
		t.Fatalf("error %q does not name %q", message, path)
	}
	if report["status"] != "incomplete" || report["source"] != source {
		t.Fatalf("status/source = %v/%v, want incomplete/%s", report["status"], report["source"], source)
	}
	for _, key := range []string{"observations", "environments", "issues"} {
		if value, ok := report[key]; ok && value == nil {
			t.Fatalf("%s must be an array, not null", key)
		}
	}
}
