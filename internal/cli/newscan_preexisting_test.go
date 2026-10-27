package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// preexistingRoot builds one conda prefix named "shared" under a fresh root and
// returns the root plus the SBOM path that scan will target for it.
func preexistingRoot(t *testing.T) (root, prefix string) {
	t.Helper()
	root = t.TempDir()
	prefix = filepath.Join(root, "shared")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(canonicalPrefixRecord("pkg", "1", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, prefix
}

// scanReport is the subset of the scan JSON report these tests assert on.
type scanReport struct {
	Status       string `json:"status"`
	Observations []struct {
		Result struct {
			Path        string `json:"path"`
			PreExisting bool   `json:"pre_existing,omitempty"`
			Conda       int    `json:"conda"`
			Total       int    `json:"total"`
		} `json:"result"`
		Error string `json:"error,omitempty"`
	} `json:"observations"`
}

// scanJSON runs `scan --format json` into outputDir and decodes the report. The
// returned error is the command error, not a decode error.
func scanJSON(t *testing.T, outputDir string, roots ...string) (scanReport, error) {
	t.Helper()
	cmd := New()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(append([]string{"scan", "--format", "json", "--output-dir", outputDir}, roots...))
	err := cmd.Execute()
	var report scanReport
	if decodeErr := json.Unmarshal(stdout.Bytes(), &report); decodeErr != nil {
		t.Fatalf("scan JSON did not decode: %v\nstdout: %s\nstderr: %s", decodeErr, stdout.String(), stderr.String())
	}
	return report, err
}

// TestScanRepeatWithExistingRegularSBOMIsPreExisting covers the first scan writing an
// SBOM and a second scan of the same root treating that regular file as pre-existing.
func TestScanRepeatWithExistingRegularSBOMIsPreExisting(t *testing.T) {
	root, _ := preexistingRoot(t)
	outputDir := t.TempDir()

	first, err := scanJSON(t, outputDir, root)
	if err != nil || first.Status != "complete" || len(first.Observations) != 1 || first.Observations[0].Result.PreExisting {
		t.Fatalf("first scan must write a fresh SBOM: err=%v report=%+v", err, first)
	}
	before, err := os.ReadFile(first.Observations[0].Result.Path)
	if err != nil {
		t.Fatal(err)
	}

	second, err := scanJSON(t, outputDir, root)
	if err != nil {
		t.Fatalf("pre-existing SBOM must not fail the scan: %v", err)
	}
	if second.Status != "complete" || len(second.Observations) != 1 {
		t.Fatalf("unexpected repeat report: %+v", second)
	}
	obs := second.Observations[0]
	if obs.Error != "" || !obs.Result.PreExisting || obs.Result.Path != first.Observations[0].Result.Path {
		t.Fatalf("repeat observation must be pre-existing at the same path: %+v", obs)
	}
	// Pre-existing evidence is not rescanned: no package counts are fabricated.
	if obs.Result.Conda != 0 || obs.Result.Total != 0 {
		t.Fatalf("pre-existing observation must not carry package counts: %+v", obs.Result)
	}
	after, err := os.ReadFile(obs.Result.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("pre-existing SBOM must be left unchanged: %v", err)
	}
}

// TestScanTextSummaryCountsPreExisting pins the text summary for the two-file repeat
// and for a mixed run with one old and one new prefix.
func TestScanTextSummaryCountsPreExisting(t *testing.T) {
	root, _ := preexistingRoot(t)
	outputDir := t.TempDir()
	run := func(roots ...string) (string, error) {
		cmd := New()
		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetArgs(append([]string{"scan", "--output-dir", outputDir}, roots...))
		err := cmd.Execute()
		return stdout.String(), err
	}
	if _, err := run(root); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	out, err := run(root)
	if err != nil {
		t.Fatalf("repeat text scan must exit 0: %v", err)
	}
	if !strings.Contains(out, "Summary: complete; 1 environments found, 0 SBOMs written, 1 pre-existing SBOMs, 0 failed scans") {
		t.Fatalf("repeat summary wrong: %s", out)
	}
	if strings.Contains(out, "SBOM already exists") {
		t.Fatalf("pre-existing must not render as a failure: %s", out)
	}
}

// TestScanMixedOldAndNewCounts runs one already-written prefix together with a new one.
func TestScanMixedOldAndNewCounts(t *testing.T) {
	oldRoot, _ := preexistingRoot(t)
	outputDir := t.TempDir()
	if _, err := scanJSON(t, outputDir, oldRoot); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	newRoot := t.TempDir()
	fresh := filepath.Join(newRoot, "fresh", "conda-meta")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "pkg.json"), []byte(canonicalPrefixRecord("pkg", "2", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", "--output-dir", outputDir, oldRoot, newRoot})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("mixed scan must exit 0: %v: %s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "Summary: complete; 2 environments found, 1 SBOMs written, 1 pre-existing SBOMs, 0 failed scans") {
		t.Fatalf("mixed summary must count 1 written + 1 pre-existing: %s", stdout.String())
	}
}

// TestScanPreExistingIgnoresMalformedInput proves a pre-existing regular file is skipped
// by presence alone: its content is never parsed, so a malformed SBOM still passes.
// A real catalog failure in a different prefix must still fail and leave the file alone.
func TestScanPreExistingIgnoresMalformedInput(t *testing.T) {
	root, prefix := preexistingRoot(t)
	outputDir := t.TempDir()
	if _, err := scanJSON(t, outputDir, root); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	// Overwrite the existing SBOM with non-JSON garbage and verify the scan still skips it.
	seeded, err := scanJSON(t, outputDir, root)
	if err != nil {
		t.Fatalf("pre-existing scan must exit 0 before corruption: %v", err)
	}
	target := seeded.Observations[0].Result.Path
	if err := os.WriteFile(target, []byte("not json {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := scanJSON(t, outputDir, root)
	if err != nil || !report.Observations[0].Result.PreExisting {
		t.Fatalf("malformed pre-existing file must be skipped by presence, not read: err=%v %+v", err, report)
	}
	if data, _ := os.ReadFile(target); string(data) != "not json {{{" {
		t.Fatalf("pre-existing file must remain unchanged, got %q", data)
	}

	// A malformed prefix with no valid conda record is a real failure, not masked by the skip.
	badRoot := t.TempDir()
	bad := filepath.Join(badRoot, "broken", "conda-meta")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "broken.json"), []byte(`{"name":"broken"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scanJSON(t, outputDir, root, badRoot); err == nil || !strings.Contains(err.Error(), "scan incomplete: 1 failed target(s)") {
		t.Fatalf("malformed real prefix must still fail the scan: %v", err)
	}
	if _, statErr := os.Stat(prefix); statErr != nil {
		t.Fatal(statErr)
	}
}

// TestScanDummyExistingFileIsNotRevalidated treats an empty placeholder at the SBOM
// path as pre-existing by presence and does not validate or rescan it.
func TestScanDummyExistingFileIsNotRevalidated(t *testing.T) {
	root, _ := preexistingRoot(t)
	outputDir := t.TempDir()
	first, err := scanJSON(t, outputDir, root)
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	target := first.Observations[0].Result.Path
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := scanJSON(t, outputDir, root)
	if err != nil || len(report.Observations) != 1 || !report.Observations[0].Result.PreExisting {
		t.Fatalf("empty placeholder must be classified pre-existing without validation: err=%v %+v", err, report)
	}
}

// TestScanPreExistingSymlinkTargetFails keeps a symlink at the target a failure, so
// output is never written through or treated as a valid SBOM.
func TestScanPreExistingSymlinkTargetFails(t *testing.T) {
	root, _ := preexistingRoot(t)
	outputDir := t.TempDir()
	first, err := scanJSON(t, outputDir, root)
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	target := first.Observations[0].Result.Path
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(t.TempDir(), "decoy.json")
	if err := os.WriteFile(decoy, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, target); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	report, err := scanJSON(t, outputDir, root)
	if err == nil || !strings.Contains(err.Error(), "failed target(s)") {
		t.Fatalf("symlink at SBOM path must fail: err=%v report=%+v", err, report)
	}
	if len(report.Observations) != 1 || report.Observations[0].Result.PreExisting || report.Observations[0].Error == "" {
		t.Fatalf("symlink target must be a recorded failure, not pre-existing: %+v", report.Observations)
	}
	if data, _ := os.ReadFile(decoy); string(data) != "{}" {
		t.Fatalf("symlink target was written through: %q", data)
	}
}

// TestScanPreExistingDirectoryTargetFails keeps a directory at the target a failure.
func TestScanPreExistingDirectoryTargetFails(t *testing.T) {
	root, _ := preexistingRoot(t)
	outputDir := t.TempDir()
	first, err := scanJSON(t, outputDir, root)
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	target := first.Observations[0].Result.Path
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := scanJSON(t, outputDir, root)
	if err == nil || !strings.Contains(err.Error(), "failed target(s)") {
		t.Fatalf("directory at SBOM path must fail: err=%v", err)
	}
	if len(report.Observations) != 1 || report.Observations[0].Result.PreExisting {
		t.Fatalf("directory target must not be pre-existing: %+v", report.Observations)
	}
}
