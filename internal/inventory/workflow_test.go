package inventory

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/testimage"
)

// writeCondaPrefix creates a minimal conda prefix with one conda package record.
func writeCondaPrefix(t *testing.T, prefix string) {
	t.Helper()
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "python-3.12-0.json"), []byte(`{"name":"python","version":"3.12","build":"0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanCondaHostTree(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "envs", "sample")
	writeCondaPrefix(t, prefix)
	outputDir := filepath.Join(t.TempDir(), "sboms")
	report, err := ScanConda(context.Background(), []string{root}, outputDir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Source != "dir" || report.Status != StatusComplete {
		t.Fatalf("unexpected source/status: %q %q", report.Source, report.Status)
	}
	if len(report.Observations) != 1 {
		t.Fatalf("observations = %+v", report.Observations)
	}
	obs := report.Observations[0]
	if obs.Error != "" || obs.Result.Conda != 1 || obs.Environment.Path != prefix {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if !strings.HasPrefix(obs.Result.Path, outputDir) {
		t.Fatalf("SBOM not in output dir: %s", obs.Result.Path)
	}
	if report.Started.IsZero() || report.TotalDuration < 0 || report.DiscoveryDuration < 0 {
		t.Fatalf("timing fields not populated: %+v", report)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"source"`, `"started_at"`, `"observations"`, `"discovery_duration_ns"`, `"status"`, `"duration_ns"`, `"syft_version"`, `"python_installed"`} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("JSON missing %s: %s", key, data)
		}
	}
}

func TestScanCondaEmptyTreeWritesNothing(t *testing.T) {
	root := t.TempDir()
	outputDir := filepath.Join(t.TempDir(), "sboms")
	report, err := ScanConda(context.Background(), []string{root}, outputDir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Observations) != 0 || report.Status != StatusComplete {
		t.Fatalf("unexpected empty report: %+v", report)
	}
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		t.Fatalf("empty scan must not create SBOM directory: %v", err)
	}
}

func TestScanCondaRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "envs", "sample"))
	outputDir := t.TempDir()
	first, err := ScanConda(context.Background(), []string{root}, outputDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(first.Observations[0].Result.Path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ScanConda(context.Background(), []string{root}, outputDir)
	if err == nil || !strings.Contains(err.Error(), "scan incomplete: 1 failed target(s), 0 discovery issue(s)") {
		t.Fatalf("repeat scan must return incomplete error: %v", err)
	}
	if second.Status != StatusIncomplete || len(second.Observations) != 1 || !strings.Contains(second.Observations[0].Error, "already exists") {
		t.Fatalf("repeat scan must record refused overwrite: %+v", second)
	}
	after, err := os.ReadFile(first.Observations[0].Result.Path)
	if err != nil || string(after) != string(before) {
		t.Fatal("existing SBOM changed on repeated scan")
	}
}

func TestScanCondaBadRootReturnsDiscoveryError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	report, err := ScanConda(context.Background(), []string{missing}, t.TempDir())
	if err == nil || report.Error != err.Error() {
		t.Fatalf("bad root must return and record the discovery error: %v / %+v", err, report)
	}
}

func TestScanCondaPartialDiscoveryStillScans(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "envs", "good"))
	// A conda-meta record with no name is a discovery issue (incomplete evidence).
	broken := filepath.Join(root, "envs", "broken", "conda-meta")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "bad.json"), []byte(`{"version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	outputDir := t.TempDir()
	report, err := ScanConda(context.Background(), []string{root}, outputDir)
	// Discovery only proves candidates; the malformed prefix fails conda validation
	// during scanning and is counted as a failed target, while the good prefix stays.
	if err == nil || !strings.Contains(err.Error(), "scan incomplete: 1 failed target(s)") {
		t.Fatalf("partial discovery must return incomplete error: %v", err)
	}
	if report.Status != StatusIncomplete || len(report.Observations) != 2 {
		t.Fatalf("scan should be incomplete with both candidates observed: %+v", report)
	}
	good := 0
	for _, observation := range report.Observations {
		if observation.Error == "" {
			good++
		}
	}
	if good != 1 {
		t.Fatalf("good prefix count = %d, want 1", good)
	}
	files, err := os.ReadDir(outputDir)
	if err != nil || len(files) != 2 {
		t.Fatalf("expected the good and malformed SBOMs to be kept: %v %v", files, err)
	}
}

func TestScanCondaContextCancellation(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "envs", "a"))
	writeCondaPrefix(t, filepath.Join(root, "envs", "b"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outputDir := t.TempDir()
	report, err := ScanConda(ctx, []string{root}, outputDir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want wrapped context.Canceled", err)
	}
	if report.Status != StatusIncomplete {
		t.Fatalf("canceled scan status = %q", report.Status)
	}
	if len(report.Observations) != 0 {
		t.Fatalf("canceled scan launched targets: %+v", report.Observations)
	}
	entries, err := os.ReadDir(outputDir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("canceled scan wrote SBOMs: %v", entries)
	}
}

func TestInspectImageFindOnlyWritesNothing(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "opt/conda/conda-meta/python.json", Data: `{"name":"python","version":"3.12","build":"0","subdir":"linux-64"}`},
	})
	report, err := InspectImage(context.Background(), archive, "linux/amd64", "")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if report.Result != nil || report.ScanError != "" || report.Status != StatusCompleted {
		t.Fatalf("find must not scan: %+v", report)
	}
	if report.Image.ManifestDigest == "" || report.Image.Input != archive {
		t.Fatalf("missing image identity: %+v", report.Image)
	}
	if len(report.Environments) != 1 || report.Environments[0].Path != "/opt/conda" {
		t.Fatalf("unexpected environments: %+v", report.Environments)
	}
	if report.LoadDuration < 0 || report.TotalDuration < 0 || report.Started.IsZero() {
		t.Fatalf("timing not populated: %+v", report)
	}
}

func TestInspectImageScanWritesOneSBOM(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "opt/conda/conda-meta/python.json", Data: `{"name":"python","version":"3.12","build":"0","subdir":"linux-64"}`},
		{Name: "opt/conda/envs/app/conda-meta/demo.json", Data: `{"name":"demo","version":"1.0","build":"0","subdir":"linux-64"}`},
	})
	outputDir := t.TempDir()
	report, err := InspectImage(context.Background(), archive, "linux/amd64", outputDir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if report.Result == nil || report.Result.Conda < 2 || report.Status != StatusCompleted {
		t.Fatalf("unexpected scan result: %+v", report)
	}
	if !strings.HasPrefix(report.Result.Path, outputDir) {
		t.Fatalf("SBOM outside requested dir: %s", report.Result.Path)
	}
	files, err := os.ReadDir(outputDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("expected exactly one SBOM: %v %v", files, err)
	}
	data, err := os.ReadFile(filepath.Join(outputDir, files[0].Name()))
	if err != nil || !json.Valid(data) {
		t.Fatalf("invalid SBOM: %v", err)
	}
	// A second scan must refuse to overwrite and surface the error.
	again, err := InspectImage(context.Background(), archive, "linux/amd64", outputDir)
	if err == nil || !strings.Contains(err.Error(), "create SBOM") || again.ScanError == "" {
		t.Fatalf("repeat image scan should refuse overwrite: %v / %+v", err, again)
	}
	if again.Image.ManifestDigest == "" {
		t.Fatal("image identity must be returned even on scan failure")
	}
}

func TestInspectImagePartialDiscoveryStillWritesSBOM(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/demo.json", Data: `{"name":"demo","version":"1"}`},
		{Name: "broken/conda-meta/bad.json", Data: `{"name":"incomplete"}`},
		{Name: "alias", Type: tar.TypeSymlink, Link: "env"},
	})
	outputDir := t.TempDir()
	report, err := InspectImage(context.Background(), archive, "linux/amd64", outputDir)
	// The malformed record is a candidate, not a discovery issue. Its conda content
	// surfaces as an unknown file coordinate, which makes the inspection incomplete
	// while the SBOM is still written and kept.
	if err == nil || !strings.Contains(err.Error(), "image inspection incomplete") {
		t.Fatalf("partial image scan should report incomplete: %v", err)
	}
	if report.Status != StatusIncomplete || report.Result == nil || report.Result.Unknowns == 0 {
		t.Fatalf("partial report must carry the kept SBOM with unknown coordinates: %+v", report)
	}
	if _, statErr := os.Stat(report.Result.Path); statErr != nil {
		t.Fatalf("kept SBOM missing: %v", statErr)
	}
	files, err := os.ReadDir(outputDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("partial discovery must still write one SBOM: %v %v", files, err)
	}
}

// cancelWhenFileExists wraps a real cancel-cause context. Err checks whether dir has
// a file (an SBOM write has completed) and then cancels with cause, so the
// cancellation lands mid-flight without timers or sleeps.
type cancelWhenFileExists struct {
	context.Context
	dir    string
	cancel context.CancelCauseFunc
	cause  error
}

func newCancelWhenFileExists(dir string, cause error) *cancelWhenFileExists {
	base, cancel := context.WithCancelCause(context.Background())
	return &cancelWhenFileExists{Context: base, dir: dir, cancel: cancel, cause: cause}
}

func (c *cancelWhenFileExists) Err() error {
	if entries, err := os.ReadDir(c.dir); err == nil && len(entries) > 0 {
		c.cancel(c.cause)
	}
	return c.Context.Err()
}

func TestScanCondaRelativeOutputResolved(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "envs", "sample"))
	t.Chdir(t.TempDir())
	report, err := ScanConda(context.Background(), []string{root}, "sboms")
	if err != nil {
		t.Fatalf("relative output must be accepted: %v", err)
	}
	if report.Source != "dir" || len(report.Observations) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	path := report.Observations[0].Result.Path
	if !filepath.IsAbs(path) {
		t.Fatalf("SBOM path must be absolute after resolution: %s", path)
	}
	if _, err := os.Stat(filepath.Join("sboms", filepath.Base(path))); err != nil {
		t.Fatalf("SBOM not written under relative sboms: %v", err)
	}
}

// TestScanCondaCancellationDuringTargetRemovesPartialOutput cancels with a custom
// cause while a target is being written. The in-flight observation must report an
// error with a zero Result, no partial SBOM may remain, and the error must keep both
// the cause and context.Canceled identity.
func TestScanCondaCancellationDuringTargetRemovesPartialOutput(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "envs", "a"))
	cause := errors.New("operator stop")
	outputDir := t.TempDir()
	ctx := newCancelWhenFileExists(outputDir, cause)
	report, err := ScanConda(ctx, []string{root}, outputDir)
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want custom cause and context.Canceled", err)
	}
	if report.Status != StatusIncomplete {
		t.Fatalf("status = %q, want incomplete", report.Status)
	}
	for _, observation := range report.Observations {
		if observation.Error != "" && observation.Result.Path != "" {
			t.Fatalf("failed observation kept a result: %+v", observation)
		}
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(outputDir, entry.Name()))
		if err != nil || !json.Valid(data) {
			t.Fatalf("cancelled scan left an invalid SBOM %s: %v", entry.Name(), err)
		}
	}
}

// TestScanCondaCompletedTargetSurvivesSubsequentStop keeps a target that completed
// before a later cancellation: its observation has no error and its SBOM remains.
func TestScanCondaCompletedTargetSurvivesSubsequentStop(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "envs", "a"))
	writeCondaPrefix(t, filepath.Join(root, "envs", "b"))
	outputDir := t.TempDir()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	// Cancel when the second target is reserved, after the first write has returned.
	watcher := &stopAfterFirstSBOM{Context: ctx, dir: outputDir, cancel: cancel, cause: errors.New("operator stop")}
	report, err := ScanConda(watcher, []string{root}, outputDir)
	if err == nil {
		t.Fatal("stopped scan must return an error")
	}
	var completed int
	for _, observation := range report.Observations {
		if observation.Error == "" {
			completed++
			if _, statErr := os.Stat(observation.Result.Path); statErr != nil {
				t.Fatalf("completed SBOM missing: %v", statErr)
			}
		}
	}
	if completed != 1 {
		t.Fatalf("completed observations = %d, want 1: %+v", completed, report.Observations)
	}
}

// stopAfterFirstSBOM cancels once a second output is reserved. The first target
// has returned successfully by then; cancellation must not remove that SBOM.
type stopAfterFirstSBOM struct {
	context.Context
	dir    string
	cancel context.CancelCauseFunc
	cause  error
}

func (s *stopAfterFirstSBOM) Err() error {
	entries, err := os.ReadDir(s.dir)
	if err == nil && len(entries) > 1 {
		s.cancel(s.cause)
	}
	return s.Context.Err()
}

func TestScanCondaNoArtifactsOnPreflightError(t *testing.T) {
	if _, err := ScanConda(context.Background(), []string{t.TempDir()}, ""); err == nil {
		t.Fatal("empty scan output directory must be rejected")
	}
	outputDir := filepath.Join(t.TempDir(), "sboms")
	if _, err := ScanConda(context.Background(), []string{filepath.Join(t.TempDir(), "missing")}, outputDir); err == nil {
		t.Fatal("expected discovery error for bad root")
	}
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		t.Fatalf("preflight failure created output directory: %v", err)
	}
}

func TestInspectImageEarlyLoadErrorStatus(t *testing.T) {
	report, err := InspectImage(context.Background(), filepath.Join(t.TempDir(), "missing.tar"), "linux/amd64", "")
	if err == nil {
		t.Fatal("expected load error")
	}
	if report.Error != err.Error() {
		t.Fatalf("load error must be present in JSON report: %v / %+v", err, report)
	}
	if report.Status != StatusIncomplete || report.TotalDuration < 0 || report.Environments == nil || report.Issues == nil {
		t.Fatalf("early error must keep incomplete status and non-nil arrays: %+v", report)
	}
}
