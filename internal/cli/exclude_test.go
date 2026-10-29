package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// excludeRoot builds one explicit root with a kept venv and excluded folders
// that would each produce an error if discovery reached them: broken METADATA.
func excludeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	venvFixture(t, root, "kept", true)
	venvFixture(t, filepath.Join(root, "drop"), "bad", true)
	venvFixture(t, filepath.Join(root, "cache"), "bad2", true)
	writeBrokenMetadata(t, filepath.Join(root, "drop", "bad", "lib/python3.13/site-packages/demo-1.dist-info/METADATA"))
	writeBrokenMetadata(t, filepath.Join(root, "cache", "bad2", "lib/python3.13/site-packages/demo-1.dist-info/METADATA"))
	return root
}

func writeBrokenMetadata(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("\x00\xff not metadata"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// findEnvironmentNames decodes find JSON and returns the base name of each
// discovered environment path, ignoring the roots array and issue text.
func findEnvironmentNames(t *testing.T, out string) []string {
	t.Helper()
	var report struct {
		Environments []struct {
			Path string `json:"path"`
		} `json:"environments"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("find json does not decode: %v\n%s", err, out)
	}
	names := make([]string, 0, len(report.Environments))
	for _, env := range report.Environments {
		names = append(names, filepath.Base(env.Path))
	}
	return names
}

func requireOnly(t *testing.T, got []string, want string) {
	t.Helper()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("environments = %v, want only %q", got, want)
	}
}

func TestExcludeFindSkipsBasenameFoldersAnywhere(t *testing.T) {
	root := excludeRoot(t)
	out, errOut, err := runCLI(t, context.Background(), "find", "--format", "json", "--exclude", "drop", "--exclude", "{cache,build}", root)
	if err != nil {
		t.Fatalf("find with excludes error = %v\nstderr=%s", err, errOut)
	}
	requireOnly(t, findEnvironmentNames(t, out), "kept")
	if strings.Contains(errOut, "bad") {
		t.Fatalf("excluded folder produced issues on stderr: %s", errOut)
	}
}

func TestExcludeFindCommaLiteralNameIsNotSplit(t *testing.T) {
	root := t.TempDir()
	venvFixture(t, root, "kept", true)
	venvFixture(t, root, "a,b", true)
	out, _, err := runCLI(t, context.Background(), "find", "--format", "json", "--exclude", "a,b", root)
	if err != nil {
		t.Fatalf("find error = %v", err)
	}
	requireOnly(t, findEnvironmentNames(t, out), "kept")
}

func TestExcludeFindSlashPatternIsRelativeToEachRoot(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	venvFixture(t, filepath.Join(first, "nested"), "skip", true)
	venvFixture(t, filepath.Join(second, "nested"), "keep", true)
	out, _, err := runCLI(t, context.Background(), "find", "--format", "json", "--exclude", "nested/skip", first, second)
	if err != nil {
		t.Fatalf("find error = %v", err)
	}
	requireOnly(t, findEnvironmentNames(t, out), "keep")
}

func TestExcludeAbsolutePatternMatchesHostPath(t *testing.T) {
	root := t.TempDir()
	venvFixture(t, filepath.Join(root, "sub"), "skip", true)
	venvFixture(t, root, "kept", true)
	out, _, err := runCLI(t, context.Background(), "find", "--format", "json", "--exclude", filepath.Join(root, "sub"), root)
	if err != nil {
		t.Fatalf("find error = %v", err)
	}
	requireOnly(t, findEnvironmentNames(t, out), "kept")
}

func TestExcludeSkipsNestedExplicitRootDescendants(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "drop", "inner")
	venvFixture(t, nested, "bad", true)
	writeBrokenMetadata(t, filepath.Join(nested, "bad", "lib/python3.13/site-packages/demo-1.dist-info/METADATA"))
	venvFixture(t, root, "kept", true)
	out, errOut, err := runCLI(t, context.Background(), "find", "--format", "json", "--exclude", "drop", root, nested)
	if err != nil {
		t.Fatalf("find error = %v\nstderr=%s", err, errOut)
	}
	requireOnly(t, findEnvironmentNames(t, out), "kept")
	if strings.Contains(errOut, "bad") {
		t.Fatalf("nested explicit root under excluded folder produced issues: %s", errOut)
	}
}

func TestExcludeScanOmitsExcludedObservations(t *testing.T) {
	root := excludeRoot(t)
	outputDir := t.TempDir()
	out, errOut, err := runCLI(t, context.Background(), "scan", "--format", "json", "--output-dir", outputDir, "--exclude", "drop", "--exclude", "{cache,build}", root)
	if err != nil {
		t.Fatalf("scan with excludes error = %v\nstdout=%s\nstderr=%s", err, out, errOut)
	}
	var report struct {
		Observations []struct {
			Environment struct {
				Path string `json:"path"`
			} `json:"environment"`
		} `json:"observations"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("scan json does not decode: %v\n%s", err, out)
	}
	if len(report.Observations) != 1 || filepath.Base(report.Observations[0].Environment.Path) != "kept" {
		t.Fatalf("observations = %+v, want only kept", report.Observations)
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("output dir has %d entries, want 1 SBOM", len(entries))
	}
}

func TestExcludeLintExitsOneForKeptMetaOnly(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "kept")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "certifi.json"), []byte(canonicalPrefixRecord("certifi", "2020.1.1", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "history"), []byte("==> transaction <==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dropped := filepath.Join(root, "drop", "env", "conda-meta")
	if err := os.MkdirAll(dropped, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropped, "bad.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := executeLint(t, "--format", "json", "--exclude", "drop", root)
	if ExitCode(err) != 1 {
		t.Fatalf("lint exit = %d, want 1 for kept stale certifi; out=%s err=%v", ExitCode(err), out, err)
	}
	if strings.Contains(out, "bad.json") {
		t.Fatalf("excluded malformed record reached lint output: %s", out)
	}
}

func TestExcludeLintExcludedBadDoesNotMarkExitTwo(t *testing.T) {
	root := t.TempDir()
	venvFixture(t, root, "kept", true)
	venvFixture(t, filepath.Join(root, "build"), "bad", true)
	writeBrokenMetadata(t, filepath.Join(root, "build", "bad", "lib/python3.13/site-packages/demo-1.dist-info/METADATA"))
	out, err := executeLint(t, "--format", "json", "--rule", "ENV013", "--exclude", "build", root)
	if err != nil {
		t.Fatalf("lint exit error = %v (code %d)\n%s", err, ExitCode(err), out)
	}
	var report struct {
		Status     string `json:"status"`
		Inspection struct {
			Inspected int `json:"inspected"`
			Failed    int `json:"failed"`
		} `json:"inspection"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("lint json does not decode: %v\n%s", err, out)
	}
	if report.Status != "completed" || report.Inspection.Inspected != 1 || report.Inspection.Failed != 0 {
		t.Fatalf("status=%q inspected=%d failed=%d, want completed/1/0\n%s", report.Status, report.Inspection.Inspected, report.Inspection.Failed, out)
	}
}

func TestExcludeRejectsInvalidGlob(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"find", "--exclude", "", root},
		{"scan", "--exclude", "", root},
		{"lint", "--exclude", "", root},
		{"find", "--exclude", "[", root},
		{"scan", "--exclude", "a/[b", root},
		{"lint", "--exclude", "{unclosed", root},
	} {
		_, _, err := runCLI(t, context.Background(), args...)
		if ExitCode(err) != 2 || !strings.Contains(err.Error(), "invalid --exclude glob") {
			t.Fatalf("%v exit = %d err = %v, want 2 with invalid --exclude glob", args, ExitCode(err), err)
		}
	}
}

func TestExcludeRejectedBeforeFilesystemIO(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	outputDir := filepath.Join(t.TempDir(), "sboms")
	_, _, err := runCLI(t, context.Background(), "scan", "--exclude", "[", "--output-dir", outputDir, missing)
	if ExitCode(err) != 2 || !strings.Contains(err.Error(), "invalid --exclude glob") {
		t.Fatalf("exit = %d err = %v, want 2 with invalid --exclude glob", ExitCode(err), err)
	}
	if _, statErr := os.Stat(outputDir); statErr == nil {
		t.Fatal("malformed exclude created the output directory before validation")
	}
}

func TestExcludeListRulesRejectsFlag(t *testing.T) {
	_, _, err := runCLI(t, context.Background(), "lint", "--list-rules", "--exclude", "drop")
	if ExitCode(err) != 2 || !strings.Contains(err.Error(), "--list-rules cannot be combined with --exclude") {
		t.Fatalf("exit = %d err = %v, want 2 with list-rules conflict naming --exclude", ExitCode(err), err)
	}
}

func TestExcludeHelpDocumentsFlag(t *testing.T) {
	out, _, err := runCLI(t, context.Background(), "find", "--help")
	if err != nil {
		t.Fatalf("help error = %v", err)
	}
	if !strings.Contains(out, "--exclude") || !strings.Contains(out, "discovery") {
		t.Fatalf("help does not document --exclude: %s", out)
	}
}
