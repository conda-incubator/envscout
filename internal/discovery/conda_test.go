package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindConda(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "envs", "research", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "python-3.12-0.json"), []byte(`{"name":"python","version":"3.12"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "history"), []byte("# preamble\n==> 2026-01-01 00:00:00 <==\n+python\n==> 2026-01-02 00:00:00 <==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	badMeta := filepath.Join(root, "bad", "conda-meta")
	if err := os.MkdirAll(badMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badMeta, "bad.json"), []byte(`{"name":"python"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "envs", "research"), filepath.Join(root, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	progress := new(Progress)
	report, err := FindCondaWithProgress([]string{filepath.Join(root, "envs"), root, root}, progress)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 {
		t.Fatalf("environments = %+v, want one", report.Environments)
	}
	got := report.Environments[0]
	if got.Name != "research" || got.Path != filepath.Join(root, "envs", "research") || got.Revision == nil || *got.Revision != 1 {
		t.Fatalf("unexpected environment: %+v", got)
	}
	if len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "bad.json") {
		t.Fatalf("issues = %+v, want invalid metadata warning", report.Issues)
	}
	if got := progress.Folders.Load(); got != 6 {
		t.Fatalf("visited folders = %d, want 6 (overlapping roots counted once)", got)
	}
	if got := progress.Environments.Load(); got != 1 {
		t.Fatalf("found environments = %d, want 1", got)
	}
}

func TestFindCondaMissingHistory(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "fresh", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(`{"name":"pkg","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := FindCondaWithProgress([]string{root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Revision != nil || len(report.Issues) != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestFindCondaRejectsNonDirectoryRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := FindCondaWithProgress([]string{path}, nil); err == nil {
		t.Fatal("expected non-directory root to fail")
	}
	if err := os.Symlink(root, filepath.Join(root, "link")); err == nil {
		if _, err := FindCondaWithProgress([]string{filepath.Join(root, "link")}, nil); err == nil {
			t.Fatal("expected symlink root to fail")
		}
	}
}

func TestRevision(t *testing.T) {
	tests := []struct {
		name string
		data string
		want *int
	}{
		{"empty", "", nil},
		{"headerless", "# cmd: conda create\n", nil},
		{"fresh", "==> 2026-01-01 00:00:00 <==\n", intPtr(0)},
		{"two including empty change", "==> 2026-01-01 00:00:00 <==\n==> 2026-01-02 00:00:00 <==\n", intPtr(1)},
		{"nonheader", "==> <==\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := revisionFromReader(strings.NewReader(tt.data))
			if err != nil || (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Fatalf("revision = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func intPtr(value int) *int { return &value }

func TestHistoryReaderEnforcesBytesEvenIfFileGrows(t *testing.T) {
	_, err := revisionFromBoundedReader(strings.NewReader(strings.Repeat("==> transaction <==\n", 100)), 128)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("growing history escaped read bound: %v", err)
	}
}
