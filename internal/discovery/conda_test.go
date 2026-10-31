package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func makePrefix(t *testing.T, prefix string) {
	t.Helper()
	writeFile(t, filepath.Join(prefix, "conda-meta", "package.json"), `{"name":"demo","version":"1"}`)
}

func TestFindRecognizesEnvironmentAndHistory(t *testing.T) {
	root := t.TempDir()
	env := filepath.Join(root, "envs", "research")
	writeFile(t, filepath.Join(env, "conda-meta", "python-3.12-0.json"), `{"name":"python","version":"3.12"}`)
	writeFile(t, filepath.Join(env, "conda-meta", "history"), "# preamble\n==> 2026-01-01 00:00:00 <==\n+python\n==> 2026-01-02 00:00:00 <==\n")
	report, err := Find(context.Background(), []string{filepath.Join(root, "envs"), root, root}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 {
		t.Fatalf("environments = %+v, want one", report.Environments)
	}
	got := report.Environments[0]
	if got.Name != "research" || got.Path != env || got.Revision == nil || *got.Revision != 1 {
		t.Fatalf("unexpected environment: %+v", got)
	}
	if len(report.Roots) != 2 || report.Roots[0] != root {
		t.Fatalf("requested roots not preserved in order: %+v", report.Roots)
	}
}

func TestDiscoveryIssuesPreserveAccessErrorClassification(t *testing.T) {
	report := newReport(ModeRoots)
	col := newCollector(&report)
	col.addIssue("denied", fmt.Errorf("enumerate: %w", os.ErrPermission))
	col.addRecordedIssue(issueFromError("marker", &os.PathError{Op: "open", Path: "pyvenv.cfg", Err: os.ErrPermission}))
	col.addIssue("invalid", errors.New("history is not a regular file"))
	if len(report.Issues) != 3 || !report.Issues[0].AccessDenied || !report.Issues[1].AccessDenied || report.Issues[2].AccessDenied {
		t.Fatalf("permission classification must survive conversion without parsing strings: %+v", report.Issues)
	}
}

// A regular .json filename is enough to be a candidate; content is not decoded.
func TestFindCandidateIsFilenameOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "bad", "conda-meta", "bad.json"), `{"name":"python"}`)
	writeFile(t, filepath.Join(root, "garbage", "conda-meta", "x.json"), `not json at all`)
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 2 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, want two candidates and no issues", report)
	}
}

func TestFindRequiresRegularRecord(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "noRecord", "conda-meta")
	if err := os.MkdirAll(filepath.Join(meta, "subdir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(meta, "readme.txt"), "x")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("directory named *.json or non-json file treated as a record: %+v", report.Environments)
	}
}

func TestFindSymlinkedRecordIsNotEvidence(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	writeFile(t, outside, `{"name":"x","version":"1"}`)
	meta := filepath.Join(root, "linked", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(meta, "pkg.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("symlinked record confirmed a prefix: %+v", report.Environments)
	}
}

func TestFindMissingHistoryIsNil(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "fresh", "conda-meta", "pkg.json"), `{"name":"pkg","version":"1"}`)
	report, err := Find(context.Background(), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Revision != nil || len(report.Issues) != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestFindSkipsHistoryWhenNotRequested(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "env", "conda-meta", "pkg.json"), `{"name":"pkg","version":"1"}`)
	writeFile(t, filepath.Join(root, "env", "conda-meta", "history"), "==> a <==\n")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Revision != nil {
		t.Fatalf("history read when not requested: %+v", report.Environments)
	}
}

func TestFindRejectsNonDirectoryRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeFile(t, path, "hello")
	if _, err := Find(context.Background(), []string{path}, false); err == nil {
		t.Fatal("expected non-directory root to fail")
	}
	if err := os.Symlink(root, filepath.Join(root, "link")); err == nil {
		if _, err := Find(context.Background(), []string{filepath.Join(root, "link")}, false); err == nil {
			t.Fatal("expected symlink root to fail")
		}
	}
}

func TestFindNilSlicesNeverEmitted(t *testing.T) {
	report, err := Find(context.Background(), []string{t.TempDir()}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Environments == nil || report.Issues == nil || report.Hints == nil || report.Roots == nil {
		t.Fatalf("report arrays must be non-nil: %+v", report)
	}
}

func TestFindPrunesNamedDirectories(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".git", "node_modules", "__pycache__", "site-packages"} {
		makePrefix(t, filepath.Join(root, name, "env"))
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("pruned directories produced environments: %+v", report.Environments)
	}
}

func TestFindExplicitRootIsNeverPruned(t *testing.T) {
	root := t.TempDir()
	site := filepath.Join(root, "site-packages")
	makePrefix(t, filepath.Join(site, "nested"))
	report, err := Find(context.Background(), []string{site}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Path != filepath.Join(site, "nested") {
		t.Fatalf("explicit site-packages root was pruned: %+v", report.Environments)
	}
}

func TestFindPrunesMacOSCloudDirectories(t *testing.T) {
	home := knownTempDir(t)
	t.Setenv("HOME", home)
	cloudEnvs := []string{
		filepath.Join(home, "Library", "CloudStorage", "Provider", "env"),
		filepath.Join(home, "Library", "Mobile Documents", "com~apple~CloudDocs", "env"),
	}
	keptEnvs := []string{
		filepath.Join(home, "Library", "Caches", "env"),
		filepath.Join(home, "Library", "CloudStorage-local", "env"),
		filepath.Join(home, "code", "CloudStorage", "env"),
		filepath.Join(home, "code", "Library", "CloudStorage", "env"),
		filepath.Join(home, "code", "Library", "Mobile Documents", "env"),
	}
	for _, env := range append(cloudEnvs, keptEnvs...) {
		makePrefix(t, env)
	}
	report, err := Find(context.Background(), []string{home}, false)
	if err != nil || len(report.Issues) != 0 {
		t.Fatalf("find = %+v, %v", report, err)
	}
	paths := envPaths(report)
	for _, env := range keptEnvs {
		if !paths[env] {
			t.Errorf("ordinary folder was pruned: %s", env)
		}
	}
	for _, env := range cloudEnvs {
		if got, want := paths[env], runtime.GOOS != "darwin"; got != want {
			t.Errorf("cloud environment found = %t, want %t: %s", got, want, env)
		}
	}
}

func TestFindCloudExplicitRootsOverrideParentPrune(t *testing.T) {
	home := knownTempDir(t)
	t.Setenv("HOME", home)
	for _, name := range []string{"CloudStorage", "Mobile Documents"} {
		cloud := filepath.Join(home, "Library", name)
		env := filepath.Join(cloud, "Provider", "env")
		makePrefix(t, env)
		for _, explicit := range []string{cloud, filepath.Dir(env)} {
			report, err := Find(context.Background(), []string{home, explicit}, false)
			if err != nil || len(report.Issues) != 0 || !envPaths(report)[env] {
				t.Fatalf("explicit cloud root %s was pruned: %+v, %v", explicit, report, err)
			}
		}
	}
}

func TestFindCloudDirectoriesPrunedBeforeEnumeration(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS cloud directory pruning")
	}
	home := knownTempDir(t)
	t.Setenv("HOME", home)
	library := filepath.Join(home, "Library")
	for _, name := range []string{"CloudStorage", "Mobile Documents"} {
		makePrefix(t, filepath.Join(library, name, "Provider", "env"))
	}
	var p Progress
	report, err := Find(WithProgress(context.Background(), &p), []string{library}, false)
	// Only Library and the two pruned entries are examined; no children are opened.
	if err != nil || len(report.Issues) != 0 || len(report.Environments) != 0 || p.Folders.Load() != 3 {
		t.Fatalf("cloud trees were traversed: report=%+v folders=%d err=%v", report, p.Folders.Load(), err)
	}
}

// A generic pkgs directory with no conda sibling or markers is ordinary content and is
// scanned; a real conda package cache is skipped.
func TestFindPkgsIsPrunedOnlyWhenConfirmed(t *testing.T) {
	root := t.TempDir()
	realEnv := filepath.Join(root, "project", "pkgs", "env")
	makePrefix(t, realEnv)
	cacheEnv := filepath.Join(root, "conda", "pkgs", "cached")
	makePrefix(t, cacheEnv)
	writeFile(t, filepath.Join(root, "conda", "conda-meta", "placeholder.json"), `{"name":"x","version":"1"}`)
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, env := range report.Environments {
		got[env.Path] = true
	}
	want := []string{realEnv, filepath.Join(root, "conda")}
	if len(got) != len(want) || !got[want[0]] || !got[want[1]] || got[filepath.Join(cacheEnv)] {
		t.Fatalf("pkgs confirmation mismatch: got %v, want %v", got, want)
	}
}

func TestFindPkgsWithPackageMarkersIsCache(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "pkgs")
	writeFile(t, filepath.Join(cache, "urls.txt"), "https://example.invalid/x\n")
	makePrefix(t, filepath.Join(cache, "pkg-1"))
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("confirmed package cache was scanned: %+v", report.Environments)
	}
}

func TestFindCancellationKeepsPartialSortedResults(t *testing.T) {
	root := t.TempDir()
	makePrefix(t, filepath.Join(root, "a"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Find(ctx, []string{root}, false)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if report.Environments == nil || report.Issues == nil {
		t.Fatalf("partial report arrays must be non-nil: %+v", report)
	}
}

func TestRevisionParsing(t *testing.T) {
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
			got, err := historyRevision(context.Background(), strings.NewReader(tt.data))
			if err != nil || (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Fatalf("revision = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestHistoryReaderEnforcesBytesEvenIfFileGrows(t *testing.T) {
	_, err := boundedHistoryRevision(context.Background(), strings.NewReader(strings.Repeat("==> transaction <==\n", maxHistoryBytes)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("growing history escaped read bound: %v", err)
	}
}

func TestHistoryReaderHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := boundedHistoryRevision(ctx, strings.NewReader("==> a <==\n")); err == nil {
		t.Fatal("cancelled history read must fail")
	}
}

func intPtr(value int) *int { return &value }
