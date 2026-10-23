package discovery

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/anaconda/envscout/internal/testimage"
)

func envPaths(report Report) map[string]bool {
	out := map[string]bool{}
	for _, e := range report.Environments {
		out[e.Path] = true
	}
	return out
}

// An explicit child root under a parent's pruned name must still be walked, and the
// environment beneath it reported exactly once, with both requested roots preserved.
func TestNestedExplicitRootUnderPrunedParent(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "site-packages", "tools")
	env := filepath.Join(child, "env")
	makePrefix(t, env)
	report, err := Find(context.Background(), []string{parent, child}, false)
	if err != nil {
		t.Fatal(err)
	}
	paths := envPaths(report)
	if len(report.Environments) != 1 || !paths[env] {
		t.Fatalf("nested explicit root under site-packages lost its environment: %+v", report.Environments)
	}
	if len(report.Roots) != 2 {
		t.Fatalf("requested roots not preserved: %+v", report.Roots)
	}
}

// Explicit pkgcache root under a parent that would otherwise prune it is honored.
func TestExplicitPkgsRootOverridesParentPrune(t *testing.T) {
	parent := t.TempDir()
	cache := filepath.Join(parent, "pkgs")
	writeFile(t, filepath.Join(cache, "urls.txt"), "https://example.invalid/x\n")
	env := filepath.Join(cache, "env")
	makePrefix(t, env)
	report, err := Find(context.Background(), []string{cache}, false)
	if err != nil || !envPaths(report)[env] {
		t.Fatalf("explicit pkgs root honored=%v err=%v: %+v", envPaths(report)[env], err, report.Environments)
	}
}

// A generic pkgs directory must not be falsely pruned by an arbitrary info/ directory,
// nor by a conda-meta FILE beside it (that is not a conda-meta directory).
func TestGenericPkgsNotFalselyPruned(t *testing.T) {
	root := t.TempDir()
	genericInfo := filepath.Join(root, "project", "pkgs", "env")
	makePrefix(t, genericInfo)
	writeFile(t, filepath.Join(root, "project", "pkgs", "info", "readme.txt"), "x")
	fileSibling := filepath.Join(root, "other", "pkgs", "env")
	makePrefix(t, fileSibling)
	writeFile(t, filepath.Join(root, "other", "conda-meta"), "not a directory")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	paths := envPaths(report)
	if !paths[genericInfo] || !paths[fileSibling] {
		t.Fatalf("generic pkgs falsely pruned: %+v", report.Environments)
	}
}

// A real package cache (conda-meta directory beside it) is pruned.
func TestConfirmedPkgsCachePruned(t *testing.T) {
	root := t.TempDir()
	// A conda-meta DIRECTORY beside pkgs confirms the package cache, so it is pruned.
	makePrefix(t, filepath.Join(root, "conda", "pkgs", "cached"))
	if err := os.MkdirAll(filepath.Join(root, "conda", "conda-meta"), 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if envPaths(report)[filepath.Join(root, "conda", "pkgs", "cached")] {
		t.Fatalf("confirmed cache was scanned: %+v", report.Environments)
	}
}

// A symlinked history must not be read as evidence: it yields an issue and no revision.
func TestSymlinkedHistoryIsIssueNotRevision(t *testing.T) {
	root := t.TempDir()
	env := filepath.Join(root, "env")
	writeFile(t, filepath.Join(env, "conda-meta", "pkg.json"), `{"name":"p","version":"1"}`)
	target := filepath.Join(t.TempDir(), "hist")
	writeFile(t, target, "==> a <==\n")
	if err := os.Symlink(target, filepath.Join(env, "conda-meta", "history")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report, err := Find(context.Background(), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Revision != nil {
		t.Fatalf("symlinked history produced a revision: %+v", report.Environments)
	}
	if len(report.Issues) != 1 {
		t.Fatalf("symlinked history not reported: %+v", report.Issues)
	}
}

// Image: a link-resolved record is not evidence even when its target is a regular file.
func TestImageLinkedRecordRejected(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "real/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "alias", Type: tar.TypeSymlink, Link: "real"},
	})
	report, err := FindImage(context.Background(), img, false)
	if err != nil {
		t.Fatal(err)
	}
	if !envPathsEqual(report, "/real") {
		t.Fatalf("expected only the direct /real prefix, got %+v", report.Environments)
	}
	for _, e := range report.Environments {
		if e.Path == "/alias" {
			t.Fatalf("link-resolved record produced an environment: %+v", report.Environments)
		}
	}
}

func envPathsEqual(report Report, want ...string) bool {
	if len(report.Environments) != len(want) {
		return false
	}
	for i, e := range report.Environments {
		if e.Path != want[i] {
			return false
		}
	}
	return true
}
