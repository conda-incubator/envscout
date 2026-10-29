package discovery

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlievieth/fastwalk"
)

// prunedNames are directory names that never hold a conda prefix worth reporting.
// "pkgs" is deliberately absent: it is a generic name, so isPackageCache decides.
var prunedNames = map[string]bool{
	".git":          true,
	"node_modules":  true,
	"__pycache__":   true,
	"site-packages": true,
}

// systemPaths are absolute OS-owned trees that never contain conda prefixes.
var systemPaths = []string{"/proc", "/sys", "/dev"}

// Find searches explicit roots for conda prefixes. Every distinct requested root is walked
// independently: a nested root is never skipped because a parent covers it, since the
// parent walk may prune or cross a device boundary that the nested root is explicitly
// asked to bypass. readHistory controls whether conda-meta/history is read for revisions.
func Find(ctx context.Context, roots []string, readHistory bool) (Report, error) {
	report := newReport(ModeRoots)
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if len(roots) == 0 {
		return report, fmt.Errorf("at least one root is required for a full walk")
	}
	seen := make(map[string]bool)
	for _, root := range roots {
		path, err := filepath.Abs(root)
		if err != nil {
			return report, fmt.Errorf("root %q: %w", root, err)
		}
		if !seen[path] {
			seen[path] = true
			report.Roots = append(report.Roots, path)
		}
	}
	sort.Strings(report.Roots)

	var included []string
	for _, root := range report.Roots {
		if err := ctx.Err(); err != nil {
			break
		}
		if excluded(ctx, root, root, report.Roots...) {
			continue
		}
		info, err := os.Lstat(root)
		if err != nil {
			return report, fmt.Errorf("root %q: %w", root, err)
		}
		if !info.IsDir() {
			return report, fmt.Errorf("root %q: must be a directory, not a file or symlink", root)
		}
		included = append(included, root)
	}
	col := newCollector(&report)
	col.progress = progressFrom(ctx)
	for _, root := range included {
		if err := ctx.Err(); err != nil {
			break
		}
		if err := walkRoot(ctx, root, report.Roots, col, readHistory); err != nil {
			col.addIssue(root, err)
		}
	}
	sortReport(&report)
	return report, ctx.Err()
}

// walkRoot walks one explicit root. The root is opened once as an os.Root and every
// candidate prefix is read through a Root opened for that prefix only, so symlinks
// pointing outside a prefix cannot be followed and no ancestor is re-resolved per hit.
func walkRoot(ctx context.Context, root string, roots []string, col *collector, readHistory bool) error {
	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = rootDir.Close() }()
	rootInfo, err := rootDir.Stat(".")
	if err != nil {
		return err
	}
	device, hasDevice := newRootDevice(root, rootInfo)

	// Zero NumWorkers selects fastwalk.DefaultNumWorkers, which is tuned for the library's
	// I/O pattern; overriding it with a generic CPU count would not preserve that tuning.
	conf := &fastwalk.Config{Follow: false}
	return fastwalk.Walk(conf, root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Prune before recording walk errors or reading environment markers.
		folder := path
		if entry != nil && !entry.IsDir() {
			folder = filepath.Dir(path)
		}
		if excluded(ctx, root, folder, roots...) {
			return fastwalk.SkipDir
		}
		if walkErr != nil {
			col.addIssue(path, walkErr)
			return nil
		}
		if !entry.IsDir() {
			if entry.Name() == pyvenvMarker {
				// A marker is evidence for its parent prefix; the parent decides the kind.
				return inspectMarkerPrefix(ctx, rootDir, root, filepath.Dir(path), readHistory, col)
			}
			return nil
		}
		if col.progress != nil {
			col.progress.Folders.Add(1)
		}
		if path != root {
			if pruneDirectory(path, entry.Name()) {
				return fastwalk.SkipDir
			}
			if hasDevice {
				var info fs.FileInfo
				if device.needsInfo(path) {
					var err error
					info, err = entry.Info()
					if err != nil {
						col.addIssue(path, err)
						return fastwalk.SkipDir
					}
				}
				if !device.same(path, info) {
					return fastwalk.SkipDir
				}
			}
			if entry.Name() == "pkgs" && isPackageCache(filepath.Dir(path), path) {
				return fastwalk.SkipDir
			}
		}
		if entry.Name() != "conda-meta" {
			return nil
		}
		prefix := filepath.Dir(path)
		env, valid, issues := inspectPrefix(ctx, rootDir, root, prefix, readHistory)
		for _, issue := range issues {
			col.addRecordedIssue(issue)
		}
		if valid {
			col.addEnvironment(env)
		}
		return fastwalk.SkipDir
	})
}

// pruneDirectory reports whether a directory is excluded by name or by system path.
// Callers never apply it to an explicit root.
func pruneDirectory(path, name string) bool {
	if prunedNames[name] {
		return true
	}
	for _, sys := range systemPaths {
		if path == sys || strings.HasPrefix(path, sys+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// isPackageCache reports whether pkgs (a child of parent) is a conda package cache.
// It is confirmed only by a conda-meta DIRECTORY beside it, or by a regular urls.txt
// inside it. Generic directories named pkgs, including ones holding an info/ directory,
// are never pruned by name alone, and no package subdirectory is read.
func isPackageCache(parent, pkgs string) bool {
	if info, err := os.Lstat(filepath.Join(parent, "conda-meta")); err == nil && info.IsDir() {
		return true
	}
	info, err := os.Lstat(filepath.Join(pkgs, "urls.txt"))
	return err == nil && info.Mode().IsRegular()
}

// inspectMarkerPrefix inspects the prefix that owns a pyvenv.cfg marker found by the walk
// and records its result. The prefix is always decided by inspectScopedPrefix, so a
// conda-meta and a pyvenv.cfg in one directory resolve identically from either callback.
func inspectMarkerPrefix(ctx context.Context, rootDir *os.Root, root, prefix string, readHistory bool, col *collector) error {
	env, valid, issues := inspectPrefix(ctx, rootDir, root, prefix, readHistory)
	for _, issue := range issues {
		col.addRecordedIssue(issue)
	}
	if valid {
		col.addEnvironment(env)
	}
	return nil
}

// inspectPrefix validates a candidate prefix through an os.Root scoped to the prefix.
// The root is opened from the explicit root by relative path, not by walking ancestors.
func inspectPrefix(ctx context.Context, rootDir *os.Root, root, prefix string, readHistory bool) (Environment, bool, []Issue) {
	rel, err := filepath.Rel(root, prefix)
	if err != nil {
		return Environment{}, false, []Issue{issueFromError(prefix, err)}
	}
	scope, err := rootDir.OpenRoot(rel)
	if err != nil {
		return Environment{}, false, []Issue{issueFromError(prefix, err)}
	}
	defer func() { _ = scope.Close() }()
	return inspectScopedPrefix(ctx, scope, prefix, readHistory)
}
