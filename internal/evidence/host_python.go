package evidence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Index the direct distribution metadata used for identity and ownership, not
// application payload or nested license contents. This resolver is for lint,
// not the full SBOM catalog, and application trees are never entered.
func indexHostPython(ctx context.Context, root *os.Root, installation string, r *hostFileResolver, target *Target, visited *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := hostLstat(root, installation); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	dir, err := root.Open(installation)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	entries, readErr := dir.ReadDir(hostEntryLimit + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		hostIssue(target, "python-distributions", filepath.Join(r.base, installation), "Python site-packages could not be enumerated")
		return nil
	}
	if len(entries) > hostEntryLimit {
		hostIssue(target, "python-distributions", filepath.Join(r.base, installation), fmt.Sprintf("Python site-packages entry limit exceeded (%d)", hostEntryLimit))
		entries = entries[:hostEntryLimit]
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		*visited++
		if *visited > hostPathLimit {
			hostIssue(target, "python-distributions", filepath.Join(r.base, installation), "host traversal path limit exceeded")
			return nil
		}
		name := entry.Name()
		rel := filepath.Join(installation, name)
		lower := strings.ToLower(name)
		isDist := strings.HasSuffix(lower, ".dist-info") || strings.HasSuffix(lower, ".egg-info")
		if !isDist {
			continue
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			hostIssue(target, "python-distributions", filepath.Join(r.base, rel), "linked Python evidence is not followed")
			continue
		}
		if !entry.IsDir() {
			if strings.HasSuffix(lower, ".egg-info") && entry.Type().IsRegular() {
				indexHostPythonFile(r, target, rel, entry)
			}
			continue
		}
		if err := indexHostPythonEntry(ctx, root, rel, r, target, visited); err != nil {
			return err
		}
	}
	return nil
}

// indexHostPythonEntry records the direct regular-file children of one
// distribution directory. Nested directories are not descended.
func indexHostPythonEntry(ctx context.Context, root *os.Root, rel string, r *hostFileResolver, target *Target, visited *int) error {
	if _, err := hostLstat(root, rel); err != nil {
		hostIssue(target, "python-distributions", filepath.Join(r.base, rel), "Python distribution directory is unavailable or linked")
		return nil
	}
	dir, err := root.Open(rel)
	if err != nil {
		hostIssue(target, "python-distributions", filepath.Join(r.base, rel), "Python distribution directory could not be opened")
		return nil
	}
	defer func() { _ = dir.Close() }()
	children, readErr := dir.ReadDir(hostEntryLimit + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		hostIssue(target, "python-distributions", filepath.Join(r.base, rel), "Python distribution directory could not be enumerated")
		return nil
	}
	if len(children) > hostEntryLimit {
		hostIssue(target, "python-distributions", filepath.Join(r.base, rel), fmt.Sprintf("Python distribution entry limit exceeded (%d)", hostEntryLimit))
		children = children[:hostEntryLimit]
	}
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return err
		}
		*visited++
		if *visited > hostPathLimit {
			hostIssue(target, "python-distributions", filepath.Join(r.base, rel), "host traversal path limit exceeded")
			return nil
		}
		if child.Type()&fs.ModeSymlink != 0 {
			hostIssue(target, "python-distributions", filepath.Join(r.base, rel, child.Name()), "linked Python evidence is not followed")
			continue
		}
		if child.Type().IsRegular() {
			indexHostPythonFile(r, target, filepath.Join(rel, child.Name()), child)
		} else if strings.EqualFold(child.Name(), "METADATA") || strings.EqualFold(child.Name(), "PKG-INFO") {
			hostIssue(target, "python-distributions", filepath.Join(r.base, rel, child.Name()), "Python distribution metadata is not a regular file")
		}
	}
	return nil
}

func indexHostPythonFile(r *hostFileResolver, target *Target, rel string, entry fs.DirEntry) {
	info, err := entry.Info()
	if err != nil {
		hostIssue(target, "python-distributions", filepath.Join(r.base, rel), "Python file metadata unavailable")
		return
	}
	name := filepath.FromSlash(rel)
	r.files[name] = info
	r.paths = append(r.paths, name)
}
