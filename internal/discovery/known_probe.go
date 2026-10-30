package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// prober inspects candidates under one shared budget. Every prefix probe, including the
// children of a container, spends budget; exhaustion stops the probe with one issue.
type prober struct {
	ctx       context.Context
	root      string
	col       *collector
	progress  *Progress // nil when instrumentation is disabled
	seen      map[string]bool
	budget    int
	exhausted bool
}

// examined records one directory that passed its usable check. Nil progress is a no-op.
func (p *prober) examined() {
	if p.progress != nil {
		p.progress.Folders.Add(1)
	}
}

// probeKnown runs every candidate through one prober and returns the per-source summary.
// Skipped counts candidates that were not probed (absent, rejected, or after cancellation).
func probeKnown(ctx context.Context, root string, candidates []candidate, col *collector) []HintSummary {
	p := &prober{ctx: ctx, root: root, col: col, progress: col.progress, seen: map[string]bool{}, budget: maxHintCandidates}
	stats := map[string]HintSummary{}
	for _, c := range candidates {
		s := stats[c.source]
		s.Source = c.source
		if ctx.Err() == nil && p.hint(c) {
			s.Checked++
		} else {
			s.Skipped++
		}
		stats[c.source] = s
	}
	out := make([]HintSummary, 0, len(stats))
	for _, s := range stats {
		out = append(out, s)
	}
	return out
}

// hint probes one candidate and reports whether it was a usable directory to inspect.
// Configured candidates report their own missing or non-directory state here; the container
// owner reports its own missing state, so no second stat is needed for containers.
func (p *prober) hint(c candidate) bool {
	if c.kind == kindContainer {
		return p.container(c.path, c.configured)
	}
	if !p.isRealDir(c.path, c.configured, "hint is not a directory") {
		return false
	}
	p.examined()
	if c.kind == kindPrefix {
		p.prefix(c.path)
		return true
	}
	if _, err := os.Lstat(filepath.Join(c.path, "conda-meta")); err == nil {
		p.prefix(c.path)
	}
	p.container(filepath.Join(c.path, "envs"), false)
	return true
}

// isRealDir reports whether path is a real (non-symlink) directory, recording the exact issue
// otherwise. A missing path is only an issue when configured.
func (p *prober) isRealDir(path string, configured bool, typeError string) bool {
	if excluded(p.ctx, p.root, path) {
		return false
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if configured {
			p.col.addIssue(path, fmt.Errorf("configured location not found"))
		}
		return false
	case err != nil:
		p.col.addIssue(path, err)
		return false
	case info.Mode()&fs.ModeSymlink != 0:
		p.col.addIssue(path, fmt.Errorf("symlink in hint path"))
		return false
	case !info.IsDir():
		if configured {
			p.col.addIssue(path, errors.New(typeError))
		}
		return false
	}
	return true
}

// prefix inspects one prefix through its own os.Root, charging the shared budget.
func (p *prober) prefix(path string) {
	if p.seen[path] || p.ctx.Err() != nil || excluded(p.ctx, p.root, path) {
		return
	}
	p.seen[path] = true
	if p.budget == 0 {
		p.exhaust(path)
		return
	}
	p.budget--
	p.examined()
	root, err := os.OpenRoot(path)
	if err != nil {
		p.col.addIssue(path, err)
		return
	}
	defer func() { _ = root.Close() }()
	env, valid, issues := inspectScopedPrefix(p.ctx, root, path, true)
	for _, issue := range issues {
		p.col.addRecordedIssue(issue)
	}
	if valid {
		p.col.addEnvironment(env)
	}
}

// container inspects each one-level child directory of a container as a prefix. It owns the
// existence and type checks of its directory. configured reports a missing directory as an
// issue. It returns false when the directory was not usable.
func (p *prober) container(dir string, configured bool) bool {
	if p.seen["container:"+dir] || p.ctx.Err() != nil {
		return false
	}
	p.seen["container:"+dir] = true
	if !p.isRealDir(dir, configured, "container is not a real directory") {
		return false
	}
	p.examined()
	root, err := os.OpenRoot(dir)
	if err != nil {
		p.col.addIssue(dir, err)
		return false
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(".")
	if err != nil {
		p.col.addIssue(dir, err)
		return false
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(maxContainerEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		p.col.addIssue(dir, err)
		return false
	}
	if len(entries) > maxContainerEntries {
		p.col.addIssue(dir, fmt.Errorf("known-location container exceeds %d entries", maxContainerEntries))
		entries = entries[:maxContainerEntries]
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	for _, e := range entries {
		if p.ctx.Err() != nil || p.exhausted {
			break
		}
		if e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
			p.prefix(filepath.Join(dir, e.Name()))
		}
	}
	return true
}

// exhaust records the candidate-limit stop once, however many probes it cuts short.
func (p *prober) exhaust(path string) {
	if !p.exhausted {
		p.exhausted = true
		p.col.addIssue(path, fmt.Errorf("known-location limit of %d candidates reached; further locations not probed", maxHintCandidates))
	}
}
