package evidence

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/inventory"
)

func FileID(filename string) string {
	filename = filepath.ToSlash(filename)
	if !strings.HasPrefix(filename, "/") {
		filename = "/" + filename
	}
	return (&url.URL{Scheme: "file", Path: filename}).String()
}

// CollectHost requires explicit roots and never invokes an external tool.
// Without requested collectors it only lists the root targets. With collectors,
// discovery returns candidate prefixes, which are validated through the conda-only
// inventory pathway before any of them counts as positive evidence.
func CollectHost(ctx context.Context, roots []string, req Request) (Snapshot, error) {
	snapshot := Snapshot{Started: time.Now().UTC(), Targets: []Target{}, Issues: []Issue{}}
	if len(roots) == 0 {
		return snapshot, fmt.Errorf("lint requires explicit directory roots")
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	if len(req.Capabilities) == 0 {
		seen := make(map[string]bool)
		for _, input := range roots {
			abs, err := filepath.Abs(input)
			if err != nil {
				return snapshot, err
			}
			info, err := os.Lstat(abs)
			if err != nil || !info.IsDir() {
				return snapshot, fmt.Errorf("lint root must be a real directory: %s", abs)
			}
			key := abs
			if runtime.GOOS == "windows" {
				key = strings.ToLower(key)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			snapshot.Targets = append(snapshot.Targets, Target{ID: FileID(abs), Kind: "dir", Input: abs, Roots: []string{abs}, Prefixes: []Prefix{}, Coverage: map[string]string{}, Issues: []Issue{}})
		}
		sort.Slice(snapshot.Targets, func(i, j int) bool { return snapshot.Targets[i].ID < snapshot.Targets[j].ID })
		return snapshot, nil
	}
	readHistory := Requested(req, "history")
	report, discoveryErr := discovery.Find(ctx, roots, readHistory)
	for _, issue := range report.Issues {
		capability := "prefixes"
		if filepath.Base(issue.Path) == "history" {
			capability = "history"
		}
		snapshot.Issues = append(snapshot.Issues, Issue{Capability: capability, Path: issue.Path, Message: issue.Error})
	}
	readHistoryCoverage := NotCollected
	if readHistory {
		readHistoryCoverage = Complete
	}
	// Discovery candidates are not proof of conda metadata. Each prefix is validated
	// through inventory.CondaRecords. Validated targets accumulate in snapshot so every
	// return path keeps them: a cancellation or later error never drops earlier evidence.
	var validated []Target
	var cancelErr error
	for _, env := range report.Environments {
		if err := ctx.Err(); err != nil {
			cancelErr = err
			break
		}
		records, err := condaRecordsForPrefix(ctx, env.Path)
		if ctxErr := ctx.Err(); ctxErr != nil {
			cancelErr = ctxErr
		}
		if err != nil {
			snapshot.Issues = append(snapshot.Issues, Issue{Capability: "prefixes", Path: env.Path, Message: err.Error()})
		}
		if len(records) == 0 {
			if err == nil {
				snapshot.Issues = append(snapshot.Issues, Issue{Capability: "prefixes", Path: env.Path, Message: "no valid conda package metadata; prefix not counted"})
			}
		} else {
			validated = append(validated, Target{ID: FileID(env.Path), Kind: "dir", Input: env.Path, Roots: report.Roots,
				Prefixes: []Prefix{{Path: env.Path, Revision: env.Revision}}, Coverage: map[string]string{}, Issues: []Issue{}})
		}
		if cancelErr != nil {
			break
		}
	}
	snapshot.Targets = validated
	if cancelErr != nil {
		discoveryErr = errors.Join(discoveryErr, cancelErr)
	}
	// Final coverage is computed once, after every issue is known.
	coverage := Complete
	if discoveryErr != nil || cancelErr != nil {
		coverage = Partial
	}
	for _, issue := range snapshot.Issues {
		if issue.Capability == "prefixes" {
			coverage = Partial
		}
	}
	historyCoverage := readHistoryCoverage
	for _, issue := range snapshot.Issues {
		if issue.Capability == "history" {
			historyCoverage = Partial
		}
	}
	for i := range snapshot.Targets {
		target := &snapshot.Targets[i]
		target.Coverage["prefixes"] = coverage
		target.Coverage["history"] = historyCoverage
		if readHistory && (discoveryErr != nil || cancelErr != nil) {
			target.Coverage["history"] = Partial
		}
		if Requested(req, "project-association") {
			target.Coverage["project-association"] = Complete
		}
	}
	// Project association uses the final validated list and runs once, only when the
	// collection finished without cancellation.
	if req.Project != "" && discoveryErr == nil && cancelErr == nil {
		if len(snapshot.Targets) != 1 {
			return snapshot, errors.Join(discoveryErr, fmt.Errorf("--project requires exactly one validated prefix for an explicit association"))
		}
		if Requested(req, "project-association") {
			project, issue, err := collectProject(req.Project)
			if err != nil {
				return snapshot, err
			}
			target := &snapshot.Targets[0]
			target.Project = project
			if issue != nil {
				target.Issues = append(target.Issues, *issue)
				target.Coverage["project-association"] = Partial
			}
		}
	}
	if len(snapshot.Targets) == 0 && len(report.Roots) > 0 {
		snapshot.Targets = append(snapshot.Targets, Target{ID: FileID(report.Roots[0]), Kind: "dir", Input: report.Roots[0], Roots: report.Roots,
			Prefixes: []Prefix{}, Coverage: map[string]string{"prefixes": coverage}, Issues: []Issue{}})
	}
	return snapshot, errors.Join(discoveryErr, cancelErr)
}

// condaRecordsForPrefix returns the valid conda records of one candidate prefix via
// the conda-only inventory pathway. The source is rooted at the prefix's conda-meta
// directory with the prefix as its virtual base, so Syft indexes only that directory
// and its records keep prefix-relative paths matching the cataloger's
// **/conda-meta/*.json glob. Nested environments and unrelated subtrees are never
// visited. Records parsed before an error are returned with it. The source is owned
// here and always closed.
func condaRecordsForPrefix(ctx context.Context, prefix string) ([]pkg.Package, error) {
	metadata := filepath.Join(prefix, "conda-meta")
	entries, err := os.ReadDir(metadata)
	if err != nil {
		return nil, err
	}
	var exclude []string
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink != 0 {
			// Quote glob metacharacters: exclusions are patterns, filenames are not.
			name := strings.NewReplacer("[", "\\[", "]", "\\]", "*", "\\*", "?", "\\?").Replace(entry.Name())
			exclude = append(exclude, "./"+name)
		}
	}
	src, err := directorysource.New(directorysource.Config{Path: metadata, Base: prefix, Exclude: source.ExcludeConfig{Paths: exclude}})
	if err != nil {
		return nil, fmt.Errorf("open conda-meta for %s: %w", prefix, err)
	}
	records, err := inventory.CondaRecords(ctx, src, source.SquashedScope)
	return records, errors.Join(err, src.Close())
}

// The association is supplied by the caller. Presence of a lock is not proof of
// manifest or installation synchronization; those require separate verifiers.
func collectProject(input string) (*Project, *Issue, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, nil, err
	}
	if info, err := os.Lstat(abs); err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("--project must name a real directory")
	}
	// os.OpenRoot confines every lock lookup to the project directory, so a lock
	// name that is a symlink or points outside it can never be read.
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	p := &Project{Path: abs, Associated: true, Reason: "explicit user association; no resolved lock found"}
	for _, name := range []string{"pixi.lock", "conda-lock.yaml", "conda-lock.yml", "uv.lock", "poetry.lock", "Pipfile.lock"} {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || info.Size() == 0 {
			return p, &Issue{Capability: "project-association", Path: filepath.Join(abs, name), Message: "lock candidate is inaccessible, empty, linked or oversized"}, nil
		}
		p.LockPath = filepath.Join(abs, name)
		p.Reason = "lock candidate present; format/synchronization verifier unavailable"
		return p, nil, nil
	}
	return p, nil, nil
}
