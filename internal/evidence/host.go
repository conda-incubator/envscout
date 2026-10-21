package evidence

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/anaconda/envscout/internal/discovery"
)

func FileID(filename string) string {
	filename = filepath.ToSlash(filename)
	if !strings.HasPrefix(filename, "/") {
		filename = "/" + filename
	}
	return (&url.URL{Scheme: "file", Path: filename}).String()
}

// CollectHost requires explicit roots and never runs an inventory or tool process.
func CollectHost(ctx context.Context, roots []string, req Request, progress *discovery.Progress) (Snapshot, error) {
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
	report, discoveryErr := discovery.FindCondaFacts(ctx, roots, progress, readHistory)
	for _, issue := range report.Issues {
		capability := "prefixes"
		if filepath.Base(issue.Path) == "history" {
			capability = "history"
		}
		snapshot.Issues = append(snapshot.Issues, Issue{Capability: capability, Path: issue.Path, Message: issue.Error})
	}
	if req.Project != "" && len(report.Environments) != 1 && discoveryErr == nil {
		return snapshot, fmt.Errorf("--project requires exactly one discovered prefix for an explicit association")
	}
	coverage, historyCoverage := Complete, NotCollected
	if discoveryErr != nil {
		coverage = Partial
	}
	if readHistory {
		historyCoverage = Complete
	}
	for _, issue := range snapshot.Issues {
		if issue.Capability == "prefixes" {
			coverage = Partial
		} else {
			historyCoverage = Partial
		}
	}
	for _, env := range report.Environments {
		target := Target{ID: FileID(env.Path), Kind: "dir", Input: env.Path, Roots: report.Roots,
			Prefixes: []Prefix{{Path: env.Path, Revision: env.Revision}}, Coverage: map[string]string{"prefixes": coverage, "history": historyCoverage}, Issues: []Issue{}}
		if Requested(req, "project-association") {
			target.Coverage["project-association"] = Complete
			if req.Project != "" && discoveryErr == nil {
				project, issue, err := collectProject(req.Project)
				if err != nil {
					return snapshot, err
				}
				target.Project = project
				if issue != nil {
					target.Issues = append(target.Issues, *issue)
					target.Coverage["project-association"] = Partial
				}
			}
		}
		snapshot.Targets = append(snapshot.Targets, target)
	}
	if len(snapshot.Targets) == 0 && len(report.Roots) > 0 {
		snapshot.Targets = append(snapshot.Targets, Target{ID: FileID(report.Roots[0]), Kind: "dir", Input: report.Roots[0], Roots: report.Roots,
			Prefixes: []Prefix{}, Coverage: map[string]string{"prefixes": coverage}, Issues: []Issue{}})
	}
	return snapshot, discoveryErr
}

// The association is supplied by the caller. Presence of a lock is not proof of
// manifest or installation synchronization; those require separate verifiers.
func collectProject(input string) (*Project, *Issue, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("--project must name a real directory")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, nil, fmt.Errorf("--project must not contain symlinked path components")
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	current, checkErr := os.Lstat(abs)
	if err != nil || checkErr != nil || !current.IsDir() || !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return nil, nil, fmt.Errorf("project directory changed while opening")
	}
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
