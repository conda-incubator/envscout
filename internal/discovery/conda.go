package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/charlievieth/fastwalk"
)

const maxMetadataBytes = 1 << 20
const maxHistoryBytes = 16 << 20
const maxMetadataEntries = 10000

// Environment is an installed conda prefix; Name is its directory name, not a registry alias.
type Environment struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Revision *int   `json:"revision"`
}

// Issue describes evidence we could not inspect; results may therefore be incomplete.
type Issue struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// Report keeps the scanned scope and any coverage gaps alongside the results.
type Report struct {
	Mode         string        `json:"mode"`
	Roots        []string      `json:"roots"`
	Hints        []HintSummary `json:"hints"`
	Environments []Environment `json:"environments"`
	Issues       []Issue       `json:"issues"`
}

// HintSummary counts locations inspected and skipped for one known-location source.
type HintSummary struct {
	Source  string `json:"source"`
	Checked int    `json:"checked"`
	Skipped int    `json:"skipped"`
}

const (
	ModeRoots          = "roots"
	ModeKnownLocations = "known-locations"
)

// Progress contains live discovery counters. Folders counts visited directories,
// not a percentage of the (unknown) total scope.
type Progress struct {
	Folders      atomic.Uint64
	Environments atomic.Uint64
}

// FindCondaWithProgress reports live counters while searching requested roots.
func FindCondaWithProgress(roots []string, progress *Progress) (Report, error) {
	return walkConda(context.Background(), roots, progress, true)
}

// FindCondaFacts lets collectors omit history when no enabled rule requires it.
func FindCondaFacts(ctx context.Context, roots []string, progress *Progress, readHistory bool) (Report, error) {
	return walkConda(ctx, roots, progress, readHistory)
}

func walkConda(ctx context.Context, roots []string, progress *Progress, readHistory bool) (Report, error) {
	report := Report{Mode: ModeRoots, Roots: []string{}, Hints: []HintSummary{}, Environments: []Environment{}, Issues: []Issue{}}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if len(roots) == 0 {
		return report, fmt.Errorf("at least one root is required for a full walk")
	}
	seenRoots := make(map[string]bool)
	for _, root := range roots {
		path, err := filepath.Abs(root)
		if err != nil {
			return report, fmt.Errorf("root %q: %w", root, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return report, fmt.Errorf("root %q: %w", path, err)
		}
		if !info.IsDir() {
			return report, fmt.Errorf("root %q: must be a directory, not a file or symlink", path)
		}
		if !seenRoots[path] {
			seenRoots[path] = true
			report.Roots = append(report.Roots, path)
		}
	}
	sort.Strings(report.Roots)
	walkRoots := make([]string, 0, len(report.Roots))
	for _, root := range report.Roots {
		covered := false
		for _, parent := range walkRoots {
			if rel, err := filepath.Rel(parent, root); err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				covered = true
				break
			}
		}
		if !covered {
			walkRoots = append(walkRoots, root)
		}
	}

	results := condaResults{report: &report, seen: make(map[string]bool), progress: progress, ctx: ctx, skipHistory: !readHistory}
	for _, root := range walkRoots {
		err := fastwalk.Walk(&fastwalk.Config{Follow: false, NumWorkers: 4}, root, func(path string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				results.addIssue(path, walkErr)
				return nil
			}
			if entry.IsDir() && progress != nil {
				progress.Folders.Add(1)
			}
			if !entry.IsDir() || entry.Name() != "conda-meta" {
				return nil
			}
			expectedMeta, err := entry.Info()
			if err != nil {
				results.addIssue(path, err)
				return fastwalk.SkipDir
			}
			prefix, err := openHintDir(filepath.Dir(path), root)
			if err != nil {
				results.addIssue(filepath.Dir(path), err)
				return fastwalk.SkipDir
			}
			openedMeta, err := prefix.Lstat("conda-meta")
			if err != nil || !openedMeta.IsDir() || !os.SameFile(expectedMeta, openedMeta) {
				_ = prefix.Close()
				results.addIssue(path, fmt.Errorf("prefix metadata changed during traversal"))
				return fastwalk.SkipDir
			}
			env, valid, issues := inspectCondaPrefixRootOptions(ctx, prefix, filepath.Dir(path), readHistory)
			_ = prefix.Close()
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, issue := range issues {
				results.addIssue(issue.Path, errors.New(issue.Error))
			}
			if valid {
				results.addEnvironment(env)
			}
			return fastwalk.SkipDir
		})
		if err != nil {
			return report, fmt.Errorf("walk %q: %w", root, err)
		}
	}
	sortReport(&report)
	return report, ctx.Err()
}

type condaResults struct {
	report      *Report
	seen        map[string]bool
	progress    *Progress
	ctx         context.Context
	skipHistory bool
	mu          sync.Mutex
}

func (r *condaResults) addEnvironment(env Environment) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[env.Path] {
		return
	}
	r.seen[env.Path] = true
	r.report.Environments = append(r.report.Environments, env)
	if r.progress != nil {
		r.progress.Environments.Add(1)
	}
}

func (r *condaResults) addIssue(path string, err error) {
	r.mu.Lock()
	r.report.Issues = append(r.report.Issues, Issue{Path: path, Error: err.Error()})
	r.mu.Unlock()
}

func sortReport(report *Report) {
	sort.Slice(report.Environments, func(i, j int) bool { return report.Environments[i].Path < report.Environments[j].Path })
	sort.Slice(report.Issues, func(i, j int) bool {
		if report.Issues[i].Path == report.Issues[j].Path {
			return report.Issues[i].Error < report.Issues[j].Error
		}
		return report.Issues[i].Path < report.Issues[j].Path
	})
	sort.Slice(report.Hints, func(i, j int) bool { return report.Hints[i].Source < report.Hints[j].Source })
}

func inspectCondaPrefixRootOptions(ctx context.Context, root *os.Root, prefix string, readHistory bool) (Environment, bool, []Issue) {
	metaDir := filepath.Join(prefix, "conda-meta")
	metaInfo, err := root.Lstat("conda-meta")
	var issues []Issue
	if err != nil {
		issues = append(issues, Issue{Path: metaDir, Error: err.Error()})
		return Environment{}, false, issues
	}
	if !metaInfo.IsDir() {
		issues = append(issues, Issue{Path: metaDir, Error: "conda-meta is not a directory"})
		return Environment{}, false, issues
	}
	meta, err := root.OpenRoot("conda-meta")
	if err != nil {
		issues = append(issues, Issue{Path: metaDir, Error: err.Error()})
		return Environment{}, false, issues
	}
	defer func() { _ = meta.Close() }()
	valid, err := hasPackageMetadataContext(ctx, meta, metaDir)
	if err != nil {
		issues = append(issues, Issue{Path: metaDir, Error: err.Error()})
	}
	if !valid {
		return Environment{}, false, issues
	}
	if !readHistory {
		return Environment{Name: filepath.Base(prefix), Path: prefix}, true, issues
	}
	rev, revErr := revisionInRootContext(ctx, meta, "history")
	if revErr != nil && !errors.Is(revErr, fs.ErrNotExist) {
		issues = append(issues, Issue{Path: filepath.Join(metaDir, "history"), Error: revErr.Error()})
	}
	return Environment{Name: filepath.Base(prefix), Path: prefix, Revision: rev}, true, issues
}

func hasPackageMetadataContext(ctx context.Context, root *os.Root, metaDir string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	dir, err := root.Open(".")
	if err != nil {
		return false, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(maxMetadataEntries + 1)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			return false, err
		}
	}
	var firstErr error
	if len(entries) > maxMetadataEntries {
		firstErr = fmt.Errorf("conda-meta exceeds %d entries", maxMetadataEntries)
		entries = entries[:maxMetadataEntries]
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(metaDir, entry.Name())
		info, err := root.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid or unreadable conda package metadata: %s", path)
			}
			continue
		}
		file, err := root.Open(entry.Name())
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read %s: %w", path, err)
			}
			continue
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxMetadataBytes || !os.SameFile(info, openedInfo) {
			_ = file.Close()
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid or unreadable conda package metadata: %s", path)
			}
			continue
		}
		valid := validPackageMetadata(imageContextReader{ctx, io.LimitReader(file, maxMetadataBytes)})
		closeErr := file.Close()
		if valid && closeErr == nil {
			return true, firstErr
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("invalid or unreadable conda package metadata: %s", path)
		}
	}
	return false, firstErr
}

func validPackageMetadata(reader io.Reader) bool {
	var metadata struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	return json.NewDecoder(reader).Decode(&metadata) == nil && metadata.Name != "" && metadata.Version != ""
}

// revisionInRootContext mirrors conda.history.History.parse: revision is the
// zero-based index of a history header, including headers with no package changes.
func revisionInRootContext(ctx context.Context, root *os.Root, name string) (*int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entry, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() || entry.Size() > maxHistoryBytes {
		return nil, fmt.Errorf("history is not a regular file of at most %d bytes", maxHistoryBytes)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxHistoryBytes || !os.SameFile(entry, openedInfo) {
		return nil, fmt.Errorf("history is not a regular file of at most %d bytes", maxHistoryBytes)
	}
	return revisionFromBoundedReader(imageContextReader{ctx, file}, maxHistoryBytes)
}

func revisionFromBoundedReader(input io.Reader, maxBytes int64) (*int, error) {
	reader := &io.LimitedReader{R: input, N: maxBytes + 1}
	revision, err := revisionFromReader(reader)
	if reader.N == 0 {
		return nil, fmt.Errorf("history exceeds %d bytes", maxBytes)
	}
	return revision, err
}

func revisionFromReader(reader io.Reader) (*int, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), maxMetadataBytes)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "==>") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "==>"))
		end := strings.Index(rest, "<==")
		if end > 0 && strings.TrimSpace(rest[:end]) != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	latest := count - 1
	return &latest, nil
}
