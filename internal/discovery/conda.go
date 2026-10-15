package discovery

import (
	"bufio"
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
	Roots        []string      `json:"roots"`
	Environments []Environment `json:"environments"`
	Issues       []Issue       `json:"issues"`
}

// Progress contains live discovery counters. Folders counts visited directories,
// not a percentage of the (unknown) total scope.
type Progress struct {
	Folders      atomic.Uint64
	Environments atomic.Uint64
}

// FindConda searches only explicitly requested directory roots without following symlinks.
func FindConda(roots []string) (Report, error) {
	return FindCondaWithProgress(roots, nil)
}

// FindCondaWithProgress reports live counters while searching requested roots.
func FindCondaWithProgress(roots []string, progress *Progress) (Report, error) {
	report := Report{Roots: []string{}, Environments: []Environment{}, Issues: []Issue{}}
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

	seen := make(map[string]bool)
	var mu sync.Mutex
	addIssue := func(path string, err error) {
		mu.Lock()
		report.Issues = append(report.Issues, Issue{Path: path, Error: err.Error()})
		mu.Unlock()
	}
	for _, root := range walkRoots {
		err := fastwalk.Walk(&fastwalk.Config{Follow: false, NumWorkers: 4}, root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				addIssue(path, walkErr)
				return nil
			}
			if entry.IsDir() && progress != nil {
				progress.Folders.Add(1)
			}
			if !entry.IsDir() || entry.Name() != "conda-meta" {
				return nil
			}
			valid, err := hasPackageMetadata(path)
			if err != nil {
				addIssue(path, err)
			}
			if valid {
				prefix := filepath.Dir(path)
				rev, revErr := revision(filepath.Join(path, "history"))
				if revErr != nil && !errors.Is(revErr, fs.ErrNotExist) {
					addIssue(filepath.Join(path, "history"), revErr)
				}
				mu.Lock()
				if !seen[prefix] {
					seen[prefix] = true
					report.Environments = append(report.Environments, Environment{
						Name: filepath.Base(prefix), Path: prefix, Revision: rev,
					})
					if progress != nil {
						progress.Environments.Add(1)
					}
				}
				mu.Unlock()
			}
			return fastwalk.SkipDir
		})
		if err != nil {
			return report, fmt.Errorf("walk %q: %w", root, err)
		}
	}
	sort.Slice(report.Environments, func(i, j int) bool { return report.Environments[i].Path < report.Environments[j].Path })
	sort.Slice(report.Issues, func(i, j int) bool {
		if report.Issues[i].Path == report.Issues[j].Path {
			return report.Issues[i].Error < report.Issues[j].Error
		}
		return report.Issues[i].Path < report.Issues[j].Path
	})
	return report, nil
}

func hasPackageMetadata(metaDir string) (bool, error) {
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		return false, err
	}
	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(metaDir, entry.Name())
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxMetadataBytes {
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid or unreadable conda package metadata: %s", path)
			}
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read %s: %w", path, err)
			}
			continue
		}
		var metadata struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxMetadataBytes {
			_ = file.Close()
			if firstErr == nil {
				firstErr = fmt.Errorf("invalid or unreadable conda package metadata: %s", path)
			}
			continue
		}
		err = json.NewDecoder(io.LimitReader(file, maxMetadataBytes)).Decode(&metadata)
		closeErr := file.Close()
		if err == nil && closeErr == nil && metadata.Name != "" && metadata.Version != "" {
			return true, firstErr
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("invalid or unreadable conda package metadata: %s", path)
		}
	}
	return false, firstErr
}

// revision mirrors conda.history.History.parse: revision is the zero-based
// index of a history header, including headers with no package changes.
func revision(path string) (*int, error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() || entry.Size() > maxHistoryBytes {
		return nil, fmt.Errorf("history is not a regular file of at most %d bytes", maxHistoryBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxHistoryBytes {
		return nil, fmt.Errorf("history is not a regular file of at most %d bytes", maxHistoryBytes)
	}
	scanner := bufio.NewScanner(file)
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
