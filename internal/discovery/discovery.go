package discovery

import (
	"sort"
	"sync"
)

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

// HintSummary counts locations inspected and skipped for one known-location source.
type HintSummary struct {
	Source  string `json:"source"`
	Checked int    `json:"checked"`
	Skipped int    `json:"skipped"`
}

const (
	ModeRoots          = "roots"
	ModeKnownLocations = "known-locations"
	ModeImage          = "image"
)

// Report describes one discovery run. Host reports set Mode, Roots, Hints; image
// reports set Mode, Source, Scope, FilesVisited, and SchemaVersion. All arrays are
// non-nil and sorted deterministically, including after cancellation.
type Report struct {
	Mode         string        `json:"mode"`
	Roots        []string      `json:"roots"`
	Hints        []HintSummary `json:"hints"`
	Environments []Environment `json:"environments"`
	Issues       []Issue       `json:"issues"`

	Source string `json:"source,omitempty"`
	Scope  string `json:"scope,omitempty"`
	// MetadataFilesExamined counts conda-meta *.json matches examined in an image search,
	// not every path in the squashed filesystem.
	MetadataFilesExamined int `json:"metadata_files_examined,omitempty"`
	SchemaVersion         int `json:"schema_version,omitempty"`
}

func newReport(mode string) Report {
	return Report{Mode: mode, Roots: []string{}, Hints: []HintSummary{}, Environments: []Environment{}, Issues: []Issue{}}
}

func sortReport(r *Report) {
	sort.Slice(r.Environments, func(i, j int) bool { return r.Environments[i].Path < r.Environments[j].Path })
	sort.Slice(r.Issues, func(i, j int) bool {
		if r.Issues[i].Path == r.Issues[j].Path {
			return r.Issues[i].Error < r.Issues[j].Error
		}
		return r.Issues[i].Path < r.Issues[j].Path
	})
	sort.Slice(r.Hints, func(i, j int) bool { return r.Hints[i].Source < r.Hints[j].Source })
}

// collector gathers results from concurrent walkers; environments are deduplicated by path.
type collector struct {
	mu       sync.Mutex
	report   *Report
	seen     map[string]bool
	progress *Progress // optional; nil disables counting
}

func newCollector(report *Report) *collector {
	return &collector{report: report, seen: make(map[string]bool)}
}

func (c *collector) addEnvironment(env Environment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[env.Path] {
		return
	}
	c.seen[env.Path] = true
	c.report.Environments = append(c.report.Environments, env)
	if c.progress != nil {
		c.progress.Environments.Add(1)
	}
}

func (c *collector) addIssue(path string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.report.Issues = append(c.report.Issues, Issue{Path: path, Error: err.Error()})
}
