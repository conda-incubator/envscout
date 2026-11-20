package evidence

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/discovery"
)

// pyMetaCase pins current direct distribution-metadata classification. The
// index oracle drives indexHostPython over a synthetic venv or conda Target; the
// collect oracle drives CollectHost. Expectations were measured from HEAD a179ba6.
type pyMetaCase struct {
	name        string
	venv        bool
	unixCatalog bool // supporting-file lookup uses slash-only paths in pinned Syft
	setup       func(t *testing.T, site string)
	indexed     []string // direct indexed paths relative to the prefix
	coverage    string   // python-distributions coverage on the collect path
	issues      []string // python-distributions issue messages on the collect path
	python      []string // Syft-cataloged "name version relPath" on the collect path
}

const pyMetaSite = "lib/python3.12/site-packages"

func pyMetaFiles(files map[string]string) func(*testing.T, string) {
	return func(t *testing.T, site string) {
		for rel, content := range files {
			hostWrite(t, filepath.Join(site, filepath.FromSlash(rel)), content)
		}
	}
}

// pyMetaSymlink writes a regular target outside site-packages and links to it.
func pyMetaSymlink(target, link string) func(*testing.T, string) {
	return func(t *testing.T, site string) {
		out := filepath.Join(filepath.Dir(site), "outside")
		hostWrite(t, filepath.Join(out, target), "Name: outside\nVersion: 1\n")
		if err := os.Symlink(filepath.Join(out, target), filepath.Join(site, link)); err != nil {
			t.Skip(err)
		}
	}
}

func pyMetaDir(rel string) func(*testing.T, string) {
	return func(t *testing.T, site string) {
		if err := os.MkdirAll(filepath.Join(site, filepath.FromSlash(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func pyMetaCases() []pyMetaCase {
	const meta = "Name: demo\nVersion: 1\n"
	b := pyMetaSite + "/"
	return []pyMetaCase{
		{
			// Case-insensitive .dist-info suffix accepts an uppercase container;
			// Syft identifies it from its exact METADATA primary.
			name:     "venv uppercase DIST-INFO container with exact METADATA",
			venv:     true,
			setup:    pyMetaFiles(map[string]string{"UP-1.DIST-INFO/METADATA": meta, "UP-1.DIST-INFO/RECORD": "x"}),
			indexed:  []string{b + "UP-1.DIST-INFO/METADATA", b + "UP-1.DIST-INFO/RECORD"},
			coverage: Complete,
			python:   []string{"demo 1 " + b + "UP-1.DIST-INFO/METADATA"},
		},
		{
			// Lowercase "metadata" is not the exact primary: the venv index raises
			// the missing-primary issue, and collect degrades through the
			// identity post-pass because the suffix match is case-insensitive.
			name:     "venv lowercase metadata in dist-info lacks exact primary",
			venv:     true,
			setup:    pyMetaFiles(map[string]string{"low-1.dist-info/metadata": meta}),
			indexed:  []string{b + "low-1.dist-info/metadata"},
			coverage: Partial,
			issues: []string{
				"Python distribution metadata did not produce an installed identity",
				"Python distribution primary metadata is missing or not a regular file",
			},
		},
		{
			name:     "conda lowercase metadata in dist-info lacks identity",
			setup:    pyMetaFiles(map[string]string{"low-1.dist-info/metadata": meta}),
			indexed:  []string{b + "low-1.dist-info/metadata"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
		{
			name:     "mixed-case container is admitted but unidentified",
			setup:    pyMetaFiles(map[string]string{"mixed-1.Dist-Info/METADATA": meta}),
			indexed:  []string{b + "mixed-1.Dist-Info/METADATA"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
		{
			name:     "Unicode lowercase container matching is retained",
			setup:    pyMetaFiles(map[string]string{"mixed-1.d\u0130st-\u0130nfo/METADATA": meta}),
			indexed:  []string{b + "mixed-1.d\u0130st-\u0130nfo/METADATA"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
		{
			name:     "Unicode lowercase primary matching is retained",
			setup:    pyMetaFiles(map[string]string{"mixed-1.egg-info/PKG-\u0130NFO": meta}),
			indexed:  []string{b + "mixed-1.egg-info/PKG-\u0130NFO"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
		{
			// Mismatched primaries (PKG-INFO in .dist-info, METADATA in .egg-info)
			// are indexed as supporting files but are not identified by Syft.
			name: "venv mismatched primaries are unidentified",
			venv: true,
			setup: pyMetaFiles(map[string]string{
				"mis-1.dist-info/PKG-INFO": meta,
				"mis-2.egg-info/METADATA":  meta,
			}),
			indexed:  []string{b + "mis-1.dist-info/PKG-INFO", b + "mis-2.egg-info/METADATA"},
			coverage: Partial,
			issues: []string{
				"Python distribution primary metadata is missing or not a regular file",
				"Python distribution primary metadata is missing or not a regular file",
			},
		},
		{
			// A regular .egg-info file is a standalone distribution: indexed and
			// identified by Syft in venv, with no classification issue.
			name:     "venv standalone regular egg-info file is identified",
			venv:     true,
			setup:    pyMetaFiles(map[string]string{"single-3.egg-info": meta}),
			indexed:  []string{b + "single-3.egg-info"},
			coverage: Complete,
			python:   []string{"demo 1 " + b + "single-3.egg-info"},
		},
		{
			// A regular .dist-info file is never indexed. Conda is silent; venv
			// reports the unsupported container.
			name:     "conda regular dist-info file is silently ignored",
			setup:    pyMetaFiles(map[string]string{"file-1.dist-info": meta}),
			coverage: Complete,
		},
		{
			name:     "uppercase standalone egg is admitted but unidentified",
			setup:    pyMetaFiles(map[string]string{"single-3.EGG-INFO": meta}),
			indexed:  []string{b + "single-3.EGG-INFO"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
		{
			name:     "venv regular dist-info file is an unsupported container",
			venv:     true,
			setup:    pyMetaFiles(map[string]string{"file-1.dist-info": meta}),
			coverage: Partial,
			issues:   []string{"Python distribution metadata container is not a directory or supported egg-info file"},
		},
		{
			name:     "conda symlinked dist-info container is not followed",
			setup:    pyMetaSymlink("METADATA", "linked-1.dist-info"),
			coverage: Partial,
			issues:   []string{"linked Python evidence is not followed"},
		},
		{
			name:     "venv symlinked egg-info container is not followed",
			venv:     true,
			setup:    pyMetaSymlink("PKG-INFO", "linked-1.egg-info"),
			coverage: Partial,
			issues:   []string{"linked Python evidence is not followed"},
		},
		{
			// A directory named METADATA inside .egg-info is nonregular at a name
			// that is not the expected PKG-INFO primary: it raises the nonregular
			// issue, and in venv the missing-primary issue as well.
			name:     "venv METADATA directory in egg-info raises nonregular and missing primary",
			venv:     true,
			setup:    pyMetaDir("dirp-1.egg-info/METADATA"),
			coverage: Partial,
			issues: []string{
				"Python distribution metadata is not a regular file",
				"Python distribution primary metadata is missing or not a regular file",
			},
		},
		{
			// PKG-INFO directory in .dist-info is nonregular for the expected
			// METADATA primary, so only the nonregular issue applies in conda.
			name:     "conda PKG-INFO directory in dist-info raises nonregular issue only",
			setup:    pyMetaDir("dirp-1.dist-info/PKG-INFO"),
			coverage: Partial,
			issues:   []string{"Python distribution metadata is not a regular file"},
		},
		{
			// Malformed supporting content is indexed without validation. The
			// Syft catalog, not the supporting file, degrades coverage; the
			// primary METADATA still identifies the distribution.
			name:        "malformed supporting files keep the primary identity and degrade catalog",
			venv:        true,
			unixCatalog: true,
			setup: pyMetaFiles(map[string]string{
				"bad-1.dist-info/METADATA":        meta,
				"bad-1.dist-info/RECORD":          "\x00\xff not csv",
				"bad-1.dist-info/direct_url.json": "{not json",
			}),
			indexed: []string{
				b + "bad-1.dist-info/METADATA",
				b + "bad-1.dist-info/RECORD",
				b + "bad-1.dist-info/direct_url.json",
			},
			coverage: Partial,
			issues:   []string{"installed Python metadata catalog is incomplete"},
			python:   []string{"demo 1 " + b + "bad-1.dist-info/METADATA"},
		},
		{
			// Only direct regular children are indexed. Nested files are not
			// entered, and the identified primary still yields one distribution.
			name: "nested supporting files are not entered",
			setup: pyMetaFiles(map[string]string{
				"nest-1.dist-info/METADATA":       meta,
				"nest-1.dist-info/sub/deep/x.txt": "x",
			}),
			indexed:  []string{b + "nest-1.dist-info/METADATA"},
			coverage: Complete,
			python:   []string{"demo 1 " + b + "nest-1.dist-info/METADATA"},
		},
		{
			name:     "Python- container with ordinary package identity is cataloged",
			setup:    pyMetaFiles(map[string]string{"Python-3.12.dist-info/METADATA": "Name: x\nVersion: 1\n"}),
			indexed:  []string{b + "Python-3.12.dist-info/METADATA"},
			coverage: Complete,
			python:   []string{"x 1 " + b + "Python-3.12.dist-info/METADATA"},
		},
		{
			// The exemption is keyed on the basename, not the container name: a
			// container named Python-lib-1.dist-info is still identified by Syft
			// from its METADATA, so no issue is raised either.
			name:     "Python- container name with METADATA is cataloged without issue",
			setup:    pyMetaFiles(map[string]string{"Python-lib-1.dist-info/METADATA": "Name: x\nVersion: 1\n"}),
			indexed:  []string{b + "Python-lib-1.dist-info/METADATA"},
			coverage: Complete,
			python:   []string{"x 1 " + b + "Python-lib-1.dist-info/METADATA"},
		},
		{
			// Syft deliberately omits Name: Python. Only an exact Python- prefix
			// on the primary file basename exempts it from the identity post-pass.
			name:     "Python- standalone runtime egg is exempt",
			setup:    pyMetaFiles(map[string]string{"Python-3.12.egg-info": "Name: Python\nVersion: 3.12\n"}),
			indexed:  []string{b + "Python-3.12.egg-info"},
			coverage: Complete,
		},
		{
			name:     "lowercase python- standalone runtime egg is not exempt",
			setup:    pyMetaFiles(map[string]string{"python-3.12.egg-info": "Name: Python\nVersion: 3.12\n"}),
			indexed:  []string{b + "python-3.12.egg-info"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
		{
			name:     "Python- runtime container does not exempt METADATA basename",
			setup:    pyMetaFiles(map[string]string{"Python-3.12.dist-info/METADATA": "Name: Python\nVersion: 3.12\n"}),
			indexed:  []string{b + "Python-3.12.dist-info/METADATA"},
			coverage: Partial,
			issues:   []string{"Python distribution metadata did not produce an installed identity"},
		},
	}
}

// pyMetaIndex runs indexHostPython over a synthetic Target whose only prefix is
// venv or conda, so the venv-only branches are reachable.
func pyMetaIndex(t *testing.T, prefix string, venv bool) (*hostFileResolver, *Target) {
	t.Helper()
	root, err := os.OpenRoot(prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	kind := discovery.KindConda
	if venv {
		kind = discovery.KindVenv
	}
	target := &Target{Kind: "dir", Prefixes: []Prefix{{Kind: kind, Path: prefix}}, Coverage: map[string]string{"python-distributions": Complete}}
	r := &hostFileResolver{ctx: context.Background(), root: root, base: prefix, files: map[string]os.FileInfo{}}
	visited := 0
	if err := indexHostPython(context.Background(), root, filepath.FromSlash(pyMetaSite), r, target, &visited); err != nil {
		t.Fatalf("indexHostPython: %v", err)
	}
	sort.Strings(r.paths)
	return r, target
}

func pyMetaIssues(issues []Issue) []string {
	out := make([]string, 0, len(issues))
	for _, issue := range issues {
		if issue.Capability == CapPythonDistributions {
			out = append(out, issue.Message)
		}
	}
	sort.Strings(out)
	return out
}

func pyMetaSummaries(dists []PythonDistribution, prefix string) []string {
	out := make([]string, 0, len(dists))
	for _, d := range dists {
		rel, err := filepath.Rel(prefix, d.Path)
		if err != nil {
			rel = d.Path
		}
		out = append(out, d.Name+" "+d.Version+" "+filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

// sortedStrings returns a sorted, non-nil copy so empty expectations compare
// equal to empty measurements regardless of nil-ness.
func sortedStrings(in []string) []string {
	out := make([]string, 0, len(in))
	out = append(out, in...)
	sort.Strings(out)
	return out
}

func pyMetaRun(t *testing.T, c pyMetaCase) {
	t.Helper()
	prefix := hostPrefix(t)
	if c.venv {
		// A venv has no conda-meta; reuse its pyvenv.cfg marker and drop conda-meta.
		if err := os.RemoveAll(filepath.Join(prefix, "conda-meta")); err != nil {
			t.Fatal(err)
		}
		hostVenv(t, prefix)
	}
	site := filepath.Join(prefix, filepath.FromSlash(pyMetaSite))
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	c.setup(t, site)

	// Index oracle: indexed paths and issues on the venv/conda synthetic Target.
	r, _ := pyMetaIndex(t, prefix, c.venv)
	if got := sortedStrings(indexedRel(r, prefix)); !reflect.DeepEqual(got, sortedStrings(c.indexed)) {
		t.Errorf("index paths = %v, want %v", got, sortedStrings(c.indexed))
	}
	if c.unixCatalog && runtime.GOOS == "windows" {
		t.Skip("Unix catalog oracle: pinned Syft supporting-file lookup uses slash-only paths, but the host resolver returns native Windows locations")
	}

	// Collect oracle: production CollectHost, coverage, issues, and identities.
	// Venv collection runs only VirtualenvCapabilities (Request.ForEnvironment).
	req := Request{Capabilities: []string{CapPythonDistributions}, VirtualenvCapabilities: []string{CapPythonDistributions}}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, req)
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("CollectHost: %+v %v", snapshot, err)
	}
	collected := snapshot.Targets[0]
	if got := collected.Coverage[CapPythonDistributions]; got != c.coverage {
		t.Errorf("collect coverage = %q, want %q (issues=%v)", got, c.coverage, pyMetaIssues(collected.Issues))
	}
	if got := pyMetaIssues(collected.Issues); !reflect.DeepEqual(got, sortedStrings(c.issues)) {
		t.Errorf("collect issues = %v, want %v", got, sortedStrings(c.issues))
	}
	if got := pyMetaSummaries(collected.Python, prefix); !reflect.DeepEqual(got, sortedStrings(c.python)) {
		t.Errorf("collect python = %v, want %v", got, sortedStrings(c.python))
	}
}

// indexedRel returns the indexed paths relative to the prefix.
func indexedRel(r *hostFileResolver, prefix string) []string {
	out := make([]string, 0, len(r.paths))
	for _, p := range r.paths {
		rel, err := filepath.Rel(prefix, filepath.Join(prefix, p))
		if err != nil {
			rel = p
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

func TestPythonMetadataContract(t *testing.T) {
	for _, c := range pyMetaCases() {
		t.Run(strings.ReplaceAll(c.name, " ", "_"), func(t *testing.T) {
			pyMetaRun(t, c)
		})
	}
}
