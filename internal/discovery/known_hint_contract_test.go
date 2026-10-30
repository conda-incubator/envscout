package discovery

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// knownHintNames lists every configured hint the venv and env-hint builders read.
var knownHintNames = []string{
	"VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "WORKON_HOME", "POETRY_VIRTUALENVS_PATH", "POETRY_CACHE_DIR",
	"CONDA_PREFIX", "CONDA_ROOT", "MAMBA_ROOT_PREFIX", "PIXI_HOME", "PIXI_PROJECT_ROOT", "CONDA_ENVS_PATH",
}

// knownHintBuild calls the two hint builders directly, with no probing and no host reads.
func knownHintBuild(inputs knownInputs) ([]candidate, Report) {
	report := newReport(ModeKnownLocations)
	col := newCollector(&report)
	out := venvCandidates(inputs, col)
	return append(out, envHintCandidates(inputs, col)...), report
}

// boundaryPath returns an absolute path of exactly n bytes. Multibyte padding uses 2-byte runes
// so byte length and rune count diverge.
func boundaryPath(base string, n int, multibyte bool) string {
	fill := n - len(base) - 1
	if !multibyte {
		return base + "/" + strings.Repeat("a", fill)
	}
	return base + "/" + strings.Repeat("\u00e9", fill/2) + strings.Repeat("a", fill%2)
}

func TestKnownHintContractRejectsInvalidValues(t *testing.T) {
	oversize := "/" + strings.Repeat("a", maxHintPathBytes)
	t.Run("nil and empty skip with no issues", func(t *testing.T) {
		empty := make(map[string]string, len(knownHintNames))
		for _, name := range knownHintNames {
			empty[name] = ""
		}
		for label, env := range map[string]map[string]string{"nil": nil, "empty": empty} {
			got, report := knownHintBuild(knownInputs{goos: "windows", env: env})
			if len(got) != 0 || len(report.Issues) != 0 {
				t.Fatalf("%s: candidates=%+v issues=%+v, want none", label, got, report.Issues)
			}
		}
	})
	for _, name := range knownHintNames {
		for _, tc := range []struct{ label, value, want string }{
			{"relative", "relative/path", "hint must be an absolute path"},
			{"oversize", oversize, "hint path exceeds known-location limit"},
			{"oversize relative", strings.Repeat("a", maxHintPathBytes+1), "hint path exceeds known-location limit"},
		} {
			t.Run(name+"/"+tc.label, func(t *testing.T) {
				got, report := knownHintBuild(knownInputs{goos: "windows", env: map[string]string{name: tc.value}})
				if len(got) != 0 {
					t.Fatalf("candidates=%+v, want none", got)
				}
				want := []Issue{{Path: name, Error: tc.want}}
				if !slices.Equal(report.Issues, want) {
					t.Fatalf("issues=%+v, want %+v", report.Issues, want)
				}
			})
		}
	}
	t.Run("issue order follows hint order", func(t *testing.T) {
		env := make(map[string]string, len(knownHintNames))
		var want []Issue
		for _, name := range knownHintNames {
			env[name] = "relative/path"
			want = append(want, Issue{Path: name, Error: "hint must be an absolute path"})
		}
		got, report := knownHintBuild(knownInputs{goos: "windows", env: env})
		if len(got) != 0 || !slices.Equal(report.Issues, want) {
			t.Fatalf("invalid hints must retain issue order: candidates=%+v issues=%+v, want %+v", got, report.Issues, want)
		}
	})
}

func TestKnownHintContractByteBoundary(t *testing.T) {
	base := knownTempDir(t)
	for _, tc := range []struct {
		label     string
		n         int
		multibyte bool
		accepted  bool
	}{
		{"ascii 4096", 4096, false, true},
		{"ascii 4097", 4097, false, false},
		{"utf8 4096", 4096, true, true},
		{"utf8 4097", 4097, true, false},
	} {
		value := boundaryPath(base, tc.n, tc.multibyte)
		if len(value) != tc.n {
			t.Fatalf("%s: helper built %d bytes, want %d", tc.label, len(value), tc.n)
		}
		for _, name := range []string{"VIRTUAL_ENV", "CONDA_PREFIX"} {
			t.Run(tc.label+"/"+name, func(t *testing.T) {
				got, report := knownHintBuild(knownInputs{goos: "linux", env: map[string]string{name: value}})
				if !tc.accepted {
					if len(got) != 0 || !slices.Equal(report.Issues, []Issue{{Path: name, Error: "hint path exceeds known-location limit"}}) {
						t.Fatalf("candidates=%+v issues=%+v, want rejection", got, report.Issues)
					}
					return
				}
				want := []candidate{{name, filepath.Clean(value), kindPrefix, true}}
				if !slices.Equal(got, want) || len(report.Issues) != 0 {
					t.Fatalf("candidates=%+v issues=%+v, want %+v", got, report.Issues, want)
				}
			})
		}
	}
}

func TestKnownHintContractOrderedProvenance(t *testing.T) {
	base := knownTempDir(t)
	env := map[string]string{
		"VIRTUAL_ENV":             base + "/venv/",
		"UV_PROJECT_ENVIRONMENT":  base + "/uv",
		"WORKON_HOME":             base + "/wh",
		"POETRY_VIRTUALENVS_PATH": base + "/pvp",
		"POETRY_CACHE_DIR":        base + "/cache/",
		"CONDA_PREFIX":            base + "/cp",
		"CONDA_ROOT":              base + "/root",
		"MAMBA_ROOT_PREFIX":       base + "/mamba",
		"PIXI_HOME":               base + "/pixi",
		"PIXI_PROJECT_ROOT":       base + "/proj",
		"CONDA_ENVS_PATH":         base + "/e1;" + base + "/e2;" + base + "/e1",
	}
	// A semicolon separator keeps native Windows drive letters inside each entry.
	got, report := knownHintBuild(knownInputs{goos: "windows", env: env})
	want := []candidate{
		{"VIRTUAL_ENV", filepath.Clean(base + "/venv"), kindPrefix, true},
		{"UV_PROJECT_ENVIRONMENT", filepath.Clean(base + "/uv"), kindPrefix, true},
		{"WORKON_HOME", filepath.Clean(base + "/wh"), kindContainer, true},
		{"POETRY_VIRTUALENVS_PATH", filepath.Clean(base + "/pvp"), kindContainer, true},
		{"POETRY_CACHE_DIR", filepath.Clean(base + "/cache/virtualenvs"), kindContainer, true},
		{"CONDA_PREFIX", filepath.Clean(base + "/cp"), kindPrefix, true},
		{"CONDA_ROOT", filepath.Clean(base + "/root"), kindRoot, true},
		{"MAMBA_ROOT_PREFIX", filepath.Clean(base + "/mamba"), kindRoot, true},
		{"PIXI_HOME", filepath.Clean(base + "/pixi/envs"), kindContainer, true},
		{"PIXI_PROJECT_ROOT", filepath.Clean(base + "/proj/.pixi/envs"), kindContainer, true},
		{"CONDA_ENVS_PATH", filepath.Clean(base + "/e1"), kindContainer, true},
		{"CONDA_ENVS_PATH", filepath.Clean(base + "/e2"), kindContainer, true},
		{"CONDA_ENVS_PATH", filepath.Clean(base + "/e1"), kindContainer, true},
	}
	if !slices.Equal(got, want) || len(report.Issues) != 0 || len(report.Hints) != 0 {
		t.Fatalf("candidates=%+v issues=%+v, want %+v", got, report.Issues, want)
	}
}

func TestKnownHintContractPoetryFallback(t *testing.T) {
	home, xdg := knownTempDir(t), knownTempDir(t)
	oversize := "/" + strings.Repeat("a", maxHintPathBytes)
	homeDirs := []candidate{
		{"home/.virtualenvs", filepath.Join(home, ".virtualenvs"), kindContainer, false},
		{"home/.venvs", filepath.Join(home, ".venvs"), kindContainer, false},
	}
	for _, tc := range []struct {
		label  string
		inputs knownInputs
		issues []Issue
		want   []candidate
	}{
		{"relative cache falls back to XDG", knownInputs{goos: "linux", home: home,
			env: map[string]string{"POETRY_CACHE_DIR": "rel/cache", "XDG_CACHE_HOME": xdg}},
			[]Issue{{Path: "POETRY_CACHE_DIR", Error: "hint must be an absolute path"}},
			append([]candidate{{"poetry/cache", filepath.Join(xdg, "pypoetry", "virtualenvs"), kindContainer, false}}, homeDirs...)},
		{"oversize cache falls back to home", knownInputs{goos: "darwin", home: home,
			env: map[string]string{"POETRY_CACHE_DIR": oversize}},
			[]Issue{{Path: "POETRY_CACHE_DIR", Error: "hint path exceeds known-location limit"}},
			append([]candidate{{"poetry/cache", filepath.Join(home, "Library", "Caches", "pypoetry", "virtualenvs"), kindContainer, false}}, homeDirs...)},
		{"valid home-only fallback", knownInputs{goos: "linux", home: home, env: map[string]string{}},
			nil,
			append([]candidate{{"poetry/cache", filepath.Join(home, ".cache", "pypoetry", "virtualenvs"), kindContainer, false}}, homeDirs...)},
		{"no home and no XDG means no poetry fallback", knownInputs{goos: "linux", env: map[string]string{}},
			nil, nil},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got, report := knownHintBuild(tc.inputs)
			if !slices.Equal(got, tc.want) || !slices.Equal(report.Issues, tc.issues) {
				t.Fatalf("candidates=%+v issues=%+v, want candidates=%+v issues=%+v", got, report.Issues, tc.want, tc.issues)
			}
		})
	}
}
