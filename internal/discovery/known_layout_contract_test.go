package discovery

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// layoutNames are the four install directory names, spelled out so expectations never read installNames.
var layoutNames = []string{"miniconda3", "anaconda3", "miniforge3", "mambaforge"}

// layoutRows expands one base into one kindRoot row per name, in the order given.
func layoutRows(source, base string, names ...string) []candidate {
	var out []candidate
	for _, n := range names {
		out = append(out, candidate{source + "/" + n, filepath.Join(base, n), kindRoot, false})
	}
	return out
}

// layoutJoin concatenates expected row groups in the order the production layout emits them.
func layoutJoin(parts ...[]candidate) []candidate {
	var out []candidate
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestKnownLayoutContractFixedRows(t *testing.T) {
	home, programData, localAppData := knownTempDir(t), knownTempDir(t), knownTempDir(t)
	homeEnvs := []candidate{
		{"home/.conda/envs", filepath.Join(home, ".conda", "envs"), kindContainer, false},
		{"home/.pixi/envs", filepath.Join(home, ".pixi", "envs"), kindContainer, false},
	}
	homeRows := layoutRows("home", home, "miniconda", "anaconda", "micromamba", "miniconda3", "anaconda3", "miniforge3", "mambaforge")
	sysConda := []candidate{
		{"system/opt-conda", filepath.Clean("/opt/conda"), kindRoot, false},
		{"system/usr-share-conda", filepath.Clean("/usr/share/conda"), kindRoot, false},
	}
	winWant := layoutJoin(homeEnvs,
		[]candidate{{"windows/localappdata/conda/envs", filepath.Join(localAppData, "conda", "envs"), kindContainer, false}},
		homeRows,
		layoutRows("windows/programdata", programData, layoutNames[:3]...),
		layoutRows("windows/localappdata", localAppData, layoutNames[:2]...))
	unixWant := layoutJoin(homeEnvs, sysConda, homeRows,
		layoutRows("home/opt", filepath.Join(home, "opt"), layoutNames...),
		layoutRows("system/opt", "/opt", layoutNames...),
		layoutRows("system/usr-local", "/usr/local", layoutNames...))
	unixNoHome := layoutJoin(sysConda,
		layoutRows("system/opt", "/opt", layoutNames...),
		layoutRows("system/usr-local", "/usr/local", layoutNames...))
	winEnv := map[string]string{"PROGRAMDATA": programData, "LOCALAPPDATA": localAppData}

	for _, tc := range []struct {
		label  string
		inputs knownInputs
		want   []candidate
	}{
		{"windows injected bases", knownInputs{goos: "windows", home: home, env: winEnv}, winWant},
		{"windows without bases", knownInputs{goos: "windows", env: map[string]string{}}, nil},
		{"windows programdata only", knownInputs{goos: "windows", env: map[string]string{"PROGRAMDATA": programData}},
			layoutRows("windows/programdata", programData, layoutNames[:3]...)},
		{"linux ignores windows bases", knownInputs{goos: "linux", home: home, env: winEnv}, unixWant},
		{"darwin with home", knownInputs{goos: "darwin", home: home, env: map[string]string{}}, unixWant},
		{"linux without home", knownInputs{goos: "linux", env: map[string]string{}}, unixNoHome},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := appendFixed(nil, tc.inputs); !slices.Equal(got, tc.want) {
				t.Fatalf("rows=%+v\nwant=%+v", got, tc.want)
			}
		})
	}
}

func TestKnownLayoutContractSuffixBoundary(t *testing.T) {
	base := knownTempDir(t)
	edge := boundaryPath(base, maxHintPathBytes, false)
	over := boundaryPath(base, maxHintPathBytes+1, false)
	// Raw length exceeds the limit, but Clean would shrink it to base/b: the raw check must reject first.
	unclean := base + "/" + strings.Repeat("./", 2100) + "b"
	if len(edge) != maxHintPathBytes || len(over) != maxHintPathBytes+1 || len(unclean) <= maxHintPathBytes {
		t.Fatalf("boundary fixtures wrong: edge=%d over=%d unclean=%d", len(edge), len(over), len(unclean))
	}
	for _, tc := range []struct{ name, suffix string }{
		{"PIXI_HOME", "envs"},
		{"PIXI_PROJECT_ROOT", filepath.Join(".pixi", "envs")},
		{"POETRY_CACHE_DIR", "virtualenvs"},
	} {
		t.Run(tc.name+"/4096 accepted before suffix", func(t *testing.T) {
			got, report := knownHintBuild(knownInputs{goos: "linux", env: map[string]string{tc.name: edge}})
			want := []candidate{{tc.name, filepath.Join(edge, tc.suffix), kindContainer, true}}
			if !slices.Equal(got, want) || len(report.Issues) != 0 {
				t.Fatalf("candidates=%+v issues=%+v, want %+v", got, report.Issues, want)
			}
		})
		for _, raw := range []struct{ label, value string }{{"4097 rejected", over}, {"unclean over limit rejected", unclean}} {
			t.Run(tc.name+"/"+raw.label, func(t *testing.T) {
				got, report := knownHintBuild(knownInputs{goos: "linux", env: map[string]string{tc.name: raw.value}})
				want := []Issue{{Path: tc.name, Error: "hint path exceeds known-location limit"}}
				if len(got) != 0 || !slices.Equal(report.Issues, want) {
					t.Fatalf("candidates=%+v issues=%+v, want none and %+v", got, report.Issues, want)
				}
			})
		}
	}
}

func TestKnownLayoutContractMixedPathList(t *testing.T) {
	base := knownTempDir(t)
	one, two := base+"/one", base+"/two"
	oversize := "/" + strings.Repeat("a", maxHintPathBytes)
	raw := strings.Join([]string{one, oversize, "relative/path", "", two, one}, ";")
	got, report := knownHintBuild(knownInputs{goos: "windows", env: map[string]string{"CONDA_ENVS_PATH": raw}})
	want := []candidate{
		{"CONDA_ENVS_PATH", filepath.Clean(one), kindContainer, true},
		{"CONDA_ENVS_PATH", filepath.Clean(two), kindContainer, true},
		{"CONDA_ENVS_PATH", filepath.Clean(one), kindContainer, true},
	}
	wantIssues := []Issue{
		{Path: "CONDA_ENVS_PATH", Error: "hint path exceeds known-location limit"},
		{Path: "CONDA_ENVS_PATH", Error: "hint must be an absolute path"},
	}
	if !slices.Equal(got, want) || !slices.Equal(report.Issues, wantIssues) {
		t.Fatalf("candidates=%+v issues=%+v, want %+v and %+v", got, report.Issues, want, wantIssues)
	}
}

func TestKnownLayoutContractPathListTotalBoundary(t *testing.T) {
	base := knownTempDir(t)
	entries := func(last int) []string {
		full := boundaryPath(base, maxHintPathBytes, false)
		return []string{full, full, full, boundaryPath(base, last, false)}
	}
	// Semicolons preserve native Windows drive letters inside the entries.
	// 3 x 4096 + 4093 bytes + 3 separators = 16384, exactly the list limit.
	accepted := strings.Join(entries(4093), ";")
	if len(accepted) != maxPathListBytes {
		t.Fatalf("accepted fixture is %d bytes, want %d", len(accepted), maxPathListBytes)
	}
	got, report := knownHintBuild(knownInputs{goos: "windows", env: map[string]string{"CONDA_ENVS_PATH": accepted}})
	var want []candidate
	for _, e := range entries(4093) {
		want = append(want, candidate{"CONDA_ENVS_PATH", filepath.Clean(e), kindContainer, true})
	}
	if !slices.Equal(got, want) || len(report.Issues) != 0 {
		t.Fatalf("at limit: candidates=%d issues=%+v, want %d candidates and none", len(got), report.Issues, len(want))
	}

	// One byte over the limit: CONDA_PREFIX still resolves, the list yields nothing but one issue.
	over := strings.Join(entries(4094), ";")
	if len(over) != maxPathListBytes+1 {
		t.Fatalf("over fixture is %d bytes, want %d", len(over), maxPathListBytes+1)
	}
	env := map[string]string{"CONDA_PREFIX": base + "/cp", "CONDA_ENVS_PATH": over}
	got, report = knownHintBuild(knownInputs{goos: "windows", env: env})
	wantPrefix := []candidate{{"CONDA_PREFIX", filepath.Clean(base + "/cp"), kindPrefix, true}}
	wantIssues := []Issue{{Path: "CONDA_ENVS_PATH", Error: "path list exceeds known-location size limit"}}
	if !slices.Equal(got, wantPrefix) || !slices.Equal(report.Issues, wantIssues) {
		t.Fatalf("over limit: candidates=%+v issues=%+v, want %+v and %+v", got, report.Issues, wantPrefix, wantIssues)
	}
}
