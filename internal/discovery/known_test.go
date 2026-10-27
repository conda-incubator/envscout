package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func knownTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func knownFind(t *testing.T, inputs knownInputs) Report {
	t.Helper()
	report, err := findKnown(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func hasIssue(report Report, substr string) bool {
	for _, issue := range report.Issues {
		if strings.Contains(issue.Error, substr) || strings.Contains(issue.Path, substr) {
			return true
		}
	}
	return false
}

func TestFindKnownEnvironments(t *testing.T) {
	home := knownTempDir(t)
	cwd := knownTempDir(t)
	active := filepath.Join(home, "elsewhere", "active")
	root := filepath.Join(home, "miniconda3")
	mamba := filepath.Join(home, "mamba-root")
	global := filepath.Join(home, ".pixi", "envs", "global")
	workspace := filepath.Join(cwd, ".pixi", "envs", "default")
	registry := filepath.Join(home, "registered")
	for _, path := range []string{active, root, filepath.Join(root, "envs", "child"), filepath.Join(mamba, "envs", "no-base"), global, workspace, registry} {
		makePrefix(t, path)
	}
	writeFile(t, filepath.Join(home, ".conda", "environments.txt"), registry+"\n"+filepath.Join(home, "stale")+"\n")
	report := knownFind(t, knownInputs{home: home, cwd: cwd, goos: "darwin", env: map[string]string{
		"CONDA_PREFIX": active, "MAMBA_ROOT_PREFIX": mamba,
	}})
	if report.Mode != ModeKnownLocations || len(report.Roots) != 0 || len(report.Environments) != 7 || len(report.Issues) != 0 {
		t.Fatalf("unexpected known-location report: %+v", report)
	}
	for i := 1; i < len(report.Environments); i++ {
		if report.Environments[i-1].Path >= report.Environments[i].Path {
			t.Fatalf("unordered or duplicate findings: %+v", report.Environments)
		}
	}
}

func TestKnownQuickModeDoesNotWalkHome(t *testing.T) {
	home := knownTempDir(t)
	makePrefix(t, filepath.Join(home, "unlisted", "hidden"))
	report := knownFind(t, knownInputs{home: home, goos: "windows"})
	if len(report.Environments) != 0 || len(report.Issues) != 0 {
		t.Fatalf("quick search walked unrelated home path: %+v", report)
	}
}

func TestKnownNoHomeOrVariablesIsSilent(t *testing.T) {
	report := knownFind(t, knownInputs{goos: "windows"})
	if len(report.Environments) != 0 || len(report.Issues) != 0 || len(report.Roots) != 0 {
		t.Fatalf("unexpected empty report: %+v", report)
	}
}

func TestPreCancelledKnownReadsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := findKnown(ctx, knownInputs{home: "/does/not/matter", goos: "darwin", env: map[string]string{"CONDARC": "/x"}})
	if !errors.Is(err, context.Canceled) || len(report.Hints) != 0 || len(report.Issues) != 0 {
		t.Fatalf("pre-cancelled run did work: %+v, %v", report, err)
	}
	report, err = FindKnown(ctx)
	if !errors.Is(err, context.Canceled) || report.Environments == nil {
		t.Fatalf("FindKnown pre-cancel = %+v, %v", report, err)
	}
}

func TestKnownPathListsPixiHomeAndSeparator(t *testing.T) {
	home := knownTempDir(t)
	pixiHome := filepath.Join(home, "pixi-home")
	for _, path := range []string{
		filepath.Join(home, "custom-a", "a"),
		filepath.Join(home, "custom-b", "b"),
		filepath.Join(pixiHome, "envs", "tool"),
	} {
		makePrefix(t, path)
	}
	report := knownFind(t, knownInputs{home: home, goos: runtime.GOOS, env: map[string]string{
		"CONDA_ENVS_PATH": filepath.Join(home, "custom-a") + string(os.PathListSeparator) + filepath.Join(home, "custom-b"),
		"PIXI_HOME":       pixiHome,
	}})
	if len(report.Environments) != 3 || len(report.Issues) != 0 {
		t.Fatalf("unexpected env-list and Pixi discovery: %+v", report)
	}
	// Windows separator is taken from the injected platform, not the test host.
	first := filepath.Join(home, "first")
	second := filepath.Join(home, "second")
	makePrefix(t, filepath.Join(first, "a"))
	makePrefix(t, filepath.Join(second, "b"))
	win := knownFind(t, knownInputs{home: home, goos: "windows", env: map[string]string{
		"CONDA_ENVS_PATH": first + ";" + second,
	}})
	if len(win.Environments) != 2 {
		t.Fatalf("windows separator not honored: %+v", win)
	}
}

func TestKnownConfiguredInvalidValuesAreIssues(t *testing.T) {
	home := knownTempDir(t)
	missing := knownFind(t, knownInputs{home: home, goos: "darwin", env: map[string]string{"CONDA_PREFIX": filepath.Join(home, "missing")}})
	if len(missing.Environments) != 0 || !hasIssue(missing, "not found") {
		t.Fatalf("missing configured prefix not reported: %+v", missing)
	}
	relative := knownFind(t, knownInputs{goos: "darwin", env: map[string]string{"CONDA_PREFIX": "relative/path"}})
	if !hasIssue(relative, "absolute") {
		t.Fatalf("relative configured value silently accepted: %+v", relative.Issues)
	}
}

func TestMissingSystemHintsAreSilent(t *testing.T) {
	home := knownTempDir(t)
	report := knownFind(t, knownInputs{home: home, goos: "darwin"})
	if len(report.Issues) != 0 {
		t.Fatalf("absent default locations reported as issues: %+v", report.Issues)
	}
}

func TestKnownHomeAndCwdFailuresReported(t *testing.T) {
	report := knownFind(t, knownInputs{goos: "windows", homeErr: fmt.Errorf("home unavailable"), cwdErr: fmt.Errorf("cwd unavailable")})
	if len(report.Issues) != 2 || report.Issues[0].Path != "cwd" || report.Issues[1].Path != "home" {
		t.Fatalf("missing quick-mode scope error: %+v", report.Issues)
	}
}

func TestKnownSymlinkHintNotFollowed(t *testing.T) {
	home := knownTempDir(t)
	outside := knownTempDir(t)
	makePrefix(t, filepath.Join(outside, "base"))
	if err := os.Symlink(filepath.Join(outside, "base"), filepath.Join(home, "miniconda3")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report := knownFind(t, knownInputs{home: home, goos: "darwin"})
	if len(report.Environments) != 0 || !hasIssue(report, "symlink") {
		t.Fatalf("symlink hint followed or not reported: %+v", report)
	}
}

func TestKnownRegistryMalformedCappedAndLongLines(t *testing.T) {
	home := knownTempDir(t)
	registry := filepath.Join(home, ".conda", "environments.txt")
	writeFile(t, registry, "relative\n")
	if report := knownFind(t, knownInputs{home: home, goos: "windows"}); !hasIssue(report, "non-absolute") {
		t.Fatalf("malformed registry accepted: %+v", report)
	}
	writeFile(t, registry, strings.Repeat("\n", maxRegistryLines+1))
	if report := knownFind(t, knownInputs{home: home, goos: "windows"}); !hasIssue(report, "exceeded") {
		t.Fatalf("registry line cap not reported: %+v", report)
	}
	writeFile(t, registry, "/"+strings.Repeat("x", maxRegistryLineLen+10)+"\n")
	if report := knownFind(t, knownInputs{home: home, goos: "windows"}); !hasIssue(report, "read registry") {
		t.Fatalf("over-long registry line silently ignored: %+v", report)
	}
}

// Container expansion emits one truncation issue, not one per skipped child.
func TestKnownContainerCapSingleIssue(t *testing.T) {
	home := knownTempDir(t)
	container := filepath.Join(home, ".conda", "envs")
	for i := range maxContainerEntries + 1 {
		if err := os.MkdirAll(filepath.Join(container, fmt.Sprintf("env-%04d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	report := knownFind(t, knownInputs{home: home, goos: "windows"})
	count := 0
	for _, issue := range report.Issues {
		if strings.Contains(issue.Error, "exceeds") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("container cap reported %d times, want 1: %+v", count, report.Issues)
	}
}

func TestKnownCandidateBudgetSingleIssue(t *testing.T) {
	home := knownTempDir(t)
	container := filepath.Join(home, ".conda", "envs")
	for i := range maxHintCandidates + 1 {
		makePrefix(t, filepath.Join(container, fmt.Sprintf("env-%04d", i)))
	}
	report := knownFind(t, knownInputs{home: home, goos: "windows"})
	if len(report.Environments) == 0 || len(report.Environments) > maxHintCandidates {
		t.Fatalf("expected bounded partial results, got %d", len(report.Environments))
	}
	limit := 0
	for _, issue := range report.Issues {
		if strings.Contains(issue.Error, "limit") {
			limit++
		}
	}
	if limit != 1 {
		t.Fatalf("budget exhaustion reported %d times, want 1", limit)
	}
	for _, h := range report.Hints {
		if h.Skipped < 0 || h.Checked < 0 {
			t.Fatalf("negative hint counter: %+v", h)
		}
	}
}

// ---- declarative table coverage ----

func TestKnownGroupedInstallLocations(t *testing.T) {
	home := "/h"
	cands := knownCandidates(knownInputs{home: home, goos: "darwin"}, newCollector(&Report{}))
	paths := map[string]bool{}
	for _, c := range cands {
		paths[c.path] = true
	}
	for _, want := range []string{
		filepath.Join(home, "miniconda"), filepath.Join(home, "anaconda"),
		filepath.Join(home, "opt", "anaconda3"), filepath.Join(home, "opt", "miniforge3"), filepath.Join(home, "opt", "mambaforge"),
		filepath.Clean("/usr/share/conda"), filepath.Join("/opt", "miniforge3"), filepath.Join("/usr/local", "mambaforge"),
	} {
		if !paths[want] {
			t.Fatalf("missing candidate %s", want)
		}
	}
}

func TestKnownPlatformGating(t *testing.T) {
	unix := knownCandidates(knownInputs{home: "/h", goos: "linux"}, newCollector(&Report{}))
	win := knownCandidates(knownInputs{home: `C:\h`, goos: "windows", env: map[string]string{"PROGRAMDATA": `C:\PD`, "LOCALAPPDATA": `C:\LA`}}, newCollector(&Report{}))
	for _, c := range win {
		if strings.HasPrefix(c.source, "system/") || strings.HasPrefix(c.source, "darwin/") {
			t.Fatalf("unix-only candidate %q leaked into windows", c.source)
		}
	}
	for _, c := range unix {
		if strings.HasPrefix(c.source, "windows/") {
			t.Fatalf("windows-only candidate %q leaked into unix", c.source)
		}
	}
}

// Caskroom is Darwin-only and probes exact children, never a recursive walk.
func TestCaskroomDarwinExactChildren(t *testing.T) {
	product := filepath.Join(knownTempDir(t), "miniconda")
	makePrefix(t, filepath.Join(product, "24.1.0", "miniconda3"))
	makePrefix(t, filepath.Join(product, "24.1.0", "deep", "conda"))
	col := newCollector(&Report{})
	versions := caskroomVersions(product, col)
	if len(versions) != 1 || versions[0] != filepath.Join(product, "24.1.0") {
		t.Fatalf("caskroom must list exactly one version level: %v", versions)
	}
	if len(col.report.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", col.report.Issues)
	}
}

// ---- condarc ----

func TestCondarcTypedParseAndHomeExpansion(t *testing.T) {
	home := knownTempDir(t)
	first := filepath.Join(home, "from-condarc")
	makePrefix(t, filepath.Join(first, "env"))
	writeFile(t, filepath.Join(home, ".condarc"), "envs_dirs:\n  - "+first+"\npkgs_dirs:\n  - "+filepath.Join(home, "pkgs")+"\n")
	report := knownFind(t, knownInputs{home: home, goos: "darwin"})
	if len(report.Environments) != 1 || report.Environments[0].Path != filepath.Join(first, "env") {
		t.Fatalf("condarc envs_dirs not discovered: %+v", report.Environments)
	}
}

func TestCondarcEnvVarAndHomeExpansion(t *testing.T) {
	home := knownTempDir(t)
	target := filepath.Join(home, "expanded", "env")
	makePrefix(t, target)
	writeFile(t, filepath.Join(home, ".config", "conda", "condarc"), "envs_dirs:\n  - ${HOMEBASE}/expanded\n  - $HOME/expanded\n")
	report := knownFind(t, knownInputs{home: home, goos: "darwin", env: map[string]string{"HOMEBASE": home, "HOME": "/ignored-host-home"}})
	if len(report.Environments) != 1 || report.Environments[0].Path != target {
		t.Fatalf("envvar expansion failed: %+v", report)
	}
	if len(report.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", report.Issues)
	}
}

func TestCondarcMalformedRelativeAndExplicit(t *testing.T) {
	home := knownTempDir(t)
	writeFile(t, filepath.Join(home, ".condarc"), "envs_dirs: [unclosed\n")
	if report := knownFind(t, knownInputs{home: home, goos: "darwin"}); !hasIssue(report, "malformed condarc") {
		t.Fatalf("malformed condarc not reported: %+v", report.Issues)
	}
	writeFile(t, filepath.Join(home, ".condarc"), "envs_dirs:\n  - relative/dir\n")
	if report := knownFind(t, knownInputs{home: home, goos: "darwin"}); !hasIssue(report, "not absolute") {
		t.Fatalf("relative envs_dirs accepted: %+v", report.Issues)
	}
	// Missing implicit condarc is silent; missing explicit CONDARC is an issue.
	if report := knownFind(t, knownInputs{home: knownTempDir(t), goos: "darwin"}); len(report.Issues) != 0 {
		t.Fatalf("missing implicit condarc reported: %+v", report.Issues)
	}
	explicitHome := knownTempDir(t)
	explicit := knownFind(t, knownInputs{home: explicitHome, goos: runtime.GOOS, env: map[string]string{"CONDARC": filepath.Join(explicitHome, "absent", "condarc")}})
	if !hasIssue(explicit, "not found") {
		t.Fatalf("missing explicit CONDARC not reported: %+v", explicit.Issues)
	}
}

func TestExpandConfigPathHomeRequired(t *testing.T) {
	if _, err := expandConfigPath("~/x", knownInputs{}); err == nil {
		t.Fatal("expansion without home must fail")
	}
}

// Symlinked container children are never followed out of scope.
func TestKnownContainerSymlinkChildNotFollowed(t *testing.T) {
	home := knownTempDir(t)
	outside := knownTempDir(t)
	makePrefix(t, filepath.Join(outside, "hidden"))
	container := filepath.Join(home, ".conda", "envs")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "hidden"), filepath.Join(container, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report := knownFind(t, knownInputs{home: home, goos: "windows"})
	if len(report.Environments) != 0 {
		t.Fatalf("symlinked container child escaped scope: %+v", report.Environments)
	}
}

// ---- virtualenv known-location candidates ----

// venvMarker creates a virtualenv-shaped prefix: pyvenv.cfg, no conda-meta, no interpreter.
func venvMarker(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "pyvenv.cfg"), "home = /base/python\ninclude-system-site-packages = false\n")
	return dir
}

func venvPaths(report Report) map[string]bool {
	out := map[string]bool{}
	for _, env := range report.Environments {
		out[env.Path] = true
	}
	return out
}

func TestVenvCwdCandidateRows(t *testing.T) {
	cwd := knownTempDir(t)
	cases := map[string]string{
		"cwd prefix":      cwd,
		"cwd .venv":       filepath.Join(cwd, ".venv"),
		"cwd venv":        filepath.Join(cwd, "venv"),
		"cwd .env":        filepath.Join(cwd, ".env"),
		"cwd .virtualenv": filepath.Join(cwd, ".virtualenv"),
	}
	for name, dir := range cases {
		venvMarker(t, dir)
		report := knownFind(t, knownInputs{cwd: cwd, goos: "linux"})
		if !venvPaths(report)[dir] {
			t.Fatalf("%s: virtualenv at %s not discovered: %+v", name, dir, report.Environments)
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVenvKnownDotenvFileIsNotAnInspectionFailure(t *testing.T) {
	cwd := knownTempDir(t)
	writeFile(t, filepath.Join(cwd, ".env"), "SETTING=value\n")
	venv := venvMarker(t, filepath.Join(cwd, ".venv"))
	report := knownFind(t, knownInputs{cwd: cwd, goos: "linux"})
	if !venvPaths(report)[venv] || len(report.Issues) != 0 {
		t.Fatalf("a normal dotenv file is not a broken virtualenv candidate: %+v", report)
	}
}

func TestVenvActiveAbsoluteOnly(t *testing.T) {
	home := knownTempDir(t)
	active := venvMarker(t, filepath.Join(home, "work", "active-venv"))
	report := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"VIRTUAL_ENV": active}})
	if !venvPaths(report)[active] || len(report.Issues) != 0 {
		t.Fatalf("active VIRTUAL_ENV not discovered: %+v", report)
	}
	relative := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"VIRTUAL_ENV": "rel/venv"}})
	if !hasIssue(relative, "absolute") {
		t.Fatalf("relative VIRTUAL_ENV accepted: %+v", relative.Issues)
	}
}

func TestVenvActiveMissingIsIssue(t *testing.T) {
	home := knownTempDir(t)
	report := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"VIRTUAL_ENV": filepath.Join(home, "gone")}})
	if len(report.Environments) != 0 || !hasIssue(report, "not found") {
		t.Fatalf("missing active virtualenv not reported: %+v", report)
	}
}

func TestVenvUvProjectEnvironmentAbsoluteOnly(t *testing.T) {
	home := knownTempDir(t)
	abs := venvMarker(t, filepath.Join(home, "uv-project", ".venv"))
	ok := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"UV_PROJECT_ENVIRONMENT": abs}})
	if !venvPaths(ok)[abs] {
		t.Fatalf("absolute UV_PROJECT_ENVIRONMENT not discovered: %+v", ok)
	}
	rel := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"UV_PROJECT_ENVIRONMENT": ".venv"}})
	if len(rel.Environments) != 0 || !hasIssue(rel, "absolute") {
		t.Fatalf("relative UV_PROJECT_ENVIRONMENT must be an issue, not probed: %+v", rel)
	}
}

func TestVenvWorkonHomeContainer(t *testing.T) {
	home := knownTempDir(t)
	workon := filepath.Join(home, "workon")
	child := venvMarker(t, filepath.Join(workon, "proj"))
	report := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"WORKON_HOME": workon}})
	if !venvPaths(report)[child] {
		t.Fatalf("WORKON_HOME child not discovered: %+v", report)
	}
}

func TestVenvHomeContainers(t *testing.T) {
	home := knownTempDir(t)
	a := venvMarker(t, filepath.Join(home, ".virtualenvs", "a"))
	b := venvMarker(t, filepath.Join(home, ".venvs", "b"))
	report := knownFind(t, knownInputs{home: home, goos: "linux"})
	paths := venvPaths(report)
	if !paths[a] || !paths[b] {
		t.Fatalf("home virtualenv containers not scanned: %+v", report.Environments)
	}
}

func TestVenvPoetryVirtualenvsPathOverride(t *testing.T) {
	home := knownTempDir(t)
	custom := filepath.Join(home, "poetry-envs")
	child := venvMarker(t, filepath.Join(custom, "proj-py3.12"))
	report := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"POETRY_VIRTUALENVS_PATH": custom}})
	if !venvPaths(report)[child] {
		t.Fatalf("POETRY_VIRTUALENVS_PATH child not discovered: %+v", report)
	}
	rel := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"POETRY_VIRTUALENVS_PATH": "relative"}})
	if !hasIssue(rel, "absolute") {
		t.Fatalf("relative POETRY_VIRTUALENVS_PATH accepted: %+v", rel.Issues)
	}
}

func TestVenvPoetryCacheDirOverride(t *testing.T) {
	home := knownTempDir(t)
	cache := filepath.Join(home, "pcache")
	child := venvMarker(t, filepath.Join(cache, "virtualenvs", "proj"))
	report := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"POETRY_CACHE_DIR": cache}})
	if !venvPaths(report)[child] {
		t.Fatalf("POETRY_CACHE_DIR/virtualenvs child not discovered: %+v", report)
	}
}

func TestVenvPoetryDefaultPerPlatform(t *testing.T) {
	home := knownTempDir(t)
	cases := []struct {
		name string
		goos string
		env  map[string]string
		dir  string
	}{
		{"darwin", "darwin", nil, filepath.Join(home, "Library", "Caches", "pypoetry", "virtualenvs")},
		{"linux xdg", "linux", map[string]string{"XDG_CACHE_HOME": filepath.Join(home, "xdg")}, filepath.Join(home, "xdg", "pypoetry", "virtualenvs")},
		{"linux fallback", "linux", nil, filepath.Join(home, ".cache", "pypoetry", "virtualenvs")},
		{"windows", "windows", map[string]string{"LOCALAPPDATA": filepath.Join(home, "LocalAppData")}, filepath.Join(home, "LocalAppData", "pypoetry", "Cache", "virtualenvs")},
	}
	for _, tc := range cases {
		child := venvMarker(t, filepath.Join(tc.dir, "proj"))
		env := tc.env
		if env == nil {
			env = map[string]string{}
		}
		report := knownFind(t, knownInputs{home: home, goos: tc.goos, env: env})
		if !venvPaths(report)[child] {
			t.Fatalf("%s: default poetry cache child not discovered: %+v", tc.name, report.Environments)
		}
		if err := os.RemoveAll(tc.dir); err != nil {
			t.Fatal(err)
		}
	}
}

// A directory without pyvenv.cfg or conda-meta is not a false positive.
func TestVenvUnmarkedDirectoriesNotFalsePositive(t *testing.T) {
	home := knownTempDir(t)
	plain := filepath.Join(home, ".virtualenvs", "plain")
	if err := os.MkdirAll(filepath.Join(plain, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	report := knownFind(t, knownInputs{home: home, goos: "linux"})
	if len(report.Environments) != 0 || len(report.Issues) != 0 {
		t.Fatalf("unmarked directory reported: %+v", report)
	}
}

// Active venv with no real interpreter is still a virtualenv candidate.
func TestVenvNoInterpreterStillCandidate(t *testing.T) {
	home := knownTempDir(t)
	active := venvMarker(t, filepath.Join(home, "no-python"))
	report := knownFind(t, knownInputs{home: home, goos: "linux", env: map[string]string{"VIRTUAL_ENV": active}})
	if !venvPaths(report)[active] {
		t.Fatalf("virtualenv without bin/python dropped: %+v", report)
	}
}

// A symlinked virtualenv entry is never followed, even when it holds a valid marker.
func TestVenvNormalLinkIgnored(t *testing.T) {
	home := knownTempDir(t)
	outside := knownTempDir(t)
	target := venvMarker(t, filepath.Join(outside, "real"))
	container := filepath.Join(home, ".virtualenvs")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(container, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report := knownFind(t, knownInputs{home: home, goos: "linux"})
	if len(report.Environments) != 0 {
		t.Fatalf("symlinked virtualenv followed: %+v", report.Environments)
	}
}

// A virtualenv container does not recurse: a marker nested two levels deep is ignored.
func TestVenvContainerNotRecursive(t *testing.T) {
	home := knownTempDir(t)
	deep := venvMarker(t, filepath.Join(home, ".virtualenvs", "group", "deep"))
	report := knownFind(t, knownInputs{home: home, goos: "linux"})
	if venvPaths(report)[deep] {
		t.Fatalf("container recursed past one level: %+v", report.Environments)
	}
}

func TestVenvSiblingConditionsIndependent(t *testing.T) {
	// Sibling of an absent conda-meta on a venv: the marker alone qualifies.
	home := knownTempDir(t)
	plain := venvMarker(t, filepath.Join(home, ".venvs", "only-cfg"))
	report := knownFind(t, knownInputs{home: home, goos: "linux"})
	if !venvPaths(report)[plain] {
		t.Fatalf("pyvenv.cfg alone not sufficient: %+v", report)
	}
}

func TestVenvCandidateBudgetCapped(t *testing.T) {
	home := knownTempDir(t)
	container := filepath.Join(home, ".virtualenvs")
	for i := range maxHintCandidates + 1 {
		venvMarker(t, filepath.Join(container, fmt.Sprintf("v-%04d", i)))
	}
	report := knownFind(t, knownInputs{home: home, goos: "linux"})
	if len(report.Environments) == 0 || len(report.Environments) > maxHintCandidates {
		t.Fatalf("venv budget not capped: %d", len(report.Environments))
	}
	limit := 0
	for _, issue := range report.Issues {
		if strings.Contains(issue.Error, "limit") {
			limit++
		}
	}
	if limit != 1 {
		t.Fatalf("venv budget exhaustion reported %d times, want 1", limit)
	}
}

func TestVenvPreCancelledReadsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := findKnown(ctx, knownInputs{home: "/x", goos: "linux", env: map[string]string{"VIRTUAL_ENV": "/x/v", "POETRY_VIRTUALENVS_PATH": "/x/p"}})
	if !errors.Is(err, context.Canceled) || len(report.Hints) != 0 || len(report.Issues) != 0 {
		t.Fatalf("pre-cancelled venv run did work: %+v, %v", report, err)
	}
}
