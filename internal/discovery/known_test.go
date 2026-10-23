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
