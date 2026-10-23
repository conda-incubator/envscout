package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeCondaFixture(t *testing.T, prefix string) {
	t.Helper()
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "package.json"), []byte(`{"name":"demo","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func knownTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFindKnownConda(t *testing.T) {
	home := knownTempDir(t)
	cwd := knownTempDir(t)
	active := filepath.Join(home, "elsewhere", "active")
	root := filepath.Join(home, "miniconda3")
	mamba := filepath.Join(home, "mamba-root")
	global := filepath.Join(home, ".pixi", "envs", "global")
	workspace := filepath.Join(cwd, ".pixi", "envs", "default")
	registry := filepath.Join(home, "registered")
	for _, path := range []string{active, root, filepath.Join(root, "envs", "child"), filepath.Join(mamba, "envs", "no-base"), global, workspace, registry} {
		makeCondaFixture(t, path)
	}
	if err := os.MkdirAll(filepath.Join(home, ".conda"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".conda", "environments.txt"), []byte(registry+"\n"+filepath.Join(home, "stale")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	progress := new(Progress)
	report, err := findKnownConda(knownInputs{home: home, cwd: cwd, goos: "darwin", env: map[string]string{
		condaPrefixVar: active, mambaRootVar: mamba,
	}}, progress)
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != ModeKnownLocations || len(report.Roots) != 0 || len(report.Environments) != 7 || len(report.Issues) != 0 {
		t.Fatalf("unexpected known-location report: %+v", report)
	}
	if progress.Environments.Load() != 7 || progress.Folders.Load() == 0 {
		t.Fatalf("unexpected progress: %+v", progress)
	}
	for i := 1; i < len(report.Environments); i++ {
		if report.Environments[i-1].Path >= report.Environments[i].Path {
			t.Fatalf("unordered or duplicate findings: %+v", report.Environments)
		}
	}
}

func TestKnownLocationQuickModeDoesNotWalkHome(t *testing.T) {
	home := knownTempDir(t)
	makeCondaFixture(t, filepath.Join(home, "unlisted", "hidden"))
	report, err := findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 0 {
		t.Fatalf("quick search walked unrelated home path: %+v, %v", report, err)
	}
}

func TestKnownHintsWithoutHomeOrVariables(t *testing.T) {
	report, err := findKnownConda(knownInputs{goos: "windows"}, nil)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 0 || len(report.Roots) != 0 {
		t.Fatalf("unexpected empty hint report: %+v, %v", report, err)
	}
}

func TestKnownLocationPathListsAndPixiHome(t *testing.T) {
	home := knownTempDir(t)
	pixiHome := filepath.Join(home, "pixi-home")
	for _, path := range []string{
		filepath.Join(home, "custom-a", "a"),
		filepath.Join(home, "custom-b", "b"),
		filepath.Join(pixiHome, "envs", "tool"),
	} {
		makeCondaFixture(t, path)
	}
	inputs := knownInputs{home: home, goos: "darwin", pathSeparator: os.PathListSeparator, env: map[string]string{
		condaEnvsPathVar: filepath.Join(home, "custom-a") + string(os.PathListSeparator) + filepath.Join(home, "custom-b"),
		pixiHomeVar:      pixiHome,
	}}
	report, err := findKnownConda(inputs, nil)
	if err != nil || len(report.Environments) != 3 || len(report.Issues) != 0 {
		t.Fatalf("unexpected env-list and Pixi discovery: %+v, %v", report, err)
	}
}

func TestKnownLocationWindowsPathList(t *testing.T) {
	home := knownTempDir(t)
	first := filepath.Join(home, "first")
	second := filepath.Join(home, "second")
	makeCondaFixture(t, filepath.Join(first, "a"))
	makeCondaFixture(t, filepath.Join(second, "b"))
	report, err := findKnownConda(knownInputs{home: home, goos: "windows", pathSeparator: ';', env: map[string]string{
		condaEnvsPathVar: first + ";" + second,
	}}, nil)
	if err != nil || len(report.Environments) != 2 || len(report.Issues) != 0 {
		t.Fatalf("path list separator did not split hints: %+v, %v", report, err)
	}
}

func TestKnownLocationConfiguredMissing(t *testing.T) {
	home := knownTempDir(t)
	report, err := findKnownConda(knownInputs{home: home, goos: "darwin", env: map[string]string{
		condaPrefixVar: filepath.Join(home, "missing"),
	}}, nil)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "not found") {
		t.Fatalf("missing configured prefix should be reported: %+v, %v", report, err)
	}
}

func TestExplicitWalkFindsKnownLocationEnvironmentOnce(t *testing.T) {
	home := knownTempDir(t)
	root := filepath.Join(home, "miniconda3")
	env := filepath.Join(root, "envs", "demo")
	makeCondaFixture(t, env)
	report, err := FindCondaWithProgress([]string{root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Path != env {
		t.Fatalf("expected the walk to find %q exactly once: %+v", env, report.Environments)
	}
	if len(report.Hints) != 0 {
		t.Fatalf("roots mode must not record hint summaries: %+v", report.Hints)
	}
}

func TestHintRootCannotEscapeExplicitScope(t *testing.T) {
	root := knownTempDir(t)
	outside := knownTempDir(t)
	makeCondaFixture(t, filepath.Join(outside, "hidden"))
	link := filepath.Join(root, "hint")
	if err := os.Symlink(filepath.Join(outside, "hidden"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := openHintDir(link, root); err == nil {
		t.Fatal("in-scope symlink must not open an external prefix")
	}
	if _, err := openHintDir(filepath.Join(outside, "hidden"), root); err == nil {
		t.Fatal("lexically out-of-scope hint must not open")
	}
}

func TestMetadataSymlinkIsNotEvidence(t *testing.T) {
	home := knownTempDir(t)
	prefix := filepath.Join(home, "miniconda3")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(knownTempDir(t), "valid.json")
	if err := os.WriteFile(outside, []byte(`{"name":"outside","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(meta, "package.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report, err := findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Environments) != 0 {
		t.Fatalf("symlinked metadata confirmed outside package: %+v, %v", report, err)
	}
}

func TestKnownLocationHomeAndCwdFailures(t *testing.T) {
	report, err := findKnownConda(knownInputs{goos: "windows", homeErr: fmt.Errorf("home unavailable"), cwdErr: fmt.Errorf("cwd unavailable")}, nil)
	if err != nil || len(report.Issues) != 2 || report.Issues[0].Path != "cwd" || report.Issues[1].Path != "home" {
		t.Fatalf("missing quick-mode scope error: %+v, %v", report.Issues, err)
	}
}

func TestCondaMetadataLimit(t *testing.T) {
	home := knownTempDir(t)
	meta := filepath.Join(home, "miniconda3", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range maxMetadataEntries + 1 {
		if err := os.WriteFile(filepath.Join(meta, fmt.Sprintf("%05d.txt", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) == 0 || !strings.Contains(report.Issues[0].Error, "exceeds") {
		t.Fatalf("metadata entry cap was not reported: %+v, %v", report, err)
	}
}

func TestKnownLocationSymlinkDoesNotEscape(t *testing.T) {
	home := knownTempDir(t)
	outside := knownTempDir(t)
	makeCondaFixture(t, filepath.Join(outside, "base"))
	if err := os.Symlink(filepath.Join(outside, "base"), filepath.Join(home, "miniconda3")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report, err := findKnownConda(knownInputs{home: home, goos: "darwin"}, nil)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "symlink") {
		t.Fatalf("symlink hint followed or not reported: %+v, %v", report, err)
	}
}

func TestKnownLocationRegistryAndCaps(t *testing.T) {
	home := knownTempDir(t)
	if err := os.MkdirAll(filepath.Join(home, ".conda"), 0o755); err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(home, ".conda", "environments.txt")
	if err := os.WriteFile(registry, []byte("relative\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "non-absolute") {
		t.Fatalf("malformed registry was silently accepted: %+v, %v", report, err)
	}
	if err := os.WriteFile(registry, []byte(strings.Repeat("\n", maxRegistryLines+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err = findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "exceeded") {
		t.Fatalf("registry line cap was not reported: %+v, %v", report, err)
	}
}

func TestKnownLocationContainerCap(t *testing.T) {
	home := knownTempDir(t)
	container := filepath.Join(home, ".conda", "envs")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range maxContainerEntries + 1 {
		if err := os.Mkdir(filepath.Join(container, fmt.Sprintf("env-%04d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	report, err := findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Issues) == 0 || !strings.Contains(report.Issues[0].Error, "exceeds") {
		t.Fatalf("container cap was not reported: %+v, %v", report.Issues, err)
	}
}

func TestKnownLocationCandidateCap(t *testing.T) {
	home := knownTempDir(t)
	container := filepath.Join(home, ".conda", "envs")
	if err := os.MkdirAll(container, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range maxHintCandidates + 1 {
		makeCondaFixture(t, filepath.Join(container, fmt.Sprintf("env-%04d", i)))
	}
	report, err := findKnownConda(knownInputs{home: home, goos: "windows"}, nil)
	if err != nil || len(report.Environments) == 0 || len(report.Environments) > maxHintCandidates || len(report.Issues) == 0 || !strings.Contains(report.Issues[0].Error, "limit") {
		t.Fatalf("candidate budget did not report partial results: %d environments, %+v, %v", len(report.Environments), report.Issues, err)
	}
}
