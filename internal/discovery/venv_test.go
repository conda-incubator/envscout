package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeVenvCfg(t *testing.T, prefix, data string) {
	t.Helper()
	writeFile(t, filepath.Join(prefix, "pyvenv.cfg"), data)
}

func kindsByPath(report Report) map[string]string {
	got := map[string]string{}
	for _, env := range report.Environments {
		got[env.Path] = env.Kind
	}
	return got
}

func TestFindRecognizesVenvByPyvenvCfg(t *testing.T) {
	root := t.TempDir()
	venv := filepath.Join(root, "project", ".venv")
	writeVenvCfg(t, venv, "home = /usr/bin\nversion = 3.12.1\n")
	report, err := Find(context.Background(), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 {
		t.Fatalf("environments = %+v, want one venv", report.Environments)
	}
	got := report.Environments[0]
	if got.Kind != KindVenv || got.Path != venv || got.Name != ".venv" {
		t.Fatalf("unexpected venv: %+v", got)
	}
	if got.Revision != nil {
		t.Fatalf("venv revision must be nil, got %d", *got.Revision)
	}
	if len(report.Issues) != 0 {
		t.Fatalf("issues = %+v, want none", report.Issues)
	}
}

func TestFindVenvMarkerContentIsNotParsed(t *testing.T) {
	root := t.TempDir()
	writeVenvCfg(t, filepath.Join(root, "empty"), "")
	writeVenvCfg(t, filepath.Join(root, "garbage"), "\x00\xff not = a config ][")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 2 || len(report.Issues) != 0 {
		t.Fatalf("identity-only marker rejected on content: %+v", report)
	}
}

func TestFindCondaKindIsExplicit(t *testing.T) {
	root := t.TempDir()
	makePrefix(t, filepath.Join(root, "env"))
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Kind != KindConda {
		t.Fatalf("conda environment kind = %+v, want %q", report.Environments, KindConda)
	}
}

func TestFindArbitrarilyNamedVenvIsRecognized(t *testing.T) {
	root := t.TempDir()
	venv := filepath.Join(root, "anything-at-all")
	writeVenvCfg(t, venv, "home = /x\n")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := kindsByPath(report)[venv]; got != KindVenv {
		t.Fatalf("arbitrary venv name kind = %q, want %q; report %+v", got, KindVenv, report.Environments)
	}
}

func TestFindDirectoryNamedPyvenvCfgIsNotVenv(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dirmarker", "pyvenv.cfg"), 0o755); err != nil {
		t.Fatal(err)
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("directory named pyvenv.cfg recognized: %+v", report.Environments)
	}
}

func TestFindSymlinkedPyvenvCfgIgnoredWithIssue(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "pyvenv.cfg")
	writeFile(t, outside, "home = /x\n")
	venv := filepath.Join(root, "linked")
	if err := os.MkdirAll(venv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(venv, "pyvenv.cfg")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("symlinked pyvenv.cfg confirmed a venv: %+v", report.Environments)
	}
	if len(report.Issues) != 1 || report.Issues[0].Path != filepath.Join(venv, "pyvenv.cfg") {
		t.Fatalf("symlinked marker must yield exactly one issue, got %+v", report.Issues)
	}
}

func TestFindVenvSymlinkedInterpreterIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	venv := filepath.Join(root, "v")
	writeVenvCfg(t, venv, "home = /x\n")
	if err := os.MkdirAll(filepath.Join(venv, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/python", filepath.Join(venv, "bin", "python")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Kind != KindVenv || len(report.Issues) != 0 {
		t.Fatalf("interpreter link affected venv discovery: %+v", report)
	}
}

func TestFindBothMarkersPrefersValidConda(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "both")
	makePrefix(t, prefix)
	writeVenvCfg(t, prefix, "home = /x\n")
	for i := 0; i < 20; i++ {
		report, err := Find(context.Background(), []string{root}, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Environments) != 1 || report.Environments[0].Kind != KindConda {
			t.Fatalf("iteration %d: both markers = %+v, want one conda", i, report.Environments)
		}
		if len(report.Issues) != 0 {
			t.Fatalf("iteration %d: issues = %+v, want none", i, report.Issues)
		}
	}
}

func TestFindCorruptCondaMarkerBlocksVenvFallback(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "corrupt")
	if err := os.MkdirAll(filepath.Join(prefix, "conda-meta"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeVenvCfg(t, prefix, "home = /x\n")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("corrupt conda marker fell back to venv: %+v", report.Environments)
	}
	if len(report.Issues) != 0 {
		t.Fatalf("empty conda-meta must follow existing strict silence rules, got %+v", report.Issues)
	}
}

// A file conda-meta with no venv marker is not evidence of anything: the walker never
// inspects it, so it is silent, like any other ordinary non-directory entry.
func TestFindNonRegularCondaMetaWithoutVenvIsSilent(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "notdir")
	writeFile(t, filepath.Join(prefix, "conda-meta"), "not a directory")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, want silent empty result", report)
	}
}

func TestFindMalformedHistoryVenvIgnored(t *testing.T) {
	root := t.TempDir()
	venv := filepath.Join(root, "v")
	writeVenvCfg(t, venv, "home = /x\n")
	writeFile(t, filepath.Join(venv, "conda-meta", "history"), "==> broken")
	report, err := Find(context.Background(), []string{root}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("venv with conda-meta history without records treated as conda or venv: %+v", report.Environments)
	}
}

func TestFindMixedCondaUvPoetryVenvsIsolated(t *testing.T) {
	root := t.TempDir()
	condaEnv := filepath.Join(root, "conda", "env")
	makePrefix(t, condaEnv)
	uvVenv := filepath.Join(root, "uv", ".venv")
	writeVenvCfg(t, uvVenv, "home = /x\nuv = 0.5\n")
	poetryVenv := filepath.Join(root, "poetry", "venv")
	writeVenvCfg(t, poetryVenv, "home = /x\n")
	writeFile(t, filepath.Join(poetryVenv, "pyproject.toml"), "[tool.poetry]\n")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	got := kindsByPath(report)
	want := map[string]string{condaEnv: KindConda, uvVenv: KindVenv, poetryVenv: KindVenv}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Fatalf("path %s kind = %q, want %q", path, got[path], kind)
		}
	}
	if len(report.Issues) != 0 {
		t.Fatalf("issues = %+v, want none", report.Issues)
	}
}

func TestFindVenvRespectsPrunedDirectories(t *testing.T) {
	root := t.TempDir()
	writeVenvCfg(t, filepath.Join(root, "node_modules", "v"), "home = /x\n")
	writeVenvCfg(t, filepath.Join(root, "ok", "v"), "home = /x\n")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Path != filepath.Join(root, "ok", "v") {
		t.Fatalf("pruning not applied to venv markers: %+v", report.Environments)
	}
}

// A regular file named conda-meta is not a conda marker; a valid venv marker beside it wins.
func TestFindFileNamedCondaMetaFallsBackToVenv(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "filemeta")
	writeFile(t, filepath.Join(prefix, "conda-meta"), "not a directory")
	writeVenvCfg(t, prefix, "home = /x\n")
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || report.Environments[0].Kind != KindVenv || len(report.Issues) != 0 {
		t.Fatalf("file conda-meta with valid pyvenv.cfg: %+v", report)
	}
}

// A symlinked conda-meta is never followed as conda evidence.
func TestFindSymlinkedCondaMetaNotFollowed(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(t.TempDir(), "meta")
	writeFile(t, filepath.Join(real, "pkg.json"), `{"name":"pkg","version":"1"}`)
	prefix := filepath.Join(root, "linkmeta")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(prefix, "conda-meta")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	report, err := Find(context.Background(), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 0 {
		t.Fatalf("symlinked conda-meta treated as conda: %+v", report.Environments)
	}
}
