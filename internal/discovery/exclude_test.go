package discovery

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/conda-incubator/envscout/internal/testimage"
)

func TestFindExcludesDirectoriesBeforeInspection(t *testing.T) {
	root := knownTempDir(t)
	kept := filepath.Join(root, "keep")
	makePrefix(t, kept)
	makePrefix(t, filepath.Join(root, "drop", "nested"))
	writeVenvCfg(t, filepath.Join(root, "project", "cache", "venv"), "")
	writeFile(t, filepath.Join(root, "drop", "nested", "conda-meta", "history"), "invalid history")
	ctx, err := WithExclusions(context.Background(), []string{"drop", "project/cache/**"})
	if err != nil {
		t.Fatal(err)
	}
	counts := &Progress{}
	report, err := Find(WithProgress(ctx, counts), []string{root, filepath.Join(root, "drop", "nested")}, true)
	if err != nil || len(report.Issues) != 0 || len(report.Environments) != 1 || report.Environments[0].Path != kept || counts.Environments.Load() != 1 {
		t.Fatalf("excluded folders must not be traversed, inspected or override nested roots: %+v %v", report, err)
	}
}

func TestFindKnownExcludesHintAncestors(t *testing.T) {
	home := knownTempDir(t)
	kept := filepath.Join(home, "miniconda3", "envs", "keep")
	makePrefix(t, kept)
	makePrefix(t, filepath.Join(home, "miniconda3", "envs", "drop"))
	excluded := filepath.Join(home, "excluded", "active")
	makePrefix(t, excluded)
	ctx, err := WithExclusions(context.Background(), []string{"drop", filepath.ToSlash(filepath.Join(home, "excluded"))})
	if err != nil {
		t.Fatal(err)
	}
	report, err := findKnown(ctx, knownInputs{home: home, cwd: home, goos: "linux", env: map[string]string{"CONDA_PREFIX": excluded}})
	if err != nil || len(report.Issues) != 0 || len(report.Environments) != 1 || report.Environments[0].Path != kept {
		t.Fatalf("direct hints must not bypass excluded ancestors: %+v %v", report, err)
	}
}

func TestFindNestedRootCannotBypassParentRelativeExclusion(t *testing.T) {
	root := knownTempDir(t)
	project := filepath.Join(root, "project")
	makePrefix(t, filepath.Join(project, "keep"))
	makePrefix(t, filepath.Join(project, "cache", "drop"))
	ctx, err := WithExclusions(context.Background(), []string{"project/cache"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Find(ctx, []string{root, project}, false)
	if err != nil || len(report.Environments) != 1 || report.Environments[0].Name != "keep" {
		t.Fatalf("an overlapping root must not rediscover the parent's excluded subtree: %+v %v", report, err)
	}
}

func TestFindImageExcludesBeforeRecordAndHistoryChecks(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "keep/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "opt/drop/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "opt/drop/conda-meta/history", Data: "invalid history"},
	})
	ctx, err := WithExclusions(context.Background(), []string{"opt/drop"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := FindImage(ctx, img, true)
	if err != nil || len(report.Issues) != 0 || len(report.Environments) != 1 || report.Environments[0].Path != "/keep" || report.MetadataFilesExamined != 1 {
		t.Fatalf("image exclusions apply to discovery, before metadata checks: %+v %v", report, err)
	}
}

func TestExclusionPatterns(t *testing.T) {
	for _, test := range []struct {
		pattern, name string
		want          bool
	}{
		{"cache", "/root/project/cache/venv", true},
		{"cache", "/root/project/cacheable/venv", false},
		{"project/*", "/root/project/cache/venv", true},
		{"project/*", "/root/other/project/cache", false},
		{"**/cache", "/root/cache", true},
		{"./project/cache/", "/root/project/cache/venv", true},
		{"/root/project", "/root/project/venv", true},
		{"/root/project", "/root/projectile/venv", false},
		{"{cache,build}", "/root/build/venv", true},
		{"cache,build", "/root/cache/venv", false},
		{"cache,build", "/root/cache,build/venv", true},
		{".", "/root", true},
		{"/", "/root/project", true},
	} {
		t.Run(test.pattern+test.name, func(t *testing.T) {
			ctx, err := WithExclusions(context.Background(), []string{test.pattern})
			if err != nil {
				t.Fatal(err)
			}
			if got := excluded(ctx, "/root", test.name); got != test.want {
				t.Fatalf("pattern %q against %q = %v, want %v", test.pattern, test.name, got, test.want)
			}
		})
	}
	ctx := context.Background()
	if got, err := WithExclusions(ctx, nil); err != nil || got != ctx || excluded(ctx, "/root", "/root/cache") {
		t.Fatal("absent exclusions must preserve the original context and behavior")
	}
	for _, pattern := range []string{"", "[", "{cache,build"} {
		if _, err := WithExclusions(ctx, []string{pattern}); err == nil {
			t.Fatalf("invalid pattern %q was accepted", pattern)
		}
	}
}

func TestExcludeMatchesFoldersNotEnvironmentMarkerFiles(t *testing.T) {
	root := knownTempDir(t)
	venv := filepath.Join(root, "keep")
	writeVenvCfg(t, venv, "")
	ctx, err := WithExclusions(context.Background(), []string{"pyvenv.cfg", "*.json"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Find(ctx, []string{root}, false)
	if err != nil || len(report.Environments) != 1 || report.Environments[0].Path != venv {
		t.Fatalf("folder globs must not exclude marker files: %+v %v", report, err)
	}
}

func TestFindExcludedRootIsNotOpened(t *testing.T) {
	missing := filepath.Join(knownTempDir(t), "excluded", "missing")
	ctx, err := WithExclusions(context.Background(), []string{"excluded"})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Find(ctx, []string{missing}, false)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 0 {
		t.Fatalf("an excluded explicit subtree must not be accessed: %+v %v", report, err)
	}
}

func TestWindowsExclusionPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows path semantics")
	}
	for _, pattern := range []string{`C:\root\drop`, `C:/root/drop`, `sub\drop`, `sub/drop`} {
		ctx, err := WithExclusions(context.Background(), []string{pattern})
		if err != nil {
			t.Fatal(err)
		}
		name := `C:\root\drop\venv`
		if pattern == `sub\drop` || pattern == "sub/drop" {
			name = `C:\root\sub\drop\venv`
		}
		if !excluded(ctx, `C:\root`, name) || excluded(ctx, `C:\root`, `C:\root\keep`) {
			t.Fatalf("native and slash-separated Windows glob must agree: %q", pattern)
		}
	}
}
