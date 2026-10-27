package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/anchore/syft/syft/source/directorysource"
)

func TestVirtualenvSourceExcludesExternalLinksBeforeIndexing(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"Lib/site-packages/internal-1.dist-info/METADATA": "Name: internal\nVersion: 1\n",
	})
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "METADATA"), []byte("Name: external\nVersion: 9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"external-absolute": outside,
		"external-relative": relativeLinkTarget(t, prefix, outside),
		"external-file":     filepath.Join(outside, "METADATA"),
		"broken":            filepath.Join(outside, "missing"),
		"inside":            filepath.Join(prefix, "Lib"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(prefix, name)); err != nil {
			t.Fatal(err)
		}
	}
	config, err := virtualenvSourceConfig(context.Background(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"external-absolute", "external-relative", "external-file", "broken"} {
		if !slices.Contains(config.Exclude.Paths, "./"+name) {
			t.Fatalf("external links must be excluded before Syft's indexer follows them: %+v", config)
		}
	}
	if slices.Contains(config.Exclude.Paths, "./inside") {
		t.Fatal("in-prefix library aliases must remain available to catalogers")
	}
	if config.Path != config.Base {
		t.Fatal("virtualenv path and base must use the same canonical root")
	}
	filters, err := directorysource.GetDirectoryExclusionFunctions(config.Path, config.Exclude.Paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"external-absolute", "external-relative", "external-file", "broken"} {
		// Syft visits canonical paths, even when TempDir's parent is a symlink.
		info, err := os.Lstat(filepath.Join(config.Path, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, filter := range filters {
			if filter("", filepath.Join(config.Path, name), info, nil) == nil {
				t.Fatalf("Syft must filter %s before resolving its target", name)
			}
		}
	}
}

func TestVirtualenvInternalAliasesAndExternalChain(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"lib/python3.13/site-packages/internal-1.dist-info/METADATA": "Metadata-Version: 2.1\nName: internal\nVersion: 1\n",
	})
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(prefix, "external")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("external", filepath.Join(prefix, "indirect")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("lib", filepath.Join(prefix, "lib64")); err != nil {
		t.Fatal(err)
	}
	config, err := virtualenvSourceConfig(context.Background(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(config.Exclude.Paths, "./indirect") || slices.Contains(config.Exclude.Paths, "./lib64") {
		t.Fatalf("resolve full chains while retaining internal aliases: %+v", config)
	}
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil || result.Total != 1 || result.PythonInstalled != 1 {
		t.Fatalf("internal packages must remain cataloged exactly once: %+v %v", result, err)
	}
}

func relativeLinkTarget(t *testing.T, prefix, target string) string {
	t.Helper()
	relative, err := filepath.Rel(prefix, target)
	if err != nil {
		t.Fatal(err)
	}
	return relative
}

func TestVirtualenvSourceLinkExclusionsAreLiteral(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("wildcard characters are not valid Windows filenames")
	}
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"Lib/site-packages/demo-1.dist-info/METADATA": "Name: demo\nVersion: 1\n",
	})
	name := "external[1]{a,b}*?"
	if err := os.Symlink(t.TempDir(), filepath.Join(prefix, name)); err != nil {
		t.Fatal(err)
	}
	config, err := virtualenvSourceConfig(context.Background(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := directorysource.GetDirectoryExclusionFunctions(config.Path, config.Exclude.Paths)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(config.Path, name))
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range filters {
		if filter("", filepath.Join(config.Path, name), info, nil) == nil {
			t.Fatal("glob syntax in a link name must not defeat its exclusion")
		}
		if filter("", filepath.Join(config.Path, "external1a"), info, nil) != nil {
			t.Fatal("a literal link exclusion must not remove similarly named real files")
		}
	}
}

func TestVirtualenvSourceConfigCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := virtualenvSourceConfig(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("link preflight must honor cancellation: %v", err)
	}
}
