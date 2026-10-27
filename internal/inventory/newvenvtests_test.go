package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/discovery"
)

// writeVenv creates a synthetic virtualenv with a pyvenv.cfg marker and the given
// relative files. Parents are created as needed.
func writeVenv(t *testing.T, prefix string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	files["pyvenv.cfg"] = "home = /base/python\ninclude-system-site-packages = false\n"
	for rel, body := range files {
		full := filepath.Join(prefix, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func venvEnv(prefix string) discovery.Environment {
	return discovery.Environment{Name: "venv", Path: prefix, Kind: discovery.KindVenv}
}

func TestWriteEnvironmentVenvDistInfoIsCataloged(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"lib/python3.13/site-packages/demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
	})
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.PythonInstalled != 1 || result.Conda != 0 || result.Unknowns != 0 {
		t.Fatalf("unexpected venv observations: %+v", result)
	}
}

func TestWriteEnvironmentVenvEggInfoIsCataloged(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"lib/python3.13/site-packages/legacy.egg-info/PKG-INFO": "Metadata-Version: 1.0\nName: legacy\nVersion: 0.9\n",
	})
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.PythonInstalled != 1 {
		t.Fatalf("egg-info not cataloged: %+v", result)
	}
}

func TestWriteEnvironmentEmptyVenvSucceedsWithZeroPackages(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{})
	report, err := Scan(context.Background(), []string{prefix}, t.TempDir())
	if err != nil {
		t.Fatalf("empty venv should not fail: %v", err)
	}
	if report.Status != StatusComplete {
		t.Fatalf("status = %q", report.Status)
	}
}

func TestWriteEnvironmentVenvWithoutRequirementsStillCountsInstalled(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"lib/python3.13/site-packages/demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
	})
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.PythonInstalled == 0 {
		t.Fatalf("expected PythonInstalled > 0: %+v", result)
	}
}

func TestWriteEnvironmentVenvIgnoresConda(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"conda-meta/python-3.13-0.json": `{"name":"python","version":"3.13","build":"0"}`,
	})
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.Conda != 0 {
		t.Fatalf("venv must not read conda-meta: %+v", result)
	}
}

func TestWriteEnvironmentVenvExternalInterpreterLinkDoesNotLeak(t *testing.T) {
	outside := t.TempDir()
	metadata := filepath.Join(outside, "lib/python3.13/site-packages/external-9.9.dist-info")
	if err := os.MkdirAll(metadata, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadata, "METADATA"), []byte("Metadata-Version: 2.1\nName: external\nVersion: 9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{})
	if err := os.MkdirAll(filepath.Join(prefix, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "lib"), filepath.Join(prefix, "lib")); err != nil {
		t.Fatal(err)
	}
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.PythonInstalled != 0 || result.Total != 0 {
		t.Fatalf("external metadata leaked through link: %+v", result)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "external") {
		t.Fatalf("external package in SBOM: %s", data)
	}
	// Relative links are the case that an unconstrained Syft source can follow
	// outside its scan path; check them separately from absolute links.
	if err := os.Remove(filepath.Join(prefix, "lib")); err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(prefix, filepath.Join(outside, "lib"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(relative, filepath.Join(prefix, "lib")); err != nil {
		t.Fatal(err)
	}
	result, err = WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil || result.Total != 0 {
		t.Fatalf("relative external metadata leaked through link: %+v %v", result, err)
	}
}

func TestWriteEnvironmentWindowsVirtualenvLayout(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"Lib/site-packages/demo-1.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nVersion: 1\n",
	})
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil || result.PythonInstalled != 1 || result.Conda != 0 {
		t.Fatalf("Windows virtualenv metadata must use the same cataloger: %+v %v", result, err)
	}
}

func TestWriteEnvironmentRejectsUnknownKind(t *testing.T) {
	prefix := t.TempDir()
	env := discovery.Environment{Name: "x", Path: prefix, Kind: "pipx"}
	if _, err := WriteEnvironment(context.Background(), env, t.TempDir()); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}

func TestScanRejectsEmptyKindForConda(t *testing.T) {
	// Kind empty is not a shipped alias: Scan validates only KindConda via
	// explicit discovery; an unknown kind must not be silently treated as conda.
	env := discovery.Environment{Name: "x", Path: t.TempDir(), Kind: ""}
	_, err := WriteEnvironment(context.Background(), env, t.TempDir())
	if !errors.Is(err, errUnknownKind) {
		t.Fatalf("empty kind should be unknown, got %v", err)
	}
}

func TestVenvSBOMIsValidCycloneDX(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "venv")
	writeVenv(t, prefix, map[string]string{
		"lib/python3.13/site-packages/demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
	})
	result, err := WriteEnvironment(context.Background(), venvEnv(prefix), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &bom); err != nil || bom.BOMFormat != "CycloneDX" {
		t.Fatalf("invalid SBOM: %v %s", err, data)
	}
}
