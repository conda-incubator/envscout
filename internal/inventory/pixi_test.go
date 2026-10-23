package inventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPixiLockSummary(t *testing.T) {
	workspace := t.TempDir()
	prefix := filepath.Join(workspace, ".pixi", "envs", "default")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "python.json"), []byte(`{"name":"python","version":"3.12","build":"0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `version: 4
environments:
  default:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      osx-arm64:
      - conda: https://conda.anaconda.org/conda-forge/osx-arm64/python-3.12.1-h123_0.conda
      - pypi: https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl
packages:
- kind: conda
  name: python
  version: 3.12.1
  build: h123_0
  subdir: osx-arm64
  url: https://conda.anaconda.org/conda-forge/osx-arm64/python-3.12.1-h123_0.conda
- kind: pypi
  name: demo
  version: '1.0'
  url: https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl
`
	if err := os.WriteFile(filepath.Join(workspace, "pixi.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(workspace, "pixi.toml")
	marker, err := json.Marshal(map[string]any{
		"manifest_path":     manifest,
		"environment_name":  "default",
		"resolved_platform": map[string]string{"subdir": "osx-arm64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pixi"), marker, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := PixiLockSummary(prefix); !strings.Contains(got, "1 conda, 1 PyPI (locked, not installed)") {
		t.Fatalf("unexpected lock summary: %q", got)
	}
	if err := os.Remove(filepath.Join(workspace, "pixi.lock")); err != nil {
		t.Fatal(err)
	}
	if got := PixiLockSummary(prefix); !strings.Contains(got, "Pixi lock: unknown") {
		t.Fatalf("missing lock should be unknown: %q", got)
	}
}

func TestScanCondaIncludesPixiLockSummary(t *testing.T) {
	workspace := t.TempDir()
	prefix := filepath.Join(workspace, ".pixi", "envs", "default")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "python.json"), []byte(`{"name":"python","version":"3.12","build":"0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lock := `version: 4
environments:
  default:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      osx-arm64:
      - conda: https://conda.anaconda.org/conda-forge/osx-arm64/python-3.12.1-h123_0.conda
      - pypi: https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl
packages:
- kind: conda
  name: python
  version: 3.12.1
  build: h123_0
  subdir: osx-arm64
  url: https://conda.anaconda.org/conda-forge/osx-arm64/python-3.12.1-h123_0.conda
- kind: pypi
  name: demo
  version: '1.0'
  url: https://files.pythonhosted.org/packages/demo-1.0-py3-none-any.whl
`
	if err := os.WriteFile(filepath.Join(workspace, "pixi.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	marker, err := json.Marshal(map[string]any{
		"manifest_path":     filepath.Join(workspace, "pixi.toml"),
		"environment_name":  "default",
		"resolved_platform": map[string]string{"subdir": "osx-arm64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pixi"), marker, 0o644); err != nil {
		t.Fatal(err)
	}
	outputDir := t.TempDir()
	report, err := ScanConda(context.Background(), []string{prefix}, outputDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(report.Observations) != 1 {
		t.Fatalf("expected one observation, got %+v", report.Observations)
	}
	obs := report.Observations[0]
	if !strings.Contains(obs.Pixi, "Pixi lock: default/osx-arm64; 1 conda, 1 PyPI") {
		t.Fatalf("scan omitted Pixi lock summary: %+v", obs)
	}
	if obs.Result.Conda != 1 || obs.Result.PythonInstalled != 0 || obs.Result.Other != 0 {
		t.Fatalf("Syft observations must not be replaced by locked counts: %+v", obs.Result)
	}
	files, err := os.ReadDir(outputDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("expected exactly one SBOM: %v, %v", files, err)
	}
}
