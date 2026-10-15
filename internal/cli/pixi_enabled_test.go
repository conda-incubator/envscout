//go:build pixi

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPixiLockSummary(t *testing.T) {
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
	if got := pixiLockSummary(prefix); !strings.Contains(got, "1 conda, 1 PyPI (locked, not installed)") {
		t.Fatalf("unexpected lock summary: %q", got)
	}
	outputDir := t.TempDir()
	t.Chdir(outputDir)
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"scan", prefix})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan failed: %v; output: %s", err, output.String())
	}
	if !strings.Contains(output.String(), "Pixi lock: default/osx-arm64; 1 conda, 1 PyPI") {
		t.Fatalf("scan omitted Pixi lock summary: %s", output.String())
	}
	if !strings.Contains(output.String(), "1 conda, 0 installed Python metadata, 0 other packages observed") || !strings.Contains(output.String(), "(locked, not installed)") {
		t.Fatalf("scan must distinguish Syft observations from locked counts: %s", output.String())
	}
	if err := os.Remove(filepath.Join(workspace, "pixi.lock")); err != nil {
		t.Fatal(err)
	}
	if got := pixiLockSummary(prefix); !strings.Contains(got, "Pixi lock: unknown") {
		t.Fatalf("missing lock should be unknown: %q", got)
	}
}
