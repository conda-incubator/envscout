package inventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/discovery"
)

func TestFilename(t *testing.T) {
	a := discovery.Environment{Name: "same / name", Path: "/tmp/a/same / name"}
	b := discovery.Environment{Name: a.Name, Path: "/tmp/b/same / name"}
	if Filename(a) == Filename(b) || strings.ContainsAny(Filename(a), "/\\ ") || !strings.HasSuffix(Filename(a), ".cdx.json") {
		t.Fatalf("unsafe or colliding filenames: %q, %q", Filename(a), Filename(b))
	}
}

func TestWriteConda(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "envs", "sample")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "python-3.12-0.json"), []byte(`{"name":"python","version":"3.12","build":"0","channel":"https://conda.anaconda.org/conda-forge/"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(prefix, "lib", "python3.12", "site-packages", "demo-1.0.dist-info")
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installed, "METADATA"), []byte("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := discovery.Environment{Name: "sample", Path: prefix}
	output := filepath.Join(root, "reports")
	result, err := WriteConda(context.Background(), env, output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Conda != 1 || result.PythonInstalled != 1 || result.Other != 0 {
		t.Fatalf("unexpected Syft observations: %+v", result)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, component := range bom.Components {
		if component.Name == "python" && component.Version == "3.12" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing conda package in SBOM: %s", data)
	}
	if _, err := WriteConda(context.Background(), env, output); err == nil {
		t.Fatal("existing SBOM should not be overwritten")
	}
	again, err := os.ReadFile(result.Path)
	if err != nil || string(again) != string(data) {
		t.Fatal("existing SBOM was changed")
	}
}
