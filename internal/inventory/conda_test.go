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

func TestFilename(t *testing.T) {
	a := discovery.Environment{Name: "same / name", Path: "/tmp/a/same / name", Kind: discovery.KindConda}
	b := discovery.Environment{Name: a.Name, Path: "/tmp/b/same / name", Kind: discovery.KindConda}
	if Filename(a) == Filename(b) || strings.ContainsAny(Filename(a), "/\\ ") || !strings.HasSuffix(Filename(a), ".cdx.json") {
		t.Fatalf("unsafe or colliding filenames: %q, %q", Filename(a), Filename(b))
	}
}

func TestWriteEnvironment(t *testing.T) {
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
	env := discovery.Environment{Name: "sample", Path: prefix, Kind: discovery.KindConda}
	output := filepath.Join(root, "reports")
	result, err := WriteEnvironment(context.Background(), env, output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Conda != 1 || result.PythonInstalled != 1 || result.Other != 0 || result.Total != 2 {
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
	existing, err := WriteEnvironment(context.Background(), env, output)
	if err != nil || !existing.PreExisting || existing.Path != result.Path || existing.Total != 0 || existing.SyftVersion != "" {
		t.Fatalf("existing SBOM should be skipped without recataloging or invented counts: %+v %v", existing, err)
	}
	again, err := os.ReadFile(result.Path)
	if err != nil || string(again) != string(data) {
		t.Fatal("existing SBOM was changed")
	}
}

func TestWriteEnvironmentExistingDirectoryIsNotASBOM(t *testing.T) {
	prefix := t.TempDir()
	env := discovery.Environment{Name: "env", Path: prefix, Kind: discovery.KindConda}
	output := t.TempDir()
	if err := os.Mkdir(filepath.Join(output, Filename(env)), 0o755); err != nil {
		t.Fatal(err)
	}
	result, err := WriteEnvironment(context.Background(), env, output)
	if err == nil || result.PreExisting {
		t.Fatalf("a directory collision is not a pre-existing SBOM: %+v %v", result, err)
	}
	info, err := os.Lstat(filepath.Join(output, Filename(env)))
	if err != nil || !info.IsDir() {
		t.Fatalf("directory collision must leave the directory intact: %v", err)
	}
}

func TestWriteEnvironmentRefusesExistingSymlink(t *testing.T) {
	root := t.TempDir()
	prefix := filepath.Join(root, "envs", "sample")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	env := discovery.Environment{Name: "sample", Path: prefix, Kind: discovery.KindConda}
	output := t.TempDir()
	destination := filepath.Join(output, Filename(env))
	if err := os.Symlink(filepath.Join(root, "missing-target"), destination); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteEnvironment(context.Background(), env, output); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected dangling symlink refusal, got %v", err)
	}
	if target, err := os.Readlink(destination); err != nil || target != filepath.Join(root, "missing-target") {
		t.Fatalf("symlink changed: %q, %v", target, err)
	}
	if _, err := os.Stat(filepath.Join(root, "missing-target")); !os.IsNotExist(err) {
		t.Fatalf("writer followed symlink to create its target: %v", err)
	}
}

func TestWriteEnvironmentCanceledLeavesNoOutput(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "sample")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	env := discovery.Environment{Name: "sample", Path: prefix, Kind: discovery.KindConda}
	output := filepath.Join(t.TempDir(), "reports")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteEnvironment(ctx, env, output); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	entries, err := os.ReadDir(output)
	if err == nil && len(entries) != 0 {
		t.Fatalf("canceled write left output: %v", entries)
	}
}
