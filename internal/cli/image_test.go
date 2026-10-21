package cli

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/testimage"
)

func TestImageFindAndScan(t *testing.T) {
	archive := testimage.Archive(t,
		[]testimage.Entry{
			{Name: "opt/conda/conda-meta/python.json", Data: `{"name":"python","version":"3.12","build":"0","subdir":"linux-64"}`},
			{Name: "opt/conda/conda-meta/history", Data: "==> 2026-01-01 00:00:00 <==\n==> 2026-01-02 00:00:00 <==\n"},
			{Name: "opt/conda/envs/app/conda-meta/demo.json", Data: `{"name":"demo","version":"1.0","build":"0","subdir":"linux-64"}`},
			{Name: "removed/conda-meta/old.json", Data: `{"name":"hidden","version":"1"}`},
		},
		[]testimage.Entry{{Name: ".wh.removed"}},
	)
	workdir := t.TempDir()
	t.Chdir(workdir)
	// Image discovery must not use the host's activated prefix.
	t.Setenv("CONDA_PREFIX", "/not-in-this-image")
	cmd := New()
	var output, warnings bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&warnings)
	cmd.SetArgs([]string{"find", "--source", "oci-archive", "--platform", "linux/amd64", "--json", archive})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("find image: %v: %s", err, warnings.String())
	}
	var report struct {
		SchemaVersion int                 `json:"schema_version"`
		Source        string              `json:"source"`
		Scope         string              `json:"scope"`
		Image         imageinput.Identity `json:"image"`
		Environments  []struct {
			Path     string `json:"path"`
			Revision *int   `json:"revision"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.Scope != "squashed" || report.Source != "oci-archive" || len(report.Environments) != 2 || report.Environments[0].Path != "/opt/conda" || report.Environments[0].Revision == nil || *report.Environments[0].Revision != 1 {
		t.Fatalf("incorrect final filesystem report: %s", output.String())
	}
	if report.Image.ManifestDigest == "" || report.Image.Input != archive {
		t.Fatalf("missing immutable image identity: %+v", report.Image)
	}
	if _, err := os.Stat("sboms"); !os.IsNotExist(err) {
		t.Fatal("find unexpectedly wrote SBOMs")
	}
	output.Reset()
	cmd = New()
	cmd.SetOut(&output)
	cmd.SetErr(&warnings)
	cmd.SetArgs([]string{"scan", "--source", "oci-archive", "--platform", "linux/amd64", archive})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan image: %v: %s %s", err, output.String(), warnings.String())
	}
	for _, text := range []string{report.Image.ManifestDigest, "final squashed image", "/opt/conda/envs/app", "2 conda", "Summary: completed"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("scan evidence omitted %q: %s", text, output.String())
		}
	}
	files, err := os.ReadDir("sboms")
	if err != nil || len(files) != 1 {
		t.Fatalf("expected exactly one whole-image SBOM: %+v, %v", files, err)
	}
	data, err := os.ReadFile(filepath.Join("sboms", files[0].Name()))
	if err != nil || !json.Valid(data) || bytes.Contains(data, []byte(`"name": "hidden"`)) {
		t.Fatalf("invalid or non-runtime SBOM: %v: %s", err, data)
	}
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "create SBOM") {
		t.Fatalf("repeated image scan should refuse overwrite: %v", err)
	}
}

func TestImageArgumentValidation(t *testing.T) {
	for _, args := range [][]string{
		{"find", "--source", "docker", "image"},
		{"find", "--source", "oci-archive", "image.tar"},
		{"find", "--source", "oci-archive", "--platform", "linux/amd64"},
		{"scan", "--source", "oci-archive", "--platform", "linux/amd64", "a", "b"},
		{"find", "--platform", "linux/amd64", "."},
	} {
		cmd := New()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestImagePartialDiscoveryStillWritesSBOM(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/demo.json", Data: `{"name":"demo","version":"1"}`},
		{Name: "broken/conda-meta/bad.json", Data: `{"name":"incomplete"}`},
		{Name: "alias", Type: tar.TypeSymlink, Link: "env"},
	})
	t.Chdir(t.TempDir())
	cmd := New()
	var output, warnings bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&warnings)
	cmd.SetArgs([]string{"scan", "--source", "oci-archive", "--platform", "linux/amd64", archive})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "inspection incomplete") {
		t.Fatalf("partial image scan should fail visibly: %v", err)
	}
	files, err := os.ReadDir("sboms")
	if err != nil || len(files) != 1 || !strings.Contains(output.String(), "Summary: incomplete") || !strings.Contains(warnings.String(), "warning: image path") {
		t.Fatalf("missing partial report/SBOM: %v %s %s", err, output.String(), warnings.String())
	}
}
