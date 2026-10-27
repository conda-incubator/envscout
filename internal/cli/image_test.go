package cli

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/imageinput"
	"github.com/conda-incubator/envscout/internal/inventory"
	"github.com/conda-incubator/envscout/internal/testimage"
)

func TestImageFindAndScan(t *testing.T) {
	archive := testimage.Archive(t,
		[]testimage.Entry{
			{Name: "opt/conda/conda-meta/python.json", Data: canonicalPrefixRecord("python", "3.12", "0")},
			{Name: "opt/conda/conda-meta/history", Data: "==> 2026-01-01 00:00:00 <==\n==> 2026-01-02 00:00:00 <==\n"},
			{Name: "opt/conda/envs/app/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1.0", "0")},
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
	cmd.SetArgs([]string{"find", "--source", "oci-archive", "--platform", "linux/amd64", "--format", "json", archive})
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
	// A repeated image scan finds the same whole-image SBOM path already written and
	// classifies it as pre-existing: exit 0, file untouched, no fabricated counts.
	before, err := os.ReadFile(filepath.Join("sboms", files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	cmd = New()
	cmd.SetOut(&output)
	cmd.SetErr(&warnings)
	cmd.SetArgs([]string{"scan", "--format", "json", "--source", "oci-archive", "--platform", "linux/amd64", archive})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("repeated image scan with pre-existing SBOM must exit 0: %v: %s", err, output.String())
	}
	var repeat struct {
		Result *struct {
			Path        string `json:"path"`
			PreExisting bool   `json:"pre_existing,omitempty"`
			Conda       int    `json:"conda"`
			Total       int    `json:"total"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output.Bytes(), &repeat); err != nil {
		t.Fatal(err)
	}
	if repeat.Result == nil || !repeat.Result.PreExisting || repeat.Result.Conda != 0 || repeat.Result.Total != 0 {
		t.Fatalf("repeated image scan must report pre-existing without counts: %s", output.String())
	}
	after, err := os.ReadFile(filepath.Join("sboms", files[0].Name()))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("pre-existing whole-image SBOM must be unchanged: %v", err)
	}
}

// TestImagePreExistingTextSummary pins the image text summary and SBOM line when the
// whole-image SBOM already exists: it is shown as pre-existing with no Syft claims.
func TestImagePreExistingTextSummary(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1", "0")},
	})
	t.Chdir(t.TempDir())
	run := func() (string, error) {
		cmd := New()
		var output, warnings bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&warnings)
		cmd.SetArgs([]string{"scan", "--source", "oci-archive", "--platform", "linux/amd64", archive})
		err := cmd.Execute()
		return output.String(), err
	}
	if _, err := run(); err != nil {
		t.Fatalf("seed image scan: %v", err)
	}
	out, err := run()
	if err != nil {
		t.Fatalf("repeated image text scan must exit 0: %v: %s", err, out)
	}
	if !strings.Contains(out, "SBOM: pre-existing") {
		t.Fatalf("image text must label the kept SBOM pre-existing: %s", out)
	}
	if !strings.Contains(out, "0 SBOMs written, 1 pre-existing SBOMs") {
		t.Fatalf("image summary must count pre-existing SBOMs: %s", out)
	}
	if strings.Contains(out, "Syft:") || strings.Contains(out, "unique packages observed") {
		t.Fatalf("pre-existing image must not claim Syft package observations: %s", out)
	}
	if strings.Contains(out, "SBOM already exists") || strings.Contains(out, "not written") {
		t.Fatalf("pre-existing image must not render as a failure: %s", out)
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
		{Name: "env/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1", "0")},
		{Name: "broken/conda-meta/bad.json", Data: `{"name":"incomplete"}`},
		{Name: "alias", Type: tar.TypeSymlink, Link: "env"},
	})
	t.Chdir(t.TempDir())
	cmd := New()
	var output, warnings bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&warnings)
	cmd.SetArgs([]string{"scan", "--source", "oci-archive", "--platform", "linux/amd64", archive})
	// The malformed record is a candidate, not a discovery issue. Its conda content
	// surfaces as an unknown file coordinate, so the image scan is incomplete while
	// the good prefix's SBOM is still written and reported.
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "image inspection incomplete") {
		t.Fatalf("partial image scan should fail visibly: %v", err)
	}
	files, err := os.ReadDir("sboms")
	if err != nil || len(files) != 1 {
		t.Fatalf("expected the whole-image SBOM to be kept: %v %v", files, err)
	}
	if !strings.Contains(output.String(), "Summary: incomplete") || !strings.Contains(output.String(), "SBOM: "+mustAbs(t, "sboms")) {
		t.Fatalf("report must show the kept SBOM and incomplete summary: %s", output.String())
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestImageFindWarningDetailsRequireVerbose(t *testing.T) {
	report := inventory.ImageReport{Report: discovery.Report{Issues: []discovery.Issue{{Path: "/env/conda-meta/history", Error: "history is unreadable"}}}}
	for _, test := range []struct {
		name                   string
		verbose, scan, details bool
	}{
		{"find default", false, false, false},
		{"find verbose", true, false, true},
		{"scan unchanged", false, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := New()
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			if err := renderImage(cmd, &commandOptions{format: "json", verbose: test.verbose}, report, test.scan); err != nil {
				t.Fatal(err)
			}
			if !json.Valid(stdout.Bytes()) || !strings.Contains(stdout.String(), "history is unreadable") {
				t.Fatalf("image JSON must retain diagnostic facts: %s", stdout.String())
			}
			if strings.Contains(stderr.String(), "warning:") != test.details {
				t.Fatalf("wrong image warning detail policy: %s", stderr.String())
			}
			if !test.details && !strings.Contains(stderr.String(), "use --verbose to see details") {
				t.Fatalf("quiet image find must point to detail flag: %s", stderr.String())
			}
		})
	}
}

func TestImageFindSummaryCountsTypes(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{
		{Name: "env/conda-meta/pkg.json", Data: canonicalPrefixRecord("pkg", "1", "0")},
	})
	cmd := New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"find", "--source", "oci-archive", "--platform", "linux/amd64", archive})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Summary: completed; 1 environments found (1 conda, 0 venv); 0 discovery issues\n") {
		t.Fatalf("image find must summarize its discovered types: %s", out.String())
	}
}

func TestPreExistingImageSBOMDoesNotHideInspectionWarning(t *testing.T) {
	var out bytes.Buffer
	report := inventory.ImageReport{Result: &inventory.Result{Path: "existing.cdx.json", PreExisting: true}, ScanError: "inspection incomplete"}
	renderImageSBOM(newPrinter(&out), report)
	if !strings.Contains(out.String(), "pre-existing (not rescanned)") || !strings.Contains(out.String(), "SBOM warning: inspection incomplete") || strings.Contains(out.String(), "Syft:") {
		t.Fatalf("pre-existing output must not hide a later error or invent package evidence: %s", out.String())
	}
}
