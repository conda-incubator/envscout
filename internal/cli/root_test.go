package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/tabwriter"
)

func TestCommands(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"help", []string{"--help"}, "find", false},
		{"find help", []string{"find", "--help"}, "OCI image archive", false},
		{"scan help", []string{"scan", "--help"}, "one whole-image SBOM", false},
		{"find invalid root", []string{"find", "not-a-real-root"}, "root", true},
		{"scan requires root", []string{"scan"}, "requires at least 1 arg", true},
		{"scan rejects missing root", []string{"scan", "not-a-real-root"}, "root", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := New()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			message := output.String()
			if err != nil {
				message += err.Error()
			}
			if !strings.Contains(message, tt.want) {
				t.Fatalf("command output %q does not contain %q", message, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, want error = %t", err, tt.wantErr)
			}
		})
	}
}

func TestFindReport(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "example", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(`{"name":"pkg","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "history"), []byte("==> date <==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"find", root})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NAME", "REV", "LOCATION", "example", "0", filepath.Join(root, "example")} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q missing %q", output.String(), want)
		}
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatal("non-terminal report should not contain ANSI escapes")
	}
}

func TestRevisionColor(t *testing.T) {
	for _, tt := range []struct {
		rev  int
		want string
	}{{0, "\x1b[32m"}, {1, "\x1b[33m"}, {3, "\x1b[38;5;208m"}, {6, "\x1b[31m"}} {
		if got := revisionColor(tt.rev); got != tt.want {
			t.Errorf("revisionColor(%d) = %q, want %q", tt.rev, got, tt.want)
		}
	}
}

func TestColoredRevisionTableCell(t *testing.T) {
	var output bytes.Buffer
	table := tabwriter.NewWriter(&output, 0, 4, 2, ' ', tabwriter.StripEscape)
	rev := 0
	if _, err := table.Write([]byte("example\t" + formatRevision(&rev, true) + "\t/path\n")); err != nil {
		t.Fatal(err)
	}
	if err := table.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\xc3\xbf") || strings.Contains(output.String(), "\xff") {
		t.Fatalf("table contains visible escape markers: %q", output.String())
	}
	if !strings.Contains(output.String(), "\x1b[32m0\x1b[0m") {
		t.Fatalf("colored revision missing: %q", output.String())
	}
	if got := formatRevision(&rev, false); got != "0" {
		t.Fatalf("uncolored revision = %q, want 0", got)
	}
}

func TestFindJSON(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "demo", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(`{"name":"pkg","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"find", "--json", root})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Roots        []string `json:"roots"`
		Environments []struct {
			Name     string `json:"name"`
			Revision *int   `json:"revision"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Roots) != 1 || len(report.Environments) != 1 || report.Environments[0].Name != "demo" || report.Environments[0].Revision != nil {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestFindKnownLocationsJSON(t *testing.T) {
	home := t.TempDir()
	var err error
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CONDA_PREFIX", "")
	t.Setenv("MAMBA_ROOT_PREFIX", "")
	t.Setenv("CONDA_ENVS_PATH", "")
	t.Setenv("PIXI_HOME", "")
	t.Setenv("PIXI_PROJECT_ROOT", "")
	t.Chdir(home)
	meta := filepath.Join(home, "miniconda3", "envs", "demo", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "demo.json"), []byte(`{"name":"demo","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"find", "--json"})
	// Other platform-default hints can be inaccessible on the test host; their
	// coverage errors must not prevent a structured partial report.
	_ = cmd.Execute()
	var report struct {
		Mode         string   `json:"mode"`
		Roots        []string `json:"roots"`
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("known-location output was not JSON: %v: %s", err, output.String())
	}
	found := false
	for _, env := range report.Environments {
		found = found || env.Name == "demo"
	}
	if report.Mode != "known-locations" || len(report.Roots) != 0 || !found {
		t.Fatalf("unexpected limited scope report: %+v", report)
	}
	text := New()
	output.Reset()
	text.SetOut(&output)
	text.SetArgs([]string{"find"})
	_ = text.Execute()
	if !strings.Contains(output.String(), "Known locations only (not a full filesystem scan)") || !strings.Contains(output.String(), "demo") {
		t.Fatalf("quick-mode text report: %s", output.String())
	}
}

func TestScanWritesOneSBOMPerPrefix(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		filepath.Join(root, "a", "shared", "conda-meta"),
		filepath.Join(root, "b", "shared", "conda-meta"),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "package.json"), []byte(`{"name":"python","version":"3.12","build":"0"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	workdir := t.TempDir()
	t.Chdir(workdir)
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"scan", root})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan failed: %v; output: %s", err, output.String())
	}
	for _, want := range []string{
		"Scan evidence | ",
		"shared  (revision ?)",
		"Prefix: " + filepath.Join(root, "a", "shared"),
		"Duration: ",
		"Syft: ",
		"; directory source; 1 conda, 0 installed Python metadata, 0 other packages observed",
		"SBOM: " + filepath.Join(workdir, "sboms"),
		"Searched roots:\n  " + root,
		"Summary: complete; 2 conda environments found, 2 SBOMs written, 0 failed scans, 0 discovery issues",
		"Timing: discovery ",
		"Coverage: conda prefixes within requested roots only",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("scan report missing %q: %s", want, output.String())
		}
	}
	entries, err := os.ReadDir(filepath.Join(workdir, "sboms"))
	if err != nil || len(entries) != 2 || entries[0].Name() == entries[1].Name() {
		t.Fatalf("wanted two distinct reports, got %v, %v", entries, err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(workdir, "sboms", entry.Name()))
		if err != nil || !json.Valid(data) {
			t.Fatalf("invalid SBOM %s: %v", entry.Name(), err)
		}
	}
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "2 failed target(s)") {
		t.Fatalf("repeated scan should not replace SBOMs: %v", err)
	}
	if !strings.Contains(output.String(), "Summary: incomplete; 2 conda environments found, 0 SBOMs written, 2 failed scans, 0 discovery issues") || !strings.Contains(output.String(), "SBOM: not written (SBOM already exists:") {
		t.Fatalf("repeated scan must report failures and retain previous SBOMs: %s", output.String())
	}
}

func TestScanWithoutEnvironments(t *testing.T) {
	root := t.TempDir()
	t.Chdir(t.TempDir())
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"scan", root})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Summary: complete; 0 conda environments found, 0 SBOMs written, 0 failed scans, 0 discovery issues") || !strings.Contains(output.String(), "Searched roots:\n  "+root) {
		t.Fatalf("empty scan must show scope and counts: %s", output.String())
	}
}

func TestScanReportsPartialDiscovery(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "broken", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "broken.json"), []byte(`{"name":"broken"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	cmd := New()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", root})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "1 discovery issue(s)") {
		t.Fatalf("expected incomplete scan error, got %v", err)
	}
	if !strings.Contains(stdout.String(), "Summary: incomplete; 0 conda environments found, 0 SBOMs written, 0 failed scans, 1 discovery issues") || !strings.Contains(stderr.String(), "warning: ") {
		t.Fatalf("missing partial discovery evidence: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}
