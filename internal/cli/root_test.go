package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/fatih/color"
)

func canonicalPrefixRecord(name, version, build string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"build":%q,"build_number":0,"subdir":"linux-64","channel":"conda-forge","files":[],"fn":%q,"url":%q}`,
		name, version, build, name+"-"+version+"-"+build+".conda", "https://conda.anaconda.org/conda-forge/linux-64/"+name+"-"+version+"-"+build+".conda")
}

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
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(canonicalPrefixRecord("pkg", "1", "0")), 0o644); err != nil {
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

func TestRevisionCellIsPlainWithoutTerminal(t *testing.T) {
	var output bytes.Buffer
	rev := 0
	if got := revisionCell(&rev, &output, false); got != "0" {
		t.Fatalf("non-terminal revision = %q, want plain 0", got)
	}
	if got := revisionCell(nil, &output, false); got != "?" {
		t.Fatalf("missing revision = %q, want ?", got)
	}
}

// TestColoredTableMatchesPlainWidth renders the same table colored and plain and
// requires identical visible output, so ANSI bytes never widen a column.
func TestColoredTableMatchesPlainWidth(t *testing.T) {
	render := func(revisions []int, colored bool) string {
		var output bytes.Buffer
		rows := [][]string{}
		for _, rev := range revisions {
			value := rev
			var cell string
			if colored {
				c := color.New(revisionAttribute(value))
				c.EnableColor()
				cell = c.Sprint(strconv.Itoa(value))
			} else {
				cell = strconv.Itoa(value)
			}
			rows = append(rows, []string{"env", cell, "/path"})
		}
		if err := printRows(&output, []string{"NAME", "REV", "LOCATION"}, rows); err != nil {
			t.Fatal(err)
		}
		return output.String()
	}
	revisions := []int{1, 1234}
	colored := render(revisions, true)
	if !strings.Contains(colored, "\x1b[") {
		t.Fatalf("colored table has no SGR sequence: %q", colored)
	}
	if got, want := ansi.Strip(colored), render(revisions, false); got != want {
		t.Fatalf("colored visible table differs from plain table:\ncolored %q\nplain   %q", got, want)
	}
}

func TestTableUsesTerminalCellWidths(t *testing.T) {
	var out bytes.Buffer
	if err := printRows(&out, []string{"NAME", "REV"}, [][]string{{"\u754c", "1"}, {"e\u0301", "2"}}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		prefix := strings.TrimRightFunc(line, func(r rune) bool { return r != ' ' })
		if width := ansi.StringWidth(prefix); width != 6 {
			t.Fatalf("last table column starts after %d cells, want 6: %q", width, line)
		}
	}
}

func TestFindJSON(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "demo", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(canonicalPrefixRecord("pkg", "1", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"find", "--format", "json", root})
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
	// Scrub every environment source the known-location scan reads so the host's
	// real conda, pixi and Windows install locations cannot leak into the report.
	for _, key := range []string{
		"CONDA_PREFIX", "MAMBA_ROOT_PREFIX", "CONDA_ENVS_PATH", "CONDA_ROOT", "CONDARC",
		"PIXI_HOME", "PIXI_PROJECT_ROOT", "LOCALAPPDATA", "PROGRAMDATA",
	} {
		t.Setenv(key, "")
	}
	t.Chdir(home)
	meta := filepath.Join(home, "miniconda3", "envs", "demo", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "demo.json"), []byte(canonicalPrefixRecord("demo", "1", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"find", "--format", "json"})
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
		if err := os.WriteFile(filepath.Join(path, "package.json"), []byte(canonicalPrefixRecord("python", "3.12", "0")), 0o644); err != nil {
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
		"Summary: complete; 2 environments found, 2 SBOMs written, 0 failed scans, 0 discovery issues",
		"Timing: discovery ",
		"Coverage: environment prefixes within requested roots only",
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
	if !strings.Contains(output.String(), "Summary: incomplete; 2 environments found, 0 SBOMs written, 2 failed scans, 0 discovery issues") || !strings.Contains(output.String(), "SBOM already exists") {
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
	if !strings.Contains(output.String(), "Summary: complete; 0 environments found, 0 SBOMs written, 0 failed scans, 0 discovery issues") || !strings.Contains(output.String(), "Searched roots:\n  "+root) {
		t.Fatalf("empty scan must show scope and counts: %s", output.String())
	}
}

func TestScanReportsPartialInventory(t *testing.T) {
	root := t.TempDir()
	meta := filepath.Join(root, "broken", "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "broken.json"), []byte(`{"name":"broken"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(root, "good", "conda-meta")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "pkg.json"), []byte(canonicalPrefixRecord("pkg", "1", "0")), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	cmd := New()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"scan", root})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "scan incomplete: 1 failed target(s)") {
		t.Fatalf("expected incomplete scan error, got %v", err)
	}
	if !strings.Contains(stdout.String(), "Summary: incomplete; 2 environments found, 1 SBOMs written, 1 failed scans, 0 discovery issues") {
		t.Fatalf("summary must count the failed candidate and the kept good prefix: stdout=%s", stdout.String())
	}
}
