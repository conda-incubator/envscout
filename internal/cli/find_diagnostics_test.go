package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/discovery"
)

func TestFindIssuesAreSummarizedWithoutFailure(t *testing.T) {
	root := condaRoot(t)
	// A non-regular history file creates a deterministic discovery issue on all
	// platforms, without depending on OS-specific permission restrictions.
	path := filepath.Join(root, "demo", "conda-meta", "history")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, err := runCLI(t, context.Background(), "find", "--format", format, root)
			if ExitCode(err) != 0 {
				t.Fatalf("ordinary discovery issues must not fail find: %v\n%s", err, stderr)
			}
			want := "discovery incomplete: 1 path(s) could not be inspected; use --verbose to see details\n"
			if stderr != want || strings.Contains(stderr, path) || strings.Contains(stderr, "warning:") {
				t.Fatalf("default stderr must contain only the summary: %q", stderr)
			}
			if format == "json" {
				var report discovery.Report
				if err := json.Unmarshal([]byte(stdout), &report); err != nil {
					t.Fatal(err)
				}
				if len(report.Issues) != 1 || report.Issues[0].Path != path || len(report.Environments) != 1 {
					t.Fatalf("JSON must preserve issues and discovered environments: %s", stdout)
				}
			} else if !strings.Contains(stdout, "demo") {
				t.Fatalf("warnings must not hide discovered environments: %s", stdout)
			}
		})
	}
	for _, args := range [][]string{
		{"find", "--verbose", root},
		{"--verbose", "find", root},
		{"find", root, "--verbose", "--format", "json"},
	} {
		_, stderr, err := runCLI(t, context.Background(), args...)
		if ExitCode(err) != 0 || !strings.Contains(stderr, "warning: "+path) || !strings.Contains(stderr, "discovery incomplete: 1 path(s)") {
			t.Fatalf("verbose find must reveal details without failing: %v, %q", err, stderr)
		}
		if strings.Contains(stderr, "use --verbose") {
			t.Fatalf("verbose output should not suggest its own flag: %s", stderr)
		}
	}
}

func TestFindPermissionWarningsHaveOneSummary(t *testing.T) {
	report := discovery.Report{Environments: []discovery.Environment{}, Issues: []discovery.Issue{}}
	for i := range 138 {
		report.Issues = append(report.Issues, discovery.Issue{Path: fmt.Sprintf("/home/user/Library/restricted-%d", i), Error: "operation not permitted"})
	}
	cmd := New()
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	if err := renderFind(cmd, &commandOptions{format: "text"}, report); err != nil {
		t.Fatalf("recorded permission failures are nonfatal: %v", err)
	}
	if stderr.String() != "discovery incomplete: 138 path(s) could not be inspected; use --verbose to see details\n" {
		t.Fatalf("expected one summary, got %q", stderr.String())
	}
}

func TestScanDiscoveryIssuesRemainFailures(t *testing.T) {
	root := condaRoot(t)
	if err := os.Mkdir(filepath.Join(root, "demo", "conda-meta", "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := runCLI(t, context.Background(), "scan", "--output-dir", t.TempDir(), root)
	if ExitCode(err) != 1 || !strings.Contains(stderr, "warning:") || !strings.Contains(err.Error(), "scan incomplete") {
		t.Fatalf("scan failures must not inherit find's nonfatal policy: %v, %q", err, stderr)
	}
}

func TestFindIssuesSummaryWriteFailureStillFails(t *testing.T) {
	cmd := New()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(failingWriter{})
	report := discovery.Report{Issues: []discovery.Issue{{Path: "unreadable", Error: "operation not permitted"}}}
	if err := renderFind(cmd, &commandOptions{format: "text"}, report); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("failed diagnostics output must not be ignored: %v", err)
	}
}

func TestFindVerboseDoesNotHideInputOrRootFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, _, err := runCLI(t, context.Background(), "find", "--verbose", missing)
	if ExitCode(err) == 0 || !strings.Contains(err.Error(), "root") {
		t.Fatalf("a missing explicit root must still fail: %v", err)
	}
	_, _, err = runCLI(t, context.Background(), "find", "--verbose", "--format", "xml", missing)
	if ExitCode(err) != 2 {
		t.Fatalf("invalid input must still exit 2: %v", err)
	}
	for _, command := range []string{"scan"} {
		stdout, _, err := runCLI(t, context.Background(), command, "--verbose", t.TempDir())
		if ExitCode(err) != 2 || stdout != "" {
			t.Fatalf("--verbose must not be silently ignored by %s: %v, %q", command, err, stdout)
		}
	}
}

func TestFindEnvironmentSummary(t *testing.T) {
	for _, test := range []struct {
		name  string
		kinds []string
		want  string
	}{
		{"empty", nil, "Summary: 0 environments found (0 conda, 0 venv)\n"},
		{"conda only", []string{discovery.KindConda}, "Summary: 1 environments found (1 conda, 0 venv)\n"},
		{"venv only", []string{discovery.KindVenv, discovery.KindVenv}, "Summary: 2 environments found (0 conda, 2 venv)\n"},
		{"mixed", []string{discovery.KindConda, discovery.KindVenv, discovery.KindConda}, "Summary: 3 environments found (2 conda, 1 venv)\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := New()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			report := discovery.Report{}
			for i, kind := range test.kinds {
				report.Environments = append(report.Environments, discovery.Environment{Name: fmt.Sprintf("env-%d", i), Path: fmt.Sprintf("/env-%d", i), Kind: kind})
			}
			if err := renderFind(cmd, &commandOptions{format: "text"}, report); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(out.String(), test.want) {
				t.Fatalf("missing count-by-type summary: %s", out.String())
			}
		})
	}
}

func TestFindSummaryCountsDiscoveredKinds(t *testing.T) {
	root := condaRoot(t)
	venvFixture(t, root, "venv-a", false)
	venvFixture(t, root, "venv-b", false)
	stdout, _, err := runCLI(t, context.Background(), "find", root)
	if err != nil || !strings.HasSuffix(stdout, "Summary: 3 environments found (1 conda, 2 venv)\n") {
		t.Fatalf("summary must count discovered environments rather than markers or packages: %v\n%s", err, stdout)
	}
	stdout, _, err = runCLI(t, context.Background(), "find", "--format", "json", root)
	if err != nil || !json.Valid([]byte(stdout)) || strings.Contains(stdout, "Summary:") {
		t.Fatalf("text summary must not pollute JSON output: %v\n%s", err, stdout)
	}
}
