package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anaconda/envscout/internal/evidence"
	"github.com/anaconda/envscout/internal/testimage"
)

func lintFixture(t *testing.T, revision int) string {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "env")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(`{"name":"demo","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "history"), []byte(strings.Repeat("==> transaction <==\n", revision+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return prefix
}

func executeLint(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var output, stderr bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&stderr)
	cmd.SetArgs(append([]string{"lint"}, args...))
	returnValue := cmd.Execute()
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("non-TTY output contains escapes: %q", output.String())
	}
	return output.String(), returnValue
}

func TestLintLocalPolicyAndExitCodes(t *testing.T) {
	prefix := lintFixture(t, 12)
	t.Chdir(t.TempDir())
	output, err := executeLint(t, prefix)
	if err != nil || !strings.Contains(output, "EC001") || !strings.Contains(output, "not a vulnerability") {
		t.Fatalf("local informational lint: %v: %s", err, output)
	}
	output, err = executeLint(t, "--format", "json", "--fail-on", "info", prefix)
	if ExitCode(err) != 1 || ShouldPrintError(err) || !json.Valid([]byte(output)) {
		t.Fatalf("policy failure not structured/silent: %v: %s", err, output)
	}
	if _, err := os.Stat("sboms"); !os.IsNotExist(err) {
		t.Fatal("lint created SBOMs")
	}
	if output, err := executeLint(t, "--fail-on", "none", prefix); err != nil || !strings.Contains(output, "EC001") {
		t.Fatalf("disabled threshold lost findings: %v %s", err, output)
	}
}

func TestLintListsAllRegisteredRules(t *testing.T) {
	output, err := executeLint(t, "--list-rules", "--format", "json")
	var listed []struct {
		ID                string `json:"id"`
		Available         bool   `json:"available"`
		UnavailableReason string `json:"unavailable_reason"`
	}
	if err != nil || json.Unmarshal([]byte(output), &listed) != nil || len(listed) != 10 {
		t.Fatalf("incorrect rules listing: %v %s", err, output)
	}
	for _, rule := range listed {
		if rule.ID == "EC002" || rule.ID == "EC003" {
			if rule.Available || rule.UnavailableReason == "" {
				t.Fatalf("unavailable rule not disclosed: %+v", rule)
			}
		} else if !rule.Available || rule.UnavailableReason != "" {
			t.Fatalf("bad listed rule: %+v", rule)
		}
	}
	output, err = executeLint(t, "--list-rules")
	if err != nil || !strings.Contains(output, "EC002") || !strings.Contains(output, "unavailable") {
		t.Fatalf("text rules listing hides unavailable rules: %v %s", err, output)
	}
}

func TestLintInputErrorsBeforeCollection(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--unknown"}, {"--profile", "bad", "missing"}, {"--fail-on", "bad", "missing"},
		{"--rule", "EC002", "missing"}, {"--rule", "EC001", "--disable-rule", "EC001", "missing"},
		{"--source", "oci-archive", "missing.tar"}, {"--platform", "linux/amd64", "missing"},
		{"--runtime-prefix", "/app", "missing"}, {"--list-rules", "missing"}, {"--format", "sarif", "missing"},
		{"--list-rules", "--fail-on", "invalid"},
	} {
		output, err := executeLint(t, args...)
		if ExitCode(err) != 2 || output != "" {
			t.Errorf("bad input %v produced %d output %q err %v", args, ExitCode(err), output, err)
		}
	}
}

func TestLintImageMultipleRulesAndLayerRetention(t *testing.T) {
	archive := testimage.Archive(t,
		[]testimage.Entry{
			{Name: "opt/conda/conda-meta/conda.json", Data: `{"name":"conda","version":"26.7"}`},
			{Name: "opt/conda/envs/app/conda-meta/demo.json", Data: `{"name":"demo","version":"1"}`},
			{Name: "opt/conda/pkgs/old-1.0-0.conda", Data: "old cache"},
			{Name: "opt/conda/pkgs/current-1.0-0.conda", Data: "current cache"},
			{Name: "opt/conda/pkgs/demo-1.0-0/info/index.json", Data: `{"name":"demo","version":"1.0"}`},
			{Name: "usr/bin/apt", Data: "#!/bin/sh\nexit 0\n", Mode: 0o755},
			{Name: "usr/bin/sh", Data: "\x7fELF\x02", Mode: 0o755},
			{Name: "bin", Type: tar.TypeSymlink, Link: "usr/bin"},
		},
		[]testimage.Entry{{Name: "opt/conda/pkgs/.wh.old-1.0-0.conda"}},
	)
	t.Chdir(t.TempDir())
	output, err := executeLint(t, "--source", "oci-archive", "--platform", "linux/amd64", "--profile", "container-runtime", "--format", "json", archive)
	if ExitCode(err) != 1 || !json.Valid([]byte(output)) {
		t.Fatalf("runtime image lint: %v %s", err, output)
	}
	for _, rule := range []string{"IC001", "IC002", "IC003", "IC004", "IC006"} {
		if !strings.Contains(output, `"rule_id": "`+rule+`"`) {
			t.Errorf("missing rule %s: %s", rule, output)
		}
	}
	if !strings.Contains(output, `"compressed_digest"`) || !strings.Contains(output, `"diff_id"`) {
		t.Fatalf("retained layer missing separate digests: %s", output)
	}
	if _, err := os.Stat("sboms"); !os.IsNotExist(err) {
		t.Fatal("image lint wrote SBOM")
	}
	output, err = executeLint(t, "--source", "oci-archive", "--platform", "linux/amd64", "--profile", "container-distroless", archive)
	if ExitCode(err) != 1 || !strings.Contains(output, "IC007") {
		t.Fatalf("distroless shell policy missing: %v %s", err, output)
	}
}

func TestLintConfigSuppressionsAndInspectionFailures(t *testing.T) {
	prefix := lintFixture(t, 12)
	config := filepath.Join(t.TempDir(), "policy.json")
	data, err := json.Marshal(map[string]any{"version": 1, "fail_on": "info", "suppressions": []map[string]string{{"rule": "EC001", "target": evidence.FileID(prefix), "reason": "accepted iterative development"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeLint(t, "--format", "json", "--config", config, prefix)
	if err != nil || !strings.Contains(output, `"status": "suppressed"`) {
		t.Fatalf("exact suppression ignored: %v %s", err, output)
	}
	output, err = executeLint(t, "--format", "json", "--fail-on", "none", "not-present")
	if ExitCode(err) != 2 || !json.Valid([]byte(output)) {
		t.Fatalf("inspection error bypassed: %v %s", err, output)
	}
}

type failedLintWriter struct{}

func (failedLintWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestLintOutputErrorAndCancellation(t *testing.T) {
	cmd := New()
	cmd.SetOut(failedLintWriter{})
	cmd.SetArgs([]string{"lint", "--list-rules"})
	if ExitCode(cmd.Execute()) != 2 {
		t.Fatal("output failure not exit2")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd = New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"lint", "--format", "json", lintFixture(t, 0)})
	if ExitCode(cmd.ExecuteContext(ctx)) != 130 || !json.Valid(output.Bytes()) {
		t.Fatalf("cancelled lint: %s", output.String())
	}
}

func TestLintTimeoutReturnsInspectionFailure(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	cmd := New()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"lint", "--format", "json", lintFixture(t, 0)})
	if err := cmd.ExecuteContext(ctx); ExitCode(err) != 2 || !json.Valid(output.Bytes()) || !strings.Contains(output.String(), "deadline") {
		t.Fatalf("expired deadline did not fail: %v %s", err, output.String())
	}
}

func TestLintProjectRuleIgnoresDisabledHistory(t *testing.T) {
	prefix := lintFixture(t, 0)
	history := filepath.Join(prefix, "conda-meta", "history")
	if err := os.Remove(history); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(history, 0o755); err != nil {
		t.Fatal(err)
	}
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	output, err := executeLint(t, "--rule", "EC004", "--project", project, prefix)
	if err != nil || !strings.Contains(output, "EC004") || strings.Contains(output, "Inspection issue") {
		t.Fatalf("disabled history changed project-rule result: %v %s", err, output)
	}
}
