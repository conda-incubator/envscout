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

	"github.com/conda-incubator/envscout/internal/evidence"
	policy "github.com/conda-incubator/envscout/internal/lint"
	"github.com/conda-incubator/envscout/internal/testimage"
)

func lintFixture(t *testing.T, revision int) string {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "env")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(canonicalPrefixRecord("demo", "1", "0")), 0o644); err != nil {
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
	if err != nil || !strings.Contains(output, "ENV001") || !strings.Contains(output, "Found:") || !strings.Contains(output, "Next:") {
		t.Fatalf("local informational lint: %v: %s", err, output)
	}
	output, err = executeLint(t, "--format", "json", "--fail-on", "info", prefix)
	if ExitCode(err) != 1 || ShouldPrintError(err) || !json.Valid([]byte(output)) {
		t.Fatalf("policy failure not structured/silent: %v: %s", err, output)
	}
	if _, err := os.Stat("sboms"); !os.IsNotExist(err) {
		t.Fatal("lint created SBOMs")
	}
	if output, err := executeLint(t, "--fail-on", "none", prefix); err != nil || !strings.Contains(output, "ENV001") {
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
	if err != nil || json.Unmarshal([]byte(output), &listed) != nil || len(listed) != len(policy.ListRules()) {
		t.Fatalf("incorrect rules listing: %v %s", err, output)
	}
	seen := make(map[string]bool, len(listed))
	for _, rule := range listed {
		if _, ok := policy.LookupRule(rule.ID); !ok || seen[rule.ID] {
			t.Fatalf("unregistered or duplicate rule in catalogue: %+v", rule)
		}
		seen[rule.ID] = true
		if rule.ID == "ENV011" {
			if rule.Available || rule.UnavailableReason == "" {
				t.Fatalf("unavailable rule not disclosed: %+v", rule)
			}
		} else if !rule.Available || rule.UnavailableReason != "" {
			t.Fatalf("bad listed rule: %+v", rule)
		}
	}
	if !seen["ENV011"] {
		t.Fatal("catalogue omits unavailable manifest/lock rule")
	}
	output, err = executeLint(t, "--list-rules")
	if err != nil || !strings.Contains(output, "ENV011") || !strings.Contains(output, "Unavailable:") {
		t.Fatalf("text rules listing hides unavailable rules: %v %s", err, output)
	}
}

func TestLintJSONSchemaOmitsDerivedFindingMetadata(t *testing.T) {
	output, err := executeLint(t, "--format", "json", "--fail-on", "none", lintFixture(t, 12))
	if err != nil {
		t.Fatalf("lint: %v %s", err, output)
	}
	var report struct {
		SchemaVersion int              `json:"schema_version"`
		Findings      []map[string]any `json:"findings"`
		OutcomeCounts map[string]int   `json:"outcome_counts"`
		Outcomes      []map[string]any `json:"outcomes"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.SchemaVersion != 4 || policy.SchemaVersion != 4 {
		t.Fatalf("schema_version = %d, want 4", report.SchemaVersion)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range report.Findings {
		for _, key := range []string{"rule_version", "confidence", "category", "references", "recommendation"} {
			if _, ok := f[key]; ok {
				t.Errorf("finding retains derived metadata key %q: %v", key, f)
			}
		}
	}
	// OutcomeCounts includes disabled/not-applicable states omitted from Outcomes.
	active := make(map[string]int)
	for _, o := range report.Outcomes {
		for _, key := range []string{"findings", "rule_version"} {
			if _, present := o[key]; present {
				t.Fatalf("outcome retains duplicate %q metadata: %+v", key, o)
			}
		}
		active[o["status"].(string)]++
	}
	for status, n := range active {
		if report.OutcomeCounts[status] != n {
			t.Errorf("OutcomeCounts[%s]=%d, active outcomes=%d", status, report.OutcomeCounts[status], n)
		}
	}
	if report.OutcomeCounts[string(policy.Disabled)] == 0 {
		t.Errorf("OutcomeCounts omits disabled outcomes: %v", report.OutcomeCounts)
	}
	for _, rule := range policy.ListRules() {
		if _, ok := policy.LookupRule(rule.ID); !ok {
			t.Errorf("listed rule %s not returned by LookupRule", rule.ID)
		}
	}
}

func TestLintInputErrorsBeforeCollection(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--unknown"}, {"--profile", "bad", "missing"}, {"--fail-on", "bad", "missing"},
		{"--rule", "ENV011", "missing"}, {"--rule", "ENV001", "--disable-rule", "ENV001", "missing"},
		{"--rule", "EC001", "missing"}, {"--disable-rule", "IC001", "missing"},
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

func TestLintRejectsLegacyRuleIDsInFlagsAndPolicy(t *testing.T) {
	prefix := lintFixture(t, 0)
	for _, id := range []string{"EC001", "EC004", "EC002", "EC003", "IC001", "IC002", "IC003", "IC004", "IC006", "IC007"} {
		for _, flag := range []string{"--rule", "--disable-rule"} {
			output, err := executeLint(t, flag, id, prefix)
			if ExitCode(err) != 2 || output != "" || !strings.Contains(err.Error(), id) {
				t.Errorf("legacy flag %s %s accepted: %v %s", flag, id, err, output)
			}
		}
		for _, config := range []policy.Policy{
			{Version: policy.ConfigVersion, Rules: map[string]policy.RuleOptions{id: {Severity: policy.Info}}},
			{Version: policy.ConfigVersion, Suppressions: []policy.Suppression{{Rule: id, Target: evidence.FileID(prefix), Reason: "old exception"}}},
		} {
			data, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "legacy-policy.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := executeLint(t, "--config", path, prefix)
			if ExitCode(err) != 2 || output != "" || !strings.Contains(err.Error(), id) {
				t.Errorf("legacy policy ID %s accepted: %v %s", id, err, output)
			}
		}
	}
}

func TestLintImageMultipleRulesAndLayerRetention(t *testing.T) {
	archive := testimage.Archive(t,
		[]testimage.Entry{
			{Name: "opt/conda/conda-meta/conda.json", Data: canonicalPrefixRecord("conda", "26.7", "0")},
			{Name: "opt/conda/envs/app/conda-meta/demo.json", Data: canonicalPrefixRecord("demo", "1", "0")},
			{Name: "opt/conda/pkgs/old-1.0-0.conda", Data: "old cache"},
			{Name: "opt/conda/pkgs/current-1.0-0.conda", Data: "current cache"},
			{Name: "opt/conda/pkgs/demo-1.0-0/info/index.json", Data: `{"name":"demo","version":"1.0","build":"0","build_number":0,"subdir":"linux-64"}`},
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
	for _, rule := range []string{"IMG001", "IMG002", "IMG003", "IMG004", "IMG005"} {
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
	if ExitCode(err) != 1 || !strings.Contains(output, "IMG006") {
		t.Fatalf("distroless shell policy missing: %v %s", err, output)
	}
}

func TestLintConfigSuppressionsAndInspectionFailures(t *testing.T) {
	prefix := lintFixture(t, 12)
	config := filepath.Join(t.TempDir(), "policy.json")
	data, err := json.Marshal(map[string]any{"version": 1, "fail_on": "info", "suppressions": []map[string]string{{"rule": "ENV001", "target": evidence.FileID(prefix), "reason": "accepted iterative development"}}})
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
	output, err := executeLint(t, "--rule", "ENV002", "--project", project, prefix)
	if err != nil || !strings.Contains(output, "ENV002") || strings.Contains(output, "Inspection issue") {
		t.Fatalf("disabled history changed project-rule result: %v %s", err, output)
	}
}
