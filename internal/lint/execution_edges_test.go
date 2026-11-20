package lint

import (
	"slices"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
)

func edgeTarget(id, path string, records ...inventory.CondaRecord) evidence.Target {
	target := localTarget(records...)
	target.ID, target.Input, target.Prefixes[0].Path = id, path, path
	return target
}

// ENV009 is dir-only, so an explicit clock is the only way the EOL check can run.
func TestExecEdgesENV009ExplicitClock(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV009")
	target := edgeTarget("file:///env", "/env", localRecord("python", "3.10"))
	report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}, policy, engineNow)

	outcome := engineOutcome(t, report, "ENV009")
	if outcome.Status != FindingStatus {
		t.Fatalf("ENV009 status=%q reason=%q, want %q", outcome.Status, outcome.Reason, FindingStatus)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "ENV009" {
		t.Fatalf("findings=%+v, want exactly one ENV009 finding", report.Findings)
	}
}

// A venv prefix has no canonical conda identity. Observed baseline behavior: the conda
// peer match still emits a finding, so the outcome is FindingStatus while its reason
// records the venv limitation. The report stays completed because no issue is recorded.
func TestExecEdgesMixedVenvPrefixRetainsFinding(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV006")
	target := edgeTarget("file:///env", "/env", localRecord("numpy", "2"))
	target.Prefixes = append(target.Prefixes, evidence.Prefix{Kind: discovery.KindVenv, Path: "/v", RecordCoverage: evidence.Complete})
	peer := edgeTarget("file:///peer", "/peer", localRecord("numpy", "2"))
	report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target, peer}}, policy, engineNow)

	outcome := engineOutcome(t, report, "ENV006")
	if outcome.Status != FindingStatus || outcome.Reason != "complete canonical conda identity metadata is unavailable for /v" {
		t.Fatalf("ENV006 status=%q reason=%q, want finding naming /v", outcome.Status, outcome.Reason)
	}
	if len(report.Findings) != 2 || !slices.Equal(report.Findings[0].Evidence.Paths, []string{"/env", "/peer"}) {
		t.Fatalf("expected two retained conda-only findings: %+v", report.Findings)
	}
	if report.Status != "completed" {
		t.Fatalf("report status=%q, want completed (no issue recorded for venv limitation)", report.Status)
	}
}

// A target whose kind differs from the policy source produces a source-mismatch issue
// and is not applicable to dir-only ENV006, so no finding may be emitted for it.
func TestExecEdgesSourceMismatchEmitsIssueNotFinding(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV006")
	target := edgeTarget("file:///env", "/env", localRecord("numpy", "2"))
	target.Kind = "oci-archive"
	report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}, policy, engineNow)

	if report.Status != "incomplete" {
		t.Fatalf("report status=%q, want incomplete", report.Status)
	}
	if !slices.ContainsFunc(report.Issues, func(i evidence.Issue) bool {
		return strings.Contains(i.Message, "does not match effective policy")
	}) {
		t.Fatalf("issues=%+v, want source mismatch issue", report.Issues)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("findings=%+v, want none", report.Findings)
	}
}

func TestExecEdgesMixedVenvRecordsStayExcluded(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV006")
	target := edgeTarget("file:///env", "/env", localRecord("numpy", "2"))
	venv := target.Prefixes[0]
	venv.Kind, venv.Path = discovery.KindVenv, "/v"
	target.Prefixes = append(target.Prefixes, venv)
	report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}, policy, engineNow)
	outcome := engineOutcome(t, report, "ENV006")
	if outcome.Status != Unknown || outcome.Reason != "complete canonical conda identity metadata is unavailable for /v" || len(report.Findings) != 0 || report.Status != "completed" || report.ExitCode() != 0 {
		t.Fatalf("excluded venv records must not become conda duplicate evidence: outcome=%+v report=%+v", outcome, report)
	}
}

func TestExecEdgesIncompatibleEnabledPoliciesFailClosed(t *testing.T) {
	for _, id := range []string{"ENV006", "ENV009"} {
		policy := enginePolicy(t, "oci-archive", "container", "IMG001")
		policy.Rules[id] = RuleOptions{Enabled: engineBool(true), Severity: Warning}
		report := Evaluate(evidence.Snapshot{Targets: []evidence.Target{edgeTarget("file:///env", "/env", localRecord("python", "3.10"))}}, policy, engineNow)
		if report.Status != "failed" || len(report.Outcomes) != 0 || len(report.Findings) != 0 || len(report.Issues) != 1 || report.Issues[0].Message != "lint evaluation requires a normalized effective policy from BuildPolicy" {
			t.Fatalf("incompatible %s policy reached evaluation: %+v", id, report)
		}
	}
}
