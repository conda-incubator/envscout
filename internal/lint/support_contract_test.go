package lint

import (
	"slices"
	"testing"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/evidence"
)

const (
	supportVenvReason   = "virtualenv lint is not supported yet for this rule"
	supportENV011Reason = "go-rattler does not provide authoritative Pixi manifest/lock synchronization; MatchSpec matching covers only part of that contract."
	supportCoverageMsg  = "required evidence coverage is not complete"
)

func supportVenvTarget(coverage map[string]string) evidence.Target {
	return evidence.Target{ID: "venv", Kind: "dir", Input: "/venv",
		Prefixes: []evidence.Prefix{{Kind: discovery.KindVenv, Path: "/venv"}}, Coverage: coverage}
}

// Gate order: Disabled > Unavailable > source > venv support > nil check > callback.
// Partial coverage never gates the callback.
func TestSupportContractEvaluateRuleGatePrecedence(t *testing.T) {
	dirConda := engineTarget("dir")
	partialConda := engineTarget("dir")
	partialConda.Coverage["conda-records"] = evidence.Partial
	dirVenv := supportVenvTarget(map[string]string{"prefixes": evidence.Complete})
	for _, tc := range []struct {
		name                    string
		enabled, available      bool
		kinds, venv             []string
		nilCheck, finding       bool
		target                  evidence.Target
		wantStatus              Status
		wantReason              string
		wantCalls, wantFindings int
	}{
		{name: "disabled beats unavailable", kinds: []string{"dir"}, target: dirConda, wantStatus: Disabled},
		{name: "unavailable beats source and venv", enabled: true, kinds: []string{"oci-archive"}, target: dirVenv, wantStatus: Unavailable, wantReason: "gate unavailable"},
		{name: "source beats venv", enabled: true, available: true, kinds: []string{"oci-archive"}, target: dirVenv, wantStatus: NotApplicable, wantReason: "rule does not apply to this source kind"},
		{name: "source beats supported venv", enabled: true, available: true, kinds: []string{"oci-archive"}, venv: []string{"prefixes"}, target: dirVenv, wantStatus: NotApplicable, wantReason: "rule does not apply to this source kind"},
		{name: "nil venv caps unknown", enabled: true, available: true, kinds: []string{"dir"}, target: dirVenv, wantStatus: Unknown, wantReason: supportVenvReason},
		{name: "empty venv caps unknown", enabled: true, available: true, kinds: []string{"dir"}, venv: []string{}, target: dirVenv, wantStatus: Unknown, wantReason: supportVenvReason},
		{name: "nil venv caps ignored for conda", enabled: true, available: true, kinds: []string{"dir"}, target: dirConda, wantStatus: Pass, wantCalls: 1},
		{name: "nil check unknown", enabled: true, available: true, kinds: []string{"dir"}, nilCheck: true, target: dirConda, wantStatus: Unknown, wantReason: "rule has no evaluation entry"},
		{name: "venv beats nil check", enabled: true, available: true, kinds: []string{"dir"}, nilCheck: true, target: dirVenv, wantStatus: Unknown, wantReason: supportVenvReason},
		{name: "partial coverage does not skip callback", enabled: true, available: true, kinds: []string{"dir"}, finding: true, target: partialConda, wantStatus: FindingStatus, wantCalls: 1, wantFindings: 1},
		{name: "supported venv runs callback", enabled: true, available: true, kinds: []string{"dir"}, venv: []string{"python-distributions"}, finding: true, target: dirVenv, wantStatus: FindingStatus, wantCalls: 1, wantFindings: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			supportInjectRegistryRow(t)
			calls := 0
			rule := Rule{ID: "TST001", Version: "1", Name: "gate", Available: tc.available,
				UnavailableReason: "gate unavailable", TargetKinds: tc.kinds, VirtualenvCapabilities: tc.venv}
			if !tc.nilCheck {
				rule.Check = func(target evidence.Target, _ RuleOptions, r Rule) (Outcome, []Finding) {
					calls++
					if !tc.finding {
						return Outcome{}, nil
					}
					return Outcome{}, []Finding{{RuleID: r.ID, Target: target.ID, Severity: Warning}}
				}
			}
			registry[ruleIndex[rule.ID]] = rule
			policy := Policy{Rules: map[string]RuleOptions{rule.ID: {Enabled: engineBool(tc.enabled), Severity: Warning}}}
			outcome, findings := executionFromPolicy(policy).evaluateRule(tc.target, rule)
			if outcome.Status != tc.wantStatus || outcome.Reason != tc.wantReason || calls != tc.wantCalls || len(findings) != tc.wantFindings {
				t.Fatalf("status=%s reason=%q calls=%d findings=%d", outcome.Status, outcome.Reason, calls, len(findings))
			}
		})
	}
}

// Selection checks unavailability before source, in Options.Rules order; explicit
// config errors follow registry order. Default unavailable rules are disclosed, not rejected.
func TestSupportContractBuildPolicyDiagnosticsOrder(t *testing.T) {
	unavailable := "rule ENV011 is unavailable: " + supportENV011Reason
	incompatible := `rule ENV006 is incompatible with source "oci-archive"`
	for _, tc := range []struct {
		name    string
		config  Policy
		options Options
		want    string
	}{
		{name: "unavailable selected before source", options: Options{Source: "oci-archive", Rules: []string{"ENV011"}}, want: unavailable},
		{name: "option order picks incompatible", options: Options{Source: "oci-archive", Rules: []string{"ENV006", "ENV011"}}, want: incompatible},
		{name: "option order picks unavailable", options: Options{Source: "oci-archive", Rules: []string{"ENV011", "ENV006"}}, want: unavailable},
		{name: "explicit config unavailable", config: Policy{Rules: map[string]RuleOptions{"ENV011": {Enabled: engineBool(true)}}}, options: Options{Source: "dir"}, want: unavailable},
		{name: "explicit config incompatible", config: Policy{Rules: map[string]RuleOptions{"ENV006": {Enabled: engineBool(true)}}}, options: Options{Source: "oci-archive"}, want: incompatible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildPolicy(tc.config, tc.options); err == nil || err.Error() != tc.want {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
	policy, err := BuildPolicy(Policy{}, Options{Source: "dir"})
	if err != nil || policy.Rules["ENV011"].Enabled == nil || !*policy.Rules["ENV011"].Enabled {
		t.Fatalf("default unavailable rule must stay enabled for disclosure: err=%v", err)
	}
	if got := engineOutcome(t, engineEvaluate(engineTarget("dir"), policy), "ENV011"); got.Status != Unavailable || got.Reason != supportENV011Reason {
		t.Fatalf("default ENV011 outcome: %+v", got)
	}
}

// Requirements accepts malformed policies: nil or unknown entries contribute nothing,
// venv caps come only from source dir, and duplicate capabilities collapse.
func TestSupportContractRequirementsMalformedAndSourceGates(t *testing.T) {
	on := engineBool(true)
	for _, tc := range []struct {
		name, runtime, project string
		policy                 Policy
		caps, venv             []string
	}{
		{name: "nil enabled is disabled", policy: Policy{Source: "dir", Rules: map[string]RuleOptions{"ENV006": {}}}},
		{name: "missing rules", policy: Policy{Source: "dir"}},
		{name: "unknown enabled id ignored", policy: Policy{Source: "dir", Rules: map[string]RuleOptions{"NOPE": {Enabled: on}}}},
		{name: "empty source selects no rules", policy: Policy{Rules: map[string]RuleOptions{"ENV006": {Enabled: on}}}},
		{name: "duplicate caps unioned and sorted", policy: Policy{Source: "dir", Rules: map[string]RuleOptions{"ENV005": {Enabled: on}, "ENV006": {Enabled: on}}},
			caps: []string{"conda-records", "prefixes"}},
		{name: "unavailable and oci-only skipped", policy: Policy{Source: "dir", Rules: map[string]RuleOptions{"ENV011": {Enabled: on}, "IMG001": {Enabled: on}}}},
		{name: "oci source skips dir rule", policy: Policy{Source: "oci-archive", Rules: map[string]RuleOptions{"ENV006": {Enabled: on}}}},
		{name: "dir venv caps from ENV013", policy: Policy{Source: "dir", Rules: map[string]RuleOptions{"ENV013": {Enabled: on}}},
			caps: []string{"conda-records", "prefixes"}, venv: []string{"prefixes", "python-distributions"}},
		{name: "oci ENV013 adds no venv caps", policy: Policy{Source: "oci-archive", Rules: map[string]RuleOptions{"ENV013": {Enabled: on}}},
			caps: []string{"conda-records", "prefixes"}},
		{name: "runtime assertion without rule", policy: Policy{Source: "oci-archive", RuntimePrefix: "/opt/app"},
			caps: []string{"runtime-config"}, runtime: "/opt/app"},
		{name: "project assertion without rule", policy: Policy{Source: "dir", Project: "/p"},
			caps: []string{"project-association"}, project: "/p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Requirements(tc.policy)
			if !slices.Equal(got.Capabilities, tc.caps) || !slices.Equal(got.VirtualenvCapabilities, tc.venv) ||
				got.RuntimePrefix != tc.runtime || got.Project != tc.project {
				t.Fatalf("requirements=%+v", got)
			}
		})
	}
}

// targetIssues emits venv-unsupported issues before source mismatch, assertions and coverage gaps.
func TestSupportContractTargetIssueOrder(t *testing.T) {
	dirPolicy := enginePolicy(t, "dir", "local", "ENV006")
	ociPolicy := enginePolicy(t, "oci-archive", "container", "IMG001")
	runtimePolicy, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Profile: "container", Rules: []string{"IMG001"}, RuntimePrefix: "/opt/app"})
	if err != nil {
		t.Fatal(err)
	}
	projectPolicy, err := BuildPolicy(Policy{}, Options{Source: "dir", Profile: "local", Rules: []string{"ENV002"}, Project: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		policy Policy
		target evidence.Target
		want   []evidence.Issue
	}{
		{name: "supported venv only requires its own capabilities", policy: enginePolicy(t, "dir", "local", "ENV013"), target: supportVenvTarget(map[string]string{"prefixes": evidence.Complete, "python-distributions": evidence.Complete})},
		{name: "venv unsupported under dir policy", policy: dirPolicy, target: supportVenvTarget(nil),
			want: []evidence.Issue{{Capability: "evaluation", Path: "/venv", Message: "ENV006 virtualenv lint is not supported yet"}}},
		{name: "venv unsupported before source mismatch", policy: ociPolicy, target: supportVenvTarget(nil),
			want: []evidence.Issue{
				{Capability: "evaluation", Path: "/venv", Message: "IMG001 virtualenv lint is not supported yet"},
				{Capability: "evaluation", Path: "venv", Message: "snapshot target source does not match effective policy"}}},
		{name: "runtime assertion before coverage", policy: runtimePolicy,
			target: evidence.Target{ID: "img", Kind: "oci-archive", Input: "image.tar", RuntimePrefix: "/opt/other",
				Coverage: map[string]string{"final-cache": evidence.Partial, "runtime-config": evidence.Complete}},
			want: []evidence.Issue{
				{Capability: "runtime-config", Path: "img", Message: "asserted runtime prefix was not verified in target evidence"},
				{Capability: "final-cache", Path: "img", Message: supportCoverageMsg}}},
		{name: "unverified project under dir policy", policy: projectPolicy,
			target: evidence.Target{ID: "conda", Kind: "dir", Input: "/p", Prefixes: []evidence.Prefix{{Path: "/p"}}},
			want:   []evidence.Issue{{Capability: "project-association", Path: "conda", Message: "explicit project association was not verified in target evidence"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := executionFromPolicy(tc.policy).targetIssues(tc.target, Requirements(tc.policy)); !slices.Equal(got, tc.want) {
				t.Fatalf("issues=%+v want %+v", got, tc.want)
			}
		})
	}
}

// supportInjectRegistryRow appends a test-only ordinary row; t.Cleanup restores registry and ruleIndex.
func supportInjectRegistryRow(t *testing.T) *int {
	t.Helper()
	calls := new(int)
	originalRegistry := registry
	registry = append(slices.Clip(registry), Rule{ID: "TST001", Version: "1", Name: "support contract", Category: "test",
		Description: "test-only ordinary row", TargetKinds: []string{"dir", "oci-archive"},
		Capabilities: []string{"prefixes", "conda-records"}, VirtualenvCapabilities: []string{"prefixes", "python-distributions"},
		Available: true, Defaults: profileDefaults(localOnly, nil, nil),
		Check: func(target evidence.Target, _ RuleOptions, rule Rule) (Outcome, []Finding) {
			*calls++
			return Outcome{}, []Finding{{RuleID: rule.ID, Target: target.ID, Severity: Warning}}
		}})
	ruleIndex["TST001"] = len(registry) - 1
	t.Cleanup(func() {
		registry = originalRegistry
		delete(ruleIndex, "TST001")
	})
	return calls
}

// An ordinary row with existing capability names needs no dispatch change.
// Partial coverage still runs the callback and yields an incomplete report.
func TestSupportContractRegistryRowSupportsExistingCapabilities(t *testing.T) {
	calls := supportInjectRegistryRow(t)
	if _, ok := LookupRule("TST001"); !ok {
		t.Fatal("injected row not registered")
	}
	conda := localTarget(localRecord("numpy", "2"))
	condaPartial := localTarget(localRecord("numpy", "2"))
	condaPartial.Coverage["conda-records"] = evidence.Partial
	venv := supportVenvTarget(map[string]string{"prefixes": evidence.Complete, "python-distributions": evidence.Complete})
	venvPartial := supportVenvTarget(map[string]string{"prefixes": evidence.Complete, "python-distributions": evidence.Partial})
	oci := engineTarget("oci-archive")
	oci.Coverage["conda-records"] = evidence.Complete
	dirCaps, dirVenv := []string{"conda-records", "prefixes"}, []string{"prefixes", "python-distributions"}
	for _, tc := range []struct {
		name, source, profile string
		target                evidence.Target
		wantCaps, wantVenv    []string
		wantReport            string
		wantIssues            []evidence.Issue
	}{
		{name: "conda dir complete", source: "dir", profile: "local", target: conda, wantCaps: dirCaps, wantVenv: dirVenv, wantReport: "completed"},
		{name: "venv dir complete", source: "dir", profile: "local", target: venv, wantCaps: dirCaps, wantVenv: dirVenv, wantReport: "completed"},
		{name: "venv partial retains positive", source: "dir", profile: "local", target: venvPartial, wantCaps: dirCaps, wantVenv: dirVenv, wantReport: "incomplete",
			wantIssues: []evidence.Issue{{Capability: "python-distributions", Path: "venv", Message: supportCoverageMsg}}},
		{name: "conda partial retains positive", source: "dir", profile: "local", target: condaPartial, wantCaps: dirCaps, wantVenv: dirVenv, wantReport: "incomplete",
			wantIssues: []evidence.Issue{{Capability: "conda-records", Path: "local", Message: supportCoverageMsg}}},
		{name: "oci complete", source: "oci-archive", profile: "container", target: oci, wantCaps: dirCaps, wantReport: "completed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := BuildPolicy(Policy{}, Options{Source: tc.source, Profile: tc.profile, Rules: []string{"TST001"}})
			if err != nil {
				t.Fatal(err)
			}
			if got := Requirements(policy); !slices.Equal(got.Capabilities, tc.wantCaps) || !slices.Equal(got.VirtualenvCapabilities, tc.wantVenv) {
				t.Fatalf("requirements=%+v", got)
			}
			*calls = 0
			report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{tc.target}}, policy, engineNow)
			outcome := engineOutcome(t, report, "TST001")
			if outcome.Status != FindingStatus || *calls != 1 || len(report.Findings) != 1 || report.Findings[0].RuleID != "TST001" ||
				report.Status != tc.wantReport || !slices.Equal(report.Issues, tc.wantIssues) {
				t.Fatalf("outcome=%+v calls=%d status=%s issues=%+v findings=%d", outcome, *calls, report.Status, report.Issues, len(report.Findings))
			}
		})
	}
}

func TestSupportContractInjectedRowIsRemoved(t *testing.T) {
	before := len(registry)
	t.Run("temporary row", func(t *testing.T) {
		supportInjectRegistryRow(t)
		if _, ok := LookupRule("TST001"); !ok || len(registry) != before+1 {
			t.Fatal("test row was not injected")
		}
	})
	if _, ok := LookupRule("TST001"); ok || len(ruleIndex) != len(registry) {
		t.Fatalf("test row leaked: found=%v index=%d registry=%d", ok, len(ruleIndex), len(registry))
	}
	if len(registry) != before {
		t.Fatal("test row changed the registry length after cleanup")
	}
}
