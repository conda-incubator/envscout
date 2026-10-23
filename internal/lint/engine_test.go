package lint

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anaconda/envscout/internal/evidence"
)

func engineBool(value bool) *bool { return &value }
func engineInt(value int) *int    { return &value }

var engineNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func enginePolicy(t *testing.T, source, profile string, rules ...string) Policy {
	t.Helper()
	p, err := BuildPolicy(Policy{}, Options{Source: source, Profile: profile, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func engineTarget(kind string) evidence.Target {
	return evidence.Target{ID: "file:///environment", Kind: kind, Input: "/environment", Coverage: map[string]string{
		"prefixes": evidence.Complete, "history": evidence.Complete, "tooling-prefix": evidence.Complete,
		"final-cache": evidence.Complete, "cache-link-dependencies": evidence.Complete, "runtime-config": evidence.Complete,
		"os-package-tools": evidence.Complete, "shell-tools": evidence.Complete, "layer-retention": evidence.Complete,
		"project-association": evidence.Complete,
	}}
}

func engineEvaluate(target evidence.Target, policy Policy) Report {
	return Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}, policy, engineNow)
}

func engineOutcome(t *testing.T, report Report, rule string) Outcome {
	t.Helper()
	for _, outcome := range report.Outcomes {
		if outcome.RuleID == rule {
			return outcome
		}
	}
	t.Fatalf("missing outcome %s", rule)
	return Outcome{}
}

func TestBuildPolicyPrecedenceAndSelection(t *testing.T) {
	config := Policy{Version: 1, Profile: "container-runtime", FailOn: "error", Rules: map[string]RuleOptions{
		"IC006": {Enabled: engineBool(false), Severity: "error"},
		"EC001": {Severity: "warning", RevisionThreshold: engineInt(12)},
	}}
	p, err := BuildPolicy(config, Options{Source: "oci-archive", Profile: "container-development", FailOn: "info", Rules: []string{"IC006", "EC001"}, DisableRules: []string{"IC001"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Profile != "container-development" || p.FailOn != "info" || len(p.Rules) != 11 || p.Source != "oci-archive" {
		t.Fatalf("bad effective policy: %+v", p)
	}
	for id, options := range p.Rules {
		if options.Enabled == nil || options.Severity == "" || *options.Enabled != (id == "IC006" || id == "EC001") {
			t.Fatalf("bad normalized rule %s: %+v", id, options)
		}
	}
	if p.Rules["IC006"].Severity != "error" || *p.Rules["EC001"].RevisionThreshold != 12 {
		t.Fatal("config rule overrides lost")
	}
	*p.Rules["EC001"].RevisionThreshold = 30
	if *config.Rules["EC001"].RevisionThreshold != 12 {
		t.Fatal("input policy mutated")
	}
	for _, tc := range []struct{ source, profile, fail string }{
		{"dir", "local", "warning"}, {"oci-archive", "container", "warning"},
	} {
		p := enginePolicy(t, tc.source, "")
		if p.Profile != tc.profile || p.FailOn != tc.fail {
			t.Fatalf("source defaults: %+v", p)
		}
	}
	// CLI restriction/disabling overrides an unavailable config enable before
	// collection; an effective explicit requirement still fails configuration.
	config = Policy{Rules: map[string]RuleOptions{"EC002": {Enabled: engineBool(true)}}}
	for _, options := range []Options{{Rules: []string{"EC001"}}, {DisableRules: []string{"EC002"}}} {
		p, err := BuildPolicy(config, options)
		if err != nil || ruleEnabled(p, "EC002") {
			t.Fatalf("explicit CLI precedence failed: %+v %v", p, err)
		}
	}
}

func TestBuildPolicyRejectsInvalidOrUnavailableRequests(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  Policy
		options Options
	}{
		{name: "source", options: Options{Source: "registry"}},
		{name: "profile", options: Options{Profile: "production"}},
		{name: "source profile", options: Options{Source: "dir", Profile: "container-runtime"}},
		{name: "severity", options: Options{FailOn: "critical"}},
		{name: "unknown", options: Options{Rules: []string{"IC099"}}},
		{name: "unknown disabled", options: Options{DisableRules: []string{"IC099"}}},
		{name: "contradiction", options: Options{Rules: []string{"EC001"}, DisableRules: []string{"EC001"}}},
		{name: "source rule", options: Options{Rules: []string{"IC001"}}},
		{name: "installed unavailable", options: Options{Rules: []string{"EC002"}}},
		{name: "manifest unavailable", options: Options{Rules: []string{"EC003"}}},
		{name: "config unavailable", config: Policy{Rules: map[string]RuleOptions{"EC002": {Enabled: engineBool(true)}}}},
		{name: "config source rule", config: Policy{Rules: map[string]RuleOptions{"IC001": {Enabled: engineBool(true)}}}},
		{name: "threshold", config: Policy{Rules: map[string]RuleOptions{"EC001": {RevisionThreshold: engineInt(-1)}}}},
		{name: "option mismatch", config: Policy{Rules: map[string]RuleOptions{"IC006": {RevisionThreshold: engineInt(10)}}}},
		{name: "runtime local", options: Options{RuntimePrefix: "/opt/app"}},
		{name: "runtime relative", options: Options{Source: "oci-archive", RuntimePrefix: "opt/app"}},
		{name: "runtime traversal", options: Options{Source: "oci-archive", RuntimePrefix: "/opt/../app"}},
		{name: "runtime windows", options: Options{Source: "oci-archive", RuntimePrefix: `C:\app`}},
		{name: "project image", options: Options{Source: "oci-archive", Project: "/project"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildPolicy(tc.config, tc.options); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestRequirementsUnionAndDisabledCollectors(t *testing.T) {
	p := enginePolicy(t, "oci-archive", "container-runtime", "IC001", "IC002", "IC003", "IC006")
	want := []string{"cache-link-dependencies", "final-cache", "os-package-tools", "prefixes", "runtime-config", "tooling-prefix"}
	if got := Requirements(p).Capabilities; !reflect.DeepEqual(got, want) {
		t.Fatalf("requirements %v, want %v", got, want)
	}
	p, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Profile: "container-runtime", DisableRules: []string{"IC004", "IC005", "IC003", "IC002"}})
	if err != nil {
		t.Fatal(err)
	}
	if caps := Requirements(p).Capabilities; slices.Contains(caps, "layer-retention") || slices.Contains(caps, "runtime-config") || slices.Contains(caps, "cache-link-dependencies") {
		t.Fatalf("disabled expensive requirements collected: %v", caps)
	}
	p = enginePolicy(t, "dir", "local")
	if caps := Requirements(p).Capabilities; slices.Contains(caps, "installed-lock") || slices.Contains(caps, "manifest-lock") {
		t.Fatalf("unavailable providers requested: %v", caps)
	}
	if engineOutcome(t, engineEvaluate(engineTarget("dir"), p), "EC002").Status != Unavailable {
		t.Fatal("profile did not disclose unavailable provider")
	}
	for _, rule := range ListRules() {
		if !rule.Available || rule.ID == "EC002" || rule.ID == "EC003" || len(rule.Defaults) != 5 {
			t.Fatalf("bad implemented rule listing: %+v", rule)
		}
	}
	listed := ListRules()
	listed[0].Capabilities[0] = "mutated"
	if ListRules()[0].Capabilities[0] == "mutated" {
		t.Fatal("listing exposes registry mutation")
	}
	p, err = BuildPolicy(Policy{}, Options{Source: "oci-archive", Rules: []string{"IC001"}, RuntimePrefix: "/opt/app"})
	if err != nil || !slices.Contains(Requirements(p).Capabilities, "runtime-config") {
		t.Fatalf("asserted runtime input bypassed validation: %v %+v", err, Requirements(p))
	}
	p, err = BuildPolicy(Policy{}, Options{Rules: []string{"EC001"}, Project: "/project"})
	if err != nil || !slices.Contains(Requirements(p).Capabilities, "project-association") {
		t.Fatalf("asserted project input bypassed validation: %v %+v", err, Requirements(p))
	}
}

func TestRevisionBoundariesAndUnknown(t *testing.T) {
	p := enginePolicy(t, "dir", "local", "EC001")
	for _, tc := range []struct {
		name     string
		revision *int
		status   string
	}{
		{"zero", engineInt(0), Pass}, {"below", engineInt(9), Pass},
		{"boundary", engineInt(10), FindingStatus}, {"above", engineInt(12), FindingStatus},
		{"missing", nil, Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := engineTarget("dir")
			target.Prefixes = []evidence.Prefix{{Path: "/environment", Revision: tc.revision}}
			report := engineEvaluate(target, p)
			if outcome := engineOutcome(t, report, "EC001"); outcome.Status != tc.status || report.ExitCode() != 0 {
				t.Fatalf("outcome=%+v exit=%d", outcome, report.ExitCode())
			}
		})
	}
	report := engineEvaluate(engineTarget("dir"), p)
	if outcome := engineOutcome(t, report, "EC001"); outcome.Status != NotApplicable || outcome.SubjectCount != 0 {
		t.Fatalf("zero subjects: %+v", outcome)
	}
	target := engineTarget("dir")
	target.Prefixes = []evidence.Prefix{{Path: "/environment"}}
	target.Coverage["history"] = evidence.NotCollected
	if report := engineEvaluate(target, p); report.ExitCode() != 0 || report.Status != "completed" {
		t.Fatalf("optional absent history made run fail: %+v", report)
	}
	target.Issues = []evidence.Issue{{Capability: "history", Path: "/environment/conda-meta/history", Message: "permission denied"}}
	if report := engineEvaluate(target, p); report.ExitCode() != 2 {
		t.Fatal("history collection error did not fail inspection")
	}
}

func TestImageArtifactRulesAndLinkageSeverity(t *testing.T) {
	for _, tc := range []struct {
		name, profile, rule, severity string
		linked                        bool
		coverage                      string
	}{
		{"runtime archives", "container-runtime", "IC001", "warning", false, evidence.Complete},
		{"development archives", "container-development", "IC001", "info", false, evidence.Complete},
		{"generic archives", "container", "IC001", "info", false, evidence.Complete},
		{"runtime extracted", "container-runtime", "IC002", "warning", false, evidence.Complete},
		{"runtime linked", "container-runtime", "IC002", "info", true, evidence.Complete},
		{"runtime unknown links", "container-runtime", "IC002", "info", false, evidence.Partial},
		{"retained", "container-runtime", "IC004", "warning", false, evidence.Complete},
		{"runtime manager", "container-runtime", "IC006", "warning", false, evidence.Complete},
		{"distroless manager", "container-distroless", "IC006", "error", false, evidence.Complete},
		{"development manager", "container-development", "IC006", "info", false, evidence.Complete},
		{"generic manager", "container", "IC006", "info", false, evidence.Complete},
		{"distroless shell", "container-distroless", "IC007", "error", false, evidence.Complete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := enginePolicy(t, "oci-archive", tc.profile, tc.rule)
			target := engineTarget("oci-archive")
			artifact := []evidence.Artifact{{Path: "/opt/conda/pkgs/package.conda", Bytes: 50, Reference: "ref1", DiffID: "sha256:diff", BlobDigest: "sha256:blob", LayerBytes: 1000}}
			switch tc.rule {
			case "IC001":
				target.Archives = artifact
			case "IC002":
				target.Extracted = artifact
				target.CacheLinked = tc.linked
				target.Coverage["cache-link-dependencies"] = tc.coverage
			case "IC004":
				target.Retained = artifact
			case "IC006":
				target.Tools = artifact
			case "IC007":
				target.Shells = artifact
			}
			report := engineEvaluate(target, p)
			if len(report.Findings) != 1 || report.Findings[0].Severity != tc.severity || report.Findings[0].Confidence != "high" {
				t.Fatalf("findings %+v", report.Findings)
			}
			if tc.rule == "IC004" && (report.Findings[0].Evidence.PayloadBytes != 50 || report.Findings[0].Evidence.Samples[0].LayerBytes != 1000) {
				t.Fatal("retained byte units were confused")
			}
		})
	}
	for _, profile := range []string{"container", "container-runtime", "container-development"} {
		target := engineTarget("oci-archive")
		target.Shells = []evidence.Artifact{{Path: "/bin/sh"}}
		if report := engineEvaluate(target, enginePolicy(t, "oci-archive", profile)); engineOutcome(t, report, "IC007").Status != Disabled {
			t.Fatal("ordinary profiles enabled shell prohibition")
		}
	}
}

func TestToolingPrefixLayoutAndRuntimeExceptions(t *testing.T) {
	p := enginePolicy(t, "oci-archive", "container-runtime", "IC003")
	for _, tc := range []struct {
		name     string
		prefixes []evidence.Prefix
		runtime  string
		tooling  bool
		want     string
	}{
		{"base only", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}}, "", false, Pass},
		{"app only", []evidence.Prefix{{Path: "/opt/app"}}, "", false, Pass},
		{"name not evidence", []evidence.Prefix{{Path: "/base"}, {Path: "/base/envs/app"}}, "", false, Pass},
		{"unrelated", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/unrelated"}}, "", false, Pass},
		{"nested", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}, "", false, FindingStatus},
		{"declared app", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/app"}}, "/opt/app", false, FindingStatus},
		{"uses tooling", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}, "", true, FindingStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := engineTarget("oci-archive")
			target.Prefixes, target.RuntimePrefix, target.RuntimeUsesTooling = tc.prefixes, tc.runtime, tc.tooling
			report := engineEvaluate(target, p)
			if engineOutcome(t, report, "IC003").Status != tc.want {
				t.Fatalf("unexpected outcome %+v", report.Outcomes)
			}
			if len(report.Findings) > 0 && report.Findings[0].Severity != "info" {
				t.Fatal("layout candidate promoted to runtime defect")
			}
			if tc.tooling && !strings.Contains(report.Findings[0].Evidence.Notes[0], "does not justify removing") {
				t.Fatal("needed tooling exception lost")
			}
		})
	}
}

func TestProjectAssociationNeverGuessesLockMismatch(t *testing.T) {
	p := enginePolicy(t, "dir", "local", "EC004")
	for _, tc := range []struct {
		project *evidence.Project
		status  string
	}{
		{nil, Unknown}, {&evidence.Project{Path: "/project"}, Unknown},
		{&evidence.Project{Path: "/project", Associated: true}, FindingStatus},
		{&evidence.Project{Path: "/project", Associated: true, LockPath: "/project/pixi.lock"}, Unknown},
		{&evidence.Project{Path: "/project", Associated: true, LockPath: "/project/pixi.lock", LockVerified: true}, Pass},
	} {
		target := engineTarget("dir")
		target.Project = tc.project
		report := engineEvaluate(target, p)
		if outcome := engineOutcome(t, report, "EC004"); outcome.Status != tc.status || report.ExitCode() != 0 {
			t.Fatalf("project %+v outcome %+v exit %d", tc.project, outcome, report.ExitCode())
		}
	}
}

func TestPolicySeverityOverridesConservativeDefaults(t *testing.T) {
	for _, rule := range []string{"IC003", "EC004"} {
		for _, severity := range []string{"", "error"} {
			t.Run(rule+"/"+severity, func(t *testing.T) {
				source, profile := "oci-archive", "container-runtime"
				target := engineTarget(source)
				target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}
				if rule == "EC004" {
					source, profile = "dir", "local"
					target = engineTarget(source)
					target.Project = &evidence.Project{Path: "/project", Associated: true}
				}
				p, err := BuildPolicy(Policy{Rules: map[string]RuleOptions{rule: {Severity: severity}}},
					Options{Source: source, Profile: profile, Rules: []string{rule}, FailOn: "error"})
				if err != nil {
					t.Fatal(err)
				}
				wantSeverity, wantExit := "info", 0
				if severity != "" {
					wantSeverity, wantExit = severity, 1
				}
				report := engineEvaluate(target, p)
				if len(report.Findings) != 1 || report.Findings[0].Severity != wantSeverity || report.ExitCode() != wantExit {
					t.Fatalf("effective severity %s not honored: %+v", p.Rules[rule].Severity, report)
				}
			})
		}
	}
}

func TestRuntimeCoverageControlsAbsenceOutcomes(t *testing.T) {
	for _, rule := range []string{"IC003", "IC005"} {
		for _, coverage := range []string{evidence.Complete, evidence.Partial, evidence.NotCollected} {
			for _, nested := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/nested=%t", rule, coverage, nested), func(t *testing.T) {
					target := engineTarget("oci-archive")
					app := "/app"
					if nested {
						app = "/opt/conda/envs/app"
					}
					target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: app}}
					target.Coverage["runtime-config"] = coverage
					report := engineEvaluate(target, enginePolicy(t, "oci-archive", "container-runtime", rule))
					wantStatus, wantExit := Pass, 0
					if coverage != evidence.Complete {
						wantStatus, wantExit = Unknown, 2
					}
					if nested {
						wantStatus = FindingStatus
					}
					if outcome := engineOutcome(t, report, rule); outcome.Status != wantStatus || report.ExitCode() != wantExit {
						t.Fatalf("runtime-dependent outcome %+v exit=%d, want %s/%d", outcome, report.ExitCode(), wantStatus, wantExit)
					}
				})
			}
		}
	}
}

func TestContextualRuleDoesNotMultiplyFailures(t *testing.T) {
	target := engineTarget("oci-archive")
	target.Archives = []evidence.Artifact{{Path: "/cache/pkg.conda", Bytes: 50}}
	p := enginePolicy(t, "oci-archive", "container-runtime", "IC005")
	p.FailOn = "info"
	report := engineEvaluate(target, p)
	if len(report.Findings) != 1 || !report.Findings[0].Contextual || report.Findings[0].Evidence.PayloadBytes != 0 || report.ExitCode() != 0 {
		t.Fatalf("contextual outcome %+v", report)
	}
	p = enginePolicy(t, "oci-archive", "container-runtime", "IC001", "IC005")
	report = engineEvaluate(target, p)
	if len(report.Findings) != 2 || len(report.Findings[1].RelatedFindings) != 1 || report.Findings[1].RelatedFindings[0] != report.Findings[0].Fingerprint {
		t.Fatalf("primary context linkage %+v", report.Findings)
	}
	p = enginePolicy(t, "oci-archive", "container-development", "IC005")
	if outcome := engineOutcome(t, engineEvaluate(target, p), "IC005"); outcome.Status != NotApplicable {
		t.Fatalf("development runtime inference: %+v", outcome)
	}
}

func TestCoverageAndExitPrecedence(t *testing.T) {
	target := engineTarget("oci-archive")
	p := enginePolicy(t, "oci-archive", "container-runtime", "IC001")
	target.Coverage["final-cache"] = evidence.Partial
	report := engineEvaluate(target, p)
	if engineOutcome(t, report, "IC001").Status != Unknown || report.Status != "incomplete" || report.ExitCode() != 2 {
		t.Fatal("partial absence passed inspection")
	}
	target.Archives = []evidence.Artifact{{Path: "/cache/pkg.conda"}}
	report = engineEvaluate(target, p)
	if len(report.Findings) != 1 || report.Findings[0].Severity != "warning" || report.ExitCode() != 2 {
		t.Fatal("positive partial facts discarded or inspection failure did not win")
	}
	p.FailOn = "none"
	if engineEvaluate(target, p).ExitCode() != 2 {
		t.Fatal("fail-on none masked inspection error")
	}
	target.Coverage["final-cache"] = evidence.Complete
	for _, tc := range []struct {
		threshold string
		code      int
	}{{"none", 0}, {"error", 0}, {"warning", 1}, {"info", 1}} {
		p.FailOn = tc.threshold
		if got := engineEvaluate(target, p).ExitCode(); got != tc.code {
			t.Fatalf("threshold %s returned %d", tc.threshold, got)
		}
	}
	target.Issues = []evidence.Issue{{Capability: "final-cache", Message: "read failure"}}
	if engineEvaluate(target, p).ExitCode() != 2 {
		t.Fatal("collector issue masked by finding")
	}
	if Evaluate(evidence.Snapshot{}, Policy{}, engineNow).ExitCode() != 2 {
		t.Fatal("unnormalized policy accepted")
	}
}

func TestExactSuppressionsAndStrictNotes(t *testing.T) {
	target := engineTarget("oci-archive")
	target.ID = "oci:sha256:image@linux/amd64"
	target.Archives = []evidence.Artifact{{Path: "/cache/pkg.conda"}}
	base := enginePolicy(t, "oci-archive", "container-runtime", "IC001")
	fingerprint := engineEvaluate(target, base).Findings[0].Fingerprint
	for _, selector := range []Suppression{
		{Target: target.ID}, {Path: "/cache/pkg.conda"}, {Fingerprint: fingerprint}, {Fingerprint: strings.ToUpper(fingerprint)},
		{Target: target.ID, Path: "/cache/pkg.conda", Fingerprint: fingerprint},
	} {
		selector.Rule, selector.Reason, selector.Expires = "IC001", "reviewed accepted cache", "2026-10-21"
		p, err := BuildPolicy(Policy{Suppressions: []Suppression{selector}}, Options{Source: "oci-archive", Profile: "container-runtime", Rules: []string{"IC001"}})
		if err != nil {
			t.Fatal(err)
		}
		report := engineEvaluate(target, p)
		if report.ExitCode() != 0 || report.Findings[0].Suppression == nil || engineOutcome(t, report, "IC001").Status != Suppressed {
			t.Fatalf("selector %+v not honored: %+v", selector, report)
		}
	}
	for _, tc := range []struct {
		name, profile, path, expires, note string
		code                               int
	}{
		{"exact no glob", "container-runtime", "/cache/*", "", "unused", 1},
		{"expired", "container-runtime", "/cache/pkg.conda", "2026-10-20", "expired", 1},
		{"strict expired", "container-distroless", "/cache/pkg.conda", "2026-10-20", "expired", 2},
		{"strict unused", "container-distroless", "/cache/other.conda", "", "unused", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := BuildPolicy(Policy{Suppressions: []Suppression{{Rule: "IC001", Path: tc.path, Expires: tc.expires, Reason: "accepted"}}}, Options{Source: "oci-archive", Profile: tc.profile, Rules: []string{"IC001"}})
			if err != nil {
				t.Fatal(err)
			}
			report := engineEvaluate(target, p)
			if report.ExitCode() != tc.code || len(report.SuppressionNotes) != 1 || report.SuppressionNotes[0].Status != tc.note {
				t.Fatalf("suppression result %+v", report)
			}
		})
	}
}

func TestAssertionsMustBeVerifiedEvenWithNarrowRules(t *testing.T) {
	target := engineTarget("oci-archive")
	p, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Rules: []string{"IC001"}, RuntimePrefix: "/opt/app"})
	if err != nil {
		t.Fatal(err)
	}
	if engineEvaluate(target, p).ExitCode() != 2 {
		t.Fatal("missing asserted prefix was silently accepted")
	}
	target.RuntimePrefix = "/opt/app"
	if engineEvaluate(target, p).ExitCode() != 0 {
		t.Fatal("verified asserted prefix rejected")
	}
	target = engineTarget("dir")
	p, err = BuildPolicy(Policy{}, Options{Rules: []string{"EC001"}, Project: "/project"})
	if err != nil {
		t.Fatal(err)
	}
	if engineEvaluate(target, p).ExitCode() != 2 {
		t.Fatal("missing asserted project association was silently accepted")
	}
	target.Project = &evidence.Project{Associated: true, Path: p.Project}
	if engineEvaluate(target, p).ExitCode() != 0 {
		t.Fatal("verified asserted project rejected")
	}
}

func TestDeterministicReportAndFingerprintIdentity(t *testing.T) {
	p := enginePolicy(t, "oci-archive", "container-runtime", "IC001", "IC004")
	a := engineTarget("oci-archive")
	a.ID = "oci:sha256:image@linux/amd64"
	a.Archives = []evidence.Artifact{{Path: "/z.conda", Reference: "z", Bytes: 5}, {Path: "/a.conda", Reference: "a", Bytes: 4}}
	a.Retained = []evidence.Artifact{{Path: "/z.conda", Reference: "older", DiffID: "sha256:diff", BlobDigest: "sha256:blob", Bytes: 3}}
	b := a
	b.ID = "oci:sha256:other@linux/amd64"
	first := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{b, a}}, p, engineNow)
	a.Archives = []evidence.Artifact{a.Archives[1], a.Archives[0]}
	second := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{a, b}}, p, engineNow)
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !slices.Equal(firstJSON, secondJSON) {
		t.Fatalf("report depends on discovery order\n%s\n%s", firstJSON, secondJSON)
	}
	target := engineTarget("oci-archive")
	target.Archives = []evidence.Artifact{{Path: "/cache/pkg.conda", Bytes: 5, Reference: "stable"}}
	one := engineEvaluate(target, p)
	target.Input = "/different-archive-label"
	target.Archives[0].Bytes = 20
	p.Rules["IC001"] = RuleOptions{Enabled: engineBool(true), Severity: "error"}
	two := Evaluate(evidence.Snapshot{Started: engineNow.Add(time.Hour), Targets: []evidence.Target{target}}, p, engineNow.Add(time.Hour))
	if one.Findings[0].Fingerprint != two.Findings[0].Fingerprint || one.ConfigDigest == two.ConfigDigest {
		t.Fatal("fingerprint includes display/size/severity/time or config digest omitted options")
	}
	p.RuntimePrefix = "/opt/app"
	if engineEvaluate(target, p).ConfigDigest == two.ConfigDigest {
		t.Fatal("transient execution input missing from config digest")
	}
	target.Archives[0].Reference = "different"
	if engineEvaluate(target, p).Findings[0].Fingerprint == two.Findings[0].Fingerprint {
		t.Fatal("reference identity missing from fingerprint")
	}
}

func TestBoundedSamplesAndFindings(t *testing.T) {
	p := enginePolicy(t, "oci-archive", "container-runtime", "IC001")
	target := engineTarget("oci-archive")
	for i := 0; i < 30; i++ {
		target.Archives = append(target.Archives, evidence.Artifact{Path: fmt.Sprintf("/cache/%02d.conda", i), Bytes: 1})
	}
	report := engineEvaluate(target, p)
	f := report.Findings[0]
	if len(f.Evidence.Samples) != MaxSamples || len(f.Evidence.Paths) != MaxSamples || len(f.Evidence.Locations) != MaxSamples || f.Evidence.Count != 30 || f.Evidence.PayloadBytes != 30 {
		t.Fatalf("bounded evidence lost full counts: %+v", f.Evidence)
	}
	p.Suppressions = []Suppression{{Rule: "IC001", Path: "/cache/29.conda", Reason: "accepted last sample"}}
	if engineEvaluate(target, p).ExitCode() != 0 {
		t.Fatal("exact selector outside rendered sample failed to match")
	}
	local := enginePolicy(t, "dir", "local", "EC001")
	target = engineTarget("dir")
	for i := 0; i < MaxFindings+1; i++ {
		target.Prefixes = append(target.Prefixes, evidence.Prefix{Path: fmt.Sprintf("/envs/%05d", i), Revision: engineInt(10)})
	}
	report = engineEvaluate(target, local)
	if len(report.Findings) != MaxFindings || report.ExitCode() != 2 || report.Status != "incomplete" {
		t.Fatalf("finding cap not enforced: count=%d status=%s exit=%d", len(report.Findings), report.Status, report.ExitCode())
	}
}

func TestQualifiedSuppressionMatchesBeyondEvidenceSamples(t *testing.T) {
	target := engineTarget("oci-archive")
	target.ID = "oci:sha256:image@linux/amd64"
	for i := 0; i < 30; i++ {
		target.Archives = append(target.Archives, evidence.Artifact{Path: fmt.Sprintf("/cache/%02d.conda", i)})
	}
	for _, tc := range []struct {
		name, selector string
		matched        bool
	}{
		{"raw", "/cache/29.conda", true},
		{"qualified", target.ID + "#/cache/29.conda", true},
		{"other image", "oci:sha256:other@linux/amd64#/cache/29.conda", false},
		{"other platform", "oci:sha256:image@linux/arm64#/cache/29.conda", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := BuildPolicy(Policy{Suppressions: []Suppression{{Rule: "IC001", Path: tc.selector, Reason: "accepted cache"}}},
				Options{Source: "oci-archive", Profile: "container-runtime", Rules: []string{"IC001"}})
			if err != nil {
				t.Fatal(err)
			}
			report := engineEvaluate(target, p)
			if len(report.Findings) != 1 {
				t.Fatalf("unexpected findings %+v", report.Findings)
			}
			f := report.Findings[0]
			if len(f.Evidence.Locations) != MaxSamples || slices.Contains(f.Evidence.Paths, "/cache/29.conda") {
				t.Fatal("regression fixture must select a path beyond the bounded evidence sample")
			}
			wantStatus, wantExit := FindingStatus, 1
			if tc.matched {
				wantStatus, wantExit = Suppressed, 0
			}
			if (f.Suppression != nil) != tc.matched || engineOutcome(t, report, "IC001").Status != wantStatus || report.ExitCode() != wantExit {
				t.Fatalf("qualified selector match=%t not honored: %+v", tc.matched, report)
			}
		})
	}
}

func TestSnapshotIsNotMutatedAndAdviceIsStatic(t *testing.T) {
	target := engineTarget("oci-archive")
	target.Archives = []evidence.Artifact{{Path: "/z.conda"}, {Path: "/a.conda"}}
	target.Tools = []evidence.Artifact{{Path: "/usr/bin/apt-get"}}
	target.Prefixes = []evidence.Prefix{{Path: "/opt/conda/envs/app"}, {Path: "/opt/conda", Tooling: true}}
	snapshot := evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}
	before, _ := json.Marshal(snapshot)
	report := Evaluate(snapshot, enginePolicy(t, "oci-archive", "container-distroless"), engineNow)
	after, _ := json.Marshal(snapshot)
	if !slices.Equal(before, after) {
		t.Fatal("pure evaluation mutated snapshot")
	}
	for _, finding := range report.Findings {
		if strings.Contains(finding.Recommendation, "rm -rf") || strings.Contains(finding.Recommendation, "--force-pkgs-dirs") {
			t.Fatal("unsafe unconditional deletion advice")
		}
		if finding.Severity == finding.Confidence {
			t.Fatal("confidence derived from severity")
		}
	}
}
