package lint

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
	gorattler "github.com/conda-incubator/go-rattler"
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

func TestReportAndPolicyVersions(t *testing.T) {
	p, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Profile: "container-runtime"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != ConfigVersion {
		t.Fatalf("BuildPolicy version = %d, want %d", p.Version, ConfigVersion)
	}
	report := engineEvaluate(engineTarget("oci-archive"), p)
	if report.SchemaVersion != SchemaVersion || report.RulesetVersion != RulesetVersion {
		t.Fatalf("report versions = %d/%q, want %d/%q", report.SchemaVersion, report.RulesetVersion, SchemaVersion, RulesetVersion)
	}
	if SchemaVersion != 4 || ConfigVersion != 1 || RulesetVersion != "3" || ProfileVersion != "2" {
		t.Fatal("wire version constants changed")
	}
}

func TestReportRecordsUTCClockSeparatelyFromSnapshotStart(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV001")
	target := engineTarget("dir")
	target.Prefixes = []evidence.Prefix{{Path: "/environment", Revision: engineInt(10)}}
	started := engineNow.Add(-48 * time.Hour)
	now := engineNow.In(time.FixedZone("evaluation", 3*60*60))
	report := Evaluate(evidence.Snapshot{Started: started, Targets: []evidence.Target{target}}, policy, now)
	if report.StartedAt != started || report.EvaluatedAt != now.UTC() || report.EvaluatedAt.Location() != time.UTC {
		t.Fatalf("report clock must identify actual evaluation time in UTC: start=%s evaluated=%s", report.StartedAt, report.EvaluatedAt)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		StartedAt   time.Time `json:"started_at"`
		EvaluatedAt time.Time `json:"evaluated_at"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.StartedAt != started || wire.EvaluatedAt != now.UTC() {
		t.Fatalf("schema4 omitted evaluation clock provenance: %s", data)
	}
}

func TestBuildPolicyPrecedenceAndSelection(t *testing.T) {
	config := Policy{Version: 1, Profile: "container-runtime", FailOn: Error, Rules: map[string]RuleOptions{
		"IMG005": {Enabled: engineBool(false), Severity: Error},
		"ENV001": {Severity: Warning, RevisionThreshold: engineInt(12)},
	}}
	p, err := BuildPolicy(config, Options{Source: "oci-archive", Profile: "container-development", FailOn: "info", Rules: []string{"IMG005", "ENV001"}, DisableRules: []string{"IMG001"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Profile != "container-development" || p.FailOn != Info || len(p.Rules) != len(registry) || p.Source != "oci-archive" {
		t.Fatalf("bad effective policy: %+v", p)
	}
	for id, options := range p.Rules {
		if options.Enabled == nil || options.Severity == "" || *options.Enabled != (id == "IMG005" || id == "ENV001") {
			t.Fatalf("bad normalized rule %s: %+v", id, options)
		}
	}
	if p.Rules["IMG005"].Severity != Error || *p.Rules["ENV001"].RevisionThreshold != 12 {
		t.Fatal("config rule overrides lost")
	}
	*p.Rules["ENV001"].RevisionThreshold = 30
	if *config.Rules["ENV001"].RevisionThreshold != 12 {
		t.Fatal("input policy mutated")
	}
	for _, tc := range []struct {
		source, profile string
		fail            Severity
	}{{"dir", "local", Warning}, {"oci-archive", "container", Warning}} {
		p := enginePolicy(t, tc.source, "")
		if p.Profile != tc.profile || p.FailOn != tc.fail {
			t.Fatalf("source defaults: %+v", p)
		}
	}
	// CLI restriction/disabling overrides an unavailable config enable before
	// collection; an effective explicit requirement still fails configuration.
	config = Policy{Rules: map[string]RuleOptions{"ENV011": {Enabled: engineBool(true)}}}
	for _, options := range []Options{{Rules: []string{"ENV001"}}, {DisableRules: []string{"ENV011"}}} {
		p, err := BuildPolicy(config, options)
		if err != nil || ruleEnabled(p, "ENV011") {
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
		{name: "unknown", options: Options{Rules: []string{"IMG099"}}},
		{name: "unknown disabled", options: Options{DisableRules: []string{"IMG099"}}},
		{name: "contradiction", options: Options{Rules: []string{"ENV001"}, DisableRules: []string{"ENV001"}}},
		{name: "source rule", options: Options{Rules: []string{"IMG001"}}},
		{name: "manifest unavailable", options: Options{Rules: []string{"ENV011"}}},
		{name: "config unavailable", config: Policy{Rules: map[string]RuleOptions{"ENV011": {Enabled: engineBool(true)}}}},
		{name: "config source rule", config: Policy{Rules: map[string]RuleOptions{"IMG001": {Enabled: engineBool(true)}}}},
		{name: "threshold", config: Policy{Rules: map[string]RuleOptions{"ENV001": {RevisionThreshold: engineInt(-1)}}}},
		{name: "option mismatch", config: Policy{Rules: map[string]RuleOptions{"IMG005": {RevisionThreshold: engineInt(10)}}}},
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

func TestBuildPolicyRuntimePrefixIsExactAndClean(t *testing.T) {
	for _, prefix := range []string{"/", "/opt/app", "/opt/app/env"} {
		p, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", RuntimePrefix: prefix})
		if err != nil {
			t.Fatalf("clean prefix %q rejected: %v", prefix, err)
		}
		if p.RuntimePrefix != prefix {
			t.Fatalf("prefix %q normalized to %q", prefix, p.RuntimePrefix)
		}
	}
	for _, prefix := range []string{
		"/opt//app", "/opt/app/", "/opt/./app", "/opt/../app", "opt/app",
		`/opt\app`, "/opt/app\n", "/opt/app\x00", "/opt/app\t", "/opt/\x7fapp",
	} {
		if _, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", RuntimePrefix: prefix}); err == nil {
			t.Fatalf("dirty runtime prefix %q accepted", prefix)
		}
	}
}

func TestBuildPolicyDoesNotMutateConfig(t *testing.T) {
	config := Policy{Version: ConfigVersion, Rules: map[string]RuleOptions{"IMG001": {Enabled: engineBool(false)}}}
	before := config.Rules["IMG001"]
	if _, err := BuildPolicy(config, Options{Source: "oci-archive", RuntimePrefix: "/opt/app"}); err != nil {
		t.Fatal(err)
	}
	if config.RuntimePrefix != "" || config.Rules["IMG001"] != before {
		t.Fatalf("input policy mutated: %+v", config)
	}
}

func TestRequirementsUnionAndDisabledCollectors(t *testing.T) {
	p := enginePolicy(t, "oci-archive", "container-runtime", "IMG001", "IMG002", "IMG003", "IMG005")
	want := []string{"cache-link-dependencies", "final-cache", "os-package-tools", "prefixes", "runtime-config", "tooling-prefix"}
	if got := Requirements(p).Capabilities; !reflect.DeepEqual(got, want) {
		t.Fatalf("requirements %v, want %v", got, want)
	}
	p, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Profile: "container-runtime", DisableRules: []string{"IMG004", "IMG003", "IMG002"}})
	if err != nil {
		t.Fatal(err)
	}
	if caps := Requirements(p).Capabilities; slices.Contains(caps, "layer-retention") || slices.Contains(caps, "runtime-config") || slices.Contains(caps, "cache-link-dependencies") {
		t.Fatalf("disabled expensive requirements collected: %v", caps)
	}
	p = enginePolicy(t, "dir", "local")
	if caps := Requirements(p).Capabilities; !slices.Contains(caps, "installed-lock") || slices.Contains(caps, "manifest-lock") {
		t.Fatalf("available installed-lock or unavailable manifest-lock requirements wrong: %v", caps)
	}
	if report := engineEvaluate(engineTarget("dir"), p); report.OutcomeCounts[Unavailable] != 1 || engineOutcome(t, report, "ENV011").Status != Unavailable {
		t.Fatal("profile did not disclose unavailable providers")
	}
	for _, rule := range ListRules() {
		if rule.Available == (rule.ID == "ENV011") || len(rule.Defaults) != 5 {
			t.Fatalf("bad rule listing: %+v", rule)
		}
	}
	listed := ListRules()
	listed[0].Capabilities[0] = "mutated"
	if ListRules()[0].Capabilities[0] == "mutated" {
		t.Fatal("listing exposes registry mutation")
	}
	p, err = BuildPolicy(Policy{}, Options{Source: "oci-archive", Rules: []string{"IMG001"}, RuntimePrefix: "/opt/app"})
	if err != nil || !slices.Contains(Requirements(p).Capabilities, "runtime-config") {
		t.Fatalf("asserted runtime input bypassed validation: %v %+v", err, Requirements(p))
	}
	p, err = BuildPolicy(Policy{}, Options{Rules: []string{"ENV001"}, Project: "/project"})
	if err != nil || !slices.Contains(Requirements(p).Capabilities, "project-association") {
		t.Fatalf("asserted project input bypassed validation: %v %+v", err, Requirements(p))
	}
}

func engineHasOutcome(report Report, rule string) bool {
	for _, outcome := range report.Outcomes {
		if outcome.RuleID == rule {
			return true
		}
	}
	return false
}

func TestInstalledLockRuleIsAvailableButNeedsSelection(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV010")
	if !slices.Contains(Requirements(policy).Capabilities, "installed-lock") || !ruleEnabled(policy, "ENV010") {
		t.Fatalf("installed-lock check not available: %+v", Requirements(policy))
	}
	for _, coverage := range []string{evidence.Complete, evidence.Partial, evidence.NotCollected} {
		t.Run(coverage, func(t *testing.T) {
			target := engineTarget("dir")
			target.Prefixes = []evidence.Prefix{{Path: "/environment", RecordCoverage: evidence.Complete}}
			target.Coverage["conda-records"] = evidence.Complete
			target.Coverage["installed-lock"] = coverage
			report := engineEvaluate(target, policy)
			if len(report.Findings) != 0 || report.OutcomeCounts[Unavailable] != 0 {
				t.Fatalf("missing selection cannot establish mismatch or provider unavailability: %+v", report)
			}
			if coverage == evidence.Complete {
				if engineHasOutcome(report, "ENV010") || report.OutcomeCounts[NotApplicable] != 1 || report.ExitCode() != 0 {
					t.Fatalf("no supported selection should be not applicable: %+v", report)
				}
			} else if outcome := engineOutcome(t, report, "ENV010"); outcome.Status != Unknown || report.ExitCode() != 2 {
				t.Fatalf("incomplete selection cannot pass: %+v exit=%d", outcome, report.ExitCode())
			}
		})
	}
}

func TestInactiveOutcomesAreCountedNotExpanded(t *testing.T) {
	p := enginePolicy(t, "dir", "local", "ENV001")
	target := engineTarget("dir")
	target.Prefixes = []evidence.Prefix{{Path: "/environment", Revision: new(0)}}
	report := engineEvaluate(target, p)
	if len(report.Outcomes) != 1 || report.Outcomes[0].RuleID != "ENV001" {
		t.Fatalf("inactive rules expanded into outcomes: %+v", report.Outcomes)
	}
	if report.OutcomeCounts[Pass] != 1 || report.OutcomeCounts[Disabled] != len(registry)-1 {
		t.Fatalf("inactive outcomes not counted: %+v", report.OutcomeCounts)
	}
	total := 0
	for _, n := range report.OutcomeCounts {
		total += n
	}
	if total != len(registry) {
		t.Fatalf("counts total %d, want %d", total, len(registry))
	}
	if len(report.OutcomeCounts) != 7 {
		t.Fatalf("summary must include all seven statuses, got %v", report.OutcomeCounts)
	}
	empty := engineEvaluate(engineTarget("dir"), p)
	if len(empty.Outcomes) != 0 || empty.OutcomeCounts[NotApplicable] != 1 || empty.OutcomeCounts[Disabled] != len(registry)-1 {
		t.Fatalf("zero-subject outcome must be counted, not expanded: %+v", empty)
	}
}

func TestRevisionBoundariesAndUnknown(t *testing.T) {
	p := enginePolicy(t, "dir", "local", "ENV001")
	for _, tc := range []struct {
		name     string
		revision *int
		status   Status
	}{
		{"zero", engineInt(0), Pass}, {"below", engineInt(9), Pass},
		{"boundary", engineInt(10), FindingStatus}, {"above", engineInt(12), FindingStatus},
		{"missing", nil, Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := engineTarget("dir")
			target.Prefixes = []evidence.Prefix{{Path: "/environment", Revision: tc.revision}}
			report := engineEvaluate(target, p)
			if outcome := engineOutcome(t, report, "ENV001"); outcome.Status != tc.status || report.ExitCode() != 0 {
				t.Fatalf("outcome=%+v exit=%d", outcome, report.ExitCode())
			}
		})
	}
	report := engineEvaluate(engineTarget("dir"), p)
	if engineHasOutcome(report, "ENV001") || report.OutcomeCounts[NotApplicable] != 1 {
		t.Fatalf("zero subjects must be not applicable: %+v", report)
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
		name, profile, rule string
		severity            Severity
		linked              bool
		coverage            string
	}{
		{"runtime archives", "container-runtime", "IMG001", Warning, false, evidence.Complete},
		{"development archives", "container-development", "IMG001", Info, false, evidence.Complete},
		{"generic archives", "container", "IMG001", Info, false, evidence.Complete},
		{"runtime extracted", "container-runtime", "IMG002", Warning, false, evidence.Complete},
		{"runtime linked", "container-runtime", "IMG002", Info, true, evidence.Complete},
		{"runtime unknown links", "container-runtime", "IMG002", Info, false, evidence.Partial},
		{"retained", "container-runtime", "IMG004", Warning, false, evidence.Complete},
		{"runtime manager", "container-runtime", "IMG005", Warning, false, evidence.Complete},
		{"distroless manager", "container-distroless", "IMG005", Error, false, evidence.Complete},
		{"development manager", "container-development", "IMG005", Info, false, evidence.Complete},
		{"generic manager", "container", "IMG005", Info, false, evidence.Complete},
		{"distroless shell", "container-distroless", "IMG006", Error, false, evidence.Complete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := enginePolicy(t, "oci-archive", tc.profile, tc.rule)
			target := engineTarget("oci-archive")
			artifact := []evidence.Artifact{{Path: "/opt/conda/pkgs/package.conda", Bytes: 50, Reference: "ref1", DiffID: "sha256:diff", BlobDigest: "sha256:blob", LayerBytes: 1000}}
			switch tc.rule {
			case "IMG001":
				target.Archives = artifact
			case "IMG002":
				target.Extracted = artifact
				target.CacheLinked = tc.linked
				target.Coverage["cache-link-dependencies"] = tc.coverage
			case "IMG004":
				target.Retained = artifact
			case "IMG005":
				target.Tools = artifact
			case "IMG006":
				target.Shells = artifact
			}
			report := engineEvaluate(target, p)
			if len(report.Findings) != 1 || report.Findings[0].Severity != tc.severity {
				t.Fatalf("findings %+v", report.Findings)
			}
			if tc.rule == "IMG004" && (report.Findings[0].Evidence.PayloadBytes != 50 || report.Findings[0].Evidence.Samples[0].LayerBytes != 1000) {
				t.Fatal("retained byte units were confused")
			}
		})
	}
	for _, profile := range []string{"container", "container-runtime", "container-development"} {
		target := engineTarget("oci-archive")
		target.Shells = []evidence.Artifact{{Path: "/bin/sh"}}
		if report := engineEvaluate(target, enginePolicy(t, "oci-archive", profile)); engineHasOutcome(report, "IMG006") || report.OutcomeCounts[Disabled] == 0 {
			t.Fatal("ordinary profiles enabled shell prohibition")
		}
	}
}

func TestToolingPrefixLayoutAndRuntimeExceptions(t *testing.T) {
	p := enginePolicy(t, "oci-archive", "container-runtime", "IMG003")
	for _, tc := range []struct {
		name     string
		prefixes []evidence.Prefix
		runtime  string
		tooling  bool
		want     Status
	}{
		{"base only", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}}, "", false, Pass},
		{"app only", []evidence.Prefix{{Path: "/opt/app"}}, "", false, Pass},
		{"name not evidence", []evidence.Prefix{{Path: "/base"}, {Path: "/base/envs/app"}}, "", false, Pass},
		{"unrelated", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/unrelated"}}, "", false, Pass},
		{"nested", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}, "", false, FindingStatus},
		{"declared app", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/app"}}, "/opt/app", false, FindingStatus},
		{"uses tooling", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}, "", true, Pass},
		{"runtime in base", []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}, "/opt/conda", false, Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := engineTarget("oci-archive")
			target.Prefixes, target.RuntimePrefix, target.RuntimeUsesTooling = tc.prefixes, tc.runtime, tc.tooling
			report := engineEvaluate(target, p)
			if engineOutcome(t, report, "IMG003").Status != tc.want {
				t.Fatalf("unexpected outcome %+v", report.Outcomes)
			}
			if len(report.Findings) > 0 && report.Findings[0].Severity != Info {
				t.Fatal("layout candidate promoted to runtime defect")
			}
			if tc.want == Pass && len(report.Findings) != 0 {
				t.Fatal("valid runtime tooling produced a finding")
			}
		})
	}
}

func TestProjectAssociationNeverGuessesLockMismatch(t *testing.T) {
	p := enginePolicy(t, "dir", "local", "ENV002")
	for _, tc := range []struct {
		project *evidence.Project
		status  Status
	}{
		{nil, NotApplicable}, {&evidence.Project{Path: "/project"}, NotApplicable},
		{&evidence.Project{Path: "/project", Associated: true}, FindingStatus},
		{&evidence.Project{Path: "/project", Associated: true, LockPath: "/project/pixi.lock"}, Pass},
	} {
		target := engineTarget("dir")
		target.Project = tc.project
		report := engineEvaluate(target, p)
		if tc.status == NotApplicable {
			if engineHasOutcome(report, "ENV002") || report.OutcomeCounts[NotApplicable] != 1 || report.ExitCode() != 0 {
				t.Fatalf("absent project must be counted, not expanded: %+v", report)
			}
			continue
		}
		if outcome := engineOutcome(t, report, "ENV002"); outcome.Status != tc.status || report.ExitCode() != 0 {
			t.Fatalf("project %+v outcome %+v exit %d", tc.project, outcome, report.ExitCode())
		}
	}
}

func TestPolicySeverityOverridesConservativeDefaults(t *testing.T) {
	for _, rule := range []string{"IMG003", "ENV002"} {
		for _, severity := range []Severity{"", Error} {
			t.Run(rule+"/"+string(severity), func(t *testing.T) {
				source, profile := "oci-archive", "container-runtime"
				target := engineTarget(source)
				target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}
				if rule == "ENV002" {
					source, profile = "dir", "local"
					target = engineTarget(source)
					target.Project = &evidence.Project{Path: "/project", Associated: true}
				}
				p, err := BuildPolicy(Policy{Rules: map[string]RuleOptions{rule: {Severity: severity}}},
					Options{Source: source, Profile: profile, Rules: []string{rule}, FailOn: "error"})
				if err != nil {
					t.Fatal(err)
				}
				wantSeverity, wantExit := Info, 0
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
	for _, coverage := range []string{evidence.Complete, evidence.Partial, evidence.NotCollected} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", coverage, nested), func(t *testing.T) {
				target := engineTarget("oci-archive")
				app := "/app"
				if nested {
					app = "/opt/conda/envs/app"
				}
				target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: app}}
				target.Coverage["runtime-config"] = coverage
				report := engineEvaluate(target, enginePolicy(t, "oci-archive", "container-runtime", "IMG003"))
				wantStatus, wantExit := Pass, 0
				if coverage != evidence.Complete {
					wantStatus, wantExit = Unknown, 2
				}
				if nested {
					wantStatus = FindingStatus
				}
				if outcome := engineOutcome(t, report, "IMG003"); outcome.Status != wantStatus || report.ExitCode() != wantExit {
					t.Fatalf("runtime-dependent outcome %+v exit=%d, want %s/%d", outcome, report.ExitCode(), wantStatus, wantExit)
				}
			})
		}
	}
}

func TestCoverageAndExitPrecedence(t *testing.T) {
	target := engineTarget("oci-archive")
	p := enginePolicy(t, "oci-archive", "container-runtime", "IMG001")
	target.Coverage["final-cache"] = evidence.Partial
	report := engineEvaluate(target, p)
	if engineOutcome(t, report, "IMG001").Status != Unknown || report.Status != "incomplete" || report.ExitCode() != 2 {
		t.Fatal("partial absence passed inspection")
	}
	target.Archives = []evidence.Artifact{{Path: "/cache/pkg.conda"}}
	report = engineEvaluate(target, p)
	if len(report.Findings) != 1 || report.Findings[0].Severity != Warning || report.ExitCode() != 2 {
		t.Fatal("positive partial facts discarded or inspection failure did not win")
	}
	p.FailOn = NoFailure
	if engineEvaluate(target, p).ExitCode() != 2 {
		t.Fatal("fail-on none masked inspection error")
	}
	target.Coverage["final-cache"] = evidence.Complete
	for _, tc := range []struct {
		threshold Severity
		code      int
	}{{NoFailure, 0}, {Error, 0}, {Warning, 1}, {Info, 1}} {
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
	base := enginePolicy(t, "oci-archive", "container-runtime", "IMG001")
	fingerprint := engineEvaluate(target, base).Findings[0].Fingerprint
	for _, selector := range []Suppression{
		{Target: target.ID}, {Path: "/cache/pkg.conda"}, {Fingerprint: fingerprint}, {Fingerprint: strings.ToUpper(fingerprint)},
		{Target: target.ID, Path: "/cache/pkg.conda", Fingerprint: fingerprint},
	} {
		selector.Rule, selector.Reason, selector.Expires = "IMG001", "reviewed accepted cache", "2026-10-21"
		p, err := BuildPolicy(Policy{Suppressions: []Suppression{selector}}, Options{Source: "oci-archive", Profile: "container-runtime", Rules: []string{"IMG001"}})
		if err != nil {
			t.Fatal(err)
		}
		report := engineEvaluate(target, p)
		if report.ExitCode() != 0 || report.Findings[0].Suppression == nil || engineOutcome(t, report, "IMG001").Status != Suppressed {
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
			p, err := BuildPolicy(Policy{Suppressions: []Suppression{{Rule: "IMG001", Path: tc.path, Expires: tc.expires, Reason: "accepted"}}}, Options{Source: "oci-archive", Profile: tc.profile, Rules: []string{"IMG001"}})
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
	p, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Rules: []string{"IMG001"}, RuntimePrefix: "/opt/app"})
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
	p, err = BuildPolicy(Policy{}, Options{Rules: []string{"ENV001"}, Project: "/project"})
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
	p := enginePolicy(t, "oci-archive", "container-runtime", "IMG001", "IMG004")
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
	p.Rules["IMG001"] = RuleOptions{Enabled: engineBool(true), Severity: Error}
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
	p := enginePolicy(t, "oci-archive", "container-runtime", "IMG001")
	target := engineTarget("oci-archive")
	for i := 0; i < 30; i++ {
		target.Archives = append(target.Archives, evidence.Artifact{Path: fmt.Sprintf("/cache/%02d.conda", i), Bytes: 1})
	}
	report := engineEvaluate(target, p)
	f := report.Findings[0]
	if len(f.Evidence.Samples) != MaxSamples || len(f.Evidence.Paths) != MaxSamples || len(f.Evidence.Locations) != MaxSamples || f.Evidence.Count != 30 || f.Evidence.PayloadBytes != 30 {
		t.Fatalf("bounded evidence lost full counts: %+v", f.Evidence)
	}
	p.Suppressions = []Suppression{{Rule: "IMG001", Path: "/cache/29.conda", Reason: "accepted last sample"}}
	if engineEvaluate(target, p).ExitCode() != 0 {
		t.Fatal("exact selector outside rendered sample failed to match")
	}
	local := enginePolicy(t, "dir", "local", "ENV001")
	target = engineTarget("dir")
	for i := 0; i < MaxFindings+1; i++ {
		target.Prefixes = append(target.Prefixes, evidence.Prefix{Path: fmt.Sprintf("/envs/%05d", i), Revision: engineInt(10)})
	}
	report = engineEvaluate(target, local)
	if len(report.Findings) != MaxFindings || report.ExitCode() != 2 || report.Status != "incomplete" {
		t.Fatalf("finding cap not enforced: count=%d status=%s exit=%d", len(report.Findings), report.Status, report.ExitCode())
	}
	paths := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		paths = append(paths, finding.Evidence.Paths[0])
	}
	slices.Sort(paths)
	if paths[0] != "/envs/00000" || paths[len(paths)-1] != fmt.Sprintf("/envs/%05d", MaxFindings-1) {
		t.Fatalf("truncation changed the original emission-order selection: %s .. %s", paths[0], paths[len(paths)-1])
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
			p, err := BuildPolicy(Policy{Suppressions: []Suppression{{Rule: "IMG001", Path: tc.selector, Reason: "accepted cache"}}},
				Options{Source: "oci-archive", Profile: "container-runtime", Rules: []string{"IMG001"}})
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
			if (f.Suppression != nil) != tc.matched || engineOutcome(t, report, "IMG001").Status != wantStatus || report.ExitCode() != wantExit {
				t.Fatalf("qualified selector match=%t not honored: %+v", tc.matched, report)
			}
		})
	}
}

func TestImageDisplayPathsPreserveRawAndQualifiedSuppressions(t *testing.T) {
	target := engineTarget("oci-archive")
	target.ID = "oci:sha256:image@linux/amd64"
	target.Archives = []evidence.Artifact{{Path: "opt/conda/pkgs/python-3.13-build_0.conda", Reference: "raw-ref"}}
	base := enginePolicy(t, "oci-archive", "container-runtime", "IMG001")
	finding := engineEvaluate(target, base).Findings[0]
	if !slices.Equal(finding.Evidence.Paths, []string{"/opt/conda/pkgs/python-3.13-build_0.conda"}) || !slices.Equal(finding.paths, []string{target.Archives[0].Path}) || finding.Evidence.Samples[0].Path != target.Archives[0].Path {
		t.Fatalf("display path normalization changed raw artifact identity: %+v", finding)
	}
	for _, selector := range []string{target.Archives[0].Path, location(target, target.Archives[0].Path), finding.Evidence.Paths[0], finding.Evidence.Locations[0]} {
		t.Run(selector, func(t *testing.T) {
			policy := base
			policy.Suppressions = []Suppression{{Rule: "IMG001", Path: selector, Reason: "accepted raw image cache path"}}
			report := engineEvaluate(target, policy)
			if len(report.Findings) != 1 || report.Findings[0].Suppression == nil || engineOutcome(t, report, "IMG001").Status != Suppressed || report.ExitCode() != 0 {
				t.Fatalf("raw or displayed source-qualified selector no longer matches after display normalization: %+v", report)
			}
		})
	}
	for i := range MaxSamples + 3 {
		target.Archives = append(target.Archives, evidence.Artifact{Path: fmt.Sprintf("opt/conda/pkgs/zz-%02d.conda", i)})
	}
	last := target.Archives[len(target.Archives)-1].Path
	report := engineEvaluate(target, base)
	if slices.Contains(report.Findings[0].Evidence.Paths, "/"+last) || len(report.Findings[0].Evidence.Paths) != MaxSamples {
		t.Fatal("alias regression must use a path beyond displayed samples")
	}
	for _, selector := range []string{"/" + last, location(target, "/"+last)} {
		policy := base
		policy.Suppressions = []Suppression{{Rule: "IMG001", Path: selector, Reason: "accepted cache path beyond display limit"}}
		report := engineEvaluate(target, policy)
		if len(report.Findings) != 1 || report.Findings[0].Suppression == nil || engineOutcome(t, report, "IMG001").Status != Suppressed || report.ExitCode() != 0 {
			t.Errorf("normalized alias beyond samples did not suppress: %q %+v", selector, report.SuppressionNotes)
		}
	}
}

func TestSnapshotIsNotMutatedAndAdviceIsStatic(t *testing.T) {
	target := engineTarget("oci-archive")
	target.Archives = []evidence.Artifact{{Path: "/z.conda"}, {Path: "/a.conda"}}
	target.Tools = []evidence.Artifact{{Path: "/usr/bin/apt-get"}}
	target.Prefixes = []evidence.Prefix{{Path: "/opt/conda/envs/app"}, {Path: "/opt/conda", Tooling: true}}
	snapshot := evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}
	before, _ := json.Marshal(snapshot)
	report := Evaluate(snapshot, enginePolicy(t, "oci-archive", "container-distroless", "IMG001", "IMG002", "IMG003", "IMG004", "IMG005", "IMG006"), engineNow)
	after, _ := json.Marshal(snapshot)
	if !slices.Equal(before, after) {
		t.Fatal("pure evaluation mutated snapshot")
	}
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message, "rm -rf") || strings.Contains(finding.Message, "--force-pkgs-dirs") {
			t.Fatal("unsafe unconditional deletion advice")
		}
	}
}

func TestReportDoesNotSerializeCanonicalRecordCredentials(t *testing.T) {
	target := engineTarget("dir")
	target.Prefixes = []evidence.Prefix{{Path: "/environment", Revision: engineInt(10), Records: []inventory.CondaRecord{{
		Path: "/environment/conda-meta/python.json",
		Record: gorattler.PrefixRecord{
			PackageRecord: gorattler.PackageRecord{Name: "python", Version: "3.13", Build: "build_0"},
			Channel:       "https://user:RECORD_PASSWORD@conda.example/private?token=RECORD_TOKEN",
			URL:           "https://user:RECORD_PASSWORD@conda.example/private/python.conda?token=RECORD_TOKEN",
		},
	}}}}
	rawURL := target.Prefixes[0].Records[0].Record.URL
	snapshot := evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{target}}
	report := Evaluate(snapshot, enginePolicy(t, "dir", "local", "ENV001"), engineNow)
	if len(report.Findings) != 1 {
		t.Fatalf("credential fixture must still produce the selected history observation: %+v", report)
	}
	for _, value := range []any{snapshot, report} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "RECORD_PASSWORD") || strings.Contains(string(data), "RECORD_TOKEN") {
			t.Errorf("internal canonical record credentials leaked into JSON: %s", data)
		}
	}
	if snapshot.Targets[0].Prefixes[0].Records[0].Record.URL != rawURL {
		t.Fatal("credential omission must not mutate retained canonical facts")
	}
}

func TestEvaluateSuppliesCrossTargetPeersAndAsOfWithoutMutation(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV001")
	makeSnapshot := func() evidence.Snapshot {
		left, right := engineTarget("dir"), engineTarget("dir")
		left.ID, right.ID = "file:///left", "file:///right"
		left.Prefixes = []evidence.Prefix{{Path: "/left", Revision: engineInt(10)}}
		right.Prefixes = []evidence.Prefix{{Path: "/right/b", Revision: engineInt(11)}, {Path: "/right/a", Revision: engineInt(12)}}
		left.AsOf, right.AsOf = engineNow.Add(-time.Hour), engineNow.Add(time.Hour)
		left.Peers, right.Peers = []evidence.Prefix{{Path: "/stale/left"}}, []evidence.Prefix{{Path: "/stale/right"}}
		return evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{right, left}}
	}
	snapshot, before := makeSnapshot(), makeSnapshot()
	index := ruleIndex["ENV001"]
	original := registry[index]
	t.Cleanup(func() { registry[index] = original })
	calls := 0
	registry[index].Check = func(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
		calls++
		if !target.AsOf.Equal(engineNow) {
			t.Errorf("callback clock = %s, want explicit evaluation time %s", target.AsOf, engineNow)
		}
		paths := make([]string, 0, len(target.Peers))
		for _, peer := range target.Peers {
			paths = append(paths, peer.Path)
		}
		slices.Sort(paths)
		if !slices.Equal(paths, []string{"/left", "/right/a", "/right/b"}) {
			t.Errorf("callback missing cross-target peers or retained stale peers: %v", paths)
		}
		return original.Check(target, opts, rule)
	}
	first := Evaluate(snapshot, policy, engineNow)
	if !reflect.DeepEqual(snapshot, before) {
		t.Fatal("evaluation changed original snapshot, including nonserialized clock/peers")
	}
	reordered := makeSnapshot()
	slices.Reverse(reordered.Targets)
	slices.Reverse(reordered.Targets[1].Prefixes)
	second := Evaluate(reordered, policy, engineNow)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 4 || !slices.Equal(firstJSON, secondJSON) {
		t.Fatalf("clock/peers evaluation is not deterministic: calls=%d\n%s\n%s", calls, firstJSON, secondJSON)
	}
}
