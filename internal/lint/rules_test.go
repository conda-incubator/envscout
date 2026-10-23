package lint

import (
	"slices"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/evidence"
)

func intPtr(v int) *int { return &v }

// testPolicy enables exactly the named rule, with its default severity and threshold.
func testPolicy(t *testing.T, id string, profile string) Policy {
	t.Helper()
	rule, ok := LookupRule(id)
	if !ok {
		t.Fatalf("missing rule %s", id)
	}
	d := rule.Defaults[profile]
	enabled := true
	opts := RuleOptions{Enabled: &enabled, Severity: d.Severity}
	if d.RevisionThreshold != nil {
		opts.RevisionThreshold = intPtr(*d.RevisionThreshold)
	}
	return Policy{Rules: map[string]RuleOptions{id: opts}}
}

func completeTarget(kind string) evidence.Target {
	coverage := map[string]string{}
	for _, c := range []string{"prefixes", "history", "project-association", "final-cache",
		"cache-link-dependencies", "layer-retention", "os-package-tools", "shell-tools",
		"tooling-prefix", "runtime-config"} {
		coverage[c] = evidence.Complete
	}
	return evidence.Target{ID: "t", Kind: kind, Coverage: coverage}
}

func TestRegistryInvariants(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range ListRules() {
		if seen[rule.ID] {
			t.Fatalf("duplicate rule ID %s", rule.ID)
		}
		seen[rule.ID] = true
		if len(rule.Defaults) != len(profiles) {
			t.Errorf("%s has %d profile defaults, want %d", rule.ID, len(rule.Defaults), len(profiles))
		}
		for _, profile := range profiles {
			d, ok := rule.Defaults[profile]
			if !ok || !d.Severity.Valid() {
				t.Errorf("%s/%s has invalid default %+v", rule.ID, profile, d)
			}
			if d.RevisionThreshold != nil && !rule.SupportsRevisionThreshold {
				t.Errorf("%s has a threshold default but does not support one", rule.ID)
			}
		}
		if rule.Available && rule.Check == nil {
			t.Errorf("%s is available without a Check", rule.ID)
		}
		if !rule.Available && rule.UnavailableReason == "" {
			t.Errorf("%s is unavailable without a reason", rule.ID)
		}
	}
	if len(seen) != len(registry) {
		t.Fatalf("ListRules returned %d rules for %d registry entries", len(seen), len(registry))
	}
	if _, ok := LookupRule("IC005"); ok {
		t.Fatal("IC005 must be absent")
	}
}

func TestSupportsRevisionThresholdOnlyEC001(t *testing.T) {
	for _, rule := range ListRules() {
		if rule.SupportsRevisionThreshold != (rule.ID == "EC001") {
			t.Errorf("%s SupportsRevisionThreshold = %v", rule.ID, rule.SupportsRevisionThreshold)
		}
	}
}

func TestEC001ThresholdDefaultAndOverride(t *testing.T) {
	rule, _ := LookupRule("EC001")
	if d := rule.Defaults["local"]; d.RevisionThreshold == nil || *d.RevisionThreshold != 10 {
		t.Fatalf("EC001 default threshold = %+v, want 10", d.RevisionThreshold)
	}
	target := completeTarget("dir")
	target.Prefixes = []evidence.Prefix{{Path: "/env", Revision: intPtr(12)}}
	policy := testPolicy(t, "EC001", "local")
	outcome, findings := evaluateRule(target, policy, mustRule(t, "EC001"))
	if len(findings) != 1 || findings[0].Evidence.RevisionThreshold == nil || *findings[0].Evidence.RevisionThreshold != 10 {
		t.Fatalf("default threshold 10: findings=%+v outcome=%+v", findings, outcome)
	}
	policy.Rules["EC001"] = RuleOptions{Enabled: policy.Rules["EC001"].Enabled, Severity: Info, RevisionThreshold: intPtr(12)}
	_, findings = evaluateRule(target, policy, mustRule(t, "EC001"))
	if len(findings) != 1 || *findings[0].Evidence.RevisionThreshold != 12 {
		t.Fatalf("override threshold 12: findings=%+v", findings)
	}
}

func mustRule(t *testing.T, id string) Rule {
	t.Helper()
	rule, ok := LookupRule(id)
	if !ok {
		t.Fatalf("missing %s", id)
	}
	return rule
}

func TestEC001PositiveNegativeUnknown(t *testing.T) {
	rule := mustRule(t, "EC001")
	policy := testPolicy(t, "EC001", "local")

	positive := completeTarget("dir")
	positive.Prefixes = []evidence.Prefix{{Path: "/env", Revision: intPtr(10)}}
	if outcome, findings := evaluateRule(positive, policy, rule); outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("positive: status=%s findings=%d", outcome.Status, len(findings))
	}

	negative := completeTarget("dir")
	negative.Prefixes = []evidence.Prefix{{Path: "/env", Revision: intPtr(9)}}
	if outcome, findings := evaluateRule(negative, policy, rule); outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("negative: status=%s findings=%d", outcome.Status, len(findings))
	}

	unknown := completeTarget("dir")
	unknown.Prefixes = []evidence.Prefix{{Path: "/env", Revision: nil}}
	if outcome, _ := evaluateRule(unknown, policy, rule); outcome.Status != Unknown {
		t.Fatalf("missing revision must be unknown, got %s", outcome.Status)
	}

	empty := completeTarget("dir")
	if outcome, _ := evaluateRule(empty, policy, rule); outcome.Status != NotApplicable {
		t.Fatalf("zero subjects with complete coverage must be not_applicable, got %s", outcome.Status)
	}
}

func TestEC004PositiveNegativeUnknown(t *testing.T) {
	rule := mustRule(t, "EC004")
	policy := testPolicy(t, "EC004", "local")

	positive := completeTarget("dir")
	positive.Project = &evidence.Project{Path: "/proj", Associated: true}
	if outcome, findings := evaluateRule(positive, policy, rule); outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("positive: status=%s", outcome.Status)
	}

	verified := completeTarget("dir")
	verified.Project = &evidence.Project{Path: "/proj", Associated: true, LockPath: "p.lock", LockVerified: true}
	if outcome, findings := evaluateRule(verified, policy, rule); outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("verified lock must pass, got %s", outcome.Status)
	}

	unverified := completeTarget("dir")
	unverified.Project = &evidence.Project{Path: "/proj", Associated: true, LockPath: "p.lock"}
	if outcome, _ := evaluateRule(unverified, policy, rule); outcome.Status != Unknown {
		t.Fatalf("unverified existing lock must be unknown, got %s", outcome.Status)
	}

	unassociated := completeTarget("dir")
	if outcome, _ := evaluateRule(unassociated, policy, rule); outcome.Status != Unknown {
		t.Fatalf("no association must be unknown, got %s", outcome.Status)
	}
}

func artifactTarget(kind string, field func(*evidence.Target, []evidence.Artifact), artifacts []evidence.Artifact) evidence.Target {
	target := completeTarget(kind)
	field(&target, artifacts)
	return target
}

func TestArtifactRulesPositiveNegativeUnknown(t *testing.T) {
	fields := map[string]struct {
		field func(*evidence.Target, []evidence.Artifact)
		cap   string
	}{
		"IC001": {func(t *evidence.Target, a []evidence.Artifact) { t.Archives = a }, "final-cache"},
		"IC002": {func(t *evidence.Target, a []evidence.Artifact) { t.Extracted = a }, "final-cache"},
		"IC004": {func(t *evidence.Target, a []evidence.Artifact) { t.Retained = a }, "layer-retention"},
		"IC006": {func(t *evidence.Target, a []evidence.Artifact) { t.Tools = a }, "os-package-tools"},
		"IC007": {func(t *evidence.Target, a []evidence.Artifact) { t.Shells = a }, "shell-tools"},
	}
	artifact := []evidence.Artifact{{Path: "/opt/x", Kind: "file", Bytes: 7, Layer: 1}}
	for id, spec := range fields {
		rule := mustRule(t, id)
		policy := testPolicy(t, id, "container-distroless")

		positive := artifactTarget("oci-archive", spec.field, artifact)
		outcome, findings := evaluateRule(positive, policy, rule)
		if outcome.Status != FindingStatus || len(findings) != 1 || findings[0].Evidence.Count != 1 {
			t.Errorf("%s positive: status=%s findings=%d", id, outcome.Status, len(findings))
		}
		if len(findings) == 1 && (findings[0].Message == "" || findings[0].Fingerprint == "") {
			t.Errorf("%s positive finding lacks message or fingerprint", id)
		}

		negative := artifactTarget("oci-archive", spec.field, nil)
		if outcome, findings := evaluateRule(negative, policy, rule); outcome.Status != Pass || len(findings) != 0 {
			t.Errorf("%s complete negative: status=%s findings=%d", id, outcome.Status, len(findings))
		}

		unknown := artifactTarget("oci-archive", spec.field, nil)
		delete(unknown.Coverage, spec.cap)
		if outcome, _ := evaluateRule(unknown, policy, rule); outcome.Status != Unknown {
			t.Errorf("%s incomplete coverage must be unknown, got %s", id, outcome.Status)
		}
	}
}

func TestIC004ByteUnitAndNoSummedSavings(t *testing.T) {
	rule := mustRule(t, "IC004")
	policy := testPolicy(t, "IC004", "container-runtime")
	target := artifactTarget("oci-archive", func(t *evidence.Target, a []evidence.Artifact) { t.Retained = a },
		[]evidence.Artifact{{Path: "/a", Bytes: 3, LayerBytes: 100, Layer: 1}, {Path: "/b", Bytes: 4, LayerBytes: 100, Layer: 1}})
	_, findings := evaluateRule(target, policy, rule)
	if len(findings) != 1 || findings[0].Evidence.PayloadBytes != 7 || !strings.Contains(findings[0].Evidence.ByteUnit, "retained logical payload") {
		t.Fatalf("IC004 byte evidence wrong: %+v", findings)
	}
}

func TestIC002SeverityDowngradesWhenLinkageUnsafe(t *testing.T) {
	rule := mustRule(t, "IC002")
	policy := testPolicy(t, "IC002", "container-runtime")
	target := artifactTarget("oci-archive", func(t *evidence.Target, a []evidence.Artifact) { t.Extracted = a },
		[]evidence.Artifact{{Path: "/c", Kind: "dir"}})
	target.CacheLinked = true
	_, findings := evaluateRule(target, policy, rule)
	if len(findings) != 1 || findings[0].Severity != Info || len(findings[0].Evidence.Notes) == 0 {
		t.Fatalf("cache-linked IC002 must be info with a note: %+v", findings)
	}
}

func TestIC003PrefixRolesPositiveNegativeUnknown(t *testing.T) {
	rule := mustRule(t, "IC003")
	policy := testPolicy(t, "IC003", "container")

	positive := completeTarget("oci-archive")
	positive.RuntimePrefix = "/app"
	positive.Prefixes = []evidence.Prefix{{Path: "/opt/tool", Tooling: true}, {Path: "/app"}}
	if outcome, findings := evaluateRule(positive, policy, rule); outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("positive IC003 status=%s findings=%d", outcome.Status, len(findings))
	}

	negative := completeTarget("oci-archive")
	negative.Prefixes = []evidence.Prefix{{Path: "/app"}}
	if outcome, findings := evaluateRule(negative, policy, rule); outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("negative IC003 status=%s findings=%d", outcome.Status, len(findings))
	}

	unknown := completeTarget("oci-archive")
	delete(unknown.Coverage, "runtime-config")
	unknown.Prefixes = []evidence.Prefix{{Path: "/opt/tool", Tooling: true}}
	if outcome, _ := evaluateRule(unknown, policy, rule); outcome.Status != Unknown {
		t.Fatalf("incomplete runtime config must be unknown, got %s", outcome.Status)
	}
}

func TestUnavailableRulesNeverRunCheck(t *testing.T) {
	for _, id := range []string{"EC002", "EC003"} {
		rule := mustRule(t, id)
		if rule.Available || rule.Check != nil || rule.UnavailableReason == "" {
			t.Fatalf("%s must be unavailable with no Check", id)
		}
		policy := Policy{Rules: map[string]RuleOptions{id: {Enabled: boolPtr(true), Severity: Warning}}}
		outcome, findings := evaluateRule(completeTarget("dir"), policy, rule)
		if outcome.Status != Unavailable || len(findings) != 0 || outcome.Reason == "" {
			t.Fatalf("%s: status=%s findings=%d", id, outcome.Status, len(findings))
		}
	}
}

func boolPtr(v bool) *bool { return &v }

func TestDisabledAndInapplicableGating(t *testing.T) {
	rule := mustRule(t, "IC001")
	disabled := Policy{Rules: map[string]RuleOptions{"IC001": {Enabled: boolPtr(false), Severity: Info}}}
	if outcome, _ := evaluateRule(completeTarget("oci-archive"), disabled, rule); outcome.Status != Disabled {
		t.Fatalf("disabled must be disabled, got %s", outcome.Status)
	}
	enabled := testPolicy(t, "IC001", "container")
	if outcome, _ := evaluateRule(completeTarget("dir"), enabled, rule); outcome.Status != NotApplicable {
		t.Fatalf("dir source for IC001 must be not_applicable, got %s", outcome.Status)
	}
}

func TestFindingFingerprintIsOrderIndependent(t *testing.T) {
	rule := mustRule(t, "IC001")
	target := completeTarget("oci-archive")
	a := []evidence.Artifact{{Path: "/x", Kind: "f", Reference: "r", DiffID: "d", BlobDigest: "b", Layer: 2, Bytes: 1}, {Path: "/a", Kind: "f", Layer: 1}}
	b := []evidence.Artifact{a[1], a[0]}
	f1 := newFinding(target, rule, Warning, nil, a)
	f2 := newFinding(target, rule, Warning, nil, b)
	if f1.Fingerprint != f2.Fingerprint || f1.Evidence.Count != 2 || f1.Evidence.PayloadBytes != 1 {
		t.Fatalf("fingerprint/order mismatch: %s vs %s", f1.Fingerprint, f2.Fingerprint)
	}
	if !slices.Equal(f1.paths, []string{"/a", "/x"}) {
		t.Fatalf("paths not sorted: %v", f1.paths)
	}
}

func TestSampleLimitAndByteSaturation(t *testing.T) {
	rule := mustRule(t, "IC001")
	target := completeTarget("oci-archive")
	var many []evidence.Artifact
	for i := 0; i < MaxSamples+5; i++ {
		many = append(many, evidence.Artifact{Path: "/p" + string(rune('a'+i%26)) + strings.Repeat("x", i), Layer: i})
	}
	f := newFinding(target, rule, Info, nil, many)
	if len(f.Evidence.Samples) != MaxSamples || f.Evidence.Count != MaxSamples+5 {
		t.Fatalf("samples=%d count=%d", len(f.Evidence.Samples), f.Evidence.Count)
	}
	big := []evidence.Artifact{{Path: "/a", Layer: 1, Bytes: 1<<62 + 1}, {Path: "/b", Layer: 2, Bytes: 1<<62 + 1}}
	if got := newFinding(target, rule, Info, nil, big).Evidence.PayloadBytes; got != 1<<63-1 {
		t.Fatalf("payload bytes must saturate, got %d", got)
	}
}

// testOnlyRule demonstrates that the generic evaluator dispatches to a new
// rule's Check without any change to evaluateRule or a rule-ID switch.
func TestExtensibleRuleDispatchesThroughGenericEvaluator(t *testing.T) {
	called := false
	extra := Rule{
		ID: "TST001", Version: "1", Name: "test", Available: true,
		TargetKinds: []string{"dir"}, Defaults: profileDefaults(localOnly, nil, nil),
		Check: func(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
			called = true
			f := newFinding(target, rule, Severity(opts.Severity), []string{"/only"}, nil)
			f.Message = "test rule"
			return Outcome{SubjectCount: 1}, []Finding{f}
		},
	}
	policy := Policy{Rules: map[string]RuleOptions{"TST001": {Enabled: boolPtr(true), Severity: Warning}}}
	outcome, findings := evaluateRule(completeTarget("dir"), policy, extra)
	if !called || outcome.Status != FindingStatus || len(findings) != 1 || findings[0].RuleID != "TST001" {
		t.Fatalf("generic dispatch failed: called=%v status=%s", called, outcome.Status)
	}
	if _, ok := LookupRule("TST001"); ok {
		t.Fatal("test-only rule must not leak into the registry")
	}
}
