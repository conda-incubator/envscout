package lint

import (
	"fmt"
	"os/exec"
	"runtime"
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
	available := 0
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
		if rule.Available {
			available++
		}
		if !rule.Available && rule.UnavailableReason == "" {
			t.Errorf("%s is unavailable without a reason", rule.ID)
		}
	}
	if len(seen) != len(registry) {
		t.Fatalf("ListRules returned %d rules for %d registry entries", len(seen), len(registry))
	}
	if len(seen) != 18 || available != 17 {
		t.Fatalf("Phase4 registry has %d total/%d available rules, want 18/17", len(seen), available)
	}
	for _, group := range []struct {
		prefix string
		count  int
	}{{"ENV", 12}, {"IMG", 6}} {
		for i := 1; i <= group.count; i++ {
			if !seen[fmt.Sprintf("%s%03d", group.prefix, i)] {
				t.Errorf("missing contiguous Phase4 rule %s%03d", group.prefix, i)
			}
		}
	}
	for _, id := range []string{"EC001", "EC002", "EC003", "EC004", "IC001", "IC002", "IC003", "IC004", "IC005", "IC006", "IC007"} {
		if _, ok := LookupRule(id); ok {
			t.Errorf("legacy or removed rule %s must not be registered", id)
		}
	}
}

func TestSupportsRevisionThresholdOnlyENV001(t *testing.T) {
	for _, rule := range ListRules() {
		if rule.SupportsRevisionThreshold != (rule.ID == "ENV001") {
			t.Errorf("%s SupportsRevisionThreshold = %v", rule.ID, rule.SupportsRevisionThreshold)
		}
	}
}

func TestENV001ThresholdDefaultAndOverride(t *testing.T) {
	rule := mustRule(t, "ENV001")
	if d := rule.Defaults["local"]; d.RevisionThreshold == nil || *d.RevisionThreshold != 10 {
		t.Fatalf("ENV001 default threshold = %+v, want 10", d.RevisionThreshold)
	}
	target := completeTarget("dir")
	target.Prefixes = []evidence.Prefix{{Path: "/env", Revision: intPtr(12)}}
	policy := testPolicy(t, "ENV001", "local")
	outcome, findings := evaluateRule(target, policy, rule)
	if len(findings) != 1 || findings[0].Evidence.RevisionThreshold == nil || *findings[0].Evidence.RevisionThreshold != 10 {
		t.Fatalf("default threshold 10: findings=%+v outcome=%+v", findings, outcome)
	}
	policy.Rules["ENV001"] = RuleOptions{Enabled: policy.Rules["ENV001"].Enabled, Severity: Info, RevisionThreshold: intPtr(12)}
	_, findings = evaluateRule(target, policy, rule)
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

func TestENV001PositiveNegativeUnknown(t *testing.T) {
	rule := mustRule(t, "ENV001")
	policy := testPolicy(t, "ENV001", "local")

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

func TestPhase4HistoryTransactionCountKeepsRevisionThreshold(t *testing.T) {
	rule := mustRule(t, "ENV001")
	policy := testPolicy(t, rule.ID, "local")
	if !strings.Contains(strings.Join(rule.Exceptions, " "), "does not prove drift") {
		t.Error("catalogue must distinguish transaction history from proven drift")
	}
	for _, revision := range []int{9, 10, 13} {
		t.Run(fmt.Sprint(revision), func(t *testing.T) {
			target := completeTarget("dir")
			target.Prefixes = []evidence.Prefix{{Path: "/env", Revision: intPtr(revision)}}
			outcome, findings := evaluateRule(target, policy, rule)
			if revision < 10 {
				if outcome.Status != Pass || len(findings) != 0 {
					t.Fatalf("revision below threshold became a finding: %+v %+v", outcome, findings)
				}
				return
			}
			if outcome.Status != FindingStatus || len(findings) != 1 {
				t.Fatalf("revision at or above threshold: %+v %+v", outcome, findings)
			}
			finding := findings[0]
			count := fmt.Sprintf("%d recorded conda transactions", revision+1)
			if !strings.Contains(finding.Message, "/env") || !strings.Contains(finding.Message, count) {
				t.Errorf("zero-based revision %d must display transactions and path: %q", revision, finding.Message)
			}
			if finding.Evidence.Revision == nil || *finding.Evidence.Revision != revision || finding.Evidence.RevisionThreshold == nil || *finding.Evidence.RevisionThreshold != 10 {
				t.Errorf("display count changed revision evidence: %+v", finding.Evidence)
			}
			for _, guarantee := range []string{"environments drift", "environment drifted", "has drifted", "guarantees", "rebuild identically"} {
				if strings.Contains(strings.ToLower(finding.Message), guarantee) || strings.Contains(strings.ToLower(rule.Fix), guarantee) {
					t.Errorf("history count/export cannot establish drift or identical rebuilds: %q / %q", finding.Message, rule.Fix)
				}
			}
		})
	}
}

func TestPhase4AssociatedLockPresenceAndAbsentProject(t *testing.T) {
	rule := mustRule(t, "ENV002")
	policy := testPolicy(t, rule.ID, "local")
	target := completeTarget("dir")
	if outcome, findings := evaluateRule(target, policy, rule); outcome.Status != NotApplicable || len(findings) != 0 {
		t.Errorf("no project is not applicable: %+v %+v", outcome, findings)
	}
	for _, name := range []string{"pixi.lock", "conda-lock.yml", "conda-lock.yaml", "uv.lock", "poetry.lock", "Pipfile.lock"} {
		t.Run(name, func(t *testing.T) {
			target.Project = &evidence.Project{Path: "/proj", Associated: true, LockPath: "/proj/" + name}
			if outcome, findings := evaluateRule(target, policy, rule); outcome.Status != Pass || len(findings) != 0 {
				t.Errorf("supported lock presence does not need synchronization verification: %+v %+v", outcome, findings)
			}
		})
	}
	target.Project = &evidence.Project{Path: "/proj", Associated: true}
	outcome, findings := evaluateRule(target, policy, rule)
	if outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("missing associated lock must produce a finding: %+v %+v", outcome, findings)
	}
	if !strings.Contains(findings[0].Message, "/proj") || !slices.Contains(findings[0].Evidence.Paths, "/proj") {
		t.Errorf("missing-lock finding must identify the project path: %+v", findings[0])
	}
}

func TestPhase4RuntimeToolingPassesAndDistinctApplicationIsObservation(t *testing.T) {
	rule := mustRule(t, "IMG003")
	policy := testPolicy(t, rule.ID, "container-runtime")
	for _, tc := range []struct {
		name, runtime string
		usesTooling   bool
	}{
		{"tooling startup", "", true},
		{"runtime in tooling prefix", "/opt/conda", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := completeTarget("oci-archive")
			target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/opt/conda/envs/app"}}
			target.RuntimePrefix, target.RuntimeUsesTooling = tc.runtime, tc.usesTooling
			if outcome, findings := evaluateRule(target, policy, rule); outcome.Status != Pass || len(findings) != 0 {
				t.Errorf("runtime depends on tooling; no removal candidate: %+v %+v", outcome, findings)
			}
		})
	}
	target := completeTarget("oci-archive")
	target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Tooling: true}, {Path: "/app"}}
	target.RuntimePrefix = "/app"
	outcome, findings := evaluateRule(target, policy, rule)
	if outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("distinct application candidate: %+v %+v", outcome, findings)
	}
	finding := findings[0]
	for _, path := range []string{"/opt/conda", "/app"} {
		if !strings.Contains(finding.Message, path) || !slices.Contains(finding.Evidence.Paths, path) {
			t.Errorf("layout observation must identify both paths: %+v", finding)
		}
	}
	warnings := strings.Join(append(slices.Clone(finding.Evidence.Notes), rule.Exceptions...), " ")
	if len(finding.Evidence.Notes) == 0 || (!strings.Contains(warnings, "not proof") && !strings.Contains(warnings, "not exclusive runtime use")) || strings.Contains(finding.Message, "runtime only needs") || strings.Contains(finding.Message, "is unused") {
		t.Errorf("configuration must not prove tooling unused: %+v", finding)
	}
}

func TestENV001NextCommandIsPlatformSafe(t *testing.T) {
	rule := mustRule(t, "ENV001")
	policy := testPolicy(t, rule.ID, "local")
	for _, path := range []string{"/env with spaces", "/env'quoted&name", "/env$(printf injected); exit 37; #", `C:\env&calc.exe&rem`} {
		t.Run(path, func(t *testing.T) {
			target := completeTarget("dir")
			target.Prefixes = []evidence.Prefix{{Path: path, Revision: intPtr(10)}}
			_, findings := evaluateRule(target, policy, rule)
			if len(findings) != 1 || !slices.Contains(findings[0].Evidence.Paths, path) {
				t.Fatalf("hostile path must remain an observation: %+v", findings)
			}
			if runtime.GOOS == "windows" {
				if findings[0].Next != "" {
					t.Errorf("unknown Windows shell must use generic action, not POSIX quoting: %q", findings[0].Next)
				}
				return
			}
			quoted := commandArg(path)
			if !strings.Contains(findings[0].Next, "conda env export --prefix "+quoted+" --from-history") {
				t.Errorf("concrete export command did not quote the observed prefix: %q", findings[0].Next)
			}
			output, err := exec.Command("/bin/sh", "-c", "set -- "+quoted+`; test "$#" -eq 1 && printf '%s' "$1"`).Output()
			if err != nil || string(output) != path {
				t.Errorf("POSIX argument changed or was evaluated: got %q, want %q, err=%v", output, path, err)
			}
		})
	}
}

func TestENV001ImageActionNamesItsSourceContext(t *testing.T) {
	target := completeTarget("oci-archive")
	target.Prefixes = []evidence.Prefix{{Path: "/opt/conda", Revision: intPtr(10)}}
	rule := mustRule(t, "ENV001")
	outcome, findings := evaluateRule(target, testPolicy(t, rule.ID, "container-development"), rule)
	if outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("image history observation lost: %+v %+v", outcome, findings)
	}
	if !strings.Contains(findings[0].Next, "matching image or its build environment") || strings.Contains(findings[0].Next, "--prefix '/opt/conda'") {
		t.Errorf("image-local prefix must not be offered as a host export command: %q", findings[0].Next)
	}
}

func TestENV002PositiveNegativeUnknown(t *testing.T) {
	rule := mustRule(t, "ENV002")
	policy := testPolicy(t, "ENV002", "local")

	positive := completeTarget("dir")
	positive.Project = &evidence.Project{Path: "/proj", Associated: true}
	if outcome, findings := evaluateRule(positive, policy, rule); outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("positive: status=%s", outcome.Status)
	}

	verified := completeTarget("dir")
	verified.Project = &evidence.Project{Path: "/proj", Associated: true, LockPath: "/proj/pixi.lock"}
	if outcome, findings := evaluateRule(verified, policy, rule); outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("verified lock must pass, got %s", outcome.Status)
	}

	unverified := completeTarget("dir")
	unverified.Project = &evidence.Project{Path: "/proj", Associated: true, LockPath: "/proj/pixi.lock"}
	if outcome, findings := evaluateRule(unverified, policy, rule); outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("supported existing lock must pass without verification, got %+v %+v", outcome, findings)
	}

	incomplete := completeTarget("dir")
	incomplete.Project = &evidence.Project{Path: "/proj", Associated: true}
	incomplete.Coverage["project-association"] = evidence.Partial
	if outcome, _ := evaluateRule(incomplete, policy, rule); outcome.Status != Unknown {
		t.Fatalf("incomplete associated project inspection must be unknown, got %s", outcome.Status)
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
		"IMG001": {func(t *evidence.Target, a []evidence.Artifact) { t.Archives = a }, "final-cache"},
		"IMG002": {func(t *evidence.Target, a []evidence.Artifact) { t.Extracted = a }, "final-cache"},
		"IMG004": {func(t *evidence.Target, a []evidence.Artifact) { t.Retained = a }, "layer-retention"},
		"IMG005": {func(t *evidence.Target, a []evidence.Artifact) { t.Tools = a }, "os-package-tools"},
		"IMG006": {func(t *evidence.Target, a []evidence.Artifact) { t.Shells = a }, "shell-tools"},
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

func TestIMG004ByteUnitAndNoSummedSavings(t *testing.T) {
	rule := mustRule(t, "IMG004")
	policy := testPolicy(t, "IMG004", "container-runtime")
	target := artifactTarget("oci-archive", func(t *evidence.Target, a []evidence.Artifact) { t.Retained = a },
		[]evidence.Artifact{{Path: "/a", Bytes: 3, LayerBytes: 100, Layer: 1}, {Path: "/b", Bytes: 4, LayerBytes: 100, Layer: 1}})
	_, findings := evaluateRule(target, policy, rule)
	if len(findings) != 1 || findings[0].Evidence.PayloadBytes != 7 || !strings.Contains(findings[0].Evidence.ByteUnit, "retained file payload bytes") {
		t.Fatalf("IMG004 byte evidence wrong: %+v", findings)
	}
	if len(findings[0].Evidence.Samples) != 2 || findings[0].Evidence.Samples[0].LayerBytes != 100 || findings[0].Evidence.Samples[1].LayerBytes != 100 {
		t.Fatalf("whole-layer descriptor must remain separate from file payload totals: %+v", findings[0].Evidence)
	}
}

func TestIMG002SeverityDowngradesWhenLinkageUnsafe(t *testing.T) {
	rule := mustRule(t, "IMG002")
	policy := testPolicy(t, "IMG002", "container-runtime")
	target := artifactTarget("oci-archive", func(t *evidence.Target, a []evidence.Artifact) { t.Extracted = a },
		[]evidence.Artifact{{Path: "/c", Kind: "dir"}})
	target.CacheLinked = true
	_, findings := evaluateRule(target, policy, rule)
	if len(findings) != 1 || findings[0].Severity != Info || len(findings[0].Evidence.Notes) == 0 {
		t.Fatalf("cache-linked IMG002 must be info with a note: %+v", findings)
	}
}

func TestIMG002RetainsDynamicCleanupSafetyNotes(t *testing.T) {
	rule := mustRule(t, "IMG002")
	policy := testPolicy(t, rule.ID, "container-runtime")
	for _, tc := range []struct {
		name, coverage, note string
		linked               bool
		severity             Severity
	}{
		{"observed references", evidence.Complete, "Preserve those dependencies", true, Info},
		{"incomplete linkage", evidence.Partial, "Do not assume", false, Info},
		{"no observed reference", evidence.Complete, "No runtime cache reference was observed", false, Warning},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := artifactTarget("oci-archive", func(t *evidence.Target, a []evidence.Artifact) { t.Extracted = a }, []evidence.Artifact{{Path: "/cache/python", Bytes: 30}})
			target.CacheLinked, target.Coverage["cache-link-dependencies"] = tc.linked, tc.coverage
			outcome, findings := evaluateRule(target, policy, rule)
			if outcome.Status != FindingStatus || len(findings) != 1 {
				t.Fatalf("positive cache observation lost: %+v %+v", outcome, findings)
			}
			finding := findings[0]
			if finding.Severity != tc.severity || finding.Evidence.CacheLinked != tc.linked || finding.Evidence.LinkCoverage != tc.coverage || !strings.Contains(strings.Join(finding.Evidence.Notes, " "), tc.note) {
				t.Errorf("dynamic linkage state or safety advice lost: %+v", finding)
			}
			if finding.Evidence.PayloadBytes != 30 || !strings.Contains(finding.Evidence.ByteUnit, "not unique or reclaimable") {
				t.Errorf("logical file accounting must not imply savings: %+v", finding.Evidence)
			}
			for _, text := range []string{finding.Message, strings.Join(finding.Evidence.Notes, " "), rule.Fix} {
				if strings.Contains(text, "removing saves no space and is safe") || strings.Contains(text, "--force-pkgs-dirs") {
					t.Errorf("unsafe unconditional cache advice: %s", text)
				}
			}
		})
	}
}

func TestLocalRuleDefaultSeverities(t *testing.T) {
	policy := enginePolicy(t, "dir", "local")
	for i := 1; i <= 12; i++ {
		id := fmt.Sprintf("ENV%03d", i)
		rule := mustRule(t, id)
		wantSeverity := Info
		if slices.Contains([]string{"ENV007", "ENV009", "ENV010", "ENV011"}, id) {
			wantSeverity = Warning
		}
		if !ruleEnabled(policy, id) || policy.Rules[id].Severity != wantSeverity || rule.Available != (id != "ENV011") {
			t.Errorf("wrong local default for %s: %+v available=%t", id, policy.Rules[id], rule.Available)
		}
		for _, profile := range profiles[1:] {
			if id != "ENV001" && rule.Defaults[profile].Enabled {
				t.Errorf("local-only %s enabled for %s", id, profile)
			}
		}
	}
}

func TestIMG003PrefixRolesPositiveNegativeUnknown(t *testing.T) {
	rule := mustRule(t, "IMG003")
	policy := testPolicy(t, "IMG003", "container")

	positive := completeTarget("oci-archive")
	positive.RuntimePrefix = "/app"
	positive.Prefixes = []evidence.Prefix{{Path: "/opt/tool", Tooling: true}, {Path: "/app"}}
	if outcome, findings := evaluateRule(positive, policy, rule); outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("positive IMG003 status=%s findings=%d", outcome.Status, len(findings))
	}

	negative := completeTarget("oci-archive")
	negative.Prefixes = []evidence.Prefix{{Path: "/app"}}
	if outcome, findings := evaluateRule(negative, policy, rule); outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("negative IMG003 status=%s findings=%d", outcome.Status, len(findings))
	}

	unknown := completeTarget("oci-archive")
	delete(unknown.Coverage, "runtime-config")
	unknown.Prefixes = []evidence.Prefix{{Path: "/opt/tool", Tooling: true}}
	if outcome, _ := evaluateRule(unknown, policy, rule); outcome.Status != Unknown {
		t.Fatalf("incomplete runtime config must be unknown, got %s", outcome.Status)
	}
}

func TestUnavailableRulesNeverRunCheck(t *testing.T) {
	for _, id := range []string{"ENV011"} {
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
	rule := mustRule(t, "IMG001")
	disabled := Policy{Rules: map[string]RuleOptions{"IMG001": {Enabled: boolPtr(false), Severity: Info}}}
	if outcome, _ := evaluateRule(completeTarget("oci-archive"), disabled, rule); outcome.Status != Disabled {
		t.Fatalf("disabled must be disabled, got %s", outcome.Status)
	}
	enabled := testPolicy(t, "IMG001", "container")
	if outcome, _ := evaluateRule(completeTarget("dir"), enabled, rule); outcome.Status != NotApplicable {
		t.Fatalf("dir source for IMG001 must be not_applicable, got %s", outcome.Status)
	}
}

func TestFindingFingerprintIsOrderIndependent(t *testing.T) {
	rule := mustRule(t, "IMG001")
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
	rule := mustRule(t, "IMG001")
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
