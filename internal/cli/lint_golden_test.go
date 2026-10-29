package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/imageinput"
	"github.com/conda-incubator/envscout/internal/inventory"
	policy "github.com/conda-incubator/envscout/internal/lint"
	gorattler "github.com/conda-incubator/go-rattler"
)

var updateLintGoldens = flag.Bool("update-lint-goldens", false, "rewrite internal/cli/testdata/lint_*.golden from the current renderer")

// goldenTime is fixed so rendered output never depends on the wall clock.
var goldenTime = time.Date(2026, 10, 26, 3, 4, 5, 0, time.UTC)

// goldenTarget is the one canonical image target shared by every image case.
var goldenTarget = imageinput.Identity{
	Source:         "oci-archive",
	Input:          "golden-image.tar",
	ManifestDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	ConfigDigest:   "sha256:4444444444444444444444444444444444444444444444444444444444444444",
	OS:             "linux",
	Architecture:   "amd64",
}

const goldenTargetID = "oci-archive:golden-image"

// goldenPrefix builds an image prefix whose conda records are fully inspected.
// Golden image prefixes carry no record payload, so record coverage is Complete.
func goldenPrefix(id string, revision *int) evidence.Prefix {
	return evidence.Prefix{Path: "/" + id, Revision: revision, RecordCoverage: evidence.Complete}
}

func intPtr(v int) *int { return &v }

// completeCoverage marks every capability as complete so no coverage issue
// is emitted, which keeps each golden focused on the case it documents.
func completeCoverage(caps ...string) map[string]string {
	coverage := make(map[string]string, len(caps))
	for _, c := range caps {
		coverage[c] = evidence.Complete
	}
	return coverage
}

// renderGolden evaluates a policy against an in-memory snapshot and renders it
// as text with colour disabled. It exercises BuildPolicy, Evaluate and renderLint.
func renderGolden(t *testing.T, snapshot evidence.Snapshot, options policy.Options) string {
	return renderGoldenWithConfig(t, snapshot, policy.Policy{Version: policy.ConfigVersion}, options)
}

func renderGoldenWithConfig(t *testing.T, snapshot evidence.Snapshot, config policy.Policy, options policy.Options) string {
	t.Helper()
	effective, err := policy.BuildPolicy(config, options)
	if err != nil {
		t.Fatalf("BuildPolicy: %v", err)
	}
	report := policy.Evaluate(snapshot, effective, goldenTime)
	// Host export and Pixi install commands vary by host shell. Pin their generic
	// fallback here; dedicated renderer tests exercise instance-action overrides.
	image := options.Source == "oci-archive"
	for i := range report.Findings {
		if !image && (report.Findings[i].RuleID == "ENV001" || report.Findings[i].RuleID == "ENV010" || report.Findings[i].RuleID == "ENV013") {
			report.Findings[i].Next = ""
		}
	}
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true, true); err != nil {
		t.Fatalf("renderLint: %v", err)
	}
	seen := make(map[string]bool, len(report.Findings))
	for _, finding := range report.Findings {
		if seen[finding.Fingerprint] {
			t.Fatalf("duplicate finding fingerprint %s: %+v", finding.Fingerprint, finding)
		}
		seen[finding.Fingerprint] = true
		if finding.Suppression != nil {
			continue
		}
		rule, ok := policy.LookupRule(finding.RuleID)
		if !ok || finding.Message == "" || len(finding.Evidence.Paths) == 0 || !strings.Contains(finding.Message, finding.Evidence.Paths[0]) {
			t.Fatalf("finding lacks observation or paths: %+v", finding)
		}
		next := finding.Next
		if next == "" {
			next = rule.Fix
		}
		for _, want := range []string{"Found: " + lintText(finding.Message), "Evidence: " + lintText(finding.Evidence.Paths[0]), "Next: " + lintText(next)} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("rendered %s omits %q: %s", finding.RuleID, want, out.String())
			}
		}
	}
	return out.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *updateLintGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update-lint-goldens to create): %v", path, err)
	}
	if string(want) != got {
		t.Fatalf("golden %s mismatch\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

// localHistoryProjectMissingLock: a local prefix with a history revision above
// the ENV001 threshold and an explicitly associated project with no supported
// lock (LockPath empty), so ENV002 emits a positive finding. The project path is
// asserted only in the snapshot, not via Options.Project, to keep the golden
// portable: BuildPolicy applies filepath.Abs on Windows, which would prefix a
// volume name and diverge from the snapshot path.
func localHistoryProjectMissingLock() evidence.Snapshot {
	prefix := "/golden/local/env"
	target := evidence.Target{
		ID: "file:///golden/local/env", Kind: "dir", Input: prefix,
		Prefixes: []evidence.Prefix{goldenPrefix("golden/local/env", intPtr(12))},
		Project:  &evidence.Project{Path: "/golden/local/project", Associated: true},
		Coverage: completeCoverage("prefixes", "history", "project-association"),
	}
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

// imagePrefixRolesShell: a distroless image with a confirmed tooling prefix at
// /opt/conda, a nested application prefix at /opt/conda/envs/app, and a shell
// at /bin/sh. Only IMG003 and IMG006 are selected, so the golden pins exactly
// those two rules' positive output.
func imagePrefixRolesShell() evidence.Snapshot {
	target := evidence.Target{
		ID: goldenTargetID, Kind: "oci-archive", Input: "golden-image.tar", Image: &goldenTarget,
		Prefixes: []evidence.Prefix{
			{Path: "/opt/conda", Revision: intPtr(3), Tooling: true},
			goldenPrefix("opt/conda/envs/app", intPtr(1)),
		},
		Shells:             []evidence.Artifact{{Path: "/bin/sh", Kind: "shell", Bytes: 900000}},
		RuntimeUsesTooling: false,
		Coverage:           completeCoverage("prefixes", "conda-records", "tooling-prefix", "runtime-config", "shell-tools"),
	}
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

// imageRetainedLayers: an oci-archive target under container-runtime carrying
// several artifact rules, with retained layer details (digests, layer index,
// compressed and logical bytes).
func imageRetainedLayers() evidence.Snapshot {
	target := evidence.Target{
		ID: goldenTargetID, Kind: "oci-archive", Input: "golden-image.tar", Image: &goldenTarget,
		Prefixes:  []evidence.Prefix{goldenPrefix("opt/conda", intPtr(3))},
		Archives:  []evidence.Artifact{{Path: "opt/conda/pkgs/old-1.0-0.conda", Kind: "archive", Bytes: 2048}},
		Extracted: []evidence.Artifact{{Path: "opt/conda/pkgs/demo-1.0-0", Kind: "extracted", Bytes: 4096}},
		Tools:     []evidence.Artifact{{Path: "usr/bin/apt", Kind: "os-package-tool", Bytes: 128}},
		Retained: []evidence.Artifact{{
			Path: "opt/conda/pkgs/old-1.0-0.conda", Kind: "retained", Bytes: 2048, Layer: 2,
			DiffID:     "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			BlobDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			LayerBytes: 512,
		}},
		Coverage: completeCoverage("final-cache", "cache-link-dependencies", "conda-records", "layer-retention", "os-package-tools", "prefixes", "tooling-prefix", "runtime-config"),
	}
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

// imageSuppressedAndUnused: a distroless image with a confirmed shell whose
// rule is suppressed by an exact target match, plus an unused suppression that
// must surface as a suppression warning.
func imageSuppressedAndUnused() evidence.Snapshot {
	target := evidence.Target{
		ID: goldenTargetID, Kind: "oci-archive", Input: "golden-image.tar", Image: &goldenTarget,
		Prefixes: []evidence.Prefix{goldenPrefix("opt/conda", intPtr(1))},
		Shells:   []evidence.Artifact{{Path: "bin/sh", Kind: "shell", Bytes: 900000}},
		Coverage: completeCoverage("shell-tools", "prefixes", "conda-records"),
	}
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

// partialUnknown: image evidence that is incomplete for a required capability,
// producing an unknown outcome with a reason and an inspection issue.
func partialUnknown() evidence.Snapshot {
	target := evidence.Target{
		ID: goldenTargetID, Kind: "oci-archive", Input: "golden-image.tar", Image: &goldenTarget,
		Prefixes: []evidence.Prefix{goldenPrefix("opt/conda", intPtr(2))},
		Coverage: map[string]string{"shell-tools": evidence.Partial, "prefixes": evidence.Complete},
		Issues:   []evidence.Issue{{Capability: "shell-tools", Path: "bin", Message: "layer 1 could not be read"}},
	}
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

// emptyTargets: no inspected targets; the report completes with no findings.
func emptyTargets() evidence.Snapshot {
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{}}
}

func TestLintGoldenLocalHistoryProjectMissingLock(t *testing.T) {
	checkGolden(t, "lint_local_history_project_missing_lock", renderGolden(t, localHistoryProjectMissingLock(),
		policy.Options{Source: "dir", Rules: []string{"ENV001", "ENV002"}}))
}

func TestLintGoldenImagePrefixRolesShell(t *testing.T) {
	checkGolden(t, "lint_image_prefix_roles_shell", renderGolden(t, imagePrefixRolesShell(),
		policy.Options{Source: "oci-archive", Profile: "container-distroless", Rules: []string{"IMG003", "IMG006"}}))
}

func TestLintGoldenImageRetainedLayers(t *testing.T) {
	checkGolden(t, "lint_image_retained_layers", renderGolden(t, imageRetainedLayers(),
		policy.Options{Source: "oci-archive", Profile: "container-runtime"}))
}

// suppressedAndUnusedConfig suppresses the observed IMG006 shell finding exactly
// and carries one suppression that matches nothing, which strict distroless
// policy reports as an unused suppression.
func suppressedAndUnusedConfig() policy.Policy {
	return policy.Policy{Version: policy.ConfigVersion, Suppressions: []policy.Suppression{
		{Rule: "IMG006", Target: goldenTargetID, Reason: "reviewed debug image exception"},
		{Rule: "IMG005", Target: goldenTargetID, Reason: "stale exception with no matching finding"},
	}}
}

func TestLintGoldenImageSuppressedAndUnused(t *testing.T) {
	checkGolden(t, "lint_image_suppressed_unused", renderGoldenWithConfig(t, imageSuppressedAndUnused(),
		suppressedAndUnusedConfig(), policy.Options{Source: "oci-archive", Profile: "container-distroless"}))
}

func TestLintGoldenPartialUnknown(t *testing.T) {
	checkGolden(t, "lint_partial_unknown", renderGolden(t, partialUnknown(),
		policy.Options{Source: "oci-archive", Profile: "container-distroless"}))
}

// caStaleCertificates: a local prefix whose conda-meta carries certifi and
// ca-certificates from the official main channel below their verified minima.
// Only package metadata is modelled; no certificate bundle content is read.
func caStaleCertificates() evidence.Snapshot {
	certifi := goldenRecord("certifi", "2026.10.19")
	certifi.Record.Channel = "https://repo.anaconda.com/pkgs/main"
	certifi.Record.URL = "https://repo.anaconda.com/pkgs/main/noarch/certifi-2026.10.19-0.conda"
	certifi.Record.Subdir = "noarch"
	ca := goldenRecord("ca-certificates", "2026.10.19")
	ca.Record.Channel = "https://repo.anaconda.com/pkgs/main"
	ca.Record.URL = "https://repo.anaconda.com/pkgs/main/noarch/ca-certificates-2026.10.19-0.conda"
	ca.Record.Subdir = "noarch"
	target := localCallbackTarget(certifi, ca)
	target.Coverage = completeCoverage("prefixes", "conda-records")
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

func TestLintGoldenCACertificateStale(t *testing.T) {
	checkGolden(t, "lint_ca_certificates_stale", renderGolden(t, caStaleCertificates(),
		policy.Options{Source: "dir", Rules: []string{"ENV013"}}))
}

func TestLintGoldenEmptyTargets(t *testing.T) {
	checkGolden(t, "lint_empty_targets", renderGolden(t, emptyTargets(),
		policy.Options{Source: "dir"}))
}

func TestLintGoldenRuleCatalogue(t *testing.T) {
	var out bytes.Buffer
	if err := renderRules(&out, "text"); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "lint_rule_catalogue", out.String())
}

func TestLintGoldenHelperKeepsPortableInstanceActions(t *testing.T) {
	text := renderGolden(t, localHistoryProjectMissingLock(), policy.Options{Source: "dir", Rules: []string{"ENV001", "ENV002"}})
	if !strings.Contains(text, "Next: In `/golden/local/project`, run `pixi lock`") {
		t.Fatalf("portable project action was replaced by a generic catalogue action: %s", text)
	}
	historyRule, ok := policy.LookupRule("ENV001")
	if !ok || !strings.Contains(text, "Next: "+historyRule.Fix) {
		t.Fatalf("host-shell-dependent history action must use the portable fallback: %s", text)
	}
}

func TestLintGoldenInstanceActions(t *testing.T) {
	lockRule, ok := policy.LookupRule("ENV010")
	if !ok {
		t.Fatal("installed-lock rule is not registered")
	}
	projectRule, ok := policy.LookupRule("ENV002")
	if !ok {
		t.Fatal("project-lock rule is not registered")
	}
	report := policy.Report{
		Profile: "local", RulesetVersion: policy.RulesetVersion, Status: "completed",
		Targets: []policy.TargetReport{{ID: "file:///golden/env", Kind: "dir", PrefixCount: 1}},
		Findings: []policy.Finding{
			{RuleID: lockRule.ID, Target: "file:///golden/env", Severity: policy.Warning,
				Message: "Installed numpy in `/golden/env` differs from `/golden/project/pixi.lock` (environment science, subdir linux-64). " + lockRule.Description,
				Next:    "In a POSIX shell, run `pixi install --manifest-path '/golden/project/pixi.toml' --environment 'science'`, then repeat this check.",
				Evidence: policy.FindingEvidence{Paths: []string{"/golden/env", "/golden/project/pixi.lock"},
					Notes: []string{"numpy: locked 1, installed 2"}},
			},
			{RuleID: projectRule.ID, Target: "file:///golden/env", Severity: policy.Info,
				Message:  "The associated project `/golden/unlocked` has no lockfile. " + projectRule.Description,
				Evidence: policy.FindingEvidence{Paths: []string{"/golden/unlocked"}},
			},
		},
		OutcomeCounts: map[policy.Status]int{policy.FindingStatus: 2},
	}
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Next: "+report.Findings[0].Next) || strings.Contains(out.String(), lockRule.Fix) || !strings.Contains(out.String(), "Next: "+projectRule.Fix) {
		t.Fatalf("golden must pin instance action override and catalogue fallback: %s", out.String())
	}
	checkGolden(t, "lint_instance_actions", out.String())
}

func goldenRecord(name, version string) inventory.CondaRecord {
	return inventory.CondaRecord{
		Path: "/golden/env/conda-meta/" + name + ".json", OwnershipKnown: true,
		Record: gorattler.PrefixRecord{
			PackageRecord: gorattler.PackageRecord{Name: name, Version: version, Build: "0", Subdir: "linux-64", SHA256: strings.Repeat("a", 64)},
			Channel:       "conda-forge", Filename: name + "-" + version + "-0.conda",
			URL: "https://conda.anaconda.org/conda-forge/linux-64/" + name + "-" + version + "-0.conda",
		},
	}
}

func localCallbackTarget(records ...inventory.CondaRecord) evidence.Target {
	return evidence.Target{
		ID: "file:///golden/env", Kind: "dir", Input: "/golden/env",
		Prefixes: []evidence.Prefix{{Path: "/golden/env", Records: records, RecordCoverage: evidence.Complete}},
		Coverage: completeCoverage("prefixes", "conda-records", "python-distributions", "host-cache", "installed-lock"),
	}
}

func TestLintGoldenNewLocalCallbacks(t *testing.T) {
	numpy := goldenRecord("numpy", "2")
	unowned := localCallbackTarget(numpy)
	unowned.Python = []evidence.PythonDistribution{{Name: "click", Version: "8", Path: "/golden/env/lib/python3.14/site-packages/click-8.dist-info/METADATA"}}
	conflict := localCallbackTarget(numpy)
	conflict.Python = []evidence.PythonDistribution{{Name: "numpy", Version: "3", OwnedBy: "numpy", Path: "/golden/env/lib/python3.14/site-packages/numpy-3.dist-info/METADATA"}}
	conda := goldenRecord("conda", "26.7")
	conda.Record.Depends = []string{"python >=3.11"}
	base := localCallbackTarget(conda, goldenRecord("python", "3.14.0"), numpy)
	duplicate := localCallbackTarget(numpy)
	other := goldenRecord("numpy", "2")
	other.Path = "/golden/other/conda-meta/numpy.json"
	duplicate.Prefixes = append(duplicate.Prefixes, evidence.Prefix{Path: "/golden/other", Records: []inventory.CondaRecord{other}, RecordCoverage: evidence.Complete})
	defaults := goldenRecord("python", "3.14.0")
	defaults.Record.Channel = "https://repo.anaconda.com/pkgs/main"
	defaults.Record.URL = "https://repo.anaconda.com/pkgs/main/linux-64/python-3.14.0-0.conda"
	mixed := localCallbackTarget(defaults, numpy)
	cache := localCallbackTarget(numpy)
	cache.Archives = []evidence.Artifact{{Path: "/golden/cache/numpy-2-0.conda", Kind: "archive", Bytes: 2048}}
	cache.Extracted = []evidence.Artifact{{Path: "/golden/cache/numpy-2-0", Kind: "extracted", Bytes: 4096}}
	cache.CacheLinked = true
	lock := localCallbackTarget(numpy)
	lock.Lock = &evidence.LockComparison{Path: "/golden/project/pixi.lock", Prefix: "/golden/env", Environment: "default", Subdir: "linux-64",
		Report: &gorattler.SyncReport{Scope: "conda", Complete: true, Changed: []gorattler.PackageChange{{
			Locked:    gorattler.LockedPackage{Kind: "conda", Name: "numpy", Version: "1", Build: "0", Subdir: "linux-64"},
			Installed: gorattler.InstalledPackage{Kind: "conda", Name: "numpy", Version: "2", Build: "0", Subdir: "linux-64"},
			Reasons:   []string{"version differs"},
		}}},
	}
	unconstrained := goldenRecord("numpy", "2")
	unconstrained.Record.RequestedSpec = "numpy"
	var out strings.Builder
	for _, test := range []struct {
		id     string
		target evidence.Target
	}{
		{"ENV003", unowned}, {"ENV004", conflict}, {"ENV005", base}, {"ENV006", duplicate},
		{"ENV007", mixed}, {"ENV008", cache}, {"ENV009", localCallbackTarget(goldenRecord("python", "3.10.16"))},
		{"ENV010", lock}, {"ENV012", localCallbackTarget(unconstrained)},
	} {
		text := renderGolden(t, evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{test.target}}, policy.Options{Source: "dir", Rules: []string{test.id}})
		rule, ok := policy.LookupRule(test.id)
		if !ok {
			t.Fatalf("new rule %s is not registered", test.id)
		}
		for _, want := range []string{test.id + " ", "Found:", rule.Description, "Evidence: /golden/", "Next: " + rule.Fix} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s golden lacks what/why/path/next %q: %s", test.id, want, text)
			}
		}
		out.WriteString(text)
		out.WriteByte('\n')
	}
	checkGolden(t, "lint_local_callbacks", out.String())
}
