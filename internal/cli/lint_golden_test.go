package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/imageinput"
	policy "github.com/conda-incubator/envscout/internal/lint"
)

var updateLintGoldens = flag.Bool("update-lint-goldens", false, "rewrite internal/cli/testdata/lint_*.golden from the current renderer")

// goldenTime is fixed so rendered output never depends on the wall clock.
var goldenTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

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

func goldenPrefix(id string, revision *int) evidence.Prefix {
	return evidence.Prefix{Path: "/" + id, Revision: revision}
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
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true); err != nil {
		t.Fatalf("renderLint: %v", err)
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
// the EC001 threshold and an explicitly associated project with no verified
// lock (LockPath empty), so EC004 emits a positive finding. The project path is
// asserted only in the snapshot, not via Options.Project, to keep the golden
// portable: BuildPolicy applies filepath.Abs on Windows, which would prefix a
// volume name and diverge from the snapshot path.
func localHistoryProjectMissingLock() evidence.Snapshot {
	prefix := "/golden/local/env"
	target := evidence.Target{
		ID: "file:///golden/local/env", Kind: "dir", Input: prefix,
		Prefixes: []evidence.Prefix{goldenPrefix("golden/local/env", intPtr(12))},
		Project:  &evidence.Project{Path: "/golden/local/project", Associated: true, LockVerified: false},
		Coverage: completeCoverage("prefixes", "history", "project-association"),
	}
	return evidence.Snapshot{Started: goldenTime, Targets: []evidence.Target{target}}
}

// imagePrefixRolesShell: a distroless image with a confirmed tooling prefix at
// /opt/conda, a nested application prefix at /opt/conda/envs/app, and a shell
// at /bin/sh. Only IC003 and IC007 are selected, so the golden pins exactly
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
		Coverage:           completeCoverage("prefixes", "tooling-prefix", "runtime-config", "shell-tools"),
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
		Coverage: completeCoverage("final-cache", "cache-link-dependencies", "layer-retention", "os-package-tools", "prefixes", "tooling-prefix", "runtime-config"),
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
		Coverage: completeCoverage("shell-tools", "prefixes"),
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
		policy.Options{Source: "dir"}))
}

func TestLintGoldenImagePrefixRolesShell(t *testing.T) {
	checkGolden(t, "lint_image_prefix_roles_shell", renderGolden(t, imagePrefixRolesShell(),
		policy.Options{Source: "oci-archive", Profile: "container-distroless", Rules: []string{"IC003", "IC007"}}))
}

func TestLintGoldenImageRetainedLayers(t *testing.T) {
	checkGolden(t, "lint_image_retained_layers", renderGolden(t, imageRetainedLayers(),
		policy.Options{Source: "oci-archive", Profile: "container-runtime"}))
}

// suppressedAndUnusedConfig suppresses the observed IC007 shell finding exactly
// and carries one suppression that matches nothing, which strict distroless
// policy reports as an unused suppression.
func suppressedAndUnusedConfig() policy.Policy {
	return policy.Policy{Version: policy.ConfigVersion, Suppressions: []policy.Suppression{
		{Rule: "IC007", Target: goldenTargetID, Reason: "reviewed debug image exception"},
		{Rule: "IC006", Target: goldenTargetID, Reason: "stale exception with no matching finding"},
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

func TestLintGoldenEmptyTargets(t *testing.T) {
	checkGolden(t, "lint_empty_targets", renderGolden(t, emptyTargets(),
		policy.Options{Source: "dir"}))
}
