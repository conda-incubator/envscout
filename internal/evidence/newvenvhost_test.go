package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// hostVenv writes a regular pyvenv.cfg marker so discovery reports the directory as
// a venv. The venv deliberately has no conda-meta, so any attempt to open conda
// metadata would surface as a prefixes or conda-records issue.
func hostVenv(t *testing.T, prefix string) string {
	t.Helper()
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "pyvenv.cfg"), []byte("home = /base/python\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return prefix
}

func hasEvaluationIssue(issues []Issue, path string) bool {
	for _, issue := range issues {
		if issue.Capability == "evaluation" && issue.Path == path {
			return true
		}
	}
	return false
}

func hasCapabilityIssue(issues []Issue, capability string) bool {
	for _, issue := range issues {
		if issue.Capability == capability {
			return true
		}
	}
	return false
}

// A venv-only root is not validated as conda and must not look clean: the snapshot
// carries an explicit evaluation issue and no venv becomes a conda target.
func TestHostVenvOnlyRootIsUnsupportedNotClean(t *testing.T) {
	root := t.TempDir()
	venv := hostVenv(t, filepath.Join(root, "app-venv"))
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"prefixes", "conda-records"}})
	if err != nil {
		t.Fatalf("unsupported venv must be an issue, not a collection error: %v", err)
	}
	for _, target := range snapshot.Targets {
		if len(target.Prefixes) != 0 {
			t.Fatalf("venv was validated as a conda prefix: %+v", target)
		}
	}
	if !hasEvaluationIssue(snapshot.Issues, venv) {
		t.Fatalf("missing explicit evaluation issue for venv: %+v", snapshot.Issues)
	}
}

// A venv with a valid conda-meta directory would be a KindConda candidate in discovery
// and must not be skipped; this test uses a venv with no conda-meta at all, so
// discovery reports only the venv and the evidence layer must not open anything
// conda-related. Any prefixes or conda-records issue would mean the skip ran too late.
func TestHostVenvSkippedBeforeCondaMetadataIsOpened(t *testing.T) {
	root := t.TempDir()
	venv := hostVenv(t, filepath.Join(root, "venv"))
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"prefixes", "conda-records", "python-distributions", "host-cache", "installed-lock"}})
	if err != nil {
		t.Fatal(err)
	}
	if hasCapabilityIssue(snapshot.Issues, "prefixes") || hasCapabilityIssue(snapshot.Issues, "conda-records") {
		t.Fatalf("venv conda metadata was opened: %+v", snapshot.Issues)
	}
	if !hasEvaluationIssue(snapshot.Issues, venv) {
		t.Fatalf("missing evaluation issue: %+v", snapshot.Issues)
	}
}

// Mixed roots keep the validated conda target and its complete coverage. The venv
// adds only an evaluation issue, and that issue must not be recorded as a conda
// prefix coverage gap.
func TestHostMixedRootPreservesCondaTargetAndSkipsVenv(t *testing.T) {
	root := t.TempDir()
	conda := filepath.Join(root, "conda-env")
	writeMeta(t, conda, "pkg.json", hostRecordJSON("demo", ""))
	venv := hostVenv(t, filepath.Join(root, "venv"))
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"prefixes", "conda-records"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes) != 1 || snapshot.Targets[0].Prefixes[0].Path != conda {
		t.Fatalf("conda target not preserved alongside venv: %+v", snapshot.Targets)
	}
	if !hasEvaluationIssue(snapshot.Issues, venv) {
		t.Fatalf("missing evaluation issue for venv: %+v", snapshot.Issues)
	}
	if got := snapshot.Targets[0].Coverage["prefixes"]; got != Complete {
		t.Fatalf("supported conda prefix coverage must stay complete, got %q", got)
	}
}

// Only conda prefixes are associated with --project. A venv alongside one conda
// prefix must not be counted as the single project-associated prefix.
func TestHostVenvDoesNotCountTowardProjectAssociation(t *testing.T) {
	root := t.TempDir()
	conda := filepath.Join(root, "conda-env")
	writeMeta(t, conda, "pkg.json", hostRecordJSON("demo", ""))
	hostVenv(t, filepath.Join(root, "venv"))
	project := t.TempDir()
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{Capabilities: []string{"prefixes", "project-association"}, Project: project})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 1 || snapshot.Targets[0].Project == nil || snapshot.Targets[0].Prefixes[0].Path != conda {
		t.Fatalf("venv altered explicit conda association: %+v", snapshot.Targets)
	}
}
