package evidence

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestHostStagesVenvProjectStopsBeforeFacts(t *testing.T) {
	venv := hostVenv(t, filepath.Join(t.TempDir(), "venv"))
	hostWrite(t, filepath.Join(venv, "Lib/site-packages/certifi.dist-info/METADATA"), "Name: certifi\nVersion: 2026.7.22\n")
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{venv}, Request{
		VirtualenvCapabilities: []string{"prefixes", "python-distributions"}, Project: t.TempDir(),
	})
	if err == nil || err.Error() != "--project requires exactly one validated prefix for an explicit association" ||
		*snapshot.Inspection != (InspectionSummary{Found: 1}) || len(snapshot.Targets) != 1 {
		t.Fatalf("venv must not become a project-associated conda prefix: %+v %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	wantCoverage := map[string]string{"prefixes": Complete, "history": NotCollected, "conda-records": NotCollected,
		"python-distributions": Complete, "host-cache": NotCollected, "installed-lock": NotCollected}
	if !target.IsVirtualenv() || len(target.Prefixes) != 1 || target.Prefixes[0].Path != venv ||
		target.Prefixes[0].RecordCoverage != NotCollected || len(target.Prefixes[0].Records) != 0 ||
		len(target.Python) != 0 || target.Project != nil || !maps.Equal(target.Coverage, wantCoverage) {
		t.Fatalf("project ambiguity must retain initialized venv without collecting facts: %+v", target)
	}
	if counts.Total.Load() != 1 || counts.Finished.Load() != 0 || counts.Failed.Load() != 0 ||
		counts.Inspected.Load() != 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("ambiguity return started evidence collection: %+v", counts)
	}
}

func TestHostStagesFatalProjectRetainsAllValidatedTargets(t *testing.T) {
	root := t.TempDir()
	conda := filepath.Join(root, "conda")
	writeMeta(t, conda, "pkg.json", hostRecordJSON("demo", ""))
	venv := hostVenv(t, filepath.Join(root, "venv"))
	for _, prefix := range []string{conda, venv} {
		hostWrite(t, filepath.Join(prefix, "Lib/site-packages/certifi.dist-info/METADATA"), "Name: certifi\nVersion: 2026.7.22\n")
	}
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{root}, Request{
		Capabilities:           []string{"prefixes", "conda-records", "project-association", "python-distributions"},
		VirtualenvCapabilities: []string{"prefixes", "python-distributions"}, Project: filepath.Join(root, "missing"),
	})
	if !errors.Is(err, os.ErrNotExist) || *snapshot.Inspection != (InspectionSummary{Found: 2, Failed: 1}) || len(snapshot.Targets) != 2 {
		t.Fatalf("fatal project error must keep both validated targets: %+v %v", snapshot, err)
	}
	for _, target := range snapshot.Targets {
		if len(target.Prefixes) != 1 || target.Project != nil || len(target.Python) != 0 || len(target.Issues) != 0 ||
			target.Coverage["python-distributions"] != Complete {
			t.Fatalf("fatal association must precede both facts passes: %+v", target)
		}
		prefix := target.Prefixes[0]
		if target.IsVirtualenv() {
			if prefix.Path != venv || prefix.RecordCoverage != NotCollected || len(prefix.Records) != 0 {
				t.Fatalf("venv target shape changed: %+v", prefix)
			}
		} else if prefix.Path != conda || prefix.RecordCoverage != Complete || len(prefix.Records) != 1 ||
			prefix.Records[0].Path != filepath.Join(conda, "conda-meta/pkg.json") || target.Coverage["project-association"] != Complete {
			t.Fatalf("canonical records or initialized coverage lost at early return: %+v", target)
		}
	}
	if counts.Finished.Load() != 1 || counts.Failed.Load() != 1 || counts.Inspected.Load() != 0 ||
		counts.InspectionDuration.Load() != 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("fatal project failure must be untimed and finished once: %+v", counts)
	}
}

func TestHostStagesProjectIssueKeepsNeighborEvidence(t *testing.T) {
	root := t.TempDir()
	conda := filepath.Join(root, "conda")
	writeMeta(t, conda, "pkg.json", hostRecordJSON("demo", ""))
	venv := hostVenv(t, filepath.Join(root, "venv"))
	metadata := filepath.Join(venv, "Lib/site-packages/certifi.dist-info/METADATA")
	hostWrite(t, metadata, "Name: certifi\nVersion: 2026.7.22\n")
	project := t.TempDir()
	lock := filepath.Join(project, "pixi.lock")
	hostWrite(t, lock, "")
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{
		Capabilities:           []string{"prefixes", "conda-records", "project-association"},
		VirtualenvCapabilities: []string{"prefixes", "python-distributions"}, Project: project,
	})
	if err != nil || *snapshot.Inspection != (InspectionSummary{Found: 2, Inspected: 1, Failed: 1}) || len(snapshot.Targets) != 2 || len(snapshot.Issues) != 0 {
		t.Fatalf("nonfatal association issue must not abort neighboring evidence: %+v %v", snapshot, err)
	}
	for _, target := range snapshot.Targets {
		if target.IsVirtualenv() {
			if target.Project != nil || len(target.Issues) != 0 || len(target.Python) != 1 || target.Python[0].Path != metadata ||
				target.Coverage["python-distributions"] != Complete {
				t.Fatalf("conda project issue leaked into venv: %+v", target)
			}
		} else {
			want := Issue{Capability: "project-association", Path: lock, Message: "lock candidate is inaccessible, empty, linked or oversized"}
			if target.Project == nil || target.Project.Path != project || !target.Project.Associated || len(target.Issues) != 1 ||
				target.Issues[0] != want || target.Coverage["project-association"] != Partial || target.Coverage["conda-records"] != Complete {
				t.Fatalf("project issue or local evidence changed: %+v", target)
			}
		}
	}
}
