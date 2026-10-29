package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestHostVirtualenvPythonEvidence(t *testing.T) {
	for _, layout := range []string{"lib/python3.13/site-packages", "Lib/site-packages"} {
		t.Run(layout, func(t *testing.T) {
			prefix := hostVenv(t, filepath.Join(t.TempDir(), "venv"))
			metadata := filepath.Join(prefix, layout, "certifi-2026.7.22.dist-info", "METADATA")
			hostWrite(t, metadata, "Metadata-Version: 2.1\nName: certifi\nVersion: 2026.7.22\n")
			// Neither the interpreter nor bundle contents are required or followed.
			hostWrite(t, filepath.Join(prefix, "pyvenv.cfg"), "home = /outside/python\nexecutable = /outside/python\ninclude-system-site-packages = true\n")
			if err := os.Symlink(filepath.Join(t.TempDir(), "missing.pem"), filepath.Join(prefix, layout, "cacert.pem")); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(layout, "lib/") {
				if err := os.Symlink("lib", filepath.Join(prefix, "lib64")); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{
				Capabilities: []string{"prefixes", "conda-records"}, VirtualenvCapabilities: []string{"prefixes", "python-distributions"},
			})
			if err != nil || len(snapshot.Targets) != 1 || len(snapshot.Issues) != 0 {
				t.Fatalf("virtualenv collection: %+v %v", snapshot, err)
			}
			target := snapshot.Targets[0]
			if !target.IsVirtualenv() || target.Coverage["conda-records"] != NotCollected || target.Coverage["python-distributions"] != Complete || len(target.Issues) != 0 || len(target.Python) != 1 || target.Python[0].Path != metadata || target.Python[0].OwnedBy != "" {
				t.Fatalf("virtualenv must collect confined Python evidence exactly once, never conda: %+v", target)
			}
		})
	}
}

func TestHostVirtualenvPythonPartialKeepsLocalCertifi(t *testing.T) {
	prefix := hostVenv(t, filepath.Join(t.TempDir(), "venv"))
	site := filepath.Join(prefix, "lib/python3.13/site-packages")
	hostWrite(t, filepath.Join(site, "certifi-2026.7.22.egg-info", "PKG-INFO"), "Metadata-Version: 1.0\nName: certifi\nVersion: 2026.7.22\n")
	outside := t.TempDir()
	hostWrite(t, filepath.Join(outside, "METADATA"), "Name: certifi\nVersion: 2026.10.18\n")
	if err := os.Symlink(outside, filepath.Join(site, "outside-1.dist-info")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{VirtualenvCapabilities: []string{"prefixes", "python-distributions"}})
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("partial virtualenv collection: %+v %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	if target.Coverage["python-distributions"] != Partial || len(target.Python) != 1 || target.Python[0].Version != "2026.7.22" || !hasCapabilityIssue(target.Issues, "python-distributions") {
		t.Fatalf("linked metadata must not escape or erase known local evidence: %+v", target)
	}
}

func TestHostProjectAssociationKeepsVirtualenvEvidence(t *testing.T) {
	root := t.TempDir()
	conda := filepath.Join(root, "conda")
	writeMeta(t, conda, "pkg.json", hostRecordJSON("demo", ""))
	venv := hostVenv(t, filepath.Join(root, "venv"))
	hostWrite(t, filepath.Join(venv, "Lib/site-packages/certifi.dist-info/METADATA"), "Name: certifi\nVersion: 2026.7.22\n")
	project := t.TempDir()
	snapshot, err := CollectHost(context.Background(), []string{root}, Request{
		Capabilities: []string{"prefixes", "conda-records", "project-association"}, VirtualenvCapabilities: []string{"prefixes", "python-distributions"}, Project: project,
	})
	if err != nil || len(snapshot.Targets) != 2 {
		t.Fatalf("one conda project association must survive a neighboring virtualenv: %+v %v", snapshot, err)
	}
	for _, target := range snapshot.Targets {
		if target.IsVirtualenv() {
			if target.Project != nil || len(target.Python) != 1 || target.Coverage["python-distributions"] != Complete {
				t.Fatalf("virtualenv evidence must remain independent of conda association: %+v", target)
			}
		} else if target.Project == nil || !target.Project.Associated {
			t.Fatalf("conda project association was lost: %+v", target)
		}
	}
}

func TestHostVirtualenvMissingPrimaryMetadataIsPartial(t *testing.T) {
	for _, path := range []string{"certifi-2026.7.22.dist-info/RECORD", "certifi-2026.7.22.dist-info"} {
		t.Run(path, func(t *testing.T) {
			prefix := hostVenv(t, filepath.Join(t.TempDir(), "venv"))
			hostWrite(t, filepath.Join(prefix, "Lib/site-packages", path), "")
			snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{VirtualenvCapabilities: []string{"prefixes", "python-distributions"}})
			if err != nil || len(snapshot.Targets) != 1 {
				t.Fatalf("missing primary metadata: %+v %v", snapshot, err)
			}
			if target := snapshot.Targets[0]; target.Coverage["python-distributions"] != Partial || !hasCapabilityIssue(target.Issues, "python-distributions") {
				t.Fatalf("an incomplete distribution must not become complete absence: %+v", target)
			}
		})
	}
}

func TestHostVirtualenvTraversalAliasIsPartial(t *testing.T) {
	prefix := hostVenv(t, filepath.Join(t.TempDir(), "venv"))
	if err := os.Mkdir(filepath.Join(prefix, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), filepath.Join(prefix, "hop")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("hop/../lib", filepath.Join(prefix, "lib64")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{VirtualenvCapabilities: []string{"prefixes", "python-distributions"}})
	if err != nil || len(snapshot.Targets) != 1 || snapshot.Targets[0].Coverage["python-distributions"] != Partial {
		t.Fatalf("only a proven redundant lib alias may be skipped: %+v %v", snapshot, err)
	}
}

func TestHostInspectionCountsLocalFailuresNotNeighborCoverage(t *testing.T) {
	root := t.TempDir()
	hostVenv(t, filepath.Join(root, "good"))
	bad := hostVenv(t, filepath.Join(root, "bad"))
	hostWrite(t, filepath.Join(bad, "Lib/site-packages/certifi.dist-info/RECORD"), "")
	hostWrite(t, filepath.Join(bad, "Lib/site-packages/other.dist-info/RECORD"), "")
	hostWrite(t, filepath.Join(root, "invalid-conda", "conda-meta", "invalid.json"), "invalid")
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{root}, Request{
		Capabilities: []string{"prefixes", "conda-records"}, VirtualenvCapabilities: []string{"prefixes", "python-distributions"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary := snapshot.Inspection; summary == nil || summary.Found != 3 || summary.Inspected != 1 || summary.Failed != 2 || summary.AccessErrors != 0 {
		t.Fatalf("count collection attempts once, not findings or global coverage: %+v", summary)
	}
	if !counts.Started.Load() || counts.Total.Load() != 3 || counts.Finished.Load() != 3 || counts.Failed.Load() != 2 || counts.Active.Load() != 0 {
		t.Fatalf("live progress must match the completed summary: total=%d finished=%d failed=%d active=%d", counts.Total.Load(), counts.Finished.Load(), counts.Failed.Load(), counts.Active.Load())
	}
	// A fast inspection can finish within one clock tick, especially on Windows.
	if counts.Inspected.Load() != 1 || counts.InspectionDuration.Load() < 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatal("successful inspection must count without negative duration or a stale active timer")
	}
	snapshot, err = CollectHost(context.Background(), []string{t.TempDir()}, Request{Capabilities: []string{"prefixes"}})
	if err != nil || len(snapshot.Targets) != 1 || snapshot.Inspection.Found != 0 || snapshot.Inspection.Inspected != 0 || snapshot.Inspection.Failed != 0 {
		t.Fatalf("fallback root targets must not count as inspected environments: %+v %v", snapshot, err)
	}
}

func TestHostInspectionSummaryCountsMetadataAccessErrors(t *testing.T) {
	prefix := hostVenv(t, filepath.Join(t.TempDir(), "venv"))
	site := filepath.Join(prefix, "Lib/site-packages")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(site, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(site, 0o755) }()
	if entries, err := os.ReadDir(site); !errors.Is(err, os.ErrPermission) {
		t.Skipf("filesystem permissions do not deny directory enumeration: %v %v", entries, err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{VirtualenvCapabilities: []string{"prefixes", "python-distributions"}})
	if err != nil || snapshot.Inspection.Found != 1 || snapshot.Inspection.Inspected != 0 || snapshot.Inspection.Failed != 1 || snapshot.Inspection.AccessErrors == 0 {
		t.Fatalf("metadata access errors must be counted without a false inspection success: %+v %v", snapshot.Inspection, err)
	}
}

func TestHostInspectionCountsSeparateCondaAccessErrors(t *testing.T) {
	prefix := hostPrefix(t)
	for _, name := range []string{"denied-a.json", "denied-b.json"} {
		writeMeta(t, prefix, name, hostRecordJSON("denied", ""))
		path := filepath.Join(prefix, "conda-meta", name)
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(path, 0o644) }()
		if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
			t.Skipf("filesystem permissions do not deny metadata reads: %v", err)
		}
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records"}})
	if err != nil || snapshot.Inspection.Inspected != 0 || snapshot.Inspection.Failed != 1 || snapshot.Inspection.AccessErrors != 2 {
		t.Fatalf("joined conda errors must count separately, but fail the environment once: %+v %v", snapshot.Inspection, err)
	}
}
