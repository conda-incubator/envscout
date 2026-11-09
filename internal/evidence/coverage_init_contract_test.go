package evidence

import (
	"context"
	"maps"
	"path/filepath"
	"testing"
)

func coverageInitRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"a", "b"} {
		writeMeta(t, filepath.Join(root, name), "pkg.json", hostRecordJSON(name, ""))
		hostWrite(t, filepath.Join(root, name, "conda-meta", "history"), "==> initial <==\n")
	}
	return root
}

// The ambiguity check follows initialization but precedes facts collection.
func coverageInitRun(t *testing.T, root string, req Request) Snapshot {
	t.Helper()
	req.Project = t.TempDir()
	snapshot, err := CollectHost(context.Background(), []string{root}, req)
	if err == nil || err.Error() != "--project requires exactly one validated prefix for an explicit association" {
		t.Fatalf("expected project ambiguity before facts, got %v", err)
	}
	return snapshot
}

func TestCoverageInitHostSelection(t *testing.T) {
	root := coverageInitRoot(t)
	for _, test := range []struct {
		name string
		caps []string
		key  string
	}{
		{"prefixes only", []string{"prefixes"}, ""},
		{"conda records", []string{"prefixes", "conda-records"}, "conda-records"},
		{"python", []string{"prefixes", "python-distributions"}, "python-distributions"},
		{"cache", []string{"prefixes", "host-cache"}, "host-cache"},
		{"lock", []string{"prefixes", "installed-lock"}, "installed-lock"},
		{"project key", []string{"prefixes", "project-association"}, "project-association"},
		{"history", []string{"prefixes", "history"}, "history"},
		{"duplicates and unknown", []string{"prefixes", "conda-records", "conda-records", "future-cap"}, "conda-records"},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := map[string]string{
				"prefixes": Complete, "history": NotCollected, "conda-records": NotCollected,
				"python-distributions": NotCollected, "host-cache": NotCollected, "installed-lock": NotCollected,
			}
			if test.key != "" {
				want[test.key] = Complete
			}
			snapshot := coverageInitRun(t, root, Request{Capabilities: test.caps})
			if len(snapshot.Targets) != 2 || *snapshot.Inspection != (InspectionSummary{Found: 2}) {
				t.Fatalf("initialization must retain both unfinished targets: %+v", snapshot)
			}
			for _, target := range snapshot.Targets {
				if !maps.Equal(target.Coverage, want) {
					t.Fatalf("coverage = %+v, want %+v", target.Coverage, want)
				}
			}
		})
	}
}

func TestCoverageInitEnvironmentSelection(t *testing.T) {
	root := coverageInitRoot(t)
	hostVenv(t, filepath.Join(root, "venv"))
	snapshot := coverageInitRun(t, root, Request{
		Capabilities:           []string{"prefixes", "conda-records", "history", "project-association"},
		VirtualenvCapabilities: []string{"prefixes", "python-distributions", "future-cap"},
	})
	if len(snapshot.Targets) != 3 || *snapshot.Inspection != (InspectionSummary{Found: 3}) {
		t.Fatalf("mixed initialized targets = %+v", snapshot)
	}
	for _, target := range snapshot.Targets {
		want := map[string]string{
			"prefixes": Complete, "history": Complete, "conda-records": Complete, "project-association": Complete,
			"python-distributions": NotCollected, "host-cache": NotCollected, "installed-lock": NotCollected,
		}
		if target.IsVirtualenv() {
			want = map[string]string{
				"prefixes": Complete, "history": NotCollected, "conda-records": NotCollected,
				"python-distributions": Complete, "host-cache": NotCollected, "installed-lock": NotCollected,
			}
			if target.Prefixes[0].RecordCoverage != NotCollected {
				t.Fatalf("venv record coverage changed: %+v", target.Prefixes)
			}
		}
		if !maps.Equal(target.Coverage, want) {
			t.Fatalf("environment selection changed: %+v, want %+v", target.Coverage, want)
		}
	}
}

func TestCoverageInitPartialRecordsOverride(t *testing.T) {
	root := coverageInitRoot(t)
	writeMeta(t, filepath.Join(root, "a"), "malformed.json", `{"name":`)
	for _, selected := range []bool{false, true} {
		req := Request{Capabilities: []string{"prefixes"}}
		if selected {
			req.Capabilities = append(req.Capabilities, "conda-records")
		}
		snapshot := coverageInitRun(t, root, req)
		if len(snapshot.Targets) != 2 {
			t.Fatalf("partial record set dropped validated targets: %+v", snapshot.Targets)
		}
		for _, target := range snapshot.Targets {
			want := map[string]string{
				"prefixes": Partial, "history": NotCollected, "conda-records": NotCollected,
				"python-distributions": NotCollected, "host-cache": NotCollected, "installed-lock": NotCollected,
			}
			if selected {
				want["conda-records"] = Complete
				if filepath.Base(target.Input) == "a" {
					want["conda-records"] = Partial
				}
			}
			if !maps.Equal(target.Coverage, want) || len(target.Prefixes[0].Records) != 1 {
				t.Fatalf("selected=%t: local record coverage override changed: %+v", selected, target)
			}
			if filepath.Base(target.Input) == "a" && target.Prefixes[0].RecordCoverage != Partial {
				t.Fatalf("incomplete canonical records must stay partial: %+v", target.Prefixes)
			}
		}
	}
}

func TestCoverageInitEmptyRootKeepsFallbackPolicy(t *testing.T) {
	snapshot, err := CollectHost(context.Background(), []string{t.TempDir()}, Request{Capabilities: []string{"future-cap", "python-distributions"}})
	want := map[string]string{"prefixes": Complete, "future-cap": Complete, "python-distributions": Complete}
	if err != nil || len(snapshot.Targets) != 1 || !maps.Equal(snapshot.Targets[0].Coverage, want) || len(snapshot.Targets[0].Prefixes) != 0 {
		t.Fatalf("empty-root fallback must not initialize validated-target capability keys: %+v, %v", snapshot, err)
	}
}
