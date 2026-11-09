package evidence

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestCoverageContractHostFactsCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		target := Target{
			Coverage: map[string]string{"prefixes": Complete, "conda-records": Partial, "host-cache": NotCollected, "empty": "", "unknown": "future"},
			Prefixes: []Prefix{{Path: "/env", RecordCoverage: Complete}},
			Archives: []Artifact{{Path: "/cache/pkg.conda", Kind: "archive", Bytes: 7}},
			Python:   []PythonDistribution{{Name: "demo", Version: "1", Path: "/env/site/demo", OwnedBy: "demo"}},
			Issues:   []Issue{{Capability: "conda-records", Path: "/env/record", Message: "kept", AccessDenied: true}},
		}
		want := target
		want.Coverage = maps.Clone(target.Coverage)
		want.Prefixes = slices.Clone(target.Prefixes)
		want.Archives = slices.Clone(target.Archives)
		want.Python = slices.Clone(target.Python)
		want.Issues = slices.Clone(target.Issues)
		if canceled {
			want.Coverage = map[string]string{"prefixes": Partial, "conda-records": Partial, "host-cache": NotCollected, "empty": Partial, "unknown": Partial}
		}
		err := collectHostFacts(ctx, &target, Request{}, nil)
		cancel()
		if (canceled && !errors.Is(err, context.Canceled)) || (!canceled && err != nil) || !reflect.DeepEqual(target, want) {
			t.Fatalf("canceled=%t: target=%+v error=%v, want %+v", canceled, target, err, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, coverage := range []map[string]string{nil, {}} {
		target := Target{Coverage: coverage}
		if !errors.Is(collectHostFacts(ctx, &target, Request{}, nil), context.Canceled) ||
			len(target.Coverage) != 0 || (target.Coverage == nil) != (coverage == nil) {
			t.Fatalf("empty coverage changed shape: %+v", target.Coverage)
		}
	}
}

func TestCoverageContractHostIssueBoundary(t *testing.T) {
	if hostEntryLimit != 10000 {
		t.Fatalf("host issue limit = %d, want 10000", hostEntryLimit)
	}
	target := Target{Coverage: map[string]string{"host-cache": Complete, "python-distributions": NotCollected}, Issues: make([]Issue, 9999)}
	hostIssue(&target, "host-cache", "/kept", "kept at boundary", fs.ErrPermission)
	want := Issue{Capability: "host-cache", Path: "/kept", Message: "kept at boundary", AccessDenied: true}
	if len(target.Issues) != 10000 || target.Issues[9999] != want {
		t.Fatalf("last retained issue changed: count=%d", len(target.Issues))
	}
	// Host truncation is silent, but still degrades coverage even if unselected.
	hostIssue(&target, "python-distributions", "/dropped", "no sentinel", fs.ErrPermission)
	if len(target.Issues) != 10000 || target.Issues[9999] != want || target.Coverage["host-cache"] != Partial ||
		target.Coverage["python-distributions"] != Partial {
		t.Fatalf("host cap or coverage degradation changed: count=%d coverage=%+v", len(target.Issues), target.Coverage)
	}
}

func TestCoverageContractHostIssueOrderAndAccess(t *testing.T) {
	target := Target{Coverage: map[string]string{"python-distributions": NotCollected}}
	hostIssue(&target, "python-distributions", "/a", "wrapped", fmt.Errorf("open: %w", fs.ErrPermission))
	hostIssue(&target, "host-cache", "/b", "ordinary", errors.New("malformed"))
	hostIssue(&target, "host-cache", "/c", "joined", errors.Join(context.Canceled, fs.ErrPermission))
	hostIssue(&target, "host-cache", "/d", "multiple causes", errors.New("malformed"), fs.ErrPermission)
	hostIssue(&target, "host-cache", "/e", "no cause")
	hostIssue(&target, "host-cache", "/f", "nil cause", nil)
	want := []Issue{
		{Capability: "python-distributions", Path: "/a", Message: "wrapped", AccessDenied: true},
		{Capability: "host-cache", Path: "/b", Message: "ordinary"},
		{Capability: "host-cache", Path: "/c", Message: "joined", AccessDenied: true},
		{Capability: "host-cache", Path: "/d", Message: "multiple causes", AccessDenied: true},
		{Capability: "host-cache", Path: "/e", Message: "no cause"},
		{Capability: "host-cache", Path: "/f", Message: "nil cause"},
	}
	if !slices.Equal(target.Issues, want) || !maps.Equal(target.Coverage, map[string]string{"python-distributions": Partial, "host-cache": Partial}) {
		t.Fatalf("host issue order, access classification or unconditional degradation changed: %+v", target)
	}
}

func TestCoverageContractAccessErrorMultiplicity(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"permission", fs.ErrPermission, 1},
		{"malformed", errors.New("malformed"), 0},
		{"canceled", context.Canceled, 0},
		{"wrapped", fmt.Errorf("wrapped: %w", fs.ErrPermission), 1},
		{"path error", &fs.PathError{Op: "open", Path: "/x", Err: fs.ErrPermission}, 1},
		{"joined pair", errors.Join(fs.ErrPermission, fs.ErrPermission), 2},
		{"permission and canceled", errors.Join(fs.ErrPermission, context.Canceled), 1},
		{"nested", fmt.Errorf("outer: %w", errors.Join(fs.ErrPermission, fmt.Errorf("inner: %w", fs.ErrPermission))), 2},
		{"mixed", errors.Join(errors.New("malformed"), errors.Join(fs.ErrPermission, context.Canceled)), 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := accessErrorCount(test.err); got != test.want {
				t.Fatalf("access errors = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCoverageContractHostPendingTargetsAfterCancellation(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		writeMeta(t, filepath.Join(root, name), "pkg.json", hostRecordJSON(name, ""))
	}
	req := Request{Capabilities: []string{"prefixes", "conda-records"}}
	baseline, err := CollectHost(context.Background(), []string{root}, req)
	if err != nil || len(baseline.Targets) != 3 || *baseline.Inspection != (InspectionSummary{Found: 3, Inspected: 3}) {
		t.Fatalf("uncanceled baseline: %+v %v", baseline.Inspection, err)
	}
	counts := &Progress{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	snapshot, err := CollectHost(WithProgress(&inspectionCancelContext{Context: ctx, progress: counts, cancel: cancel}, counts), []string{root}, req)
	if !errors.Is(err, context.Canceled) || *snapshot.Inspection != (InspectionSummary{Found: 3, Inspected: 1}) {
		t.Fatalf("only first attempt may finish: %+v %v", snapshot.Inspection, err)
	}
	if counts.Total.Load() != 3 || counts.Finished.Load() != 1 || counts.Inspected.Load() != 1 || counts.Failed.Load() != 0 ||
		counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("canceled/pending work counted or left active: %+v", counts)
	}
	if len(snapshot.Targets) != 3 || len(snapshot.Issues) != 0 || !reflect.DeepEqual(snapshot.Targets[0], baseline.Targets[0]) {
		t.Fatalf("earlier evidence or validated targets changed: %+v", snapshot)
	}
	wantCoverage := map[string]string{
		"prefixes": Partial, "conda-records": Partial, "history": NotCollected,
		"python-distributions": NotCollected, "host-cache": NotCollected, "installed-lock": NotCollected,
	}
	for i := 1; i < 3; i++ {
		want := baseline.Targets[i]
		want.Coverage = wantCoverage
		if !reflect.DeepEqual(snapshot.Targets[i], want) {
			t.Fatalf("target %d lost evidence or incorrect pending/canceled coverage: %+v, want %+v", i, snapshot.Targets[i], want)
		}
	}
}
