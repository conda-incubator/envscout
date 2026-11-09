package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// inspectionContractFixture holds one valid conda prefix, one invalid conda candidate,
// and one unsupported venv under a shared root. Discovery reports three environments.
func inspectionContractFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeMeta(t, filepath.Join(root, "good"), "pkg.json", hostRecordJSON("demo", ""))
	hostVenv(t, filepath.Join(root, "app-venv"))
	hostWrite(t, filepath.Join(root, "invalid", "conda-meta", "invalid.json"), "invalid")
	return root
}

func TestInspectionContractNilAndEnabledProgressAreEquivalent(t *testing.T) {
	root := inspectionContractFixture(t)
	req := Request{Capabilities: []string{"prefixes", "conda-records"}}
	plain, err := CollectHost(context.Background(), []string{root}, req)
	if err != nil {
		t.Fatal(err)
	}
	counts := &Progress{}
	observed, err := CollectHost(WithProgress(context.Background(), counts), []string{root}, req)
	if err != nil {
		t.Fatal(err)
	}
	// Started is a wall-clock timestamp; every other field must match exactly.
	plain.Started = time.Time{}
	observed.Started = time.Time{}
	if !reflect.DeepEqual(plain, observed) {
		t.Fatalf("progress recorder changed collection output:\nnil: %+v\nenabled: %+v", plain, observed)
	}
	if s := observed.Inspection; s.Found != 3 || s.Inspected != 1 || s.Failed != 2 || s.AccessErrors != 0 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if counts.Total.Load() != 3 || counts.Finished.Load() != 3 || counts.Inspected.Load() != 1 || counts.Failed.Load() != 2 {
		t.Fatalf("progress disagrees with summary: total=%d finished=%d inspected=%d failed=%d",
			counts.Total.Load(), counts.Finished.Load(), counts.Inspected.Load(), counts.Failed.Load())
	}
}

func TestInspectionContractUnsupportedAndInvalidFailuresFinishOnce(t *testing.T) {
	root := t.TempDir()
	hostVenv(t, filepath.Join(root, "app-venv"))
	hostWrite(t, filepath.Join(root, "invalid", "conda-meta", "invalid.json"), "invalid")
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{root}, Request{Capabilities: []string{"prefixes", "conda-records"}})
	if err != nil {
		t.Fatal(err)
	}
	if s := snapshot.Inspection; s.Found != 2 || s.Inspected != 0 || s.Failed != 2 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if !counts.Started.Load() || counts.Total.Load() != 2 || counts.Finished.Load() != 2 || counts.Failed.Load() != 2 ||
		counts.Inspected.Load() != 0 || counts.InspectionDuration.Load() != 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("each failed attempt must finish once without timing: %+v", counts)
	}
}

func TestInspectionContractSuccessfulAttemptCountsOnce(t *testing.T) {
	prefix := hostPrefix(t)
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{prefix}, Request{Capabilities: []string{"prefixes"}})
	if err != nil {
		t.Fatal(err)
	}
	if s := snapshot.Inspection; s.Found != 1 || s.Inspected != 1 || s.Failed != 0 {
		t.Fatalf("unexpected summary: %+v", s)
	}
	if counts.Inspected.Load() != 1 || counts.Finished.Load() != 1 || counts.Failed.Load() != 0 ||
		counts.InspectionDuration.Load() < 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("successful attempt must count once with non-negative timing: %+v", counts)
	}
}

func TestInspectionContractFinishExcludesFailedTiming(t *testing.T) {
	p := &Progress{}
	p.Active.Store(1)
	p.ActiveStarted.Store(99)
	p.finish(true, 5*time.Millisecond)
	if p.Failed.Load() != 1 || p.Finished.Load() != 1 || p.Inspected.Load() != 0 || p.InspectionDuration.Load() != 0 {
		t.Fatalf("failed finish must not add timing: %+v", p)
	}
	if p.Active.Load() != 0 || p.ActiveStarted.Load() != 0 {
		t.Fatal("finish must clear the active timer")
	}
	p.finish(false, 0)
	if p.Inspected.Load() != 1 || p.Finished.Load() != 2 || p.Failed.Load() != 1 || p.InspectionDuration.Load() != 0 {
		t.Fatalf("successful zero-duration finish must count without failing: %+v", p)
	}
	p.finish(false, 7)
	if p.Inspected.Load() != 2 || p.InspectionDuration.Load() != 7 {
		t.Fatalf("successful finish must add its duration: %+v", p)
	}
	var nilProgress *Progress
	nilProgress.finish(true, time.Second)
}

func TestInspectionContractProjectEarlyReturnCountsFailure(t *testing.T) {
	prefix := hostPrefix(t)
	project := t.TempDir()
	if err := os.Chmod(project, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(project, 0o755) }()
	if _, err := os.ReadDir(project); !errors.Is(err, os.ErrPermission) {
		t.Skipf("filesystem permissions do not deny project inspection: %v", err)
	}
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{prefix}, Request{Capabilities: []string{"project-association"}, Project: project})
	if !errors.Is(err, os.ErrPermission) || *snapshot.Inspection != (InspectionSummary{Found: 1, Failed: 1, AccessErrors: 1}) {
		t.Fatalf("project failure summary: %+v %v", snapshot.Inspection, err)
	}
	if len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes) != 1 || snapshot.Targets[0].Input != prefix {
		t.Fatalf("validated prefix must survive project early return: %+v", snapshot.Targets)
	}
	if !counts.Started.Load() || counts.Total.Load() != 1 || counts.Finished.Load() != 1 || counts.Failed.Load() != 1 ||
		counts.Inspected.Load() != 0 || counts.InspectionDuration.Load() != 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("project early return must finish its attempt once as failed: %+v", counts)
	}
}

func TestInspectionContractPreCancelledLeavesProgressUntouched(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(ctx, counts), []string{hostPrefix(t)}, Request{Capabilities: []string{"prefixes", "conda-records"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled error = %v", err)
	}
	if s := snapshot.Inspection; s == nil || s.Found != 0 || s.Inspected != 0 || s.Failed != 0 || s.AccessErrors != 0 {
		t.Fatalf("pre-cancelled summary must stay zero: %+v", s)
	}
	if counts.Started.Load() || counts.Total.Load() != 0 || counts.Finished.Load() != 0 || counts.Active.Load() != 0 {
		t.Fatalf("pre-cancelled collection must not start progress: %+v", counts)
	}
}

func TestInspectionContractNoCapabilityPathLeavesProgressUntouched(t *testing.T) {
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{hostPrefix(t)}, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if s := snapshot.Inspection; s == nil || s.Found != 0 || s.Inspected != 0 || s.Failed != 0 || s.AccessErrors != 0 {
		t.Fatalf("no-capability summary must stay zero: %+v", s)
	}
	if counts.Started.Load() || counts.Total.Load() != 0 || counts.Finished.Load() != 0 {
		t.Fatalf("no-capability path must not start progress: %+v", counts)
	}
}

func TestInspectionContractEmptyRootStartsProgressWithNoAttempts(t *testing.T) {
	counts := &Progress{}
	snapshot, err := CollectHost(WithProgress(context.Background(), counts), []string{t.TempDir()}, Request{Capabilities: []string{"prefixes"}})
	if err != nil || *snapshot.Inspection != (InspectionSummary{}) {
		t.Fatalf("empty root must have no inspection attempts: %+v %v", snapshot.Inspection, err)
	}
	if len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes) != 0 {
		t.Fatalf("empty root must retain the fallback target: %+v", snapshot.Targets)
	}
	if !counts.Started.Load() || counts.Total.Load() != 0 || counts.Finished.Load() != 0 || counts.Failed.Load() != 0 ||
		counts.Inspected.Load() != 0 || counts.InspectionDuration.Load() != 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("empty root must start progress without attempts: %+v", counts)
	}
}

// Validation precedes all evidence passes, so this cancels during the second pass
// without tying the test to the number of context checks or elapsed clock time.
type inspectionCancelContext struct {
	context.Context
	progress *Progress
	cancel   context.CancelFunc
}

func (c *inspectionCancelContext) Err() error {
	if c.progress.Inspected.Load() > 0 && c.progress.Active.Load() > 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestInspectionContractCancellationDuringSecondEvidencePass(t *testing.T) {
	root := t.TempDir()
	writeMeta(t, filepath.Join(root, "a"), "pkg.json", hostRecordJSON("a", ""))
	writeMeta(t, filepath.Join(root, "b"), "pkg.json", hostRecordJSON("b", ""))
	req := Request{Capabilities: []string{"prefixes", "conda-records"}}
	baseline, err := CollectHost(context.Background(), []string{root}, req)
	if err != nil || len(baseline.Targets) != 2 {
		t.Fatalf("uncancelled baseline: %+v %v", baseline, err)
	}
	counts := &Progress{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = &inspectionCancelContext{Context: ctx, progress: counts, cancel: cancel}
	snapshot, err := CollectHost(WithProgress(ctx, counts), []string{root}, req)
	if !errors.Is(err, context.Canceled) || *snapshot.Inspection != (InspectionSummary{Found: 2, Inspected: 1}) {
		t.Fatalf("only the earlier successful pass must finish: %+v %v", snapshot.Inspection, err)
	}
	if !counts.Started.Load() || counts.Total.Load() != 2 || counts.Finished.Load() != 1 || counts.Inspected.Load() != 1 ||
		counts.Failed.Load() != 0 || counts.InspectionDuration.Load() < 0 || counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
		t.Fatalf("canceled pass must remain unfinished without a stale timer: %+v", counts)
	}
	if len(snapshot.Targets) != 2 || !reflect.DeepEqual(snapshot.Targets[0], baseline.Targets[0]) ||
		!reflect.DeepEqual(snapshot.Targets[1].Prefixes, baseline.Targets[1].Prefixes) {
		t.Fatalf("cancellation must retain earlier evidence and validated records: %+v", snapshot.Targets)
	}
	for capability, state := range baseline.Targets[1].Coverage {
		want := state
		if state != NotCollected {
			want = Partial
		}
		if got := snapshot.Targets[1].Coverage[capability]; got != want {
			t.Fatalf("canceled pass %s coverage = %q, want %q", capability, got, want)
		}
	}
}

// Every cancellation point must leave no active timer; canceled attempts stay unfinished.
// The budget is swept rather than pinned; no Err count is asserted.
func TestInspectionContractCancellationLeavesNoStaleActive(t *testing.T) {
	root := inspectionContractFixture(t)
	req := Request{Capabilities: []string{"prefixes", "conda-records"}}
	sawCancel := false
	for limit := 0; limit < 2000; limit++ {
		ctx := &countdownContext{Context: context.Background(), limit: limit}
		counts := &Progress{}
		snapshot, err := CollectHost(WithProgress(ctx, counts), []string{root}, req)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("limit %d: unexpected error %v", limit, err)
			}
			sawCancel = true
		}
		if counts.Active.Load() != 0 || counts.ActiveStarted.Load() != 0 {
			t.Fatalf("limit %d: stale active attempt: active=%d started=%d", limit, counts.Active.Load(), counts.ActiveStarted.Load())
		}
		if counts.Finished.Load() != counts.Inspected.Load()+counts.Failed.Load() {
			t.Fatalf("limit %d: unfinished attempt counted as finished: %+v", limit, counts)
		}
		if s := snapshot.Inspection; s.Inspected != int(counts.Inspected.Load()) || s.Failed != int(counts.Failed.Load()) {
			t.Fatalf("limit %d: summary %+v disagrees with progress %+v", limit, s, counts)
		}
	}
	if !sawCancel {
		t.Fatal("cancellation budget sweep never cancelled collection")
	}
}
