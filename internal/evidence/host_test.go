package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func hostPrefix(t *testing.T) string {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "env")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(hostRecordJSON("demo", "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "history"), []byte("==> initial <==\n==> update <==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return prefix
}

func TestCollectHostAndProject(t *testing.T) {
	prefix := hostPrefix(t)
	project := t.TempDir()
	var resolveErr error
	project, resolveErr = filepath.EvalSymlinks(project)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	request := Request{Capabilities: []string{"prefixes", "history", "project-association"}, Project: project}
	snapshot, err := CollectHost(context.Background(), []string{prefix, prefix}, request)
	if err != nil || len(snapshot.Targets) != 1 || snapshot.Targets[0].Prefixes[0].Revision == nil || *snapshot.Targets[0].Prefixes[0].Revision != 1 {
		t.Fatalf("unexpected host evidence: %+v, %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	if target.Project == nil || !target.Project.Associated || target.Project.LockPath != "" || !strings.HasPrefix(target.ID, "file:") {
		t.Fatalf("missing explicit association: %+v", target)
	}
	if err := os.WriteFile(filepath.Join(project, "pixi.lock"), []byte(hostPixiLock), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err = CollectHost(context.Background(), []string{prefix}, request)
	if err != nil || snapshot.Targets[0].Project.LockPath == "" {
		t.Fatalf("lock presence claimed verification: %+v, %v", snapshot, err)
	}
}

func TestHostContextAndAmbiguousAssociation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectHost(ctx, []string{hostPrefix(t)}, Request{}); err == nil {
		t.Fatal("cancelled collection succeeded")
	}
	if _, err := CollectHost(context.Background(), []string{hostPrefix(t), hostPrefix(t)}, Request{Capabilities: []string{"project-association"}, Project: t.TempDir()}); err == nil {
		t.Fatal("ambiguous project association accepted")
	}
}

func TestDisabledHistoryDoesNotInspectInvalidHistory(t *testing.T) {
	prefix := hostPrefix(t)
	history := filepath.Join(prefix, "conda-meta", "history")
	if err := os.Remove(history); err != nil {
		t.Fatal(err)
	}
	// A directory is invalid history but must be irrelevant to ENV002-only lint.
	if err := os.Mkdir(history, 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"prefixes", "project-association"}})
	if err != nil || len(snapshot.Issues) != 0 || snapshot.Targets[0].Coverage["history"] != NotCollected || snapshot.Targets[0].Prefixes[0].Revision != nil {
		t.Fatalf("unrequested history affected lint: %+v %v", snapshot, err)
	}
	snapshot, err = CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"prefixes", "history"}})
	if err != nil || len(snapshot.Issues) == 0 || snapshot.Issues[0].Capability != "history" || snapshot.Targets[0].Coverage["prefixes"] != Complete {
		t.Fatalf("history error not independently reported: %+v %v", snapshot, err)
	}
}

// countdownContext reports nil from Err for the first limit calls, then Canceled.
// Cancellation then lands at some deterministic point inside collection without
// timers or exported progress hooks.
type countdownContext struct {
	context.Context
	limit int
	calls atomic.Int64
}

func (c *countdownContext) Err() error {
	if c.calls.Add(1) > int64(c.limit) {
		return context.Canceled
	}
	return nil
}

// TestHostCancellationPreservesPartialFindings uses two prefixes and searches the
// countdown budget for a cancellation that lands after the first prefix validated.
// Any run that returns a cancellation error must keep every validated target with
// Partial coverage, never Complete. The exact budget is not pinned.
func TestHostCancellationPreservesPartialFindings(t *testing.T) {
	shared := t.TempDir()
	writeMeta(t, filepath.Join(shared, "a"), "pkg.json", hostRecordJSON("a", ""))
	writeMeta(t, filepath.Join(shared, "b"), "pkg.json", hostRecordJSON("b", ""))
	roots := []string{shared}
	sawPartial := false
	for limit := 1; limit < 2000; limit++ {
		ctx := &countdownContext{Context: context.Background(), limit: limit}
		snapshot, err := CollectHost(ctx, roots, Request{Capabilities: []string{"prefixes", "history"}})
		if err == nil {
			continue
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("limit %d: unexpected error %v", limit, err)
		}
		for _, target := range snapshot.Targets {
			if len(target.Prefixes) == 0 {
				// Cancelled before any prefix validated: only the root fallback remains.
				if target.Coverage["prefixes"] != Partial {
					t.Fatalf("limit %d: root fallback not partial: %+v", limit, target)
				}
				continue
			}
			if target.Coverage["prefixes"] != Partial {
				t.Fatalf("limit %d: cancelled collection reported %q coverage: %+v", limit, target.Coverage["prefixes"], target)
			}
			sawPartial = true
		}
		if sawPartial {
			return
		}
	}
	t.Fatal("no cancellation budget preserved a validated prefix")
}

func TestHostPreCancelledReturnsNoTargets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot, err := CollectHost(ctx, []string{hostPrefix(t)}, Request{Capabilities: []string{"prefixes"}})
	if !errors.Is(err, context.Canceled) || len(snapshot.Targets) != 0 {
		t.Fatalf("pre-cancelled collection = %+v, %v", snapshot.Targets, err)
	}
}

func TestHostNoCollectorsDeduplicatesRoots(t *testing.T) {
	prefix := hostPrefix(t)
	snapshot, err := CollectHost(context.Background(), []string{prefix, prefix}, Request{})
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("empty-capability roots not deduplicated: %+v %v", snapshot, err)
	}
}

// writeMeta writes one conda-meta record under prefix.
func writeMeta(t *testing.T, prefix, file, data string) {
	t.Helper()
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, file), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestHostNestedEnvDoesNotValidateOuterPrefix: an outer prefix whose own metadata is
// invalid must not borrow records from a nested environment. The nested environment is
// a separate positive target, and the outer prefix stays unvalidated with an issue.
func TestHostNestedEnvDoesNotValidateOuterPrefix(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "outer")
	writeMeta(t, outer, "bad.json", `{"version":"1"}`)
	nested := filepath.Join(outer, "envs", "inner")
	writeMeta(t, nested, "pkg.json", hostRecordJSON("inner", ""))

	snapshot, err := CollectHost(context.Background(), []string{outer}, Request{Capabilities: []string{"prefixes"}})
	if err != nil {
		t.Fatalf("metadata problems must not fail collection: %v", err)
	}
	var sawNested, sawOuter bool
	for _, target := range snapshot.Targets {
		if len(target.Prefixes) != 1 {
			t.Fatalf("target without prefix: %+v", target)
		}
		switch target.Prefixes[0].Path {
		case nested:
			sawNested = true
		case outer:
			sawOuter = true
		}
	}
	if !sawNested {
		t.Fatalf("nested environment missing as positive target: %+v", snapshot.Targets)
	}
	if sawOuter {
		t.Fatalf("outer prefix validated from nested records: %+v", snapshot.Targets)
	}
	if !hasIssue(snapshot, outer) {
		t.Fatalf("outer invalid prefix must carry an issue: %+v", snapshot.Issues)
	}
}

// TestHostUnrelatedSubtreeDoesNotAffectPrefixValidation: a symlink cycle under a
// directory unrelated to conda-meta (which the metadata-only resolver never walks)
// must not make a valid prefix partial or unknown. Symlink loops are used instead of
// permission bits, so the test does not depend on the runner's privileges.
func TestHostUnrelatedSubtreeDoesNotAffectPrefixValidation(t *testing.T) {
	prefix := hostPrefix(t)
	unrelated := filepath.Join(prefix, "lib", "site-packages")
	if err := os.MkdirAll(unrelated, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(unrelated, filepath.Join(unrelated, "loop")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"prefixes"}})
	if err != nil {
		t.Fatalf("unrelated subtree broke collection: %v", err)
	}
	if len(snapshot.Targets) != 1 || snapshot.Targets[0].Coverage["prefixes"] != Complete {
		t.Fatalf("valid prefix degraded by unrelated subtree: %+v", snapshot)
	}
	if len(snapshot.Issues) != 0 {
		t.Fatalf("unrelated subtree produced issues: %+v", snapshot.Issues)
	}
}

func TestHostMetadataValidationDoesNotFollowRecordLinks(t *testing.T) {
	prefix := hostPrefix(t)
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(hostRecordJSON("outside", "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(prefix, "conda-meta", "alias.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	records, err := condaRecordsForPrefix(context.Background(), prefix)
	if err == nil || len(records) != 1 || records[0].Record.Name == "outside" {
		t.Fatalf("metadata validation followed a record link: %+v, %v", records, err)
	}
}

func hostRecordJSON(name, extra string) string {
	ownership := `,"files":[]`
	if strings.Contains(extra, `"files"`) || strings.Contains(extra, `"paths_data"`) {
		ownership = ""
	}
	return fmt.Sprintf(`{"name":%q,"version":"1","build":"0","build_number":0,"subdir":"linux-64","fn":%q,"url":%q%s%s}`, name, name+"-1-0.conda", "https://conda.anaconda.org/conda-forge/linux-64/"+name+"-1-0.conda", ownership, extra)
}

func hasIssue(snapshot Snapshot, path string) bool {
	for _, issue := range snapshot.Issues {
		if issue.Path == path {
			return true
		}
	}
	return false
}
