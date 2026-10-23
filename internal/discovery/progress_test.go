package discovery

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestWithProgressNilReturnsOriginalContext(t *testing.T) {
	type testKey struct{}
	ctx := context.WithValue(context.Background(), testKey{}, "v")
	if got := WithProgress(ctx, nil); got != ctx {
		t.Fatal("nil progress must return the original context")
	}
	if progressFrom(ctx) != nil {
		t.Fatal("no progress must be attached for a nil Progress")
	}
}

func TestProgressFromRoundTrip(t *testing.T) {
	var p Progress
	ctx := WithProgress(context.Background(), &p)
	if progressFrom(ctx) != &p {
		t.Fatal("progressFrom did not return the attached Progress")
	}
	if progressFrom(context.Background()) != nil {
		t.Fatal("unattached context must yield nil progress")
	}
}

func TestFindProgressCountsFoldersAndEnvironments(t *testing.T) {
	root := knownTempDir(t)
	makePrefix(t, filepath.Join(root, "a"))
	makePrefix(t, filepath.Join(root, "b", "c"))
	if err := os.MkdirAll(filepath.Join(root, ".git", "x"), 0o755); err != nil {
		t.Fatal(err)
	}

	var p Progress
	report, err := Find(WithProgress(context.Background(), &p), []string{root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Environments.Load(); got != uint64(len(report.Environments)) || got != 2 {
		t.Fatalf("environments counter=%d report=%d, want 2", got, len(report.Environments))
	}
	// The pruned .git entry is examined; its children are never walked.
	if got := p.Folders.Load(); got < 4 {
		t.Fatalf("folders counter=%d, want at least the walked directories", got)
	}
}

func TestFindProgressEnvironmentDedupeWithinRun(t *testing.T) {
	root := knownTempDir(t)
	makePrefix(t, filepath.Join(root, "env"))
	// The same root given twice is deduplicated into one walk, so the environment counts once.
	var p Progress
	report, err := Find(WithProgress(context.Background(), &p), []string{root, root}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || p.Environments.Load() != 1 {
		t.Fatalf("environments=%d counter=%d, want 1", len(report.Environments), p.Environments.Load())
	}
}

func TestFindProgressAdditiveAcrossCallsSharingContext(t *testing.T) {
	root := knownTempDir(t)
	makePrefix(t, filepath.Join(root, "env"))
	var p Progress
	ctx := WithProgress(context.Background(), &p)
	if _, err := Find(ctx, []string{root}, false); err != nil {
		t.Fatal(err)
	}
	first := p.Environments.Load()
	if _, err := Find(ctx, []string{root}, false); err != nil {
		t.Fatal(err)
	}
	if got := p.Environments.Load(); got != 2*first || first != 1 {
		t.Fatalf("environments=%d after two runs, want additive 2x%d", got, first)
	}
}

func TestFindKnownProgressCountsExaminedDirectories(t *testing.T) {
	home := knownTempDir(t)
	container := filepath.Join(home, ".conda", "envs")
	makePrefix(t, filepath.Join(container, "one"))
	makePrefix(t, filepath.Join(container, "two"))

	var p Progress
	ctx := WithProgress(context.Background(), &p)
	report, err := findKnown(ctx, knownInputs{home: home, goos: "darwin", env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 2 || p.Environments.Load() != 2 {
		t.Fatalf("environments=%d counter=%d, want 2", len(report.Environments), p.Environments.Load())
	}
	if p.Folders.Load() == 0 {
		t.Fatal("known probing must count examined directories")
	}
}

func TestFindKnownProgressDedupesEnvironmentAcrossHints(t *testing.T) {
	home := knownTempDir(t)
	prefix := filepath.Join(home, "shared")
	makePrefix(t, prefix)
	// The same prefix named by two hints is probed once and counted once.
	var p Progress
	ctx := WithProgress(context.Background(), &p)
	report, err := findKnown(ctx, knownInputs{
		home: home, goos: "linux",
		env: map[string]string{"CONDA_PREFIX": prefix, "CONDA_ROOT": prefix},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Environments) != 1 || p.Environments.Load() != 1 {
		t.Fatalf("environments=%d counter=%d, want 1", len(report.Environments), p.Environments.Load())
	}
}

func TestPreCancelledProgressReadsNothing(t *testing.T) {
	root := knownTempDir(t)
	makePrefix(t, filepath.Join(root, "env"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var p Progress
	ctx = WithProgress(ctx, &p)
	if _, err := Find(ctx, []string{root}, false); err == nil {
		t.Fatal("cancelled Find must return the context error")
	}
	if _, err := findKnown(ctx, knownInputs{home: root, goos: "linux"}); err == nil {
		t.Fatal("cancelled findKnown must return the context error")
	}
	if p.Folders.Load() != 0 || p.Environments.Load() != 0 {
		t.Fatalf("pre-cancelled run counted folders=%d environments=%d", p.Folders.Load(), p.Environments.Load())
	}
}

func TestNilProgressFindUnchanged(t *testing.T) {
	root := knownTempDir(t)
	makePrefix(t, filepath.Join(root, "env"))
	report, err := Find(WithProgress(context.Background(), nil), []string{root}, false)
	if err != nil || len(report.Environments) != 1 {
		t.Fatalf("environments=%d err=%v, want 1 nil", len(report.Environments), err)
	}
}

// TestProgressConcurrentReaders loads the counters from other goroutines while a walk runs.
// Run with -race: the counters are atomics, so reads during the walk must be race-free.
func TestProgressConcurrentReaders(t *testing.T) {
	root := knownTempDir(t)
	for i := 0; i < 20; i++ {
		makePrefix(t, filepath.Join(root, "p", string(rune('a'+i))))
	}
	var p Progress
	ctx := WithProgress(context.Background(), &p)

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last uint64
			for !stop.Load() {
				f := p.Folders.Load()
				if f < last {
					t.Error("folders counter went backwards")
					return
				}
				last = f
				_ = p.Environments.Load()
			}
		}()
	}
	if _, err := Find(ctx, []string{root}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := findKnown(ctx, knownInputs{home: root, goos: "linux"}); err != nil {
		t.Fatal(err)
	}
	stop.Store(true)
	wg.Wait()
	if p.Environments.Load() != 20 {
		t.Fatalf("environments=%d, want 20", p.Environments.Load())
	}
}

// BenchmarkFindProgress compares Find with and without instrumentation on the same tree,
// built once outside both sub-benchmarks. The enabled case validates the counters.
func BenchmarkFindProgress(b *testing.B) {
	root := buildSyntheticTree(b, 5000)
	b.Run("disabled", func(b *testing.B) {
		ctx := WithProgress(context.Background(), nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			report, err := Find(ctx, []string{root}, false)
			if err != nil || len(report.Environments) != 5 {
				b.Fatalf("environments=%d err=%v", len(report.Environments), err)
			}
		}
	})
	b.Run("enabled", func(b *testing.B) {
		var p Progress
		ctx := WithProgress(context.Background(), &p)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			report, err := Find(ctx, []string{root}, false)
			if err != nil || len(report.Environments) != 5 {
				b.Fatalf("environments=%d err=%v", len(report.Environments), err)
			}
		}
		if p.Folders.Load() == 0 || p.Environments.Load() == 0 {
			b.Fatalf("progress not recorded folders=%d environments=%d", p.Folders.Load(), p.Environments.Load())
		}
	})
}
