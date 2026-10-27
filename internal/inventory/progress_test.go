package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestScanProgressCountsSerialOutcomes(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "a"))
	writeCondaPrefix(t, filepath.Join(root, "b"))
	progress := &Progress{}
	output := t.TempDir()
	ctx := WithProgress(context.Background(), progress)
	report, err := Scan(ctx, []string{root}, output)
	if err != nil || len(report.Observations) != 2 {
		t.Fatalf("scan failed: %+v %v", report, err)
	}
	if !progress.Started.Load() || progress.Total.Load() != 2 || progress.Finished.Load() != 2 || progress.Failed.Load() != 0 || progress.Active.Load() != 0 {
		t.Fatalf("wrong completed counters: total=%d finished=%d failed=%d active=%d", progress.Total.Load(), progress.Finished.Load(), progress.Failed.Load(), progress.Active.Load())
	}
	if progress.Cataloged.Load() != 2 || progress.CatalogDuration.Load() <= 0 || progress.ActiveStarted.Load() != 0 {
		t.Fatal("remaining-time estimates need actual completed catalog durations and no stale active timestamp")
	}
	// Existing outputs complete as pre-existing, without recataloging or failure.
	progress = &Progress{}
	_, err = Scan(WithProgress(context.Background(), progress), []string{root}, output)
	if err != nil || progress.Finished.Load() != 2 || progress.Failed.Load() != 0 || progress.PreExisting.Load() != 2 || progress.Active.Load() != 0 {
		t.Fatalf("pre-existing attempts must complete without counting as failures: %v", err)
	}
	if progress.Cataloged.Load() != 0 || progress.CatalogDuration.Load() != 0 {
		t.Fatal("pre-existing skips must not supply scan-rate samples")
	}
}

func TestScanProgressCancellationSettlesActiveAttempt(t *testing.T) {
	root := t.TempDir()
	writeCondaPrefix(t, filepath.Join(root, "a"))
	writeCondaPrefix(t, filepath.Join(root, "b"))
	progress := &Progress{}
	cause := errors.New("operator stop")
	output := t.TempDir()
	ctx := WithProgress(newCancelWhenFileExists(output, cause), progress)
	report, err := Scan(ctx, []string{root}, output)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || len(report.Observations) != 1 {
		t.Fatalf("cancellation must retain the original serial result behavior: %+v %v", report, err)
	}
	if progress.Total.Load() != 2 || progress.Finished.Load() != 1 || progress.Failed.Load() != 1 || progress.Active.Load() != 0 {
		t.Fatal("canceled active attempt must settle, without counting the unstarted target")
	}
	if progress.Cataloged.Load() != 0 || progress.CatalogDuration.Load() != 0 || progress.ActiveStarted.Load() != 0 {
		t.Fatal("failed or canceled attempts must not supply scan-rate samples or leave an active timer")
	}
}

func TestScanProgressDisabledAndPreflight(t *testing.T) {
	ctx := context.Background()
	if WithProgress(ctx, nil) != ctx || progressFrom(ctx) != nil {
		t.Fatal("disabled counters must be a no-op")
	}
	progress := &Progress{}
	_, err := Scan(WithProgress(ctx, progress), []string{t.TempDir()}, "")
	if err == nil || progress.Started.Load() || progress.Total.Load() != 0 {
		t.Fatal("failed preflight must not start the SBOM phase")
	}
	_, err = Scan(WithProgress(ctx, progress), []string{t.TempDir()}, t.TempDir())
	if err != nil || !progress.Started.Load() || progress.Total.Load() != 0 || progress.Active.Load() != 0 {
		t.Fatal("empty discovery starts and completes the zero-target phase")
	}
}
