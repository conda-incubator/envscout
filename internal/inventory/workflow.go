package inventory

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/imageinput"
)

// Status values reported by ScanReport and ImageReport.
const (
	StatusComplete   = "complete"
	StatusCompleted  = "completed"
	StatusIncomplete = "incomplete"
)

// ScanObservation records one discovered environment and its SBOM outcome.
// Result is zero when Error is set. Pixi is empty unless the prefix carries a
// Pixi marker that can be read.
type ScanObservation struct {
	Environment discovery.Environment `json:"environment"`
	Result      Result                `json:"result"`
	Duration    time.Duration         `json:"duration_ns"`
	Pixi        string                `json:"pixi,omitempty"`
	Error       string                `json:"error,omitempty"`
}

// ScanReport is the business outcome of Scan, independent of any output format.
type ScanReport struct {
	Source            string            `json:"source"`
	Started           time.Time         `json:"started_at"`
	Discovery         discovery.Report  `json:"discovery"`
	Observations      []ScanObservation `json:"observations"`
	DiscoveryDuration time.Duration     `json:"discovery_duration_ns"`
	TotalDuration     time.Duration     `json:"total_duration_ns"`
	Status            string            `json:"status"`
	Error             string            `json:"error,omitempty"`
}

// Scan discovers environments under roots and writes one CycloneDX SBOM per
// environment into outputDir. A relative outputDir is resolved to an absolute path.
// Existing SBOMs are never overwritten. Per-target failures and discovery issues are
// recorded in the report and returned as an ordinary "scan incomplete" error while
// successful observations and files are preserved. Context cancellation stops further
// launches and returns the cancellation cause wrapped, so errors.Is holds for both
// context.Canceled and custom causes. Bad roots return a discovery error.
func Scan(ctx context.Context, roots []string, outputDir string) (report ScanReport, err error) {
	started := time.Now()
	report = ScanReport{
		Source:       "dir",
		Started:      started,
		Discovery:    discovery.Report{Roots: []string{}, Hints: []discovery.HintSummary{}, Environments: []discovery.Environment{}, Issues: []discovery.Issue{}},
		Observations: []ScanObservation{},
		Status:       StatusIncomplete,
	}
	defer func() {
		report.TotalDuration = time.Since(started)
		if err != nil {
			report.Error = err.Error()
		}
	}()
	if outputDir == "" {
		return report, fmt.Errorf("output directory must not be empty")
	}
	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		report.TotalDuration = time.Since(started)
		return report, fmt.Errorf("resolve output directory: %w", err)
	}
	discovered, err := discovery.Find(ctx, roots, true)
	report.Discovery = discovered
	report.DiscoveryDuration = time.Since(started)
	if err != nil {
		report.TotalDuration = time.Since(started)
		return report, err
	}
	progress := progressFrom(ctx)
	if progress != nil {
		progress.Total.Store(uint64(len(discovered.Environments)))
		progress.Started.Store(true)
	}
	for _, env := range discovered.Environments {
		if err := ctx.Err(); err != nil {
			return finishScan(ctx, report, started, err)
		}
		start := time.Now()
		if progress != nil {
			progress.ActiveStarted.Store(start.UnixNano())
			progress.Active.Store(1)
		}
		result, err := WriteEnvironment(ctx, env, absOutput)
		observation := ScanObservation{Environment: env, Result: result, Duration: time.Since(start)}
		if err != nil {
			observation.Error = err.Error()
			observation.Result = Result{}
		} else if !result.PreExisting {
			if env.Kind == discovery.KindConda {
				observation.Pixi = PixiLockSummary(env.Path)
			}
			// The SBOM is kept either way, but unknown coordinates or a prefix with no
			// valid conda record make the observation incomplete, so the scan exits non-zero.
			switch {
			case env.Kind == discovery.KindConda && result.Conda == 0:
				observation.Error = "no valid conda package metadata in prefix"
			case result.Unknowns > 0:
				observation.Error = fmt.Sprintf("%d unknown file coordinate(s) in SBOM", result.Unknowns)
			}
		}
		report.Observations = append(report.Observations, observation)
		if progress != nil {
			if observation.Result.PreExisting {
				progress.PreExisting.Add(1)
			} else if observation.Error != "" {
				progress.Failed.Add(1)
			} else {
				progress.CatalogDuration.Add(int64(observation.Duration))
				progress.Cataloged.Add(1)
			}
			progress.Finished.Add(1)
			progress.Active.Store(0)
			progress.ActiveStarted.Store(0)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return finishScan(ctx, report, started, ctxErr)
		}
	}
	return finishScan(ctx, report, started, nil)
}

// finishScan settles status and the returned error. Cancellation (either the
// caller's ctx or an error from the loop) takes precedence over ordinary failures.
func finishScan(ctx context.Context, report ScanReport, started time.Time, loopErr error) (ScanReport, error) {
	report.TotalDuration = time.Since(started)
	if loopErr != nil || ctx.Err() != nil {
		report.Status = StatusIncomplete
		cause := context.Cause(ctx)
		if cause == nil {
			cause = loopErr
		}
		return report, errors.Join(ctx.Err(), cause, fmt.Errorf("scan canceled after %d target(s)", len(report.Observations)))
	}
	failures := scanFailures(report)
	if failures > 0 || len(report.Discovery.Issues) > 0 {
		report.Status = StatusIncomplete
		return report, fmt.Errorf("scan incomplete: %d failed target(s), %d discovery issue(s)", failures, len(report.Discovery.Issues))
	}
	report.Status = StatusComplete
	return report, nil
}

func scanFailures(report ScanReport) int {
	failures := 0
	for _, observation := range report.Observations {
		if observation.Error != "" {
			failures++
		}
	}
	return failures
}

// ImageReport is the business outcome of InspectImage. Result is nil when no SBOM
// was requested or the scan failed; ScanError carries the scan failure text.
type ImageReport struct {
	discovery.Report
	Image         imageinput.Identity `json:"image"`
	Started       time.Time           `json:"started_at"`
	LoadDuration  time.Duration       `json:"load_duration_ns"`
	TotalDuration time.Duration       `json:"total_duration_ns"`
	Result        *Result             `json:"result,omitempty"`
	ScanError     string              `json:"scan_error,omitempty"`
	Status        string              `json:"status"`
	Error         string              `json:"error,omitempty"`
}

// InspectImage loads one OCI archive for platform, discovers conda prefixes in its
// final squashed filesystem, and, when outputDir is non-empty, writes a whole-image
// SBOM there (a relative outputDir is resolved to an absolute path). Empty outputDir
// performs discovery only. Partial discovery issues do not prevent the SBOM write.
// The caller supplies ctx; the image is always closed before returning, and a
// cleanup failure marks the report incomplete and is returned via errors.Join.
func InspectImage(ctx context.Context, input, platform, outputDir string) (report ImageReport, err error) {
	started := time.Now()
	report = ImageReport{
		Started: started,
		Report:  discovery.Report{SchemaVersion: 1, Source: "oci-archive", Scope: "squashed", Roots: []string{}, Hints: []discovery.HintSummary{}, Environments: []discovery.Environment{}, Issues: []discovery.Issue{}},
		Status:  StatusIncomplete,
	}
	defer func() {
		// Cleanup happens before this runs, so TotalDuration covers it.
		report.TotalDuration = time.Since(started)
		if err != nil {
			report.Error = err.Error()
		}
	}()
	var absOutput string
	if outputDir != "" {
		absOutput, err = filepath.Abs(outputDir)
		if err != nil {
			return report, fmt.Errorf("resolve output directory: %w", err)
		}
	}
	loaded, err := imageinput.Load(ctx, input, platform)
	if err != nil {
		return report, err
	}
	defer func() {
		closeErr := loaded.Close()
		if closeErr != nil {
			report.Status = StatusIncomplete
		}
		err = errors.Join(err, closeErr)
	}()
	report.Image = loaded.Identity
	report.LoadDuration = time.Since(started)

	found, err := discovery.FindImage(ctx, loaded.Image, true)
	report.Report = found
	if err != nil {
		return report, err
	}

	var scanErr error
	if absOutput != "" {
		result, writeErr := WriteImage(ctx, loaded.Image, input, absOutput)
		if writeErr != nil {
			scanErr = writeErr
			report.ScanError = writeErr.Error()
		} else {
			report.Result = &result
			if !result.PreExisting && len(found.Environments) > 0 && result.Conda == 0 {
				scanErr = fmt.Errorf("no valid conda package metadata in discovered image prefixes")
				report.ScanError = scanErr.Error()
			}
		}
	}
	report.Status = StatusCompleted
	if len(found.Issues) > 0 || scanErr != nil || (report.Result != nil && report.Result.Unknowns > 0) {
		report.Status = StatusIncomplete
	}
	if scanErr != nil {
		return report, scanErr
	}
	if len(found.Issues) > 0 || (report.Result != nil && report.Result.Unknowns > 0) {
		unknowns := 0
		if report.Result != nil {
			unknowns = report.Result.Unknowns
		}
		return report, fmt.Errorf("image inspection incomplete: %d discovery issues, %d unknown file coordinates", len(found.Issues), unknowns)
	}
	return report, nil
}
