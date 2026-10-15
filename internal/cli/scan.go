package cli

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/anaconda/envscout/internal/inventory"
	"github.com/spf13/cobra"
)

func runScan(cmd *cobra.Command, roots []string) error {
	started := time.Now()
	report, err := findCondaWithStatus(roots, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	discoveryDuration := time.Since(started)
	outputDir, err := filepath.Abs("sboms")
	if err != nil {
		return err
	}
	type observation struct {
		env      discovery.Environment
		result   inventory.Result
		duration time.Duration
		pixi     string
		err      error
	}
	observations := make([]observation, 0, len(report.Environments))
	var processed atomic.Uint64
	status := startStatus(cmd.ErrOrStderr(), func() string {
		return fmt.Sprintf("SBOMs processed: %d/%d", processed.Load(), len(report.Environments))
	})
	for _, env := range report.Environments {
		start := time.Now()
		result, scanErr := inventory.WriteConda(cmd.Context(), env, outputDir)
		item := observation{env: env, result: result, duration: time.Since(start), err: scanErr}
		if scanErr == nil {
			item.pixi = pixiLockSummary(env.Path)
		}
		observations = append(observations, item)
		processed.Add(1)
	}
	status.close()

	out := cmd.OutOrStdout()
	if _, err := fmt.Fprintf(out, "Scan evidence | %s\n\n", started.Format(time.RFC3339)); err != nil {
		return err
	}
	failures := 0
	for _, item := range observations {
		if _, err := fmt.Fprintf(out, "%s  (revision %s)\n  Prefix: %s\n  Duration: %s\n", item.env.Name, formatRevision(item.env.Revision, false), item.env.Path, item.duration.Round(time.Millisecond)); err != nil {
			return err
		}
		if item.err != nil {
			failures++
			if _, err := fmt.Fprintf(out, "  SBOM: not written (%v)\n\n", item.err); err != nil {
				return err
			}
			continue
		}
		version := item.result.SyftVersion
		if version == "" {
			version = "unknown"
		}
		if _, err := fmt.Fprintf(out, "  Syft: %s; directory source; %d conda, %d installed Python metadata, %d other packages observed\n  SBOM: %s\n", version, item.result.Conda, item.result.PythonInstalled, item.result.Other, item.result.Path); err != nil {
			return err
		}
		if item.pixi != "" {
			if _, err := fmt.Fprintf(out, "  %s\n", item.pixi); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out, "Searched roots:"); err != nil {
		return err
	}
	for _, root := range report.Roots {
		if _, err := fmt.Fprintf(out, "  %s\n", root); err != nil {
			return err
		}
	}
	state := "complete"
	if failures > 0 || len(report.Issues) > 0 {
		state = "incomplete"
	}
	if _, err := fmt.Fprintf(out, "Summary: %s; %d conda environments found, %d SBOMs written, %d failed scans, %d discovery issues\n", state, len(report.Environments), len(report.Environments)-failures, failures, len(report.Issues)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Timing: discovery %s; total %s\n", discoveryDuration.Round(time.Millisecond), time.Since(started).Round(time.Millisecond)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Coverage: conda prefixes within requested roots only; package counts are Syft observations, not verified totals."); err != nil {
		return err
	}
	for _, issue := range report.Issues {
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s\n", issue.Path, issue.Error); err != nil {
			return err
		}
	}
	if failures > 0 || len(report.Issues) > 0 {
		return fmt.Errorf("scan incomplete: %d failed target(s), %d discovery issue(s)", failures, len(report.Issues))
	}
	return nil
}
