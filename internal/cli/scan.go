package cli

import (
	"errors"
	"strconv"
	"time"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/inventory"
	"github.com/spf13/cobra"
)

func scanCommand(opts *commandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "scan ROOT...",
		Short: "Write prefix SBOMs for directories or one whole-image SBOM for an OCI archive",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, inputs []string) error {
			if cmd.Flags().Changed("output-dir") && opts.outputDir == "" {
				return inputError(errors.New("--output-dir must not be empty"))
			}
			if err := validateImageArgs(opts.source, opts.platform, inputs); err != nil {
				return err
			}
			// The domain resolves a relative output directory against the working
			// directory and returns any incomplete-scan error; the CLI only renders.
			if opts.source == "oci-archive" {
				return runImage(cmd, opts, inputs[0], true)
			}
			ctx, stopProgress := startScanProgress(cmd.Context(), cmd.ErrOrStderr(), opts.format == "text")
			report, err := inventory.Scan(ctx, inputs, opts.outputDir)
			err = errors.Join(err, stopProgress())
			// A text report with nothing recorded would be misleading; the error alone is the answer.
			if err != nil && opts.format == "text" && len(report.Discovery.Environments) == 0 && len(report.Discovery.Issues) == 0 && len(report.Observations) == 0 {
				return err
			}
			return errors.Join(renderScan(cmd, opts, report), err)
		},
	}
}

// renderScan writes the directory scan. It returns only rendering errors; the
// caller joins the domain error that Scan returned.
func renderScan(cmd *cobra.Command, opts *commandOptions, report inventory.ScanReport) error {
	if opts.format == "json" {
		if err := encodeJSON(cmd.OutOrStdout(), report); err != nil {
			return err
		}
	} else if err := renderScanText(cmd, report); err != nil {
		return err
	}
	warnings := newPrinter(cmd.ErrOrStderr())
	renderIssues(warnings, "", report.Discovery.Issues)
	return warnings.Err()
}

func renderScanText(cmd *cobra.Command, report inventory.ScanReport) error {
	out := newPrinter(cmd.OutOrStdout())
	out.Printf("Scan evidence | %s\n\n", report.Started.Format(time.RFC3339))
	failures, written, preExisting := 0, 0, 0
	for _, observation := range report.Observations {
		env := observation.Environment
		if env.Kind == discovery.KindVenv {
			out.Printf("%s  (venv)\n", lintText(env.Name))
		} else {
			out.Printf("%s  (revision %s)\n", lintText(env.Name), formatRevision(env.Revision))
		}
		out.Printf("  Prefix: %s\n  Duration: %s\n", lintText(env.Path), observation.Duration.Round(time.Millisecond))
		if observation.Result.PreExisting {
			preExisting++
			out.Printf("  SBOM: pre-existing (not rescanned): %s\n\n", lintText(observation.Result.Path))
			continue
		}
		if observation.Error != "" {
			failures++
			out.Printf("  SBOM: not written (%s)\n\n", lintText(observation.Error))
			continue
		}
		written++
		result := observation.Result
		out.Printf("  Syft: %s; directory source; %d conda, %d installed Python metadata, %d other packages observed\n  SBOM: %s\n", syftVersion(result.SyftVersion), result.Conda, result.PythonInstalled, result.Other, lintText(result.Path))
		if observation.Pixi != "" {
			out.Printf("  %s\n", lintText(observation.Pixi))
		}
		out.Println()
	}
	out.Println("Searched roots:")
	for _, root := range report.Discovery.Roots {
		out.Printf("  %s\n", lintText(root))
	}
	environments := len(report.Discovery.Environments)
	out.Printf("Summary: %s; %d environments found, %d SBOMs written, %d pre-existing SBOMs, %d failed scans, %d discovery issues\n", report.Status, environments, written, preExisting, failures, len(report.Discovery.Issues))
	out.Printf("Timing: discovery %s; total %s\n", report.DiscoveryDuration.Round(time.Millisecond), report.TotalDuration.Round(time.Millisecond))
	out.Println("Coverage: environment prefixes within requested roots only; package counts are Syft observations, not verified totals.")
	return out.Err()
}

func syftVersion(version string) string {
	if version == "" {
		return "unknown"
	}
	return version
}

// formatRevision returns the plain (uncolored) revision text.
func formatRevision(revision *int) string {
	if revision == nil {
		return "?"
	}
	return strconv.Itoa(*revision)
}
