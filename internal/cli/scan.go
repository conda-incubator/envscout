package cli

import (
	"errors"
	"strconv"
	"time"

	"github.com/anaconda/envscout/internal/inventory"
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
				ctx, cancel := operationContext(cmd.Context())
				defer cancel()
				report, err := inventory.InspectImage(ctx, inputs[0], opts.platform, opts.outputDir)
				if err != nil && opts.format == "text" && report.Image.ManifestDigest == "" {
					return err
				}
				return errors.Join(renderImage(cmd, opts, report, true), err)
			}
			report, err := inventory.ScanConda(cmd.Context(), inputs, opts.outputDir)
			// A text report with nothing recorded would be misleading; the error alone is the answer.
			if err != nil && opts.format == "text" && len(report.Discovery.Environments) == 0 && len(report.Discovery.Issues) == 0 && len(report.Observations) == 0 {
				return err
			}
			return errors.Join(renderScan(cmd, opts, report), err)
		},
	}
}

// renderScan writes the directory scan. It returns only rendering errors; the
// caller joins the domain error that ScanConda returned.
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
	failures := 0
	for _, observation := range report.Observations {
		env := observation.Environment
		out.Printf("%s  (revision %s)\n  Prefix: %s\n  Duration: %s\n", lintText(env.Name), formatRevision(env.Revision), lintText(env.Path), observation.Duration.Round(time.Millisecond))
		if observation.Error != "" {
			failures++
			out.Printf("  SBOM: not written (%s)\n\n", lintText(observation.Error))
			continue
		}
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
	out.Printf("Summary: %s; %d conda environments found, %d SBOMs written, %d failed scans, %d discovery issues\n", report.Status, environments, len(report.Observations)-failures, failures, len(report.Discovery.Issues))
	out.Printf("Timing: discovery %s; total %s\n", report.DiscoveryDuration.Round(time.Millisecond), report.TotalDuration.Round(time.Millisecond))
	out.Println("Coverage: conda prefixes within requested roots only; package counts are Syft observations, not verified totals.")
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
