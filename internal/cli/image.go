package cli

import (
	"errors"
	"time"

	"github.com/conda-incubator/envscout/internal/inventory"
	"github.com/spf13/cobra"
)

// runImage shares image inspection while keeping find read-only and scan inventory-enabled.
func runImage(cmd *cobra.Command, opts *commandOptions, input string, scan bool) error {
	outputDir := ""
	if scan {
		outputDir = opts.outputDir
	}
	ctx, cancel := operationContext(cmd.Context())
	defer cancel()
	report, err := inventory.InspectImage(ctx, input, opts.platform, outputDir)
	if err != nil && opts.format == "text" && report.Image.ManifestDigest == "" {
		return err
	}
	return errors.Join(renderImage(cmd, opts, report, scan), err)
}

// renderImage writes an image inspection and its warnings. scan reports whether an
// SBOM was requested. It returns only rendering errors; the caller joins the domain
// error from InspectImage so partial reports are visible first.
func renderImage(cmd *cobra.Command, opts *commandOptions, report inventory.ImageReport, scan bool) error {
	if opts.format == "json" {
		if err := encodeJSON(cmd.OutOrStdout(), report); err != nil {
			return err
		}
	} else if err := renderImageText(cmd, opts, report, scan); err != nil {
		return err
	}
	warnings := newPrinter(cmd.ErrOrStderr())
	if scan || opts.verbose {
		renderIssues(warnings, "image path ", report.Issues)
	}
	if !scan && len(report.Issues) > 0 && !opts.verbose {
		warnings.Printf("discovery incomplete: %d path(s) could not be inspected; use --verbose to see details\n", len(report.Issues))
	}
	return warnings.Err()
}

func renderImageText(cmd *cobra.Command, opts *commandOptions, report inventory.ImageReport, scan bool) error {
	out := newPrinter(cmd.OutOrStdout())
	id := report.Image
	platform := id.OS + "/" + id.Architecture
	if id.Variant != "" {
		platform += "/" + id.Variant
	}
	out.Printf("Image evidence | %s\n  Source: %s\n  Input: %s\n  Manifest: %s\n  Config: %s\n  Platform: %s\n", report.Started.Format(time.RFC3339), safeText(id.Source), safeText(id.Input), id.ManifestDigest, id.ConfigDigest, platform)
	out.Println("  Scope: final squashed image filesystem (not a running container)")
	out.Println()
	if err := out.Err(); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Environments))
	for _, env := range report.Environments {
		rows = append(rows, []string{safeText(env.Name), revisionCell(env.Revision, cmd.OutOrStdout(), opts.noColor), safeText(env.Path)})
	}
	if err := printRows(cmd.OutOrStdout(), []string{"NAME", "REV", "IMAGE PREFIX"}, rows); err != nil {
		return err
	}
	if scan {
		renderImageSBOM(out, report)
		written, preExisting, failed := 0, 0, 0
		if report.Result != nil {
			if report.Result.PreExisting {
				preExisting = 1
			} else {
				written = 1
			}
		}
		if report.ScanError != "" {
			failed = 1
		}
		out.Printf("Summary: %s; %d conda prefixes, %d SBOMs written, %d pre-existing SBOMs, %d failed scans, %d discovery issues\n", report.Status, len(report.Environments), written, preExisting, failed, len(report.Issues))
	} else {
		out.Printf("Summary: %s; %s; %d discovery issues\n", report.Status, environmentSummary(report.Environments), len(report.Issues))
	}
	out.Printf("Timing: load/preflight %s; total %s\nCoverage: final image only; package counts are observations, not verified totals.\n", report.LoadDuration.Round(time.Millisecond), report.TotalDuration.Round(time.Millisecond))
	return out.Err()
}

// renderImageSBOM reports the whole-image SBOM. A written SBOM is always shown with
// its path and counts, even when a later step made the inspection incomplete; the
// error text is shown separately so a kept file is never reported as missing.
func renderImageSBOM(out *printer, report inventory.ImageReport) {
	if result := report.Result; result != nil {
		if result.PreExisting {
			out.Printf("SBOM: pre-existing (not rescanned): %s\n", safeText(result.Path))
		} else {
			out.Printf("SBOM: %s\nSyft: %s; %d unique packages observed (%d conda, %d installed Python metadata, %d other); %d unknown file coordinates\n", safeText(result.Path), syftVersion(result.SyftVersion), result.Total, result.Conda, result.PythonInstalled, result.Other, result.Unknowns)
		}
		if report.ScanError != "" {
			out.Printf("SBOM warning: %s\n", safeText(report.ScanError))
		}
		return
	}
	if report.ScanError != "" {
		out.Printf("SBOM: not written (%s)\n", safeText(report.ScanError))
	}
}
