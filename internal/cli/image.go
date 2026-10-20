package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/inventory"
	"github.com/spf13/cobra"
)

func validateImageArgs(source, platform string, inputs []string) error {
	switch source {
	case "dir":
		if platform != "" {
			return fmt.Errorf("--platform is only valid with --source oci-archive")
		}
	case "oci-archive":
		if len(inputs) != 1 {
			return fmt.Errorf("--source oci-archive requires exactly one archive path")
		}
		if platform == "" {
			return fmt.Errorf("--source oci-archive requires --platform OS/ARCH[/VARIANT]")
		}
	default:
		return fmt.Errorf("unsupported source %q: use dir or oci-archive", source)
	}
	return nil
}

func runImage(cmd *cobra.Command, input, platform string, scan, jsonOutput, noColor bool) (err error) {
	started := time.Now()
	signalCtx, stopSignals := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	// Restore the default signal behavior after the first cancellation so a
	// second Ctrl-C can terminate indexing that is not promptly interruptible.
	go func() { <-signalCtx.Done(); stopSignals() }()
	ctx, cancel := context.WithTimeout(signalCtx, 5*time.Minute)
	defer cancel()
	status := startStatus(cmd.ErrOrStderr(), func() string { return "Image: validating and loading OCI archive" })
	loaded, err := imageinput.Load(ctx, input, platform)
	status.close()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, loaded.Close()) }()
	loadDuration := time.Since(started)
	status = startStatus(cmd.ErrOrStderr(), func() string { return "Image: inspecting final filesystem" })
	report, err := discovery.FindImageConda(ctx, loaded.Image)
	status.close()
	if err != nil {
		return err
	}
	var result inventory.Result
	var scanErr error
	if scan {
		outputDir, err := filepath.Abs("sboms")
		if err != nil {
			return err
		}
		status = startStatus(cmd.ErrOrStderr(), func() string { return "Image: generating whole-image SBOM" })
		result, scanErr = inventory.WriteImage(ctx, loaded.Image, input, outputDir)
		status.close()
	}
	if jsonOutput {
		output := struct {
			discovery.ImageReport
			Image imageinput.Identity `json:"image"`
		}{report, loaded.Identity}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(output); err != nil {
			return err
		}
	} else {
		id := loaded.Identity
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Image evidence | %s\n  Source: %s\n  Input: %s\n  Manifest: %s\n  Config: %s\n  Platform: %s/%s", started.Format(time.RFC3339), id.Source, id.Input, id.ManifestDigest, id.ConfigDigest, id.OS, id.Architecture); err != nil {
			return err
		}
		if id.Variant != "" {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "/%s", id.Variant); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(cmd.OutOrStdout(), "\n  Scope: final squashed image filesystem (not a running container)\n\n"); err != nil {
			return err
		}
		table := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', tabwriter.StripEscape)
		if _, err := fmt.Fprintln(table, "NAME\tREV\tIMAGE PREFIX"); err != nil {
			return err
		}
		color := !noColor && os.Getenv("NO_COLOR") == "" && isTerminal(cmd.OutOrStdout())
		for _, env := range report.Environments {
			if _, err := fmt.Fprintf(table, "%s\t%s\t%s\n", env.Name, formatRevision(env.Revision, color), env.Path); err != nil {
				return err
			}
		}
		if err := table.Flush(); err != nil {
			return err
		}
		if scan {
			if scanErr != nil {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "SBOM: not written (%v)\n", scanErr); err != nil {
					return err
				}
			} else {
				version := result.SyftVersion
				if version == "" {
					version = "unknown"
				}
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "SBOM: %s\nSyft: %s; %d unique packages observed (%d conda, %d installed Python metadata, %d other); %d unknown file coordinates\n", result.Path, version, result.Total, result.Conda, result.PythonInstalled, result.Other, result.Unknowns); err != nil {
					return err
				}
			}
		}
		state := "completed"
		if len(report.Issues) > 0 || scanErr != nil || result.Unknowns > 0 {
			state = "incomplete"
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Summary: %s; %d conda prefixes, %d discovery issues\nTiming: load/preflight %s; total %s\nCoverage: final image only; package counts are observations, not verified totals.\n", state, len(report.Environments), len(report.Issues), loadDuration.Round(time.Millisecond), time.Since(started).Round(time.Millisecond)); err != nil {
			return err
		}
	}
	for _, issue := range report.Issues {
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: image path %s: %s\n", issue.Path, issue.Error); err != nil {
			return err
		}
	}
	if scanErr != nil {
		return scanErr
	}
	if len(report.Issues) > 0 || result.Unknowns > 0 {
		return fmt.Errorf("image inspection incomplete: %d discovery issues, %d unknown file coordinates", len(report.Issues), result.Unknowns)
	}
	return nil
}
