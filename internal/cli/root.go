// Package cli provides the envscout command-line interface.
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// New constructs the root command without performing any filesystem operations.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:           "envscout",
		Short:         "Discover Python environments and inventory selected targets",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	var noColor bool
	var jsonOutput bool
	find := &cobra.Command{
		Use:   "find [ROOT...]",
		Short: "Find installed conda environments in known locations or explicit roots",
		RunE: func(cmd *cobra.Command, roots []string) error {
			var report discovery.Report
			var err error
			if len(roots) == 0 {
				report, err = discovery.FindKnownCondaWithProgress(nil)
			} else {
				report, err = findCondaWithStatus(roots, cmd.ErrOrStderr())
			}
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
				if len(report.Issues) > 0 {
					return fmt.Errorf("discovery incomplete: %d path(s) could not be inspected", len(report.Issues))
				}
				return nil
			}
			color := !noColor && os.Getenv("NO_COLOR") == "" && isTerminal(cmd.OutOrStdout())
			if report.Mode == discovery.ModeKnownLocations {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Known locations only (not a full filesystem scan)"); err != nil {
					return err
				}
			}
			out := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', tabwriter.StripEscape)
			if _, err := fmt.Fprintln(out, "NAME\tREV\tLOCATION"); err != nil {
				return err
			}
			for _, env := range report.Environments {
				rev := formatRevision(env.Revision, color)
				if _, err := fmt.Fprintf(out, "%s\t%s\t%s\n", env.Name, rev, env.Path); err != nil {
					return err
				}
			}
			if err := out.Flush(); err != nil {
				return err
			}
			if len(report.Environments) == 0 {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "No installed conda environments found."); err != nil {
					return err
				}
			}
			for _, issue := range report.Issues {
				if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s\n", issue.Path, issue.Error); err != nil {
					return err
				}
			}
			if len(report.Issues) > 0 {
				return fmt.Errorf("discovery incomplete: %d path(s) could not be inspected", len(report.Issues))
			}
			return nil
		},
	}
	find.Flags().BoolVar(&noColor, "no-color", false, "disable colored revision numbers")
	find.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON report, including scope and coverage issues")
	root.AddCommand(find)
	root.AddCommand(&cobra.Command{
		Use:   "scan ROOT...",
		Short: "Find conda environments and write one local SBOM per environment",
		Args:  cobra.MinimumNArgs(1),
		RunE:  runScan,
	})
	return root
}

func isTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(file.Fd()))
}

func revisionColor(rev int) string {
	switch {
	case rev == 0:
		return "\x1b[32m"
	case rev < 3:
		return "\x1b[33m"
	case rev < 6:
		return "\x1b[38;5;208m"
	default:
		return "\x1b[31m"
	}
}

func formatRevision(revision *int, color bool) string {
	if revision == nil {
		return "?"
	}
	rev := strconv.Itoa(*revision)
	if color {
		return "\xff" + revisionColor(*revision) + "\xff" + rev + "\xff\x1b[0m\xff"
	}
	return rev
}
