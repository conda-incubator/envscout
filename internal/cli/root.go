// Package cli provides the envscout command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/inventory"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// commandOptions holds the persistent flags shared by every subcommand.
type commandOptions struct {
	source    string
	format    string
	platform  string
	noColor   bool
	outputDir string
}

// New constructs the root command without performing any filesystem operations.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:           "envscout",
		Short:         "Discover Python environments and inventory selected targets",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	opts := &commandOptions{source: "dir", format: "text", outputDir: "sboms"}
	flags := root.PersistentFlags()
	flags.Var(newEnumValue(&opts.source, "dir", "oci-archive"), "source", "input source: dir or oci-archive (offline)")
	flags.Var(newEnumValue(&opts.format, "text", "json"), "format", "output format: text or json")
	flags.StringVar(&opts.platform, "platform", "", "required for oci-archive: OS/ARCH[/VARIANT]")
	flags.BoolVar(&opts.noColor, "no-color", false, "disable colored output")
	flags.StringVar(&opts.outputDir, "output-dir", opts.outputDir, "directory for SBOM output (scan only)")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return inputError(err) })
	// Only scan writes SBOMs, so an explicit --output-dir elsewhere would be silently ignored.
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Name() != "scan" && cmd.Flags().Changed("output-dir") {
			return inputError(fmt.Errorf("--output-dir is only valid for scan"))
		}
		return nil
	}
	root.AddCommand(findCommand(opts), scanCommand(opts), lintCommand(opts))
	return root
}

// validateImageArgs enforces value-aware source and platform rules. Explicit dir
// takes no platform; oci-archive needs exactly one archive and a platform.
// Syntactic platform validation is delegated to the image loader.
func validateImageArgs(source, platform string, inputs []string) error {
	switch source {
	case "dir":
		if platform != "" {
			return inputError(errors.New("--platform is only valid with --source oci-archive"))
		}
	case "oci-archive":
		if len(inputs) != 1 {
			return inputError(errors.New("--source oci-archive requires exactly one archive path"))
		}
		if platform == "" {
			return inputError(errors.New("--source oci-archive requires --platform OS/ARCH[/VARIANT]"))
		}
	default:
		return inputError(fmt.Errorf("unsupported source %q: use dir or oci-archive", source))
	}
	return nil
}

// findCommand lists conda environments. Without roots it inspects known
// locations (not a full filesystem scan); with an OCI archive it reads the image.
func findCommand(opts *commandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "find [ROOT...]",
		Short: "Find conda environments in local directories or an OCI image archive",
		RunE: func(cmd *cobra.Command, roots []string) error {
			if err := validateImageArgs(opts.source, opts.platform, roots); err != nil {
				return err
			}
			if opts.source == "oci-archive" {
				ctx, cancel := operationContext(cmd.Context())
				defer cancel()
				report, err := inventory.InspectImage(ctx, roots[0], opts.platform, "")
				if err != nil && opts.format == "text" && report.Image.ManifestDigest == "" {
					return err
				}
				return errors.Join(renderImage(cmd, opts, report, false), err)
			}
			ctx, stopProgress := startDiscoveryProgress(cmd.Context(), cmd.ErrOrStderr(), opts.format == "text")
			report, err := findLocal(ctx, roots)
			err = errors.Join(err, stopProgress())
			// Cancellation keeps any partial evidence: environments found before the
			// walk stopped are still rendered. A walk with nothing recorded, or any
			// other failure, returns the error alone.
			partial := len(report.Environments) > 0 || len(report.Issues) > 0
			if err != nil && (cmd.Context().Err() == nil || !partial) {
				return err
			}
			return errors.Join(renderFind(cmd, opts, report), err)
		},
	}
}

// findLocal discovers explicit roots, or known locations when none are given.
// Both discovery entry points are context-aware and return partial reports with
// the cancellation error.
func findLocal(ctx context.Context, roots []string) (discovery.Report, error) {
	if len(roots) > 0 {
		return discovery.Find(ctx, roots, true)
	}
	return discovery.FindKnown(ctx)
}

// renderFind writes the discovery report. Partial discovery is rendered before
// any domain error is returned by the caller.
func renderFind(cmd *cobra.Command, opts *commandOptions, report discovery.Report) error {
	if opts.format == "json" {
		if err := encodeJSON(cmd.OutOrStdout(), report); err != nil {
			return err
		}
	} else if err := renderFindText(cmd, opts, report); err != nil {
		return err
	}
	warnings := newPrinter(cmd.ErrOrStderr())
	renderIssues(warnings, "", report.Issues)
	if err := warnings.Err(); err != nil {
		return err
	}
	if len(report.Issues) > 0 {
		return fmt.Errorf("discovery incomplete: %d path(s) could not be inspected", len(report.Issues))
	}
	return nil
}

func renderFindText(cmd *cobra.Command, opts *commandOptions, report discovery.Report) error {
	out := newPrinter(cmd.OutOrStdout())
	if report.Mode == discovery.ModeKnownLocations {
		out.Println("Known locations only (not a full filesystem scan)")
	}
	if len(report.Environments) == 0 {
		out.Println("No installed conda environments found.")
	}
	if err := out.Err(); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Environments))
	for _, env := range report.Environments {
		rows = append(rows, []string{lintText(env.Name), revisionCell(env.Revision, cmd.OutOrStdout(), opts.noColor), lintText(env.Path)})
	}
	return printRows(cmd.OutOrStdout(), []string{"NAME", "REV", "LOCATION"}, rows)
}

// printRows writes an aligned table with a header row, two spaces between columns.
// ANSI-aware display widths keep colored and wide-character cells aligned.
func printRows(out io.Writer, header []string, rows [][]string) error {
	all := append([][]string{header}, rows...)
	widths := make([]int, len(header))
	for _, row := range all {
		for i, cell := range row {
			widths[i] = max(widths[i], ansi.StringWidth(cell))
		}
	}
	p := newPrinter(out)
	for _, row := range all {
		var line strings.Builder
		for i, cell := range row {
			line.WriteString(cell)
			if i < len(row)-1 {
				line.WriteString(strings.Repeat(" ", widths[i]-ansi.StringWidth(cell)+2))
			}
		}
		p.Printf("%s\n", line.String())
	}
	return p.Err()
}

// revisionCell formats a revision for an ANSI-aware table.
func revisionCell(revision *int, writer io.Writer, noColor bool) string {
	if revision == nil {
		return "?"
	}
	text := strconv.Itoa(*revision)
	return colour(writer, noColor, text, revisionAttribute(*revision))
}

// revisionAttribute maps a revision count to a color: newest green, oldest red.
func revisionAttribute(revision int) color.Attribute {
	switch {
	case revision == 0:
		return color.FgGreen
	case revision < 3:
		return color.FgYellow
	case revision < 6:
		return color.FgHiYellow
	default:
		return color.FgRed
	}
}
