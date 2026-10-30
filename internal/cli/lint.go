package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	policy "github.com/conda-incubator/envscout/internal/lint"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// lintFlags are the lint-only settings. list-rules rejects every one of them
// when explicitly set, including values equal to their defaults.
type lintFlags struct {
	profile, failOn, configFile, runtimePrefix, project string
	rules, disabled                                     []string
	list                                                bool
}

// listConflicts are the flags that --list-rules refuses when explicitly set.
// --format and --no-color remain valid because they only affect rendering.
var listConflicts = []string{"source", "platform", "output-dir", "exclude", "profile", "fail-on", "config", "runtime-prefix", "project", "rule", "disable-rule"}

func lintCommand(opts *commandOptions) *cobra.Command {
	flags := &lintFlags{}
	cmd := &cobra.Command{
		Use:   "lint ROOT...",
		Short: "Evaluate evidence-based environment and image policies without creating SBOMs",
		Args: func(cmd *cobra.Command, inputs []string) error {
			if flags.list {
				if err := rejectListConflicts(cmd); err != nil {
					return err
				}
				if len(inputs) != 0 {
					return inputError(fmt.Errorf("--list-rules cannot be combined with targets"))
				}
				return nil
			}
			if len(inputs) == 0 {
				return inputError(fmt.Errorf("lint requires explicit roots or one OCI archive"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, inputs []string) error {
			return runLint(cmd, opts, flags, inputs)
		},
	}
	cmd.Flags().StringVar(&flags.profile, "profile", "", "local, container, container-runtime, container-development, container-distroless")
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "", "failure threshold: error, warning (default), info, or none")
	cmd.Flags().StringVar(&flags.configFile, "config", "", "explicit versioned JSON policy file")
	cmd.Flags().StringVar(&flags.runtimePrefix, "runtime-prefix", "", "asserted image runtime prefix")
	cmd.Flags().StringVar(&flags.project, "project", "", "explicit local project association for one prefix")
	cmd.Flags().StringArrayVar(&flags.rules, "rule", nil, "evaluate only this rule ID (repeatable)")
	cmd.Flags().StringArrayVar(&flags.disabled, "disable-rule", nil, "disable this rule ID (repeatable)")
	cmd.Flags().BoolVar(&flags.list, "list-rules", false, "list every registered rule, including unavailable ones, without inspecting targets")
	return cmd
}

// rejectListConflicts reports explicitly set flags that --list-rules forbids. It
// runs from Args, after parsing, so inherited persistent flags are visible.
func rejectListConflicts(cmd *cobra.Command) error {
	var set []string
	for _, name := range listConflicts {
		if cmd.Flags().Changed(name) {
			set = append(set, "--"+name)
		}
	}
	if len(set) > 0 {
		return inputError(fmt.Errorf("--list-rules cannot be combined with %s", strings.Join(set, ", ")))
	}
	return nil
}

// lintOutput maps a failed report write to exit 2; nil passes through.
func lintOutput(err error) error {
	if err == nil {
		return nil
	}
	return inputError(fmt.Errorf("write lint output: %w", err))
}

func runLint(cmd *cobra.Command, opts *commandOptions, flags *lintFlags, inputs []string) error {
	if flags.list {
		return lintOutput(renderRules(cmd.OutOrStdout(), opts.format))
	}
	cfg := policy.Policy{Version: policy.ConfigVersion}
	if flags.configFile != "" {
		var err error
		if cfg, err = policy.ReadConfig(flags.configFile); err != nil {
			return inputError(err)
		}
	}
	if err := validateImageArgs(opts.source, opts.platform, inputs); err != nil {
		return inputError(err)
	}
	effective, err := policy.BuildPolicy(cfg, policy.Options{
		Source: opts.source, Profile: flags.profile, FailOn: flags.failOn, Rules: flags.rules,
		DisableRules: flags.disabled, RuntimePrefix: flags.runtimePrefix, Project: flags.project,
	})
	if err != nil {
		return inputError(err)
	}
	req := policy.Requirements(effective)

	ctx, cancel := operationContext(cmd.Context())
	defer cancel()
	progressCtx, stopProgress := startLintProgress(ctx, cmd.ErrOrStderr(), opts.source == "dir" && opts.format == "text")
	snapshot, collectErr := evidence.Collect(progressCtx, opts.source, inputs, opts.platform, req)
	if err := stopProgress(); err != nil {
		return errors.Join(lintOutput(err), collectErr, ctx.Err())
	}
	report := policy.Evaluate(snapshot, effective, time.Now().UTC())
	if err := lintOutput(renderLint(cmd.OutOrStdout(), report, opts.format, opts.noColor, opts.verbose)); err != nil {
		return err
	}
	if errors.Is(collectErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return &commandExit{code: canceledExitCode, err: context.Canceled, silent: true}
	}
	if code := report.ExitCode(); code != 0 {
		return &commandExit{code: code, silent: true}
	}
	return nil
}

func renderRules(out io.Writer, format string) error {
	if format == "json" {
		return encodeJSON(out, policy.ListRules())
	}
	printer := newPrinter(out)
	for _, rule := range policy.ListRules() {
		printer.Printf("%s  %s\n  Why: %s\n  Fix: %s\n", safeText(rule.ID), safeText(rule.Name), safeText(rule.Description), safeText(rule.Fix))
		var enabled []string
		for profile, defaults := range rule.Defaults {
			if defaults.Enabled {
				enabled = append(enabled, safeText(profile)+" ("+safeText(string(defaults.Severity))+")")
			}
		}
		slices.Sort(enabled)
		printer.Printf("  Enabled profiles: %s\n", strings.Join(enabled, ", "))
		printer.Println("  Docs:")
		for _, reference := range rule.References {
			printer.Printf("    %s\n", safeText(reference))
		}
		printer.Println("  Exceptions:")
		for _, exception := range rule.Exceptions {
			printer.Printf("    %s\n", safeText(exception))
		}
		if !rule.Available {
			printer.Printf("  Unavailable: %s\n", safeText(rule.UnavailableReason))
		}
		printer.Println()
	}
	return printer.Err()
}

func renderLint(out io.Writer, report policy.Report, format string, noColor bool, verbose bool) error {
	if format == "json" {
		return encodeJSON(out, report)
	}
	printer := newPrinter(out)
	printer.Printf("Lint | profile %s | ruleset %s\n", safeText(report.Profile), safeText(report.RulesetVersion))
	imageTargets := make(map[string]bool, len(report.Targets))
	for _, target := range report.Targets {
		imageTargets[target.ID] = target.Kind == "oci-archive"
		if verbose {
			printer.Printf("Target: %s (%d prefixes)\n", safeText(target.ID), target.PrefixCount)
			for _, root := range target.Roots {
				printer.Printf("  Scope root: %s\n", safeText(root))
			}
		}
	}
	findings, suppressed := 0, 0
	for _, finding := range report.Findings {
		if finding.Suppression != nil {
			suppressed++
			continue
		}
		rule, ok := policy.LookupRule(finding.RuleID)
		if !ok {
			return errors.Join(printer.Err(), fmt.Errorf("render lint finding %q: rule metadata unavailable", finding.RuleID))
		}
		findings++
		severity := colour(out, noColor, safeText(string(finding.Severity)), severityAttribute(finding.Severity))
		printer.Printf("%s %s %s\n  Found: %s\n", safeText(finding.RuleID), severity, safeText(finding.Target), safeText(finding.Message))
		renderEvidence(printer, finding.Evidence, imageTargets[finding.Target])
		for _, note := range finding.Evidence.Notes {
			printer.Printf("  Note: %s\n", safeText(note))
		}
		next := finding.Next
		if next == "" {
			next = rule.Fix
		}
		printer.Printf("  Next: %s\n", safeText(next))
	}
	if verbose {
		renderOutcomes(printer, report)
	}
	printer.Printf("Summary: %s; %d targets; %d findings; %d unknown", safeText(report.Status), len(report.Targets), findings, report.OutcomeCounts[policy.Unknown])
	if suppressed > 0 {
		printer.Printf("; %d suppressed", suppressed)
	}
	printer.Println()
	if summary := report.Inspection; summary != nil {
		printer.Printf("Inspection: %d environments found; %d inspected; %d failed; %d access errors; %d discovery issues", summary.Found, summary.Inspected, summary.Failed, summary.AccessErrors, summary.DiscoveryIssues)
		if pending := summary.Found - summary.Inspected - summary.Failed; pending > 0 {
			printer.Printf("; %d unfinished", pending)
		}
		printer.Println()
	}
	if !verbose && (len(report.Issues) != 0 || report.OutcomeCounts[policy.Unknown] != 0 || len(report.SuppressionNotes) != 0) {
		printer.Printf("Inspection diagnostics: %d issues; use --verbose to see details\n", len(report.Issues))
	}
	if verbose {
		for _, issue := range report.Issues {
			printer.Printf("Inspection issue: %s: %s\n", safeText(issue.Path), safeText(issue.Message))
		}
		for _, note := range report.SuppressionNotes {
			printer.Printf("Suppression: %s %s: %s\n", safeText(note.Rule), safeText(note.Status), safeText(note.Reason))
		}
	}
	return printer.Err()
}

func severityAttribute(severity policy.Severity) color.Attribute {
	switch severity {
	case policy.Info:
		return color.FgCyan
	case policy.Warning:
		return color.FgYellow
	default:
		return color.FgRed
	}
}

func renderEvidence(printer *printer, ev policy.FindingEvidence, image bool) {
	seen := make(map[string]bool, len(ev.Samples))
	for _, item := range ev.Samples {
		path := lintPath(item.Path, image)
		seen[path] = true
		printer.Printf("  Evidence: %s", path)
		if item.Bytes > 0 {
			printer.Printf(" (%s)", lintBytes(item.Bytes))
		}
		if item.BlobDigest != "" {
			printer.Printf("; source layer %d %s (%s compressed layer)", item.Layer+1, safeText(item.BlobDigest), lintBytes(item.LayerBytes))
		}
		printer.Println()
	}
	for _, path := range ev.Paths {
		path = lintPath(path, image)
		if !seen[path] {
			printer.Printf("  Evidence: %s\n", path)
			seen[path] = true
		}
	}
	if len(seen) == 0 {
		for _, location := range ev.Locations {
			printer.Printf("  Evidence: %s\n", safeText(location))
		}
	}
}

func lintPath(path string, image bool) string {
	if image && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return safeText(path)
}

func lintBytes(bytes int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	size := float64(bytes)
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func renderOutcomes(printer *printer, report policy.Report) {
	for _, outcome := range report.Outcomes {
		if outcome.Status == policy.Unknown {
			printer.Printf("Check %s %s: %s\n", safeText(outcome.RuleID), safeText(string(outcome.Status)), safeText(outcome.Reason))
		}
	}
}
