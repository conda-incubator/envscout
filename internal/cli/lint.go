package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
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
var listConflicts = []string{"source", "platform", "output-dir", "profile", "fail-on", "config", "runtime-prefix", "project", "rule", "disable-rule"}

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
	progressCtx, stopProgress := startDiscoveryProgress(ctx, cmd.ErrOrStderr(), opts.source == "dir" && opts.format == "text")
	snapshot, collectErr := evidence.Collect(progressCtx, opts.source, inputs, opts.platform, req)
	if err := stopProgress(); err != nil {
		return errors.Join(lintOutput(err), collectErr, ctx.Err())
	}
	report := policy.Evaluate(snapshot, effective, time.Now().UTC())
	if err := lintOutput(renderLint(cmd.OutOrStdout(), report, opts.format, opts.noColor)); err != nil {
		return err
	}
	if errors.Is(collectErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return &commandExit{code: 130, err: context.Canceled, silent: true}
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
		suffix := ""
		if !rule.Available {
			suffix = fmt.Sprintf(" (unavailable: %s)", rule.UnavailableReason)
		}
		printer.Printf("%s  %s%s\n", rule.ID, lintText(rule.Name), lintText(suffix))
	}
	return printer.Err()
}

func renderLint(out io.Writer, report policy.Report, format string, noColor bool) error {
	if format == "json" {
		return encodeJSON(out, report)
	}
	printer := newPrinter(out)
	printer.Printf("Lint | profile %s | ruleset %s\n", report.Profile, report.RulesetVersion)
	for _, target := range report.Targets {
		printer.Printf("Target: %s (%d confirmed prefixes)\n", lintText(target.ID), target.PrefixCount)
		for _, root := range target.Roots {
			printer.Printf("  Scope root: %s\n", lintText(root))
		}
	}
	for _, finding := range report.Findings {
		if finding.Suppression != nil {
			continue
		}
		rule, ok := policy.LookupRule(finding.RuleID)
		if !ok {
			return fmt.Errorf("render lint finding %q: rule metadata unavailable", finding.RuleID)
		}
		severity := colour(out, noColor, string(finding.Severity), severityAttribute(finding.Severity))
		printer.Printf("%s %s %s\n  %s\n  Next: %s\n", finding.RuleID, severity, lintText(finding.Target), lintText(finding.Message), lintText(rule.Fix))
		renderEvidence(printer, finding.Evidence)
	}
	renderOutcomes(printer, report)
	counts := report.OutcomeCounts
	printer.Printf("Summary: %s; %d targets; pass %d, findings %d, unknown %d, not applicable %d, disabled %d, suppressed %d\n", report.Status, len(report.Targets), counts[policy.Pass], counts[policy.FindingStatus], counts[policy.Unknown], counts[policy.NotApplicable], counts[policy.Disabled], counts[policy.Suppressed])
	for _, issue := range report.Issues {
		printer.Printf("Inspection issue: %s: %s\n", lintText(issue.Path), lintText(issue.Message))
	}
	for _, note := range report.SuppressionNotes {
		printer.Printf("Suppression: %s %s: %s\n", lintText(note.Rule), note.Status, lintText(note.Reason))
	}
	printer.Println("Coverage: selected rules and stated scopes only; this is not a vulnerability assessment.")
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

func renderEvidence(printer *printer, ev policy.FindingEvidence) {
	for _, item := range ev.Samples {
		printer.Printf("  Evidence: %s", lintText(item.Path))
		if item.Bytes > 0 {
			printer.Printf(" (%d logical payload bytes)", item.Bytes)
		}
		if item.BlobDigest != "" {
			printer.Printf(" layer %d %s (%d compressed layer bytes, not per-file savings)", item.Layer, item.BlobDigest, item.LayerBytes)
		}
		printer.Println()
	}
	if len(ev.Samples) > 0 {
		return
	}
	for _, location := range ev.Locations {
		printer.Printf("  Evidence: %s\n", lintText(location))
	}
}

func renderOutcomes(printer *printer, report policy.Report) {
	for _, outcome := range report.Outcomes {
		if outcome.Status == policy.Unknown {
			printer.Printf("Check %s %s: %s\n", outcome.RuleID, outcome.Status, lintText(outcome.Reason))
		}
	}
}
