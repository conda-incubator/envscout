package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/anaconda/envscout/internal/evidence"
	"github.com/anaconda/envscout/internal/imageinput"
	policy "github.com/anaconda/envscout/internal/lint"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/spf13/cobra"
)

type commandExit struct {
	code   int
	err    error
	silent bool
}

func (e *commandExit) Error() string {
	if e.err != nil {
		return lintText(e.err.Error())
	}
	return "lint policy threshold exceeded"
}
func (e *commandExit) Unwrap() error { return e.err }

// ExitCode preserves existing commands' status while lint distinguishes policy and inspection.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *commandExit
	if errors.As(err, &exit) {
		return exit.code
	}
	return 1
}

func ShouldPrintError(err error) bool {
	var exit *commandExit
	return err != nil && (!errors.As(err, &exit) || !exit.silent)
}

func lintCommand() *cobra.Command {
	var source, platform, profile, format, failOn, configFile, runtimePrefix, project string
	var rules, disabled []string
	var list, noColor bool
	cmd := &cobra.Command{
		Use:   "lint ROOT...",
		Short: "Evaluate evidence-based environment and image policies without creating SBOMs",
		RunE: func(cmd *cobra.Command, inputs []string) error {
			invalid := func(err error) error { return &commandExit{code: 2, err: err} }
			if format != "text" && format != "json" {
				return invalid(fmt.Errorf("--format must be text or json"))
			}
			if source != "dir" && source != "oci-archive" {
				return invalid(fmt.Errorf("unsupported lint source %q", source))
			}
			cfg := policy.Policy{Version: 1}
			if configFile != "" {
				var err error
				cfg, err = policy.ReadConfig(configFile)
				if err != nil {
					return invalid(err)
				}
			}
			if list {
				if len(inputs) != 0 || platform != "" || runtimePrefix != "" || project != "" || profile != "" || failOn != "" || source != "dir" || len(rules) > 0 || len(disabled) > 0 || configFile != "" {
					return invalid(fmt.Errorf("--list-rules cannot be combined with targets or policy selection"))
				}
				if err := renderRules(cmd.OutOrStdout(), format); err != nil {
					return invalid(err)
				}
				return nil
			}
			if len(inputs) == 0 {
				return invalid(fmt.Errorf("lint requires explicit roots or one OCI archive"))
			}
			if err := validateImageArgs(source, platform, inputs); err != nil {
				return invalid(err)
			}
			if source == "oci-archive" {
				p, err := image.NewPlatform(platform)
				if err != nil || p == nil || !strings.Contains(platform, "/") {
					return invalid(fmt.Errorf("invalid image platform %q", platform))
				}
				if project != "" {
					return invalid(fmt.Errorf("--project is only valid for directory targets"))
				}
			} else if runtimePrefix != "" {
				return invalid(fmt.Errorf("--runtime-prefix is only valid for image targets"))
			}
			if runtimePrefix != "" && (!path.IsAbs(runtimePrefix) || path.Clean(runtimePrefix) != runtimePrefix || strings.ContainsAny(runtimePrefix, "\\\x00\r\n")) {
				return invalid(fmt.Errorf("--runtime-prefix must be a clean absolute image path"))
			}
			if project != "" {
				abs, err := filepath.Abs(project)
				if err != nil {
					return invalid(err)
				}
				project = abs
				info, err := os.Lstat(project)
				if err != nil || !info.IsDir() {
					return invalid(fmt.Errorf("--project must name a real directory"))
				}
				resolved, err := filepath.EvalSymlinks(project)
				if err != nil || resolved != project {
					return invalid(fmt.Errorf("--project must not contain symlinked path components"))
				}
			}
			effective, err := policy.BuildPolicy(cfg, policy.Options{Source: source, Profile: profile, FailOn: failOn, Rules: rules, DisableRules: disabled, RuntimePrefix: runtimePrefix, Project: project})
			if err != nil {
				return invalid(err)
			}
			req := policy.Requirements(effective)
			req.RuntimePrefix, req.Project = runtimePrefix, project
			if runtimePrefix != "" && !evidence.Requested(req, "runtime-config") {
				return invalid(fmt.Errorf("--runtime-prefix requires an enabled runtime-layout rule"))
			}
			if project != "" && !evidence.Requested(req, "project-association") {
				return invalid(fmt.Errorf("--project requires an enabled project-association rule"))
			}
			signalCtx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go func() { <-signalCtx.Done(); stop() }()
			ctx, cancel := context.WithTimeout(signalCtx, 5*time.Minute)
			defer cancel()
			started := time.Now().UTC()
			snapshot := evidence.Snapshot{Started: started, Targets: []evidence.Target{}, Issues: []evidence.Issue{}}
			var collectErr error
			if source == "dir" {
				progress := new(discovery.Progress)
				status := startStatus(cmd.ErrOrStderr(), func() string {
					return fmt.Sprintf("Lint discovery: folders %d  envs %d", progress.Folders.Load(), progress.Environments.Load())
				})
				snapshot, collectErr = evidence.CollectHost(ctx, inputs, req, progress)
				status.close()
			} else {
				status := startStatus(cmd.ErrOrStderr(), func() string { return "Lint: loading and collecting image evidence" })
				loaded, err := imageinput.Load(ctx, inputs[0], platform)
				if err == nil {
					var target evidence.Target
					target, collectErr = evidence.CollectImage(ctx, loaded, req)
					if target.ID != "" {
						snapshot.Targets = append(snapshot.Targets, target)
					}
					collectErr = errors.Join(collectErr, loaded.Close())
				} else {
					collectErr = err
				}
				status.close()
			}
			if collectErr != nil {
				snapshot.Issues = append(snapshot.Issues, evidence.Issue{Capability: "source", Path: source, Message: collectErr.Error()})
			}
			if ctx.Err() != nil && collectErr == nil {
				collectErr = ctx.Err()
				snapshot.Issues = append(snapshot.Issues, evidence.Issue{Capability: "source", Path: source, Message: collectErr.Error()})
			}
			report := policy.Evaluate(snapshot, effective, time.Now().UTC())
			if err := renderLint(cmd.OutOrStdout(), report, format, !noColor && os.Getenv("NO_COLOR") == "" && isTerminal(cmd.OutOrStdout())); err != nil {
				return invalid(err)
			}
			if errors.Is(collectErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return &commandExit{code: 130, err: context.Canceled, silent: true}
			}
			if code := report.ExitCode(); code != 0 {
				return &commandExit{code: code, silent: true}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "source", "dir", "target source: dir or oci-archive (offline)")
	cmd.Flags().StringVar(&platform, "platform", "", "image platform OS/ARCH[/VARIANT]")
	cmd.Flags().StringVar(&profile, "profile", "", "local, container, container-runtime, container-development, container-distroless")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "failure threshold: error, warning (default), info, or none")
	cmd.Flags().StringVar(&configFile, "config", "", "explicit versioned JSON policy file")
	cmd.Flags().StringVar(&runtimePrefix, "runtime-prefix", "", "asserted image runtime prefix")
	cmd.Flags().StringVar(&project, "project", "", "explicit local project association for one prefix")
	cmd.Flags().StringArrayVar(&rules, "rule", nil, "evaluate only this rule ID (repeatable)")
	cmd.Flags().StringArrayVar(&disabled, "disable-rule", nil, "disable this rule ID (repeatable)")
	cmd.Flags().BoolVar(&list, "list-rules", false, "list implemented rules without inspecting targets")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable colored lint severities")
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &commandExit{code: 2, err: err} })
	return cmd
}

// Quote control characters so untrusted paths and policy messages cannot alter a terminal.
func lintText(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return strconv.QuoteToASCII(s)
	}
	return s
}

func renderRules(out io.Writer, format string) error {
	if format == "json" {
		return json.NewEncoder(out).Encode(policy.ListRules())
	}
	for _, rule := range policy.ListRules() {
		suffix := ""
		if !rule.Available {
			suffix = fmt.Sprintf(" (unavailable: %s)", rule.UnavailableReason)
		}
		if _, err := fmt.Fprintf(out, "%s  %s%s\n", rule.ID, lintText(rule.Name), lintText(suffix)); err != nil {
			return err
		}
	}
	return nil
}

func renderLint(out io.Writer, report policy.Report, format string, color bool) error {
	if format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if _, err := fmt.Fprintf(out, "Lint | profile %s | ruleset %s\n", report.Profile, report.RulesetVersion); err != nil {
		return err
	}
	for _, target := range report.Targets {
		if _, err := fmt.Fprintf(out, "Target: %s (%d confirmed prefixes)\n", lintText(target.ID), target.PrefixCount); err != nil {
			return err
		}
		for _, root := range target.Roots {
			if _, err := fmt.Fprintf(out, "  Scope root: %s\n", lintText(root)); err != nil {
				return err
			}
		}
	}
	for _, finding := range report.Findings {
		if finding.Suppression != nil {
			continue
		}
		severity := finding.Severity
		if color {
			codes := map[string]string{"info": "\x1b[36m", "warning": "\x1b[33m", "error": "\x1b[31m"}
			severity = codes[severity] + severity + "\x1b[0m"
		}
		if _, err := fmt.Fprintf(out, "%s %s %s\n  %s\n  Next: %s\n", finding.RuleID, severity, lintText(finding.Target), lintText(finding.Message), lintText(finding.Recommendation)); err != nil {
			return err
		}
		for _, item := range finding.Evidence.Samples {
			if _, err := fmt.Fprintf(out, "  Evidence: %s", lintText(item.Path)); err != nil {
				return err
			}
			if item.Bytes > 0 {
				if _, err := fmt.Fprintf(out, " (%d logical payload bytes)", item.Bytes); err != nil {
					return err
				}
			}
			if item.BlobDigest != "" {
				if _, err := fmt.Fprintf(out, " layer %d %s (%d compressed layer bytes, not per-file savings)", item.Layer, item.BlobDigest, item.LayerBytes); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
		if len(finding.Evidence.Samples) == 0 {
			for _, location := range finding.Evidence.Locations {
				if _, err := fmt.Fprintf(out, "  Evidence: %s\n", lintText(location)); err != nil {
					return err
				}
			}
		}
	}
	counts := make(map[string]int)
	for _, outcome := range report.Outcomes {
		counts[outcome.Status]++
		if outcome.Status == policy.Unknown {
			if _, err := fmt.Fprintf(out, "Check %s %s: %s\n", outcome.RuleID, outcome.Status, lintText(outcome.Reason)); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(out, "Summary: %s; %d targets; pass %d, findings %d, unknown %d, not applicable %d, disabled %d, suppressed %d\n", report.Status, len(report.Targets), counts["pass"], counts["finding"], counts["unknown"], counts["not_applicable"], counts["disabled"], counts["suppressed"]); err != nil {
		return err
	}
	for _, issue := range report.Issues {
		if _, err := fmt.Fprintf(out, "Inspection issue: %s: %s\n", lintText(issue.Path), lintText(issue.Message)); err != nil {
			return err
		}
	}
	for _, note := range report.SuppressionNotes {
		if _, err := fmt.Fprintf(out, "Suppression: %s %s: %s\n", lintText(note.Rule), note.Status, lintText(note.Reason)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(out, "Coverage: selected rules and stated scopes only; this is not a vulnerability assessment.")
	return err
}
