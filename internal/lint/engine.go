package lint

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/conda-incubator/envscout/internal/evidence"
)

// BuildPolicy merges profile defaults, config and explicit CLI options, in that
// precedence order (CLI over config over profile). It performs no collection
// and never mutates its inputs.
func BuildPolicy(config Policy, options Options) (Policy, error) {
	if config.Version == 0 {
		config.Version = ConfigVersion
	}
	if err := ValidateConfig(config); err != nil {
		return Policy{}, err
	}
	source := cmp.Or(options.Source, config.Source, "dir")
	if source != "dir" && source != "oci-archive" {
		return Policy{}, fmt.Errorf("unsupported lint source %q", source)
	}
	defaultProfile := "local"
	if source == "oci-archive" {
		defaultProfile = "container"
	}
	profile := cmp.Or(options.Profile, config.Profile, defaultProfile)
	if !slices.Contains(profiles, profile) {
		return Policy{}, fmt.Errorf("unknown lint profile %q", profile)
	}
	if (profile == "local") != (source == "dir") {
		return Policy{}, fmt.Errorf("lint profile %q is incompatible with source %q", profile, source)
	}
	failOn := cmp.Or(Severity(options.FailOn), config.FailOn, Warning)
	if failOn != NoFailure && failOn.Rank() == 0 {
		return Policy{}, fmt.Errorf("invalid lint failure threshold %q", failOn)
	}
	p := Policy{Version: ConfigVersion, Source: source, Profile: profile, FailOn: failOn,
		Rules: make(map[string]RuleOptions, len(registry)), Suppressions: slices.Clone(config.Suppressions)}
	for i := range p.Suppressions {
		p.Suppressions[i].Fingerprint = strings.ToLower(p.Suppressions[i].Fingerprint)
	}
	if options.RuntimePrefix != "" {
		if source != "oci-archive" {
			return Policy{}, fmt.Errorf("runtime prefix requires an OCI image source")
		}
		if err := validateRuntimePrefix(options.RuntimePrefix); err != nil {
			return Policy{}, err
		}
		p.RuntimePrefix = options.RuntimePrefix
	}
	if options.Project != "" {
		if source != "dir" {
			return Policy{}, fmt.Errorf("project association requires a local project path")
		}
		project, err := filepath.Abs(options.Project)
		if err != nil {
			return Policy{}, fmt.Errorf("resolve project path: %w", err)
		}
		p.Project = filepath.Clean(project)
	}
	selected := make(map[string]bool, len(options.Rules))
	for _, id := range options.Rules {
		rule, ok := lookupRule(id)
		if !ok {
			return Policy{}, fmt.Errorf("unknown lint rule %q", id)
		}
		if !rule.Available {
			return Policy{}, fmt.Errorf("rule %s is unavailable: %s", id, rule.UnavailableReason)
		}
		if !slices.Contains(rule.TargetKinds, source) {
			return Policy{}, fmt.Errorf("rule %s is incompatible with source %q", id, source)
		}
		selected[id] = true
	}
	disabled := make(map[string]bool, len(options.DisableRules))
	for _, id := range options.DisableRules {
		if _, ok := lookupRule(id); !ok {
			return Policy{}, fmt.Errorf("unknown lint rule %q", id)
		}
		if selected[id] {
			return Policy{}, fmt.Errorf("rule %s is both selected and disabled", id)
		}
		disabled[id] = true
	}
	for _, rule := range registry {
		d := rule.Defaults[profile]
		configured := config.Rules[rule.ID]
		opts := RuleOptions{Severity: cmp.Or(configured.Severity, d.Severity),
			RevisionThreshold: cloneInt(cmp.Or(configured.RevisionThreshold, d.RevisionThreshold))}
		enabled := d.Enabled
		if configured.Enabled != nil {
			enabled = *configured.Enabled
		}
		if len(selected) > 0 {
			enabled = selected[rule.ID]
		}
		if disabled[rule.ID] {
			enabled = false
		}
		// Unavailable profile defaults are disclosed as outcomes; explicit enables fail.
		if enabled && configured.Enabled != nil && *configured.Enabled && !rule.Available {
			return Policy{}, fmt.Errorf("rule %s is unavailable: %s", rule.ID, rule.UnavailableReason)
		}
		if enabled && !slices.Contains(rule.TargetKinds, source) {
			return Policy{}, fmt.Errorf("rule %s is incompatible with source %q", rule.ID, source)
		}
		opts.Enabled = new(enabled)
		p.Rules[rule.ID] = opts
	}
	return p, nil
}

// Requirements returns a deterministic set union, excluding disabled,
// unavailable and source-inapplicable rules. Explicit runtime and project
// assertions are always included, even when no selected rule consumes them.
func Requirements(policy Policy) evidence.Request {
	caps := make(map[string]bool)
	if policy.RuntimePrefix != "" {
		caps["runtime-config"] = true
	}
	if policy.Project != "" {
		caps["project-association"] = true
	}
	for _, rule := range registry {
		if !rule.Available || !ruleEnabled(policy, rule.ID) || !slices.Contains(rule.TargetKinds, policy.Source) {
			continue
		}
		for _, capability := range rule.Capabilities {
			caps[capability] = true
		}
	}
	request := evidence.Request{Capabilities: make([]string, 0, len(caps)), RuntimePrefix: policy.RuntimePrefix, Project: policy.Project}
	for capability := range caps {
		request.Capabilities = append(request.Capabilities, capability)
	}
	slices.Sort(request.Capabilities)
	return request
}

// validateRuntimePrefix accepts only an exact clean absolute POSIX image path.
// Dirty input is rejected rather than normalized so callers cannot pass a
// different path than the one they asserted. It performs no filesystem I/O.
func validateRuntimePrefix(prefix string) error {
	if strings.IndexFunc(prefix, func(r rune) bool { return r == '\\' || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("runtime prefix must not contain backslashes or control characters")
	}
	if !path.IsAbs(prefix) {
		return fmt.Errorf("runtime prefix must be an absolute image POSIX path")
	}
	if path.Clean(prefix) != prefix {
		return fmt.Errorf("runtime prefix must be a clean path without parent traversal or redundant separators")
	}
	return nil
}

func ruleEnabled(policy Policy, id string) bool {
	opts, ok := policy.Rules[id]
	return ok && opts.Enabled != nil && *opts.Enabled
}

// validEffectivePolicy rejects incomplete settings supplied by direct callers.
func validEffectivePolicy(policy Policy) error {
	if err := ValidateConfig(policy); err != nil {
		return err
	}
	if !slices.Contains(profiles, policy.Profile) ||
		(policy.Source != "dir" && policy.Source != "oci-archive") || (policy.Profile == "local") != (policy.Source == "dir") ||
		(policy.FailOn != NoFailure && !policy.FailOn.Valid()) || len(policy.Rules) != len(registry) {
		return fmt.Errorf("policy settings are not normalized")
	}
	for _, rule := range registry {
		options, ok := policy.Rules[rule.ID]
		if !ok || options.Enabled == nil || !options.Severity.Valid() ||
			(*options.Enabled && rule.Available && !slices.Contains(rule.TargetKinds, policy.Source)) {
			return fmt.Errorf("rule settings not normalized")
		}
	}
	return nil
}

// Evaluate is pure: snapshots are never changed and rules receive no I/O
// handles. Positive partial evidence may produce findings, never an all-clear.
func Evaluate(snapshot evidence.Snapshot, policy Policy, now time.Time) Report {
	r := Report{SchemaVersion: SchemaVersion, Tool: "envscout", ToolVersion: "development",
		RulesetVersion: RulesetVersion, ProfileVersion: ProfileVersion, Profile: policy.Profile,
		Source: policy.Source, RuntimePrefix: policy.RuntimePrefix, Project: policy.Project,
		StartedAt: snapshot.Started, EvaluatedAt: now.UTC(), Policy: policy, Status: "completed", Limits: ReportLimits{MaxSamples, MaxFindings},
		Targets: []TargetReport{}, Outcomes: []Outcome{}, OutcomeCounts: zeroCounts(), Findings: []Finding{},
		Issues: slices.Clone(snapshot.Issues), SuppressionNotes: []SuppressionNote{}}
	if r.Issues == nil {
		r.Issues = []evidence.Issue{}
	}
	// These policy fields contain only JSON scalar values, slices and maps.
	encoded, _ := json.Marshal(struct {
		Policy        Policy `json:"policy"`
		Source        string `json:"source"`
		RuntimePrefix string `json:"runtime_prefix"`
		Project       string `json:"project"`
	}{policy, policy.Source, policy.RuntimePrefix, policy.Project})
	r.ConfigDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	if err := validEffectivePolicy(policy); err != nil {
		r.Status = "failed"
		r.Issues = append(r.Issues, evidence.Issue{Capability: "policy", Message: "lint evaluation requires a normalized effective policy from BuildPolicy"})
		return r
	}
	targets := slices.Clone(snapshot.Targets)
	slices.SortFunc(targets, func(a, b evidence.Target) int { return strings.Compare(a.ID, b.ID) })
	var peers []evidence.Prefix
	for _, target := range targets {
		peers = append(peers, target.Prefixes...)
	}
	checks := map[string]func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding){}
	for _, rule := range registry {
		options := policy.Rules[rule.ID]
		if rule.prepare != nil && options.Enabled != nil && *options.Enabled && slices.Contains(rule.TargetKinds, policy.Source) {
			checks[rule.ID] = rule.prepare(peers)
		}
	}
	request := Requirements(policy)
	truncated := false
	for _, target := range targets {
		target.Peers = peers
		target.AsOf = now
		r.Issues = append(r.Issues, targetIssues(target, policy, request)...)
		projection := targetReport(target)
		r.Targets = append(r.Targets, projection)
		r.Issues = append(r.Issues, projection.Issues...)
		for _, rule := range registry {
			if check := checks[rule.ID]; check != nil {
				rule.Check = check
			}
			outcome, findings := evaluateRule(target, policy, rule)
			if outcome.limited {
				r.Issues = append(r.Issues, evidence.Issue{Capability: "evaluation", Path: target.ID, Message: outcome.Reason})
			}
			if outcome.Status == Disabled || outcome.Status == NotApplicable {
				r.OutcomeCounts[outcome.Status]++
				continue
			}
			r.Outcomes = append(r.Outcomes, outcome)
			remaining := MaxFindings - len(r.Findings)
			truncated = truncated || len(findings) > remaining
			r.Findings = append(r.Findings, findings[:min(len(findings), remaining)]...)
		}
	}
	if truncated {
		r.Issues = append(r.Issues, evidence.Issue{Capability: "evaluation", Message: fmt.Sprintf("finding limit %d exceeded; report is truncated", MaxFindings)})
	}
	applySuppressions(&r, now)
	projectOutcomes(&r)
	if len(r.Issues) > 0 {
		r.Status = "incomplete"
	}
	slices.SortFunc(r.Outcomes, func(a, b Outcome) int {
		return cmp.Or(strings.Compare(a.Target, b.Target), strings.Compare(a.RuleID, b.RuleID))
	})
	slices.SortFunc(r.Findings, func(a, b Finding) int {
		return cmp.Or(strings.Compare(a.Target, b.Target), strings.Compare(a.RuleID, b.RuleID), strings.Compare(a.Fingerprint, b.Fingerprint))
	})
	sortIssues(r.Issues)
	return r
}

// targetIssues returns the evidence-coverage and assertion issues for a target.
// History coverage is non-fatal and an unassociated project is allowed.
func targetIssues(target evidence.Target, policy Policy, request evidence.Request) []evidence.Issue {
	var issues []evidence.Issue
	if target.Kind != policy.Source {
		issues = append(issues, evidence.Issue{Capability: "evaluation", Path: target.ID, Message: "snapshot target source does not match effective policy"})
	}
	if policy.RuntimePrefix != "" && target.RuntimePrefix != policy.RuntimePrefix {
		issues = append(issues, evidence.Issue{Capability: "runtime-config", Path: target.ID, Message: "asserted runtime prefix was not verified in target evidence"})
	}
	if policy.Project != "" && (target.Project == nil || !target.Project.Associated || target.Project.Path != policy.Project) {
		issues = append(issues, evidence.Issue{Capability: "project-association", Path: target.ID, Message: "explicit project association was not verified in target evidence"})
	}
	for _, capability := range request.Capabilities {
		if target.Coverage[capability] == evidence.Complete || capability == "history" ||
			(capability == "project-association" && (target.Project == nil || !target.Project.Associated)) {
			continue
		}
		issues = append(issues, evidence.Issue{Capability: capability, Path: target.ID, Message: "required evidence coverage is not complete"})
	}
	return issues
}

// targetReport builds a read-only projection; arrays and maps are copied so the
// snapshot is never aliased by the report.
func targetReport(target evidence.Target) TargetReport {
	issues := slices.Clone(target.Issues)
	if issues == nil {
		issues = []evidence.Issue{}
	}
	sortIssues(issues)
	roots := slices.Clone(target.Roots)
	slices.Sort(roots)
	return TargetReport{ID: target.ID, Kind: target.Kind, Input: target.Input, Roots: roots, Image: target.Image,
		PrefixCount: len(target.Prefixes), RuntimePrefix: target.RuntimePrefix, Coverage: maps.Clone(target.Coverage), Issues: issues}
}

// projectOutcomes links post-suppression findings and counts final active statuses.
func projectOutcomes(report *Report) {
	groups := make(map[string]bool, len(report.Findings))
	for _, f := range report.Findings {
		key := f.Target + "\x00" + f.RuleID
		groups[key] = groups[key] || f.Suppression == nil
	}
	for i := range report.Outcomes {
		outcome := &report.Outcomes[i]
		if unsuppressed, found := groups[outcome.Target+"\x00"+outcome.RuleID]; found && !unsuppressed && outcome.Status == FindingStatus {
			outcome.Status = Suppressed
		}
		report.OutcomeCounts[outcome.Status]++
	}
}

// zeroCounts initializes every status so the JSON summary always lists all keys.
func zeroCounts() map[Status]int {
	return map[Status]int{Pass: 0, FindingStatus: 0, Unknown: 0, NotApplicable: 0, Disabled: 0, Unavailable: 0, Suppressed: 0}
}

// evaluateRule runs the general gating shared by all rules, then delegates to
// the rule's Check. Gating for disabled, unavailable and inapplicable rules
// never calls Check.
func evaluateRule(target evidence.Target, policy Policy, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{RuleID: rule.ID, Target: target.ID, Status: Pass}
	switch {
	case !ruleEnabled(policy, rule.ID):
		outcome.Status = Disabled
	case !rule.Available:
		outcome.Status, outcome.Reason = Unavailable, rule.UnavailableReason
	case !slices.Contains(rule.TargetKinds, target.Kind):
		outcome.Status, outcome.Reason = NotApplicable, "rule does not apply to this source kind"
	case rule.Check == nil:
		outcome.Status, outcome.Reason = Unknown, "rule has no evaluation entry"
	default:
		checked, findings := rule.Check(target, policy.Rules[rule.ID], rule)
		checked.RuleID, checked.Target = rule.ID, target.ID
		if len(findings) > 0 {
			checked.Status = FindingStatus
		} else if checked.Status == "" {
			checked.Status = Pass
		}
		return checked, findings
	}
	return outcome, nil
}

func applySuppressions(report *Report, now time.Time) {
	targets := make(map[string]evidence.Target, len(report.Targets))
	for _, target := range report.Targets {
		targets[target.ID] = evidence.Target{ID: target.ID, Kind: target.Kind}
	}
	for index, suppression := range report.Policy.Suppressions {
		if suppression.Expires != "" {
			expiry, err := time.Parse(time.DateOnly, suppression.Expires)
			// Expiry is inclusive for the whole stated UTC calendar date.
			if err != nil || !now.Before(expiry.AddDate(0, 0, 1)) {
				report.SuppressionNotes = append(report.SuppressionNotes, SuppressionNote{Index: index, Rule: suppression.Rule,
					Status: "expired", Reason: "suppression expiry date has passed"})
				continue
			}
		}
		matched := false
		for i := range report.Findings {
			f := &report.Findings[i]
			if f.RuleID != suppression.Rule || (suppression.Target != "" && suppression.Target != f.Target) ||
				(suppression.Fingerprint != "" && suppression.Fingerprint != f.Fingerprint) {
				continue
			}
			if suppression.Path != "" && !findingHasPath(f, suppression.Path, targets) {
				continue
			}
			matched = true
			if f.Suppression == nil {
				copied := suppression
				f.Suppression = &copied
			}
		}
		if !matched {
			report.SuppressionNotes = append(report.SuppressionNotes, SuppressionNote{Index: index, Rule: suppression.Rule,
				Status: "unused", Reason: "suppression did not match an observed finding"})
		}
	}
	if report.Profile == "container-distroless" && len(report.SuppressionNotes) > 0 {
		report.Issues = append(report.Issues, evidence.Issue{Capability: "policy", Message: "strict distroless policy rejects expired or unused suppressions"})
	}
}

// findingHasPath matches a suppression path against the raw paths or their
// location encodings for the finding's target.
func findingHasPath(f *Finding, want string, targets map[string]evidence.Target) bool {
	if slices.Contains(f.paths, want) {
		return true
	}
	target := targets[f.Target]
	for _, p := range f.paths {
		if location(target, p) == want {
			return true
		}
		if target.Kind == "oci-archive" {
			absolute := path.Join("/", p)
			if absolute == want || location(target, absolute) == want {
				return true
			}
		}
	}
	return false
}

func location(target evidence.Target, p string) string {
	if target.Kind == "oci-archive" {
		return target.ID + "#" + (&url.URL{Path: p}).EscapedPath()
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(p)}).String()
}

func sortIssues(issues []evidence.Issue) {
	slices.SortFunc(issues, func(a, b evidence.Issue) int {
		return cmp.Or(strings.Compare(a.Capability, b.Capability), strings.Compare(a.Path, b.Path), strings.Compare(a.Message, b.Message))
	})
}

func cloneInt(v *int) *int {
	if v == nil {
		return nil
	}
	return new(*v)
}
