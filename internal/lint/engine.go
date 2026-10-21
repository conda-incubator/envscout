package lint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/anaconda/envscout/internal/evidence"
)

// BuildPolicy applies explicit CLI values over config values over profile
// defaults. It performs no collection and does not modify its inputs.
func BuildPolicy(config Policy, options Options) (Policy, error) {
	if config.Version == 0 {
		config.Version = SchemaVersion
	}
	if err := ValidateConfig(config); err != nil {
		return Policy{}, err
	}
	source := options.Source
	if source == "" {
		source = config.Source
	}
	if source == "" {
		source = "dir"
	}
	if source != "dir" && source != "oci-archive" {
		return Policy{}, fmt.Errorf("unsupported lint source %q", source)
	}
	profile := options.Profile
	if profile == "" {
		profile = config.Profile
	}
	if profile == "" {
		profile = "local"
		if source == "oci-archive" {
			profile = "container"
		}
	}
	if !slices.Contains(profiles, profile) {
		return Policy{}, fmt.Errorf("unknown lint profile %q", profile)
	}
	if (profile == "local") != (source == "dir") {
		return Policy{}, fmt.Errorf("lint profile %q is incompatible with source %q", profile, source)
	}
	failOn := options.FailOn
	if failOn == "" {
		failOn = config.FailOn
	}
	if failOn == "" {
		failOn = "warning"
	}
	if failOn != "none" && severityRank(failOn) == 0 {
		return Policy{}, fmt.Errorf("invalid lint failure threshold %q", failOn)
	}
	p := Policy{Version: SchemaVersion, Source: source, Profile: profile, FailOn: failOn,
		Rules: make(map[string]RuleOptions, len(registry)), Suppressions: slices.Clone(config.Suppressions)}
	for i := range p.Suppressions {
		p.Suppressions[i].Fingerprint = strings.ToLower(p.Suppressions[i].Fingerprint)
	}
	if options.RuntimePrefix != "" {
		if source != "oci-archive" {
			return Policy{}, fmt.Errorf("runtime prefix requires an OCI image source")
		}
		if err := validateConfigString("runtime prefix", options.RuntimePrefix); err != nil {
			return Policy{}, err
		}
		if !path.IsAbs(options.RuntimePrefix) || strings.Contains(options.RuntimePrefix, "\\") {
			return Policy{}, fmt.Errorf("runtime prefix must be an absolute image POSIX path")
		}
		for _, part := range strings.Split(options.RuntimePrefix, "/") {
			if part == ".." {
				return Policy{}, fmt.Errorf("runtime prefix must not contain parent traversal")
			}
		}
		p.RuntimePrefix = path.Clean(options.RuntimePrefix)
	}
	if options.Project != "" {
		if source != "dir" {
			return Policy{}, fmt.Errorf("project association requires a local project path")
		}
		if err := validateConfigString("project", options.Project); err != nil {
			return Policy{}, err
		}
		project, err := filepath.Abs(options.Project)
		if err != nil {
			return Policy{}, fmt.Errorf("resolve project path: %w", err)
		}
		p.Project = filepath.Clean(project)
	}
	selected := make(map[string]bool, len(options.Rules))
	disabled := make(map[string]bool, len(options.DisableRules))
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
		enabled := d.Enabled
		explicitlyEnabled := false
		opts := RuleOptions{Severity: d.Severity}
		if d.RevisionThreshold != nil {
			threshold := *d.RevisionThreshold
			opts.RevisionThreshold = &threshold
		}
		if configured, ok := config.Rules[rule.ID]; ok {
			if configured.Enabled != nil {
				enabled = *configured.Enabled
				explicitlyEnabled = enabled
			}
			if configured.Severity != "" {
				opts.Severity = configured.Severity
			}
			if configured.RevisionThreshold != nil {
				threshold := *configured.RevisionThreshold
				opts.RevisionThreshold = &threshold
			}
		}
		if len(selected) > 0 {
			enabled = selected[rule.ID]
		}
		if disabled[rule.ID] {
			enabled = false
		}
		if enabled && explicitlyEnabled && !rule.Available {
			return Policy{}, fmt.Errorf("rule %s is unavailable: %s", rule.ID, rule.UnavailableReason)
		}
		if enabled && !slices.Contains(rule.TargetKinds, source) {
			return Policy{}, fmt.Errorf("rule %s is incompatible with source %q", rule.ID, source)
		}
		opts.Enabled = &enabled
		p.Rules[rule.ID] = opts
	}
	return p, nil
}

// Requirements returns a deterministic set union, excluding disabled,
// unavailable and source-inapplicable rules. Collectors execute that set once.
func Requirements(policy Policy) evidence.Request {
	caps := make(map[string]bool)
	// Explicit assertions are input validation, even when selected rules do not
	// otherwise consume their facts.
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

func ruleEnabled(policy Policy, id string) bool {
	opts, ok := policy.Rules[id]
	return ok && opts.Enabled != nil && *opts.Enabled
}

// Evaluate is pure: snapshots are never changed, and rules receive no I/O
// handles. Positive partial evidence may produce findings, never an all-clear.
func Evaluate(snapshot evidence.Snapshot, policy Policy, now time.Time) Report {
	r := Report{SchemaVersion: SchemaVersion, Tool: "envscout", ToolVersion: "development",
		RulesetVersion: RulesetVersion, ProfileVersion: ProfileVersion, Profile: policy.Profile,
		Source: policy.Source, RuntimePrefix: policy.RuntimePrefix, Project: policy.Project,
		StartedAt: snapshot.Started, Policy: policy, Status: "completed", Limits: ReportLimits{MaxSamples, MaxFindings},
		Targets: []TargetReport{}, Outcomes: []Outcome{}, Findings: []Finding{},
		Issues: slices.Clone(snapshot.Issues), SuppressionNotes: []SuppressionNote{}}
	if r.Issues == nil {
		r.Issues = []evidence.Issue{}
	}
	encoded, err := json.Marshal(struct {
		Policy        Policy `json:"policy"`
		Source        string `json:"source"`
		RuntimePrefix string `json:"runtime_prefix"`
		Project       string `json:"project"`
	}{policy, policy.Source, policy.RuntimePrefix, policy.Project})
	if err != nil {
		r.Status = "failed"
		r.Issues = append(r.Issues, evidence.Issue{Capability: "policy", Message: "cannot serialize effective lint policy"})
		return r
	}
	digest := sha256.Sum256(encoded)
	r.ConfigDigest = "sha256:" + hex.EncodeToString(digest[:])
	if err := ValidateConfig(policy); err != nil || !slices.Contains(profiles, policy.Profile) ||
		(policy.Source != "dir" && policy.Source != "oci-archive") || (policy.Profile == "local") != (policy.Source == "dir") ||
		(policy.FailOn != "none" && severityRank(policy.FailOn) == 0) || len(policy.Rules) != len(registry) {
		r.Status = "failed"
		r.Issues = append(r.Issues, evidence.Issue{Capability: "policy", Message: "lint evaluation requires a normalized effective policy from BuildPolicy"})
		return r
	}
	for _, rule := range registry {
		options, ok := policy.Rules[rule.ID]
		if !ok || options.Enabled == nil || severityRank(options.Severity) == 0 {
			r.Status = "failed"
			r.Issues = append(r.Issues, evidence.Issue{Capability: "policy", Message: "effective rule settings are not normalized"})
			return r
		}
	}
	targets := slices.Clone(snapshot.Targets)
	slices.SortFunc(targets, func(a, b evidence.Target) int { return strings.Compare(a.ID, b.ID) })
	request := Requirements(policy)
	truncated := false
	for _, target := range targets {
		if target.Kind != policy.Source {
			r.Issues = append(r.Issues, evidence.Issue{Capability: "evaluation", Path: target.ID, Message: "snapshot target source does not match effective policy"})
		}
		if policy.RuntimePrefix != "" && target.RuntimePrefix != policy.RuntimePrefix {
			r.Issues = append(r.Issues, evidence.Issue{Capability: "runtime-config", Path: target.ID, Message: "asserted runtime prefix was not verified in target evidence"})
		}
		if policy.Project != "" && (target.Project == nil || !target.Project.Associated || target.Project.Path != policy.Project) {
			r.Issues = append(r.Issues, evidence.Issue{Capability: "project-association", Path: target.ID, Message: "explicit project association was not verified in target evidence"})
		}
		for _, capability := range request.Capabilities {
			if target.Coverage[capability] == evidence.Complete || capability == "history" ||
				(capability == "project-association" && (target.Project == nil || !target.Project.Associated)) {
				continue
			}
			r.Issues = append(r.Issues, evidence.Issue{Capability: capability, Path: target.ID, Message: "required evidence coverage is not complete"})
		}
		coverage := make(map[string]string, len(target.Coverage))
		for capability, state := range target.Coverage {
			coverage[capability] = state
		}
		issues := slices.Clone(target.Issues)
		if issues == nil {
			issues = []evidence.Issue{}
		}
		sortIssues(issues)
		roots := slices.Clone(target.Roots)
		slices.Sort(roots)
		r.Targets = append(r.Targets, TargetReport{ID: target.ID, Kind: target.Kind, Input: target.Input,
			Roots: roots, Image: target.Image, PrefixCount: len(target.Prefixes), RuntimePrefix: target.RuntimePrefix,
			Coverage: coverage, Issues: issues})
		r.Issues = append(r.Issues, issues...)
		primary := []Finding{}
		for _, rule := range registry {
			if rule.ID == "IC005" {
				continue
			}
			outcome, findings := evaluateRule(target, policy, rule)
			primary = append(primary, findings...)
			r.Outcomes = append(r.Outcomes, outcome)
			for _, f := range findings {
				if len(r.Findings) < MaxFindings {
					r.Findings = append(r.Findings, f)
				} else {
					truncated = true
				}
			}
		}
		rule, _ := lookupRule("IC005")
		outcome, contextual := evaluateRule(target, policy, rule)
		for i := range contextual {
			for _, f := range primary {
				if strings.HasPrefix(f.RuleID, "IC") {
					contextual[i].RelatedFindings = append(contextual[i].RelatedFindings, f.Fingerprint)
				}
			}
			slices.Sort(contextual[i].RelatedFindings)
			contextual[i].RelatedFindings = sampleStrings(contextual[i].RelatedFindings)
			if len(r.Findings) < MaxFindings {
				r.Findings = append(r.Findings, contextual[i])
			} else {
				truncated = true
			}
		}
		r.Outcomes = append(r.Outcomes, outcome)
	}
	if truncated {
		r.Issues = append(r.Issues, evidence.Issue{Capability: "evaluation", Message: fmt.Sprintf("finding limit %d exceeded; report is truncated", MaxFindings)})
	}
	applySuppressions(&r, now)
	groups := make(map[string][]Finding)
	for _, f := range r.Findings {
		key := f.Target + "\x00" + f.RuleID
		groups[key] = append(groups[key], f)
	}
	for i := range r.Outcomes {
		outcome := &r.Outcomes[i]
		outcome.Findings = []string{}
		allSuppressed := true
		for _, f := range groups[outcome.Target+"\x00"+outcome.RuleID] {
			outcome.Findings = append(outcome.Findings, f.Fingerprint)
			allSuppressed = allSuppressed && f.Suppression != nil
		}
		slices.Sort(outcome.Findings)
		if outcome.Status == FindingStatus && len(outcome.Findings) > 0 && allSuppressed {
			outcome.Status = Suppressed
		}
	}
	if len(r.Issues) > 0 {
		r.Status = "incomplete"
	}
	slices.SortFunc(r.Findings, func(a, b Finding) int {
		if n := strings.Compare(a.Target, b.Target); n != 0 {
			return n
		}
		if n := strings.Compare(a.RuleID, b.RuleID); n != 0 {
			return n
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	slices.SortFunc(r.Outcomes, func(a, b Outcome) int {
		if n := strings.Compare(a.Target, b.Target); n != 0 {
			return n
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	sortIssues(r.Issues)
	return r
}

func sortIssues(issues []evidence.Issue) {
	slices.SortFunc(issues, func(a, b evidence.Issue) int {
		if n := strings.Compare(a.Capability, b.Capability); n != 0 {
			return n
		}
		if n := strings.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return strings.Compare(a.Message, b.Message)
	})
}

func applySuppressions(report *Report, now time.Time) {
	targets := make(map[string]evidence.Target, len(report.Targets))
	for _, target := range report.Targets {
		targets[target.ID] = evidence.Target{ID: target.ID, Kind: target.Kind}
	}
	for index, suppression := range report.Policy.Suppressions {
		if suppression.Expires != "" {
			expiry, err := time.Parse("2006-01-02", suppression.Expires)
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
			if suppression.Path != "" {
				pathMatches := slices.Contains(f.paths, suppression.Path)
				if target, ok := targets[f.Target]; !pathMatches && ok {
					for _, p := range f.paths {
						if location(target, p) == suppression.Path {
							pathMatches = true
							break
						}
					}
				}
				if !pathMatches {
					continue
				}
			}
			matched = true
			if f.Suppression == nil {
				copy := suppression
				f.Suppression = &copy
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

func location(target evidence.Target, p string) string {
	if target.Kind == "oci-archive" {
		return target.ID + "#" + (&url.URL{Path: p}).EscapedPath()
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(p)}).String()
}
