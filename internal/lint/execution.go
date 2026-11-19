package lint

import (
	"slices"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/evidence"
)

// Configuration and wire identity stay in Policy; execution reads explicit enablement.
type executionPolicy struct {
	source, runtimePrefix, project string
	rules                          map[string]executionRule
}

type executionRule struct {
	enabled           bool
	severity          Severity
	revisionThreshold *int
}

func executionFromPolicy(policy Policy) executionPolicy {
	execution := executionPolicy{source: policy.Source, runtimePrefix: policy.RuntimePrefix,
		project: policy.Project, rules: make(map[string]executionRule, len(policy.Rules))}
	for id, options := range policy.Rules {
		execution.rules[id] = executionRule{enabled: options.Enabled != nil && *options.Enabled,
			severity: options.Severity, revisionThreshold: options.RevisionThreshold}
	}
	return execution
}

func (execution executionPolicy) requirements() evidence.Request {
	caps := make(map[string]bool)
	venvCaps := make(map[string]bool)
	if execution.runtimePrefix != "" {
		caps["runtime-config"] = true
	}
	if execution.project != "" {
		caps["project-association"] = true
	}
	for _, rule := range registry {
		if !rule.Available || !execution.rules[rule.ID].enabled || !slices.Contains(rule.TargetKinds, execution.source) {
			continue
		}
		for _, capability := range rule.Capabilities {
			caps[capability] = true
		}
		if execution.source == "dir" {
			for _, capability := range rule.VirtualenvCapabilities {
				venvCaps[capability] = true
			}
		}
	}
	request := evidence.Request{Capabilities: make([]string, 0, len(caps)), RuntimePrefix: execution.runtimePrefix, Project: execution.project}
	for capability := range caps {
		request.Capabilities = append(request.Capabilities, capability)
	}
	for capability := range venvCaps {
		request.VirtualenvCapabilities = append(request.VirtualenvCapabilities, capability)
	}
	slices.Sort(request.Capabilities)
	slices.Sort(request.VirtualenvCapabilities)
	return request
}

// History coverage is non-fatal and an unassociated project is allowed.
func (execution executionPolicy) targetIssues(target evidence.Target, request evidence.Request) []evidence.Issue {
	var issues []evidence.Issue
	if target.IsVirtualenv() {
		request = request.ForEnvironment(discovery.KindVenv)
		for _, rule := range registry {
			if execution.rules[rule.ID].enabled && rule.Available && len(rule.VirtualenvCapabilities) == 0 {
				issues = append(issues, evidence.Issue{Capability: "evaluation", Path: target.Input, Message: rule.ID + " virtualenv lint is not supported yet"})
			}
		}
	}
	if target.Kind != execution.source {
		issues = append(issues, evidence.Issue{Capability: "evaluation", Path: target.ID, Message: "snapshot target source does not match effective policy"})
	}
	if execution.runtimePrefix != "" && target.RuntimePrefix != execution.runtimePrefix {
		issues = append(issues, evidence.Issue{Capability: "runtime-config", Path: target.ID, Message: "asserted runtime prefix was not verified in target evidence"})
	}
	if execution.project != "" && !target.IsVirtualenv() && (target.Project == nil || !target.Project.Associated || target.Project.Path != execution.project) {
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

func (execution executionPolicy) evaluateRule(target evidence.Target, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{RuleID: rule.ID, Target: target.ID, Status: Pass}
	options := execution.rules[rule.ID]
	switch {
	case !options.enabled:
		outcome.Status = Disabled
	case !rule.Available:
		outcome.Status, outcome.Reason = Unavailable, rule.UnavailableReason
	case !slices.Contains(rule.TargetKinds, target.Kind):
		outcome.Status, outcome.Reason = NotApplicable, "rule does not apply to this source kind"
	case target.IsVirtualenv() && len(rule.VirtualenvCapabilities) == 0:
		outcome.Status, outcome.Reason = Unknown, "virtualenv lint is not supported yet for this rule"
	case rule.Check == nil:
		outcome.Status, outcome.Reason = Unknown, "rule has no evaluation entry"
	default:
		checked, findings := rule.Check(target, RuleOptions{Enabled: &options.enabled,
			Severity: options.severity, RevisionThreshold: options.revisionThreshold}, rule)
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
