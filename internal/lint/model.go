// Package lint evaluates immutable facts against an explicit, versioned policy.
package lint

import (
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/imageinput"
)

const (
	// ConfigVersion is the version of the --config policy file format; unchanged since 1.
	ConfigVersion = 1
	// SchemaVersion is the JSON report contract; 4 adds per-instance next actions.
	SchemaVersion = 4
	// RulesetVersion changes when rule identities or predicates change.
	RulesetVersion = "5"
	// ProfileVersion is the version of the lint profile set.
	ProfileVersion = "3"
	MaxSamples     = 20
	MaxFindings    = 5000
)

// Severity is the severity of a finding or a configured rule. NoFailure is a
// failure-threshold value only and is never a finding severity.
type Severity string

const (
	Info      Severity = "info"
	Warning   Severity = "warning"
	Error     Severity = "error"
	NoFailure Severity = "none"
)

// Rank orders severities for threshold comparisons. Unknown and blank values
// and NoFailure rank 0.
func (s Severity) Rank() int {
	switch s {
	case Info:
		return 1
	case Warning:
		return 2
	case Error:
		return 3
	}
	return 0
}

// Valid reports whether s is a finding severity (info, warning or error).
func (s Severity) Valid() bool {
	return s == Info || s == Warning || s == Error
}

// Status is the evaluation outcome of one rule against one target.
type Status string

const (
	Pass          Status = "pass"
	FindingStatus Status = "finding"
	Unknown       Status = "unknown"
	NotApplicable Status = "not_applicable"
	Disabled      Status = "disabled"
	Unavailable   Status = "unavailable"
	Suppressed    Status = "suppressed"
)

// Empty scalar options mean the CLI did not explicitly set that option.
type Options struct {
	Source        string
	Profile       string
	FailOn        string
	Rules         []string
	DisableRules  []string
	RuntimePrefix string
	Project       string
}

type RuleDefault struct {
	Enabled           bool     `json:"enabled"`
	Severity          Severity `json:"severity"`
	RevisionThreshold *int     `json:"revision_threshold,omitempty"`
}

// Rule is the immutable metadata and evaluation entry for one lint rule.
// Check is nil only for unavailable design entries.
type Rule struct {
	ID                string                 `json:"id"`
	Version           string                 `json:"version"`
	Name              string                 `json:"name"`
	Category          string                 `json:"category"`
	Description       string                 `json:"description"`
	TargetKinds       []string               `json:"target_kinds"`
	Capabilities      []string               `json:"capabilities"`
	Defaults          map[string]RuleDefault `json:"profile_defaults"`
	Available         bool                   `json:"available"`
	UnavailableReason string                 `json:"unavailable_reason,omitempty"`
	Confidence        string                 `json:"confidence,omitempty"`
	Fix               string                 `json:"recommendation,omitempty"`
	References        []string               `json:"references"`
	Exceptions        []string               `json:"known_exceptions"`
	// SupportsRevisionThreshold is true only for rules whose option set accepts a revision threshold.
	SupportsRevisionThreshold bool `json:"-"`
	// Check returns the rule's observation; the engine supplies target/ID/status.
	Check func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding) `json:"-"`
	// prepare optionally shares immutable per-evaluation facts across target checks.
	prepare func([]evidence.Prefix) func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding)
}

type Outcome struct {
	// limited tells the engine to retain positives but mark evaluation incomplete.
	limited      bool
	RuleID       string `json:"rule_id"`
	Target       string `json:"target"`
	Status       Status `json:"status"`
	Reason       string `json:"reason,omitempty"`
	SubjectCount int    `json:"subject_count"`
}

// Evidence samples are bounded; Count and PayloadBytes describe all observed
// artifacts in the group, not merely the displayed sample or reclaimable space.
type FindingEvidence struct {
	Paths              []string            `json:"paths"`
	Locations          []string            `json:"locations"`
	Samples            []evidence.Artifact `json:"samples"`
	Count              int                 `json:"count"`
	PayloadBytes       int64               `json:"payload_bytes,omitempty"`
	ByteUnit           string              `json:"byte_unit,omitempty"`
	Revision           *int                `json:"revision,omitempty"`
	RevisionThreshold  *int                `json:"revision_threshold,omitempty"`
	ToolingPrefixes    []string            `json:"tooling_prefixes,omitempty"`
	AppPrefixes        []string            `json:"app_prefixes,omitempty"`
	RuntimePrefix      string              `json:"runtime_prefix,omitempty"`
	RuntimeUsesTooling bool                `json:"runtime_uses_tooling,omitempty"`
	CacheLinked        bool                `json:"cache_linked,omitempty"`
	LinkCoverage       string              `json:"link_coverage,omitempty"`
	Project            *evidence.Project   `json:"project,omitempty"`
	Notes              []string            `json:"notes,omitempty"`
}

// Finding carries only per-instance data. Rule metadata (version, confidence,
// category, references, recommendation) is available via LookupRule(RuleID).
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Target   string   `json:"target"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	// Next overrides the catalogue's generic fix when an instance can name its command.
	Next        string          `json:"next,omitempty"`
	Evidence    FindingEvidence `json:"evidence"`
	Fingerprint string          `json:"fingerprint"`
	Suppression *Suppression    `json:"suppression,omitempty"`
	paths       []string
}

type SuppressionNote struct {
	Index  int    `json:"index"`
	Rule   string `json:"rule"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// TargetReport excludes unbounded fact arrays and raw runtime configuration.
type TargetReport struct {
	ID            string               `json:"id"`
	Kind          string               `json:"kind"`
	Input         string               `json:"input"`
	Roots         []string             `json:"roots,omitempty"`
	Image         *imageinput.Identity `json:"image,omitempty"`
	PrefixCount   int                  `json:"prefix_count"`
	RuntimePrefix string               `json:"runtime_prefix,omitempty"`
	Coverage      map[string]string    `json:"coverage"`
	Issues        []evidence.Issue     `json:"issues"`
}

type Report struct {
	SchemaVersion    int               `json:"schema_version"`
	Tool             string            `json:"tool"`
	ToolVersion      string            `json:"tool_version"`
	RulesetVersion   string            `json:"ruleset_version"`
	ProfileVersion   string            `json:"profile_version"`
	Profile          string            `json:"profile"`
	Source           string            `json:"source"`
	RuntimePrefix    string            `json:"runtime_prefix,omitempty"`
	Project          string            `json:"project,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	EvaluatedAt      time.Time         `json:"evaluated_at"`
	ConfigDigest     string            `json:"config_digest"`
	Policy           Policy            `json:"policy"`
	Targets          []TargetReport    `json:"targets"`
	Outcomes         []Outcome         `json:"outcomes"`
	OutcomeCounts    map[Status]int    `json:"outcome_counts"`
	Findings         []Finding         `json:"findings"`
	Issues           []evidence.Issue  `json:"issues"`
	SuppressionNotes []SuppressionNote `json:"suppression_notes"`
	Status           string            `json:"status"`
	Limits           ReportLimits      `json:"limits"`
}

type ReportLimits struct {
	EvidenceSamples int `json:"evidence_samples"`
	Findings        int `json:"findings"`
}

// ExitCode returns 2 for an incomplete or failed evaluation, 1 when an
// unsuppressed finding meets the fail-on threshold, and 0 otherwise.
func (r Report) ExitCode() int {
	if r.Status != "completed" {
		return 2
	}
	if r.Policy.FailOn == NoFailure {
		return 0
	}
	threshold := r.Policy.FailOn.Rank()
	if threshold == 0 {
		threshold = Warning.Rank()
	}
	for _, f := range r.Findings {
		if f.Suppression == nil && f.Severity.Rank() >= threshold {
			return 1
		}
	}
	return 0
}
