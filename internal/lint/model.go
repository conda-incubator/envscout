// Package lint evaluates immutable facts against an explicit, versioned policy.
package lint

import (
	"time"

	"github.com/anaconda/envscout/internal/evidence"
	"github.com/anaconda/envscout/internal/imageinput"
)

const (
	// ConfigVersion is the version of the --config policy file format; unchanged since 1.
	ConfigVersion = 1
	// SchemaVersion is the version of the JSON lint report; 2 removed Finding.related_findings and Finding.contextual.
	SchemaVersion = 2
	// RulesetVersion is the version of the rule set; 2 removed IC005.
	RulesetVersion = "2"
	// ProfileVersion is the version of the lint profile set.
	ProfileVersion = "1"
	MaxSamples     = 20
	MaxFindings    = 5000

	Pass          = "pass"
	FindingStatus = "finding"
	Unknown       = "unknown"
	NotApplicable = "not_applicable"
	Disabled      = "disabled"
	Unavailable   = "unavailable"
	Suppressed    = "suppressed"
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
	Enabled           bool   `json:"enabled"`
	Severity          string `json:"severity"`
	RevisionThreshold *int   `json:"revision_threshold,omitempty"`
}

type Rule struct {
	ID                string                 `json:"id"`
	Version           string                 `json:"version"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Category          string                 `json:"category"`
	TargetKinds       []string               `json:"target_kinds"`
	Capabilities      []string               `json:"capabilities"`
	Defaults          map[string]RuleDefault `json:"profile_defaults"`
	Available         bool                   `json:"available"`
	UnavailableReason string                 `json:"unavailable_reason,omitempty"`
	References        []string               `json:"references"`
	Exceptions        []string               `json:"known_exceptions"`
}

type Outcome struct {
	RuleID       string   `json:"rule_id"`
	RuleVersion  string   `json:"rule_version"`
	Target       string   `json:"target"`
	Status       string   `json:"status"`
	Reason       string   `json:"reason,omitempty"`
	SubjectCount int      `json:"subject_count"`
	Findings     []string `json:"findings"`
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

type Finding struct {
	RuleID         string          `json:"rule_id"`
	RuleVersion    string          `json:"rule_version"`
	Target         string          `json:"target"`
	Severity       string          `json:"severity"`
	Confidence     string          `json:"confidence"`
	Category       string          `json:"category"`
	Message        string          `json:"message"`
	Evidence       FindingEvidence `json:"evidence"`
	Recommendation string          `json:"recommendation"`
	References     []string        `json:"references"`
	Fingerprint    string          `json:"fingerprint"`
	Suppression    *Suppression    `json:"suppression,omitempty"`
	paths          []string
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
	ConfigDigest     string            `json:"config_digest"`
	Policy           Policy            `json:"policy"`
	Targets          []TargetReport    `json:"targets"`
	Outcomes         []Outcome         `json:"outcomes"`
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

func (r Report) ExitCode() int {
	if r.Status != "completed" {
		return 2
	}
	if r.Policy.FailOn == "none" {
		return 0
	}
	threshold := severityRank(r.Policy.FailOn)
	if threshold == 0 {
		threshold = severityRank("warning")
	}
	for _, f := range r.Findings {
		if f.Suppression == nil && severityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

func severityRank(severity string) int {
	switch severity {
	case "info":
		return 1
	case "warning":
		return 2
	case "error":
		return 3
	}
	return 0
}
