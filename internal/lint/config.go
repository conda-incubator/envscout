package lint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	maxConfigBytes        = 1 << 20
	maxConfigRules        = 32
	maxConfigSuppressions = 256
	maxRevisionThreshold  = 1_000_000
)

// Policy contains explicit configuration overrides, before profile and CLI merging.
type Policy struct {
	Version      int                    `json:"version"`
	Profile      string                 `json:"profile,omitempty"`
	FailOn       Severity               `json:"fail_on,omitempty"`
	Rules        map[string]RuleOptions `json:"rules,omitempty"`
	Suppressions []Suppression          `json:"suppressions,omitempty"`
	// Execution inputs are set by the engine and cannot be supplied in config JSON.
	Source        string `json:"-"`
	RuntimePrefix string `json:"-"`
	Project       string `json:"-"`
}

type RuleOptions struct {
	Enabled           *bool    `json:"enabled,omitempty"`
	Severity          Severity `json:"severity,omitempty"`
	RevisionThreshold *int     `json:"revision_threshold,omitempty"`
}

type Suppression struct {
	Rule        string `json:"rule"`
	Target      string `json:"target,omitempty"`
	Path        string `json:"path,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason"`
	Expires     string `json:"expires,omitempty"`
}

// ReadConfig reads one bounded regular JSON file. It never reads targets.
func ReadConfig(filename string) (Policy, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("stat lint config %q: %w", filename, err)
	}
	if !info.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("lint config %q must be a regular file", filename)
	}
	if info.Size() > maxConfigBytes {
		return Policy{}, fmt.Errorf("lint config exceeds %d bytes", maxConfigBytes)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("read lint config %q: %w", filename, err)
	}
	if len(data) > maxConfigBytes {
		return Policy{}, fmt.Errorf("lint config exceeds %d bytes", maxConfigBytes)
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode lint config: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return Policy{}, fmt.Errorf("trailing JSON: %w", err)
		}
		return Policy{}, fmt.Errorf("trailing JSON value")
	}
	if err := ValidateConfig(policy); err != nil {
		return Policy{}, fmt.Errorf("invalid lint config: %w", err)
	}
	return policy, nil
}

// ValidateConfig checks policy syntax without resolving selectors or applying defaults.
func ValidateConfig(policy Policy) error {
	if policy.Version != ConfigVersion {
		return fmt.Errorf("version must be %d", ConfigVersion)
	}
	if len(policy.Rules) > maxConfigRules {
		return fmt.Errorf("rules exceed the limit of %d", maxConfigRules)
	}
	if len(policy.Suppressions) > maxConfigSuppressions {
		return fmt.Errorf("suppressions exceed the limit of %d", maxConfigSuppressions)
	}
	if policy.Profile != "" && !slices.Contains(profiles, policy.Profile) {
		return fmt.Errorf("unknown profile %q", policy.Profile)
	}
	if policy.FailOn != "" && policy.FailOn != NoFailure && !policy.FailOn.Valid() {
		return fmt.Errorf("invalid fail_on %q", policy.FailOn)
	}
	ids := make([]string, 0, len(policy.Rules))
	for id := range policy.Rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		rule, ok := lookupRule(id)
		if !ok {
			return fmt.Errorf("unknown rule ID %q", id)
		}
		options := policy.Rules[id]
		if options.Severity != "" && !options.Severity.Valid() {
			return fmt.Errorf("invalid severity %q for rule %q", options.Severity, id)
		}
		if options.RevisionThreshold != nil {
			if !rule.SupportsRevisionThreshold {
				return fmt.Errorf("revision_threshold is only supported for rules with a revision threshold, not %q", id)
			}
			if *options.RevisionThreshold <= 0 || *options.RevisionThreshold > maxRevisionThreshold {
				return fmt.Errorf("%s revision_threshold must be between 1 and %d", id, maxRevisionThreshold)
			}
		}
	}
	for i, suppression := range policy.Suppressions {
		if err := validateSuppression(suppression); err != nil {
			return fmt.Errorf("suppression %d: %w", i+1, err)
		}
	}
	return nil
}

func validateSuppression(suppression Suppression) error {
	if _, ok := lookupRule(suppression.Rule); !ok {
		return fmt.Errorf("unknown rule ID %q", suppression.Rule)
	}
	if strings.TrimSpace(suppression.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if suppression.Target == "" && suppression.Path == "" && suppression.Fingerprint == "" {
		return fmt.Errorf("target, path or fingerprint is required")
	}
	if suppression.Fingerprint != "" {
		if len(suppression.Fingerprint) != 64 {
			return fmt.Errorf("fingerprint must be a 64-character SHA256 hex digest")
		}
		if _, err := hex.DecodeString(suppression.Fingerprint); err != nil {
			return fmt.Errorf("fingerprint must be a 64-character SHA256 hex digest")
		}
	}
	if suppression.Expires != "" {
		expires, err := time.Parse(time.DateOnly, suppression.Expires)
		if err != nil || expires.Format(time.DateOnly) != suppression.Expires {
			return fmt.Errorf("expires must be a valid UTC date in yyyy-mm-dd format")
		}
	}
	return nil
}
