package lint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	maxConfigBytes        = 1 << 20
	maxConfigRules        = 32
	maxConfigSuppressions = 256
)

// Policy contains explicit configuration overrides, before profile and CLI merging.
type Policy struct {
	Version      int                    `json:"version"`
	Profile      string                 `json:"profile,omitempty"`
	FailOn       string                 `json:"fail_on,omitempty"`
	Rules        map[string]RuleOptions `json:"rules,omitempty"`
	Suppressions []Suppression          `json:"suppressions,omitempty"`
	// Execution inputs are set by the engine and cannot be supplied in config JSON.
	Source        string `json:"-"`
	RuntimePrefix string `json:"-"`
	Project       string `json:"-"`
}

type RuleOptions struct {
	Enabled           *bool  `json:"enabled,omitempty"`
	Severity          string `json:"severity,omitempty"`
	RevisionThreshold *int   `json:"revision_threshold,omitempty"`
}

type Suppression struct {
	Rule        string `json:"rule"`
	Target      string `json:"target,omitempty"`
	Path        string `json:"path,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Reason      string `json:"reason"`
	Expires     string `json:"expires,omitempty"`
}

var configRuleIDs = map[string]struct{}{
	"EC001": {}, "EC002": {}, "EC003": {}, "EC004": {},
	"IC001": {}, "IC002": {}, "IC003": {}, "IC004": {},
	"IC006": {}, "IC007": {},
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
	switch policy.Profile {
	case "", "local", "container", "container-runtime", "container-distroless", "container-development":
	default:
		return fmt.Errorf("unknown profile %q", policy.Profile)
	}
	switch policy.FailOn {
	case "", "none", "info", "warning", "error":
	default:
		return fmt.Errorf("invalid fail_on %q", policy.FailOn)
	}
	ids := make([]string, 0, len(policy.Rules))
	for id := range policy.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := configRuleIDs[id]; !ok {
			return fmt.Errorf("unknown rule ID %q", id)
		}
		options := policy.Rules[id]
		switch options.Severity {
		case "", "info", "warning", "error":
		default:
			return fmt.Errorf("invalid severity %q for rule %q", options.Severity, id)
		}
		if options.RevisionThreshold != nil {
			if id != "EC001" {
				return fmt.Errorf("revision_threshold is only supported for EC001, not %q", id)
			}
			if *options.RevisionThreshold <= 0 || *options.RevisionThreshold > 1_000_000 {
				return fmt.Errorf("EC001 revision_threshold must be between 1 and 1000000")
			}
		}
	}
	for i, suppression := range policy.Suppressions {
		if _, ok := configRuleIDs[suppression.Rule]; !ok {
			return fmt.Errorf("suppression %d: unknown rule ID %q", i+1, suppression.Rule)
		}
		if strings.TrimSpace(suppression.Reason) == "" {
			return fmt.Errorf("suppression %d: reason is required", i+1)
		}
		if suppression.Target == "" && suppression.Path == "" && suppression.Fingerprint == "" {
			return fmt.Errorf("suppression %d: target, path or fingerprint is required", i+1)
		}
		if suppression.Fingerprint != "" {
			if len(suppression.Fingerprint) != 64 {
				return fmt.Errorf("suppression %d: fingerprint must be a 64-character SHA256 hex digest", i+1)
			}
			if _, err := hex.DecodeString(suppression.Fingerprint); err != nil {
				return fmt.Errorf("suppression %d: fingerprint must be a 64-character SHA256 hex digest", i+1)
			}
		}
		if suppression.Expires != "" {
			expires, err := time.Parse(time.DateOnly, suppression.Expires)
			if err != nil || expires.Format(time.DateOnly) != suppression.Expires {
				return fmt.Errorf("suppression %d: expires must be a valid UTC date in yyyy-mm-dd format", i+1)
			}
		}
	}
	return nil
}
