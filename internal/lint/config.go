package lint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxConfigBytes        = 1 << 20
	maxConfigDepth        = 32
	maxConfigRules        = 32
	maxConfigSuppressions = 256
	maxConfigStringBytes  = 2048
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
	"IC005": {}, "IC006": {}, "IC007": {},
}

// ReadConfig reads one bounded, non-symlink regular JSON file. It never reads targets.
func ReadConfig(filename string) (policy Policy, err error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("stat lint config %q: %w", filename, err)
	}
	if !info.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("lint config %q must be a non-symlink regular file", filename)
	}
	if info.Size() > maxConfigBytes {
		return Policy{}, fmt.Errorf("lint config exceeds %d bytes", maxConfigBytes)
	}
	f, err := os.Open(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("open lint config %q: %w", filename, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			policy = Policy{}
			err = fmt.Errorf("close lint config %q: %w", filename, closeErr)
		}
	}()

	// Verify the descriptor and path still identify the checked regular file.
	opened, err := f.Stat()
	if err != nil {
		return Policy{}, fmt.Errorf("stat open lint config %q: %w", filename, err)
	}
	current, err := os.Lstat(filename)
	if err != nil {
		return Policy{}, fmt.Errorf("recheck lint config %q: %w", filename, err)
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return Policy{}, fmt.Errorf("lint config %q changed while opening", filename)
	}
	if opened.Size() > maxConfigBytes {
		return Policy{}, fmt.Errorf("lint config exceeds %d bytes", maxConfigBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read lint config %q: %w", filename, err)
	}
	if len(data) > maxConfigBytes {
		return Policy{}, fmt.Errorf("lint config exceeds %d bytes", maxConfigBytes)
	}
	if int64(len(data)) != opened.Size() {
		return Policy{}, fmt.Errorf("lint config %q changed length while reading", filename)
	}
	if err := checkConfigJSON(data); err != nil {
		return Policy{}, fmt.Errorf("invalid lint config: %w", err)
	}
	if err := checkConfigJSONFields(data); err != nil {
		return Policy{}, fmt.Errorf("invalid lint config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode lint config: %w", err)
	}
	if err := ValidateConfig(policy); err != nil {
		return Policy{}, fmt.Errorf("invalid lint config: %w", err)
	}
	return policy, nil
}

// ValidateConfig checks policy syntax without resolving selectors or applying defaults.
func ValidateConfig(policy Policy) error {
	if policy.Version != 1 {
		return fmt.Errorf("version must be 1")
	}
	if len(policy.Rules) > maxConfigRules {
		return fmt.Errorf("rules exceed the limit of %d", maxConfigRules)
	}
	if len(policy.Suppressions) > maxConfigSuppressions {
		return fmt.Errorf("suppressions exceed the limit of %d", maxConfigSuppressions)
	}
	if err := validateConfigString("profile", policy.Profile); err != nil {
		return err
	}
	switch policy.Profile {
	case "", "local", "container", "container-runtime", "container-distroless", "container-development":
	default:
		return fmt.Errorf("unknown profile %q", policy.Profile)
	}
	if err := validateConfigString("fail_on", policy.FailOn); err != nil {
		return err
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
		if err := validateConfigString("rule ID", id); err != nil {
			return err
		}
		if _, ok := configRuleIDs[id]; !ok {
			return fmt.Errorf("unknown rule ID %q", id)
		}
		options := policy.Rules[id]
		if err := validateConfigString("rule severity", options.Severity); err != nil {
			return err
		}
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
		for _, field := range []struct{ name, value string }{
			{"rule", suppression.Rule}, {"target", suppression.Target},
			{"path", suppression.Path}, {"fingerprint", suppression.Fingerprint},
			{"reason", suppression.Reason}, {"expires", suppression.Expires},
		} {
			if err := validateConfigString(field.name, field.value); err != nil {
				return fmt.Errorf("suppression %d: %w", i+1, err)
			}
		}
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

func validateConfigString(field, value string) error {
	if len(value) > maxConfigStringBytes {
		return fmt.Errorf("%s exceeds %d bytes", field, maxConfigStringBytes)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return fmt.Errorf("%s contains a control or line-separator character", field)
		}
	}
	return nil
}

func checkConfigJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("JSON must contain a policy object")
	}
	if err := scanConfigJSON(decoder, token, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("trailing JSON: %w", err)
		}
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

// Struct decoding accepts case-insensitive aliases, so check decoded keys exactly first.
func checkConfigJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var policy map[string]any
	if err := decoder.Decode(&policy); err != nil {
		return err
	}
	checkFields := func(object map[string]any, allowed ...string) error {
		for key := range object {
			if !slices.Contains(allowed, key) {
				return fmt.Errorf("unknown field %q", key)
			}
		}
		return nil
	}
	if err := checkFields(policy, "version", "profile", "fail_on", "rules", "suppressions"); err != nil {
		return err
	}
	if rules, ok := policy["rules"].(map[string]any); ok {
		for _, value := range rules {
			if options, ok := value.(map[string]any); ok {
				if err := checkFields(options, "enabled", "severity", "revision_threshold"); err != nil {
					return err
				}
			}
		}
	}
	if suppressions, ok := policy["suppressions"].([]any); ok {
		for _, value := range suppressions {
			if suppression, ok := value.(map[string]any); ok {
				if err := checkFields(suppression, "rule", "target", "path", "fingerprint", "reason", "expires"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Token scanning catches escaped duplicate keys before typed decoding loses them.
func scanConfigJSON(decoder *json.Decoder, token json.Token, depth int) error {
	delim, container := token.(json.Delim)
	if !container {
		if value, ok := token.(string); ok {
			return validateConfigString("JSON string", value)
		}
		return nil
	}
	if depth > maxConfigDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxConfigDepth)
	}
	var closing json.Delim
	switch delim {
	case '{':
		closing = '}'
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key must be a string")
			}
			if err := validateConfigString("JSON object key", key); err != nil {
				return err
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanConfigJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanConfigJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != closing {
		return fmt.Errorf("expected JSON delimiter %q", closing)
	}
	return nil
}
