package lint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestReadConfigValid(t *testing.T) {
	filename := writeLintConfig(t, `{
		"version": 1,
		"profile": "container-runtime",
		"fail_on": "warning",
		"rules": {
			"EC001": {"enabled": true, "severity": "info", "revision_threshold": 12},
			"IC004": {"enabled": false}
		},
		"suppressions": [{
			"rule": "IC001",
			"target": "oci:sha256:example/linux/amd64",
			"path": "/opt/conda/pkgs",
			"fingerprint": "`+strings.Repeat("a", 64)+`",
			"reason": "Intentional offline package cache",
			"expires": "2028-02-29"
		}]
	}`)
	policy, err := ReadConfig(filename)
	if err != nil {
		t.Fatal(err)
	}
	want := Policy{
		Version: 1, Profile: "container-runtime", FailOn: Warning,
		Rules: map[string]RuleOptions{
			"EC001": {Enabled: new(true), Severity: Info, RevisionThreshold: new(12)},
			"IC004": {Enabled: new(false)},
		},
		Suppressions: []Suppression{{
			Rule: "IC001", Target: "oci:sha256:example/linux/amd64", Path: "/opt/conda/pkgs",
			Fingerprint: strings.Repeat("a", 64), Reason: "Intentional offline package cache", Expires: "2028-02-29",
		}},
	}
	if !reflect.DeepEqual(policy, want) {
		t.Fatalf("policy = %+v, want %+v", policy, want)
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ReadConfig(writeLintConfig(t, string(encoded)))
	if err != nil || !reflect.DeepEqual(roundTrip, policy) {
		t.Fatalf("snake_case round trip = %+v, %v", roundTrip, err)
	}
	if err := os.Remove(filename); err != nil {
		t.Fatalf("config file was not released: %v", err)
	}
}

func TestReadConfigRejectsInvalidJSON(t *testing.T) {
	for _, tt := range []struct {
		name, data, message string
	}{
		{"empty", "", "decode lint config"},
		{"malformed", `{"version":1`, "decode lint config"},
		{"invalid token", `{"version":not_json}`, "decode lint config"},
		{"trailing comma", `{"version":1,}`, "decode lint config"},
		{"array", `[{"version":1}]`, "decode lint config"},
		{"null", `null`, "version must be 1"},
		{"scalar", `1`, "decode lint config"},
		{"missing version", `{}`, "version must be 1"},
		{"old version", `{"version":0}`, "version must be 1"},
		{"future version", `{"version":2}`, "version must be 1"},
		{"null version", `{"version":null}`, "version must be 1"},
		{"fractional version", `{"version":1.0}`, "decode lint config"},
		{"exponent version", `{"version":1e0}`, "decode lint config"},
		{"string version", `{"version":"1"}`, "decode lint config"},
		{"overflow version", `{"version":999999999999999999999999999999}`, "decode lint config"},
		{"unknown root field", `{"version":1,"unexpected":true}`, "unknown field"},
		{"transient source", `{"version":1,"source":"dir"}`, "unknown field"},
		{"transient runtime prefix", `{"version":1,"runtime_prefix":"/opt/conda"}`, "unknown field"},
		{"transient project", `{"version":1,"project":"/missing/project"}`, "unknown field"},
		{"unknown rule field", `{"version":1,"rules":{"EC001":{"unexpected":true}}}`, "unknown field"},
		{"threshold wrong name", `{"version":1,"rules":{"EC001":{"revisionThreshold":10}}}`, "unknown field"},
		{"unknown suppression field", `{"version":1,"suppressions":[{"rule":"EC001","target":"x","reason":"reviewed","unexpected":1}]}`, "unknown field"},
		{"trailing object", `{"version":1} {"version":1}`, "trailing JSON"},
		{"trailing array", `{"version":1} []`, "trailing JSON"},
		{"trailing null", `{"version":1} null`, "trailing JSON"},
		{"trailing scalar", `{"version":1} 2`, "trailing JSON"},
		{"trailing garbage", `{"version":1} garbage`, "trailing JSON"},
		{"fractional threshold", `{"version":1,"rules":{"EC001":{"revision_threshold":1.5}}}`, "decode lint config"},
		{"decimal threshold", `{"version":1,"rules":{"EC001":{"revision_threshold":10.0}}}`, "decode lint config"},
		{"exponent threshold", `{"version":1,"rules":{"EC001":{"revision_threshold":1e1}}}`, "decode lint config"},
		{"string threshold", `{"version":1,"rules":{"EC001":{"revision_threshold":"10"}}}`, "decode lint config"},
		{"overflow threshold", `{"version":1,"rules":{"EC001":{"revision_threshold":999999999999999999999999999999}}}`, "decode lint config"},
		{"nonboolean enabled", `{"version":1,"rules":{"EC001":{"enabled":0}}}`, "decode lint config"},
		{"rule array", `{"version":1,"rules":[]}`, "decode lint config"},
		{"suppression object", `{"version":1,"suppressions":{}}`, "decode lint config"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := ReadConfig(writeLintConfig(t, tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("ReadConfig error = %v, want %q", err, tt.message)
			}
			if !reflect.DeepEqual(policy, Policy{}) {
				t.Fatalf("invalid input returned a partial policy: %+v", policy)
			}
		})
	}
}

func TestReadConfigOptionalFieldsAndExactSelectors(t *testing.T) {
	for _, data := range []string{
		" \n\t" + `{"version":1}` + "\r\n\t ",
		`{"version":1,"rules":{"EC001":{},"IC001":{}},"suppressions":[]}`,
		`{"version":1,"suppressions":[{"rule":"EC001","path":"../nonexistent/\u00e9/\u73af\u5883","reason":"Review accepted"},{"rule":"EC001","target":"C:\\nonexistent\\env","reason":"Review accepted","expires":"2000-01-01"}]}`,
	} {
		policy, err := ReadConfig(writeLintConfig(t, data))
		if err != nil {
			t.Fatalf("valid partial config rejected: %v", err)
		}
		if len(policy.Suppressions) != 0 && (policy.Suppressions[0].Path != "../nonexistent/\u00e9/\u73af\u5883" || policy.Suppressions[1].Target != `C:\nonexistent\env`) {
			t.Fatalf("selectors were canonicalized or changed: %+v", policy.Suppressions)
		}
	}
}

func TestReadConfigAcceptsEscapedCanonicalKeys(t *testing.T) {
	policy, err := ReadConfig(writeLintConfig(t, `{
		"\u0076ersion":1,
		"\u0070rofile":"local",
		"\u0066ail_on":"warning",
		"\u0072ules":{"\u0045C001":{"\u0065nabled":true,"\u0073everity":"info","\u0072evision_threshold":10}},
		"\u0073uppressions":[{"\u0072ule":"EC001","\u0070ath":"/env","\u0072eason":"reviewed"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if policy.FailOn != "warning" || policy.Rules["EC001"].Enabled == nil || !*policy.Rules["EC001"].Enabled || policy.Suppressions[0].Reason != "reviewed" {
		t.Fatalf("escaped canonical keys decoded incorrectly: %+v", policy)
	}
	if _, err := ReadConfig(writeLintConfig(t, `{"version":1,"rules":{"ec001":{}}}`)); err == nil || !strings.Contains(err.Error(), "unknown rule ID") {
		t.Fatalf("case-sensitive rule ID validation bypassed: %v", err)
	}
}

func TestPolicyExecutionInputsAreNotConfigJSON(t *testing.T) {
	policy := Policy{Version: 1, Source: "dir", RuntimePrefix: "/opt/conda", Project: "/missing/project"}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"version":1}` {
		t.Fatalf("execution inputs exposed in config JSON: %s", data)
	}
}

func TestValidateConfig(t *testing.T) {
	for _, tt := range []struct {
		name, message string
		change        func(*Policy)
	}{
		{"version", "version", func(p *Policy) { p.Version = 2 }},
		{"profile", "profile", func(p *Policy) { p.Profile = "production" }},
		{"fail_on", "fail_on", func(p *Policy) { p.FailOn = Severity("critical") }},
		{"unknown rule", "unknown rule", func(p *Policy) { p.Rules["EC999"] = RuleOptions{} }},
		{"lowercase rule", "unknown rule", func(p *Policy) { p.Rules["ec001"] = RuleOptions{} }},
		{"severity", "severity", func(p *Policy) { p.Rules["EC001"] = RuleOptions{Severity: NoFailure} }},
		{"zero threshold", "revision_threshold", func(p *Policy) { p.Rules["EC001"] = RuleOptions{RevisionThreshold: new(0)} }},
		{"negative threshold", "revision_threshold", func(p *Policy) { p.Rules["EC001"] = RuleOptions{RevisionThreshold: new(-1)} }},
		{"large threshold", "revision_threshold", func(p *Policy) { p.Rules["EC001"] = RuleOptions{RevisionThreshold: new(1_000_001)} }},
		{"wrong threshold rule", "only supported", func(p *Policy) { p.Rules["IC001"] = RuleOptions{RevisionThreshold: new(10)} }},
		{"unknown suppression rule", "unknown rule", func(p *Policy) { p.Suppressions[0].Rule = "IC999" }},
		{"missing suppression rule", "unknown rule", func(p *Policy) { p.Suppressions[0].Rule = "" }},
		{"missing reason", "reason is required", func(p *Policy) { p.Suppressions[0].Reason = "" }},
		{"blank reason", "reason is required", func(p *Policy) { p.Suppressions[0].Reason = " \u00a0 " }},
		{"missing selector", "target, path or fingerprint", func(p *Policy) { p.Suppressions[0].Target = "" }},
		{"prefixed fingerprint", "fingerprint", func(p *Policy) { p.Suppressions[0].Fingerprint = "sha256:" + strings.Repeat("a", 64) }},
		{"short fingerprint", "fingerprint", func(p *Policy) { p.Suppressions[0].Fingerprint = strings.Repeat("a", 63) }},
		{"long fingerprint", "fingerprint", func(p *Policy) { p.Suppressions[0].Fingerprint = strings.Repeat("a", 65) }},
		{"nonhex fingerprint", "fingerprint", func(p *Policy) { p.Suppressions[0].Fingerprint = strings.Repeat("g", 64) }},
		{"invalid date", "expires", func(p *Policy) { p.Suppressions[0].Expires = "2027-02-29" }},
		{"date timestamp", "expires", func(p *Policy) { p.Suppressions[0].Expires = "2028-02-29T00:00:00Z" }},
		{"unpadded date", "expires", func(p *Policy) { p.Suppressions[0].Expires = "2028-2-29" }},
		{"date space", "expires", func(p *Policy) { p.Suppressions[0].Expires = "2028-02-29 " }},
		{"too many rules", "rules exceed", func(p *Policy) {
			for i := range maxConfigRules + 1 {
				p.Rules[fmt.Sprintf("R%03d", i)] = RuleOptions{}
			}
		}},
		{"too many suppressions", "suppressions exceed", func(p *Policy) { p.Suppressions = make([]Suppression, maxConfigSuppressions+1) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policy := validLintPolicy()
			tt.change(&policy)
			if err := ValidateConfig(policy); err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("ValidateConfig error = %v, want %q", err, tt.message)
			}
			encoded, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadConfig(writeLintConfig(t, string(encoded))); err == nil {
				t.Fatal("ReadConfig skipped semantic validation")
			}
		})
	}
}

func TestValidateConfigValidValues(t *testing.T) {
	for _, profile := range append([]string{""}, profiles...) {
		for _, failOn := range []Severity{"", NoFailure, Info, Warning, Error} {
			policy := Policy{Version: 1, Profile: profile, FailOn: failOn}
			if err := ValidateConfig(policy); err != nil {
				t.Fatalf("valid profile %q, fail_on %q: %v", profile, failOn, err)
			}
		}
	}
	for _, rule := range ListRules() {
		for _, severity := range []Severity{"", Info, Warning, Error} {
			policy := validLintPolicy()
			policy.Rules[rule.ID] = RuleOptions{Severity: severity, Enabled: new(false)}
			policy.Suppressions[0].Rule = rule.ID
			if err := ValidateConfig(policy); err != nil {
				t.Fatalf("valid rule %q, severity %q: %v", rule.ID, severity, err)
			}
		}
	}
	for _, threshold := range []int{1, 1_000_000} {
		policy := validLintPolicy()
		policy.Rules["EC001"] = RuleOptions{RevisionThreshold: new(threshold)}
		if err := ValidateConfig(policy); err != nil {
			t.Fatalf("valid threshold %d: %v", threshold, err)
		}
	}
	for _, selector := range []Suppression{
		{Rule: "EC001", Target: "missing target", Reason: "reviewed"},
		{Rule: "EC001", Path: "missing path", Reason: "reviewed"},
		{Rule: "EC001", Fingerprint: strings.Repeat("AB", 32), Reason: "reviewed"},
	} {
		policy := Policy{Version: 1, Suppressions: []Suppression{selector}}
		if err := ValidateConfig(policy); err != nil {
			t.Fatalf("valid selector %+v: %v", selector, err)
		}
	}
	policy := validLintPolicy()
	policy.Suppressions = make([]Suppression, maxConfigSuppressions)
	for i := range policy.Suppressions {
		policy.Suppressions[i] = Suppression{
			Rule: "EC001", Path: "/missing/environment",
			Reason: strings.Repeat("x", 2048), Expires: "2028-02-29",
		}
	}
	policy.Suppressions[0].Path = strings.Repeat("é", 1024)
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(writeLintConfig(t, string(encoded))); err != nil {
		t.Fatalf("valid suppression limits rejected: %v", err)
	}
}

func TestReadConfigFileLimits(t *testing.T) {
	base := `{"version":1}`
	for _, size := range []int{maxConfigBytes, maxConfigBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			filename := writeLintConfig(t, base+strings.Repeat(" ", size-len(base)))
			_, err := ReadConfig(filename)
			if size == maxConfigBytes && err != nil {
				t.Fatalf("maximum file size rejected: %v", err)
			}
			if size > maxConfigBytes && (err == nil || !strings.Contains(err.Error(), "exceeds")) {
				t.Fatalf("oversized file accepted: %v", err)
			}
		})
	}
}

func TestReadConfigFileKinds(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "missing.json")
	if _, err := ReadConfig(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file error = %v", err)
	}
	if _, err := ReadConfig(parent); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory accepted: %v", err)
	}
	if _, err := ReadConfig(os.DevNull); err == nil {
		t.Fatal("device file accepted")
	}
	filename := writeLintConfig(t, `{"version":1}`)
	link := filepath.Join(t.TempDir(), "policy.json")
	if err := os.Symlink(filename, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	policy, err := ReadConfig(link)
	if err != nil || policy.Version != 1 {
		t.Fatalf("symlink to a regular config rejected: %v", err)
	}
	dangling := filepath.Join(t.TempDir(), "dangling.json")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(dangling); err == nil {
		t.Fatal("dangling symlink accepted")
	}
}

func validLintPolicy() Policy {
	return Policy{
		Version: 1,
		Rules: map[string]RuleOptions{
			"EC001": {Severity: "info", RevisionThreshold: new(10)},
		},
		Suppressions: []Suppression{{Rule: "EC001", Target: "file:/missing/environment", Reason: "reviewed"}},
	}
}

func writeLintConfig(t *testing.T, data string) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(filename, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}
