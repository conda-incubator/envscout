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
		Version: 1, Profile: "container-runtime", FailOn: "warning",
		Rules: map[string]RuleOptions{
			"EC001": {Enabled: new(true), Severity: "info", RevisionThreshold: new(12)},
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
		{"empty", "", "invalid lint config"},
		{"malformed", `{"version":1`, "invalid lint config"},
		{"invalid token", `{"version":not_json}`, "invalid lint config"},
		{"trailing comma", `{"version":1,}`, "invalid lint config"},
		{"array", `[{"version":1}]`, "policy object"},
		{"null", `null`, "policy object"},
		{"scalar", `1`, "policy object"},
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
		{"duplicate root", `{"version":1,"version":1}`, "duplicate JSON key"},
		{"escaped duplicate root", `{"version":1,"\u0076ersion":1}`, "duplicate JSON key"},
		{"duplicate rule ID", `{"version":1,"rules":{"EC001":{},"EC001":{}}}`, "duplicate JSON key"},
		{"duplicate nested option", `{"version":1,"rules":{"EC001":{"enabled":true,"enabled":false}}}`, "duplicate JSON key"},
		{"duplicate suppression", `{"version":1,"suppressions":[{"rule":"EC001","reason":"first","reason":"second","path":"x"}]}`, "duplicate JSON key"},
		{"duplicate in nested array", `{"version":1,"unexpected":[[{"a":1,"a":2}]]}`, "duplicate JSON key"},
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
		{"deep array", `{"version":1,"unexpected":` + strings.Repeat("[", maxConfigDepth) + "0" + strings.Repeat("]", maxConfigDepth) + "}", "nesting exceeds"},
		{"invalid UTF-8", "{\"version\":1,\"profile\":\"\xff\"}", "valid UTF-8"},
		{"escaped control", `{"version":1,"suppressions":[{"rule":"EC001","path":"bad\u0000path","reason":"reviewed"}]}`, "control"},
		{"escaped newline", `{"version":1,"suppressions":[{"rule":"EC001","path":"bad\npath","reason":"reviewed"}]}`, "control"},
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

func TestReadConfigRejectsNoncanonicalKeys(t *testing.T) {
	for _, tt := range []struct{ name, data string }{
		{"root alias only", `{"version":1,"FAIL_ON":"none"}`},
		{"root alias override", `{"version":1,"fail_on":"warning","FAIL_ON":"none"}`},
		{"root alias before canonical", `{"version":1,"FAIL_ON":"none","fail_on":"warning"}`},
		{"escaped root alias", `{"version":1,"fail_on":"warning","\u0046AIL_ON":"none"}`},
		{"escaped root alias only", `{"version":1,"\u0046AIL_ON":"none"}`},
		{"option alias only", `{"version":1,"rules":{"EC001":{"Enabled":false}}}`},
		{"option alias override", `{"version":1,"rules":{"EC001":{"enabled":true,"Enabled":false}}}`},
		{"option alias before canonical", `{"version":1,"rules":{"EC001":{"Enabled":false,"enabled":true}}}`},
		{"escaped option alias", `{"version":1,"rules":{"EC001":{"enabled":true,"\u0045nabled":false}}}`},
		{"suppression alias only", `{"version":1,"suppressions":[{"rule":"EC001","path":"/env","Reason":"reviewed"}]}`},
		{"suppression alias override", `{"version":1,"suppressions":[{"rule":"EC001","path":"/env","reason":"reviewed","Reason":"other"}]}`},
		{"suppression alias before canonical", `{"version":1,"suppressions":[{"rule":"EC001","path":"/env","Reason":"other","reason":"reviewed"}]}`},
		{"escaped suppression alias", `{"version":1,"suppressions":[{"rule":"EC001","path":"/env","reason":"reviewed","\u0052eason":"other"}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := ReadConfig(writeLintConfig(t, tt.data))
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Fatalf("ReadConfig error = %v, want noncanonical key rejected", err)
			}
			if !reflect.DeepEqual(policy, Policy{}) {
				t.Fatalf("rejected alias returned a partial policy: %+v", policy)
			}
		})
	}
	for _, scope := range []struct {
		name, format string
		fields       []string
	}{
		{"root", `{"version":1,%q:null}`, []string{"version", "profile", "fail_on", "rules", "suppressions"}},
		{"options", `{"version":1,"rules":{"EC001":{%q:null}}}`, []string{"enabled", "severity", "revision_threshold"}},
		{"suppression", `{"version":1,"suppressions":[{"rule":"EC001","path":"/env","reason":"reviewed",%q:null}]}`, []string{"rule", "target", "path", "fingerprint", "reason", "expires"}},
	} {
		for _, field := range scope.fields {
			t.Run(scope.name+"/"+field, func(t *testing.T) {
				for _, alias := range []string{strings.ToUpper(field), strings.ToUpper(field[:1]) + field[1:]} {
					data := fmt.Sprintf(scope.format, alias)
					if _, err := ReadConfig(writeLintConfig(t, data)); err == nil || !strings.Contains(err.Error(), "unknown field") {
						t.Fatalf("alias %q: ReadConfig error = %v, want unknown field", alias, err)
					}
				}
			})
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
		{"fail_on", "fail_on", func(p *Policy) { p.FailOn = "critical" }},
		{"unknown rule", "unknown rule", func(p *Policy) { p.Rules["EC999"] = RuleOptions{} }},
		{"lowercase rule", "unknown rule", func(p *Policy) { p.Rules["ec001"] = RuleOptions{} }},
		{"severity", "severity", func(p *Policy) { p.Rules["EC001"] = RuleOptions{Severity: "none"} }},
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
	for _, profile := range []string{"", "local", "container", "container-runtime", "container-distroless", "container-development"} {
		for _, failOn := range []string{"", "none", "info", "warning", "error"} {
			policy := Policy{Version: 1, Profile: profile, FailOn: failOn}
			if err := ValidateConfig(policy); err != nil {
				t.Fatalf("valid profile %q, fail_on %q: %v", profile, failOn, err)
			}
		}
	}
	for _, id := range []string{"EC001", "EC002", "EC003", "EC004", "IC001", "IC002", "IC003", "IC004", "IC005", "IC006", "IC007"} {
		for _, severity := range []string{"", "info", "warning", "error"} {
			policy := validLintPolicy()
			policy.Rules[id] = RuleOptions{Severity: severity, Enabled: new(false)}
			policy.Suppressions[0].Rule = id
			if err := ValidateConfig(policy); err != nil {
				t.Fatalf("valid rule %q, severity %q: %v", id, severity, err)
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
			Reason: strings.Repeat("x", maxConfigStringBytes), Expires: "2028-02-29",
		}
	}
	policy.Suppressions[0].Path = strings.Repeat("\u00e9", maxConfigStringBytes/2)
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(writeLintConfig(t, string(encoded))); err != nil {
		t.Fatalf("valid suppression and string limits rejected: %v", err)
	}
}

func TestValidateConfigStringLimitsAndControls(t *testing.T) {
	for _, field := range []struct {
		name string
		set  func(*Policy, string)
	}{
		{"profile", func(p *Policy, value string) { p.Profile = value }},
		{"fail_on", func(p *Policy, value string) { p.FailOn = value }},
		{"rule ID", func(p *Policy, value string) { p.Rules[value] = RuleOptions{} }},
		{"severity", func(p *Policy, value string) { p.Rules["EC001"] = RuleOptions{Severity: value} }},
		{"suppression rule", func(p *Policy, value string) { p.Suppressions[0].Rule = value }},
		{"target", func(p *Policy, value string) { p.Suppressions[0].Target = value }},
		{"path", func(p *Policy, value string) { p.Suppressions[0].Path = value }},
		{"fingerprint", func(p *Policy, value string) { p.Suppressions[0].Fingerprint = value }},
		{"reason", func(p *Policy, value string) { p.Suppressions[0].Reason = value }},
		{"expires", func(p *Policy, value string) { p.Suppressions[0].Expires = value }},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, tt := range []struct{ value, message string }{
				{strings.Repeat("x", maxConfigStringBytes+1), "exceeds"},
				{"bad\x00value", "control"},
				{"bad\nvalue", "control"},
				{"bad\rvalue", "control"},
				{"bad\tvalue", "control"},
				{"bad\x1bvalue", "control"},
				{"bad\x7fvalue", "control"},
				{"bad\u0085value", "control"},
				{"bad\u2028value", "line-separator"},
				{"bad\u2029value", "line-separator"},
				{"bad\xffvalue", "valid UTF-8"},
			} {
				policy := validLintPolicy()
				field.set(&policy, tt.value)
				if err := ValidateConfig(policy); err == nil || !strings.Contains(err.Error(), tt.message) {
					t.Fatalf("value %q: error = %v, want %q", tt.value, err, tt.message)
				}
			}
		})
	}
}

func TestConfigJSONDepthBoundary(t *testing.T) {
	for _, depth := range []int{maxConfigDepth - 1, maxConfigDepth} {
		data := []byte(`{"value":` + strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth) + "}")
		err := checkConfigJSON(data)
		if depth == maxConfigDepth-1 && err != nil {
			t.Fatalf("maximum allowed nesting rejected: %v", err)
		}
		if depth == maxConfigDepth && (err == nil || !strings.Contains(err.Error(), "nesting exceeds")) {
			t.Fatalf("excessive nesting accepted: %v", err)
		}
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
	filename := writeLintConfig(t, `{"version":1,"suppressions":[{"rule":"EC001","target":"`+strings.Repeat("x", maxConfigStringBytes+1)+`","reason":"reviewed"}]}`)
	if _, err := ReadConfig(filename); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized JSON string accepted: %v", err)
	}
}

func TestReadConfigRejectsSymlinksAndNonRegularFiles(t *testing.T) {
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
	for _, target := range []string{filename, missing} {
		link := filepath.Join(t.TempDir(), "policy.json")
		if err := os.Symlink(target, link); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlinks unavailable: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := ReadConfig(link); err == nil || !strings.Contains(err.Error(), "non-symlink regular file") {
			t.Fatalf("symlink accepted: %v", err)
		}
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
