package lint

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/conda-incubator/envscout/internal/evidence"
)

func TestExecutionContractPolicyIdentity(t *testing.T) {
	configured, err := BuildPolicy(Policy{Version: ConfigVersion,
		Rules:        map[string]RuleOptions{"IMG005": {Severity: Error}},
		Suppressions: []Suppression{{Rule: "IMG005", Path: "/reviewed", Reason: "reviewed", Expires: "2026-12-31"}},
	}, Options{Source: "oci-archive", Profile: "container-runtime", Rules: []string{"IMG005"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		policy Policy
		digest string
	}{
		{"default local", enginePolicy(t, "dir", "local"), "sha256:105b130e5760bbef470361d399e1820e3ecc5f814ecbab723abf3564d3995e54"},
		{"default runtime", enginePolicy(t, "oci-archive", "container-runtime"), "sha256:007d2b96d96daeb10416ebea1567459999e87008c12a4b4114fde07495c20a64"},
		{"configured", configured, "sha256:8601dcca9b9d93a7b636ed749312243db0afaaed965a607925cf9dce17feffba"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := Evaluate(evidence.Snapshot{Started: engineNow}, test.policy, engineNow)
			if report.ConfigDigest != test.digest {
				t.Fatalf("digest=%q, want %q", report.ConfigDigest, test.digest)
			}
		})
	}
}

func TestExecutionContractRequestUnions(t *testing.T) {
	for _, test := range []struct {
		profile, source string
		caps, venv      []string
	}{
		{"local", "dir", []string{"conda-records", "history", "host-cache", "installed-lock", "prefixes", "project-association", "python-distributions"}, []string{"prefixes", "python-distributions"}},
		{"container", "oci-archive", []string{"cache-link-dependencies", "conda-records", "final-cache", "os-package-tools", "prefixes", "runtime-config", "tooling-prefix"}, nil},
		{"container-runtime", "oci-archive", []string{"cache-link-dependencies", "conda-records", "final-cache", "layer-retention", "os-package-tools", "prefixes", "runtime-config", "tooling-prefix"}, nil},
		{"container-distroless", "oci-archive", []string{"cache-link-dependencies", "conda-records", "final-cache", "layer-retention", "os-package-tools", "prefixes", "runtime-config", "shell-tools", "tooling-prefix"}, nil},
		{"container-development", "oci-archive", []string{"cache-link-dependencies", "conda-records", "final-cache", "history", "os-package-tools", "prefixes", "runtime-config", "tooling-prefix"}, nil},
	} {
		t.Run(test.profile, func(t *testing.T) {
			got := Requirements(enginePolicy(t, test.source, test.profile))
			want := evidence.Request{Capabilities: test.caps, VirtualenvCapabilities: test.venv}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("request=%+v, want %+v", got, want)
			}
		})
	}
	policy, err := BuildPolicy(Policy{}, Options{Source: "oci-archive", Rules: []string{"IMG001", "IMG001"}, RuntimePrefix: "/opt/app"})
	if err != nil {
		t.Fatal(err)
	}
	if got := Requirements(policy); !reflect.DeepEqual(got, evidence.Request{Capabilities: []string{"final-cache", "runtime-config"}, RuntimePrefix: "/opt/app"}) {
		t.Fatalf("explicit runtime union: %+v", got)
	}
	if got := Requirements(enginePolicy(t, "dir", "local", "ENV013")); !reflect.DeepEqual(got, evidence.Request{
		Capabilities: []string{"conda-records", "prefixes"}, VirtualenvCapabilities: []string{"prefixes", "python-distributions"},
	}) {
		t.Fatalf("ENV013 environment request: %+v", got)
	}
}

func TestExecutionContractWireShape(t *testing.T) {
	report := Evaluate(evidence.Snapshot{Started: engineNow}, enginePolicy(t, "dir", "local"), engineNow)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"targets", "outcomes", "findings", "issues", "suppression_notes"} {
		if string(wire[key]) != "[]" {
			t.Fatalf("empty %s must serialize as []: %s", key, wire[key])
		}
	}
	for _, key := range []string{"runtime_prefix", "project", "inspection"} {
		if _, present := wire[key]; present {
			t.Fatalf("empty %s must be omitted", key)
		}
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(wire["policy"], &policy); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"source", "runtime_prefix", "project", "suppressions"} {
		if _, present := policy[key]; present {
			t.Fatalf("policy wire leaked %s", key)
		}
	}
	if string(wire["outcome_counts"]) != `{"disabled":0,"finding":0,"not_applicable":0,"pass":0,"suppressed":0,"unavailable":0,"unknown":0}` {
		t.Fatalf("empty outcome count shape changed: %s", wire["outcome_counts"])
	}
}

func TestExecutionContractMalformedPoliciesFailClosed(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.Version = 0 }, func(p *Policy) { p.Profile = "container" },
		func(p *Policy) { p.Source = "unknown" }, func(p *Policy) { p.FailOn = "" },
		func(p *Policy) { delete(p.Rules, "ENV001") },
		func(p *Policy) { p.Rules["ENV001"] = RuleOptions{Severity: Info} },
		func(p *Policy) { p.Rules["ENV001"] = RuleOptions{Enabled: engineBool(true), Severity: "bad"} },
	} {
		policy := enginePolicy(t, "dir", "local", "ENV001")
		change(&policy)
		report := engineEvaluate(engineTarget("dir"), policy)
		if report.Status != "failed" || len(report.Outcomes) != 0 || len(report.Findings) != 0 ||
			!reflect.DeepEqual(report.Issues, []evidence.Issue{{Capability: "policy", Message: "lint evaluation requires a normalized effective policy from BuildPolicy"}}) {
			t.Fatalf("malformed policy must fail before rule execution: %+v", report)
		}
	}
}
