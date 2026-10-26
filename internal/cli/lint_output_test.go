package cli

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/evidence"
	policy "github.com/conda-incubator/envscout/internal/lint"
)

func TestLintTextFindingShowsObservationPathsSafetyAndNext(t *testing.T) {
	rule := policy.ListRules()[0]
	report := policy.Report{
		Profile: "local", RulesetVersion: policy.RulesetVersion, Status: "completed",
		Targets: []policy.TargetReport{{ID: "file:///env", Kind: "dir", PrefixCount: 1}},
		Findings: []policy.Finding{{
			RuleID: rule.ID, Target: "file:///env", Severity: policy.Info,
			Message: "Observed repeated transactions; review them because recreation may be harder to reproduce.",
			Evidence: policy.FindingEvidence{
				Paths: []string{"/env/conda-meta/history"},
				Notes: []string{"Required linkage inspection is incomplete; cleanup safety is unknown."},
			},
		}},
		OutcomeCounts: map[policy.Status]int{policy.FindingStatus: 1, policy.Disabled: 9, policy.NotApplicable: 2},
	}
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	last := -1
	for _, want := range []string{
		"Found: " + report.Findings[0].Message,
		"Evidence: /env/conda-meta/history",
		"Note: " + report.Findings[0].Evidence.Notes[0],
		"Next: " + rule.Fix,
		"Summary: completed; 1 targets; 1 findings; 0 unknown",
	} {
		index := strings.Index(text, want)
		if index <= last {
			t.Fatalf("missing or out-of-order %q: %s", want, text)
		}
		last = index
	}
	for _, hidden := range []string{"confirmed", "disabled", "not applicable", "Coverage:", "not a vulnerability", "suppressed 0"} {
		if strings.Contains(text, hidden) {
			t.Errorf("normal output retains %q: %s", hidden, text)
		}
	}
}

func TestLintTextSummaryCountsVisibleFindings(t *testing.T) {
	rule := policy.ListRules()[0]
	report := policy.Report{Status: "completed",
		Findings: []policy.Finding{
			{RuleID: rule.ID, Severity: policy.Info},
			{RuleID: rule.ID, Severity: policy.Info},
			{RuleID: rule.ID, Severity: policy.Info, Suppression: &policy.Suppression{Reason: "reviewed exception"}},
		},
		OutcomeCounts: map[policy.Status]int{policy.FindingStatus: 1, policy.Unknown: 3, policy.Suppressed: 1},
	}
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Summary: completed; 0 targets; 2 findings; 3 unknown; 1 suppressed") || strings.Count(out.String(), "Found:") != 2 {
		t.Fatalf("summary must count visible instances, not rule outcomes: %s", out.String())
	}
}

func TestLintTextUsesInstanceNextAction(t *testing.T) {
	rule := policy.ListRules()[0]
	for _, test := range []struct {
		name, next string
	}{
		{"catalogue fallback", ""},
		{"instance override", "Export the observed prefix /golden/env with its command"},
		{"sanitized override", "untrusted\n\x1b[31maction"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			report := policy.Report{Findings: []policy.Finding{{RuleID: rule.ID, Next: test.next}}}
			if err := renderLint(&out, report, "text", true); err != nil {
				t.Fatal(err)
			}
			want := test.next
			if want == "" {
				want = rule.Fix
			}
			text := out.String()
			if !strings.Contains(text, "Next: "+lintText(want)+"\n") || strings.Contains(text, "\x1b") || strings.Count(text, "  Next:") != 1 {
				t.Fatalf("instance next action was ignored or unsanitized: %q", text)
			}
			if test.next != "" && strings.Contains(text, rule.Fix) {
				t.Fatalf("instance action did not replace generic action: %s", text)
			}
			out.Reset()
			if err := renderLint(&out, report, "json", true); err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				Findings []map[string]any `json:"findings"`
			}
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || len(decoded.Findings) != 1 {
				t.Fatalf("invalid action JSON: %v %s", err, out.String())
			}
			next, present := decoded.Findings[0]["next"]
			if present != (test.next != "") || present && next != test.next || report.Findings[0].Next != test.next {
				t.Fatalf("rendering mutated or lost optional instance action: %s", out.String())
			}
		})
	}
}

func TestLintHumanBytes(t *testing.T) {
	for _, test := range []struct {
		bytes int64
		want  string
	}{{0, "0 B"}, {512, "512 B"}, {1024, "1.0 KiB"}, {1 << 20, "1.0 MiB"}, {1 << 30, "1.0 GiB"}, {1 << 40, "1.0 TiB"}, {1 << 50, "1.0 PiB"}, {math.MaxInt64, "8.0 EiB"}} {
		if got := lintBytes(test.bytes); got != test.want {
			t.Errorf("lintBytes(%d) = %q, want %q", test.bytes, got, test.want)
		}
	}
}

func TestLintTextImageEvidenceUsesAbsolutePathsAndSourceLayers(t *testing.T) {
	rule := policy.ListRules()[0]
	report := policy.Report{
		Targets: []policy.TargetReport{{ID: "image", Kind: "oci-archive"}},
		Findings: []policy.Finding{{RuleID: rule.ID, Target: "image", Severity: policy.Info,
			Evidence: policy.FindingEvidence{
				Paths: []string{"/opt/conda/pkgs/demo-1-0.conda", "/opt/conda/conda-meta/history"},
				Samples: []evidence.Artifact{{Path: "opt/conda/pkgs/demo-1-0.conda", Bytes: 2048,
					Layer: 0, BlobDigest: "sha256:source", LayerBytes: 512}},
			},
		}},
	}
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"Evidence: /opt/conda/pkgs/demo-1-0.conda (2.0 KiB)", "source layer 1", "sha256:source", "512 B compressed layer", "Evidence: /opt/conda/conda-meta/history"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q: %s", want, text)
		}
	}
	for _, forbidden := range []string{"logical payload", "deletion layer", "source layer 0"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("misleading evidence %q: %s", forbidden, text)
		}
	}
	if n := strings.Count(text, "Evidence: /opt/conda/pkgs/demo-1-0.conda"); n != 1 {
		t.Fatalf("sampled path rendered %d times: %s", n, text)
	}
	out.Reset()
	if err := renderLint(&out, report, "json", true); err != nil {
		t.Fatal(err)
	}
	var decoded policy.Report
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || decoded.Findings[0].Evidence.Samples[0].Layer != 0 {
		t.Fatalf("text rendering changed the JSON source-layer index: %v %s", err, out.String())
	}
}

func TestLintRuleCatalogueIsLongByDefault(t *testing.T) {
	var out bytes.Buffer
	if err := renderRules(&out, "text"); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, rule := range policy.ListRules() {
		start := strings.Index(text, rule.ID+"  "+rule.Name)
		if start < 0 {
			t.Fatalf("missing rule %s: %s", rule.ID, text)
		}
		block := strings.SplitN(text[start:], "\n\n", 2)[0]
		for _, want := range []string{"Why: " + rule.Description, "Fix: " + rule.Fix, "Enabled profiles:", "Docs:", "Exceptions:"} {
			if !strings.Contains(block, want) {
				t.Errorf("rule %s omits %q: %s", rule.ID, want, block)
			}
		}
		for profile, defaults := range rule.Defaults {
			if defaults.Enabled && !strings.Contains(block, profile+" ("+string(defaults.Severity)+")") {
				t.Errorf("rule %s omits profile/severity %s: %s", rule.ID, profile, block)
			}
		}
		for _, detail := range append(rule.References, rule.Exceptions...) {
			if !strings.Contains(block, detail) {
				t.Errorf("rule %s omits %q: %s", rule.ID, detail, block)
			}
		}
		if !rule.Available && !strings.Contains(block, "Unavailable: "+rule.UnavailableReason) {
			t.Errorf("rule %s hides unavailable reason: %s", rule.ID, block)
		}
	}
	out.Reset()
	if err := renderRules(&out, "json"); err != nil {
		t.Fatal(err)
	}
	var rules []policy.Rule
	if err := json.Unmarshal(out.Bytes(), &rules); err != nil || len(rules) != len(policy.ListRules()) {
		t.Fatalf("catalogue JSON contract changed: %v %s", err, out.String())
	}
}

func TestLintTextSanitizesEveryReportField(t *testing.T) {
	rule := policy.ListRules()[0]
	unsafe := "untrusted\n\x1b[31m"
	report := policy.Report{
		Profile: unsafe, RulesetVersion: unsafe, Status: unsafe,
		Targets: []policy.TargetReport{{ID: unsafe, Roots: []string{unsafe}}},
		Findings: []policy.Finding{{RuleID: rule.ID, Target: unsafe, Severity: policy.Severity(unsafe), Message: unsafe,
			Evidence: policy.FindingEvidence{Paths: []string{unsafe}, Notes: []string{unsafe},
				Samples: []evidence.Artifact{{Path: unsafe, BlobDigest: unsafe}}},
		}},
		Outcomes:         []policy.Outcome{{RuleID: unsafe, Status: policy.Unknown, Reason: unsafe}},
		Issues:           []evidence.Issue{{Path: unsafe, Message: unsafe}},
		SuppressionNotes: []policy.SuppressionNote{{Rule: unsafe, Status: unsafe, Reason: unsafe}},
	}
	var out bytes.Buffer
	if err := renderLint(&out, report, "text", true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), unsafe) || strings.Contains(out.String(), "\x1b") {
		t.Fatalf("unescaped report metadata: %q", out.String())
	}
}

func TestLintTextEvidenceLocationFallback(t *testing.T) {
	var out bytes.Buffer
	printer := newPrinter(&out)
	location := "file:///env\nunsafe"
	renderEvidence(printer, policy.FindingEvidence{Locations: []string{location}}, false)
	if err := printer.Err(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "  Evidence: "+lintText(location)+"\n" {
		t.Fatalf("location fallback lost sanitization: %q", out.String())
	}
}

func TestLintRenderersPreserveWriteErrors(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		if err := renderRules(failedLintWriter{}, format); err == nil || !strings.Contains(err.Error(), "output unavailable") {
			t.Errorf("%s catalogue swallowed write error: %v", format, err)
		}
		if err := renderLint(failedLintWriter{}, policy.Report{}, format, true); err == nil || !strings.Contains(err.Error(), "output unavailable") {
			t.Errorf("%s report swallowed write error: %v", format, err)
		}
	}
}

func TestLintTextRejectsMissingRuleMetadata(t *testing.T) {
	var out bytes.Buffer
	err := renderLint(&out, policy.Report{Findings: []policy.Finding{{RuleID: "unregistered"}}}, "text", true)
	if err == nil || !strings.Contains(err.Error(), "rule metadata unavailable") {
		t.Fatalf("missing recommendation metadata was hidden: %v", err)
	}
	err = renderLint(failedLintWriter{}, policy.Report{Findings: []policy.Finding{{RuleID: "unregistered"}}}, "text", true)
	if err == nil || !strings.Contains(err.Error(), "rule metadata unavailable") || !strings.Contains(err.Error(), "output unavailable") {
		t.Fatalf("metadata failure lost an earlier write error: %v", err)
	}
}
