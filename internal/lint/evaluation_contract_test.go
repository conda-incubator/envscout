package lint

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
)

func contractTarget(id, path string, records ...inventory.CondaRecord) evidence.Target {
	target := localTarget(records...)
	target.ID, target.Input = id, path
	target.Prefixes[0].Path = path
	return target
}

func contractOutcome(t *testing.T, report Report, target string) Outcome {
	t.Helper()
	for _, outcome := range report.Outcomes {
		if outcome.Target == target && outcome.RuleID == "ENV006" {
			return outcome
		}
	}
	t.Fatalf("missing ENV006 outcome for %s", target)
	return Outcome{}
}

func TestEvaluationContractProductionDuplicates(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV006")
	left := contractTarget("file:///left", "/left", localRecord("numpy", "2"))
	right := contractTarget("file:///right", "/right", localRecord("numpy", "2"))
	report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{left, right}}, policy, engineNow)
	if report.Status != "completed" || len(report.Findings) != 2 {
		t.Fatalf("production duplicates: %+v", report)
	}
	for _, finding := range report.Findings {
		want := "1529e1c0f4b22f48bcfe8f5580bd0af756fddc6c269645eda1ca5050e33e73fb"
		if finding.Target == "file:///right" {
			want = "c28d108408d79d592dd69a499e7fd19d3a2e1b246382e0921cfe9d406b3c7925"
		}
		if finding.Fingerprint != want || !slices.Equal(finding.Evidence.Paths, []string{"/left", "/right"}) || finding.RuleID != "ENV006" {
			t.Errorf("finding identity: target=%s fingerprint=%s paths=%v", finding.Target, finding.Fingerprint, finding.Evidence.Paths)
		}
	}
}

func TestEvaluationContractPartialPeerRetainsPositives(t *testing.T) {
	policy := enginePolicy(t, "dir", "local", "ENV006")
	left := contractTarget("file:///left", "/left", localRecord("numpy", "2"))
	right := contractTarget("file:///right", "/right", localRecord("numpy", "2"))
	bad := contractTarget("file:///bad", "/bad", localRecord("numpy", "2"))
	bad.Prefixes[0].RecordCoverage = evidence.Partial
	bad.Coverage["conda-records"] = evidence.Partial
	report := Evaluate(evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{left, right, bad}}, policy, engineNow)
	if report.Status != "incomplete" || report.ExitCode() != 2 || len(report.Findings) != 2 {
		t.Fatalf("partial peer erased positives or incomplete status: %+v", report)
	}
	for _, finding := range report.Findings {
		if finding.Target == bad.ID || !slices.Equal(finding.Evidence.Paths, []string{"/left", "/right"}) {
			t.Fatalf("invalid peer entered duplicate evidence: %+v", finding)
		}
	}
	if got := contractOutcome(t, report, left.ID); got.Status != FindingStatus || got.Reason != "a peer has incomplete canonical conda identity metadata" {
		t.Fatalf("positive outcome must retain peer uncertainty: %+v", got)
	}
	if got := contractOutcome(t, report, bad.ID); got.Status != Unknown || !strings.Contains(got.Reason, "unavailable for /bad") {
		t.Fatalf("partial subject must remain unknown: %+v", got)
	}
}

func TestEvaluationContractOrderingAndNonMutation(t *testing.T) {
	makeSnapshot := func() evidence.Snapshot {
		return evidence.Snapshot{Started: engineNow, Targets: []evidence.Target{
			contractTarget("file:///a", "/a", localRecord("numpy", "2"), localRecord("python", "3.14")),
			contractTarget("file:///b", "/b", localRecord("python", "3.14"), localRecord("numpy", "2")),
		}}
	}
	snapshot, before := makeSnapshot(), makeSnapshot()
	policy := enginePolicy(t, "dir", "local", "ENV006")
	first := Evaluate(snapshot, policy, engineNow)
	if len(first.Findings) != 2 || !reflect.DeepEqual(snapshot, before) {
		t.Fatal("production evaluation mutated facts or lost duplicates")
	}
	reordered := makeSnapshot()
	slices.Reverse(reordered.Targets)
	for i := range reordered.Targets {
		slices.Reverse(reordered.Targets[i].Prefixes[0].Records)
	}
	a, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Evaluate(reordered, policy, engineNow))
	if err != nil || !slices.Equal(a, b) {
		t.Fatalf("target/record order changed report bytes: %v\n%s\n%s", err, a, b)
	}
}

// Keep the removed direct helper's nil/empty contract on the single prepared path;
// production Evaluate always includes each conda subject in the peer scope.
func TestEvaluationContractNilAndEmptyPeers(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		target := localTarget(localRecord("numpy", "2"))
		context := evaluationContext{}
		if supplied {
			context.peers = []evidence.Prefix{}
		}
		outcome, findings := runLocalCheck(target, "ENV006", prepareDuplicates(context), context)
		if supplied {
			if outcome.Status != Pass || len(findings) != 0 {
				t.Fatalf("supplied-empty peers: %+v %+v", outcome, findings)
			}
		} else if outcome.Status != Unknown || outcome.Reason != "cross-prefix conda metadata was not supplied" || len(findings) != 0 {
			t.Fatalf("nil peers must not mean supplied-empty: %+v %+v", outcome, findings)
		}
	}
}
