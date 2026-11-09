package evidence

import (
	"io/fs"
	"testing"
)

// Classification must happen after coverage degradation and before issue append.
type issueProbe struct {
	t            *testing.T
	target       *Target
	capability   string
	issuesBefore int
	matches      bool
	isCalls      int
	unwrapCalls  int
}

func (p *issueProbe) Error() string { return "issue probe" }

func (p *issueProbe) Unwrap() error {
	p.unwrapCalls++
	return nil
}

func (p *issueProbe) Is(target error) bool {
	p.isCalls++
	if p.target.Coverage[p.capability] != Partial || len(p.target.Issues) != p.issuesBefore {
		p.t.Fatalf("classification ran with coverage=%q issues=%d, want partial and %d", p.target.Coverage[p.capability], len(p.target.Issues), p.issuesBefore)
	}
	return p.matches && target == fs.ErrPermission
}

func TestIssueContractCauseShortCircuit(t *testing.T) {
	target := &Target{Coverage: map[string]string{"host-cache": Complete}}
	first := &issueProbe{t: t, target: target, capability: "host-cache"}
	permission := &issueProbe{t: t, target: target, capability: "host-cache", matches: true}
	later := &issueProbe{t: t, target: target, capability: "host-cache"}
	hostIssue(target, "host-cache", "/p", "ordered", first, permission, later)
	if first.isCalls != 1 || first.unwrapCalls != 1 || permission.isCalls != 1 || permission.unwrapCalls != 0 ||
		later.isCalls != 0 || later.unwrapCalls != 0 {
		t.Fatalf("cause classification did not short-circuit: first=%+v permission=%+v later=%+v", first, permission, later)
	}
	want := Issue{Capability: "host-cache", Path: "/p", Message: "ordered", AccessDenied: true}
	if target.Coverage["host-cache"] != Partial || len(target.Issues) != 1 || target.Issues[0] != want {
		t.Fatalf("coverage=%q issues=%+v, want partial and [%+v]", target.Coverage["host-cache"], target.Issues, want)
	}
}

func TestIssueContractHostCapSkipsClassification(t *testing.T) {
	target := &Target{Coverage: map[string]string{"host-cache": Complete}, Issues: make([]Issue, 10000)}
	cause := &issueProbe{t: t, target: target, capability: "host-cache", issuesBefore: 10000, matches: true}
	hostIssue(target, "host-cache", "/capped", "dropped", cause)
	if cause.isCalls != 0 || cause.unwrapCalls != 0 || target.Coverage["host-cache"] != Partial || len(target.Issues) != 10000 {
		t.Fatalf("at cap: Is=%d Unwrap=%d coverage=%q issues=%d", cause.isCalls, cause.unwrapCalls, target.Coverage["host-cache"], len(target.Issues))
	}
}

func TestIssueContractImageSentinelAndUnknownCapability(t *testing.T) {
	c := imageCollector{target: Target{Coverage: map[string]string{}, Issues: make([]Issue, 9990)}, limited: map[string]bool{}}
	const sentinel = "collection issue limit exceeded (10000)"
	for i, capability := range imageCapabilities {
		c.target.Coverage[capability] = Complete
		c.issue(capability, "/known", "known")
		want := Issue{Capability: capability, Path: "/known", Message: sentinel}
		if len(c.target.Issues) != 9991+i || c.target.Issues[9990+i] != want {
			t.Fatalf("sentinel for %s changed: count=%d", capability, len(c.target.Issues))
		}
	}
	if len(c.target.Issues) != 10000 {
		t.Fatalf("issues after known sentinels = %d, want 10000", len(c.target.Issues))
	}
	c.target.Coverage["layer-retention"] = NotCollected
	c.issue("layer-retention", "/gated", "ignored")
	c.limit("layer-retention", "/gated", "ignored")
	if len(c.target.Issues) != 10000 || c.target.Coverage["layer-retention"] != NotCollected {
		t.Fatalf("gated capability changed after cap: issues=%d coverage=%q", len(c.target.Issues), c.target.Coverage["layer-retention"])
	}
	c.issue("future", "/unknown", "unknown")
	c.issue("future", "/unknown-repeat", "unknown")
	want := Issue{Capability: "future", Path: "/unknown", Message: sentinel}
	if len(c.target.Issues) != 10001 || c.target.Issues[10000] != want || c.target.Coverage["future"] != Partial {
		t.Fatalf("unknown capability: issues=%d coverage=%q", len(c.target.Issues), c.target.Coverage["future"])
	}
}
