package evidence

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"
)

func TestImageCoverageContractPreCancellation(t *testing.T) {
	wantCapabilities := []string{"prefixes", "conda-records", "history", "tooling-prefix", "final-cache", "cache-link-dependencies", "runtime-config", "os-package-tools", "shell-tools", "layer-retention"}
	if !slices.Equal(imageCapabilities, wantCapabilities) {
		t.Fatalf("capability order = %v", imageCapabilities)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target, err := CollectImage(ctx, nil, Request{Capabilities: []string{"prefixes", "tooling-prefix"}})
	want := map[string]string{
		"prefixes": Complete, "conda-records": NotCollected, "history": NotCollected, "tooling-prefix": Complete,
		"final-cache": NotCollected, "cache-link-dependencies": NotCollected, "runtime-config": NotCollected,
		"os-package-tools": NotCollected, "shell-tools": NotCollected, "layer-retention": NotCollected,
	}
	// Pre-cancellation returns before the collector's cancellation cleanup exists.
	if !errors.Is(err, context.Canceled) || !maps.Equal(target.Coverage, want) {
		t.Fatalf("pre-canceled coverage = %+v, %v", target.Coverage, err)
	}
}

func TestImageCoverageContractCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		c := imageCollector{target: Target{
			Coverage: map[string]string{"prefixes": Complete, "history": Partial, "final-cache": NotCollected, "empty": "", "unknown": "future"},
			Prefixes: []Prefix{{Path: "/a", RecordCoverage: Complete}, {Path: "/b", RecordCoverage: NotCollected}, {Path: "/c", RecordCoverage: ""}},
			Archives: []Artifact{{Path: "/cache/a.conda", Kind: "archive", Bytes: 7}},
			Issues:   []Issue{{Capability: "history", Path: "/a/history", Message: "kept"}},
		}}
		want := c.target
		want.Coverage = maps.Clone(c.target.Coverage)
		want.Prefixes = slices.Clone(c.target.Prefixes)
		want.Archives = slices.Clone(c.target.Archives)
		want.Issues = slices.Clone(c.target.Issues)
		if canceled {
			want.Coverage = map[string]string{"prefixes": Partial, "history": Partial, "final-cache": NotCollected, "empty": Partial, "unknown": Partial}
			for i := range want.Prefixes {
				want.Prefixes[i].RecordCoverage = Partial
			}
		}
		err := c.cancelled(ctx)
		cancel()
		if (canceled && !errors.Is(err, context.Canceled)) || (!canceled && err != nil) || !reflect.DeepEqual(c.target, want) {
			t.Fatalf("canceled=%t: target=%+v error=%v, want %+v", canceled, c.target, err, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, coverage := range []map[string]string{nil, {}} {
		c := imageCollector{target: Target{Coverage: coverage}}
		if !errors.Is(c.cancelled(ctx), context.Canceled) || len(c.target.Coverage) != 0 || (c.target.Coverage == nil) != (coverage == nil) {
			t.Fatalf("empty coverage changed shape: %+v", c.target.Coverage)
		}
	}
}

func TestImageCoverageContractIssueThreshold(t *testing.T) {
	c := imageCollector{target: Target{Coverage: map[string]string{"prefixes": Complete, "final-cache": NotCollected}}, limited: map[string]bool{}}
	c.issue("final-cache", "/disabled", "ignored")
	c.limit("final-cache", "/disabled", "ignored")
	if len(c.target.Issues) != 0 || c.target.Coverage["final-cache"] != NotCollected {
		t.Fatal("disabled capability recorded an issue")
	}
	for i := 0; i < 9990; i++ {
		c.issue("prefixes", "/regular", "regular")
	}
	if len(c.target.Issues) != 9990 || c.target.Issues[9989] != (Issue{Capability: "prefixes", Path: "/regular", Message: "regular"}) {
		t.Fatalf("regular issue threshold changed: %d", len(c.target.Issues))
	}
	c.issue("prefixes", "/trigger", "regular")
	c.issue("prefixes", "/repeat", "regular")
	c.issue("final-cache", "/disabled-at-limit", "ignored")
	if len(c.target.Issues) != 9991 || c.target.Issues[9990] != (Issue{Capability: "prefixes", Path: "/trigger", Message: "collection issue limit exceeded (10000)"}) ||
		c.target.Coverage["prefixes"] != Partial || c.target.Coverage["final-cache"] != NotCollected {
		t.Fatalf("sentinel or disabled gate changed: count=%d coverage=%+v", len(c.target.Issues), c.target.Coverage)
	}
}

func TestImageCoverageContractSentinelPerCapability(t *testing.T) {
	for _, disabled := range []string{"", "layer-retention"} {
		c := imageCollector{target: Target{Coverage: map[string]string{}, Issues: make([]Issue, 9990)}, limited: map[string]bool{}}
		want := []Issue{}
		for _, capability := range imageCapabilities {
			c.target.Coverage[capability] = Complete
			if capability == disabled {
				c.target.Coverage[capability] = NotCollected
			} else {
				want = append(want, Issue{Capability: capability, Path: "/trigger/" + capability, Message: "collection issue limit exceeded (10000)"})
			}
			c.issue(capability, "/trigger/"+capability, "regular")
			c.issue(capability, "/repeat", "regular")
			c.limit(capability, "/another-limit", "prefix entry limit exceeded (10000)")
		}
		if !slices.Equal(c.target.Issues[9990:], want) {
			t.Fatalf("disabled=%q: per-capability sentinels = %+v, want %+v", disabled, c.target.Issues[9990:], want)
		}
		for _, capability := range imageCapabilities {
			state := Partial
			if capability == disabled {
				state = NotCollected
			}
			if c.target.Coverage[capability] != state {
				t.Fatalf("%s coverage = %q, want %q", capability, c.target.Coverage[capability], state)
			}
		}
	}
}

func TestImageCoverageContractIssueOrderAndLimits(t *testing.T) {
	c := imageCollector{target: Target{Coverage: map[string]string{"prefixes": Complete, "final-cache": Complete}}, limited: map[string]bool{}}
	c.issue("prefixes", "/b", "same")
	c.issue("final-cache", "/z", "cache")
	c.issue("prefixes", "/b", "same")
	c.limit("prefixes", "/a", "z-limit")
	c.limit("prefixes", "/ignored", "z-limit")
	c.limit("prefixes", "/a", "a-limit")
	want := []Issue{
		{Capability: "prefixes", Path: "/b", Message: "same"},
		{Capability: "final-cache", Path: "/z", Message: "cache"},
		{Capability: "prefixes", Path: "/b", Message: "same"},
		{Capability: "prefixes", Path: "/a", Message: "z-limit"},
		{Capability: "prefixes", Path: "/a", Message: "a-limit"},
	}
	if !slices.Equal(c.target.Issues, want) {
		t.Fatalf("append order or limit deduplication changed: %+v", c.target.Issues)
	}
	c.sort()
	want = []Issue{want[1], want[4], want[3], want[0], want[2]}
	if !slices.Equal(c.target.Issues, want) {
		t.Fatalf("capability/path/message order or duplicate retention changed: %+v", c.target.Issues)
	}
}
