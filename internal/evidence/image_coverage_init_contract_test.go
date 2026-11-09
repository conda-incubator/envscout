package evidence

import (
	"context"
	"maps"
	"slices"
	"testing"

	"github.com/conda-incubator/envscout/internal/testimage"
)

func TestImageCoverageInitMatrix(t *testing.T) {
	known := []string{"prefixes", "conda-records", "history", "tooling-prefix", "final-cache", "cache-link-dependencies", "runtime-config", "os-package-tools", "shell-tools", "layer-retention"}
	cases := []struct {
		name     string
		req      Request
		selected []string
	}{
		{"nil request", Request{}, nil},
		{"empty request", Request{Capabilities: []string{}}, nil},
		{"duplicates and unknown", Request{Capabilities: []string{"history", "history", "future-cap", "prefixes"}}, []string{"history", "prefixes"}},
		{"virtualenv only", Request{VirtualenvCapabilities: []string{"prefixes", "python-distributions"}}, nil},
	}
	for _, capability := range known {
		cases = append(cases, struct {
			name     string
			req      Request
			selected []string
		}{capability, Request{Capabilities: []string{capability}}, []string{capability}})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			want := map[string]string{}
			for _, capability := range known {
				want[capability] = NotCollected
				if slices.Contains(test.selected, capability) {
					want[capability] = Complete
				}
			}
			target, err := CollectImage(context.Background(), nil, test.req)
			if err == nil || err.Error() != "a loaded image is required" || !maps.Equal(target.Coverage, want) {
				t.Fatalf("coverage = %+v, error = %v, want %+v and load error", target.Coverage, err, want)
			}
		})
	}
}

func TestImageCoverageInitEmptyImage(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{{Name: "etc/os-release", Data: "ID=test\n"}})
	target, err := CollectImage(context.Background(), loaded, Request{Capabilities: []string{"history", "future-cap"}})
	want := map[string]string{
		"prefixes": NotCollected, "conda-records": NotCollected, "history": Complete, "tooling-prefix": NotCollected,
		"final-cache": NotCollected, "cache-link-dependencies": NotCollected, "runtime-config": NotCollected,
		"os-package-tools": NotCollected, "shell-tools": NotCollected, "layer-retention": NotCollected,
	}
	if err != nil || !maps.Equal(target.Coverage, want) {
		t.Fatalf("empty image coverage = %+v, %v, want %+v", target.Coverage, err, want)
	}
	if target.Prefixes == nil || target.Archives == nil || target.Extracted == nil || target.Tools == nil ||
		target.Shells == nil || target.Retained == nil || target.Issues == nil || len(target.Prefixes)+len(target.Issues) != 0 {
		t.Fatalf("empty image array shape or contents changed: %+v", target)
	}
}
