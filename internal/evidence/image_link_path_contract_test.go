package evidence

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/conda-incubator/envscout/internal/testimage"
)

func TestImageLinkPathContractPolicies(t *testing.T) {
	tree := filetree.New()
	for _, p := range []file.Path{"/cache/pkg/lib/data", "/app/unrelated/file", "/other/data"} {
		if _, err := tree.AddFile(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range [][2]file.Path{
		{"/app/relative", "../bridge"}, {"/bridge", "/cache/alias"}, {"/cache/alias", "pkg/lib"},
		{"/app/absolute", "/cache/pkg"}, {"/app/empty", ""}, {"/app/gone", "/gone/pkg"},
		{"/app/root", "/"}, {"/self", "self"}, {"/cycle-a", "/cycle-b"}, {"/cycle-b", "cycle-a"},
	} {
		if _, err := tree.AddSymLink(link[0], link[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tree.AddHardLink("/hard", "cache/pkg/lib"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []file.Path{"/cache", "/cache/pkg", "/cache/pkg/lib"} {
		node, ok := tree.TreeReader().Node(filenode.IDByPath(p)).(*filenode.FileNode)
		if !ok || node.Reference != nil || node.FileType != file.TypeDirectory {
			t.Fatalf("%s is not a synthetic directory: %+v", p, node)
		}
	}
	c := imageCollector{ctx: context.Background(), tree: tree}
	for _, tc := range []struct {
		name, input, resolved, message string
		roots                          []string
		relevant                       bool
	}{
		{"synthetic-directory", "/cache/pkg/lib", "/cache/pkg/lib", "", []string{"/cache"}, true},
		{"relative-absolute-chain-suffix", "/app/relative/data", "/cache/pkg/lib/data", "", []string{"/cache"}, true},
		{"absolute-directory-suffix", "/app/absolute/lib/data", "/cache/pkg/lib/data", "", []string{"/cache/pkg"}, true},
		{"hardlink-directory-suffix", "/hard/data", "/cache/pkg/lib/data", "", []string{"/cache"}, true},
		{"source-root-before-rewrite", "/app/absolute/lib/data", "/cache/pkg/lib/data", "", []string{"/app/absolute"}, true},
		{"unrelated-existing-path", "/other/data", "/other/data", "", []string{"/cache"}, false},
		{"root-is-not-every-path", "/other/data", "/other/data", "", []string{"/"}, false},
		{"clean-before-components", "//cache//pkg/lib/../lib/data/", "/cache/pkg/lib/data", "", []string{"/cache"}, true},
		{"clean-removes-missing-component", "/missing/../cache/pkg/lib/data", "/cache/pkg/lib/data", "", []string{"/cache"}, true},
		{"relative-result-stays-relative", "cache/pkg/lib/../lib/data", "cache/pkg/lib/data", "", []string{"/cache"}, true},
		{"root", "/", "/", "", nil, false},
		{"cleaned-root", "/app/../", "/", "", []string{"/"}, true},
		{"link-to-root", "/app/root", "/", "", []string{"/"}, true},
		{"empty-input-is-dot-not-root", "", "", "image-local target is missing", []string{"/"}, false},
		{"malformed-empty-destination", "/app/empty", "", "image-local link is malformed", nil, false},
		{"malformed-parent-and-suffix", "/app/empty/unrelated/file", "", "image-local link is malformed", []string{"/app/unrelated"}, true},
		{"malformed-missing-suffix-root", "/app/empty/absent/file", "", "image-local link is malformed", []string{"/app/absent"}, true},
		{"missing-component-root-first", "/cache/absent/file", "", "image-local target is missing", []string{"/cache/absent"}, true},
		{"missing-ancestor-hides-deeper-root", "/cache/absent/file", "", "image-local target is missing", []string{"/cache/absent/file"}, false},
		{"missing-destination-root-first", "/app/gone/file", "", "image-local target is missing", []string{"/gone"}, true},
		{"missing-destination-ancestor", "/app/gone/file", "", "image-local target is missing", []string{"/gone/pkg"}, false},
		{"root-membership-not-text-prefix", "/cache/pkg/lib/data", "/cache/pkg/lib/data", "", []string{"/ca"}, false},
		{"roots-are-not-cleaned", "/cache/pkg/lib/data", "/cache/pkg/lib/data", "", []string{"/cache/."}, false},
		{"self-cycle", "/self/data", "", "image-local link resolution limit exceeded", []string{"/cache"}, false},
		{"two-link-cycle", "/cycle-a/data", "", "image-local link resolution limit exceeded", nil, false},
		{"cycle-root-before-failure", "/cycle-a/data", "", "image-local link resolution limit exceeded", []string{"/cycle-b"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := map[string]bool{}
			for _, root := range tc.roots {
				roots[root] = true
			}
			got, err := c.resolvedPath(tc.input)
			message := ""
			if err != nil {
				message = err.Error()
			}
			if got != tc.resolved || message != tc.message {
				t.Fatalf("resolvedPath(%q) = %q, %q; want %q, %q", tc.input, got, message, tc.resolved, tc.message)
			}
			if got := c.cacheRelevantPath(tc.input, roots); got != tc.relevant {
				t.Fatalf("cacheRelevantPath(%q, %v) = %v; want %v", tc.input, roots, got, tc.relevant)
			}
		})
	}
	if c.cacheRelevantPath("/cache/pkg/lib/data", map[string]bool{"/cache": false}) {
		t.Fatal("false-valued root was treated as relevant")
	}
}

func TestImageLinkPathContractRewriteLimit(t *testing.T) {
	for _, count := range []int{127, 128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			tree := filetree.New()
			if _, err := tree.AddFile("/cache/pkg/data"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				destination := file.Path(fmt.Sprintf("/link-%d", i+1))
				if i == count-1 {
					destination = "/cache/pkg"
				}
				if _, err := tree.AddSymLink(file.Path(fmt.Sprintf("/link-%d", i)), destination); err != nil {
					t.Fatal(err)
				}
			}
			c := imageCollector{ctx: context.Background(), tree: tree}
			got, err := c.resolvedPath("/link-0/data")
			// The final rewritten path needs another pass: 128 rewrites exhaust it.
			if count == 127 {
				if got != "/cache/pkg/data" || err != nil {
					t.Fatalf("127 rewrites = %q, %v", got, err)
				}
			} else if got != "" || err == nil || err.Error() != "image-local link resolution limit exceeded" {
				t.Fatalf("%d rewrites = %q, %v", count, got, err)
			}
			if got := c.cacheRelevantPath("/link-0/data", map[string]bool{"/cache": true}); got != (count == 127) {
				t.Fatalf("%d rewrites reaching cache = %v", count, got)
			}
			last := fmt.Sprintf("/link-%d", count-1)
			if got := c.cacheRelevantPath("/link-0/data", map[string]bool{last: true}); got != (count <= 128) {
				t.Fatalf("%d rewrites reaching last link = %v", count, got)
			}
		})
	}
}

func TestImageLinkPathContractPreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// No tree is needed: cancellation wins even over an empty relevance root set.
	c := imageCollector{ctx: ctx}
	for _, p := range []string{"/", "/missing", ""} {
		if got, err := c.resolvedPath(p); got != "" || !errors.Is(err, context.Canceled) {
			t.Fatalf("resolvedPath(%q) = %q, %v", p, got, err)
		}
		for _, roots := range []map[string]bool{nil, {}, {"/missing": true}} {
			if !c.cacheRelevantPath(p, roots) {
				t.Fatalf("cancelled relevance(%q, %v) = false", p, roots)
			}
		}
	}
}

func TestImageLinkPathContractCacheLinkConsumer(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "pkg"),
		{Name: "cache/pkg/data", Data: "payload"},
		{Name: "app/a-dir", Type: tar.TypeSymlink, Link: "../cache/alias"},
		{Name: "cache/alias", Type: tar.TypeSymlink, Link: "/cache/pkg"},
		{Name: "app/b-broken", Type: tar.TypeSymlink, Link: "/cache/absent"},
		{Name: "app/z-unrelated", Type: tar.TypeSymlink, Link: "/missing"},
		{Name: "cache/z-dangling", Type: tar.TypeSymlink, Link: "/missing"},
	})
	got := collectFixture(t, loaded, "final-cache", "cache-link-dependencies")
	wantIssues := []Issue{{Capability: "cache-link-dependencies", Path: "/app/b-broken", Message: "image-local target is missing"}}
	if !got.CacheLinked || !reflect.DeepEqual(got.Issues, wantIssues) {
		t.Fatalf("cache-link positive/diagnostics = %+v", got)
	}
	wantExtracted := []Artifact{{Path: "/cache/pkg", Kind: "extracted", Bytes: 86,
		Reference: fmt.Sprintf("0:%s:/cache/pkg/info/index.json", loaded.Image.Metadata.Config.RootFS.DiffIDs[0])}}
	if !reflect.DeepEqual(got.Extracted, wantExtracted) || len(got.Archives) != 0 || len(got.Retained) != 0 {
		t.Fatalf("cache-link artifacts = %+v", got)
	}
	assertImageLinkPathContractCoverage(t, got.Coverage, Complete, Partial, NotCollected)
}

func TestImageLinkPathContractHistoricalFailedLink(t *testing.T) {
	for _, relevant := range []bool{false, true} {
		t.Run(fmt.Sprint(relevant), func(t *testing.T) {
			destination := "/missing"
			if relevant {
				destination = "/cache/absent"
			}
			loaded := loadEvidenceImage(t, []testimage.Entry{
				packageMarker("cache/pkg/info/index.json", "pkg"),
				{Name: "cache/pkg/data", Data: "payload"},
				{Name: "cache/pkg-1.0-0.conda", Data: "archive"},
			}, []testimage.Entry{
				{Name: ".wh.cache"}, {Name: "app/broken", Type: tar.TypeSymlink, Link: destination},
			})
			got := collectFixture(t, loaded, "final-cache", "cache-link-dependencies", "layer-retention")
			manifest := manifestOf(t, loaded)
			want := []Artifact{{Path: "/cache/pkg-1.0-0.conda", Kind: "archive-hidden", Bytes: 7, Layer: 0,
				DiffID: loaded.Image.Metadata.Config.RootFS.DiffIDs[0].String(), BlobDigest: manifest.Layers[0].Digest.String(),
				LayerBytes: manifest.Layers[0].Size, Reference: fmt.Sprintf("0:%s:/cache/pkg-1.0-0.conda", loaded.Image.Metadata.Config.RootFS.DiffIDs[0])}}
			issues, coverage := []Issue{}, Complete
			if relevant {
				issues = append(issues, Issue{Capability: "layer-retention", Path: "/app/broken", Message: "image-local target is missing"})
				coverage = Partial
			} else {
				want = append([]Artifact{{Path: "/cache/pkg", Kind: "extracted-hidden", Bytes: 86, Layer: 0,
					DiffID: loaded.Image.Metadata.Config.RootFS.DiffIDs[0].String(), BlobDigest: manifest.Layers[0].Digest.String(),
					LayerBytes: manifest.Layers[0].Size, Reference: fmt.Sprintf("0:%s:/cache/pkg/data", loaded.Image.Metadata.Config.RootFS.DiffIDs[0])}}, want...)
			}
			if !reflect.DeepEqual(got.Retained, want) || !reflect.DeepEqual(got.Issues, issues) || got.CacheLinked || len(got.Archives)+len(got.Extracted) != 0 {
				t.Fatalf("historical failed-link relevance = %+v\nwant retained=%+v issues=%+v", got, want, issues)
			}
			assertImageLinkPathContractCoverage(t, got.Coverage, Complete, Complete, coverage)
		})
	}
}

func assertImageLinkPathContractCoverage(t *testing.T, got map[string]string, cache, links, layers string) {
	t.Helper()
	want := map[string]string{
		"prefixes": NotCollected, "conda-records": NotCollected, "history": NotCollected, "tooling-prefix": NotCollected,
		"final-cache": cache, "cache-link-dependencies": links, "layer-retention": layers,
		"runtime-config": NotCollected, "os-package-tools": NotCollected, "shell-tools": NotCollected,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("coverage = %v; want %v", got, want)
	}
}
