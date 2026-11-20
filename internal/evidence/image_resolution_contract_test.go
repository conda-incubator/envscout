package evidence

import (
	"archive/tar"
	"context"
	"errors"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/conda-incubator/envscout/internal/testimage"
)

// Step states expose private-helper checkpoints without goroutines or timers.
type imageResolutionContractContext struct {
	context.Context
	t             *testing.T
	states        []error
	calls, budget int
}

func (ctx *imageResolutionContractContext) Err() error {
	ctx.t.Helper()
	ctx.calls++
	if ctx.calls > ctx.budget {
		ctx.t.Fatalf("context Err calls = %d; budget %d", ctx.calls, ctx.budget)
	}
	if len(ctx.states) == 0 {
		return nil
	}
	return ctx.states[min(ctx.calls-1, len(ctx.states)-1)]
}

// Only the scalar consumed by callers is frozen, not the resolution chain.
func imageResolutionContractResolve(c *imageCollector, p string) (*file.Reference, error) {
	return c.resolveReference(p)
}

func assertImageResolutionContract(t *testing.T, got, want *file.Reference, err error, message string) {
	t.Helper()
	if (got == nil) != (want == nil) || got != nil && (got.ID() != want.ID() || got.RealPath != want.RealPath) {
		t.Fatalf("reference = %v; want %v", got, want)
	}
	actual := ""
	if err != nil {
		actual = err.Error()
	}
	if actual != message {
		t.Fatalf("error = %q; want %q", actual, message)
	}
}

func TestImageResolutionContractScalars(t *testing.T) {
	tree := filetree.New()
	regular, err := tree.AddFile("/real/file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.AddFile("/synthetic/child"); err != nil {
		t.Fatal(err)
	}
	directory, err := tree.AddDir("/explicit")
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range [][2]file.Path{
		{"/basename", "real/file"}, {"/ancestor", "/real"}, {"/chain", "/basename"},
		{"/synthetic-link", "/synthetic"}, {"/explicit-link", "/explicit"},
		{"/dangling", "/missing"}, {"/self", "self"}, {"/cycle-a", "/cycle-b"}, {"/cycle-b", "/cycle-a"},
	} {
		if _, err := tree.AddSymLink(link[0], link[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tree.AddHardLink("/hard", "real/file"); err != nil {
		t.Fatal(err)
	}
	c := imageCollector{ctx: context.Background(), tree: tree}
	for _, tc := range []struct {
		name, path, message string
		ref                 *file.Reference
	}{
		{"regular", "/real/file", "", regular},
		{"normalized", "real/./file", "", regular},
		{"basename-link", "/basename", "", regular},
		{"ancestor-link", "/ancestor/file", "", regular},
		{"link-chain", "/chain", "", regular},
		{"hardlink", "/hard", "", regular},
		{"synthetic-directory", "/synthetic", "", nil},
		{"synthetic-directory-link", "/synthetic-link", "", nil},
		{"explicit-directory", "/explicit", "", directory},
		{"explicit-directory-link", "/explicit-link", "", directory},
		{"missing", "/missing", "image-local target is missing", nil},
		{"missing-suffix", "/ancestor/missing", "image-local target is missing", nil},
		{"dangling", "/dangling", "image-local target is missing", nil},
		{"self-cycle", "/self", "image-local link cannot be resolved", nil},
		{"two-link-cycle", "/cycle-a", "image-local link cannot be resolved", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for pass := 0; pass < 2; pass++ {
				got, err := imageResolutionContractResolve(&c, tc.path)
				assertImageResolutionContract(t, got, tc.ref, err, tc.message)
			}
		})
	}
}

func TestImageResolutionContractContextCheckpoints(t *testing.T) {
	tree := filetree.New()
	regular, err := tree.AddFile("/file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.AddSymLink("/self", "/self"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, message string
		states              []error
		checks              int
		ref                 *file.Reference
		cause               error
	}{
		{"pre-cancel", "/file", "context canceled", []error{context.Canceled}, 1, nil, context.Canceled},
		{"pre-deadline", "/file", "context deadline exceeded", []error{context.DeadlineExceeded}, 1, nil, context.DeadlineExceeded},
		{"success", "/file", "", nil, 2, regular, nil},
		{"missing", "/missing", "image-local target is missing", nil, 2, nil, nil},
		{"cycle", "/self", "image-local link cannot be resolved", nil, 2, nil, nil},
		{"after-file-cancel", "/file", "context canceled", []error{nil, context.Canceled}, 3, nil, context.Canceled},
		{"cancel-wins-over-missing", "/missing", "context canceled", []error{nil, context.Canceled}, 3, nil, context.Canceled},
		{"cancel-wins-over-cycle", "/self", "context canceled", []error{nil, context.Canceled}, 3, nil, context.Canceled},
		{"third-check-supplies-error", "/file", "context deadline exceeded", []error{nil, context.Canceled, context.DeadlineExceeded}, 3, nil, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &imageResolutionContractContext{Context: context.Background(), t: t, states: tc.states, budget: tc.checks}
			c := imageCollector{ctx: ctx, tree: tree}
			if tc.checks == 1 {
				c.tree = nil // Pre-cancellation must not require a tree.
			}
			got, err := imageResolutionContractResolve(&c, tc.path)
			assertImageResolutionContract(t, got, tc.ref, err, tc.message)
			if ctx.calls != tc.checks || tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("Err calls = %d; want %d, cause = %v", ctx.calls, tc.checks, err)
			}
		})
	}
}

func TestImageResolutionContractLastCheckpoint(t *testing.T) {
	tree := filetree.New()
	regular, err := tree.AddFile("/file")
	if err != nil {
		t.Fatal(err)
	}
	ctx := &imageResolutionContractContext{Context: context.Background(), t: t, states: []error{nil, nil, context.Canceled}, budget: 2}
	c := imageCollector{ctx: ctx, tree: tree}
	got, err := imageResolutionContractResolve(&c, "/file")
	assertImageResolutionContract(t, got, regular, err, "")
	if ctx.calls != 2 {
		t.Fatalf("successful Err calls = %d; want 2", ctx.calls)
	}
	ctx.budget = 3
	got, err = imageResolutionContractResolve(&c, "/file")
	assertImageResolutionContract(t, got, nil, err, "context canceled")
	if ctx.calls != 3 || !errors.Is(err, context.Canceled) {
		t.Fatalf("next-call Err calls = %d; want 3, cause = %v", ctx.calls, err)
	}
}

func TestImageResolutionContractExecutableContexts(t *testing.T) {
	tree := filetree.New()
	if _, err := tree.AddFile("/synthetic/child"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, message string
		states        []error
		checks        int
	}{
		{"synthetic-directory", "", nil, 2},
		{"pre-cancel", "context canceled", []error{context.Canceled}, 1},
		{"after-file-cancel", "context canceled", []error{nil, context.Canceled}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &imageResolutionContractContext{Context: context.Background(), t: t, states: tc.states, budget: tc.checks}
			c := imageCollector{ctx: ctx, tree: tree}
			got, err := c.executable("/synthetic")
			assertImageResolutionContract(t, got, nil, err, tc.message)
			if ctx.calls != tc.checks {
				t.Fatalf("Err calls = %d; want %d", ctx.calls, tc.checks)
			}
		})
	}
}

func TestImageResolutionContractConsumers(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "pkg"), commandEntry("cache/pkg/apt"),
		{Name: "cache/pkg/data", Data: "old"}, {Name: "cache/pkg-1.0-0.conda", Data: "archive"},
	}, []testimage.Entry{
		{Name: "cache/pkg/data", Data: "new"}, {Name: "cache/pkg-1.0-0.conda", Data: "new"},
		{Name: "usr/bin/apt", Type: tar.TypeSymlink, Link: "../../cache/pkg/apt"},
		{Name: "usr/bin/apt-get", Type: tar.TypeSymlink, Link: "apt"},
		{Name: "bin", Type: tar.TypeSymlink, Link: "usr/bin"},
		{Name: "app/cache", Type: tar.TypeSymlink, Link: "../cache/pkg"},
	})
	for _, tc := range []struct {
		name string
		caps []string
		all  bool
	}{
		{"all", []string{"final-cache", "cache-link-dependencies", "layer-retention", "os-package-tools"}, true},
		{"tools-only", []string{"os-package-tools"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := markerContractTarget(loaded, NotCollected, NotCollected, NotCollected)
			want.Coverage["os-package-tools"] = Complete
			want.Tools = []Artifact{{Path: "/usr/bin/apt", Kind: "apt", Reference: markerContractReference(loaded, 0, "/cache/pkg/apt")}}
			if tc.all {
				want.CacheLinked = true
				want.Coverage["final-cache"], want.Coverage["cache-link-dependencies"], want.Coverage["layer-retention"] = Complete, Complete, Complete
				want.Archives = []Artifact{{Path: "/cache/pkg-1.0-0.conda", Kind: "archive", Bytes: 3, Reference: markerContractReference(loaded, 1, "/cache/pkg-1.0-0.conda")}}
				want.Extracted = []Artifact{{Path: "/cache/pkg", Kind: "extracted", Bytes: 93, Reference: markerContractReference(loaded, 0, "/cache/pkg/info/index.json")}}
				blob := manifestOf(t, loaded).Layers[0]
				want.Retained = []Artifact{{Path: "/cache/pkg-1.0-0.conda", Kind: "archive-overwritten", Bytes: 7, Layer: 0,
					DiffID: loaded.Image.Metadata.Config.RootFS.DiffIDs[0].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size,
					Reference: markerContractReference(loaded, 0, "/cache/pkg-1.0-0.conda")}}
			}
			for pass := 0; pass < 2; pass++ {
				assertMarkerContract(t, collectFixture(t, loaded, tc.caps...), want)
			}
		})
	}
}
